"""Execute response actions: pfSense blocking via SSH and local process termination.

Handles the automated response to confirmed threats by adding IPs
to the pfSense blocklist table via SSH+pfctl and optionally killing
local processes.

SAFETY CONSTRAINTS:
- Whitelist check BEFORE any block — P0 requirement
- Rate limiter enforced — max 20 blocks/hour (anti-runaway)
- Dry-run mode supported — logs decisions without executing
- Fail-safe: any error → do NOT block, log the error
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import psutil
from psutil import AccessDenied, NoSuchProcess

from wardsoar.core.asn_enricher import AsnInfo
from wardsoar.core.cdn_allowlist import CdnAllowlist
from wardsoar.core.config import WhitelistConfig
from wardsoar.core.models import (
    BlockAction,
    ResponseAction,
    ThreatAnalysis,
    ThreatVerdict,
    WardMode,
)
from wardsoar.core.remote_agents import RemoteAgent
from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker
from wardsoar.core.trusted_temp import TrustedTempRegistry

# Hard Protect — minimum confidence on a BENIGN verdict to skip the block.
# Anything below blocks, even on BENIGN. Exposed as a config knob so the
# operator can relax the bar (e.g. 0.95) if the false-positive rate is too
# high in practice — the 1-click rollback absorbs the remaining noise.
DEFAULT_HARD_PROTECT_BENIGN_THRESHOLD = 0.97

logger = logging.getLogger("ward_soar.responder")


# Exact networks we refuse to block — explicit CIDR list rather than
# ``ipaddress.IPv4Address.is_private`` because the latter also covers
# documentation ranges (TEST-NET-1/2/3, benchmark) that are legitimate
# public targets for the Responder. The guard is *only* about the
# operator's own network fabric.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 CGNAT — ISPs use this
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
)


def _is_rfc1918_or_local(ip: str) -> bool:
    """True if ``ip`` belongs to a network WardSOAR must never block.

    The categories listed in :data:`_PRIVATE_NETWORKS` are the only
    ones that match the operator's own network fabric — LAN devices,
    loopback, link-local, carrier-grade NAT used by some home ISPs.
    Everything else (including TEST-NET documentation ranges, which
    Python's ``is_private`` spuriously covers) remains blockable.

    The check is *unconditional* — it sits before the whitelist
    check in :meth:`ThreatResponder.respond`. An operator can wipe
    the whitelist, run a broken migration, or deliberately craft a
    CIDR that excludes their own subnet: blocking a private IP is
    still impossible. The worst case is WardSOAR failing to block a
    LAN-to-LAN attack, which is preferable to silencing the
    operator's own machine.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _PRIVATE_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    return False


class RateLimiter:
    """Track and enforce blocking rate limits.

    Prevents runaway blocking scenarios by limiting the number
    of blocks per hour.
    """

    def __init__(self, max_per_hour: int = 20) -> None:
        self._max_per_hour = max_per_hour
        self._actions: list[datetime] = []

    def can_block(self) -> bool:
        """Check if a new block is allowed under rate limits.

        Returns:
            True if blocking is allowed, False if rate limit reached.
        """
        now = datetime.now(timezone.utc)
        self._actions = [t for t in self._actions if (now - t).total_seconds() < 3600]
        return len(self._actions) < self._max_per_hour

    def record_action(self) -> None:
        """Record a blocking action for rate limiting."""
        self._actions.append(datetime.now(timezone.utc))


class ThreatResponder:
    """Execute automated response actions for confirmed threats.

    Args:
        config: Responder configuration dict from config.yaml.
        whitelist: Whitelist configuration to prevent blocking protected IPs.
        ssh: ``RemoteAgent`` for firewall block / unblock operations.
            Today this is always a ``NetgateAgent`` (Phase 3b.2); the
            type widened to the protocol so future agents (Virus Sniff
            Pi, third-party sensors) plug in without touching the
            responder's hot path.
        tracker: BlockTracker instance for block timestamp tracking.
    """

    def __init__(
        self,
        config: dict[str, Any],
        whitelist: WhitelistConfig,
        ssh: RemoteAgent,
        tracker: BlockTracker,
        trusted_temp: Optional[TrustedTempRegistry] = None,
        confidence_threshold: float = 0.7,
        hard_protect_benign_threshold: float = DEFAULT_HARD_PROTECT_BENIGN_THRESHOLD,
        cdn_allowlist: Optional["CdnAllowlist"] = None,
    ) -> None:
        self._config = config
        self._whitelist = whitelist
        self._ssh = ssh
        self._tracker = tracker
        # Optional: if provided, IPs in the registry are refused for blocking.
        # Populated by the Rollback orchestrator after a user-initiated unblock
        # to prevent immediate re-blocking of the same IP (flapping).
        self._trusted_temp = trusted_temp
        # v0.5.5: ``mode`` replaces the legacy ``dry_run`` bool. The config
        # migration layer in :mod:`src.config` translates legacy keys, but we
        # also read ``dry_run`` here so the Responder stays safe if it is
        # instantiated directly from a raw dict (tests).
        self._mode: WardMode = WardMode.parse(config.get("mode", config.get("dry_run", True)))
        self._block_duration: int = config.get("block_duration_hours", 24)
        self._kill_local: bool = config.get("kill_local_process", True)
        self._rate_limiter = RateLimiter(max_per_hour=config.get("max_blocks_per_hour", 20))
        # Thresholds per mode — see :class:`src.models.WardMode` docstring.
        self._confidence_threshold: float = float(confidence_threshold)
        self._hard_protect_benign_threshold: float = float(hard_protect_benign_threshold)
        # Optional CDN / major-SaaS allowlist (Phase 7e, v0.7.6).
        # If present and the alert's source IP resolves to a listed
        # ASN, the Hard-Protect branch of :meth:`_decide_block` falls
        # back to Protect semantics. Without an allowlist the mode
        # behaves exactly as in v0.7.5 (stricter, which is the safe
        # default if the registry fails to load).
        self._cdn_allowlist = cdn_allowlist

    # ------------------------------------------------------------------
    # Runtime controls — used by the UI (dashboard mode toggle and
    # config_view threshold sliders) to change behaviour without a
    # restart. Each setter validates its input and logs the change so
    # the operator can audit policy edits in trace_debug.log.
    # ------------------------------------------------------------------

    @property
    def mode(self) -> WardMode:
        return self._mode

    def set_mode(self, mode: WardMode) -> None:
        """Switch operating mode at runtime.

        Whitelist, trusted-temp and rate-limit guardrails are not
        affected — they apply to every mode identically.
        """
        if mode != self._mode:
            logger.warning("Responder mode: %s → %s", self._mode.value, mode.value)
            self._mode = mode

    @property
    def confidence_threshold(self) -> float:
        return self._confidence_threshold

    def set_confidence_threshold(self, value: float) -> None:
        """Update the Protect-mode CONFIRMED threshold.

        Clamped to [0.0, 1.0] — values outside are silently snapped.
        """
        clamped = max(0.0, min(1.0, float(value)))
        if clamped != self._confidence_threshold:
            logger.warning(
                "Responder confidence_threshold: %.2f → %.2f",
                self._confidence_threshold,
                clamped,
            )
            self._confidence_threshold = clamped

    @property
    def hard_protect_benign_threshold(self) -> float:
        return self._hard_protect_benign_threshold

    def set_hard_protect_benign_threshold(self, value: float) -> None:
        """Update the Hard-Protect BENIGN threshold.

        Same clamping as :meth:`set_confidence_threshold`. A lower
        value means *more* traffic is spared (less strict). 0.99 is
        very strict; 0.90 is moderate.
        """
        clamped = max(0.0, min(1.0, float(value)))
        if clamped != self._hard_protect_benign_threshold:
            logger.warning(
                "Responder hard_protect_benign_threshold: %.2f → %.2f",
                self._hard_protect_benign_threshold,
                clamped,
            )
            self._hard_protect_benign_threshold = clamped

    async def respond(
        self,
        analysis: ThreatAnalysis,
        source_ip: str,
        confidence_threshold: Optional[float] = None,
        process_id: Optional[int] = None,
        asn_info: Optional["AsnInfo"] = None,
    ) -> list[ResponseAction]:
        """Execute response actions based on threat analysis and mode.

        The block decision follows :class:`~src.models.WardMode` semantics:

        * ``MONITOR`` — never blocks.
        * ``PROTECT`` — blocks on CONFIRMED ∧ confidence ≥ threshold.
        * ``HARD_PROTECT`` — blocks on anything *except* BENIGN with
          confidence ≥ ``hard_protect_benign_threshold``. Opus failure
          (typically INCONCLUSIVE with zero confidence) counts as a
          block trigger, consistent with "any doubt → block".

        Whitelist, trusted-temp and rate-limit gates apply identically
        in all three modes — they can never be bypassed by a stricter
        mode.

        Args:
            analysis: Opus's threat analysis result (always non-None;
                on Opus error the analyzer returns INCONCLUSIVE with
                zero confidence).
            source_ip: IP address to potentially block.
            confidence_threshold: Per-call override of the Protect-mode
                threshold. ``None`` = use instance attribute. Kept for
                backward compat with existing tests; new code should
                use :meth:`set_confidence_threshold` instead.
            process_id: Optional local process ID to terminate.

        Returns:
            List of ResponseAction records documenting what was done.
        """
        actions: list[ResponseAction] = []

        # Always-on safety gates — same semantics in all modes.
        # Hard-coded first gate: blocking a private / loopback / link-
        # local address is silently refused. This protects the operator
        # from accidentally blacklisting their own workstation or LAN
        # gateway when Hard Protect, a faulty whitelist, or a buggy
        # future mode would otherwise have done so. Introduced in
        # v0.6.4 after WardSOAR blocked 192.168.2.100 in Hard Protect
        # on a BENIGN 0.92 verdict for its own ipinfo.io lookup.
        if _is_rfc1918_or_local(source_ip):
            # Downgrade to DEBUG when the verdict is BENIGN: the guard
            # intervened but no block was about to be issued anyway,
            # so a WARNING misleads operators into thinking a risky
            # action was averted. Keep WARNING for verdicts where a
            # block was actually wanted (CONFIRMED, INCONCLUSIVE in
            # HARD_PROTECT) — those are the cases the guard truly saved.
            log_level = (
                logging.DEBUG if analysis.verdict == ThreatVerdict.BENIGN else logging.WARNING
            )
            logger.log(
                log_level,
                "RFC1918 GUARD: %s is private/loopback/link-local — refusing to block "
                "(unconditional safety, independent of whitelist/mode)",
                source_ip,
            )
            actions.append(
                ResponseAction(
                    action_type=BlockAction.NONE,
                    target_ip=source_ip,
                    error_message="IP is RFC1918/loopback/link-local — blocking refused",
                )
            )
            return actions

        if self._whitelist.is_whitelisted(source_ip):
            # Same DEBUG/WARNING split as the RFC1918 guard above:
            # on BENIGN no block was about to occur, so a WARNING is
            # noise. CONFIRMED / INCONCLUSIVE in HARD_PROTECT means a
            # block was wanted and the whitelist genuinely saved the
            # operator — keep WARNING there.
            log_level = (
                logging.DEBUG if analysis.verdict == ThreatVerdict.BENIGN else logging.WARNING
            )
            logger.log(
                log_level,
                "WHITELIST BLOCK: %s is whitelisted — refusing to block",
                source_ip,
            )
            actions.append(
                ResponseAction(
                    action_type=BlockAction.NONE,
                    target_ip=source_ip,
                    error_message="IP is whitelisted — blocking refused",
                )
            )
            return actions

        if self._trusted_temp is not None and self._trusted_temp.is_trusted(source_ip):
            # Same DEBUG/WARNING split. The trusted-temp registry exists
            # to prevent re-blocking an IP the user just rolled back; a
            # BENIGN verdict was never going to re-block anyway, so a
            # WARNING about "refusing to re-block" is misleading. Keep
            # WARNING for CONFIRMED / INCONCLUSIVE — those are the
            # actual flapping signals the operator should notice.
            log_level = (
                logging.DEBUG if analysis.verdict == ThreatVerdict.BENIGN else logging.WARNING
            )
            logger.log(
                log_level,
                "TRUSTED_TEMP: %s was recently rolled back by user — refusing to re-block",
                source_ip,
            )
            actions.append(
                ResponseAction(
                    action_type=BlockAction.NONE,
                    target_ip=source_ip,
                    error_message="IP recently rolled back — refusing to re-block",
                )
            )
            return actions

        # Mode-driven decision.
        should_block, reason = self._decide_block(analysis, confidence_threshold, asn_info=asn_info)
        if not should_block:
            logger.info("Mode=%s — no block for %s (%s)", self._mode.value, source_ip, reason)
            actions.append(ResponseAction(action_type=BlockAction.NONE, target_ip=source_ip))
            return actions

        # MONITOR never reaches here — _decide_block returns False.
        logger.info("Mode=%s — block decision for %s (%s)", self._mode.value, source_ip, reason)

        if not self._rate_limiter.can_block():
            logger.warning("RATE LIMIT: Cannot block %s — rate limit exceeded", source_ip)
            actions.append(
                ResponseAction(
                    action_type=BlockAction.NONE,
                    target_ip=source_ip,
                    error_message="Rate limit exceeded",
                )
            )
            return actions

        block_action = await self.block_ip_pfsense(source_ip, self._block_duration)
        actions.append(block_action)

        # Rate limit is charged only for actions that actually mutate
        # pfSense state. An idempotent skip did not add a rule, so
        # counting it would erode the genuine budget — worst case the
        # limiter would trip on redundant no-ops while real blocks are
        # denied on the next alert.
        if block_action.success and not block_action.idempotent:
            self._rate_limiter.record_action()

        if process_id is not None and self._kill_local:
            kill_action = await self.kill_local_process(process_id)
            actions.append(kill_action)

        return actions

    def _decide_block(
        self,
        analysis: ThreatAnalysis,
        confidence_threshold: Optional[float] = None,
        asn_info: Optional[AsnInfo] = None,
    ) -> tuple[bool, str]:
        """Apply the mode-specific block rule.

        Returns a ``(should_block, reason)`` pair. The reason string is
        consumed by the caller's audit log so the rationale for each
        decision — especially "no block" ones in HARD_PROTECT — is
        visible in trace_debug.log.

        In HARD_PROTECT, if ``asn_info`` resolves to an ASN listed in
        the CDN / major-SaaS allowlist, the mode falls back to Protect
        semantics: only a CONFIRMED verdict with sufficient confidence
        triggers a block. This is the fix for the v0.7.5 Netflix
        incident — Opus verdicted the retransmission alert BENIGN 0.88,
        below the 0.99 threshold, and Hard Protect blocked a Netflix
        CDN IP. With the allowlist in place, the same scenario now
        short-circuits to Protect and lets the traffic through.
        """
        if self._mode == WardMode.MONITOR:
            return False, "MONITOR mode — blocks disabled"

        if self._mode == WardMode.PROTECT:
            return self._decide_protect(analysis, confidence_threshold)

        # HARD_PROTECT — invert the burden of proof, with CDN bypass.
        cdn_match = (
            self._cdn_allowlist.classify_asn(asn_info.asn)
            if (asn_info is not None and self._cdn_allowlist is not None)
            else None
        )
        if cdn_match is not None:
            allow, reason = self._decide_protect(analysis, confidence_threshold)
            prefix = (
                f"CDN allowlist hit ({cdn_match.organisation}, AS{cdn_match.asn}); "
                "HARD_PROTECT → PROTECT semantics. "
            )
            return allow, prefix + reason

        benign_threshold = self._hard_protect_benign_threshold
        if analysis.verdict == ThreatVerdict.BENIGN and analysis.confidence >= benign_threshold:
            return (
                False,
                f"BENIGN {analysis.confidence:.2f} ≥ {benign_threshold:.2f}",
            )
        return (
            True,
            f"verdict={analysis.verdict.value} conf={analysis.confidence:.2f} — "
            f"not BENIGN ≥ {benign_threshold:.2f}",
        )

    def _decide_protect(
        self,
        analysis: ThreatAnalysis,
        confidence_threshold: Optional[float] = None,
    ) -> tuple[bool, str]:
        """Factored out: Protect-mode decision, reused from the CDN fallback."""
        threshold = (
            confidence_threshold if confidence_threshold is not None else self._confidence_threshold
        )
        if analysis.verdict != ThreatVerdict.CONFIRMED:
            return False, f"verdict={analysis.verdict.value}, require CONFIRMED"
        if analysis.confidence < threshold:
            return (
                False,
                f"CONFIRMED confidence {analysis.confidence:.2f} < threshold {threshold:.2f}",
            )
        return True, f"CONFIRMED ≥ {threshold:.2f}"

    async def block_ip_pfsense(self, ip: str, duration_hours: int = 24) -> ResponseAction:
        """Add an IP to the pfSense blocklist table via SSH.

        Idempotence (CLAUDE.md §3): if the IP is already on the alias
        file, the call short-circuits and returns a successful
        ``idempotent=True`` action. No second tracker record is
        written (we would overwrite the original block time with
        ``now()`` and lose audit accuracy) and no duplicate
        ``"Blocked IP …"`` log line is emitted.

        Regression context: on 2026-04-23 22:40 two concurrent alerts
        on ``2a0d:3341:…:2000`` both reached ``add_to_blocklist`` and
        produced two ``Blocked IP`` lines inside two seconds. The file
        itself was already deduplicated, but the audit trail was not
        and the block tracker's timestamp was silently overwritten.

        Args:
            ip: IP address to block.
            duration_hours: How long to maintain the block.

        Returns:
            ResponseAction documenting the result. ``idempotent=True``
            when the IP was already in the blocklist before this call.
        """
        try:
            if await self._ssh.is_blocked(ip):
                logger.info("IP %s already on pfSense blocklist — idempotent skip", ip)
                return ResponseAction(
                    action_type=BlockAction.IP_BLOCK,
                    target_ip=ip,
                    block_duration_hours=duration_hours,
                    success=True,
                    idempotent=True,
                )

            success = await self._ssh.add_to_blocklist(ip)
            if success:
                self._tracker.record_block(ip)
                logger.info("Blocked IP %s on pfSense blocklist", ip)
                return ResponseAction(
                    action_type=BlockAction.IP_BLOCK,
                    target_ip=ip,
                    block_duration_hours=duration_hours,
                    success=True,
                    executed_at=datetime.now(timezone.utc),
                )

            logger.error("Failed to add %s to pfSense blocklist", ip)
            return ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip=ip,
                success=False,
                error_message="pfctl add failed",
            )
        except (OSError, ValueError) as exc:
            logger.error("pfSense SSH call failed for IP %s: %s", ip, exc)
            return ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip=ip,
                success=False,
                error_message=str(exc),
            )

    async def kill_local_process(self, pid: int) -> ResponseAction:
        """Terminate a local process by PID.

        Args:
            pid: Process ID to terminate.

        Returns:
            ResponseAction documenting the result.
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            logger.info("Terminated process %d (%s)", pid, proc_name)
            return ResponseAction(
                action_type=BlockAction.PROCESS_KILL,
                target_process_id=pid,
                success=True,
                executed_at=datetime.now(timezone.utc),
            )
        except (NoSuchProcess, AccessDenied, OSError) as exc:
            logger.error("Failed to terminate process %d: %s", pid, exc)
            return ResponseAction(
                action_type=BlockAction.PROCESS_KILL,
                target_process_id=pid,
                success=False,
                error_message=str(exc),
            )

    async def get_active_blocks(self) -> list[dict[str, Any]]:
        """List currently blocked IPs from pfSense blocklist.

        Returns:
            List of dicts with ip and blocked_at fields.
        """
        try:
            ips = await self._ssh.list_blocklist()
            blocks: list[dict[str, Any]] = []
            for ip in ips:
                blocked_at = self._tracker.get_block_time(ip)
                blocks.append(
                    {
                        "ip": ip,
                        "blocked_at": blocked_at.isoformat() if blocked_at else None,
                    }
                )
            return blocks
        except (OSError, ValueError) as exc:
            logger.error("Failed to get active blocks: %s", exc)
            return []
