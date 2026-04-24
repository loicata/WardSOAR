"""Read-only sanity audit of a pfSense/Netgate appliance.

Phase 7a of the WardSOAR roadmap. This module inspects an already-
configured (or partially-configured, or blank) Netgate 4200 via SSH
and reports *what's wrong* with the Suricata + pf + output + security
layers that WardSOAR depends on. It never mutates anything — that job
belongs to Phase 7b, which reuses the findings produced here.

Architectural contract
----------------------
* Each check is a coroutine on :class:`NetgateAuditor` that returns a
  single :class:`AuditFinding`. Checks are allowed to fail: any
  uncaught exception is turned into a finding with status ``unknown``
  so the audit as a whole still completes.
* Findings carry enough context for the UI to group them (`category`,
  `tier`) and for a future Apply step to act on them (`fix_id`,
  `fix_description`, `risk_badge`).
* The three tiers are:

    * **critical** — WardSOAR cannot block at all until this is
      resolved (no Suricata, no blocklist table, missing eve.json).
      The escalation gate refuses to switch to Protect / Hard Protect
      while any critical finding is in KO state.
    * **recommended** — WardSOAR works but detection quality is
      compromised. Runmode, memcaps, auto-update schedule.
    * **advanced** — nice-to-have tuning. File-store off for privacy,
      CPU affinity, lua scripting. Collapsed by default in the UI.

* Risk badges annotate *the fix*, not the current state:

    * 🟢 (green)  no-op — toggling an eve.json event type, enabling a
      protocol parser, writing a log.
    * 🟡 (amber)  restarts Suricata — short (~10 s) gap in detection.
    * 🔴 (red)    touches ``config.xml`` + requires pfSense reload,
      can impact routing. Requires a pre-change backup.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.config import AppConfig
    from src.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.netgate_audit")


# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------


# Tiers — the UI groups findings into three collapsible sections.
TIER_CRITICAL = "critical"
TIER_RECOMMENDED = "recommended"
TIER_ADVANCED = "advanced"

# Statuses — the colour the UI paints next to the finding.
STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_UNKNOWN = "unknown"  # SSH failed or parse error — treat as blocking only for critical tier.

# Risk badges — annotate what a future Apply fix would cost.
RISK_GREEN = "green"  # safe: config flip only
RISK_AMBER = "amber"  # restarts Suricata (~10s gap)
RISK_RED = "red"  # patches config.xml + pfSense reload

# Categories — logical grouping for the UI's collapsible panels.
CAT_SURICATA = "suricata"
CAT_PF = "pf"
CAT_OUTPUT = "output"
CAT_SECURITY = "security"
CAT_HARDWARE = "hardware"


def _memcap_to_bytes(number: str, unit: str, *, assume_when_bare: str = "bytes") -> Optional[int]:
    """Normalise a Suricata memcap value to a byte count.

    Two YAML conventions coexist:

    * Suricata 7.x / pfSense 25.x write raw byte integers (``memcap: 33554432``).
    * Older Suricata / pfSense < 24 wrote a suffixed form
      (``host-mem-cap: 32mb``).

    When the unit suffix is absent, the interpretation depends on
    the *key* the value was read from. The caller tells us via
    ``assume_when_bare`` whether a bare integer should be treated
    as bytes (new nested form) or megabytes (legacy top-level form).

    Returns ``None`` when the input is unparseable rather than
    raising — callers surface it as "not detected".
    """
    try:
        value = int(number)
    except (TypeError, ValueError):
        return None
    multipliers: dict[str, int] = {
        "": 1 if assume_when_bare == "bytes" else 1024 * 1024,
        "b": 1,
        "kb": 1024,
        "k": 1024,
        "mb": 1024 * 1024,
        "m": 1024 * 1024,
        "gb": 1024 * 1024 * 1024,
        "g": 1024 * 1024 * 1024,
    }
    factor = multipliers.get(unit.lower().strip(), 1)
    return value * factor


@dataclass(frozen=True)
class AuditFinding:
    """One line in the audit report.

    The ``id`` is a stable machine-readable key (``suricata.package_installed``,
    ``pf.blocklist_table_exists``, …). Phase 7b keys its fix handlers off
    this identifier, so renaming one is a breaking change.
    """

    id: str
    title: str
    tier: str
    category: str
    status: str
    current_value: str
    expected_value: str
    risk_badge: str
    fix_description: str
    details: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        """Serialise for export / logging."""
        return asdict(self)


@dataclass(frozen=True)
class AuditResult:
    """Complete output of one audit run."""

    started_at: datetime
    duration_seconds: float
    ssh_reachable: bool
    findings: list[AuditFinding] = field(default_factory=list)
    ssh_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Derived views — consumed by the UI and the escalation gate.
    # ------------------------------------------------------------------

    @property
    def any_critical_ko(self) -> bool:
        """True if at least one critical finding is NOT in ``ok`` status.

        This is the input the mode-escalation gate uses: as long as
        this is True, switching to Protect or Hard Protect is refused
        with the blocking modal.
        """
        return any(f.tier == TIER_CRITICAL and f.status != STATUS_OK for f in self.findings)

    def counts_by_tier(self) -> dict[str, dict[str, int]]:
        """``{tier: {status: count}}`` summary for the UI header."""
        result: dict[str, dict[str, int]] = {
            TIER_CRITICAL: {},
            TIER_RECOMMENDED: {},
            TIER_ADVANCED: {},
        }
        for finding in self.findings:
            bucket = result.setdefault(finding.tier, {})
            bucket[finding.status] = bucket.get(finding.status, 0) + 1
        return result

    def findings_by_category(self) -> dict[str, list[AuditFinding]]:
        """Group findings by ``category`` — preserves insertion order."""
        grouped: dict[str, list[AuditFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped

    def to_dict(self) -> dict[str, object]:
        """Serialise the full result for JSON export / decision log."""
        return {
            "started_at": self.started_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "ssh_reachable": self.ssh_reachable,
            "ssh_error": self.ssh_error,
            "any_critical_ko": self.any_critical_ko,
            "counts_by_tier": self.counts_by_tier(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------


class NetgateAuditor:
    """Drive the full audit against a live SSH session.

    Args:
        ssh: Connected :class:`~src.pfsense_ssh.PfSenseSSH` — the
            auditor reuses the operator's configured SSH key and
            port; it never prompts for a new credential.
        eve_json_path: Path to the EVE JSON file as WardSOAR expects
            to find it. When the on-disk file is elsewhere, the
            ``output.eve_json_path`` check fails.
        blocklist_table_name: Name of the pf table WardSOAR writes to.
            Defaults to ``"blocklist"`` but is configurable in
            ``config.yaml > responder.pfsense.blocklist_table``.
    """

    # Commands are hard-coded string literals — no operator input is
    # ever interpolated into an SSH argument, so injection is moot.
    _CMD_PFCTL_INFO = "pfctl -s info"
    _CMD_PFCTL_TABLES = "pfctl -s Tables"
    # ``pkg info -e`` prints nothing on stdout (it only sets the exit
    # code), so a parser that looks for ``Name:`` on stdout always
    # fails. Drop the ``-e`` flag so the full ``Name: ...`` line
    # appears and the check can confirm the package is genuinely
    # installed. Regression from v0.7.1: an ET-Open-enabled Netgate
    # was falsely flagged "package missing" in the audit UI.
    _CMD_PKG_SURICATA = (
        "pkg info pfSense-pkg-suricata 2>/dev/null | head -5 "
        "|| pkg query '%n %v' pfSense-pkg-suricata 2>/dev/null "
        "|| true"
    )
    _CMD_SURICATA_INSTANCES = (
        "ls -1 /usr/local/etc/suricata 2>/dev/null | grep -E '^suricata_' || true"
    )
    _CMD_SURICATA_PIDS = "pgrep -lf '^/usr/local/bin/suricata' 2>/dev/null || true"
    _CMD_CONFIG_XML_HEAD = "head -c 200 /cf/conf/config.xml 2>/dev/null || true"
    _CMD_NTPQ = "ntpq -pn 2>&1 | head -20 || true"
    _CMD_DATE = "date -u +%s"
    _CMD_DF_VAR_LOG = "df -k /var/log 2>&1 | tail -1 || true"
    _CMD_UNAME = "uname -rms"
    _CMD_PFSENSE_VERSION = (
        "cat /etc/version 2>/dev/null || cat /etc/version.patch 2>/dev/null || echo unknown"
    )
    _CMD_IFCONFIG_SHORT = "ifconfig -l 2>/dev/null || true"
    # ---- Suricata introspection
    _CMD_SURICATA_VERSION = "/usr/local/bin/suricata -V 2>&1 || true"
    # pfSense keeps per-instance config under
    # /usr/local/etc/suricata/suricata_<uuid>_<iface>. Reading the
    # top of the YAML with ``head -500`` yields ~25 KB per instance,
    # which is more than enough to cover the sections the audit
    # checks (outputs, app-layer, stream, flow, host-mem-cap,
    # af-packet, runmode, rule-files). Previously this used grep
    # with an ``^(...)`` anchor that discarded every indented line,
    # which silently broke detection of HTTP/TLS/DNS/SSH parsers,
    # EVE event types and host-mem-cap -- every one of which is
    # nested at least one level deep under its parent key.
    _CMD_SURICATA_YAML = (
        "for d in /usr/local/etc/suricata/suricata_*/; do "
        '  if [ -f "$d/suricata.yaml" ]; then '
        "    echo --- $d; "
        '    head -500 "$d/suricata.yaml" 2>/dev/null; '
        "  fi; "
        "done"
    )
    _CMD_SURICATA_RULES_COUNT = (
        "find /usr/local/etc/suricata -maxdepth 3 -name '*.rules' "
        "-exec wc -l {} + 2>/dev/null | tail -1 || true"
    )
    # Read the ``<alias>`` block for the ``blocklist`` alias straight
    # out of config.xml. ``awk`` gives us the first block after the
    # ``<name>blocklist</name>`` marker up to the closing ``</alias>``;
    # grep then pulls only the ``<type>...</type>`` line. The output is
    # one of "host", "urltable", or empty (alias missing). We also
    # test for the seed file so the check can distinguish a fully
    # migrated deployment from a partially-migrated one.
    _CMD_BLOCKLIST_ALIAS_TYPE = (
        "awk '/<name>blocklist<\\/name>/{flag=1} "
        "flag{print} /<\\/alias>/{if(flag){exit}}' "
        "/cf/conf/config.xml 2>/dev/null "
        "| grep -oE '<type>[^<]*</type>' "
        "| head -1 "
        "| sed -e 's|<type>||' -e 's|</type>||'; "
        "echo ---; "
        "test -f /var/db/aliastables/wardsoar_blocklist.txt "
        "&& echo seed_ok || echo seed_missing"
    )

    def __init__(
        self,
        ssh: "PfSenseSSH",
        eve_json_path: str,
        blocklist_table_name: str = "blocklist",
    ) -> None:
        self._ssh = ssh
        self._eve_path = eve_json_path
        self._blocklist_table = blocklist_table_name
        # Collected command outputs — populated by :meth:`_gather` at the
        # start of a run so each check can read from cache rather than
        # re-issuing the same command.
        self._cache: dict[str, tuple[bool, str]] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> AuditResult:
        """Execute every check and return the aggregated result."""
        started_at = datetime.now(timezone.utc)
        started_mono = time.monotonic()

        # Step 0 — verify SSH before investing in the command battery.
        ssh_ok, ssh_msg = await self._ssh.check_status()
        if not ssh_ok:
            return AuditResult(
                started_at=started_at,
                duration_seconds=time.monotonic() - started_mono,
                ssh_reachable=False,
                findings=[
                    AuditFinding(
                        id="ssh.reachable",
                        title="pfSense SSH reachable",
                        tier=TIER_CRITICAL,
                        category=CAT_SECURITY,
                        status=STATUS_CRITICAL,
                        current_value="unreachable",
                        expected_value="reachable",
                        risk_badge=RISK_GREEN,
                        fix_description=(
                            "Enable SSH in pfSense (System → Advanced → "
                            "Admin Access) and install the WardSOAR public "
                            "key for the admin user."
                        ),
                        details=ssh_msg,
                    )
                ],
                ssh_error=ssh_msg,
            )

        # Step 1 — batch-run the discovery commands so each check can
        # consume the cached output. Running them sequentially keeps
        # the SSH session from piling up concurrent connections.
        await self._gather()

        # Step 2 — run every check. Each returns exactly one finding.
        findings: list[AuditFinding] = []
        for coroutine in (
            self._check_pfctl_info,
            self._check_pfsense_version,
            self._check_uname,
            self._check_ntp_sync,
            self._check_disk_space,
            self._check_suricata_package_installed,
            self._check_suricata_instance_present,
            self._check_suricata_running,
            self._check_suricata_attached_to_interface,
            self._check_suricata_version_current,
            self._check_suricata_rules_loaded,
            self._check_suricata_runmode,
            self._check_suricata_afpacket,
            self._check_suricata_memcap,
            self._check_suricata_protocol_parsers,
            self._check_eve_event_types,
            self._check_eve_file_store_off,
            self._check_pf_blocklist_table,
            self._check_pf_alias_persistent,
            self._check_eve_file_exists,
            self._check_eve_file_recent,
        ):
            try:
                finding = await coroutine()
            except Exception as exc:  # noqa: BLE001 — one broken check must not kill the run
                logger.exception("Audit check %s raised unexpectedly", coroutine.__name__)
                finding = AuditFinding(
                    id=f"internal.{coroutine.__name__}",
                    title=coroutine.__name__,
                    tier=TIER_ADVANCED,
                    category=CAT_SECURITY,
                    status=STATUS_UNKNOWN,
                    current_value="check crashed",
                    expected_value="check succeeds",
                    risk_badge=RISK_GREEN,
                    fix_description="Internal WardSOAR bug — report it.",
                    details=repr(exc),
                )
            findings.append(finding)

        return AuditResult(
            started_at=started_at,
            duration_seconds=time.monotonic() - started_mono,
            ssh_reachable=True,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Command caching — single place that issues SSH calls.
    # ------------------------------------------------------------------

    async def _gather(self) -> None:
        """Populate :attr:`_cache` with the output of each discovery command."""
        commands = {
            "pfctl_info": self._CMD_PFCTL_INFO,
            "pfctl_tables": self._CMD_PFCTL_TABLES,
            "pkg_suricata": self._CMD_PKG_SURICATA,
            "suricata_instances": self._CMD_SURICATA_INSTANCES,
            "suricata_pids": self._CMD_SURICATA_PIDS,
            "suricata_version": self._CMD_SURICATA_VERSION,
            "suricata_yaml": self._CMD_SURICATA_YAML,
            "suricata_rules_count": self._CMD_SURICATA_RULES_COUNT,
            "blocklist_alias_type": self._CMD_BLOCKLIST_ALIAS_TYPE,
            "ntpq": self._CMD_NTPQ,
            "date_utc": self._CMD_DATE,
            "df_var_log": self._CMD_DF_VAR_LOG,
            "uname": self._CMD_UNAME,
            "pfsense_version": self._CMD_PFSENSE_VERSION,
            "ifconfig_l": self._CMD_IFCONFIG_SHORT,
            "config_xml_head": self._CMD_CONFIG_XML_HEAD,
            # Check if the configured eve path exists + mtime.
            # ``stat`` on FreeBSD uses -f for formatting.
            "eve_stat": f"stat -f '%m %z' '{self._eve_path}' 2>&1 || true",
        }
        for key, cmd in commands.items():
            self._cache[key] = await self._ssh.run_read_only(cmd, timeout=10)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    async def _check_pfctl_info(self) -> AuditFinding:
        ok, out = self._cache.get("pfctl_info", (False, ""))
        if ok and "Status:" in out:
            return AuditFinding(
                id="pf.pfctl_alive",
                title="pf is alive (pfctl -s info)",
                tier=TIER_CRITICAL,
                category=CAT_PF,
                status=STATUS_OK,
                current_value="running",
                expected_value="running",
                risk_badge=RISK_GREEN,
                fix_description="—",
            )
        return AuditFinding(
            id="pf.pfctl_alive",
            title="pf is alive (pfctl -s info)",
            tier=TIER_CRITICAL,
            category=CAT_PF,
            status=STATUS_CRITICAL,
            current_value="unreachable",
            expected_value="running",
            risk_badge=RISK_GREEN,
            fix_description="Reboot pfSense or check firewall daemon state — blocking is impossible while pf is down.",
            details=out[:200] if out else None,
        )

    async def _check_pfsense_version(self) -> AuditFinding:
        ok, out = self._cache.get("pfsense_version", (False, ""))
        version = out.strip() if ok else "unknown"
        status = STATUS_OK if version and version != "unknown" else STATUS_UNKNOWN
        return AuditFinding(
            id="hardware.pfsense_version",
            title="pfSense version",
            tier=TIER_ADVANCED,
            category=CAT_HARDWARE,
            status=status,
            current_value=version,
            expected_value="≥ 2.7 or Plus 24.x",
            risk_badge=RISK_GREEN,
            fix_description="—",
        )

    async def _check_uname(self) -> AuditFinding:
        ok, out = self._cache.get("uname", (False, ""))
        arch = out.strip() if ok else "unknown"
        return AuditFinding(
            id="hardware.uname",
            title="Kernel / architecture",
            tier=TIER_ADVANCED,
            category=CAT_HARDWARE,
            status=STATUS_OK if ok else STATUS_UNKNOWN,
            current_value=arch or "unknown",
            expected_value="FreeBSD amd64",
            risk_badge=RISK_GREEN,
            fix_description="—",
        )

    async def _check_ntp_sync(self) -> AuditFinding:
        ok, out = self._cache.get("ntpq", (False, ""))
        synced = ok and any(line.lstrip().startswith("*") for line in out.splitlines())
        return AuditFinding(
            id="security.ntp_synced",
            title="NTP synchronised with upstream",
            tier=TIER_RECOMMENDED,
            category=CAT_SECURITY,
            status=STATUS_OK if synced else STATUS_WARNING,
            current_value="synced" if synced else "not synced",
            expected_value="at least one * peer in ntpq",
            risk_badge=RISK_GREEN,
            fix_description=(
                "Forensic timelines become unreliable without NTP. "
                "Enable in Services → NTP with a reachable pool server."
            ),
            details=out[:400] if out else None,
        )

    async def _check_disk_space(self) -> AuditFinding:
        ok, out = self._cache.get("df_var_log", (False, ""))
        percent_used: Optional[int] = None
        if ok:
            match = re.search(r"(\d+)%", out)
            if match:
                percent_used = int(match.group(1))
        if percent_used is None:
            status = STATUS_UNKNOWN
        elif percent_used >= 90:
            status = STATUS_CRITICAL
        elif percent_used >= 70:
            status = STATUS_WARNING
        else:
            status = STATUS_OK
        return AuditFinding(
            id="security.disk_free_var_log",
            title="Disk free on /var/log",
            tier=TIER_RECOMMENDED,
            category=CAT_SECURITY,
            status=status,
            current_value=f"{percent_used}% used" if percent_used is not None else "unknown",
            expected_value="< 70% used",
            risk_badge=RISK_GREEN,
            fix_description=(
                "Rotate Suricata logs (Status → System Logs → Settings) "
                "or enlarge /var on the Netgate."
            ),
            details=out[:200] if out else None,
        )

    async def _check_suricata_package_installed(self) -> AuditFinding:
        ok, out = self._cache.get("pkg_suricata", (False, ""))
        # Recognise three outputs from the updated command:
        #   1. ``pkg info``  → multi-line "Name:" / "Version:" block
        #   2. ``pkg query '%n %v'`` fallback → one line "pfSense-pkg-suricata 7.0.x_y"
        #   3. empty        → package genuinely missing
        text = (out or "").strip()
        installed = ok and "pfSense-pkg-suricata" in text and text != ""
        # Try to surface a human version string for the details panel.
        version: Optional[str] = None
        if installed:
            match = re.search(r"pfSense-pkg-suricata\S*\s+([0-9][\w\.\-_]*)", text)
            if match:
                version = match.group(1)
            else:
                match = re.search(r"Version\s*:\s*(\S+)", text)
                if match:
                    version = match.group(1)
        return AuditFinding(
            id="suricata.package_installed",
            title="Suricata package present",
            tier=TIER_CRITICAL,
            category=CAT_SURICATA,
            status=STATUS_OK if installed else STATUS_CRITICAL,
            current_value=(
                (f"installed ({version})" if version else "installed") if installed else "missing"
            ),
            expected_value="pfSense-pkg-suricata",
            risk_badge=RISK_RED,
            fix_description=(
                "Install the Suricata pfSense package (System → Package "
                "Manager → Available Packages). A Phase 7d/7e MSI will "
                "drive this over SSH for a blank Netgate."
            ),
            details=text[:200] if text else None,
        )

    async def _check_suricata_instance_present(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_instances", (False, ""))
        instances = [ln.strip() for ln in (out or "").splitlines() if ln.strip()] if ok else []
        status = STATUS_OK if instances else STATUS_CRITICAL
        return AuditFinding(
            id="suricata.instance_present",
            title="Suricata instance configured",
            tier=TIER_CRITICAL,
            category=CAT_SURICATA,
            status=status,
            current_value=(
                f"{len(instances)} instance(s): {', '.join(instances)}" if instances else "none"
            ),
            expected_value="≥ 1 instance attached to WAN",
            risk_badge=RISK_RED,
            fix_description=(
                "Create a Suricata instance on the WAN interface "
                "(Services → Suricata → Interfaces → Add)."
            ),
        )

    async def _check_suricata_running(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_pids", (False, ""))
        pids = [ln for ln in (out or "").splitlines() if "/usr/local/bin/suricata" in ln]
        status = STATUS_OK if pids else STATUS_CRITICAL
        return AuditFinding(
            id="suricata.process_running",
            title="Suricata process running",
            tier=TIER_CRITICAL,
            category=CAT_SURICATA,
            status=status,
            current_value=f"{len(pids)} PID(s)" if pids else "not running",
            expected_value="≥ 1 PID",
            risk_badge=RISK_AMBER,
            fix_description=(
                "Start Suricata on each configured interface from "
                "Services → Suricata → Interfaces → Start."
            ),
            details=(out or "").strip()[:400] or None,
        )

    async def _check_suricata_attached_to_interface(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_instances", (False, ""))
        if not ok:
            return AuditFinding(
                id="suricata.attached_to_wan",
                title="Suricata attached to WAN",
                tier=TIER_CRITICAL,
                category=CAT_SURICATA,
                status=STATUS_UNKNOWN,
                current_value="unknown",
                expected_value="at least one instance on WAN",
                risk_badge=RISK_RED,
                fix_description="—",
            )
        # Instance directory names are formatted "suricata_<uuid>_<ifname>"
        # on pfSense. The trailing segment tells us the interface.
        interfaces = []
        for name in out.splitlines():
            segments = name.strip().split("_")
            if len(segments) >= 3:
                interfaces.append(segments[-1])

        # Accept any real network interface name. A Netgate 4200 has
        # ``igc0`` through ``igc3``; different hardware families use
        # ``igb*``, ``ix*``, ``em*``, ``re*``, or assignments such as
        # ``opt1`` or ``lagg0``. The only names we *reject* are the
        # obviously non-routable ones (loopback, pflog) -- if Suricata
        # is bound there, the user definitely misconfigured.
        invalid_prefixes = ("lo", "pflog", "enc", "pfsync")
        routable = [
            iface
            for iface in interfaces
            if iface and not any(iface.lower().startswith(p) for p in invalid_prefixes)
        ]
        if routable:
            status = STATUS_OK
        elif interfaces:
            status = STATUS_WARNING
        else:
            status = STATUS_CRITICAL
        return AuditFinding(
            id="suricata.attached_to_wan",
            title="Suricata attached to a public interface",
            tier=TIER_CRITICAL,
            category=CAT_SURICATA,
            status=status,
            current_value=", ".join(interfaces) if interfaces else "none",
            expected_value="a routable interface (WAN or equivalent)",
            risk_badge=RISK_RED,
            fix_description=(
                "Attach Suricata to the WAN interface so inbound "
                "traffic from the Internet is inspected."
            ),
        )

    async def _check_suricata_version_current(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_version", (False, ""))
        version: Optional[str] = None
        if ok:
            match = re.search(r"Suricata version (\S+)", out)
            if match:
                version = match.group(1)
        return AuditFinding(
            id="suricata.version",
            title="Suricata version",
            tier=TIER_ADVANCED,
            category=CAT_SURICATA,
            status=STATUS_OK if version else STATUS_UNKNOWN,
            current_value=version or "unknown",
            expected_value="≥ 7.0 (7.x has TLS 1.3 + prefilter)",
            risk_badge=RISK_GREEN,
            fix_description="—",
            details=out[:200] if out else None,
        )

    async def _check_suricata_rules_loaded(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_rules_count", (False, ""))
        total: Optional[int] = None
        if ok:
            match = re.search(r"^\s*(\d+)\s+total", out, re.MULTILINE)
            if match:
                total = int(match.group(1))
            else:
                # Fallback: grab the last number encountered
                numbers = re.findall(r"(\d+)", out)
                if numbers:
                    total = int(numbers[-1])
        if total is None:
            status = STATUS_UNKNOWN
        elif total >= 10_000:
            status = STATUS_OK
        elif total >= 1_000:
            status = STATUS_WARNING
        else:
            status = STATUS_CRITICAL
        return AuditFinding(
            id="suricata.rules_loaded",
            title="Suricata rules loaded",
            tier=TIER_RECOMMENDED,
            category=CAT_SURICATA,
            status=status,
            current_value=(f"{total:,} rules" if total is not None else "unknown").replace(
                ",", " "
            ),
            expected_value="≥ 10 000 (ET Open + Snort community at minimum)",
            risk_badge=RISK_AMBER,
            fix_description=(
                "Enable additional rule sources (Services → Suricata → "
                "Global Settings → Rule Sources) and run the update."
            ),
            details=out[:200] if out else None,
        )

    async def _check_suricata_runmode(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        runmode: Optional[str] = None
        if ok:
            match = re.search(r"runmode:\s*(\w+)", out)
            if match:
                runmode = match.group(1)
        optimal = runmode == "workers"
        return AuditFinding(
            id="suricata.runmode",
            title="Suricata runmode",
            tier=TIER_RECOMMENDED,
            category=CAT_SURICATA,
            status=STATUS_OK if optimal else STATUS_WARNING,
            current_value=runmode or "unknown",
            expected_value="workers (best on Netgate 4200 multi-core)",
            risk_badge=RISK_AMBER,
            fix_description=(
                "Set runmode to 'workers' in each suricata.yaml — "
                "better throughput on 4-core hardware."
            ),
        )

    async def _check_suricata_afpacket(self) -> AuditFinding:
        """Audit the Suricata capture method — platform-aware.

        The previous implementation blindly flagged "legacy PCAP"
        anything that wasn't ``af-packet`` in the YAML. That check is
        **Linux-only semantics**: AF_PACKET is a Linux socket API
        (``/usr/include/linux/if_packet.h``) that has no FreeBSD
        equivalent. pfSense runs on FreeBSD, so the string ``af-packet``
        never appears in any valid pfSense Suricata YAML — meaning
        every Netgate in the world was being marked WARNING wrongly.

        On FreeBSD / pfSense the capture method choice is:

        * **libpcap** (default) — IDS mode, alerts flow through the
          pfSense ``blockoffenders`` daemon. This is *exactly* the
          pipeline WardSOAR requires: every alert reaches the AI
          scorer before any block is issued. Optimal for our use case.
        * **netmap** (inline IPS via ``ips_mode=ips_mode_inline``) —
          Suricata drops packets itself, preemptively. This
          short-circuits WardSOAR's per-alert analysis, so we would
          never recommend it to an operator running this tool.

        Therefore the finding is OK whenever ``pcap:`` or ``netmap:``
        is present in the YAML — both are valid on FreeBSD. We only
        WARN if neither is detected, which means parse failure.
        """
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        on_linux = "linux" in (self._cache.get("uname", (False, ""))[1] or "").lower()

        uses_pcap = ok and "pcap:" in out
        uses_netmap = ok and "netmap:" in out
        uses_afpacket = ok and "af-packet" in out

        if on_linux:
            # Linux semantics: AF_PACKET is the high-throughput path.
            optimal = uses_afpacket
            current = "af-packet" if uses_afpacket else "legacy PCAP"
            expected = "af-packet (higher throughput, lower drops)"
        else:
            # FreeBSD / pfSense: libpcap is the canonical capture
            # method for IDS mode. Mark OK as long as Suricata has a
            # capture configured at all. netmap is also acceptable but
            # not preferred for WardSOAR because it bypasses our
            # alert pipeline.
            optimal = uses_pcap or uses_netmap
            if uses_netmap:
                current = "netmap (inline IPS — bypasses WardSOAR pipeline)"
            elif uses_pcap:
                current = "libpcap (IDS — optimal for WardSOAR)"
            else:
                current = "no capture method detected"
            expected = "libpcap (FreeBSD IDS default, required by WardSOAR)"

        return AuditFinding(
            id="suricata.afpacket",
            title="Suricata capture mode",
            tier=TIER_ADVANCED if not on_linux else TIER_RECOMMENDED,
            category=CAT_SURICATA,
            status=STATUS_OK if optimal else STATUS_WARNING,
            current_value=current,
            expected_value=expected,
            risk_badge=RISK_AMBER,
            fix_description=(
                "Switch the capture method to AF_PACKET in each "
                "suricata.yaml. Brief detection gap during restart."
                if on_linux
                else (
                    "No action needed — libpcap is the canonical "
                    "FreeBSD capture method and exactly what WardSOAR "
                    "needs. AF_PACKET is Linux-only."
                )
            ),
        )

    async def _check_suricata_memcap(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        host_memcap_bytes: Optional[int] = None
        source: str = ""

        if ok:
            # Suricata 7.x / pfSense 25.x puts memcaps as raw byte
            # integers nested under their section, e.g.:
            #
            #     host:
            #       memcap: 33554432
            #
            # The pre-0.7.3 check looked for the legacy top-level
            # ``host-mem-cap: 32mb`` form and therefore reported
            # "not detected" on every modern Netgate. We now look
            # for the nested ``host:\n memcap:`` block first, with
            # the legacy form as fallback. Either yields the value in
            # bytes.
            host_block = re.search(
                r"^host:\s*\n((?:\s+[^\n]+\n)+)",
                out,
                re.MULTILINE,
            )
            if host_block:
                inner = host_block.group(1)
                nested = re.search(
                    r"^\s+memcap:\s*(\d+)(?:\s*([kmgKMG]?[bB]?))?",
                    inner,
                    re.MULTILINE,
                )
                if nested:
                    host_memcap_bytes = _memcap_to_bytes(
                        nested.group(1),
                        nested.group(2) or "",
                        assume_when_bare="bytes",
                    )
                    source = "host.memcap"

            if host_memcap_bytes is None:
                legacy = re.search(
                    r"host-mem-cap:\s*(\d+)\s*([kmgKMG]?[bB]?)",
                    out,
                    re.IGNORECASE,
                )
                if legacy:
                    host_memcap_bytes = _memcap_to_bytes(
                        legacy.group(1),
                        legacy.group(2) or "",
                        assume_when_bare="mb",
                    )
                    source = "host-mem-cap"

        # 16 MB is pfSense's default; anything above is fine. Below 16
        # usually indicates an operator typo.
        threshold = 16 * 1024 * 1024
        sane = host_memcap_bytes is not None and host_memcap_bytes >= threshold

        human: str
        if host_memcap_bytes is None:
            human = "not detected"
        else:
            mb = host_memcap_bytes // (1024 * 1024)
            human = f"{source}={mb} MB"

        return AuditFinding(
            id="suricata.memcap",
            title="Suricata memory caps reasonable",
            tier=TIER_ADVANCED,
            category=CAT_SURICATA,
            status=STATUS_OK if sane else STATUS_WARNING,
            current_value=human,
            expected_value="host memcap ≥ 16 MB (pfSense default)",
            risk_badge=RISK_AMBER,
            fix_description=(
                "Raise host.memcap / flow.memcap / stream.memcap to "
                "leverage the Netgate 4200's RAM budget."
            ),
            details=human,
        )

    async def _check_suricata_protocol_parsers(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        if not ok:
            return AuditFinding(
                id="suricata.protocol_parsers",
                title="HTTP/TLS/DNS/SSH parsers enabled",
                tier=TIER_RECOMMENDED,
                category=CAT_SURICATA,
                status=STATUS_UNKNOWN,
                current_value="unknown",
                expected_value="all four enabled",
                risk_badge=RISK_GREEN,
                fix_description="—",
            )
        # Each ``- <proto>:`` block is followed by an ``enabled: yes`` line.
        # We only count parsers whose block explicitly ships enabled.
        enabled = set()
        for proto in ("http", "tls", "dns", "ssh"):
            if re.search(rf"{proto}:\s*\n\s*enabled:\s*yes", out):
                enabled.add(proto)
            elif re.search(rf"{proto}:\s*\n[\s\S]{{0,50}}enabled:\s*no", out):
                pass  # explicitly disabled
            elif re.search(rf"{proto}:\s*$", out, re.MULTILINE):
                enabled.add(proto)  # section present and not explicitly disabled
        status = STATUS_OK if enabled == {"http", "tls", "dns", "ssh"} else STATUS_WARNING
        return AuditFinding(
            id="suricata.protocol_parsers",
            title="HTTP/TLS/DNS/SSH parsers enabled",
            tier=TIER_RECOMMENDED,
            category=CAT_SURICATA,
            status=status,
            current_value=", ".join(sorted(enabled)) or "none detected",
            expected_value="http, tls, dns, ssh",
            risk_badge=RISK_GREEN,
            fix_description=(
                "Enable each parser in the 'app-layer' section of "
                "suricata.yaml. No restart gap — parsers apply at reload."
            ),
        )

    async def _check_eve_event_types(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        if not ok:
            return AuditFinding(
                id="output.eve_event_types",
                title="EVE JSON event types",
                tier=TIER_RECOMMENDED,
                category=CAT_OUTPUT,
                status=STATUS_UNKNOWN,
                current_value="unknown",
                expected_value="alert, dns, tls, http, ssh, flow",
                risk_badge=RISK_GREEN,
                fix_description="—",
            )
        expected = {"alert", "dns", "tls", "http", "ssh", "flow"}
        present = {kind for kind in expected if f"- {kind}" in out}
        status = STATUS_OK if expected.issubset(present) else STATUS_WARNING
        return AuditFinding(
            id="output.eve_event_types",
            title="EVE JSON event types (alert/dns/tls/http/ssh/flow)",
            tier=TIER_RECOMMENDED,
            category=CAT_OUTPUT,
            status=status,
            current_value=", ".join(sorted(present)) or "none",
            expected_value=", ".join(sorted(expected)),
            risk_badge=RISK_GREEN,
            fix_description=(
                "In suricata.yaml under eve-log → types, enable the "
                "six event types WardSOAR consumes."
            ),
        )

    async def _check_eve_file_store_off(self) -> AuditFinding:
        ok, out = self._cache.get("suricata_yaml", (False, ""))
        file_store_on = ok and bool(re.search(r"file-store:\s*\n\s*enabled:\s*yes", out))
        return AuditFinding(
            id="output.file_store_off",
            title="file-store disabled (privacy)",
            tier=TIER_ADVANCED,
            category=CAT_OUTPUT,
            status=STATUS_WARNING if file_store_on else STATUS_OK,
            current_value="on" if file_store_on else "off",
            expected_value="off — do not archive payloads on the firewall",
            risk_badge=RISK_GREEN,
            fix_description=(
                "Disable file-store in suricata.yaml. Forensic payload "
                "capture belongs in WardSOAR's encrypted evidence ZIP, "
                "not in plain files on pfSense."
            ),
        )

    async def _check_pf_blocklist_table(self) -> AuditFinding:
        ok, out = self._cache.get("pfctl_tables", (False, ""))
        present = ok and self._blocklist_table in out
        return AuditFinding(
            id="pf.blocklist_table",
            title=f"pf table '{self._blocklist_table}' present",
            tier=TIER_CRITICAL,
            category=CAT_PF,
            status=STATUS_OK if present else STATUS_CRITICAL,
            current_value="present" if present else "missing",
            expected_value=f"table '{self._blocklist_table}' in pfctl -s Tables",
            risk_badge=RISK_RED,
            fix_description=(
                "Create the alias '{name}' (type 'Host(s)') in pfSense "
                "and reference it in a WAN drop rule. WardSOAR writes "
                "to this table via pfctl; without it every block is a "
                "no-op."
            ).format(name=self._blocklist_table),
            details=out[:400] if out else None,
        )

    async def _check_pf_alias_persistent(self) -> AuditFinding:
        """Check the blocklist alias is url-table-backed (Phase 7h).

        A host-type alias stores its entries inside ``config.xml``,
        which pfSense regenerates from the saved baseline on every
        filter reload. WardSOAR's ``pfctl -T add`` calls survive only
        until the next reload (minutes-to-hours), so the block log
        lies: the rule disappears but no feedback reaches WardSOAR.
        An url-table alias, backed by the seed file we ship, makes
        blocks survive every reload scenario.

        The finding is ``WARNING`` — not ``CRITICAL`` — because the
        pf table itself can still be populated; we just lose the
        blocks at the next filter_configure. That is worse than
        Monitor mode (the operator trusts the "blocked" log) but it
        does not leave the box defenceless the way a missing table
        would.
        """
        ok, out = self._cache.get("blocklist_alias_type", (False, ""))
        if not ok:
            return AuditFinding(
                id="pf.alias_persistent",
                title="Blocklist alias persists across pfSense reloads",
                tier=TIER_RECOMMENDED,
                category=CAT_PF,
                status=STATUS_UNKNOWN,
                current_value="unknown",
                expected_value="urltable (file-backed)",
                risk_badge=RISK_RED,
                fix_description=(
                    "Run 'Apply' on this finding to migrate the "
                    "blocklist alias from host to urltable (backed by "
                    "/var/db/aliastables/wardsoar_blocklist.txt)."
                ),
                details=out[:200] if out else None,
            )

        # Expected output shape:
        #   <alias_type>\n---\n<seed_marker>
        # where alias_type is "host", "urltable", or "" (missing) and
        # seed_marker is "seed_ok" or "seed_missing".
        parts = (out or "").split("---")
        alias_type = (parts[0].strip() if parts else "").strip().lower()
        seed_marker = (parts[1].strip() if len(parts) > 1 else "").strip().lower()
        seed_present = "seed_ok" in seed_marker

        if alias_type == "urltable" and seed_present:
            return AuditFinding(
                id="pf.alias_persistent",
                title="Blocklist alias persists across pfSense reloads",
                tier=TIER_RECOMMENDED,
                category=CAT_PF,
                status=STATUS_OK,
                current_value="urltable (file-backed)",
                expected_value="urltable (file-backed)",
                risk_badge=RISK_RED,
                fix_description="—",
                details="seed file: /var/db/aliastables/wardsoar_blocklist.txt",
            )

        # Either the alias is still host-type, or we migrated the XML
        # but the seed file was wiped separately. Both are surfaced
        # the same way: Apply again is safe (idempotent migration).
        if alias_type == "urltable" and not seed_present:
            current = "urltable but seed file missing"
        elif alias_type == "host":
            current = "host (in-memory only — lost on reload)"
        elif alias_type == "":
            current = "alias not found in config.xml"
        else:
            current = alias_type

        return AuditFinding(
            id="pf.alias_persistent",
            title="Blocklist alias persists across pfSense reloads",
            tier=TIER_RECOMMENDED,
            category=CAT_PF,
            status=STATUS_WARNING,
            current_value=current,
            expected_value="urltable (file-backed)",
            risk_badge=RISK_RED,
            fix_description=(
                "Apply 'pf.alias_persistent' to convert the alias to "
                "urltable and seed the backing file. A config.xml "
                "backup is taken automatically before the change."
            ),
            details=(out or "")[:400],
        )

    async def _check_eve_file_exists(self) -> AuditFinding:
        ok, out = self._cache.get("eve_stat", (False, ""))
        present = ok and out.strip() and not out.strip().lower().startswith("stat:")
        return AuditFinding(
            id="output.eve_file_exists",
            title="EVE JSON file present at configured path",
            tier=TIER_CRITICAL,
            category=CAT_OUTPUT,
            status=STATUS_OK if present else STATUS_CRITICAL,
            current_value="present" if present else "missing",
            expected_value=self._eve_path,
            risk_badge=RISK_AMBER,
            fix_description=(
                "Adjust config.yaml > watcher.ssh.remote_eve_path to "
                "match the Suricata log path, or create the Suricata "
                "instance so the file appears."
            ),
            details=out[:200] if out else None,
        )

    async def _check_eve_file_recent(self) -> AuditFinding:
        ok_eve, eve_out = self._cache.get("eve_stat", (False, ""))
        ok_date, date_out = self._cache.get("date_utc", (False, ""))
        if not (ok_eve and ok_date):
            return AuditFinding(
                id="output.eve_file_recent",
                title="EVE JSON recently updated (< 5 min)",
                tier=TIER_RECOMMENDED,
                category=CAT_OUTPUT,
                status=STATUS_UNKNOWN,
                current_value="unknown",
                expected_value="mtime within last 5 minutes",
                risk_badge=RISK_AMBER,
                fix_description="—",
            )
        # stat -f '%m %z' returns "<mtime_epoch> <size>".
        match = re.match(r"(\d+)\s+(\d+)", eve_out.strip())
        if not match:
            return AuditFinding(
                id="output.eve_file_recent",
                title="EVE JSON recently updated (< 5 min)",
                tier=TIER_RECOMMENDED,
                category=CAT_OUTPUT,
                status=STATUS_UNKNOWN,
                current_value="parse failed",
                expected_value="mtime within last 5 minutes",
                risk_badge=RISK_AMBER,
                fix_description="—",
                details=eve_out[:100],
            )
        mtime = int(match.group(1))
        try:
            now_epoch = int(date_out.strip())
        except ValueError:
            return AuditFinding(
                id="output.eve_file_recent",
                title="EVE JSON recently updated (< 5 min)",
                tier=TIER_RECOMMENDED,
                category=CAT_OUTPUT,
                status=STATUS_UNKNOWN,
                current_value="remote clock unparsed",
                expected_value="mtime within last 5 minutes",
                risk_badge=RISK_AMBER,
                fix_description="—",
            )
        age_seconds = now_epoch - mtime
        if age_seconds < 300:
            status = STATUS_OK
            value = f"{age_seconds}s ago"
        elif age_seconds < 1800:
            status = STATUS_WARNING
            value = f"{age_seconds // 60} min ago"
        else:
            status = STATUS_CRITICAL
            value = f"{age_seconds // 60} min ago"
        return AuditFinding(
            id="output.eve_file_recent",
            title="EVE JSON recently updated",
            tier=TIER_RECOMMENDED,
            category=CAT_OUTPUT,
            status=status,
            current_value=value,
            expected_value="< 5 min ago",
            risk_badge=RISK_AMBER,
            fix_description=(
                "Suricata has stopped writing events. Restart the "
                "instance (Services → Suricata → Interfaces → Start)."
            ),
        )


# ---------------------------------------------------------------------------
# Convenience — single-shot audit
# ---------------------------------------------------------------------------


async def run_audit(
    ssh: "PfSenseSSH",
    config: "AppConfig",
) -> AuditResult:
    """One-shot helper that builds an auditor from the current config.

    The watcher.ssh.remote_eve_path key carries the canonical EVE JSON
    location when running in SSH mode; for file mode we fall back to
    watcher.eve_json_path but trim any Windows drive prefix.
    """
    watcher = config.watcher
    eve_path = (
        watcher.get("ssh", {}).get("remote_eve_path")
        or watcher.get("eve_json_path")
        or "/var/log/suricata/eve.json"
    )
    blocklist_table = (
        config.responder.get("pfsense", {}).get("blocklist_table", "blocklist") or "blocklist"
    )
    auditor = NetgateAuditor(
        ssh=ssh,
        eve_json_path=str(eve_path),
        blocklist_table_name=str(blocklist_table),
    )
    return await auditor.run()


__all__ = [
    "AuditFinding",
    "AuditResult",
    "NetgateAuditor",
    "run_audit",
    "TIER_CRITICAL",
    "TIER_RECOMMENDED",
    "TIER_ADVANCED",
    "STATUS_OK",
    "STATUS_WARNING",
    "STATUS_CRITICAL",
    "STATUS_UNKNOWN",
    "RISK_GREEN",
    "RISK_AMBER",
    "RISK_RED",
    "CAT_SURICATA",
    "CAT_PF",
    "CAT_OUTPUT",
    "CAT_SECURITY",
    "CAT_HARDWARE",
]

# Public symbols count used by the UI for capacity hints.
_ = asyncio  # silence "unused import" when asyncio is only referenced in type hints
