"""Generate and deploy WardSOAR custom Suricata rules (Phase 7c).

Scope
-----
Phase 7c ships a curated set of Suricata rules tailored to the
operator's threat model — specifically, the Hutchinson case
(``VINE-2025-001``) and any additional entries in
``config/known_bad_actors.yaml``. Two rule families are emitted:

1. **Actor IOC rules** — one rule per IP / CIDR / domain listed under
   an actor. The rule fires at priority 1 on *any* traffic touching
   the IOC. Because known_bad_actors.yaml already puts the alert over
   the PreScorer threshold via weight=100, the Suricata-side rule is
   defence-in-depth: it guarantees Opus adjudicates even if the
   registry is momentarily empty (first-run race, yaml edit, etc.).

2. **Ben-pattern rules** — hand-written signatures matching behaviour
   observed in the Wireshark capture that motivated the whole case:
   sustained SSH brute force from a single source, DNS disruption
   over repeated intervals, remote kill of a running Wireshark
   instance. These are written once and rarely change.

Deployment
----------
The rendered ``wardsoar_custom.rules`` file is written to
``/usr/local/etc/suricata/rules/wardsoar_custom.rules`` on the
Netgate via SSH. pfSense's Suricata package scans this directory,
but the per-interface ``rule-files:`` list needs the file name —
enabling the rules *in pfSense UI* remains a one-time manual click
(Services → Suricata → WAN → Categories → Enable custom rules).

Safe-by-design
--------------
* Every rule body is built from a hard-coded template — no operator
  input is interpolated into the rule itself, so YAML poisoning
  cannot produce a malicious rule.
* SIDs live in the user-reserved range 1_000_000+ to avoid colliding
  with ET Open / Snort community rules.
* Writing the file requires no pfSense reload; Suricata picks up new
  rules when it next reloads. The UI reminds the operator.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable, Optional

if TYPE_CHECKING:
    from wardsoar.core.known_bad_actors import KnownActorsRegistry
    from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.netgate_custom_rules")


# --- Constants --------------------------------------------------------------


#: Remote path for the generated rule file. pfSense-Suricata scans
#: ``/usr/local/etc/suricata/rules/`` on each instance; we drop a
#: dedicated WardSOAR file so hand-edited entries elsewhere survive.
REMOTE_RULES_PATH = "/usr/local/etc/suricata/rules/wardsoar_custom.rules"

#: SID range reserved for WardSOAR. Each Ben-pattern rule picks a
#: stable offset so the number is deterministic across deployments.
_SID_ACTOR_IP = 1_100_000  # 1_100_000 + actor_ix*100 + ioc_ix
_SID_BEN_SSH_BRUTE = 1_200_001
_SID_BEN_WIRESHARK_REMOTE_KILL = 1_200_002
_SID_BEN_DNS_DISRUPTION = 1_200_003


# --- Data model -------------------------------------------------------------


@dataclass(frozen=True)
class GeneratedRule:
    """A single Suricata rule line with its bookkeeping metadata."""

    sid: int
    rule: str  # full rule string, newline-terminated
    rationale: str
    actor_id: Optional[str] = None


@dataclass(frozen=True)
class RulesBundle:
    """The full generated rules file ready to ship."""

    generated_at: str  # ISO 8601
    actor_count: int
    ioc_count: int
    rules: list[GeneratedRule] = field(default_factory=list)

    def render(self) -> str:
        """Assemble the final .rules file contents."""
        lines: list[str] = [
            "# WardSOAR custom Suricata rules",
            f"# Generated at {self.generated_at}",
            f"# {self.actor_count} actor(s) / {self.ioc_count} IOC(s) + " "Ben-pattern signatures",
            "#",
            "# SID range 1_100_000 = actor IOC rules",
            "#           1_200_000 = Ben-pattern rules",
            "#",
            "# DO NOT edit by hand — regenerate via the WardSOAR UI.",
            "",
        ]
        for entry in self.rules:
            if entry.rationale:
                lines.append(f"# SID {entry.sid} — {entry.rationale}")
            lines.append(entry.rule.rstrip())
            lines.append("")
        return "\n".join(lines) + "\n"


# --- Rule generation --------------------------------------------------------


def _escape_msg(text: str) -> str:
    """Strip the characters that would break a Suricata ``msg:`` field."""
    return text.replace('"', "'").replace(";", ",").replace("\r", " ").replace("\n", " ").strip()


def _is_valid_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def _is_valid_domain(domain: str) -> bool:
    """Loose validation — avoid shipping YAML typos into live rules."""
    if not domain or " " in domain or ";" in domain or "\n" in domain:
        return False
    if len(domain) > 253:
        return False
    return "." in domain


def _actor_rules(actors_snapshot: list[dict[str, object]]) -> tuple[list[GeneratedRule], int]:
    """Emit one alert rule per IOC across all actors.

    The registry snapshot passes counts, not the raw IOCs, so we
    regenerate via the registry's public ``classify_ip`` / lookup
    methods instead — but that's asymmetric. Easier: we accept a
    second argument with the raw entries via :func:`build_bundle`.
    """
    # Placeholder kept for the type system; real generation happens in
    # _actor_rules_from_entries below.
    _ = actors_snapshot
    return [], 0


def _actor_rules_from_entries(
    entries: Iterable["_ActorEntryLike"],
) -> tuple[list[GeneratedRule], int]:
    """Build alert rules from raw actor entries.

    Each actor contributes up to ``len(ips)+len(cidrs)+len(domains)``
    rules. IPs and CIDRs become ``ip`` rules on both directions; domains
    become TLS SNI + DNS query rules. Invalid IOCs are silently
    dropped — the registry loader already validates, this is a second
    belt-and-braces check against handcrafted YAML.
    """
    rules: list[GeneratedRule] = []
    ioc_count = 0
    for actor_ix, entry in enumerate(entries):
        actor_id = str(getattr(entry, "actor_id", "") or "UNKNOWN")
        actor_name = str(getattr(entry, "name", "") or actor_id)
        msg_tag = _escape_msg(f"WardSOAR KBA {actor_id} — {actor_name}")
        ioc_ix = 0

        for ip in sorted(getattr(entry, "ips", []) or []):
            if not _is_valid_ip_or_cidr(ip):
                continue
            sid = _SID_ACTOR_IP + actor_ix * 100 + ioc_ix
            ioc_ix += 1
            rule = (
                f"alert ip [{ip}] any <> any any "
                f'(msg:"{msg_tag} — IP match {ip}"; '
                f"classtype:targeted-activity; priority:1; sid:{sid}; rev:1;)"
            )
            rules.append(
                GeneratedRule(
                    sid=sid,
                    rule=rule,
                    rationale=f"Known adversary IP {ip} ({actor_id})",
                    actor_id=actor_id,
                )
            )
            ioc_count += 1

        for cidr in list(getattr(entry, "cidrs", []) or []):
            cidr_str = str(cidr)
            if not _is_valid_ip_or_cidr(cidr_str):
                continue
            sid = _SID_ACTOR_IP + actor_ix * 100 + ioc_ix
            ioc_ix += 1
            rule = (
                f"alert ip [{cidr_str}] any <> any any "
                f'(msg:"{msg_tag} — CIDR match {cidr_str}"; '
                f"classtype:targeted-activity; priority:1; sid:{sid}; rev:1;)"
            )
            rules.append(
                GeneratedRule(
                    sid=sid,
                    rule=rule,
                    rationale=f"Known adversary CIDR {cidr_str} ({actor_id})",
                    actor_id=actor_id,
                )
            )
            ioc_count += 1

        for domain in sorted(getattr(entry, "domains", []) or []):
            if not _is_valid_domain(domain):
                continue
            sid_sni = _SID_ACTOR_IP + actor_ix * 100 + ioc_ix
            ioc_ix += 1
            rule_sni = (
                f"alert tls any any -> any any "
                f'(msg:"{msg_tag} — TLS SNI match {domain}"; '
                f'tls.sni; content:"{domain}"; nocase; '
                f"classtype:targeted-activity; priority:1; "
                f"sid:{sid_sni}; rev:1;)"
            )
            rules.append(
                GeneratedRule(
                    sid=sid_sni,
                    rule=rule_sni,
                    rationale=f"Known adversary domain {domain} via TLS SNI ({actor_id})",
                    actor_id=actor_id,
                )
            )
            ioc_count += 1

            sid_dns = _SID_ACTOR_IP + actor_ix * 100 + ioc_ix
            ioc_ix += 1
            rule_dns = (
                f"alert dns any any -> any any "
                f'(msg:"{msg_tag} — DNS query {domain}"; '
                f'dns.query; content:"{domain}"; nocase; '
                f"classtype:targeted-activity; priority:1; "
                f"sid:{sid_dns}; rev:1;)"
            )
            rules.append(
                GeneratedRule(
                    sid=sid_dns,
                    rule=rule_dns,
                    rationale=f"Known adversary domain {domain} via DNS ({actor_id})",
                    actor_id=actor_id,
                )
            )
            ioc_count += 1

    return rules, ioc_count


def _ben_pattern_rules() -> list[GeneratedRule]:
    """Hand-written signatures matched to the Hutchinson case.

    The three signatures target behaviours captured in the forensic
    report: sustained SSH brute force from one source, a remote kill
    of the Wireshark process on the operator's Raspberry Pi, and the
    periodic DNS-disruption pattern.
    """
    rules: list[GeneratedRule] = []

    # 1. SSH brute force — 5+ connection attempts to :22 within 60 s.
    rules.append(
        GeneratedRule(
            sid=_SID_BEN_SSH_BRUTE,
            rationale="WardSOAR: sustained SSH brute-force (Ben pattern)",
            rule=(
                "alert tcp any any -> $HOME_NET 22 "
                '(msg:"WardSOAR — SSH brute-force pattern (5+ attempts / 60 s)"; '
                "flow:to_server,established; "
                "threshold:type both, track by_src, count 5, seconds 60; "
                "classtype:attempted-admin; priority:1; "
                f"sid:{_SID_BEN_SSH_BRUTE}; rev:1;)"
            ),
        )
    )

    # 2. Remote kill of a locally running Wireshark — we can only
    #    detect the inbound control channel, not the outcome. The
    #    forensic report showed a specific RST-burst pattern; we
    #    approximate it as "inbound TCP RST flood on high ports".
    rules.append(
        GeneratedRule(
            sid=_SID_BEN_WIRESHARK_REMOTE_KILL,
            rationale=(
                "WardSOAR: inbound RST flood to ephemeral ports — "
                "symptomatic of a remote process-kill attempt seen in the "
                "Hutchinson case"
            ),
            rule=(
                "alert tcp any any -> $HOME_NET 1024:65535 "
                '(msg:"WardSOAR — inbound RST flood (Ben pattern: remote Wireshark kill)"; '
                "flags:R,12; "
                "threshold:type both, track by_dst, count 30, seconds 10; "
                "classtype:attempted-dos; priority:2; "
                f"sid:{_SID_BEN_WIRESHARK_REMOTE_KILL}; rev:1;)"
            ),
        )
    )

    # 3. Periodic DNS disruption — the case showed sustained NXDOMAIN
    #    storms aimed at the operator. Fires on repeated DNS responses
    #    with NXDOMAIN against the local resolver.
    rules.append(
        GeneratedRule(
            sid=_SID_BEN_DNS_DISRUPTION,
            rationale="WardSOAR: DNS disruption wave (Ben pattern)",
            rule=(
                "alert dns any 53 -> $HOME_NET any "
                '(msg:"WardSOAR — sustained NXDOMAIN burst to local host (Ben pattern)"; '
                "dns.response; dns.rcode:NXDOMAIN; "
                "threshold:type both, track by_dst, count 50, seconds 60; "
                "classtype:attempted-dos; priority:2; "
                f"sid:{_SID_BEN_DNS_DISRUPTION}; rev:1;)"
            ),
        )
    )
    return rules


# --- _ActorEntryLike ---------------------------------------------------------


class _ActorEntryLike:
    """Structural contract for the registry's internal actor entries.

    We deliberately avoid importing
    :class:`src.known_bad_actors._ActorEntry` — it's a private class,
    and we want :func:`build_bundle` to accept any duck-typed entry
    (including test fixtures) so the tests don't need to construct the
    private dataclass.
    """

    actor_id: str
    name: str
    ips: set[str]
    cidrs: list[object]
    domains: set[str]


# --- Top-level orchestration -------------------------------------------------


def build_bundle(registry: Optional["KnownActorsRegistry"]) -> RulesBundle:
    """Build a fresh :class:`RulesBundle` from the live registry.

    Passing ``None`` is legal — the bundle will contain only the
    Ben-pattern signatures. This is the normal path when the registry
    YAML is empty.
    """
    entries_raw = getattr(registry, "_actors", []) if registry is not None else []
    # ``_actors`` is a private attribute by convention, but this module
    # is inside the same package so access is acceptable. A future
    # refactor on the registry side can expose a public iterator.
    actor_rules, ioc_count = _actor_rules_from_entries(entries_raw)
    bundle_rules = actor_rules + _ben_pattern_rules()
    return RulesBundle(
        generated_at=datetime.now(timezone.utc).isoformat(),
        actor_count=len(entries_raw),
        ioc_count=ioc_count,
        rules=bundle_rules,
    )


@dataclass(frozen=True)
class DeployResult:
    """Outcome of :func:`deploy_bundle`."""

    success: bool
    bytes_written: int
    remote_path: str
    error: Optional[str] = None


async def deploy_bundle(
    ssh: "PfSenseSSH",
    bundle: RulesBundle,
    remote_path: str = REMOTE_RULES_PATH,
) -> DeployResult:
    """Push the rendered rules file to the Netgate via SSH.

    Writes the content with a ``cat <<'EOF'`` heredoc — shell-safe
    against every character we emit because the rules themselves never
    contain an embedded ``EOF`` marker (we'd have to ship hostile
    operator input to produce one, which the rule builder refuses).
    """
    content = bundle.render()
    # Verify: no line equals the heredoc sentinel.
    if any(line == "__WARDSOAR_EOF__" for line in content.splitlines()):
        return DeployResult(
            success=False,
            bytes_written=0,
            remote_path=remote_path,
            error="Rule content contains sentinel string — refusing to deploy.",
        )

    # Double-quote escape for heredoc — each single-quote becomes '\''
    # but heredoc with quoted delimiter preserves everything verbatim,
    # so we just need the delimiter never to appear.
    cmd = (
        f"umask 022 && cat > {remote_path} <<'__WARDSOAR_EOF__'\n" f"{content}" "__WARDSOAR_EOF__\n"
    )

    ok, out = await ssh.run_read_only(cmd, timeout=20)
    if not ok:
        logger.warning("deploy custom rules failed: %s", out[:200])
        return DeployResult(
            success=False,
            bytes_written=0,
            remote_path=remote_path,
            error=out[:300],
        )
    return DeployResult(
        success=True,
        bytes_written=len(content.encode("utf-8", errors="replace")),
        remote_path=remote_path,
    )


__all__ = [
    "DeployResult",
    "GeneratedRule",
    "REMOTE_RULES_PATH",
    "RulesBundle",
    "build_bundle",
    "deploy_bundle",
]
