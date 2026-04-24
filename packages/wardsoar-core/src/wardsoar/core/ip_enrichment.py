"""IP ownership and reputation enrichment for the Alert Detail view.

For every alert (filtered or analyzed), WardSOAR builds an
``IpEnrichment`` snapshot that the Alert Detail UI renders as the
"IP OWNERSHIP & REPUTATION" section. The snapshot aggregates four
sub-blocks:

* **Identity** — ASN, country, reverse DNS, Tor-exit flag,
  VPN/proxy flag.
* **External reputation** — one row per intelligence source, with
  a concise per-source verdict (score, classification, or
  "not listed"). Sources requiring API keys that the operator has
  not configured are simply omitted; auto-enabled feeds are always
  shown.
* **WardSOAR history** — first/last seen on this IP, total alerts,
  verdict breakdown, whether the IP was ever blocked.
* **WardSOAR classification** — CDN allowlist match, suspect ASN
  match, known-bad-actor match, final tier verdict.

The v0.10.0 aggregator wires the **local-only** sources: the ASN
enricher cache, reverse DNS (``socket.gethostbyaddr``), the Tor
exit registry, the CDN allowlist, the suspect ASN registry and the
known-bad-actor registry, plus a historical scan of
``alerts_history.jsonl``. External HTTP clients (VirusTotal,
AbuseIPDB, GreyNoise, ...) are **declared** in the dataclass but
left as ``None`` placeholders in 0.10.0; Phase 2 implements each
HTTP client with a shared cache layer.

Design rules
------------
1. No HTTP from within this module in 0.10.0. Every lookup is
   cache-only or local file I/O. Phase 2 adds a per-source async
   client that populates the same dataclass fields.
2. RFC 1918 / loopback / link-local / RFC 5735 special IPs are
   handled explicitly: we skip the external-reputation queries and
   mark the IP as "private / local".
3. Every failure inside the aggregator is caught and logged. The
   section is a convenience — it must never crash the pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from wardsoar.core.api_keys_registry import MANUAL_CHECKS

logger = logging.getLogger("ward_soar.ip_enrichment")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IpIdentity:
    """Who owns this IP and what kind of address is it."""

    asn: Optional[int] = None
    asn_name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    rdns: Optional[str] = None
    is_tor_exit: bool = False
    is_private: bool = False
    is_vpn_or_proxy: Optional[bool] = None  # None = unknown (no ipinfo pro key)


@dataclass(frozen=True)
class ReputationRow:
    """One per-source reputation verdict rendered in the UI list.

    ``level`` drives the emoji at the start of the row:
    ``"clean"`` → 🟢, ``"info"`` → 🔵, ``"warn"`` → 🟠,
    ``"bad"`` → 🔴, ``"unknown"`` → (no emoji, gray text).

    ``source_name`` matches the label rendered in the row.
    ``verdict`` is a short (≤ 80 chars) human-readable summary.
    """

    source_name: str
    level: str
    verdict: str


@dataclass(frozen=True)
class WardsoarHistory:
    """What WardSOAR has observed on this IP historically."""

    total_alerts: int = 0
    first_seen: Optional[str] = None  # ISO 8601
    last_seen: Optional[str] = None
    breakdown: dict[str, int] = field(default_factory=dict)
    ever_blocked: bool = False


@dataclass(frozen=True)
class WardsoarClassification:
    """How WardSOAR classifies this IP against its local lists."""

    cdn_match: Optional[str] = None  # "Fastly (category: cdn)" or None
    suspect_asn: Optional[str] = None  # "suspect" / "tor-exit" / None
    bad_actor_match: Optional[str] = None  # Label or None
    final_tier: str = "unknown"
    final_tier_reason: str = ""


@dataclass(frozen=True)
class IpEnrichment:
    """Full snapshot attached to one alert's ``_full`` dict.

    Rendered by ``alert_detail._populate_ip_ownership`` into the
    "IP OWNERSHIP & REPUTATION" section.
    """

    ip: str
    identity: IpIdentity
    reputation: list[ReputationRow]
    history: WardsoarHistory
    classification: WardsoarClassification
    manual_checks: list[dict[str, str]]  # [{name, url, relevance, description}]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for persistence."""
        return {
            "ip": self.ip,
            "identity": asdict(self.identity),
            "reputation": [asdict(r) for r in self.reputation],
            "history": asdict(self.history),
            "classification": asdict(self.classification),
            "manual_checks": list(self.manual_checks),
        }


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _categorise_ip(ip: str) -> tuple[bool, str]:
    """Decide whether the IP belongs to a special (non-routable) block.

    Returns ``(is_private, description)``. ``description`` is the
    short note that goes in the ``Identity`` block when
    ``is_private`` is ``True``.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (False, "")
    if addr.is_private:
        return (True, "RFC 1918 private network")
    if addr.is_loopback:
        return (True, "loopback")
    if addr.is_link_local:
        return (True, "link-local")
    if addr.is_multicast:
        return (True, "multicast")
    if addr.is_reserved:
        return (True, "reserved / special-use")
    return (False, "")


def _safe_rdns(ip: str, timeout_s: float = 1.5) -> Optional[str]:
    """Reverse DNS lookup with a short timeout and total isolation.

    Uses ``socket.gethostbyaddr``. Any failure returns ``None`` —
    the UI shows "no reverse DNS record".
    """
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_s)
        host, _aliases, _ips = socket.gethostbyaddr(ip)
        return host
    except (OSError, socket.herror, socket.gaierror):
        return None
    except Exception:  # noqa: BLE001 — defensive: lookups must not crash
        logger.debug("rDNS lookup for %s failed unexpectedly", ip, exc_info=True)
        return None
    finally:
        socket.setdefaulttimeout(prev)


def _manual_checks_for(ip: str) -> list[dict[str, str]]:
    """Return the 7 click-through manual-check URLs formatted for ``ip``.

    The UI renders them inside a collapsible sub-block of the
    reputation section.
    """
    rows: list[dict[str, str]] = []
    for mc in MANUAL_CHECKS:
        try:
            url = mc.url_template.format(ip=ip)
        except (KeyError, ValueError):
            # Safety net — a template without ``{ip}`` must still
            # render without crashing.
            url = mc.url_template
        rows.append(
            {
                "name": mc.name,
                "url": url,
                "relevance": mc.relevance,
                "description": mc.description,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def _scan_history(
    history_path: Optional[Path],
    ip: str,
) -> WardsoarHistory:
    """Scan alerts_history.jsonl for every row involving ``ip``.

    Either as ``src_ip`` or ``dest_ip``. Returns aggregate counts.
    The file is read line-by-line to keep memory bounded even on
    large histories. Failures produce a zeroed ``WardsoarHistory``
    rather than raising.
    """
    if not history_path or not history_path.exists():
        return WardsoarHistory()
    total = 0
    first: Optional[str] = None
    last: Optional[str] = None
    breakdown: dict[str, int] = {}
    ever_blocked = False
    try:
        with history_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("src_ip") != ip and row.get("dest_ip") != ip:
                    continue
                total += 1
                ts = row.get("_ts")
                if isinstance(ts, str):
                    if first is None or ts < first:
                        first = ts
                    if last is None or ts > last:
                        last = ts
                verdict = row.get("verdict") or "unknown"
                breakdown[verdict] = breakdown.get(verdict, 0) + 1
                actions = row.get("actions") or []
                if any(a in ("ip_block", "ip_port_block") for a in actions):
                    ever_blocked = True
    except OSError:
        logger.warning("Could not read %s for IP history", history_path, exc_info=True)
        return WardsoarHistory()
    return WardsoarHistory(
        total_alerts=total,
        first_seen=first,
        last_seen=last,
        breakdown=breakdown,
        ever_blocked=ever_blocked,
    )


def _final_tier(
    identity: IpIdentity,
    classification_hints: dict[str, Optional[str]],
) -> tuple[str, str]:
    """Compute the final reputation tier + human reason.

    Rules (first match wins):
    * Private / loopback / reserved → ``private_local``.
    * Known bad actor match → ``confirmed_bad``.
    * Suspect ASN match (no good countervailing signal) → ``suspect``.
    * CDN allowlist match → ``legit_cdn``.
    * Otherwise → ``unknown``.
    """
    if identity.is_private:
        return ("private_local", "Private / loopback / reserved range — no external lookup")
    if classification_hints.get("bad_actor_match"):
        return (
            "confirmed_bad",
            f"Known bad actor: {classification_hints['bad_actor_match']}",
        )
    if classification_hints.get("cdn_match"):
        return (
            "legit_cdn",
            f"CDN allowlist hit: {classification_hints['cdn_match']}",
        )
    if classification_hints.get("suspect_asn"):
        return (
            "suspect",
            f"Suspect ASN: {classification_hints['suspect_asn']}",
        )
    return ("unknown", "Insufficient signal")


async def build_ip_enrichment_async(
    ip: str,
    *,
    asn_cache_lookup: Optional[Any] = None,
    cdn_allowlist: Optional[Any] = None,
    suspect_asn_registry: Optional[Any] = None,
    bad_actor_registry: Optional[Any] = None,
    tor_exit_registry: Optional[Any] = None,
    intel_manager: Optional[Any] = None,
    history_path: Optional[Path] = None,
    do_rdns: bool = True,
) -> IpEnrichment:
    """Asynchronous counterpart of :func:`build_ip_enrichment`.

    v0.12.0: when ``intel_manager`` is provided, query BOTH the local
    registries AND every enabled HTTP API client concurrently via
    :meth:`IntelManager.query_all_for_ip_async`. On a cache hit the
    total wall time is still <5ms.

    The sync :func:`build_ip_enrichment` is kept for callers that
    don't have an event loop (e.g. unit tests, the Replay view);
    it queries feeds only.
    """
    # Delegate the sync part (identity, history, local classifiers).
    result = build_ip_enrichment(
        ip,
        asn_cache_lookup=asn_cache_lookup,
        cdn_allowlist=cdn_allowlist,
        suspect_asn_registry=suspect_asn_registry,
        bad_actor_registry=bad_actor_registry,
        tor_exit_registry=tor_exit_registry,
        intel_manager=None,  # Skip feeds here \u2014 we call the async path below.
        history_path=history_path,
        do_rdns=do_rdns,
    )
    if intel_manager is None or result.identity.is_private:
        return result

    # Query feeds + API clients concurrently.
    try:
        query_results = await intel_manager.query_all_for_ip_async(ip)
    except Exception:  # noqa: BLE001 \u2014 defensive
        logger.debug("IntelManager.query_all_for_ip_async failed", exc_info=True)
        query_results = []

    updated_reputation = [
        ReputationRow(
            source_name=qr.display_name,
            level=qr.level,
            verdict=qr.verdict,
        )
        for qr in query_results
    ]

    # v0.13.0 \u2014 enrich the Identity block with the ipinfo pro
    # privacy flag (VPN / proxy / Tor / hosting). Only runs when
    # the operator has configured the IPINFO_API_KEY.
    updated_identity = result.identity
    ipinfo_pro = getattr(intel_manager, "ipinfo_pro", None)
    if ipinfo_pro is not None and ipinfo_pro.is_enabled():
        import dataclasses as _dc

        try:
            flag = await ipinfo_pro.is_vpn_or_proxy(ip)
            if flag is not None:
                updated_identity = _dc.replace(result.identity, is_vpn_or_proxy=flag)
        except Exception:  # noqa: BLE001
            logger.debug("ipinfo_pro.is_vpn_or_proxy failed for %s", ip, exc_info=True)

    # Rebuild IpEnrichment with the async reputation list + possibly
    # updated identity; other fields stay as computed by the sync
    # helper.
    return IpEnrichment(
        ip=result.ip,
        identity=updated_identity,
        reputation=updated_reputation or result.reputation,
        history=result.history,
        classification=result.classification,
        manual_checks=result.manual_checks,
    )


def build_ip_enrichment(
    ip: str,
    *,
    asn_cache_lookup: Optional[Any] = None,
    cdn_allowlist: Optional[Any] = None,
    suspect_asn_registry: Optional[Any] = None,
    bad_actor_registry: Optional[Any] = None,
    tor_exit_registry: Optional[Any] = None,
    intel_manager: Optional[Any] = None,
    history_path: Optional[Path] = None,
    do_rdns: bool = True,
) -> IpEnrichment:
    """Assemble every locally-available signal for ``ip``.

    All dependencies are *injected* so the aggregator has no
    implicit globals and tests can feed stubs. Passing ``None``
    means "this source is unavailable in the current process" and
    the corresponding field stays ``None`` / empty list.

    Args:
        ip: The IP address to enrich (``str``).
        asn_cache_lookup: Callable ``ip -> AsnInfo | None`` that
            returns a cached ASN record when available. The v0.10.0
            wire uses ``AsnEnricher.lookup_cached``.
        cdn_allowlist: A :class:`CdnAllowlist` instance.
        suspect_asn_registry: A :class:`SuspectAsnRegistry` instance.
        bad_actor_registry: A :class:`KnownActorsRegistry` instance.
        tor_exit_registry: A :class:`TorExitFetcher` or any object
            exposing ``contains(ip) -> bool``.
        history_path: Absolute path to ``alerts_history.jsonl``.
        do_rdns: When ``False``, the reverse-DNS lookup is skipped.
            Used by tests (offline) and by the aggregator when a
            prior call already populated the cache.

    Returns:
        A fully-populated :class:`IpEnrichment` snapshot. Missing
        signals translate to ``None`` fields / empty collections —
        the UI renders a caption for those rather than crashing.
    """
    # --- Identity ---------------------------------------------------
    is_private, _private_note = _categorise_ip(ip)

    asn: Optional[int] = None
    asn_name: Optional[str] = None
    country: Optional[str] = None
    if not is_private and asn_cache_lookup is not None:
        try:
            info = asn_cache_lookup(ip)
            if info is not None:
                asn = getattr(info, "asn", None)
                asn_name = getattr(info, "name", None) or getattr(info, "org", None)
                country = getattr(info, "country", None)
        except Exception:  # noqa: BLE001 — defensive
            logger.debug("ASN cache lookup failed for %s", ip, exc_info=True)

    rdns = _safe_rdns(ip) if (do_rdns and not is_private) else None

    is_tor_exit = False
    if tor_exit_registry is not None and not is_private:
        try:
            if hasattr(tor_exit_registry, "contains"):
                is_tor_exit = bool(tor_exit_registry.contains(ip))
            elif hasattr(tor_exit_registry, "__contains__"):
                is_tor_exit = ip in tor_exit_registry
        except Exception:  # noqa: BLE001 — defensive
            logger.debug("Tor exit lookup failed for %s", ip, exc_info=True)

    identity = IpIdentity(
        asn=asn,
        asn_name=asn_name,
        country=country,
        city=None,  # 0.10.0: not captured; ipinfo response only has country
        rdns=rdns,
        is_tor_exit=is_tor_exit,
        is_private=is_private,
        is_vpn_or_proxy=None,  # phase 2: populated by ipinfo pro tier
    )

    # --- External reputation (0.10.0: auto-enabled + local classifiers) -----
    reputation: list[ReputationRow] = []

    # Classifier rows first — derived locally, always populated.
    cdn_match_label: Optional[str] = None
    suspect_label: Optional[str] = None
    bad_actor_label: Optional[str] = None

    if cdn_allowlist is not None and not is_private:
        try:
            match = cdn_allowlist.classify_asn(asn)
            if match is not None:
                cdn_match_label = f"{getattr(match, 'organisation', 'unknown')} (category: {getattr(match, 'category', 'cdn')})"
        except Exception:  # noqa: BLE001
            logger.debug("CDN allowlist lookup failed for %s", ip, exc_info=True)

    if suspect_asn_registry is not None and not is_private:
        try:
            classification = suspect_asn_registry.classify(ip, None)
            tier = getattr(classification, "tier", None)
            if tier and tier != "legitimate":
                suspect_label = tier
        except Exception:  # noqa: BLE001
            logger.debug("Suspect ASN lookup failed for %s", ip, exc_info=True)

    if bad_actor_registry is not None and not is_private:
        try:
            match = bad_actor_registry.classify_ip(ip)
            if match is not None:
                bad_actor_label = getattr(match, "label", str(match))
        except Exception:  # noqa: BLE001
            logger.debug("Bad-actor lookup failed for %s", ip, exc_info=True)

    # v0.11.0 — Phase 2a wires the IntelManager. Each registry
    # contributes one row. RFC 1918 / loopback / reserved IPs still
    # skip the external lookups (nothing internal would show up in
    # abuse.ch or Blocklist.de).
    if intel_manager is not None and not is_private:
        try:
            for qr in intel_manager.query_all_for_ip(ip):
                reputation.append(
                    ReputationRow(
                        source_name=qr.display_name,
                        level=qr.level,
                        verdict=qr.verdict,
                    )
                )
        except Exception:  # noqa: BLE001 — defensive
            logger.debug("IntelManager.query_all_for_ip failed for %s", ip, exc_info=True)
    elif is_private:
        # Keep the UI honest: show that we deliberately skipped
        # external lookups for a private range.
        reputation.append(
            ReputationRow(
                source_name="External feeds",
                level="unknown",
                verdict="Skipped (IP is in a private/loopback range)",
            )
        )

    classification_hints = {
        "cdn_match": cdn_match_label,
        "suspect_asn": suspect_label,
        "bad_actor_match": bad_actor_label,
    }
    final_tier, final_reason = _final_tier(identity, classification_hints)
    classification = WardsoarClassification(
        cdn_match=cdn_match_label,
        suspect_asn=suspect_label,
        bad_actor_match=bad_actor_label,
        final_tier=final_tier,
        final_tier_reason=final_reason,
    )

    history = _scan_history(history_path, ip)

    return IpEnrichment(
        ip=ip,
        identity=identity,
        reputation=reputation,
        history=history,
        classification=classification,
        manual_checks=_manual_checks_for(ip),
    )


def iso_to_human_delta(iso_ts: Optional[str]) -> str:
    """Format an ISO timestamp as "YYYY-MM-DD HH:MM UTC (N days ago)".

    Safe for use in the UI — ``None`` returns the empty string.
    """
    if not iso_ts:
        return ""
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta_days = max(0, (now - dt).days)
    ago = "today" if delta_days == 0 else f"{delta_days} day{'s' if delta_days > 1 else ''} ago"
    return f"{dt.strftime('%Y-%m-%d %H:%M UTC')} ({ago})"


__all__ = [
    "IpEnrichment",
    "IpIdentity",
    "ReputationRow",
    "WardsoarClassification",
    "WardsoarHistory",
    "build_ip_enrichment",
    "build_ip_enrichment_async",
    "iso_to_human_delta",
]
