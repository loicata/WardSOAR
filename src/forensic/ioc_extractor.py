"""Extract Indicators of Compromise from captured evidence.

The IOC extractor walks the DecisionRecord and the quick-acquisition
artefacts and produces a normalised list of observables usable by
downstream tools (MISP, TAXII, SOAR playbooks). Output schema is
modelled on STIX 2.1 — the community standard for IOC exchange — but
we emit a simplified subset focused on the fields every SOC consumes:
    ipv4-addr, ipv6-addr, domain-name, url, email-addr,
    file (name + hashes), network-traffic.

The extractor is **pure**: no I/O, no network. Callers hand it
structured data (already deserialised from JSON); it returns Python
dicts that the reporting module serialises.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import timezone
from typing import Any, Iterable, Optional

from src.models import (
    DecisionRecord,
    ForensicResult,
    NetworkContext,
    SuricataAlert,
    VirusTotalResult,
)

# Lightweight regexes for text harvesting. We stay conservative to
# avoid false positives; the IOCs we miss can still be added by hand.
_DOMAIN_RE = re.compile(
    r"\b(?=[A-Za-z0-9-]{1,63}\.)(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


def _stix_id(type_: str) -> str:
    """Build a STIX-like identifier: ``<type>--<uuid4>``."""
    return f"{type_}--{uuid.uuid4()}"


def _is_public_ip(ip: str) -> bool:
    """Return True if ``ip`` is a routable public address.

    Used to avoid polluting the IOC list with LAN / link-local / loopback.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


class IocExtractor:
    """Produce STIX 2.1-flavoured observables from a DecisionRecord.

    The extractor is intentionally forgiving: it will skip malformed
    entries rather than raise, so a single bad line in forensic data
    cannot abort the whole export.
    """

    def __init__(self, include_private_ips: bool = False) -> None:
        self._include_private_ips = include_private_ips

    def extract(self, record: DecisionRecord) -> list[dict[str, Any]]:
        """Main entry point.

        Args:
            record: Decision record produced by the pipeline for the alert.

        Returns:
            List of observable dicts. Each dict is self-contained and
            matches the STIX 2.1 SCO shape (type + fields).
        """
        observables: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def _add(obj: dict[str, Any]) -> None:
            key = (obj["type"], _dedup_key(obj))
            if key in seen:
                return
            seen.add(key)
            observables.append(obj)

        self._from_alert(record.alert, _add)
        if record.network_context is not None:
            self._from_network_context(record.network_context, _add)
        if record.forensic_result is not None:
            self._from_forensic_result(record.forensic_result, _add)
        for vt in record.virustotal_results or []:
            self._from_vt(vt, _add)

        return observables

    # ------------------------------------------------------------------
    # Per-source harvesters
    # ------------------------------------------------------------------

    def _from_alert(self, alert: SuricataAlert, add: Any) -> None:
        """Source + destination IPs, destination port as network-traffic."""
        for ip in (alert.src_ip, alert.dest_ip):
            self._emit_ip(ip, add, source="suricata_alert")

        add(
            {
                "type": "network-traffic",
                "id": _stix_id("network-traffic"),
                "protocols": [alert.proto.lower()],
                "src_ref": alert.src_ip,
                "dst_ref": alert.dest_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dest_port,
                "first_observed": alert.timestamp.astimezone(timezone.utc).isoformat(),
                "_source": "suricata_alert",
            }
        )

    def _from_network_context(self, ctx: NetworkContext, add: Any) -> None:
        """DNS/ARP text fields are regex-harvested."""
        # ip_reputation → an observable if present
        rep = getattr(ctx, "ip_reputation", None)
        if rep is not None and getattr(rep, "ip", None):
            self._emit_ip(str(rep.ip), add, source="ip_reputation")

        # DNS cache / ARP cache are lists of dicts with a "raw" text line.
        for field_name in ("dns_cache", "arp_cache"):
            entries = getattr(ctx, field_name, []) or []
            for entry in entries:
                raw = entry.get("raw", "") if isinstance(entry, dict) else ""
                self._harvest_text(raw, add, source=field_name)

        # Active connections → (ip, port) tuples.
        for conn in getattr(ctx, "active_connections", []) or []:
            if not isinstance(conn, dict):
                continue
            ip = conn.get("remote_ip") or conn.get("raddr") or ""
            if ip:
                self._emit_ip(str(ip), add, source="net_connections")

    def _from_forensic_result(self, fr: ForensicResult, add: Any) -> None:
        """Process executables + suspicious files → file observables.

        SysmonEvent / windows_events may carry plaintext that contains
        URLs and domains (e.g. PowerShell command lines); the harvester
        scans those too.
        """
        for proc in getattr(fr, "suspect_processes", []) or []:
            if not isinstance(proc, dict):
                continue
            exe_path = proc.get("exe")
            name = proc.get("name")
            if exe_path or name:
                add(
                    {
                        "type": "file",
                        "id": _stix_id("file"),
                        "name": name or "",
                        "path": exe_path or "",
                        "_source": "process",
                    }
                )

        for sf in getattr(fr, "suspicious_files", []) or []:
            if not isinstance(sf, dict):
                continue
            path = sf.get("path")
            if path:
                add(
                    {
                        "type": "file",
                        "id": _stix_id("file"),
                        "name": path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
                        "path": path,
                        "size": sf.get("size"),
                        "_source": "suspicious_files",
                    }
                )

        # Free text in Sysmon / windows event messages.
        for field_name in ("sysmon_events", "windows_events"):
            events = getattr(fr, field_name, []) or []
            for ev in events:
                raw = ""
                if isinstance(ev, dict):
                    raw = str(ev.get("Message") or ev.get("description") or "")
                else:
                    raw = str(getattr(ev, "description", "") or "")
                if raw:
                    self._harvest_text(raw, add, source=field_name)

    def _from_vt(self, vt: VirusTotalResult, add: Any) -> None:
        """A VirusTotal hit always contributes a file observable + hash."""
        add(
            {
                "type": "file",
                "id": _stix_id("file"),
                "name": vt.file_name or "",
                "hashes": {"SHA-256": vt.file_hash},
                "x_verdict": {
                    "malicious": vt.is_malicious,
                    "detection_count": vt.detection_count,
                    "total_engines": vt.total_engines,
                    "labels": list(vt.threat_labels),
                    "scanner": vt.lookup_type,
                },
                "_source": vt.lookup_type,
            }
        )

    # ------------------------------------------------------------------
    # Low-level emitters
    # ------------------------------------------------------------------

    def _emit_ip(self, ip: str, add: Any, source: str) -> None:
        """Emit an ipv4-addr / ipv6-addr observable if the address qualifies."""
        if not ip:
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if not self._include_private_ips and not _is_public_ip(ip):
            return
        add(
            {
                "type": "ipv6-addr" if addr.version == 6 else "ipv4-addr",
                "id": _stix_id("ipv4-addr" if addr.version == 4 else "ipv6-addr"),
                "value": ip,
                "_source": source,
            }
        )

    def _harvest_text(self, text: str, add: Any, source: str) -> None:
        """Regex-scan a string for domains, URLs, emails, hashes."""
        for match in _URL_RE.findall(text):
            add({"type": "url", "id": _stix_id("url"), "value": match, "_source": source})
        for match in _DOMAIN_RE.findall(text):
            add(
                {
                    "type": "domain-name",
                    "id": _stix_id("domain-name"),
                    "value": match,
                    "_source": source,
                }
            )
        for match in _EMAIL_RE.findall(text):
            add(
                {
                    "type": "email-addr",
                    "id": _stix_id("email-addr"),
                    "value": match,
                    "_source": source,
                }
            )
        for match in _SHA256_RE.findall(text):
            add(
                {
                    "type": "file",
                    "id": _stix_id("file"),
                    "hashes": {"SHA-256": match.lower()},
                    "_source": source,
                }
            )
        for match in _MD5_RE.findall(text):
            # Avoid MD5 matches that are actually a substring of a SHA-256.
            if len(match) == 32 and not _SHA256_RE.search(match):
                add(
                    {
                        "type": "file",
                        "id": _stix_id("file"),
                        "hashes": {"MD5": match.lower()},
                        "_source": source,
                    }
                )


def _dedup_key(obj: dict[str, Any]) -> str:
    """Stable key for deduplication — ignores the STIX id (always unique)."""
    t = obj["type"]
    if t in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
        return str(obj.get("value", ""))
    if t == "file":
        sha = (obj.get("hashes") or {}).get("SHA-256")
        if sha:
            return f"sha256:{sha}"
        return f"path:{obj.get('path', '')}|name:{obj.get('name', '')}"
    if t == "network-traffic":
        return (
            f"{obj.get('src_ref')}:{obj.get('src_port')}->"
            f"{obj.get('dst_ref')}:{obj.get('dst_port')}/{obj.get('protocols')}"
        )
    return ""


def to_stix_bundle(observables: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Wrap observables in a STIX 2.1 Bundle envelope."""
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": list(observables),
    }


def to_csv(observables: Iterable[dict[str, Any]]) -> str:
    """Flatten observables into a simple CSV for Excel / grep."""
    rows = ["type,value,source"]
    for obj in observables:
        value: Optional[str]
        if obj["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
            value = str(obj.get("value", ""))
        elif obj["type"] == "file":
            sha = (obj.get("hashes") or {}).get("SHA-256") or (obj.get("hashes") or {}).get("MD5")
            value = sha or obj.get("path", "") or obj.get("name", "")
        elif obj["type"] == "network-traffic":
            value = (
                f"{obj.get('src_ref')}:{obj.get('src_port')}->"
                f"{obj.get('dst_ref')}:{obj.get('dst_port')}"
            )
        else:
            value = ""
        source = obj.get("_source", "")
        rows.append(f'{obj["type"]},"{value}",{source}')
    return "\n".join(rows) + "\n"
