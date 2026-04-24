"""ThreatFox (abuse.ch) feed downloader.

ThreatFox is abuse.ch's IOC exchange: IPs, URLs, and hashes tied to
active malware / APT / botnet C&C infrastructure. We consume the
``recent`` JSON export which covers the last ~3 days of submissions.

Endpoint: https://threatfox-api.abuse.ch/api/v1/ with
``{"query": "get_iocs", "days": 3}``. The public dump at
https://threatfox.abuse.ch/export/json/recent/ returns the same data
without requiring an auth token and is easier to parse from a MSI
install without a key.

Refresh: hourly.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from wardsoar.core.intel.base import FeedEntry, FeedRegistry

logger = logging.getLogger("ward_soar.intel.threatfox")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class ThreatFoxRegistry(FeedRegistry):
    """abuse.ch ThreatFox — live IOC feed for active threats."""

    name = "threatfox"
    display_name = "ThreatFox"
    url = "https://threatfox.abuse.ch/export/json/recent/"
    refresh_interval_s = 3600

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.warning("threatfox: invalid JSON from %s", self.url)
            return set(), {}

        indicators: set[str] = set()
        meta: dict[str, FeedEntry] = {}

        # The public dump is a dict keyed by submission timestamp;
        # each value is a list of IOC records. Normalise to a flat
        # list so mypy sees a single iterator type.
        iocs: list[Any] = []
        if isinstance(payload, dict):
            for group in payload.values():
                if isinstance(group, list):
                    iocs.extend(group)
        elif isinstance(payload, list):
            iocs.extend(payload)
        else:
            return set(), {}

        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
            # The public dump names the indicator ``ioc_value`` (seen
            # 2026-04-24). Earlier revisions of this parser looked for
            # ``ioc`` / ``indicator``, which matched nothing against
            # the current schema — every refresh cycle yielded
            # "refreshed 0 indicators" in ward_soar.log while feeds
            # like blocklist_de kept growing. Accept the current key
            # first and fall back to the legacy names so an API
            # rollback does not silently re-break the parser.
            ioc_value = str(ioc.get("ioc_value") or ioc.get("ioc") or ioc.get("indicator") or "")
            ioc_type = str(ioc.get("ioc_type") or "")

            # ThreatFox IP entries carry ``ioc_type = "ip:port"`` and
            # the port is part of ``ioc_value``. Keep only the host
            # portion for the blocklist; the port is preserved in
            # ``raw`` for forensic traceability.
            candidate = ioc_value.split(":", 1)[0]
            if not _is_ip(candidate):
                continue
            indicators.add(candidate)
            meta[candidate] = FeedEntry(
                indicator=candidate,
                kind="ip",
                category=str(ioc.get("threat_type") or "ioc"),
                # The field was renamed ``first_seen_utc`` server-side
                # while we kept the legacy ``first_seen`` read. Prefer
                # the new name; fall back to the old one.
                first_seen=str(ioc.get("first_seen_utc") or ioc.get("first_seen") or ""),
                description=(
                    f"{ioc.get('malware_printable') or ioc.get('malware') or 'Active IOC'}"
                    f" — {ioc_type}"
                ),
                raw={"ioc_value": ioc_value, "confidence": ioc.get("confidence_level")},
            )
        return indicators, meta
