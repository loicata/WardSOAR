"""Feodo Tracker (abuse.ch) feed downloader.

Feodo Tracker is abuse.ch's specialised feed of command-and-control
IPs for banking-trojan families: Emotet, TrickBot, QakBot, Dridex,
BazarLoader, Heodo, IcedID. Every IP in the feed has been observed
hosting a botnet C&C within the last 30 days — a very strong signal
for blocking.

Feed: https://feodotracker.abuse.ch/downloads/ipblocklist.json
Refresh: hourly.
"""

from __future__ import annotations

import ipaddress
import json
import logging

from wardsoar.core.intel.base import FeedEntry, FeedRegistry

logger = logging.getLogger("ward_soar.intel.feodo_tracker")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class FeodoTrackerRegistry(FeedRegistry):
    """abuse.ch Feodo Tracker — banking botnet C&C IPs."""

    name = "feodo_tracker"
    display_name = "Feodo Tracker"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    refresh_interval_s = 3600

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        try:
            rows = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.warning("feodo_tracker: invalid JSON")
            return set(), {}
        if not isinstance(rows, list):
            return set(), {}

        indicators: set[str] = set()
        meta: dict[str, FeedEntry] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = str(row.get("ip_address") or "")
            if not _is_ip(ip):
                continue
            malware = row.get("malware") or "unknown"
            port = row.get("port")
            indicators.add(ip)
            meta[ip] = FeedEntry(
                indicator=ip,
                kind="ip",
                category="botnet_cc",
                first_seen=str(row.get("first_seen") or ""),
                description=(
                    f"Banking botnet C&C: {malware}" + (f" (port {port})" if port else "")
                ),
                raw={
                    "malware": malware,
                    "port": port,
                    "status": row.get("status"),
                },
            )
        return indicators, meta
