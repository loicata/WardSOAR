"""Blocklist.de feed downloader.

Blocklist.de publishes a real-time feed of IPs actively brute-forcing
public honeypots on SSH, HTTP, Mail, IMAP, FTP and other protocols.
The feed is refreshed every minute; we pull it every 30 minutes,
which is the sweet spot between freshness and bandwidth.

Feed format: plain text, one IP per line, no header, no metadata.

Source: https://lists.blocklist.de/lists/all.txt
Refresh: every 30 minutes.
"""

from __future__ import annotations

import ipaddress

from wardsoar.core.intel.base import FeedEntry, FeedRegistry


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class BlocklistDeRegistry(FeedRegistry):
    """Blocklist.de — IPs currently brute-forcing public honeypots."""

    name = "blocklist_de"
    display_name = "Blocklist.de"
    url = "https://lists.blocklist.de/lists/all.txt"
    refresh_interval_s = 30 * 60  # 30 minutes

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        indicators: set[str] = set()
        for line in raw_text.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            if _is_ip(candidate):
                indicators.add(candidate)
        # Blocklist.de is a bare list without per-IP metadata; we
        # return a synthetic FeedEntry for each IP so the UI row can
        # quote a standard description.
        meta = {
            ip: FeedEntry(
                indicator=ip,
                kind="ip",
                category="brute_force",
                description="Recently brute-forced public honeypots (SSH / HTTP / Mail / ...)",
            )
            for ip in indicators
        }
        return indicators, meta
