"""URLhaus (abuse.ch) feed downloader.

URLhaus is the authoritative public database of malware-serving
URLs operated by abuse.ch. We download the ``csv_recent`` feed
(last 30 days, updated every 5 minutes) and extract the **hostname
or bare IP** from each URL so the aggregator can flag any alert
whose destination IP has recently served malware.

Feed format: CSV with a ``# Header`` line, then per-row:
    ``id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter``

Source: https://urlhaus.abuse.ch/downloads/csv_recent/
Refresh: hourly (the feed updates every 5 min, hourly is plenty).
"""

from __future__ import annotations

import csv
import io
import ipaddress
from typing import Optional
from urllib.parse import urlparse

from src.intel.base import FeedEntry, FeedRegistry


def _extract_host(url: str) -> Optional[str]:
    """Extract the bare hostname/IP from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host and host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class URLhausRegistry(FeedRegistry):
    """abuse.ch URLhaus — malware URL distribution tracker."""

    name = "urlhaus"
    display_name = "URLhaus"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    refresh_interval_s = 3600  # 1h

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        indicators: set[str] = set()
        meta: dict[str, FeedEntry] = {}

        # URLhaus CSV is prefixed with comment lines starting with ``#``.
        stripped = "\n".join(line for line in raw_text.splitlines() if not line.startswith("#"))
        reader = csv.reader(io.StringIO(stripped))
        for row in reader:
            if len(row) < 7:
                continue
            _id, date_added, url, status, _last_online, threat, tags = row[:7]
            host = _extract_host(url)
            if not host or not _is_ip(host):
                # URLhaus serves domains mostly; we only index
                # entries whose host resolves to a bare IP so the
                # aggregator can do an O(1) IP match. Domain matching
                # is a separate concern (URL-focused alerts are
                # uncommon on IDS flows).
                continue
            indicators.add(host)
            meta[host] = FeedEntry(
                indicator=host,
                kind="ip",
                category=threat or "malware_url",
                first_seen=date_added,
                description=f"Serves malware URL ({tags})" if tags else "Serves a malware URL",
                raw={"url": url, "status": status},
            )
        return indicators, meta
