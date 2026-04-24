"""FireHOL IP Lists aggregator downloader.

FireHOL maintains a curated aggregation of ~100 free reputation
feeds on GitHub at ``firehol/blocklist-ipsets``. We pull a single
composite list named ``firehol_level1`` which combines the highest-
confidence lists (Spamhaus DROP, DShield, Team Cymru bogons, CI Army,
...) into one file refreshed continuously by the FireHOL team.

Why pull level1 rather than every individual list:
  * level1 is the safest for automated blocking — very few false
    positives — which matches WardSOAR's use case (reputation
    signal, not enforcement).
  * Aggregating ~100 lists ourselves would multiply the maintenance
    cost and bandwidth use.

Feed format: plain text with comment lines starting with ``#``, then
one IP or CIDR per line. We accept both.

Source: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
Refresh: daily.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from wardsoar.core.intel.base import FeedEntry, FeedRegistry

logger = logging.getLogger("ward_soar.intel.firehol")


class FireHolRegistry(FeedRegistry):
    """FireHOL level1 \u2014 aggregator of ~100 high-confidence reputation feeds."""

    name = "firehol"
    display_name = "FireHOL"
    url = (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/" "firehol_level1.netset"
    )
    refresh_interval_s = 24 * 3600  # daily

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._networks: list[ipaddress.IPv4Network] = []
        self._rehydrate_networks()

    def _rehydrate_networks(self) -> None:
        parsed: list[ipaddress.IPv4Network] = []
        for entry in self._indicators:
            try:
                parsed.append(ipaddress.IPv4Network(entry, strict=False))
            except (ValueError, ipaddress.NetmaskValueError):
                continue
        self._networks = parsed

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        indicators: set[str] = set()
        for line in raw_text.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            try:
                ipaddress.IPv4Network(candidate, strict=False)
            except (ValueError, ipaddress.NetmaskValueError):
                continue
            indicators.add(candidate)
        # FireHOL level1 does not expose per-entry metadata at the
        # aggregation level \u2014 the original provenance is attached
        # to the source feeds not the aggregator. We attach a
        # generic description for every entry.
        meta = {
            entry: FeedEntry(
                indicator=entry,
                kind="network",
                category="aggregate_blocklist",
                description=(
                    "Listed in FireHOL level1 aggregator (safety-net "
                    "pooled from ~100 high-confidence free feeds)"
                ),
            )
            for entry in indicators
        }
        return indicators, meta

    async def refresh(self) -> None:
        """Download + parse then re-hydrate the network objects."""
        await super().refresh()
        self._rehydrate_networks()

    def lookup_ip(self, ip: str) -> Optional[FeedEntry]:
        """Check containment in any FireHOL level1 network."""
        try:
            candidate = ipaddress.IPv4Address(ip)
        except (ValueError, ipaddress.AddressValueError):
            return None
        for network in self._networks:
            if candidate in network:
                return self._meta.get(str(network))
        return None
