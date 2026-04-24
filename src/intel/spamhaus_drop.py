"""Spamhaus DROP / EDROP feed downloaders.

The Spamhaus DROP (Don't Route Or Peer) and EDROP lists enumerate
**network blocks** — not individual IPs — operated by bulletproof
hosters and cyber-criminals known to host attackers. Matching an
alert's IP against these lists is one of the strongest "this is not
a legitimate destination" signals available in the free tier.

We download both lists and expand each CIDR into a
:class:`ipaddress.IPv4Network` object. Membership is then tested
via iteration — slower than a ``set`` of bare IPs but still O(N)
on ~1 000 networks, which is well under 1 ms per alert.

Feed format: plain text, one line per record:
    ``<CIDR> ; <SBL reference>``
Comments start with ``;``.

Sources:
  * https://www.spamhaus.org/drop/drop.txt
  * https://www.spamhaus.org/drop/edrop.txt

Refresh: daily.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from src.intel.base import FeedEntry, FeedRegistry

logger = logging.getLogger("ward_soar.intel.spamhaus_drop")


class SpamhausDropRegistry(FeedRegistry):
    """Spamhaus DROP + EDROP combined.

    We publish both lists behind one registry because operators
    invariably want them together. The DROP list covers blocks
    owned directly by cyber-criminal operations; EDROP adds
    "extended" hijacked ranges.
    """

    name = "spamhaus_drop"
    display_name = "Spamhaus DROP"
    # Override with a composite URL that we split inside refresh().
    # We fetch both DROP and EDROP in sequence from the same
    # refresh() entry point.
    url = "https://www.spamhaus.org/drop/drop.txt"
    _edrop_url = "https://www.spamhaus.org/drop/edrop.txt"
    refresh_interval_s = 24 * 3600  # daily

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        # Parsed IPv4 networks kept in memory for containment tests.
        self._networks: list[ipaddress.IPv4Network] = []
        # Build ``_networks`` from the on-disk snapshot loaded by
        # the base class. The base class populated ``_indicators``
        # with the CIDR strings; we rehydrate the network objects.
        self._networks = [
            ipaddress.IPv4Network(cidr, strict=False)
            for cidr in self._indicators
            if self._is_v4_cidr(cidr)
        ]

    @staticmethod
    def _is_v4_cidr(value: str) -> bool:
        try:
            ipaddress.IPv4Network(value, strict=False)
            return True
        except (ValueError, ipaddress.NetmaskValueError):
            return False

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        indicators: set[str] = set()
        meta: dict[str, FeedEntry] = {}
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            # Row shape: ``1.2.3.0/24 ; SBL123456``
            parts = line.split(";", 1)
            cidr = parts[0].strip()
            if not self._is_v4_cidr(cidr):
                continue
            sbl = parts[1].strip() if len(parts) > 1 else ""
            indicators.add(cidr)
            meta[cidr] = FeedEntry(
                indicator=cidr,
                kind="network",
                category="bulletproof_hoster",
                description=(
                    "Bulletproof-hoster network (Spamhaus DROP/EDROP)"
                    + (f" — {sbl}" if sbl else "")
                ),
                raw={"sbl": sbl},
            )
        return indicators, meta

    async def refresh(self) -> None:
        """Download DROP first, then EDROP, and merge the parsed output.

        The base class' :meth:`refresh` downloads a single URL; we
        override it so one refresh covers both lists. Any failure on
        one download leaves the previous snapshot untouched — we
        only commit when at least one list parsed successfully.
        """
        import httpx

        combined: set[str] = set()
        combined_meta: dict[str, FeedEntry] = {}
        success_count = 0
        for url in (self.url, self._edrop_url):
            try:
                async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
                    logger.info("intel.%s: downloading %s", self.name, url)
                    response = await client.get(url, follow_redirects=True)
                    response.raise_for_status()
                    indicators, meta = self._parse(response.text)
                combined.update(indicators)
                combined_meta.update(meta)
                success_count += 1
            except httpx.HTTPError as exc:
                logger.warning("intel.%s: %s failed: %s", self.name, url, exc)
            except Exception:  # noqa: BLE001
                logger.exception("intel.%s: %s parse failed", self.name, url)

        if success_count == 0:
            self._last_error = "Both Spamhaus DROP and EDROP failed to refresh"
            return

        self._indicators = combined
        self._meta = combined_meta
        self._networks = [
            ipaddress.IPv4Network(cidr, strict=False) for cidr in combined if self._is_v4_cidr(cidr)
        ]
        import datetime as _dt

        self._last_refresh_ts = _dt.datetime.now(_dt.timezone.utc).timestamp()
        self._last_error = None
        self._persist_to_disk()
        logger.info("intel.%s: refreshed %d networks", self.name, len(combined))

    def lookup_ip(self, ip: str) -> Optional[FeedEntry]:
        """Check whether ``ip`` falls inside any DROP/EDROP network.

        The base class' O(1) set-membership test doesn't work here —
        we're matching against CIDRs. Iterate instead, which is still
        cheap (~1 000 networks, ~1 ms per alert).
        """
        try:
            candidate = ipaddress.IPv4Address(ip)
        except (ValueError, ipaddress.AddressValueError):
            return None
        for network in self._networks:
            if candidate in network:
                # Return the first matching network's entry.
                return self._meta.get(str(network))
        return None
