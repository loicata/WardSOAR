"""Central registry owner and background-refresh scheduler.

The :class:`IntelManager` holds one instance of every
:class:`FeedRegistry` and:

1. Loads the on-disk snapshots at boot (every registry does that in
   its constructor).
2. Kicks off an asyncio task that wakes up every 5 minutes and
   calls ``refresh_if_stale`` on each registry. Staleness is
   per-feed (URLhaus: 1h, Blocklist.de: 30min, Spamhaus DROP: 1d).
3. Exposes :meth:`query_all_for_ip` \u2014 the synchronous, O(N_feeds)
   helper the alert pipeline uses to build its reputation rows.

The manager is designed to survive the feed being offline: we keep
serving the last snapshot and the UI shows it as stale with the
``last_refresh_iso`` timestamp.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from wardsoar.core.intel.abuseipdb import AbuseIpDbClient
from wardsoar.core.intel.alienvault_otx import AlienVaultOtxClient
from wardsoar.core.intel.base import FeedEntry, FeedRegistry
from wardsoar.core.intel.blocklist_de import BlocklistDeRegistry
from wardsoar.core.intel.censys_client import CensysClient
from wardsoar.core.intel.feodo_tracker import FeodoTrackerRegistry
from wardsoar.core.intel.firehol import FireHolRegistry
from wardsoar.core.intel.greynoise import GreyNoiseClient
from wardsoar.core.intel.honeypot import ProjectHoneyPotClient
from wardsoar.core.intel.http_client_base import (
    HttpReputationClient,
    IpReputationCache,
)
from wardsoar.core.intel.ipinfo_pro import IpinfoProClient
from wardsoar.core.intel.securitytrails import SecurityTrailsClient
from wardsoar.core.intel.shodan_client import ShodanClient
from wardsoar.core.intel.spamhaus_drop import SpamhausDropRegistry
from wardsoar.core.intel.threatfox import ThreatFoxRegistry
from wardsoar.core.intel.urlhaus import URLhausRegistry
from wardsoar.core.intel.virustotal_client import VirusTotalClient
from wardsoar.core.intel.xforce import XForceClient

logger = logging.getLogger("ward_soar.intel.manager")


@dataclass(frozen=True)
class QueryResult:
    """One feed's verdict on an IP, normalised for the UI row."""

    display_name: str
    level: str  # "clean" / "bad" / "unknown"
    verdict: str


class IntelManager:
    """Owns every :class:`FeedRegistry`.

    The manager's ``registries`` list is the UI's source of truth:
    every entry contributes exactly one row to the Alert Detail
    "External reputation" section.
    """

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._registries: list[FeedRegistry] = [
            URLhausRegistry(cache_dir),
            ThreatFoxRegistry(cache_dir),
            FeodoTrackerRegistry(cache_dir),
            BlocklistDeRegistry(cache_dir),
            SpamhausDropRegistry(cache_dir),
            FireHolRegistry(cache_dir),
        ]
        # v0.12.0 \u2014 HTTP-based reputation clients share one SQLite
        # cache so the daily quota of free-tier keys is preserved
        # across restarts and across clients.
        ip_rep_db = cache_dir / "ip_reputation.db"
        self._ip_cache = IpReputationCache(db_path=ip_rep_db)
        self._api_clients: list[HttpReputationClient] = [
            # Tier S \u2014 highest aggregate signal
            VirusTotalClient(cache=self._ip_cache),
            # v0.13.0 \u2014 X-Force sits between VT and the crowdsourced
            # sources: commercial-grade curated intel feed.
            XForceClient(cache=self._ip_cache),
            AbuseIpDbClient(cache=self._ip_cache),
            GreyNoiseClient(cache=self._ip_cache),
            AlienVaultOtxClient(cache=self._ip_cache),
            # v0.13.0 \u2014 Project Honey Pot is DNSBL-based and
            # narrower (email spam / harvester focus) so it sits
            # after the generalist rows.
            ProjectHoneyPotClient(cache=self._ip_cache),
            # v0.14.0 \u2014 paid sources. They sit at the end of the
            # reputation list so the operator sees the unpaid rows
            # first (most will have these configured).
            ShodanClient(cache=self._ip_cache),
            SecurityTrailsClient(cache=self._ip_cache),
            CensysClient(cache=self._ip_cache),
        ]
        # v0.13.0 \u2014 ipinfo pro tier sits OUTSIDE ``_api_clients``
        # because it does not produce a reputation row. Its purpose
        # is to populate the Identity block's ``VPN / Proxy`` field.
        # :func:`src.ip_enrichment.build_ip_enrichment_async` calls
        # :meth:`ipinfo_pro.is_vpn_or_proxy` directly.
        self._ipinfo_pro = IpinfoProClient(cache=self._ip_cache)
        self._refresh_task: Optional[asyncio.Task[None]] = None
        self._stopping = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def refresh_all(self) -> None:
        """Run :meth:`refresh_if_stale` on every registry concurrently."""
        await asyncio.gather(
            *(r.refresh_if_stale() for r in self._registries),
            return_exceptions=True,
        )

    async def start_background_refresh(self, interval_s: int = 300) -> None:
        """Spawn the periodic refresh task.

        Called once by :class:`EngineWorker` during its asyncio
        bootstrap. The task wakes every ``interval_s`` seconds and
        walks the registries, refreshing only those whose cache has
        exceeded its own ``refresh_interval_s``.
        """
        if self._refresh_task is not None and not self._refresh_task.done():
            return  # Already running.

        async def _loop() -> None:
            # Opportunistic first pass on startup \u2014 catches registries
            # whose on-disk snapshot was stale when the process booted.
            try:
                await self.refresh_all()
            except Exception:  # noqa: BLE001
                logger.exception("Intel: initial refresh pass failed")
            while not self._stopping:
                await asyncio.sleep(interval_s)
                if self._stopping:
                    break
                try:
                    await self.refresh_all()
                except Exception:  # noqa: BLE001
                    logger.exception("Intel: periodic refresh pass failed")

        self._refresh_task = asyncio.create_task(_loop())

    def stop(self) -> None:
        """Signal the background task to exit at the next wake-up."""
        self._stopping = True
        if self._refresh_task is not None and not self._refresh_task.done():
            self._refresh_task.cancel()

    # ------------------------------------------------------------------
    # Synchronous query API (used at alert time)
    # ------------------------------------------------------------------

    def query_all_for_ip(self, ip: str) -> list[QueryResult]:
        """Ask every local registry about ``ip`` (feeds only).

        Synchronous, O(1) per registry. Used when only the
        offline-able feeds are needed \u2014 e.g. the UI's quick
        preview or offline testing.
        """
        rows: list[QueryResult] = []
        for registry in self._registries:
            rows.append(self._single_query(registry, ip))
        return rows

    async def query_all_for_ip_async(self, ip: str) -> list[QueryResult]:
        """Ask every registry AND every API client about ``ip``.

        Feeds are queried synchronously (O(1) look-ups). API clients
        are queried concurrently with :func:`asyncio.gather` so the
        total wall time is bounded by the slowest HTTP response
        (typically VT, ~500ms on a cache miss; <5ms on a cache hit).

        The rendering order in the resulting list:
          1. The 6 feed registries in registry order.
          2. The API clients in the order they were declared, but
             only those the operator has configured (key present).
        """
        feed_rows = [self._single_query(registry, ip) for registry in self._registries]

        async def _query_one(client: HttpReputationClient) -> Optional[QueryResult]:
            if not client.is_enabled():
                return None
            verdict = await client.query_ip(ip)
            if verdict is None:
                return None
            return QueryResult(
                display_name=client.display_name,
                level=verdict.level,
                verdict=verdict.verdict,
            )

        api_results = await asyncio.gather(
            *(_query_one(c) for c in self._api_clients),
            return_exceptions=False,
        )
        api_rows = [row for row in api_results if row is not None]
        return feed_rows + api_rows

    @staticmethod
    def _single_query(registry: FeedRegistry, ip: str) -> QueryResult:
        hit: Optional[FeedEntry] = None
        try:
            hit = registry.lookup_ip(ip)
        except Exception:  # noqa: BLE001 \u2014 defensive: a broken feed must not kill the alert
            logger.debug("intel.%s: lookup_ip crashed", registry.name, exc_info=True)
        if hit is None:
            empty = registry.indicator_count() == 0
            if empty:
                return QueryResult(
                    display_name=registry.display_name,
                    level="unknown",
                    verdict="Feed offline or empty (will retry in background).",
                )
            return QueryResult(
                display_name=registry.display_name,
                level="clean",
                verdict="Not listed",
            )
        return QueryResult(
            display_name=registry.display_name,
            level="bad",
            verdict=hit.description or hit.category or "Listed",
        )

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def registries(self) -> list[FeedRegistry]:
        """Expose the registry list (e.g. for a diagnostics view)."""
        return list(self._registries)

    @property
    def api_clients(self) -> list[HttpReputationClient]:
        """Expose the HTTP-client list for diagnostics / tests."""
        return list(self._api_clients)

    @property
    def ipinfo_pro(self) -> IpinfoProClient:
        """Expose the ipinfo pro-tier client for the Identity block."""
        return self._ipinfo_pro
