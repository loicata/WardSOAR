"""Cache recent threat analysis verdicts to avoid redundant API calls.

Stores verdicts keyed by (src_ip, signature_id, dest_port) with
configurable TTL per verdict type. Benign verdicts are cached longer,
confirmed threats are fast-tracked, and inconclusive results expire
quickly for re-analysis.

Fail-safe: if the cache fails, re-analyze from scratch.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Optional

from src.models import ThreatAnalysis, ThreatVerdict

logger = logging.getLogger("ward_soar.decision_cache")

# Cache key type
CacheKey = tuple[str, int, int]  # (src_ip, signature_id, dest_port)


class CacheEntry:
    """A cached threat analysis verdict.

    Attributes:
        key: The cache key (src_ip, signature_id, dest_port).
        analysis: The cached ThreatAnalysis result.
        created_at: When this entry was created.
        ttl_seconds: How long this entry remains valid.
        hit_count: Number of times this entry was used.
    """

    def __init__(
        self,
        key: CacheKey,
        analysis: ThreatAnalysis,
        ttl_seconds: int,
    ) -> None:
        self.key = key
        self.analysis = analysis
        self.created_at = datetime.now(timezone.utc)
        self.ttl_seconds = ttl_seconds
        self.hit_count: int = 0

    def is_expired(self) -> bool:
        """Check if this cache entry has expired.

        Returns:
            True if the entry is past its TTL.
        """
        elapsed = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds


class DecisionCache:
    """LRU cache for threat analysis verdicts.

    Args:
        config: DecisionCache configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._max_entries: int = config.get("max_entries", 10000)
        self._ttl_by_verdict: dict[ThreatVerdict, int] = {
            ThreatVerdict.BENIGN: config.get("ttl_benign_seconds", 3600),
            ThreatVerdict.CONFIRMED: config.get("ttl_confirmed_seconds", 86400),
            ThreatVerdict.SUSPICIOUS: config.get("ttl_suspicious_seconds", 1800),
            ThreatVerdict.INCONCLUSIVE: config.get("ttl_inconclusive_seconds", 600),
        }
        self._cache: OrderedDict[CacheKey, CacheEntry] = OrderedDict()

    def lookup(self, src_ip: str, signature_id: int, dest_port: int) -> Optional[ThreatAnalysis]:
        """Look up a cached verdict for an alert pattern.

        Args:
            src_ip: Source IP address.
            signature_id: Suricata signature ID.
            dest_port: Destination port.

        Returns:
            Cached ThreatAnalysis if found and not expired, None otherwise.
        """
        if not self._enabled:
            return None

        key: CacheKey = (src_ip, signature_id, dest_port)
        entry = self._cache.get(key)
        if entry is None:
            return None

        if entry.is_expired():
            del self._cache[key]
            logger.debug("Cache entry expired: %s", key)
            return None

        entry.hit_count += 1
        self._cache.move_to_end(key)

        logger.debug(
            "Cache hit: %s — verdict=%s hits=%d",
            key,
            entry.analysis.verdict.value,
            entry.hit_count,
        )
        return entry.analysis

    def store(
        self,
        src_ip: str,
        signature_id: int,
        dest_port: int,
        analysis: ThreatAnalysis,
    ) -> None:
        """Store a verdict in the cache.

        Args:
            src_ip: Source IP address.
            signature_id: Suricata signature ID.
            dest_port: Destination port.
            analysis: The ThreatAnalysis to cache.
        """
        if not self._enabled:
            return

        key: CacheKey = (src_ip, signature_id, dest_port)
        ttl = self._ttl_by_verdict.get(analysis.verdict, 3600)

        entry = CacheEntry(key=key, analysis=analysis, ttl_seconds=ttl)

        # Remove existing entry if present (to update position)
        if key in self._cache:
            del self._cache[key]

        self._cache[key] = entry
        self._cache.move_to_end(key)

        # Enforce max entries — evict oldest (front of OrderedDict)
        while len(self._cache) > self._max_entries:
            evicted_key, _ = self._cache.popitem(last=False)
            logger.debug("Cache evicted (LRU): %s", evicted_key)

        logger.debug(
            "Cache stored: %s — verdict=%s ttl=%ds",
            key,
            analysis.verdict.value,
            ttl,
        )

    def evict_expired(self) -> int:
        """Remove all expired entries from the cache.

        Returns:
            Number of entries removed.
        """
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired()]
        for key in expired_keys:
            del self._cache[key]

        if expired_keys:
            logger.info("Evicted %d expired cache entries", len(expired_keys))
        return len(expired_keys)

    @property
    def size(self) -> int:
        """Current number of entries in the cache."""
        return len(self._cache)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        self._cache.clear()
