"""Tests for WardSOAR decision cache.

DecisionCache is HIGH (85% coverage). Fail-safe: if cache fails,
re-analyze from scratch.
"""

from datetime import datetime, timedelta, timezone


from src.decision_cache import CacheEntry, CacheKey, DecisionCache
from src.models import ThreatAnalysis, ThreatVerdict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analysis(
    verdict: ThreatVerdict = ThreatVerdict.CONFIRMED,
    confidence: float = 0.85,
) -> ThreatAnalysis:
    """Create a test ThreatAnalysis."""
    return ThreatAnalysis(
        verdict=verdict,
        confidence=confidence,
        reasoning="Test analysis",
    )


# ---------------------------------------------------------------------------
# CacheEntry tests
# ---------------------------------------------------------------------------


class TestCacheEntry:
    """Tests for CacheEntry."""

    def test_construction(self) -> None:
        key: CacheKey = ("10.0.0.1", 1000, 443)
        analysis = _make_analysis()
        entry = CacheEntry(key=key, analysis=analysis, ttl_seconds=3600)
        assert entry.key == key
        assert entry.hit_count == 0
        assert entry.ttl_seconds == 3600

    def test_not_expired_when_fresh(self) -> None:
        entry = CacheEntry(
            key=("10.0.0.1", 1000, 443),
            analysis=_make_analysis(),
            ttl_seconds=3600,
        )
        assert entry.is_expired() is False

    def test_expired_when_old(self) -> None:
        entry = CacheEntry(
            key=("10.0.0.1", 1000, 443),
            analysis=_make_analysis(),
            ttl_seconds=60,
        )
        # Force creation time to be in the past
        entry.created_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        assert entry.is_expired() is True


# ---------------------------------------------------------------------------
# DecisionCache init tests
# ---------------------------------------------------------------------------


class TestDecisionCacheInit:
    """Tests for DecisionCache initialization."""

    def test_default_config(self) -> None:
        cache = DecisionCache({})
        assert cache._enabled is True
        assert cache._max_entries == 10000
        assert cache.size == 0

    def test_disabled_cache(self) -> None:
        cache = DecisionCache({"enabled": False})
        assert cache._enabled is False

    def test_custom_ttls(self) -> None:
        cache = DecisionCache(
            {
                "ttl_benign_seconds": 7200,
                "ttl_confirmed_seconds": 43200,
                "ttl_suspicious_seconds": 900,
                "ttl_inconclusive_seconds": 300,
            }
        )
        assert cache._ttl_by_verdict[ThreatVerdict.BENIGN] == 7200
        assert cache._ttl_by_verdict[ThreatVerdict.CONFIRMED] == 43200
        assert cache._ttl_by_verdict[ThreatVerdict.SUSPICIOUS] == 900
        assert cache._ttl_by_verdict[ThreatVerdict.INCONCLUSIVE] == 300

    def test_suspicious_ttl_default(self) -> None:
        """SUSPICIOUS verdict must have its own TTL, not copy BENIGN."""
        cache = DecisionCache({})
        assert cache._ttl_by_verdict[ThreatVerdict.SUSPICIOUS] == 1800
        assert cache._ttl_by_verdict[ThreatVerdict.BENIGN] == 3600
        assert (
            cache._ttl_by_verdict[ThreatVerdict.SUSPICIOUS]
            != cache._ttl_by_verdict[ThreatVerdict.BENIGN]
        )


# ---------------------------------------------------------------------------
# store + lookup tests
# ---------------------------------------------------------------------------


class TestStoreAndLookup:
    """Tests for DecisionCache.store and lookup."""

    def test_store_and_lookup(self) -> None:
        cache = DecisionCache({})
        analysis = _make_analysis()
        cache.store("10.0.0.1", 1000, 443, analysis)

        result = cache.lookup("10.0.0.1", 1000, 443)
        assert result is not None
        assert result.verdict == ThreatVerdict.CONFIRMED
        assert result.confidence == 0.85

    def test_lookup_nonexistent_returns_none(self) -> None:
        cache = DecisionCache({})
        result = cache.lookup("10.0.0.1", 1000, 443)
        assert result is None

    def test_lookup_expired_returns_none(self) -> None:
        cache = DecisionCache({"ttl_confirmed_seconds": 60})
        analysis = _make_analysis()
        cache.store("10.0.0.1", 1000, 443, analysis)

        # Force expiry
        key: CacheKey = ("10.0.0.1", 1000, 443)
        cache._cache[key].created_at = datetime.now(timezone.utc) - timedelta(seconds=120)

        result = cache.lookup("10.0.0.1", 1000, 443)
        assert result is None
        assert cache.size == 0  # Expired entry was removed

    def test_lookup_increments_hit_count(self) -> None:
        cache = DecisionCache({})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())

        cache.lookup("10.0.0.1", 1000, 443)
        cache.lookup("10.0.0.1", 1000, 443)

        key: CacheKey = ("10.0.0.1", 1000, 443)
        assert cache._cache[key].hit_count == 2

    def test_disabled_cache_lookup_returns_none(self) -> None:
        cache = DecisionCache({"enabled": False})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())
        result = cache.lookup("10.0.0.1", 1000, 443)
        assert result is None

    def test_disabled_cache_store_is_noop(self) -> None:
        cache = DecisionCache({"enabled": False})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())
        assert cache.size == 0

    def test_different_keys_stored_separately(self) -> None:
        cache = DecisionCache({})
        cache.store("10.0.0.1", 1000, 443, _make_analysis(ThreatVerdict.CONFIRMED))
        cache.store("10.0.0.2", 1000, 443, _make_analysis(ThreatVerdict.BENIGN))

        r1 = cache.lookup("10.0.0.1", 1000, 443)
        r2 = cache.lookup("10.0.0.2", 1000, 443)
        assert r1 is not None and r1.verdict == ThreatVerdict.CONFIRMED
        assert r2 is not None and r2.verdict == ThreatVerdict.BENIGN

    def test_overwrite_existing_key(self) -> None:
        cache = DecisionCache({})
        cache.store("10.0.0.1", 1000, 443, _make_analysis(ThreatVerdict.BENIGN))
        cache.store("10.0.0.1", 1000, 443, _make_analysis(ThreatVerdict.CONFIRMED))

        result = cache.lookup("10.0.0.1", 1000, 443)
        assert result is not None
        assert result.verdict == ThreatVerdict.CONFIRMED

    def test_max_entries_eviction(self) -> None:
        cache = DecisionCache({"max_entries": 3})
        for i in range(5):
            cache.store(f"10.0.0.{i}", 1000, 443, _make_analysis())

        assert cache.size <= 3
        # Most recent entries should be kept
        assert cache.lookup("10.0.0.4", 1000, 443) is not None


# ---------------------------------------------------------------------------
# evict_expired tests
# ---------------------------------------------------------------------------


class TestEvictExpired:
    """Tests for DecisionCache.evict_expired."""

    def test_evict_removes_expired(self) -> None:
        cache = DecisionCache({"ttl_confirmed_seconds": 60})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())
        cache.store("10.0.0.2", 1000, 443, _make_analysis())

        # Expire one entry
        key: CacheKey = ("10.0.0.1", 1000, 443)
        cache._cache[key].created_at = datetime.now(timezone.utc) - timedelta(seconds=120)

        removed = cache.evict_expired()
        assert removed == 1
        assert cache.size == 1

    def test_evict_no_expired(self) -> None:
        cache = DecisionCache({})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())
        removed = cache.evict_expired()
        assert removed == 0

    def test_evict_empty_cache(self) -> None:
        cache = DecisionCache({})
        removed = cache.evict_expired()
        assert removed == 0


# ---------------------------------------------------------------------------
# clear and size tests
# ---------------------------------------------------------------------------


class TestClearAndSize:
    """Tests for clear and size."""

    def test_clear(self) -> None:
        cache = DecisionCache({})
        cache.store("10.0.0.1", 1000, 443, _make_analysis())
        assert cache.size == 1
        cache.clear()
        assert cache.size == 0
