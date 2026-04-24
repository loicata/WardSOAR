"""Tests for WardSOAR VirusTotal cache and rate limiter.

VTCache is HIGH criticality: a failure here either burns the free-tier
quota (if cache reads silently return None) or blocks legitimate lookups
(if the rate limiter is too aggressive). Tests use a temp SQLite file so
they are hermetic.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.models import VirusTotalResult
from src.vt_cache import VTCache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _malicious_result(file_hash: str = "a" * 64) -> VirusTotalResult:
    """Build a malicious sample verdict."""
    return VirusTotalResult(
        file_hash=file_hash,
        detection_count=50,
        total_engines=70,
        detection_ratio=50 / 70,
        is_malicious=True,
        threat_labels=["trojan.generic"],
        lookup_type="hash",
    )


def _clean_result(file_hash: str = "b" * 64) -> VirusTotalResult:
    """Build a clean sample verdict."""
    return VirusTotalResult(
        file_hash=file_hash,
        detection_count=0,
        total_engines=70,
        detection_ratio=0.0,
        is_malicious=False,
        threat_labels=[],
        lookup_type="hash",
    )


@pytest.fixture
def cache(tmp_path: Path) -> VTCache:
    """Fresh cache backed by a temp SQLite file."""
    return VTCache(db_path=tmp_path / "vt_cache.db")


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for VTCache initialization."""

    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "vt_cache.db"
        VTCache(db_path=nested)
        assert nested.parent.exists()

    def test_schema_idempotent(self, tmp_path: Path) -> None:
        """Instantiating twice on the same file must not fail."""
        db = tmp_path / "vt_cache.db"
        VTCache(db_path=db)
        VTCache(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# lookup / store round-trip
# ---------------------------------------------------------------------------


class TestLookupStore:
    """Round-trip tests for lookup() and store()."""

    def test_lookup_empty_returns_none(self, cache: VTCache) -> None:
        assert cache.lookup("a" * 64) is None

    def test_store_then_lookup(self, cache: VTCache) -> None:
        result = _malicious_result()
        cache.store(result)

        cached = cache.lookup(result.file_hash)
        assert cached is not None
        assert cached.file_hash == result.file_hash
        assert cached.is_malicious is True
        assert cached.detection_count == 50
        assert cached.threat_labels == ["trojan.generic"]

    def test_store_overwrites_previous(self, cache: VTCache) -> None:
        """Re-caching the same hash must update, not duplicate."""
        cache.store(_clean_result("c" * 64))
        cache.store(_malicious_result("c" * 64))

        cached = cache.lookup("c" * 64)
        assert cached is not None
        assert cached.is_malicious is True

    def test_clean_and_malicious_use_separate_ttls(self, tmp_path: Path) -> None:
        """Malicious verdicts must be kept longer than clean ones."""
        cache = VTCache(
            db_path=tmp_path / "vt_cache.db",
            ttl_malicious=1000,
            ttl_clean=10,
        )
        cache.store(_malicious_result("a" * 64))
        cache.store(_clean_result("b" * 64))

        # Both must be fresh immediately after store().
        assert cache.lookup("a" * 64) is not None
        assert cache.lookup("b" * 64) is not None


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    """Tests for TTL-based expiration."""

    def test_expired_entry_returns_none(self, tmp_path: Path) -> None:
        """An entry stored with TTL=0 must be treated as expired immediately."""
        cache = VTCache(
            db_path=tmp_path / "vt_cache.db",
            ttl_malicious=0,
            ttl_clean=0,
        )
        cache.store(_malicious_result())

        # Brief sleep to ensure `now - cached_at > 0`.
        time.sleep(1.1)
        assert cache.lookup("a" * 64) is None

    def test_cleanup_removes_expired_rows(self, tmp_path: Path) -> None:
        cache = VTCache(
            db_path=tmp_path / "vt_cache.db",
            ttl_malicious=0,
            ttl_clean=0,
        )
        cache.store(_malicious_result("a" * 64))
        cache.store(_clean_result("b" * 64))
        time.sleep(1.1)

        deleted = cache.cleanup_expired()
        assert deleted == 2
        assert cache.lookup("a" * 64) is None
        assert cache.lookup("b" * 64) is None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimit:
    """Tests for rate limiting (per-minute and per-day)."""

    @pytest.mark.asyncio
    async def test_under_limit_allows_call(self, cache: VTCache) -> None:
        assert await cache.can_call_api() is True

    @pytest.mark.asyncio
    async def test_per_minute_limit_blocks_fifth_call(self, tmp_path: Path) -> None:
        cache = VTCache(
            db_path=tmp_path / "vt_cache.db",
            max_per_minute=4,
            max_per_day=1000,
        )
        for _ in range(4):
            assert await cache.can_call_api() is True
            await cache.record_call()

        # Fifth call within the same minute must be blocked.
        assert await cache.can_call_api() is False

    @pytest.mark.asyncio
    async def test_per_day_limit_blocks(self, tmp_path: Path) -> None:
        cache = VTCache(
            db_path=tmp_path / "vt_cache.db",
            max_per_minute=1000,
            max_per_day=2,
        )
        for _ in range(2):
            assert await cache.can_call_api() is True
            await cache.record_call()

        assert await cache.can_call_api() is False

    @pytest.mark.asyncio
    async def test_record_call_persists_daily_counter(self, tmp_path: Path) -> None:
        """The daily counter must survive reopening the DB."""
        db = tmp_path / "vt_cache.db"
        cache1 = VTCache(db_path=db, max_per_minute=1000, max_per_day=2)
        await cache1.record_call()
        await cache1.record_call()

        cache2 = VTCache(db_path=db, max_per_minute=1000, max_per_day=2)
        assert await cache2.can_call_api() is False
