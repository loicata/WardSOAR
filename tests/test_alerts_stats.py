"""Tests for the longitudinal alert statistics store."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.alerts_stats import (
    AlertOccurrence,
    AlertsStatsStore,
    StatsSignals,
)


class TestRecordAndQuery:
    def test_record_then_query_round_trip(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        now = int(time.time())
        store.record(sid=1000, src_ip="1.2.3.4", verdict="benign", ts=now - 10)
        store.record(sid=1000, src_ip="1.2.3.4", verdict="benign", ts=now - 5)
        store._flush_now()

        occs = store.query_window(sid=1000, src_ip="1.2.3.4", days=1)
        assert len(occs) == 2
        assert all(o.verdict == "benign" for o in occs)

    def test_query_filters_by_sid(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        now = int(time.time())
        store.record(sid=1, src_ip="1.2.3.4", verdict="benign", ts=now)
        store.record(sid=2, src_ip="1.2.3.4", verdict="benign", ts=now)
        store._flush_now()

        assert len(store.query_window(sid=1, src_ip="1.2.3.4")) == 1
        assert len(store.query_window(sid=2, src_ip="1.2.3.4")) == 1
        assert len(store.query_window(sid=3, src_ip="1.2.3.4")) == 0

    def test_query_respects_time_window(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        now = int(time.time())
        store.record(sid=1, src_ip="x", verdict="benign", ts=now - 10 * 86400)  # 10 days ago
        store.record(sid=1, src_ip="x", verdict="benign", ts=now - 3 * 86400)  # 3 days ago
        store._flush_now()

        assert len(store.query_window(sid=1, src_ip="x", days=7)) == 1
        assert len(store.query_window(sid=1, src_ip="x", days=30)) == 2


class TestComputeSignals:
    def _store_with(self, tmp_path: Path, occs: list[tuple[int, str]]) -> AlertsStatsStore:
        """Seed a store with a list of (ts_offset_seconds, verdict) pairs."""
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        now = int(time.time())
        for delta, verdict in occs:
            store.record(sid=1, src_ip="x", verdict=verdict, ts=now + delta)
        store._flush_now()
        return store

    def test_no_occurrences_returns_none(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        assert store.compute_signals(sid=1, src_ip="x") is None

    def test_single_occurrence_frequency_and_no_regularity(self, tmp_path: Path) -> None:
        store = self._store_with(tmp_path, [(0, "benign")])
        signals = store.compute_signals(sid=1, src_ip="x")
        assert signals is not None
        assert signals.total_count == 1
        assert signals.regularity is None  # <3 occurrences = not meaningful
        assert signals.verdict_stability == 1.0
        assert signals.dominant_verdict == "benign"

    def test_beacon_pattern_gets_high_regularity(self, tmp_path: Path) -> None:
        """Occurrences every exactly 3600 s (hourly beacon)."""
        store = self._store_with(
            tmp_path,
            [(-i * 3600, "benign") for i in range(24)],  # 24 hourly beats
        )
        signals = store.compute_signals(sid=1, src_ip="x")
        assert signals is not None
        assert signals.regularity is not None
        assert signals.regularity > 0.95  # near-perfect regularity
        assert signals.total_count == 24

    def test_random_pattern_gets_low_regularity(self, tmp_path: Path) -> None:
        """Irregular intervals → CV high → regularity low."""
        import random

        random.seed(42)
        occs = []
        t = 0
        for _ in range(20):
            occs.append((-t, "benign"))
            t += random.randint(10, 10000)  # spread intervals
        store = self._store_with(tmp_path, occs)
        signals = store.compute_signals(sid=1, src_ip="x")
        assert signals is not None
        assert signals.regularity is not None
        assert signals.regularity < 0.6  # clearly irregular

    def test_oscillating_verdict_lowers_stability(self, tmp_path: Path) -> None:
        store = self._store_with(
            tmp_path,
            [
                (-10, "benign"),
                (-8, "suspicious"),
                (-6, "benign"),
                (-4, "confirmed"),
                (-2, "suspicious"),
            ],
        )
        signals = store.compute_signals(sid=1, src_ip="x")
        assert signals is not None
        assert signals.verdict_stability < 0.6  # mixed bag

    def test_recent_first_seen_marked_novelty(self, tmp_path: Path) -> None:
        """All occurrences fit in the last 24h → novelty True."""
        store = self._store_with(
            tmp_path,
            [(-3600, "benign"), (-1800, "benign")],
        )
        signals = store.compute_signals(sid=1, src_ip="x")
        assert signals is not None
        assert signals.novelty is True

    def test_old_first_seen_not_novelty(self, tmp_path: Path) -> None:
        """First occurrence > 3 days ago → novelty False."""
        store = self._store_with(
            tmp_path,
            [
                (-5 * 86400, "benign"),  # 5 days ago
                (-1 * 86400, "benign"),  # 1 day ago
            ],
        )
        signals = store.compute_signals(sid=1, src_ip="x", days=30)
        assert signals is not None
        assert signals.novelty is False


class TestPurgeOlderThan:
    def test_removes_only_rows_older_than_retention(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db", retention_days=7)
        now = int(time.time())
        store.record(sid=1, src_ip="x", verdict="benign", ts=now - 10 * 86400)
        store.record(sid=1, src_ip="x", verdict="benign", ts=now - 1 * 86400)
        store._flush_now()

        deleted = store.purge_older_than()

        assert deleted == 1
        occs = store.query_window(sid=1, src_ip="x", days=30)
        assert len(occs) == 1
        assert (now - occs[0].ts) < 7 * 86400


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop_flushes_pending(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        await store.start()
        try:
            # Record without manual flush — stop() must persist it.
            store.record(sid=42, src_ip="1.1.1.1", verdict="benign")
        finally:
            await store.stop()

        # Fresh store on the same DB should see the row.
        fresh = AlertsStatsStore(db_path=tmp_path / "stats.db")
        assert len(fresh.query_window(sid=42, src_ip="1.1.1.1")) == 1

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self, tmp_path: Path) -> None:
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        await store.start()
        first_task = store._task
        await store.start()
        assert store._task is first_task
        await store.stop()


class TestInlineBackpressure:
    def test_large_queue_triggers_inline_flush(self, tmp_path: Path) -> None:
        """Crossing MAX_QUEUE_BEFORE_INLINE_FLUSH must persist without a flush loop."""
        store = AlertsStatsStore(db_path=tmp_path / "stats.db")
        for i in range(1500):
            store.record(sid=i % 10, src_ip="x", verdict="benign")
        # Queue should not have accumulated past the threshold.
        assert len(store._pending) < 1500

    def test_dataclass_is_frozen(self) -> None:
        occ = AlertOccurrence(sid=1, src_ip="x", ts=0, verdict="benign")
        with pytest.raises(Exception):
            occ.sid = 99  # type: ignore[misc]

    def test_signals_dataclass_is_frozen(self) -> None:
        s = StatsSignals(
            total_count=1,
            frequency_per_day=1.0,
            regularity=None,
            verdict_stability=1.0,
            dominant_verdict="benign",
            novelty=True,
        )
        with pytest.raises(Exception):
            s.total_count = 2  # type: ignore[misc]
