"""Tests for the TTL-based risk-scan cache."""

from __future__ import annotations

import time
from unittest.mock import patch

from src.process_risk import ProcessRiskResult
from src.process_risk_cache import ProcessRiskCache


def _fake_result(pid: int, verdict: str = "benign") -> ProcessRiskResult:
    return ProcessRiskResult(pid=pid, score=5, verdict=verdict, signals=[f"result for {pid}"])


class TestCacheHit:
    def test_first_lookup_invokes_scan_second_does_not(self) -> None:
        call_counter = {"n": 0}

        def fake_scan(pid: int) -> ProcessRiskResult:
            call_counter["n"] += 1
            return _fake_result(pid)

        with (
            patch("src.process_risk_cache.scan_process", side_effect=fake_scan),
            patch("src.process_risk_cache._safe_create_time", return_value=123.0),
        ):
            cache = ProcessRiskCache()
            first = cache.get_or_scan(1234)
            second = cache.get_or_scan(1234)

        assert first is second
        assert call_counter["n"] == 1
        assert cache.size() == 1


class TestTTLExpiry:
    def test_entry_is_refreshed_after_ttl(self) -> None:
        call_counter = {"n": 0}

        def fake_scan(pid: int) -> ProcessRiskResult:
            call_counter["n"] += 1
            return _fake_result(pid)

        with (
            patch("src.process_risk_cache.scan_process", side_effect=fake_scan),
            patch("src.process_risk_cache._safe_create_time", return_value=123.0),
        ):
            # TTL is clamped at 1 s to prevent an accidental spinning
            # loop in prod — pick 1 s and sleep just past it.
            cache = ProcessRiskCache(ttl_seconds=1.0)
            cache.get_or_scan(1234)
            time.sleep(1.1)
            cache.get_or_scan(1234)

        assert call_counter["n"] == 2


class TestPIDReuseDetection:
    def test_different_create_time_forces_rescan(self) -> None:
        call_counter = {"n": 0}

        def fake_scan(pid: int) -> ProcessRiskResult:
            call_counter["n"] += 1
            return _fake_result(pid)

        create_times = iter([100.0, 200.0])  # two different stamps
        with (
            patch("src.process_risk_cache.scan_process", side_effect=fake_scan),
            patch(
                "src.process_risk_cache._safe_create_time",
                side_effect=lambda pid: next(create_times),
            ),
        ):
            cache = ProcessRiskCache()
            cache.get_or_scan(1234)  # create_time=100.0
            cache.get_or_scan(1234)  # create_time=200.0 (reused PID)

        assert call_counter["n"] == 2


class TestClearAndInvalidate:
    def test_clear_empties_cache(self) -> None:
        with (
            patch("src.process_risk_cache.scan_process", side_effect=_fake_result),
            patch("src.process_risk_cache._safe_create_time", return_value=1.0),
        ):
            cache = ProcessRiskCache()
            cache.get_or_scan(1)
            cache.get_or_scan(2)
            assert cache.size() == 2
            cache.clear()
            assert cache.size() == 0

    def test_invalidate_removes_single_entry(self) -> None:
        with (
            patch("src.process_risk_cache.scan_process", side_effect=_fake_result),
            patch("src.process_risk_cache._safe_create_time", return_value=1.0),
        ):
            cache = ProcessRiskCache()
            cache.get_or_scan(1)
            cache.get_or_scan(2)
            cache.invalidate(1)
            assert cache.size() == 1


class TestCreateTimeUnavailable:
    def test_ttl_alone_decides_freshness(self) -> None:
        """When psutil cannot read create_time, the cache falls back on
        TTL. Two back-to-back calls still hit the cache."""
        call_counter = {"n": 0}

        def fake_scan(pid: int) -> ProcessRiskResult:
            call_counter["n"] += 1
            return _fake_result(pid)

        with (
            patch("src.process_risk_cache.scan_process", side_effect=fake_scan),
            patch("src.process_risk_cache._safe_create_time", return_value=None),
        ):
            cache = ProcessRiskCache()
            cache.get_or_scan(1234)
            cache.get_or_scan(1234)

        assert call_counter["n"] == 1
