"""Tests for WardSOAR metrics collection.

Metrics is STANDARD (80% coverage).
"""

from src.metrics import MetricsCollector


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_increment(self) -> None:
        mc = MetricsCollector({})
        mc.increment("alerts_total")
        mc.increment("alerts_total", 5)
        snapshot = mc.get_snapshot()
        assert snapshot["counters"]["alerts_total"] == 6

    def test_gauge(self) -> None:
        mc = MetricsCollector({})
        mc.gauge("queue_depth", 42.0)
        snapshot = mc.get_snapshot()
        assert snapshot["gauges"]["queue_depth"] == 42.0

    def test_timing(self) -> None:
        mc = MetricsCollector({})
        mc.timing("pipeline_ms", 100.0)
        mc.timing("pipeline_ms", 200.0)
        mc.timing("pipeline_ms", 300.0)
        snapshot = mc.get_snapshot()
        assert snapshot["timings"]["pipeline_ms"]["avg"] == 200.0
        assert snapshot["timings"]["pipeline_ms"]["count"] == 3

    def test_get_snapshot_includes_uptime(self) -> None:
        mc = MetricsCollector({})
        snapshot = mc.get_snapshot()
        assert "uptime_seconds" in snapshot
        assert snapshot["uptime_seconds"] >= 0

    def test_get_daily_summary(self) -> None:
        mc = MetricsCollector({})
        mc.increment("alerts_total", 10)
        mc.increment("blocks_total", 2)
        summary = mc.get_daily_summary()
        assert "alerts_total" in summary

    def test_reset_daily(self) -> None:
        mc = MetricsCollector({})
        mc.increment("alerts_total", 10)
        mc.reset_daily()
        snapshot = mc.get_snapshot()
        assert "alerts_total" not in snapshot["counters"]

    def test_empty_snapshot(self) -> None:
        mc = MetricsCollector({})
        snapshot = mc.get_snapshot()
        assert snapshot["counters"] == {}
        assert snapshot["gauges"] == {}

    def test_timing_p95(self) -> None:
        mc = MetricsCollector({})
        for i in range(100):
            mc.timing("latency", float(i))
        snapshot = mc.get_snapshot()
        assert snapshot["timings"]["latency"]["p95"] >= 90
