"""Collect and compute system metrics for dashboard and monitoring.

Tracks alert rates, false positive ratios, processing latencies,
API call counts, queue depth, blocking statistics, and more.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("ward_soar.metrics")


class MetricsCollector:
    """Collect and compute real-time system metrics.

    Args:
        config: Metrics configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._flush_interval: int = config.get("flush_interval_seconds", 60)
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._timings: dict[str, list[float]] = defaultdict(list)
        self._start_time = datetime.now(timezone.utc)

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric.

        Args:
            metric: Metric name.
            value: Amount to increment by.
        """
        self._counters[metric] += value

    def gauge(self, metric: str, value: float) -> None:
        """Set a gauge metric to a specific value.

        Args:
            metric: Metric name.
            value: Current value.
        """
        self._gauges[metric] = value

    def timing(self, metric: str, duration_ms: float) -> None:
        """Record a timing metric.

        Args:
            metric: Metric name.
            duration_ms: Duration in milliseconds.
        """
        self._timings[metric].append(duration_ms)

    def get_snapshot(self) -> dict[str, Any]:
        """Get a complete snapshot of all current metrics.

        Returns:
            Dict with counters, gauges, timing summaries, and uptime.
        """
        now = datetime.now(timezone.utc)
        uptime = (now - self._start_time).total_seconds()

        timing_summaries: dict[str, dict[str, float]] = {}
        for metric, values in self._timings.items():
            if values:
                sorted_vals = sorted(values)
                count = len(sorted_vals)
                timing_summaries[metric] = {
                    "count": float(count),
                    "avg": sum(sorted_vals) / count,
                    "min": sorted_vals[0],
                    "max": sorted_vals[-1],
                    "p95": sorted_vals[int(count * 0.95)] if count > 1 else sorted_vals[0],
                }

        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "timings": timing_summaries,
            "uptime_seconds": uptime,
            "snapshot_at": now.isoformat(),
        }

    def get_daily_summary(self) -> dict[str, Any]:
        """Compute daily summary metrics for notifications.

        Returns:
            Dict with daily totals.
        """
        return {
            **dict(self._counters),
            "uptime_seconds": (datetime.now(timezone.utc) - self._start_time).total_seconds(),
        }

    def reset_daily(self) -> None:
        """Reset daily counters."""
        self._counters.clear()
        self._timings.clear()
        logger.info("Daily metrics reset")
