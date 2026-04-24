"""Tests for WardSOAR async alert priority queue.

AlertQueue is HIGH (85% coverage). Tests cover enqueueing,
priority ordering, overflow strategies, and backpressure.
"""

from datetime import datetime, timezone

import pytest

from src.alert_queue import AlertPriority, AlertQueue, AlertQueueItem
from src.models import SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(src_ip: str = "10.0.0.1") -> SuricataAlert:
    """Create a minimal test alert."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ---------------------------------------------------------------------------
# AlertPriority tests
# ---------------------------------------------------------------------------


class TestAlertPriority:
    """Tests for AlertPriority enum."""

    def test_priority_ordering(self) -> None:
        assert AlertPriority.CRITICAL < AlertPriority.HIGH
        assert AlertPriority.HIGH < AlertPriority.NORMAL
        assert AlertPriority.NORMAL < AlertPriority.LOW


# ---------------------------------------------------------------------------
# AlertQueueItem tests
# ---------------------------------------------------------------------------


class TestAlertQueueItem:
    """Tests for AlertQueueItem wrapper."""

    def test_construction(self) -> None:
        alert = _make_alert()
        item = AlertQueueItem(alert=alert, priority=AlertPriority.HIGH)
        assert item.alert == alert
        assert item.priority == AlertPriority.HIGH

    def test_comparison(self) -> None:
        a = AlertQueueItem(alert=_make_alert(), priority=AlertPriority.CRITICAL)
        b = AlertQueueItem(alert=_make_alert(), priority=AlertPriority.LOW)
        assert a < b


# ---------------------------------------------------------------------------
# AlertQueue tests
# ---------------------------------------------------------------------------


class TestAlertQueue:
    """Tests for AlertQueue async priority queue."""

    @pytest.mark.asyncio
    async def test_put_and_get(self) -> None:
        q = AlertQueue({"max_size": 10})
        alert = _make_alert()
        result = await q.put(alert, AlertPriority.NORMAL)
        assert result is True
        assert q.size == 1

        item = await q.get()
        assert item.alert == alert
        assert q.size == 0

    @pytest.mark.asyncio
    async def test_priority_ordering(self) -> None:
        """Higher-priority items should come out first."""
        q = AlertQueue({"max_size": 10})
        await q.put(_make_alert("low"), AlertPriority.LOW)
        await q.put(_make_alert("critical"), AlertPriority.CRITICAL)
        await q.put(_make_alert("normal"), AlertPriority.NORMAL)

        item1 = await q.get()
        item2 = await q.get()
        item3 = await q.get()

        assert item1.priority == AlertPriority.CRITICAL
        assert item2.priority == AlertPriority.NORMAL
        assert item3.priority == AlertPriority.LOW

    @pytest.mark.asyncio
    async def test_is_full(self) -> None:
        q = AlertQueue({"max_size": 2})
        await q.put(_make_alert(), AlertPriority.NORMAL)
        assert q.is_full is False
        await q.put(_make_alert(), AlertPriority.NORMAL)
        assert q.is_full is True

    @pytest.mark.asyncio
    async def test_size_property(self) -> None:
        q = AlertQueue({"max_size": 10})
        assert q.size == 0
        await q.put(_make_alert(), AlertPriority.NORMAL)
        assert q.size == 1

    @pytest.mark.asyncio
    async def test_dropped_count_initial(self) -> None:
        q = AlertQueue({"max_size": 10})
        assert q.dropped_count == 0

    @pytest.mark.asyncio
    async def test_overflow_drop_new(self) -> None:
        """With drop_new strategy, new alerts are rejected when full."""
        q = AlertQueue({"max_size": 1, "overflow_strategy": "drop_new"})
        await q.put(_make_alert(), AlertPriority.NORMAL)
        result = await q.put(_make_alert(), AlertPriority.CRITICAL)
        assert result is False
        assert q.dropped_count == 1
        assert q.size == 1

    @pytest.mark.asyncio
    async def test_overflow_drop_lowest(self) -> None:
        """With drop_lowest, lowest-priority item is dropped to make room."""
        q = AlertQueue({"max_size": 2, "overflow_strategy": "drop_lowest"})
        await q.put(_make_alert("low"), AlertPriority.LOW)
        await q.put(_make_alert("normal"), AlertPriority.NORMAL)
        assert q.is_full is True

        # Add a higher-priority alert — should drop the LOW one
        result = await q.put(_make_alert("critical"), AlertPriority.CRITICAL)
        assert result is True
        assert q.size == 2
        assert q.dropped_count == 1

    @pytest.mark.asyncio
    async def test_overflow_drop_lowest_rejects_if_new_is_lowest(self) -> None:
        """If new alert is lower priority than all existing, it is dropped."""
        q = AlertQueue({"max_size": 1, "overflow_strategy": "drop_lowest"})
        await q.put(_make_alert(), AlertPriority.CRITICAL)

        result = await q.put(_make_alert(), AlertPriority.LOW)
        assert result is False
        assert q.dropped_count == 1
