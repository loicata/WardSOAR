"""Tests for WardSOAR alert deduplication and grouping.

Deduplicator is HIGH (85% coverage). Fail-safe: if grouping fails,
process alert individually.
"""

from datetime import datetime, timedelta, timezone


from src.deduplicator import AlertDeduplicator, AlertGroup
from src.models import SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_alert(
    src_ip: str = "10.0.0.1",
    sig_id: int = 2024897,
    timestamp: datetime | None = None,
) -> SuricataAlert:
    """Helper to create alerts with varying src_ip, sig_id, and timestamp."""
    ts = timestamp or datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    return SuricataAlert(
        timestamp=ts,
        src_ip=src_ip,
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test Alert",
        alert_signature_id=sig_id,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ---------------------------------------------------------------------------
# AlertGroup tests
# ---------------------------------------------------------------------------


class TestAlertGroup:
    """Tests for AlertGroup data structure."""

    def test_construction(self) -> None:
        alert = _make_alert()
        group = AlertGroup(key=("10.0.0.1", 2024897), first_alert=alert)
        assert group.key == ("10.0.0.1", 2024897)
        assert group.count == 1
        assert group.first_seen == alert.timestamp
        assert group.last_seen == alert.timestamp

    def test_count_property(self) -> None:
        alert = _make_alert()
        group = AlertGroup(key=("10.0.0.1", 2024897), first_alert=alert)
        group.alerts.append(_make_alert())
        assert group.count == 2


# ---------------------------------------------------------------------------
# AlertDeduplicator tests
# ---------------------------------------------------------------------------


class TestAlertDeduplicator:
    """Tests for AlertDeduplicator."""

    def test_disabled_deduplicator_always_returns_group(self) -> None:
        dedup = AlertDeduplicator({"enabled": False})
        alert = _make_alert()
        result = dedup.process_alert(alert)
        assert result is not None
        assert result.count == 1

    def test_new_alert_creates_group(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        alert = _make_alert()
        result = dedup.process_alert(alert)
        assert result is not None
        assert result.count == 1
        assert result.key == ("10.0.0.1", 2024897)

    def test_duplicate_alert_returns_none(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        t0 = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        alert1 = _make_alert(timestamp=t0)
        alert2 = _make_alert(timestamp=t0 + timedelta(seconds=10))

        result1 = dedup.process_alert(alert1)
        result2 = dedup.process_alert(alert2)

        assert result1 is not None
        assert result2 is None  # Merged into existing group

    def test_different_src_ip_creates_new_group(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        alert1 = _make_alert(src_ip="10.0.0.1")
        alert2 = _make_alert(src_ip="10.0.0.2")

        result1 = dedup.process_alert(alert1)
        result2 = dedup.process_alert(alert2)

        assert result1 is not None
        assert result2 is not None
        assert result1.key != result2.key

    def test_different_signature_creates_new_group(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        alert1 = _make_alert(sig_id=1000)
        alert2 = _make_alert(sig_id=2000)

        result1 = dedup.process_alert(alert1)
        result2 = dedup.process_alert(alert2)

        assert result1 is not None
        assert result2 is not None

    def test_alert_outside_window_creates_new_group(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        t0 = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        alert1 = _make_alert(timestamp=t0)
        alert2 = _make_alert(timestamp=t0 + timedelta(seconds=120))

        result1 = dedup.process_alert(alert1)
        result2 = dedup.process_alert(alert2)

        assert result1 is not None
        assert result2 is not None  # Outside window, new group

    def test_burst_detection(self) -> None:
        """When max_group_size is exceeded, return group for burst escalation."""
        dedup = AlertDeduplicator(
            {
                "enabled": True,
                "grouping_window_seconds": 60,
                "max_group_size": 3,
                "burst_escalation": True,
            }
        )
        t0 = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)

        result1 = dedup.process_alert(_make_alert(timestamp=t0))
        assert result1 is not None  # First alert, new group

        result2 = dedup.process_alert(_make_alert(timestamp=t0 + timedelta(seconds=1)))
        assert result2 is None  # Merged

        result3 = dedup.process_alert(_make_alert(timestamp=t0 + timedelta(seconds=2)))
        assert result3 is None  # Merged

        # 4th alert exceeds max_group_size=3 → burst escalation
        result4 = dedup.process_alert(_make_alert(timestamp=t0 + timedelta(seconds=3)))
        assert result4 is not None
        assert result4.count >= 3

    def test_get_group_context(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        alert = _make_alert()
        dedup.process_alert(alert)

        group = dedup.get_group_context(("10.0.0.1", 2024897))
        assert group is not None
        assert group.count == 1

    def test_get_group_context_nonexistent(self) -> None:
        dedup = AlertDeduplicator({"enabled": True})
        assert dedup.get_group_context(("1.2.3.4", 999)) is None


# ---------------------------------------------------------------------------
# expire_old_groups tests
# ---------------------------------------------------------------------------


class TestExpireOldGroups:
    """Tests for AlertDeduplicator.expire_old_groups."""

    def test_expire_removes_old_groups(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        t0 = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        alert = _make_alert(timestamp=t0)
        dedup.process_alert(alert)

        # Manually set last_seen to be old enough to expire
        key = ("10.0.0.1", 2024897)
        group = dedup._groups.get(key)
        assert group is not None
        group.last_seen = t0 - timedelta(seconds=120)

        dedup.expire_old_groups()
        assert dedup.get_group_context(key) is None

    def test_expire_keeps_recent_groups(self) -> None:
        dedup = AlertDeduplicator({"enabled": True, "grouping_window_seconds": 60})
        # Use a very recent timestamp so expire_old_groups won't expire it
        now = datetime.now(timezone.utc)
        alert = _make_alert(timestamp=now)
        dedup.process_alert(alert)

        dedup.expire_old_groups()
        assert dedup.get_group_context(("10.0.0.1", 2024897)) is not None
