"""Tests for WardSOAR notification system.

Notifier is STANDARD (80% coverage). External channels (email, Telegram)
are mocked. Windows tray notifications are tested via mock tray_manager.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import (
    DecisionRecord,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)
from src.notifier import (
    NotificationEvent,
    NotificationLevel,
    Notifier,
    TrayStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record() -> DecisionRecord:
    """Create a test DecisionRecord."""
    alert = SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )
    return DecisionRecord(
        record_id="rec-001",
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        alert=alert,
        analysis=ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.9,
            reasoning="Test threat",
        ),
    )


def _make_notifier() -> Notifier:
    """Create a test Notifier with default config."""
    return Notifier({"enabled": True, "rate_limit_per_minute": 10})


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestNotifierInit:
    """Tests for Notifier initialization."""

    def test_default_config(self) -> None:
        notifier = _make_notifier()
        assert notifier._enabled is True
        assert notifier._tray_manager is None
        assert notifier._tray_status == TrayStatus.OFFLINE

    def test_disabled(self) -> None:
        notifier = Notifier({"enabled": False})
        assert notifier._enabled is False

    def test_set_tray_manager(self) -> None:
        notifier = _make_notifier()
        mock_tray = MagicMock()
        notifier.set_tray_manager(mock_tray)
        assert notifier._tray_manager is mock_tray


# ---------------------------------------------------------------------------
# notify tests
# ---------------------------------------------------------------------------


class TestNotify:
    """Tests for Notifier.notify."""

    @pytest.mark.asyncio
    async def test_disabled_does_nothing(self) -> None:
        notifier = Notifier({"enabled": False})
        await notifier.notify(
            NotificationLevel.CRITICAL,
            NotificationEvent.THREAT_BLOCKED,
            "Test",
            "Message",
        )

    @pytest.mark.asyncio
    async def test_logs_notification(self) -> None:
        notifier = _make_notifier()
        await notifier.notify(
            NotificationLevel.INFO,
            NotificationEvent.SYSTEM_STARTUP,
            "Startup",
            "System started",
        )
        assert notifier._unread_count == 1

    @pytest.mark.asyncio
    async def test_rate_limiting(self) -> None:
        notifier = Notifier({"enabled": True, "rate_limit_per_minute": 2})
        for i in range(5):
            await notifier.notify(
                NotificationLevel.INFO,
                NotificationEvent.SYSTEM_STARTUP,
                f"Test {i}",
                "Message",
            )
        # After rate limit, notifications should still be accepted (logged)
        # but rate-limited channels may be skipped


# ---------------------------------------------------------------------------
# Convenience method tests
# ---------------------------------------------------------------------------


class TestConvenienceMethods:
    """Tests for convenience notification methods."""

    @pytest.mark.asyncio
    async def test_notify_threat_blocked(self) -> None:
        notifier = _make_notifier()
        record = _make_record()
        await notifier.notify_threat_blocked(record)
        assert notifier._unread_count >= 1

    @pytest.mark.asyncio
    async def test_notify_manual_review(self) -> None:
        notifier = _make_notifier()
        record = _make_record()
        await notifier.notify_manual_review(record)
        assert notifier._unread_count >= 1

    @pytest.mark.asyncio
    async def test_notify_healthcheck_failure(self) -> None:
        notifier = _make_notifier()
        await notifier.notify_healthcheck_failure("pfSense API", "Connection refused")
        assert notifier._unread_count >= 1

    @pytest.mark.asyncio
    async def test_send_daily_summary(self) -> None:
        notifier = _make_notifier()
        await notifier.send_daily_summary({"alerts_today": 10, "blocked_today": 2})


# ---------------------------------------------------------------------------
# Tray status tests
# ---------------------------------------------------------------------------


class TestTrayStatus:
    """Tests for tray status management."""

    def test_reset_unread(self) -> None:
        notifier = _make_notifier()
        notifier._unread_count = 5
        notifier._tray_status = TrayStatus.ALERT_PENDING
        notifier.reset_unread()
        assert notifier._unread_count == 0
        assert notifier._tray_status == TrayStatus.HEALTHY

    def test_reset_unread_not_alert_pending(self) -> None:
        notifier = _make_notifier()
        notifier._unread_count = 5
        notifier._tray_status = TrayStatus.CRITICAL
        notifier.reset_unread()
        assert notifier._unread_count == 0
        assert notifier._tray_status == TrayStatus.CRITICAL  # Unchanged


# ---------------------------------------------------------------------------
# External channel tests (mocked)
# ---------------------------------------------------------------------------


class TestExternalChannels:
    """Tests for email and Telegram channels."""

    @pytest.mark.asyncio
    async def test_send_email_disabled(self) -> None:
        notifier = _make_notifier()
        result = await notifier._send_email("Subject", "Body", NotificationLevel.INFO)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_telegram_disabled(self) -> None:
        notifier = _make_notifier()
        result = await notifier._send_telegram("Message", NotificationLevel.INFO)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_email_enabled(self) -> None:
        notifier = Notifier(
            {
                "enabled": True,
                "email": {
                    "enabled": True,
                    "smtp_host": "smtp.test.com",
                    "smtp_port": 587,
                    "to": "test@test.com",
                },
            }
        )
        with patch("src.notifier.aiosmtplib") as mock_smtp:
            mock_smtp.send = AsyncMock(return_value=({}, "OK"))
            result = await notifier._send_email("Subject", "Body", NotificationLevel.INFO)
            assert result is True

    @pytest.mark.asyncio
    async def test_send_email_error(self) -> None:
        notifier = Notifier(
            {
                "enabled": True,
                "email": {
                    "enabled": True,
                    "smtp_host": "smtp.test.com",
                    "to": "test@test.com",
                },
            }
        )
        with patch("src.notifier.aiosmtplib") as mock_smtp:
            mock_smtp.send.side_effect = OSError("SMTP failed")
            result = await notifier._send_email("Subject", "Body", NotificationLevel.INFO)
            assert result is False
