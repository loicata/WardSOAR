"""Send notifications on key events.

Three notification channels:
- Windows native (MANDATORY): Qt tray icon + toast (set by UI layer)
- Email (OPTIONAL): SMTP, disabled by default
- Telegram (OPTIONAL): Bot messages, disabled by default

Rate-limited to prevent notification storms during burst alerts.
Fail-safe: if any channel fails, log the error and continue.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Optional

import aiosmtplib
from aiosmtplib import SMTPException

from wardsoar.core.models import DecisionRecord

logger = logging.getLogger("ward_soar.notifier")


class NotificationLevel(str, Enum):
    """Notification severity levels."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class NotificationEvent(str, Enum):
    """Types of notification events."""

    THREAT_BLOCKED = "threat_blocked"
    MANUAL_REVIEW_NEEDED = "manual_review_needed"
    HEALTHCHECK_FAILURE = "healthcheck_failure"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    DAILY_SUMMARY = "daily_summary"


class TrayStatus(str, Enum):
    """System tray icon status indicators."""

    HEALTHY = "healthy"
    ALERT_PENDING = "alert"
    CRITICAL = "critical"
    OFFLINE = "offline"


class Notifier:
    """Send notifications via Windows tray and optional external channels.

    Args:
        config: Notifier configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._rate_limit_per_minute: int = config.get("rate_limit_per_minute", 10)
        self._daily_summary: bool = config.get("daily_summary", True)

        # Windows tray (set by UI layer)
        win_config: dict[str, Any] = config.get("windows", {})
        self._toast_duration_ms: int = win_config.get("toast_duration_seconds", 10) * 1000
        self._sound_critical: bool = win_config.get("sound_critical", True)
        self._tray_manager: Optional[object] = None
        self._tray_status: TrayStatus = TrayStatus.OFFLINE
        self._unread_count: int = 0

        # Email channel
        email_config: dict[str, Any] = config.get("email", {})
        self._email_enabled: bool = email_config.get("enabled", False)
        self._email_events: dict[str, bool] = email_config.get("events", {})
        self._smtp_host: str = email_config.get("smtp_host", "")
        self._smtp_port: int = email_config.get("smtp_port", 587)
        self._smtp_use_tls: bool = email_config.get("smtp_use_tls", True)
        self._email_from: str = email_config.get("from", "")
        self._email_to: str = email_config.get("to", "")

        # Telegram channel
        telegram_config: dict[str, Any] = config.get("telegram", {})
        self._telegram_enabled: bool = telegram_config.get("enabled", False)
        self._telegram_events: dict[str, bool] = telegram_config.get("events", {})
        self._telegram_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self._telegram_chat_id: str = telegram_config.get("chat_id", "")

        # Rate limiting
        self._recent_notifications: list[datetime] = []

    def set_tray_manager(self, tray_manager: object) -> None:
        """Connect the notifier to the Qt TrayManager.

        Args:
            tray_manager: The TrayManager instance from the UI layer.
        """
        self._tray_manager = tray_manager
        self._tray_status = TrayStatus.HEALTHY

    def _check_rate_limit(self) -> bool:
        """Check if we are within the notification rate limit.

        Returns:
            True if sending is allowed.
        """
        now = datetime.now(timezone.utc)
        self._recent_notifications = [
            t for t in self._recent_notifications if (now - t).total_seconds() < 60
        ]
        if len(self._recent_notifications) >= self._rate_limit_per_minute:
            return False
        self._recent_notifications.append(now)
        return True

    async def notify(
        self,
        level: NotificationLevel,
        event: NotificationEvent,
        title: str,
        message: str,
        data: Optional[dict[str, Any]] = None,
    ) -> None:
        """Send a notification on all active channels.

        Args:
            level: Notification severity.
            event: Event type.
            title: Short title.
            message: Detailed message.
            data: Optional structured data.
        """
        if not self._enabled:
            return

        self._unread_count += 1
        logger.info("Notification [%s] %s: %s", level.value, title, message)

        if not self._check_rate_limit():
            logger.warning("Notification rate limit reached, skipping channels")
            return

        # Update tray status
        if level == NotificationLevel.CRITICAL:
            self._tray_status = TrayStatus.CRITICAL
        elif level == NotificationLevel.WARNING:
            if self._tray_status != TrayStatus.CRITICAL:
                self._tray_status = TrayStatus.ALERT_PENDING

        # Email channel
        if self._email_enabled and self._email_events.get(event.value, False):
            await self._send_email(title, message, level)

        # Telegram channel
        if self._telegram_enabled and self._telegram_events.get(event.value, False):
            await self._send_telegram(f"[{level.value.upper()}] {title}\n{message}", level)

    async def notify_threat_blocked(self, record: DecisionRecord) -> None:
        """Notify that a threat was confirmed and blocked.

        Args:
            record: The decision record for the blocked threat.
        """
        title = f"Threat Blocked: {record.alert.src_ip}"
        message = (
            f"Signature: {record.alert.alert_signature}\n"
            f"Confidence: {record.analysis.confidence if record.analysis else 'N/A'}"
        )
        await self.notify(
            NotificationLevel.CRITICAL, NotificationEvent.THREAT_BLOCKED, title, message
        )

    async def notify_manual_review(self, record: DecisionRecord) -> None:
        """Notify that an alert requires manual review.

        Args:
            record: The decision record requiring review.
        """
        title = f"Review Needed: {record.alert.src_ip}"
        message = f"Signature: {record.alert.alert_signature}"
        await self.notify(
            NotificationLevel.WARNING, NotificationEvent.MANUAL_REVIEW_NEEDED, title, message
        )

    async def notify_healthcheck_failure(self, component: str, error: str) -> None:
        """Notify that a system component has failed.

        Args:
            component: Name of the failed component.
            error: Error description.
        """
        await self.notify(
            NotificationLevel.CRITICAL,
            NotificationEvent.HEALTHCHECK_FAILURE,
            f"Component Failed: {component}",
            error,
        )

    async def send_daily_summary(self, metrics: dict[str, Any]) -> None:
        """Send a daily summary of system activity.

        Args:
            metrics: Summary metrics dict.
        """
        title = "Daily Summary"
        lines = [f"{k}: {v}" for k, v in metrics.items()]
        message = "\n".join(lines)
        await self.notify(NotificationLevel.INFO, NotificationEvent.DAILY_SUMMARY, title, message)

    def reset_unread(self) -> None:
        """Reset unread count (called when user opens alerts tab)."""
        self._unread_count = 0
        if self._tray_status == TrayStatus.ALERT_PENDING:
            self._tray_status = TrayStatus.HEALTHY

    async def _send_email(self, subject: str, body: str, level: NotificationLevel) -> bool:
        """Send an email notification.

        Args:
            subject: Email subject.
            body: Email body.
            level: Notification level.

        Returns:
            True if sent successfully.
        """
        if not self._email_enabled:
            return False

        try:
            msg = MIMEText(body)
            msg["Subject"] = f"[WardSOAR {level.value.upper()}] {subject}"
            msg["From"] = self._email_from
            msg["To"] = self._email_to

            await aiosmtplib.send(
                msg,
                hostname=self._smtp_host,
                port=self._smtp_port,
                username=os.getenv("SMTP_USER", ""),
                password=os.getenv("SMTP_PASSWORD", ""),
                use_tls=self._smtp_use_tls,
            )
            logger.info("Email notification sent: %s", subject)
            return True
        except (OSError, SMTPException) as exc:
            logger.error("Failed to send email: %s", exc)
            return False

    async def _send_telegram(self, message: str, level: NotificationLevel) -> bool:
        """Send a Telegram notification.

        Args:
            message: Message text.
            level: Notification level.

        Returns:
            True if sent successfully.
        """
        if not self._telegram_enabled or not self._telegram_token:
            return False

        try:
            import httpx

            url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json={"chat_id": self._telegram_chat_id, "text": message},
                    timeout=10,
                )
            if response.status_code == 200:
                logger.info("Telegram notification sent")
                return True
            logger.warning("Telegram API returned status %d", response.status_code)
            return False
        except (OSError, ValueError) as exc:
            logger.error("Failed to send Telegram notification: %s", exc)
            return False
