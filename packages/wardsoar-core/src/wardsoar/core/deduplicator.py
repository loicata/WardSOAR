"""Deduplicate and group Suricata alerts by source IP and signature.

Prevents processing the same attack pattern multiple times when
Suricata generates many alerts for a single event. Also detects
burst patterns that may indicate a real attack.

Fail-safe: if grouping fails, process alert individually.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from wardsoar.core.models import SuricataAlert

logger = logging.getLogger("ward_soar.deduplicator")


class AlertGroup:
    """A group of related alerts sharing the same (src_ip, signature_id).

    Attributes:
        key: Tuple of (src_ip, signature_id) identifying this group.
        alerts: List of alerts in this group.
        first_seen: Timestamp of the first alert.
        last_seen: Timestamp of the most recent alert.
    """

    def __init__(self, key: tuple[str, int], first_alert: SuricataAlert) -> None:
        self.key = key
        self.alerts: list[SuricataAlert] = [first_alert]
        self.first_seen: datetime = first_alert.timestamp
        self.last_seen: datetime = first_alert.timestamp

    @property
    def count(self) -> int:
        """Number of alerts in this group."""
        return len(self.alerts)


class AlertDeduplicator:
    """Group and deduplicate alerts within a time window.

    Args:
        config: Deduplicator configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._window_seconds: int = config.get("grouping_window_seconds", 60)
        self._max_group_size: int = config.get("max_group_size", 50)
        self._burst_escalation: bool = config.get("burst_escalation", True)
        self._groups: dict[tuple[str, int], AlertGroup] = {}

    def _is_within_window(self, group: AlertGroup, alert: SuricataAlert) -> bool:
        """Check if an alert falls within the group's time window.

        Args:
            group: The existing alert group.
            alert: The incoming alert.

        Returns:
            True if the alert is within the grouping window.
        """
        elapsed = (alert.timestamp - group.last_seen).total_seconds()
        return elapsed <= self._window_seconds

    def process_alert(self, alert: SuricataAlert) -> Optional[AlertGroup]:
        """Process an incoming alert and decide if it should trigger analysis.

        Args:
            alert: The incoming Suricata alert.

        Returns:
            AlertGroup if this alert should trigger analysis (new group or burst),
            None if it was merged into an existing group and should be skipped.
        """
        if not self._enabled:
            return AlertGroup(key=(alert.src_ip, alert.alert_signature_id), first_alert=alert)

        key = (alert.src_ip, alert.alert_signature_id)
        existing = self._groups.get(key)

        if existing is not None and self._is_within_window(existing, alert):
            # Merge into existing group
            existing.alerts.append(alert)
            existing.last_seen = alert.timestamp

            # Check burst threshold
            if self._burst_escalation and existing.count > self._max_group_size:
                logger.info(
                    "Burst detected: %s SID %d — %d alerts in group",
                    key[0],
                    key[1],
                    existing.count,
                )
                return existing

            logger.debug(
                "Merged alert into group: %s SID %d — %d alerts",
                key[0],
                key[1],
                existing.count,
            )
            return None

        # New group (or old group expired)
        group = AlertGroup(key=key, first_alert=alert)
        self._groups[key] = group
        logger.debug("New alert group: %s SID %d", key[0], key[1])
        return group

    def expire_old_groups(self) -> None:
        """Remove alert groups older than the grouping window."""
        now = datetime.now(timezone.utc)
        cutoff = timedelta(seconds=self._window_seconds)
        expired_keys = [
            key for key, group in self._groups.items() if (now - group.last_seen) > cutoff
        ]
        for key in expired_keys:
            del self._groups[key]
            logger.debug("Expired alert group: %s SID %d", key[0], key[1])

    def get_group_context(self, key: tuple[str, int]) -> Optional[AlertGroup]:
        """Get the alert group for a given key, if it exists.

        Args:
            key: Tuple of (src_ip, signature_id).

        Returns:
            The AlertGroup if found, None otherwise.
        """
        return self._groups.get(key)
