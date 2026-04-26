"""Activity tab — system event log in clear language.

Shows all system events (start, stop, mode changes, errors,
connections, healthchecks) reformulated for non-technical users.

Uses PyQt-Fluent-Widgets for Windows 11 Fluent Design.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    PushButton,
    SubtitleLabel,
    TableWidget,
)

logger = logging.getLogger("ward_soar.ui.activity_view")

# Map raw event types to user-friendly messages
_EVENT_REWRITES: dict[str, tuple[str, str]] = {
    # (event_keyword_in_details, friendly_event_label)
}


def _rewrite_event(event: str, details: str) -> tuple[str, str, QColor | None]:
    """Rewrite a raw engine event into user-friendly language.

    Returns:
        (friendly_event, friendly_details, optional_color)
    """
    event_upper = event.upper()

    if event_upper == "SYSTEM":
        if "Engine started" in details:
            mode = "Monitor" if "Monitor" in details else "Protect"
            return "Started", f"WardSOAR started in {mode} mode", QColor(76, 175, 80)
        return "System", details, None

    if event_upper == "HEALTH":
        if "healthy" in details.lower():
            return "Health check", "All systems operational", QColor(76, 175, 80)
        if "degraded" in details.lower():
            return "Health warning", "Some components need attention", QColor(255, 152, 0)
        if "failed" in details.lower():
            return "Health alert", "System component failure detected", QColor(244, 67, 54)
        return "Health check", details, None

    if event_upper.startswith("SSH:"):
        status = event.replace("SSH: ", "").replace("SSH:", "")
        # Only show disconnections and errors — connections are noise
        if "Disconnect" in status:
            return "Firewall", "Lost connection to pfSense", QColor(244, 67, 54)
        # Skip connection/reconnection events
        return "", "", None

    if event_upper == "MODE":
        if "Protect" in details:
            return "Mode changed", "Switched to Protect — blocking enabled", QColor(244, 67, 54)
        return "Mode changed", "Switched to Monitor — blocking disabled", QColor(0, 120, 212)

    if event_upper == "PIPELINE":
        if "confirmed" in details.lower():
            return "Threat blocked", details, QColor(244, 67, 54)
        if "suspicious" in details.lower():
            return "Suspicious activity", details, QColor(255, 152, 0)
        if "benign" in details.lower():
            return "False positive", details, QColor(76, 175, 80)
        return "Alert analyzed", details, None

    if event_upper == "ERROR":
        return "Error", details, QColor(244, 67, 54)

    # Network events (SSH, DNS, TLS, HTTP) — skip, not useful for users
    if event_upper in ("SSH", "DNS", "TLS", "HTTP"):
        return "", "", None  # empty = will be filtered out

    if event_upper == "FILTERED":
        return "Filtered", details, QColor(158, 158, 158)

    if event_upper == "ALERT":
        return "IDS Alert", details, QColor(255, 152, 0)

    if event_upper == "DIVERGENCE":
        # Step 11 of project_dual_suricata_sync.md. The pipeline
        # tags two-source disagreements that reached stage 0.5;
        # ``details`` is the explanation token from the
        # DivergenceInvestigator. Three visual classes drive the
        # operator's eye:
        #   * benign-explained (loopback / VPN / LAN-only)
        #     -> info blue, prefixed with "i" — normal traffic
        #     pattern, no action needed.
        #   * suricata_local_dead -> warning orange, prefixed with
        #     "!" — high-signal failure mode that bumps the verdict.
        #   * unexplained -> warning red, prefixed with "!!" — the
        #     local Suricata is silent for an unknown reason; the
        #     verdict is bumped and the operator should investigate.
        explanation = details.lower().strip()
        if explanation in ("loopback_traffic", "vpn_traffic", "lan_only_traffic"):
            label = explanation.replace("_traffic", "").replace("_", " ")
            return (
                "Divergence (info)",
                f"i  Two-source disagreement explained by {label} traffic — normal",
                QColor(0, 120, 212),
            )
        if explanation == "suricata_local_dead":
            return (
                "Divergence (warning)",
                "!  Local Suricata stopped during the event — verdict escalated",
                QColor(255, 152, 0),
            )
        # Default branch — unexplained or unknown explanation token.
        return (
            "Divergence (alert)",
            "!! Unexplained divergence between sources — verdict escalated",
            QColor(244, 67, 54),
        )

    return event, details, None


class ActivityView(QWidget):
    """Activity log tab — all system events in clear language.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        header.addWidget(SubtitleLabel("System Activity"))
        header.addStretch()
        self._clear_btn = PushButton("Clear")
        self._clear_btn.clicked.connect(self._on_clear)
        header.addWidget(self._clear_btn)
        layout.addLayout(header)

        # Activity table
        self._table = TableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["Time", "Event", "Details"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 120)
        self._table.setColumnWidth(1, 140)
        self._table.setRowCount(0)
        layout.addWidget(self._table, stretch=1)

    def add_activity(self, time: str, event: str, details: str) -> None:
        """Add an activity entry, rewritten for clarity (newest first, max 500)."""
        friendly_event, friendly_details, color = _rewrite_event(event, details)

        # Skip filtered events (network traffic noise)
        if not friendly_event:
            return

        if self._table.rowCount() >= 500:
            self._table.removeRow(self._table.rowCount() - 1)

        self._table.insertRow(0)

        time_item = QTableWidgetItem(time)
        event_item = QTableWidgetItem(friendly_event)
        details_item = QTableWidgetItem(friendly_details)

        if color:
            event_item.setForeground(color)

        self._table.setItem(0, 0, time_item)
        self._table.setItem(0, 1, event_item)
        self._table.setItem(0, 2, details_item)

    def _on_clear(self) -> None:
        """Clear all activity entries."""
        self._table.setRowCount(0)
