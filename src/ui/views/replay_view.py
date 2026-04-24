"""Replay tab — simulate config changes against historical alerts.

Displays date range picker, simulation controls, progress bar,
results comparison table, and impact summary.

Uses PyQt-Fluent-Widgets for Windows 11 Fluent Design.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CalendarPicker,
    PrimaryPushButton,
    ProgressBar,
    PushButton,
    SimpleCardWidget,
    SubtitleLabel,
    TableWidget,
)

logger = logging.getLogger("ward_soar.ui.replay_view")


class ReplayView(QWidget):
    """Replay simulation tab with controls, progress, and results.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Controls card
        controls_card = SimpleCardWidget()
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(20, 16, 20, 16)
        controls_layout.addWidget(SubtitleLabel("Simulation Configuration"))

        # Date range
        date_row = QHBoxLayout()
        date_row.addWidget(BodyLabel("From:"))
        self._date_from = CalendarPicker()
        date_row.addWidget(self._date_from)
        date_row.addWidget(BodyLabel("To:"))
        self._date_to = CalendarPicker()
        date_row.addWidget(self._date_to)
        date_row.addStretch()
        controls_layout.addLayout(date_row)

        # Action buttons
        btn_row = QHBoxLayout()
        self._start_btn = PrimaryPushButton("Start Simulation")
        self._stop_btn = PushButton("Stop")
        self._stop_btn.setEnabled(False)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        controls_layout.addLayout(btn_row)

        layout.addWidget(controls_card)

        # Progress bar
        self._progress = ProgressBar()
        self._progress.setValue(0)
        layout.addWidget(self._progress)

        # Impact card
        impact_card = SimpleCardWidget()
        impact_layout = QVBoxLayout(impact_card)
        impact_layout.setContentsMargins(20, 12, 20, 12)
        impact_layout.addWidget(SubtitleLabel("Impact Report"))

        metrics_row = QHBoxLayout()
        self._total_label = BodyLabel("Total: 0")
        self._changes_label = BodyLabel("Changes: 0")
        self._new_blocks_label = BodyLabel("New Blocks: 0")
        self._removed_label = BodyLabel("Removed: 0")
        for label in (
            self._total_label,
            self._changes_label,
            self._new_blocks_label,
            self._removed_label,
        ):
            metrics_row.addWidget(label)
        impact_layout.addLayout(metrics_row)
        layout.addWidget(impact_card)

        # Results table
        self._results_table = TableWidget()
        self._results_table.setColumnCount(5)
        self._results_table.setHorizontalHeaderLabels(
            ["Time", "Source IP", "Signature", "Original", "Replay"]
        )
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._results_table.setRowCount(0)
        layout.addWidget(self._results_table, stretch=1)

    def set_progress(self, value: int) -> None:
        """Update the progress bar value (0-100)."""
        self._progress.setValue(value)

    def update_impact(self, report: dict[str, Any]) -> None:
        """Update impact summary labels."""
        self._total_label.setText(f"Total: {report.get('total_replayed', 0)}")
        self._changes_label.setText(f"Changes: {report.get('verdict_changes', 0)}")
        self._new_blocks_label.setText(f"New Blocks: {report.get('new_blocks', 0)}")
        self._removed_label.setText(f"Removed: {report.get('removed_blocks', 0)}")

    def add_result_row(
        self,
        time: str,
        src_ip: str,
        signature: str,
        original: str,
        replay: str,
    ) -> None:
        """Add a replay result row to the table."""
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)
        self._results_table.setItem(row, 0, QTableWidgetItem(time))
        self._results_table.setItem(row, 1, QTableWidgetItem(src_ip))
        self._results_table.setItem(row, 2, QTableWidgetItem(signature))

        orig_item = QTableWidgetItem(original)
        replay_item = QTableWidgetItem(replay)

        # Highlight verdict changes
        if original != replay:
            orig_item.setForeground(QColor(255, 152, 0))
            replay_item.setForeground(QColor(76, 175, 80))

        self._results_table.setItem(row, 3, orig_item)
        self._results_table.setItem(row, 4, replay_item)

    def clear_results(self) -> None:
        """Clear the results table."""
        self._results_table.setRowCount(0)

    def set_running(self, running: bool) -> None:
        """Update UI state for running/stopped simulation."""
        self._start_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        self._date_from.setEnabled(not running)
        self._date_to.setEnabled(not running)
