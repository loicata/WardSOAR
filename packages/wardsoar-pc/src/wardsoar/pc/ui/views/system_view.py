"""System tab — health of the WardSOAR pipeline + active Windows services.

Two stacked tables:

* **System Health** — internal pipeline components fed by the
  ``health_updated`` signal from the PipelineController. The table is
  populated dynamically on first event for each component name; no
  hardcoded list. The set of probes (and therefore component names) is
  authoritative in :mod:`wardsoar.pc.healthcheck`, so duplicating it
  here would just risk drifting.
* **Active Services** — Windows services declared in ``config.yaml``
  under ``system_view.services``. Refresh cadence is also configurable
  (``system_view.refresh_interval_seconds``). Services that are not
  installed on the host are silently skipped — listing every
  conceivable security product would just add noise.

This view is Windows-only (``psutil.win_service_iter``); it lives
under ``wardsoar.pc.ui`` per the layering contract in
``CLAUDE.md`` §10.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHeaderView,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    CaptionLabel,
    PushButton,
    SimpleCardWidget,
    SubtitleLabel,
    TableWidget,
)

logger = logging.getLogger("ward_soar.ui.system_view")

COLOR_GREEN = QColor(76, 175, 80)
COLOR_ORANGE = QColor(255, 152, 0)
COLOR_RED = QColor(244, 67, 54)
COLOR_GREY = QColor(158, 158, 158)

# Fallback used only when the operator's ``config.yaml`` carries no
# ``system_view.refresh_interval_seconds`` key. Picked to be fast
# enough that a manual ``net stop`` shows up before the operator
# checks twice, and slow enough that the WMI query overhead stays
# invisible in the activity log.
_DEFAULT_REFRESH_INTERVAL_SECONDS = 30


class SystemView(QWidget):
    """System tab: pipeline health + active Windows services.

    Args:
        services: List of ``{label, service_name}`` dicts read from
            ``config.yaml`` (``system_view.services``). Empty list is
            valid — the Active Services card simply shows a "no
            services configured" placeholder.
        refresh_interval_seconds: How often to re-query the services.
            Read from the same config section.
        parent: Standard Qt parent.
    """

    def __init__(
        self,
        services: list[dict[str, Any]],
        refresh_interval_seconds: Optional[int] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._services_config = [
            (
                str(entry.get("label") or entry.get("service_name", "")),
                str(entry.get("service_name", "")),
            )
            for entry in services
            if entry.get("service_name")
        ]
        interval = (
            refresh_interval_seconds
            if refresh_interval_seconds is not None
            else _DEFAULT_REFRESH_INTERVAL_SECONDS
        )
        self._refresh_interval_ms = max(1, interval) * 1000

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(SubtitleLabel("System"))

        # --- System Health card ---
        health_card = SimpleCardWidget()
        health_layout = QVBoxLayout(health_card)
        health_layout.setContentsMargins(16, 12, 16, 12)
        health_layout.addWidget(CaptionLabel("System Health"))

        self._health_table = TableWidget()
        self._health_table.setColumnCount(2)
        self._health_table.setHorizontalHeaderLabels(["Component", "Status"])
        self._health_table.verticalHeader().setVisible(False)
        self._health_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._health_table.setShowGrid(False)
        self._health_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._health_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        # Maps component name → row index. Rows are added on the first
        # update_health event for each component, which is the only way
        # we can avoid duplicating the (configurable) list of probes
        # owned by ``wardsoar.pc.healthcheck``.
        self._health_rows: dict[str, int] = {}
        health_layout.addWidget(self._health_table)
        layout.addWidget(health_card)

        # --- Active Services card ---
        services_card = SimpleCardWidget()
        services_layout = QVBoxLayout(services_card)
        services_layout.setContentsMargins(16, 12, 16, 12)
        services_layout.addWidget(CaptionLabel("Active Services"))

        self._services_table = TableWidget()
        self._services_table.setColumnCount(3)
        self._services_table.setHorizontalHeaderLabels(["Service", "Status", "Start"])
        self._services_table.verticalHeader().setVisible(False)
        self._services_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._services_table.setShowGrid(False)
        self._services_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._services_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self._services_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        services_layout.addWidget(self._services_table)

        refresh_btn = PushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_services)
        services_layout.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)
        layout.addWidget(services_card, stretch=1)

        # First snapshot + periodic refresh.
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(self._refresh_interval_ms)
        self._refresh_timer.timeout.connect(self.refresh_services)
        self._refresh_timer.start()
        self.refresh_services()

    def update_health(self, component: str, status: str) -> None:
        """Update one component health row.

        Connected to ``PipelineController.health_updated`` via the
        engine bridge. New component names create new rows on first
        sight; subsequent events update the existing row in place.
        """
        if component not in self._health_rows:
            row = self._health_table.rowCount()
            self._health_table.insertRow(row)
            self._health_table.setItem(row, 0, QTableWidgetItem(component))
            self._health_rows[component] = row
        row = self._health_rows[component]
        status_item = QTableWidgetItem(status)
        color = {
            "healthy": COLOR_GREEN,
            "degraded": COLOR_ORANGE,
            "failed": COLOR_RED,
        }.get(status.lower())
        if color is not None:
            status_item.setForeground(color)
        self._health_table.setItem(row, 1, status_item)

    def refresh_services(self) -> None:
        """Re-query the watched Windows services and rebuild the table.

        Best-effort — if ``psutil`` is unavailable or the query fails,
        the table shows a one-row notice rather than crashing the UI.
        Services declared in config but not installed on the host
        appear as "Not installed" so the operator knows the wiring
        reached this layer.
        """
        if not self._services_config:
            self._services_table.setRowCount(1)
            placeholder = QTableWidgetItem("No services configured")
            placeholder.setForeground(COLOR_GREY)
            self._services_table.setItem(0, 0, placeholder)
            self._services_table.setItem(0, 1, QTableWidgetItem(""))
            self._services_table.setItem(0, 2, QTableWidgetItem(""))
            return

        installed = _query_windows_services()
        self._services_table.setRowCount(len(self._services_config))
        for row, (label, service_name) in enumerate(self._services_config):
            self._services_table.setItem(row, 0, QTableWidgetItem(label))
            entry = installed.get(service_name)
            if entry is None:
                missing = QTableWidgetItem("Not installed")
                missing.setForeground(COLOR_GREY)
                self._services_table.setItem(row, 1, missing)
                self._services_table.setItem(row, 2, QTableWidgetItem(""))
                continue
            status, start_type = entry
            status_item = QTableWidgetItem(status)
            color = {
                "running": COLOR_GREEN,
                "stopped": COLOR_GREY,
                "paused": COLOR_ORANGE,
            }.get(status.lower(), COLOR_RED)
            status_item.setForeground(color)
            self._services_table.setItem(row, 1, status_item)
            self._services_table.setItem(row, 2, QTableWidgetItem(start_type))


def _query_windows_services() -> dict[str, tuple[str, str]]:
    """Return ``{service_name: (status, start_type)}`` for every installed service.

    Best-effort: per-service errors are swallowed so the loop returns
    whatever subset the SCM allowed. A total failure (psutil missing,
    SCM access denied) returns an empty dict.
    """
    try:
        import psutil
    except ImportError:
        logger.warning("psutil unavailable — services tab will show no data")
        return {}

    out: dict[str, tuple[str, str]] = {}
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                out[info["name"]] = (
                    info.get("status", "unknown"),
                    info.get("start_type", "unknown"),
                )
            except Exception:  # noqa: BLE001 — per-service failures must not break the loop
                continue
    except Exception:  # noqa: BLE001 — SCM access can fail on locked-down hosts
        logger.warning("win_service_iter failed", exc_info=True)
    return out
