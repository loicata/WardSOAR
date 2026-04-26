"""Main application window for WardSOAR.

PySide6 + PyQt-Fluent-Widgets (Windows 11 Fluent Design):
- FluentWindow with NavigationView sidebar
- Mica backdrop effect (Windows 11)
- Dark/Light theme via qfluentwidgets.setTheme()
- System tray icon with color-coded status (green/orange/red)
- Native Windows toast notifications
- Minimize to tray (stays running in background)
- Single instance enforcement
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QPointF, QSettings, Qt
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QIcon,
    QPainter,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QApplication,
    QMenu,
    QSystemTrayIcon,
    QWidget,
)
from qfluentwidgets import (
    FluentIcon as FIF,
    FluentWindow,
    NavigationItemPosition,
    Theme,
    setTheme,
    setThemeColor,
)

from wardsoar.core.config import get_app_dir, get_data_dir, load_config, load_env, load_whitelist
from wardsoar.pc.main import Pipeline
from wardsoar.core.remote_agents import NetgateAgent
from wardsoar.pc.ui.agent_stream_consumer import AgentStreamConsumer
from wardsoar.pc.ui.engine_bridge import EngineWorker
from wardsoar.pc.ui.views.activity_view import ActivityView
from wardsoar.pc.ui.views.alerts import AlertsView
from wardsoar.pc.ui.views.config_view import ConfigView
from wardsoar.pc.ui.views.dashboard import DashboardView
from wardsoar.pc.ui.views.keys_view import KeysView
from wardsoar.pc.ui.views.netgate import NetgateView
from wardsoar.pc.ui.views.replay_view import ReplayView

logger = logging.getLogger("ward_soar.ui.app")

# Window constants
DEFAULT_WIDTH = 1600
DEFAULT_HEIGHT = 900
MIN_WIDTH = 1280
MIN_HEIGHT = 720
APP_NAME = "WardSOAR"
ORG_NAME = "loicata"


def _create_status_icon(color: QColor, size: int = 32) -> QIcon:
    """Create a shield icon with status color for the system tray.

    Draws a shield shape filled with the given status color,
    matching the application's sentinel/security theme.

    Args:
        color: Status color (green=healthy, orange=alert, red=critical, grey=offline).
        size: Icon size in pixels.

    Returns:
        QIcon with a colored shield.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    margin = max(1, size // 10)
    cx = size // 2
    top = margin
    bottom = size - margin
    left = margin + size // 8
    right = size - margin - size // 8
    mid_y = cx + size // 6

    # Shield shape
    shield = QPolygonF(
        [
            QPointF(cx, top),
            QPointF(right, top + size // 6),
            QPointF(right, mid_y),
            QPointF(cx, bottom),
            QPointF(left, mid_y),
            QPointF(left, top + size // 6),
        ]
    )

    # Dark base + status color overlay
    painter.setBrush(QColor(20, 30, 70))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawPolygon(shield)

    # Status dot in center
    dot_r = max(2, size // 6)
    dot_y = cx - size // 12
    painter.setBrush(color)
    painter.drawEllipse(cx - dot_r, dot_y - dot_r, dot_r * 2, dot_r * 2)

    painter.end()
    return QIcon(pixmap)


class TrayManager(QSystemTrayIcon):
    """System tray icon with status and notifications.

    Args:
        parent: Parent widget (MainWindow).
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._status = "offline"
        self._unread_count = 0

        # Status icons
        self._icons = {
            "healthy": _create_status_icon(QColor(76, 175, 80)),  # Green
            "alert": _create_status_icon(QColor(255, 152, 0)),  # Orange
            "critical": _create_status_icon(QColor(244, 67, 54)),  # Red
            "offline": _create_status_icon(QColor(158, 158, 158)),  # Grey
        }

        self.setIcon(self._icons["offline"])
        self.setToolTip(f"{APP_NAME} — Offline")

        # Context menu
        self._menu = QMenu()
        self._open_action = QAction("Open WardSOAR", self._menu)
        self._status_action = QAction("Status: Offline", self._menu)
        self._status_action.setEnabled(False)
        self._unread_action = QAction("Unread alerts: 0", self._menu)
        self._unread_action.setEnabled(False)
        self._mode_action = QAction("Mode: Dry-run", self._menu)
        self._mode_action.setEnabled(False)
        self._quit_action = QAction("Quit", self._menu)

        self._menu.addAction(self._open_action)
        self._menu.addSeparator()
        self._menu.addAction(self._status_action)
        self._menu.addAction(self._unread_action)
        self._menu.addSeparator()
        self._menu.addAction(self._mode_action)
        self._menu.addSeparator()
        self._menu.addAction(self._quit_action)

        self.setContextMenu(self._menu)
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle tray icon activation (double-click opens window).

        Args:
            reason: Activation reason.
        """
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._open_action.trigger()

    def set_status(self, status: str) -> None:
        """Update the tray icon status.

        Args:
            status: One of 'healthy', 'alert', 'critical', 'offline'.
        """
        self._status = status
        icon = self._icons.get(status, self._icons["offline"])
        self.setIcon(icon)
        self._status_action.setText(f"Status: {status.capitalize()}")
        self._update_tooltip()

    def set_unread_count(self, count: int) -> None:
        """Update the unread alert count.

        Args:
            count: Number of unread alerts.
        """
        self._unread_count = count
        self._unread_action.setText(f"Unread alerts: {count}")
        self._update_tooltip()

    def set_mode(self, mode: str) -> None:
        """Update the operating mode display.

        Args:
            mode: Operating mode string.
        """
        self._mode_action.setText(f"Mode: {mode}")

    def _update_tooltip(self) -> None:
        """Update the tray icon tooltip text."""
        parts = [APP_NAME, f"Status: {self._status.capitalize()}"]
        if self._unread_count > 0:
            parts.append(f"{self._unread_count} unread alert(s)")
        self.setToolTip(" — ".join(parts))

    def show_notification(self, title: str, message: str, level: str = "info") -> None:
        """Show a native Windows toast notification.

        Args:
            title: Notification title.
            message: Notification message.
            level: One of 'info', 'warning', 'critical'.
        """
        icon_map = {
            "info": QSystemTrayIcon.MessageIcon.Information,
            "warning": QSystemTrayIcon.MessageIcon.Warning,
            "critical": QSystemTrayIcon.MessageIcon.Critical,
        }
        msg_icon = icon_map.get(level, QSystemTrayIcon.MessageIcon.Information)
        self.showMessage(title, message, msg_icon, 10000)


class MainWindow(FluentWindow):  # type: ignore[misc]
    """Main window with Fluent Design navigation.

    Uses FluentWindow from qfluentwidgets which provides:
    - Built-in NavigationView sidebar
    - Mica backdrop (Windows 11)
    - Smooth transitions between views

    Args:
        parent: Parent widget.
    """

    _INTERFACE_NAMES = ["Dashboard", "Alerts", "Configuration", "Replay"]

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(MIN_WIDTH, MIN_HEIGHT)

        # Set window icon from assets
        if getattr(sys, "frozen", False):
            icon_path = (
                Path(sys.executable).parent / "_internal" / "src" / "ui" / "assets" / "ward.ico"
            )
        else:
            icon_path = get_app_dir() / "src" / "ui" / "assets" / "ward.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._settings = QSettings(ORG_NAME, APP_NAME)
        self._minimize_to_tray = True

        # Create views
        self._dashboard = DashboardView()
        self._dashboard.setObjectName("dashboardView")
        self._alerts = AlertsView()
        self._alerts.setObjectName("alertsView")
        self._activity = ActivityView()
        self._activity.setObjectName("activityView")
        self._config = ConfigView()
        self._config.setObjectName("configView")
        self._keys = KeysView()
        self._keys.setObjectName("keysView")
        self._replay = ReplayView()
        self._replay.setObjectName("replayView")
        self._netgate = NetgateView()
        self._netgate.setObjectName("netgateView")

        # Connect dashboard activity forwarding to Activity tab
        self._dashboard._activity_callback = self._activity.add_activity

        # Add views to FluentWindow navigation
        self.addSubInterface(
            self._dashboard,
            FIF.HOME,
            "Dashboard",
            position=NavigationItemPosition.TOP,
        )
        self.addSubInterface(
            self._alerts,
            FIF.MAIL,
            "Alerts",
            position=NavigationItemPosition.TOP,
        )
        self.addSubInterface(
            self._activity,
            FIF.HISTORY,
            "Activity",
            position=NavigationItemPosition.TOP,
        )
        self.addSubInterface(
            self._config,
            FIF.SETTING,
            "Configuration",
            position=NavigationItemPosition.BOTTOM,
        )
        self.addSubInterface(
            self._keys,
            FIF.VPN,
            "Keys",
            position=NavigationItemPosition.BOTTOM,
        )
        self.addSubInterface(
            self._replay,
            FIF.SYNC,
            "Replay",
            position=NavigationItemPosition.BOTTOM,
        )
        self.addSubInterface(
            self._netgate,
            FIF.CERTIFICATE,
            "Netgate",
            position=NavigationItemPosition.BOTTOM,
        )

        # About — last item in the bottom group. Not a sub-interface:
        # a plain click item that opens a modal dialog with the
        # version / copyright / license block. ``selectable=False``
        # keeps the navigation highlight on whatever the operator was
        # viewing when they clicked About.
        from wardsoar.pc.ui.views.about_dialog import show_about_dialog

        self.navigationInterface.addItem(
            routeKey="about",
            icon=FIF.INFO,
            text="About",
            onClick=lambda: show_about_dialog(self),
            selectable=False,
            position=NavigationItemPosition.BOTTOM,
        )

        # Restore geometry
        self._restore_state()

    def _restore_state(self) -> None:
        """Restore window geometry from saved settings."""
        geometry = self._settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        else:
            self.resize(DEFAULT_WIDTH, DEFAULT_HEIGHT)

    def _save_state(self) -> None:
        """Save window geometry to settings."""
        self._settings.setValue("geometry", self.saveGeometry())

    def closeEvent(self, event: QCloseEvent) -> None:
        """Override close to minimize to tray instead of quitting.

        Args:
            event: The close event.
        """
        if self._minimize_to_tray:
            event.ignore()
            self.hide()
            self._save_state()
        else:
            self._save_state()
            event.accept()

    def quit_application(self) -> None:
        """Actually quit the application (from tray menu)."""
        self._minimize_to_tray = False
        self._save_state()
        self.close()


class WardApp:
    """Application orchestrator — creates window, tray, connects signals.

    Args:
        argv: Command line arguments.
    """

    def __init__(self, argv: Optional[list[str]] = None, first_run: bool = False) -> None:
        self._app = QApplication(argv or sys.argv)
        self._app.setApplicationName(APP_NAME)
        self._app.setOrganizationName(ORG_NAME)
        self._app.setQuitOnLastWindowClosed(False)

        # Apply Fluent dark theme + Windows 11 accent color
        setTheme(Theme.DARK)
        setThemeColor("#0078d4")

        # Single-instance guard — a named Win32 mutex. If another
        # WardSOAR is already running in the same user session, we
        # surface the existing window (best-effort) and exit instead
        # of racing on the EVE JSON stream and on log files. The guard
        # must stay alive for the lifetime of the process, hence the
        # self-reference on ``self``. See src/single_instance.py for
        # the fail-open semantics when pywin32 is not installed.
        from wardsoar.pc.single_instance import SingleInstanceGuard, activate_existing_window

        self._single_instance_guard = SingleInstanceGuard()
        if self._single_instance_guard.already_running():
            activated = activate_existing_window(APP_NAME)
            # Use a plain QMessageBox here — our main window does not
            # exist yet, and the qfluentwidgets ``MessageBox`` requires
            # a valid parent. A native dialog is fine for this one-off
            # "already running" notice.
            from PySide6.QtWidgets import QMessageBox

            box = QMessageBox()
            box.setIcon(QMessageBox.Icon.Information)
            box.setWindowTitle("WardSOAR already running")
            if activated:
                box.setText(
                    "Another WardSOAR instance is already running in this "
                    "session. Its window has been brought to the front."
                )
            else:
                box.setText(
                    "Another WardSOAR instance is already running in this "
                    "session (it may be minimised to the system tray). "
                    "Close it from the tray before launching a new one."
                )
            box.setStandardButtons(QMessageBox.StandardButton.Ok)
            box.exec()
            sys.exit(0)

        # Launch setup flow on first run (before load_config creates
        # defaults). The flow has two stages now (v0.22.20):
        #   1. SourcesQuestionnaire — three Yes/No questions about which
        #      alert sources the operator has (Netgate / Virus Sniff /
        #      local Suricata) plus a recap. Cancelling exits the app.
        #   2. SetupWizard — the eleven-page detailed config flow,
        #      gated on the source choices (e.g. pfSense SSH page is
        #      skipped when Netgate=No).
        if first_run:
            from wardsoar.core.config import get_data_dir
            from wardsoar.pc.ui.setup_wizard import SetupWizard
            from wardsoar.pc.ui.sources_questionnaire import SourcesQuestionnaire

            questionnaire = SourcesQuestionnaire()
            if questionnaire.exec() != SourcesQuestionnaire.DialogCode.Accepted:
                sys.exit(0)

            wizard = SetupWizard(
                data_dir=get_data_dir(),
                sources=questionnaire.choices,
            )
            if wizard.exec() != SetupWizard.DialogCode.Accepted:
                sys.exit(0)

        # Now load config (wizard created it, or it already existed)
        load_env()
        load_config()

        self._window = MainWindow()
        self._tray = TrayManager(self._window)

        # Connect tray signals
        self._tray._open_action.triggered.connect(self._show_window)
        self._tray._quit_action.triggered.connect(self._quit)

        self._tray.show()
        self._tray.set_status("healthy")

        # Start engine worker
        self._start_engine()

    def _start_engine(self) -> None:
        """Start the background engine worker with the full Pipeline."""
        try:
            load_env()
            config = load_config()
            whitelist = load_whitelist()
            watcher_mode = config.watcher.get("mode", "file")
            eve_path = config.watcher.get("eve_json_path", "")
            # v0.5.5 — ward_mode replaces the legacy ``dry_run`` bool. For
            # configs still on the old key, the translation below mirrors
            # what the config-migration layer writes back to disk.
            ward_mode = str(
                config.responder.get(
                    "mode",
                    "monitor" if config.responder.get("dry_run", True) else "protect",
                )
            )

            # Build healthcheck config with pfSense connection info
            healthcheck_cfg = dict(config.healthcheck)
            healthcheck_cfg["pfsense_ip"] = config.network.get("pfsense_ip", "")
            pfsense_cfg = config.responder.get("pfsense", {})
            healthcheck_cfg["pfsense_ssh_port"] = int(pfsense_cfg.get("ssh_port", 22))

            # Create the full 13-step Pipeline
            pipeline = Pipeline(config, whitelist)

            self._engine = EngineWorker(
                pipeline=pipeline,
                eve_path=eve_path,
                mode=watcher_mode,
                ward_mode=ward_mode,
                healthcheck_cfg=healthcheck_cfg,
            )

            # Connect signals to UI
            dashboard = self._window._dashboard
            alerts_view = self._window._alerts

            self._engine.alert_received.connect(alerts_view.add_alert_row)
            self._engine.alert_received.connect(self._on_alert_for_charts)
            self._engine.metrics_updated.connect(dashboard.update_metrics)
            self._engine.activity_logged.connect(dashboard.add_activity)
            self._engine.status_changed.connect(dashboard.set_status)
            self._engine.health_updated.connect(dashboard.update_health)
            # Rollback wiring: user clicks "Unblock IP" in the detail panel,
            # the engine runs the full rollback async, then reports back so
            # the UI can re-enable the button and log the outcome.
            alerts_view.rollback_requested.connect(self._engine.request_rollback)
            self._engine.rollback_completed.connect(alerts_view.on_rollback_completed)
            self._engine.rollback_completed.connect(self._on_rollback_completed)
            dashboard.mode_changed.connect(self._on_mode_changed)

            # v0.9.0 — Alert Detail view exposes three new signals. The
            # user-FP overlay is cheap (append to YAML + live-add to the
            # filter set), so we handle it synchronously on the UI thread.
            # Manual Review and Forensic Report are stubs for now — they
            # just log the request; the existing ManualReviewDialog and
            # forensic zip flow will be re-plugged in 0.9.1.
            alerts_view.add_sid_filter_requested.connect(self._on_add_sid_filter)
            alerts_view.manual_review_requested.connect(self._on_manual_review_requested)
            alerts_view.forensic_report_requested.connect(self._on_forensic_report_requested)

            # ConfigView exposes quick threshold spinboxes that map onto
            # the Responder's decision-rule knobs. Apply live so the
            # operator sees the effect on the next alert.
            config_view = self._window._config
            config_view.threshold_changed.connect(self._on_threshold_changed)

            # Netgate audit (Phase 7a) — "Run Check" button + result
            # stream. Also consulted by the mode-escalation gate below.
            netgate = self._window._netgate
            netgate.run_check_requested.connect(self._engine.request_netgate_audit)
            self._engine.netgate_audit_completed.connect(netgate.display_audit_result)

            # Tamper detection (Phase 7g) — Establish / Check buttons
            # connected to the pipeline's detector, and the initial
            # baseline state pushed into the view so the button label
            # reflects whether a baseline already exists on disk.
            netgate.establish_baseline_requested.connect(
                self._engine.request_netgate_establish_baseline
            )
            netgate.tamper_check_requested.connect(self._engine.request_netgate_tamper_check)
            self._engine.netgate_baseline_established.connect(netgate.display_baseline_established)
            self._engine.netgate_tamper_check_completed.connect(netgate.display_tamper_check)
            try:
                captured_at = pipeline.netgate_baseline_captured_at()
            except Exception:  # noqa: BLE001 — first-launch races, don't crash the UI
                logger.debug("Could not read initial baseline state", exc_info=True)
                captured_at = None
            netgate.set_baseline_status(captured_at)

            # Custom rules (Phase 7c) — Preview/Deploy buttons.
            netgate.deploy_custom_rules_requested.connect(self._engine.request_deploy_custom_rules)
            self._engine.netgate_custom_rules_deployed.connect(
                netgate.display_custom_rules_deployed
            )
            netgate.set_rules_provider(self._engine.preview_custom_rules)

            # Safe-apply (Phase 7b, v0.7.1) — operator ticks findings in
            # the Netgate tab and clicks Apply; we run the registered
            # handlers with backup + verify + rollback, then echo
            # results back for display.
            netgate.apply_fixes_requested.connect(self._engine.request_netgate_apply)
            self._engine.netgate_apply_completed.connect(netgate.display_apply_results)
            netgate.set_applicable_fix_ids(self._engine.netgate_applicable_fix_ids())

            # Post-reset cleanup — dedicated button in the Netgate tab
            # for the bootstrap track of a factory-reset appliance.
            netgate.netgate_reset_cleanup_requested.connect(
                self._engine.request_netgate_reset_cleanup
            )
            self._engine.netgate_reset_cleanup_completed.connect(
                netgate.display_netgate_reset_cleanup
            )

            # v0.6.4 — pop a Windows toast every time an IP is blocked.
            # Crucial: if the blocked IP is on the LAN (RFC 1918) we
            # mark the toast as *critical* so the operator sees it
            # immediately. The RFC 1918 guard in the Responder should
            # already prevent self-blocks, but a visible confirmation
            # is still valuable.
            self._engine.ip_blocked.connect(self._on_ip_blocked)
            # v0.17.1 \u2014 surface the outcome of a manual block
            # (triggered via Manual Review \u2192 CONFIRMED override) as
            # a Windows toast so the operator immediately knows
            # whether a safety rail refused the block.
            self._engine.manual_block_completed.connect(self._on_manual_block_completed)

            # v0.22.1 — rotate the active history file so it only
            # carries entries from the current calendar month. Past
            # months land in monthly archives that the alerts view
            # exposes via its "Archives" menu.
            try:
                from wardsoar.core.history_rotator import rotate_if_needed

                rotate_if_needed(self._engine.history_path)
            except Exception:  # noqa: BLE001 — rotation is best-effort
                logger.debug("History rotation skipped", exc_info=True)

            # Reload persisted alerts from previous sessions. v0.16.0
            # \u2014 also merge the operator's manual reviews so each
            # alert carries its ``manual_review`` dict on reload.
            # v0.22.1 — the active file is already bounded to the
            # current calendar month by ``rotate_if_needed`` above.
            # We still load only the 200 most recent entries at
            # startup so a busy month (a few thousand alerts) does
            # not stall the UI; the rest paginates via "Load older".
            history = self._engine.load_alert_history(limit=200)
            try:
                from wardsoar.core.config import get_data_dir
                from wardsoar.core.manual_reviews import (
                    default_store_path,
                    load_reviews,
                    merge_into_history,
                )

                reviews = load_reviews(default_store_path(get_data_dir()))
                if reviews:
                    merge_into_history(history, reviews)
                    logger.info("Merged %d manual review(s) into history", len(reviews))
            except Exception:  # noqa: BLE001 \u2014 defensive
                logger.warning("Could not merge manual reviews", exc_info=True)

            for alert_data in history:
                alerts_view.add_alert_row(alert_data)
                self._on_alert_for_charts(alert_data)
            if history:
                logger.info("Reloaded %d alerts from history", len(history))

            # v0.22.1 — align the AlertsView pagination cursor + wire
            # the lazy-load and archives signals. The view stays
            # agnostic of the engine; it just emits signals and
            # receives batches.
            alerts_view.mark_history_loaded(len(history))
            alerts_view.set_archive_provider(self._engine.list_history_archives)
            alerts_view.load_older_requested.connect(self._on_load_older_requested)
            alerts_view.load_archive_requested.connect(self._on_load_archive_requested)

            self._engine.start()

            # Start agent-driven alert stream consumer based on the
            # operator's ``sources`` choices (see SourcesQuestionnaire
            # / Pipeline.__init__ for the matching server-side wiring).
            #
            # Decision tree:
            #   sources.netgate=True AND
            #   sources.suricata_local=True     → DualSourceCorrelator
            #                                     (configs 3 / 5 — Q4
            #                                     A doctrine)
            #   sources.netgate=True            → NetgateAgent (SSH+tail)
            #   sources.suricata_local=True     → LocalSuricataAgent
            #                                     (local Suricata + WinFW)
            #   neither                          → no consumer (file mode)
            #
            # Phase 3b.5 introduced the AgentStreamConsumer abstraction
            # so any RemoteAgent's stream_alerts() can drive the
            # pipeline. The dual-source case (Step 9 of the
            # dual-Suricata implementation, see
            # project_dual_suricata_sync.md) wraps both agents in a
            # DualSourceCorrelator that fans them in to a single
            # tagged stream.
            sources = getattr(config, "sources", {}) or {}
            self._stream_consumer: Optional[AgentStreamConsumer] = None
            netgate_on = bool(sources.get("netgate", False)) and watcher_mode == "ssh"
            local_on = bool(sources.get("suricata_local", False))
            if netgate_on and local_on:
                self._start_dual_source_stream_consumer(config, dashboard)
            elif netgate_on:
                self._start_netgate_stream_consumer(config, dashboard)
            elif local_on:
                self._start_local_suricata_stream_consumer(config, dashboard)

            logger.info("Engine worker started (mode: %s)", watcher_mode)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Failed to start engine: %s", exc)

    def _start_netgate_stream_consumer(self, config: Any, dashboard: Any) -> None:
        """Start the agent-driven EVE event consumer for the Netgate source.

        Builds a :class:`NetgateAgent` from the operator's config and
        spawns an :class:`AgentStreamConsumer` to feed parsed events
        into ``EngineWorker.on_alert_event``. Reconnection is owned
        by the agent (see :meth:`PfSenseSSH.stream_alerts`).

        Args:
            config: Application configuration.
            dashboard: Dashboard view for status updates.
        """
        ssh_config = config.watcher.get("ssh", {})
        responder_ssh = config.responder.get("pfsense", {})
        network = config.network

        pfsense_ip = network.get("pfsense_ip", "192.168.2.1")
        pc_ip = network.get("pc_ip", "")
        ssh_user = responder_ssh.get("ssh_user", "admin")
        ssh_key_path = responder_ssh.get("ssh_key_path", "")
        ssh_port = int(responder_ssh.get("ssh_port", 22))
        remote_eve_path = ssh_config.get(
            "remote_eve_path",
            "/var/log/suricata/suricata_igc252678/eve.json",
        )

        agent = NetgateAgent.from_credentials(
            host=pfsense_ip,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            eve_path=remote_eve_path,
            local_bind_addr=pc_ip,
        )

        self._stream_consumer = AgentStreamConsumer(agent)
        # Connect parsed EVE events to the engine for dispatch.
        self._stream_consumer.event_received.connect(self._engine.on_alert_event)
        self._stream_consumer.status_changed.connect(dashboard.add_ssh_status)

        self._stream_consumer.start()
        logger.info(
            "AgentStreamConsumer started: %s@%s (agent=NetgateAgent)",
            ssh_user,
            pfsense_ip,
        )

    def _start_local_suricata_stream_consumer(self, config: Any, dashboard: Any) -> None:
        """Start the agent-driven EVE event consumer for local Suricata.

        Builds a :class:`LocalSuricataAgent` (composing
        :class:`SuricataProcess` for lifecycle + :class:`WindowsFirewallBlocker`
        for enforcement), spawns Suricata via the agent's
        :meth:`startup`, then feeds the eve.json stream into
        ``EngineWorker.on_alert_event`` via :class:`AgentStreamConsumer`.

        The agent is also added to the dashboard's status surface so
        the operator sees Suricata up / down / stale states next to
        the SSH banner used for the Netgate.

        Args:
            config: Application configuration.
            dashboard: Dashboard view for status updates.
        """
        from wardsoar.core.config import get_data_dir
        from wardsoar.pc.local_suricata import (
            SuricataProcess,
            find_suricata_install_dir,
        )
        from wardsoar.pc.local_suricata_agent import LocalSuricataAgent
        from wardsoar.pc.windows_firewall import WindowsFirewallBlocker

        suricata_dir = find_suricata_install_dir()
        local_cfg = getattr(config, "suricata_local", {}) or {}
        interface = local_cfg.get("interface", "") if isinstance(local_cfg, dict) else ""

        if suricata_dir is None or not interface:
            logger.warning(
                "_start_local_suricata_stream_consumer: cannot start — "
                "Suricata install dir=%s, interface=%r. Run the wizard "
                "to complete the local Suricata setup. The pipeline "
                "will continue with file-mode polling on the EVE path "
                "in config.watcher (if any).",
                suricata_dir,
                interface,
            )
            return

        log_dir = get_data_dir() / "suricata"
        config_path = log_dir / "suricata.yaml"
        process = SuricataProcess(
            binary_path=suricata_dir / "suricata.exe",
            config_path=config_path,
            interface=interface,
            log_dir=log_dir,
        )
        agent = LocalSuricataAgent(
            process=process,
            blocker=WindowsFirewallBlocker(),
        )

        # Spawn Suricata before the consumer starts tailing eve.json.
        # The agent's startup is async, so schedule it on the engine
        # loop and keep going — stream_alerts itself recovers from a
        # missing file (Suricata still booting) so we don't need to
        # wait for the spawn to complete here.
        loop = asyncio.get_event_loop()
        loop.create_task(agent.startup())

        self._stream_consumer = AgentStreamConsumer(agent)
        self._stream_consumer.event_received.connect(self._engine.on_alert_event)
        self._stream_consumer.status_changed.connect(dashboard.add_ssh_status)
        self._stream_consumer.start()
        logger.info(
            "AgentStreamConsumer started (agent=LocalSuricataAgent, " "interface=%s, eve=%s)",
            interface,
            process.eve_path,
        )

    def _start_dual_source_stream_consumer(self, config: Any, dashboard: Any) -> None:
        """Start the dual-source consumer for configs 3 & 5.

        Builds **both** agents (NetgateAgent for the external source +
        LocalSuricataAgent for the PC source) and wraps them in a
        :class:`DualSourceCorrelator`. The correlator fans-in their
        two streams into one tagged stream that
        :class:`AgentStreamConsumer` consumes transparently.

        Reconciliation window is read from
        ``config.suricata_local.reconciliation_window_s`` (default
        120 s — Q1 doctrine, ``project_dual_suricata_sync.md``).
        Clamped to ``[30, 180]`` to defend against hand-edited
        configs.

        If the local Suricata is not yet installed (no install dir
        or no interface configured), the method falls back to a
        Netgate-only stream so the operator still has a working
        pipeline; a WARNING log invites them to run the wizard.

        Args:
            config: Application configuration.
            dashboard: Dashboard view for status updates.
        """
        from wardsoar.core.config import get_data_dir
        from wardsoar.core.remote_agents import DualSourceCorrelator
        from wardsoar.pc.local_suricata import (
            SuricataProcess,
            find_suricata_install_dir,
        )
        from wardsoar.pc.local_suricata_agent import LocalSuricataAgent
        from wardsoar.pc.windows_firewall import WindowsFirewallBlocker

        # ----- External source: NetgateAgent -----
        ssh_config = config.watcher.get("ssh", {})
        responder_ssh = config.responder.get("pfsense", {})
        network = config.network
        pfsense_ip = network.get("pfsense_ip", "192.168.2.1")
        pc_ip = network.get("pc_ip", "")
        ssh_user = responder_ssh.get("ssh_user", "admin")
        ssh_key_path = responder_ssh.get("ssh_key_path", "")
        ssh_port = int(responder_ssh.get("ssh_port", 22))
        remote_eve_path = ssh_config.get(
            "remote_eve_path",
            "/var/log/suricata/suricata_igc252678/eve.json",
        )
        external_agent = NetgateAgent.from_credentials(
            host=pfsense_ip,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            eve_path=remote_eve_path,
            local_bind_addr=pc_ip,
        )

        # ----- Local source: LocalSuricataAgent -----
        suricata_dir = find_suricata_install_dir()
        local_cfg = getattr(config, "suricata_local", {}) or {}
        interface = local_cfg.get("interface", "") if isinstance(local_cfg, dict) else ""

        if suricata_dir is None or not interface:
            # Fallback: stream from the external source only. The
            # dual-source correlation cannot engage without the local
            # Suricata, but the operator still gets a functional
            # Netgate-only pipeline. A wizard-prompt log invites
            # them to complete the setup.
            logger.warning(
                "_start_dual_source_stream_consumer: local Suricata not "
                "ready (suricata_dir=%s, interface=%r). Falling back to "
                "Netgate-only stream — dual-source correlation cannot "
                "engage until the operator runs the Suricata-install "
                "wizard.",
                suricata_dir,
                interface,
            )
            self._stream_consumer = AgentStreamConsumer(external_agent)
            self._stream_consumer.event_received.connect(self._engine.on_alert_event)
            self._stream_consumer.status_changed.connect(dashboard.add_ssh_status)
            self._stream_consumer.start()
            logger.info("AgentStreamConsumer started (agent=NetgateAgent, fallback)")
            return

        log_dir = get_data_dir() / "suricata"
        config_path = log_dir / "suricata.yaml"
        process = SuricataProcess(
            binary_path=suricata_dir / "suricata.exe",
            config_path=config_path,
            interface=interface,
            log_dir=log_dir,
        )
        local_agent = LocalSuricataAgent(
            process=process,
            blocker=WindowsFirewallBlocker(),
        )

        # Spawn Suricata before the consumer starts tailing eve.json.
        # The agent's ``startup`` is async, so schedule it on the
        # engine loop and keep going — ``stream_alerts`` itself
        # recovers from a missing file (Suricata still booting) so
        # we don't need to wait for the spawn to complete here.
        loop = asyncio.get_event_loop()
        loop.create_task(local_agent.startup())

        # ----- Reconciliation window: read + clamp -----
        # Q1 doctrine: 120 s default, configurable in [30, 180].
        # Anything outside that band is silently coerced rather than
        # propagated as an error — the pipeline must keep working
        # even on a hand-edited config.
        raw_window: Any = (
            local_cfg.get("reconciliation_window_s", 120.0)
            if isinstance(local_cfg, dict)
            else 120.0
        )
        try:
            window_s = float(raw_window)
        except (TypeError, ValueError):
            window_s = 120.0
        clamped_window = max(30.0, min(180.0, window_s))
        if clamped_window != window_s:
            logger.warning(
                "config.suricata_local.reconciliation_window_s = %s "
                "outside [30, 180] band; clamped to %.0fs.",
                raw_window,
                clamped_window,
            )

        # ----- Wrap both in the correlator -----
        correlator = DualSourceCorrelator(
            external_agent=external_agent,
            local_agent=local_agent,
            window_seconds=clamped_window,
        )
        logger.info(
            "DualSourceCorrelator built: external=NetgateAgent@%s, "
            "local=LocalSuricataAgent (interface=%s), window=%.0fs",
            pfsense_ip,
            interface,
            clamped_window,
        )

        self._stream_consumer = AgentStreamConsumer(correlator)
        self._stream_consumer.event_received.connect(self._engine.on_alert_event)
        self._stream_consumer.status_changed.connect(dashboard.add_ssh_status)
        self._stream_consumer.start()
        logger.info(
            "AgentStreamConsumer started (agent=DualSourceCorrelator, "
            "external=%s@%s, local=%s, window=%.0fs)",
            ssh_user,
            pfsense_ip,
            interface,
            clamped_window,
        )

    def _on_alert_for_charts(self, alert_data: dict[str, Any]) -> None:
        """Feed alert data to dashboard charts.

        v0.9.2 fix: the previous check was ``bool(actions)`` which
        returned True for the sentinel ``["none"]`` value the Responder
        emits when it decides NOT to act (benign verdict, CDN
        allowlist fallback, whitelisted IP, rate-limited). Every
        analysed alert therefore showed up as "Blocked" in the
        dashboard chart even though no firewall rule was installed —
        contradicting the ``Blocked Today`` card (which reads the
        correct count from engine metrics). We now count a block
        only when an actual block-type action appears in the list.

        v0.9.4 fix: on startup the engine replays the persisted alert
        history through this same callback. Previously every replayed
        alert was timestamped at *boot* time, which stacked all N
        historical alerts into the current-hour bucket of every
        chart — the tall spike at the right-most column + empty bars
        elsewhere. We now parse the alert's original ``_ts`` field
        (ISO-8601 timestamp added during persistence) and pass it
        through so the chart distributes alerts over their real
        detection times.
        """
        from datetime import datetime

        actions = alert_data.get("actions") or []
        blocked = any(a in ("ip_block", "ip_port_block") for a in actions)

        # Parse the persisted ``_ts`` when present. Fail-safe: any
        # parse error falls back to "now" (the old behaviour).
        ts_value: Optional[datetime] = None
        ts_raw = alert_data.get("_ts")
        if isinstance(ts_raw, str) and ts_raw:
            try:
                ts_value = datetime.fromisoformat(ts_raw)
            except ValueError:
                ts_value = None

        self._window._dashboard.record_alert(
            alert_data.get("src_ip", "?"),
            alert_data.get("verdict", "inconclusive"),
            blocked=blocked,
            ts=ts_value,
        )

    def _on_rollback_completed(self, payload: dict[str, Any]) -> None:
        """Log the rollback outcome on the dashboard activity feed.

        Args:
            payload: dict from RollbackManager.rollback() as emitted by
                     EngineWorker.rollback_completed.
        """
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        ip = payload.get("ip", "?")
        dashboard = self._window._dashboard
        if payload.get("success"):
            sid = payload.get("signature_id")
            sid_part = f" (SID {sid})" if sid is not None else ""
            dashboard.add_activity(
                ts,
                "ROLLBACK",
                f"{ip} unblocked by user{sid_part} — in quarantine "
                f"for {payload.get('trusted_temp_ttl', 0)}s",
            )
        else:
            dashboard.add_activity(
                ts,
                "ROLLBACK_FAILED",
                f"{ip}: {payload.get('error', 'unknown error')}",
            )

    def _on_manual_block_completed(self, payload: dict[str, Any]) -> None:
        """Surface the outcome of a manual (review-triggered) block.

        v0.17.1 \u2014 the Manual Review dialog lets the operator
        override a verdict to CONFIRMED; that override in turn asks
        the Responder to install a real block on pfSense. This
        handler picks up the :attr:`EngineWorker.manual_block_completed`
        signal and shows a Windows toast with the outcome.
        """
        ip = str(payload.get("ip") or "?")
        success = bool(payload.get("success"))
        reason = str(payload.get("reason") or "")
        if success:
            logger.info("Manual block succeeded for %s: %s", ip, reason)
            if self._tray is not None:
                self._tray.show_notification(
                    f"WardSOAR manually blocked {ip}",
                    f"Operator override \u2014 {reason}",
                    level="warning",
                )
        else:
            logger.warning("Manual block refused for %s: %s", ip, reason)
            if self._tray is not None:
                self._tray.show_notification(
                    f"WardSOAR refused to block {ip}",
                    f"Safety rule triggered \u2014 {reason}",
                    level="info",
                )

    def _on_ip_blocked(self, payload: dict[str, Any]) -> None:
        """Surface a Windows toast when the Responder blocks an IP.

        Payload shape emitted by :class:`EngineWorker.ip_blocked`:
        ``{ip, signature, verdict, confidence}``.

        We mark self-blocks as ``critical`` so the system tray uses
        the red exclamation icon. The rationale is the v0.6.3
        incident: the operator's own machine went offline silently
        because no UI affordance told them WardSOAR had just
        blocklisted them. From v0.6.4 every block fires a toast, and
        a self-block is visually unmissable.
        """
        ip = str(payload.get("ip", ""))
        signature = str(payload.get("signature", ""))
        verdict = str(payload.get("verdict", ""))
        confidence = str(payload.get("confidence", "?"))

        is_self_block = False
        if ip:
            try:
                import ipaddress

                addr = ipaddress.ip_address(ip)
                is_self_block = addr.is_private or addr.is_loopback or addr.is_link_local
            except ValueError:
                is_self_block = False

        if is_self_block:
            title = f"WardSOAR blocked YOUR OWN NETWORK ({ip})"
            body = (
                f"verdict={verdict} confidence={confidence} "
                f"signature={signature[:60]} -- open the Alerts tab "
                "and click Unblock IP on that row. This should never "
                "have happened; please report it."
            )
            level = "critical"
        else:
            title = f"WardSOAR blocked {ip}"
            body = f"verdict={verdict} confidence={confidence} " f"signature={signature[:80]}"
            level = "warning"

        try:
            self._tray.show_notification(title, body, level=level)
        except Exception:  # noqa: BLE001 -- toast is best-effort
            logger.exception("Failed to show block toast for %s", ip)

    def _on_threshold_changed(self, mode_name: str, value: float) -> None:
        """Push a threshold edit from :class:`ConfigView` to the live Responder.

        The ConfigView has already persisted the value to
        ``config.yaml``; here we only need to propagate it in-process
        so the decision on the next alert uses the new threshold.

        Args:
            mode_name: ``"protect"`` or ``"hard_protect"``.
            value: New threshold value, already clamped to [0, 1] by
                the spinbox range.
        """
        if not (hasattr(self, "_engine") and hasattr(self._engine, "_pipeline")):
            return
        responder = self._engine._pipeline._responder
        if mode_name == "protect":
            responder.set_confidence_threshold(value)
        elif mode_name == "hard_protect":
            responder.set_hard_protect_benign_threshold(value)
        else:
            logger.warning("Unknown threshold mode received: %s", mode_name)
            return
        logger.info("Threshold %s updated to %.2f (live)", mode_name, value)

    # ----------------------------------------------------------------
    # Netgate audit gate — shared helpers for escalation refusal.
    # ----------------------------------------------------------------

    def _netgate_gate_block_reason(self) -> Optional[str]:
        """Return a human reason to refuse escalation, or ``None`` if OK.

        Safer-than-sorry policy:

        * No audit ever run → allow (operator hasn't yet been introduced
          to the tab — we don't want to surprise them on first launch)
        * Audit exists with at least one critical KO → refuse
        * Audit exists, no critical KO → allow

        First-launch behaviour is intentionally permissive so an
        operator who never opens the Netgate tab isn't locked in
        Monitor forever. A follow-up phase will add a one-shot
        silent audit on first escalation.
        """
        if not hasattr(self, "_engine"):
            return None
        pipeline = getattr(self._engine, "_pipeline", None)
        result = getattr(pipeline, "last_audit_result", None) if pipeline else None
        if result is None:
            return None
        if not getattr(result, "any_critical_ko", False):
            return None
        # Build a short bullet list of the offending critical items.
        try:
            critical_findings = [
                f
                for f in getattr(result, "findings", [])
                if getattr(f, "tier", "") == "critical" and getattr(f, "status", "") != "ok"
            ]
        except AttributeError:
            critical_findings = []
        if not critical_findings:
            return "Netgate audit reports a critical failure."
        bullet_list = "\n".join(f"• {f.title}" for f in critical_findings[:5])
        more = "\n…" if len(critical_findings) > 5 else ""
        return "Netgate audit failed on the following critical checks:\n\n" + bullet_list + more

    def _current_responder_mode(self) -> "Any":
        """Read the live Responder mode for UI synchronisation.

        Returns a :class:`~src.models.WardMode`. Falls back to MONITOR
        when the engine has not started — the caller uses that value
        to repaint the dashboard after a refused escalation.
        """
        from wardsoar.core.models import WardMode

        if not hasattr(self, "_engine"):
            return WardMode.MONITOR
        pipeline = getattr(self._engine, "_pipeline", None)
        responder = getattr(pipeline, "_responder", None) if pipeline else None
        return getattr(responder, "mode", WardMode.MONITOR)

    def _on_load_older_requested(self, older_than_count: int) -> None:
        """Fetch the next page of older alerts within the current month.

        Handler for ``AlertsView.load_older_requested``. The engine
        returns up to 200 older entries of the active file (which
        only contains the current calendar month, enforced by the
        rotator). The view appends them at the bottom of the table.
        An empty batch means the current month is exhausted —
        further history must come from the Archives menu.
        """
        try:
            batch = self._engine.load_history_page(
                older_than_count=older_than_count,
                page_size=200,
            )
        except Exception:  # noqa: BLE001 — defensive; no-op on failure
            logger.warning("Failed to load older history page", exc_info=True)
            batch = []
        self._window._alerts.append_older_alerts(batch)
        logger.info(
            "Load older: offset=%d returned %d entries",
            older_than_count,
            len(batch),
        )

    def _on_load_archive_requested(self, archive_path: str) -> None:
        """Load a full monthly archive and merge it into the view.

        Handler for ``AlertsView.load_archive_requested``. We load
        the whole month in one go — a monthly archive for this
        operator's volume is a few MB decompressed, sub-second
        parse on the UI thread. For pathologically large months
        we can switch to a worker thread later.
        """
        try:
            alerts = self._engine.load_history_from_archive(archive_path)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to load archive %s", archive_path, exc_info=True)
            alerts = []
        self._window._alerts.append_archive_alerts(archive_path, alerts)
        logger.info("Archive loaded: %s (%d entries)", archive_path, len(alerts))

    def _on_add_sid_filter(self, sid: int, signature: str) -> None:
        """Persist a user-chosen SID into the false-positives overlay.

        Handler for ``AlertsView.add_sid_filter_requested``. Writes
        the SID to ``%APPDATA%\\WardSOAR\\config\\known_false_positives_user.yaml``
        AND injects it into the live filter's in-memory suppression
        set so the very next matching alert is suppressed without
        waiting for a restart.

        The operator gets a toast regardless of outcome.
        """
        from wardsoar.core.user_false_positives import append_sid

        ok, message = append_sid(sid, signature=signature)
        alerts_view = self._window._alerts
        alerts_view.on_sid_filtered(sid, ok, message)
        if ok:
            # Live-add to the pipeline's filter so the SID takes
            # effect immediately for in-flight alerts too.
            try:
                filter_stage = getattr(self._engine._pipeline, "filter", None)
                if filter_stage is not None and hasattr(filter_stage, "add_sid_live"):
                    filter_stage.add_sid_live(sid)
                    logger.info("Live-added SID %d to filter's suppression set", sid)
            except Exception:  # noqa: BLE001 — persistence already succeeded
                logger.warning(
                    "Could not live-add SID %d to filter; change takes effect on restart",
                    sid,
                    exc_info=True,
                )
        logger.info("Add-SID-to-filter: sid=%d ok=%s msg=%s", sid, ok, message)

    def _on_manual_review_requested(self, record: dict[str, Any]) -> None:
        """Open the Manual Review dialog for the clicked alert.

        v0.16.0 \u2014 full implementation replacing the 0.9.0 stub.
        Opens a dialog pre-populated with the alert's key fields,
        lets the operator override the verdict and / or add a note,
        and on Save persists the review to
        ``%APPDATA%\\WardSOAR\\logs\\manual_reviews.jsonl``. The
        Alert Detail view is then refreshed to show a new
        "Manual review" block on the target alert.
        """
        from wardsoar.core.config import get_data_dir
        from wardsoar.core.manual_reviews import (
            append_review,
            default_store_path,
            new_review,
        )
        from wardsoar.pc.ui.views.alerts import ManualReviewDialog

        dialog = ManualReviewDialog(record, parent=self._window)

        def _on_submitted(
            alert_ts: str,
            original: str,
            operator_verdict: str,
            notes: str,
        ) -> None:
            if not alert_ts:
                logger.warning(
                    "Manual review emitted without alert_ts \u2014 "
                    "alert persisted before v0.9.0 cannot be overridden."
                )
                return
            review = new_review(
                alert_ts=alert_ts,
                original_verdict=original,
                operator_verdict=operator_verdict,
                notes=notes,
            )
            store = default_store_path(get_data_dir())
            append_review(store, review)
            # Update the in-memory record so the Alert Detail view
            # refreshes without a restart. The ``manual_review``
            # key is read by :meth:`_populate_manual_review` in
            # alert_detail.py.
            record["manual_review"] = review.to_dict()
            # Trigger a re-render of the detail view on the same
            # record (the AlertsView exposes the detail widget via
            # ``_detail_view`` private attr \u2014 use it only because
            # we own the shell).
            try:
                alerts_view = getattr(self._window, "_alerts", None)
                if alerts_view is not None and hasattr(alerts_view, "_detail_view"):
                    alerts_view._detail_view.set_record(record)  # noqa: SLF001
            except Exception:  # noqa: BLE001 \u2014 defensive UI refresh
                logger.debug("Could not refresh detail view after review", exc_info=True)
            logger.info(
                "Manual review saved: alert_ts=%s original=%s operator=%s notes=%r",
                alert_ts,
                original,
                operator_verdict or "(none)",
                notes[:80] + ("\u2026" if len(notes) > 80 else ""),
            )

            # v0.17.1 \u2014 if the operator overrode the verdict to
            # CONFIRMED, trigger a real pfSense block via the
            # Responder. The Responder applies every safety rail
            # (whitelist, CDN allowlist, rate limit) so manual
            # blocks cannot bypass operator protections.
            if operator_verdict == "confirmed":
                target_ip = str(record.get("src_ip") or "").strip()
                if not target_ip:
                    logger.warning("Manual block skipped \u2014 alert has no src_ip")
                    return
                sig_id: Optional[int] = None
                sig_id_raw = record.get("signature_id")
                if sig_id_raw not in (None, ""):
                    try:
                        sig_id = int(str(sig_id_raw))
                    except (TypeError, ValueError):
                        sig_id = None
                logger.info(
                    "Manual block requested for %s (SID %s) \u2014 "
                    "dispatching to Responder via engine bridge",
                    target_ip,
                    sig_id,
                )
                self._engine.request_manual_block(
                    ip=target_ip,
                    signature_id=sig_id,
                    operator_notes=notes,
                )

        dialog.review_submitted.connect(_on_submitted)
        dialog.exec()

    def _on_forensic_report_requested(self, record: dict[str, Any]) -> None:
        """Stub handler for the Forensic Report button.

        Opens ``%APPDATA%\\WardSOAR\\evidence\\<record_id>\\`` in
        Explorer when the record has an id, otherwise falls back to
        the evidence root so the operator can browse manually.
        """
        import os
        import subprocess

        from wardsoar.core.config import get_data_dir

        record_id = (record.get("_full") or {}).get("record_id") or record.get("record_id")
        evidence_root = get_data_dir() / "evidence"
        target = evidence_root / record_id if record_id else evidence_root
        if not target.exists():
            target = evidence_root
        try:
            # Open the folder in Windows Explorer. ``os.startfile`` is
            # the canonical way; fall back to ``explorer`` for
            # non-standard setups (remote desktops mostly).
            if hasattr(os, "startfile"):
                os.startfile(str(target))  # noqa: S606
            else:  # pragma: no cover — Windows-only code path
                subprocess.Popen(["explorer", str(target)])  # nosec B603 B607
        except OSError:
            logger.warning("Could not open forensic evidence dir %s", target, exc_info=True)

    def _on_mode_changed(self, new_mode: str) -> None:
        """Handle mode toggle from dashboard — persist to config.yaml.

        Accepts one of ``"monitor"``, ``"protect"``, ``"hard_protect"``.
        Writes the new value to the ``responder.mode`` key and applies
        it live to the pipeline's Responder so the change takes effect
        immediately without requiring a restart.

        Args:
            new_mode: Target :class:`~src.models.WardMode` value.
        """
        import yaml

        from qfluentwidgets import MessageBox

        from wardsoar.core.models import WardMode

        resolved = WardMode.parse(new_mode)

        # --- Netgate audit gate ---------------------------------------
        # Phase 7a: an escalation from Monitor into a blocking mode is
        # refused if the last audit is missing or has any critical KO.
        # Monitor → anything-else (except escalation) is always allowed
        # because downgrading is always safe.
        if resolved in (WardMode.PROTECT, WardMode.HARD_PROTECT):
            block_reason = self._netgate_gate_block_reason()
            if block_reason is not None:
                dashboard = self._window._dashboard
                MessageBox(
                    "Netgate not ready",
                    block_reason + "\n\nOpen the Netgate tab and fix the critical items, "
                    "then try again.",
                    dashboard,
                ).exec()
                # Revert the dashboard's internal state so the button label
                # and colour snap back to the previous mode. The dashboard
                # has already mutated ``_ward_mode`` when this handler
                # fires, so we have to overwrite it explicitly.
                current = self._current_responder_mode()
                dashboard._ward_mode = current.value
                dashboard._update_mode_button()
                logger.warning("Mode escalation to %s refused: %s", resolved.value, block_reason)
                return

        config_path = get_data_dir() / "config" / "config.yaml"
        if not config_path.exists():
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}

            responder_cfg = raw.setdefault("responder", {})
            responder_cfg["mode"] = resolved.value
            # Drop the legacy flag if it is still present — the new key
            # is authoritative and leaving both in sync is pointless.
            responder_cfg.pop("dry_run", None)

            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(raw, f, default_flow_style=False, sort_keys=False)

            # Apply live — set_mode logs the transition itself.
            if hasattr(self, "_engine") and hasattr(self._engine, "_pipeline"):
                self._engine._pipeline._responder.set_mode(resolved)
                # Keep the engine worker's own label in sync (used by
                # status banner + activity log). v0.22.16: the field
                # moved from EngineWorker into PipelineController as
                # part of the V3.5 extraction.
                self._engine._pipeline_controller._ward_mode = resolved.value

            logger.info("Mode changed to %s", resolved.value)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Failed to save mode change: %s", exc)

    def _show_window(self) -> None:
        """Show and raise the main window."""
        self._window.show()
        self._window.raise_()
        self._window.activateWindow()

    def _quit(self) -> None:
        """Quit the application."""
        if hasattr(self, "_stream_consumer") and self._stream_consumer is not None:
            self._stream_consumer.stop()
            self._stream_consumer.wait(3000)
        if hasattr(self, "_engine"):
            self._engine.stop()
            self._engine.wait(3000)
        self._tray.hide()
        self._window.quit_application()
        self._app.quit()

    def run(self) -> int:
        """Start the application event loop.

        Returns:
            Exit code.
        """
        self._window.show()
        return self._app.exec()
