"""Tests for WardSOAR UI components.

UI modules are STANDARD (80% coverage). Tests use a shared QApplication
instance to avoid multiple QApplication creation errors.
"""

import sys

import pytest
from PySide6.QtWidgets import QApplication
from qfluentwidgets import Theme, setTheme


from wardsoar.pc.ui.app import MainWindow, TrayManager, _create_status_icon
from wardsoar.pc.ui.views.alert_detail import AlertDetailView
from wardsoar.pc.ui.views.alerts import AlertsView
from wardsoar.pc.ui.views.config_view import ConfigView, DiffDialog
from wardsoar.pc.ui.views.dashboard import DashboardView, _display_labels
from wardsoar.pc.ui.views.replay_view import ReplayView


# Shared QApplication for all UI tests
@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Create a shared QApplication for the test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    setTheme(Theme.DARK)
    return app


# ---------------------------------------------------------------------------
# TrayManager tests
# ---------------------------------------------------------------------------


class TestTrayManager:
    """Tests for TrayManager."""

    def test_construction(self, qapp: QApplication) -> None:
        tray = TrayManager()
        assert tray._status == "offline"
        assert tray._unread_count == 0

    def test_set_status(self, qapp: QApplication) -> None:
        tray = TrayManager()
        tray.set_status("healthy")
        assert tray._status == "healthy"

    def test_set_unread_count(self, qapp: QApplication) -> None:
        tray = TrayManager()
        tray.set_unread_count(5)
        assert tray._unread_count == 5

    def test_set_mode(self, qapp: QApplication) -> None:
        tray = TrayManager()
        tray.set_mode("Active")
        assert "Active" in tray._mode_action.text()

    def test_create_status_icon(self, qapp: QApplication) -> None:
        from PySide6.QtGui import QColor

        icon = _create_status_icon(QColor(0, 255, 0))
        assert not icon.isNull()


# ---------------------------------------------------------------------------
# MainWindow tests
# ---------------------------------------------------------------------------


class TestMainWindow:
    """Tests for MainWindow (FluentWindow with navigation)."""

    def test_construction(self, qapp: QApplication) -> None:
        window = MainWindow()
        assert window.windowTitle() == "WardSOAR"

    def test_has_four_interfaces(self, qapp: QApplication) -> None:
        window = MainWindow()
        assert window._dashboard is not None
        assert window._alerts is not None
        assert window._config is not None
        assert window._replay is not None

    def test_close_minimizes_to_tray(self, qapp: QApplication) -> None:
        window = MainWindow()
        window.show()
        window.close()
        assert not window.isVisible()

    def test_quit_application(self, qapp: QApplication) -> None:
        window = MainWindow()
        window._minimize_to_tray = False
        window.quit_application()


# ---------------------------------------------------------------------------
# DashboardView tests
# ---------------------------------------------------------------------------


class TestDashboardView:
    """Tests for DashboardView."""

    def test_construction(self, qapp: QApplication) -> None:
        dashboard = DashboardView()
        assert dashboard._alerts_card is not None

    def test_update_metrics(self, qapp: QApplication) -> None:
        dashboard = DashboardView()
        dashboard.update_metrics(
            {
                "alerts_today": 42,
                "blocked_today": 3,
            }
        )
        assert dashboard._alerts_value.text() == "42"
        assert dashboard._blocked_value.text() == "3"

    def test_set_status(self, qapp: QApplication) -> None:
        dashboard = DashboardView()
        dashboard.set_status("Operational", "Monitor")
        assert "Operational" in dashboard._status_label.text()
        assert dashboard._mode_btn.text() == "Mode: Monitor"

    def test_set_status_protect(self, qapp: QApplication) -> None:
        dashboard = DashboardView()
        dashboard.set_status("Operational", "Protect")
        assert dashboard._ward_mode == "protect"
        assert dashboard._mode_btn.text() == "Mode: Protect"

    def test_set_status_hard_protect(self, qapp: QApplication) -> None:
        """v0.5.5 — the dashboard now recognises Hard Protect as a
        third mode with its own button label and internal state."""
        dashboard = DashboardView()
        dashboard.set_status("Operational", "Hard Protect")
        assert dashboard._ward_mode == "hard_protect"
        assert dashboard._mode_btn.text() == "Mode: Hard Protect"

    def test_record_alert_updates_charts(self, qapp: QApplication) -> None:
        dashboard = DashboardView()
        dashboard.record_alert("10.0.0.1", "confirmed", blocked=True)
        assert len(dashboard._alert_records) == 1
        ts, ip, verdict, blocked = dashboard._alert_records[0]
        assert ip == "10.0.0.1"
        assert verdict == "confirmed"
        assert blocked is True
        assert dashboard._ip_counts["10.0.0.1"] == 1

    def test_display_labels_all_visible_from_v097(self) -> None:
        """v0.9.7 — every bucket carries its own label. Dense scales now
        emit at most 12 bars (coarse buckets) instead of 60, so
        ``_display_labels`` can safely pass through all of them."""
        for scale in ("minute", "hour", "day", "week", "month", "year"):
            labels = [f"lbl_{i}" for i in range(12)]
            displayed = _display_labels(labels, scale)
            assert displayed == labels, f"Scale {scale} thinned labels unexpectedly"


# ---------------------------------------------------------------------------
# AlertsView tests
# ---------------------------------------------------------------------------


class TestAlertsView:
    """Tests for AlertsView."""

    def test_construction(self, qapp: QApplication) -> None:
        alerts = AlertsView()
        assert alerts._alert_table.rowCount() == 0

    def test_add_alert_row(self, qapp: QApplication) -> None:
        alerts = AlertsView()
        alerts.add_alert_row(
            {
                "time": "14:30",
                "src_ip": "10.0.0.1",
                "signature": "ET MALWARE Test",
                "verdict": "confirmed",
                "score": "87",
                "severity": "1",
            }
        )
        assert alerts._alert_table.rowCount() == 1

    def test_newest_alert_appears_at_top(self, qapp: QApplication) -> None:
        """v0.8.5 — newest alerts sort to the top so the operator
        sees them without scrolling. Matches the Activity tab
        convention. Regression guard: if someone reverts the
        insertion to append-at-end, this test catches it."""
        alerts = AlertsView()
        alerts.add_alert_row(
            {
                "time": "14:30",
                "src_ip": "10.0.0.1",
                "signature": "OLD alert",
                "verdict": "benign",
                "score": "10",
                "severity": "3",
            }
        )
        alerts.add_alert_row(
            {
                "time": "14:31",
                "src_ip": "10.0.0.2",
                "signature": "NEW alert",
                "verdict": "confirmed",
                "score": "90",
                "severity": "1",
            }
        )

        # Row 0 (top) must be the newest entry (NEW alert).
        # v0.9.0 column order: time, src_ip, dest_ip, signature, verdict, severity
        sig_col = 3
        top_item = alerts._alert_table.item(0, sig_col)
        bottom_item = alerts._alert_table.item(1, sig_col)
        assert top_item is not None and bottom_item is not None
        assert top_item.text() == "NEW alert"
        assert bottom_item.text() == "OLD alert"

        # And ``_alert_data`` must mirror the visual order so row index
        # passed to ``_on_alert_selected`` resolves to the right record.
        assert alerts._alert_data[0]["signature"] == "NEW alert"
        assert alerts._alert_data[1]["signature"] == "OLD alert"

    def test_clear_alerts(self, qapp: QApplication) -> None:
        alerts = AlertsView()
        alerts.add_alert_row({"time": "14:30", "src_ip": "10.0.0.1"})
        alerts.clear_alerts()
        assert alerts._alert_table.rowCount() == 0


class TestActivityViewEventShape:
    """Tests for v0.8.6 option B2 — System Activity is now a pure
    system-event journal. Per-alert rows (FILTERED, PIPELINE,
    raw ALERT) no longer reach Activity — they live in the Alerts
    tab, which has a detail panel for drill-down.

    The tests guard four regressions:

    * Engine doesn't emit a generic ``ALERT`` row on raw eve arrival.
    * Engine doesn't emit ``FILTERED`` / ``PIPELINE`` rows after
      pipeline completion (verified by inspecting the emit sites
      indirectly via the on_ssh_line dispatcher).
    * Healthy healthchecks are silenced — only degraded / failed
      get an Activity row.
    * The view's ``_rewrite_event`` still handles FILTERED / PIPELINE
      formats correctly if some future caller re-emits them (defense
      in depth).
    """

    def test_no_alert_event_reaches_activity_from_raw_ssh_line(self, qapp: QApplication) -> None:
        """Raw ``event_type: alert`` arriving from Suricata must not
        produce an ALERT / FILTERED / PIPELINE row. The async
        pipeline task is mocked so we can assert purely on the
        dispatcher's synchronous emissions."""
        from unittest.mock import MagicMock

        from src.ui.engine_bridge import EngineWorker

        pipeline = MagicMock()
        pipeline.process_alert = MagicMock()
        worker = EngineWorker(
            pipeline=pipeline,
            eve_path="/nonexistent",
            mode="file",
            ward_mode="monitor",
            healthcheck_cfg={},
        )
        emitted: list[tuple[str, str, str]] = []
        worker.activity_logged.connect(lambda t, e, d: emitted.append((t, e, d)))
        # Fake event loop so the async schedule call doesn't crash.
        worker._loop = MagicMock()
        worker._loop.create_task = MagicMock()

        alert_line = (
            '{"event_type": "alert", "src_ip": "1.2.3.4", '
            '"dest_ip": "5.6.7.8", "alert": {"signature_id": 2210054, '
            '"signature": "TEST", "severity": 3, "category": "test"}}'
        )
        worker.on_ssh_line(alert_line)

        # No per-alert events should reach Activity: not ALERT
        # (removed in 0.8.6) nor FILTERED / PIPELINE (removed in B2).
        forbidden_types = {"ALERT", "FILTERED", "PIPELINE"}
        bad = [e for e in emitted if e[1].upper() in forbidden_types]
        assert bad == [], f"Activity saw per-alert events that should be suppressed: {bad}"

    def test_healthy_healthcheck_emits_no_activity_row(self, qapp: QApplication) -> None:
        """A ``healthy`` status is routine — we don't want 12 rows an
        hour saying "all good". The Dashboard's health widget
        surfaces the same info without cluttering Activity. The
        emit MUST fire for degraded / failed so regressions stay
        visible."""
        import asyncio
        from unittest.mock import MagicMock

        from src.ui.engine_bridge import EngineWorker

        worker = EngineWorker(
            pipeline=MagicMock(),
            eve_path="/nonexistent",
            mode="file",
            ward_mode="monitor",
            healthcheck_cfg={},
        )
        emitted: list[tuple[str, str, str]] = []
        worker.activity_logged.connect(lambda t, e, d: emitted.append((t, e, d)))

        # Fake the healthchecker to return a healthy overall.
        fake_status_healthy = MagicMock()
        fake_status_healthy.value = "healthy"
        fake_result = MagicMock()
        fake_result.component = "test"
        fake_result.status.value = "healthy"
        worker._healthchecker = MagicMock()

        async def _run_all() -> list[object]:
            return [fake_result]

        worker._healthchecker.run_all_checks = _run_all
        worker._healthchecker.get_overall_status = MagicMock(return_value=fake_status_healthy)

        asyncio.run(worker._run_healthchecks_async())
        health_rows = [e for e in emitted if e[1].lower() == "health"]
        assert health_rows == [], f"healthy check leaked an Activity row: {health_rows}"

        # Now degrade the overall and verify the row IS emitted.
        emitted.clear()
        fake_status_degraded = MagicMock()
        fake_status_degraded.value = "degraded"
        worker._healthchecker.get_overall_status = MagicMock(return_value=fake_status_degraded)
        asyncio.run(worker._run_healthchecks_async())
        health_rows = [e for e in emitted if e[1].lower() == "health"]
        assert len(health_rows) == 1, f"degraded check should emit one row, got: {health_rows}"
        assert "degraded" in health_rows[0][2]

    def test_view_still_renders_filtered_pipeline_if_called_directly(
        self, qapp: QApplication
    ) -> None:
        """Defense in depth: if a future caller re-emits FILTERED /
        PIPELINE events for any reason (replay view? integration
        test?), the view must still format them correctly with
        both endpoints + signature + reason so no stale mapping
        gets silently committed."""
        from src.ui.views.activity_view import ActivityView

        view = ActivityView()
        detail = (
            "192.168.2.100 -> 18.97.36.72 — "
            "SURICATA STREAM reassembly overlap — known false positive"
        )
        view.add_activity("15:36:19", "FILTERED", detail)
        shown = view._table.item(0, 2).text()
        assert "192.168.2.100" in shown
        assert "18.97.36.72" in shown
        assert "STREAM" in shown


class TestAlertDetailView:
    """Tests for the v0.9.0 full-page AlertDetailView.

    Replaces v0.8.x TestAlertDetailPanel. The side-panel pattern is
    gone — we now test the footer action-button visibility rules,
    the hero card rendering, and the pipeline-trace population.
    """

    def _sample_confirmed_record(self) -> dict:
        """A confirmed threat with an active block — should surface all
        four footer buttons."""
        return {
            "time": "15:42:11",
            "src_ip": "51.161.42.18",
            "src_port": "51203",
            "dest_ip": "192.168.2.100",
            "dest_port": "22",
            "proto": "TCP",
            "signature": "ET SCAN SSH Brute Force Attempt",
            "signature_id": "2003067",
            "category": "Attempted Administrator Privilege Gain",
            "severity": "1",
            "verdict": "confirmed",
            "confidence": "97%",
            "reasoning": "Clear SSH brute-force…",
            "actions": ["ip_block"],
            "pipeline_ms": "8312",
            "_full": {
                "record_id": "f209-b8d7",
                "pipeline_trace": [
                    {"index": 1, "name": "Filter", "outcome": "passed", "detail": "ok"},
                    {"index": 8, "name": "Analyzer", "outcome": "passed", "detail": "confirmed"},
                ],
                "analysis": {
                    "verdict": "confirmed",
                    "confidence": 0.97,
                    "reasoning": "Clear SSH brute-force attack.",
                    "recommended_actions": ["ip_block"],
                },
                "actions_taken": [
                    {
                        "action_type": "ip_block",
                        "target_ip": "51.161.42.18",
                        "pfsense_rule_id": "blocklist",
                        "block_duration_hours": 24,
                        "success": True,
                    }
                ],
                "alert": {"raw_event": {"event_type": "alert"}},
            },
        }

    def test_set_record_populates_hero(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.set_record(self._sample_confirmed_record())
        assert "CONFIRMED" in view._hero_verdict_label.text()
        assert "51.161.42.18" in view._hero_flow_label.text()
        assert "192.168.2.100" in view._hero_flow_label.text()
        assert "2003067" in view._hero_sig_label.text()

    def test_confirmed_blocked_shows_all_four_footer_buttons(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.show()
        view.set_record(self._sample_confirmed_record())
        assert view._review_btn.isVisibleTo(view)
        assert view._forensic_btn.isVisibleTo(view)
        assert view._unblock_btn.isVisibleTo(view)
        # Confirmed verdict → filter SID button NOT shown (it's a threat).
        assert not view._addfp_btn.isVisibleTo(view)

    def test_benign_shows_manual_review_and_filter_sid_only(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.show()
        record = {
            "verdict": "benign",
            "signature_id": "2210033",
            "signature": "STREAM FIN1 invalid ack",
            "actions": [],
            "_full": {},
        }
        view.set_record(record)
        assert view._review_btn.isVisibleTo(view)
        # Benign with no block → no forensic, no unblock.
        assert not view._forensic_btn.isVisibleTo(view)
        assert not view._unblock_btn.isVisibleTo(view)
        # But add-to-filter IS useful for recurring benign alerts.
        assert view._addfp_btn.isVisibleTo(view)
        assert "2210033" in view._addfp_btn.text()

    def test_filtered_shows_only_manual_review(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.show()
        record = {
            "verdict": "filtered",
            "signature_id": "2210054",
            "actions": [],
            "_full": {"filtered": True, "pipeline_trace": []},
        }
        view.set_record(record)
        assert view._review_btn.isVisibleTo(view)
        assert not view._forensic_btn.isVisibleTo(view)
        assert not view._unblock_btn.isVisibleTo(view)
        # Filter SID for an already-filtered SID is pointless — hidden.
        assert not view._addfp_btn.isVisibleTo(view)

    def test_add_sid_filter_signal_carries_sid_and_signature(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.set_record(
            {
                "verdict": "benign",
                "signature_id": "2210033",
                "signature": "STREAM FIN1 invalid ack",
                "actions": [],
                "_full": {},
            }
        )
        emitted: list[tuple[int, str]] = []
        view.add_sid_filter_requested.connect(lambda sid, sig: emitted.append((sid, sig)))
        view._on_addfp_clicked()
        assert emitted == [(2210033, "STREAM FIN1 invalid ack")]

    def test_unblock_signal_carries_ip_and_sid(self, qapp: QApplication) -> None:
        view = AlertDetailView()
        view.set_record(self._sample_confirmed_record())
        emitted: list[tuple[str, object]] = []
        view.rollback_requested.connect(lambda ip, sid: emitted.append((ip, sid)))
        view._on_unblock_clicked()
        assert emitted == [("51.161.42.18", 2003067)]


# ---------------------------------------------------------------------------
# ConfigView tests
# ---------------------------------------------------------------------------


class TestConfigView:
    """Tests for ConfigView."""

    def test_construction(self, qapp: QApplication) -> None:
        config = ConfigView()
        assert config._editor is not None


class TestDiffDialog:
    """Tests for DiffDialog."""

    def test_construction(self, qapp: QApplication) -> None:
        dialog = DiffDialog("before", "after")
        assert dialog is not None


# ---------------------------------------------------------------------------
# ReplayView tests
# ---------------------------------------------------------------------------


class TestReplayView:
    """Tests for ReplayView."""

    def test_construction(self, qapp: QApplication) -> None:
        replay = ReplayView()
        assert replay._results_table.rowCount() == 0

    def test_set_progress(self, qapp: QApplication) -> None:
        replay = ReplayView()
        replay.set_progress(50)
        assert replay._progress.value() == 50

    def test_update_impact(self, qapp: QApplication) -> None:
        replay = ReplayView()
        replay.update_impact(
            {
                "total_replayed": 100,
                "verdict_changes": 5,
                "new_blocks": 2,
                "removed_blocks": 3,
            }
        )
        assert "100" in replay._total_label.text()
        assert "5" in replay._changes_label.text()

    def test_add_result_row(self, qapp: QApplication) -> None:
        replay = ReplayView()
        replay.add_result_row("14:30", "10.0.0.1", "Test", "benign", "confirmed")
        assert replay._results_table.rowCount() == 1

    def test_clear_results(self, qapp: QApplication) -> None:
        replay = ReplayView()
        replay.add_result_row("14:30", "10.0.0.1", "Test", "benign", "confirmed")
        replay.clear_results()
        assert replay._results_table.rowCount() == 0

    def test_set_running(self, qapp: QApplication) -> None:
        replay = ReplayView()
        replay.set_running(True)
        assert not replay._start_btn.isEnabled()
        assert replay._stop_btn.isEnabled()
        replay.set_running(False)
        assert replay._start_btn.isEnabled()
        assert not replay._stop_btn.isEnabled()


class TestNetgateView:
    """Tests for the Netgate audit view's Apply-button wiring.

    Regression cover for v0.8.0: the "Apply selected" button used to
    stay greyed out after the operator manually ticked a finding,
    because its enabled state was only refreshed during a full
    ``display_audit_result`` re-render. The fix wires
    ``QTreeWidget.itemChanged`` to refresh the button on every
    checkbox flip, so both manual clicks and Select-all / Select-none
    now update the button immediately.
    """

    @staticmethod
    def _sample_payload() -> dict:
        """One critical KO and one recommended KO — both applicable."""
        return {
            "started_at": "2026-04-21T09:27:56+00:00",
            "duration_seconds": 2.0,
            "ssh_reachable": True,
            "any_critical_ko": True,
            "counts_by_tier": {},
            "findings": [
                {
                    "id": "suricata.rules_loaded",  # applicable, critical tier
                    "title": "Suricata rules loaded",
                    "tier": "critical",
                    "category": "suricata",
                    "status": "critical",
                    "current_value": "500 rules",
                    "expected_value": "≥ 10 000",
                    "risk_badge": "amber",
                    "fix_description": "Run the rules updater",
                },
                {
                    "id": "pf.alias_persistent",  # applicable, recommended tier
                    "title": "Blocklist alias persists across reloads",
                    "tier": "recommended",
                    "category": "pf",
                    "status": "warning",
                    "current_value": "host",
                    "expected_value": "urltable",
                    "risk_badge": "red",
                    "fix_description": "Apply to migrate",
                },
            ],
        }

    def test_apply_button_enables_when_manual_tick(self, qapp: QApplication) -> None:
        """After render, manually ticking a recommended row must enable
        Apply immediately — no second audit run required."""
        from PySide6.QtCore import Qt

        from src.ui.views.netgate import NetgateView

        view = NetgateView()
        view.set_applicable_fix_ids({"suricata.rules_loaded", "pf.alias_persistent"})
        view.display_audit_result(self._sample_payload())

        # Find the pf.alias_persistent row and untick the critical one
        # so we can isolate the behaviour. The critical row is
        # pre-checked by ``_default_checked``.
        root = view._tree.invisibleRootItem()
        pf_row = None
        critical_row = None
        for i in range(root.childCount()):
            tier = root.child(i)
            for j in range(tier.childCount()):
                child = tier.child(j)
                fix_id = child.data(0, Qt.ItemDataRole.UserRole)
                if fix_id == "pf.alias_persistent":
                    pf_row = child
                elif fix_id == "suricata.rules_loaded":
                    critical_row = child
        assert pf_row is not None and critical_row is not None

        # Start from a clean slate: uncheck everything. The button must
        # go disabled.
        critical_row.setCheckState(0, Qt.CheckState.Unchecked)
        assert view._apply_btn.isEnabled() is False

        # Simulate the exact operator flow from the screenshot: tick
        # the pf.alias_persistent row → Apply must enable.
        pf_row.setCheckState(0, Qt.CheckState.Checked)
        assert view._apply_btn.isEnabled() is True

        # And unticking again disables the button.
        pf_row.setCheckState(0, Qt.CheckState.Unchecked)
        assert view._apply_btn.isEnabled() is False

    def test_select_all_and_select_none_update_button(self, qapp: QApplication) -> None:
        from PySide6.QtCore import Qt

        from src.ui.views.netgate import NetgateView

        view = NetgateView()
        view.set_applicable_fix_ids({"suricata.rules_loaded", "pf.alias_persistent"})
        view.display_audit_result(self._sample_payload())

        # Clear everything first.
        view._set_all_checked(False)
        # Manually trigger the itemChanged handler on one row to mimic
        # Qt's actual signal plumbing (setCheckState fires it).
        root = view._tree.invisibleRootItem()
        for i in range(root.childCount()):
            tier = root.child(i)
            for j in range(tier.childCount()):
                child = tier.child(j)
                if bool(child.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                    assert child.checkState(0) == Qt.CheckState.Unchecked
        assert view._apply_btn.isEnabled() is False

        view._set_all_checked(True)
        # Any checkable row is now ticked → button enabled.
        assert view._apply_btn.isEnabled() is True

    def test_apply_results_with_success_auto_triggers_run_check(self, qapp: QApplication) -> None:
        """Regression for v0.8.0: after an Apply succeeds on any fix,
        the audit must re-run automatically so the operator sees the
        green check-mark without clicking Run Check. Without this,
        the tree kept showing the pre-apply state — specifically the
        ``pf.alias_persistent`` row stayed orange even though the
        migration had genuinely converted host → urltable on pfSense.
        """
        from src.ui.views.netgate import NetgateView

        view = NetgateView()
        view.set_applicable_fix_ids({"pf.alias_persistent"})
        view.display_audit_result(self._sample_payload())

        emitted: list[bool] = []
        view.run_check_requested.connect(lambda: emitted.append(True))

        # Monkeypatch MessageBox.exec to close the modal instantly so
        # the test does not hang on a blocking dialog.
        from qfluentwidgets import MessageBox

        original_exec = MessageBox.exec
        try:
            MessageBox.exec = lambda self: 1  # type: ignore[assignment,method-assign]

            view.display_apply_results(
                [
                    {
                        "fix_id": "pf.alias_persistent",
                        "success": True,
                        "backup_created": True,
                        "verify_passed": True,
                        "rollback_performed": False,
                        "messages": [],
                        "error": None,
                    }
                ]
            )

            assert emitted == [True], "Apply success did not trigger run_check_requested"
        finally:
            MessageBox.exec = original_exec  # type: ignore[method-assign]

    def test_apply_results_all_failed_does_not_auto_refresh(self, qapp: QApplication) -> None:
        """Mirror test: no point re-running the audit when nothing
        succeeded — the state has not changed."""
        from src.ui.views.netgate import NetgateView

        view = NetgateView()
        view.set_applicable_fix_ids({"pf.alias_persistent"})
        view.display_audit_result(self._sample_payload())

        emitted: list[bool] = []
        view.run_check_requested.connect(lambda: emitted.append(True))

        from qfluentwidgets import MessageBox

        original_exec = MessageBox.exec
        try:
            MessageBox.exec = lambda self: 1  # type: ignore[assignment,method-assign]

            view.display_apply_results(
                [
                    {
                        "fix_id": "pf.alias_persistent",
                        "success": False,
                        "backup_created": True,
                        "verify_passed": False,
                        "rollback_performed": True,
                        "messages": [],
                        "error": "apply failed: pfSense filter reload failed",
                    }
                ]
            )

            assert emitted == [], "audit should not auto-refresh when every fix failed"
        finally:
            MessageBox.exec = original_exec  # type: ignore[method-assign]
