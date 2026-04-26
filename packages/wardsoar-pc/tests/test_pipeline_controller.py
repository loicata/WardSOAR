"""Tests for :class:`wardsoar.pc.ui.controllers.PipelineController`.

The controller was extracted from ``EngineWorker`` in v0.22.16
(refactor V3.5, the last of the four planned extractions). It is
the largest controller and the only one that owns lifecycle
(asyncio loop creation, thread bootstrapping). Tests focus on the
slices that can be exercised without a real ``QThread`` /
``run_forever`` loop:

* **Construction + lifecycle state** — counters at zero, signals
  exist, loop starts ``None``.
* **Cross-thread entry points** — ``on_ssh_line``, ``request_stop``
  with mocked loops.
* **Synchronous processing** — ``_process_line`` (parse + dispatch)
  and ``_process_new_lines`` (file polling + OS error fail-safe).
* **Async processing** — ``_process_alert_async`` for both result
  types (FilteredResult, DecisionRecord) including the block /
  no-block / exception fail-safe paths.
* **Healthcheck** — healthy → silent, degraded → emits Activity row.
* **IP enrichment** — async failure returns ``None`` (fail-safe).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.core.intel.manager import IntelManager
from wardsoar.core.models import BlockAction, ResponseAction, ThreatAnalysis, ThreatVerdict
from wardsoar.pc.main import FilteredResult
from wardsoar.pc.ui.controllers import HistoryController, PipelineController

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Reuse / create a QApplication for the test module."""
    import sys

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def _make_controller(
    tmp_path: Path,
    pipeline: Any = None,
    mode: str = "ssh",
    ward_mode: str = "monitor",
    eve_path: str = "/nonexistent/eve.json",
) -> PipelineController:
    """Build a controller with sensible defaults — pipeline auto-mocked."""
    if pipeline is None:
        pipeline = MagicMock()
    history_controller = HistoryController(tmp_path / "logs" / "alerts_history.jsonl")
    intel_manager = MagicMock(spec=IntelManager)
    healthchecker = MagicMock()
    return PipelineController(
        pipeline=pipeline,
        eve_path=eve_path,
        mode=mode,
        ward_mode=ward_mode,
        history_controller=history_controller,
        intel_manager=intel_manager,
        healthchecker=healthchecker,
        health_interval_s=300,
    )


def _capture(controller: PipelineController, signal_name: str) -> list:
    """Connect a list spy to ``signal_name`` and return the list."""
    captured: list = []
    getattr(controller, signal_name).connect(lambda *args: captured.append(args))
    return captured


def _make_alert(src_ip: str = "1.2.3.4", dest_ip: str = "5.6.7.8") -> Any:
    """Construct a fake alert object compatible with the controller's expectations."""
    alert = MagicMock()
    alert.src_ip = src_ip
    alert.dest_ip = dest_ip
    alert.src_port = 12345
    alert.dest_port = 80
    alert.proto = "TCP"
    alert.alert_signature = "ET MALWARE Test"
    alert.alert_signature_id = 2210054
    alert.alert_category = "test"
    alert.alert_severity = MagicMock(value=2)
    alert.timestamp = MagicMock()
    alert.timestamp.strftime = MagicMock(return_value="2026-04-25 10:00:00")
    return alert


def _eve_alert_json() -> str:
    """Render an EVE JSON line that ``parse_eve_alert`` accepts.

    The watcher requires every Suricata field (timestamp, ports,
    proto, severity); a trimmed payload returns ``None`` and
    bypasses ``_alert_count`` increment.
    """
    return json.dumps(
        {
            "event_type": "alert",
            "timestamp": "2026-04-25T10:00:00.000000+0000",
            "src_ip": "1.2.3.4",
            "src_port": 12345,
            "dest_ip": "5.6.7.8",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 2210054,
                "signature": "TEST",
                "severity": 3,
                "category": "test",
            },
        }
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_six_signals_exist(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for name in (
            "alert_received",
            "metrics_updated",
            "activity_logged",
            "status_changed",
            "health_updated",
            "ip_blocked",
        ):
            assert hasattr(controller, name), f"missing signal: {name}"

    def test_initial_lifecycle_state(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        assert controller.loop is None
        assert controller._running is False  # noqa: SLF001
        assert controller._alert_count == 0  # noqa: SLF001
        assert controller._filtered_count == 0  # noqa: SLF001
        assert controller._blocked_count == 0  # noqa: SLF001
        assert controller._processed_count == 0  # noqa: SLF001

    def test_loop_property_exposes_internal_attribute(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """Sibling controllers borrow the loop through this property."""
        controller = _make_controller(tmp_path)
        loop = MagicMock()
        controller._loop = loop  # noqa: SLF001
        assert controller.loop is loop


# ---------------------------------------------------------------------------
# on_alert_event — cross-thread entry point (Phase 3b.5)
# ---------------------------------------------------------------------------


class TestOnAlertEvent:
    def test_loop_none_silently_drops_event(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        # Must not raise even though the loop is None.
        controller.on_alert_event({"event_type": "alert"})

    def test_loop_running_schedules_dispatch(self, qapp: QApplication, tmp_path: Path) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(tmp_path)
        controller._loop = loop  # noqa: SLF001

        event = {"event_type": "alert", "src_ip": "203.0.113.7"}
        controller.on_alert_event(event)

        loop.call_soon_threadsafe.assert_called_once_with(
            controller._dispatch_event, event  # noqa: SLF001
        )

    def test_loop_present_but_not_running_drops_event(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=False)
        controller = _make_controller(tmp_path)
        controller._loop = loop  # noqa: SLF001

        controller.on_alert_event({"event_type": "alert"})
        loop.call_soon_threadsafe.assert_not_called()


# ---------------------------------------------------------------------------
# request_stop
# ---------------------------------------------------------------------------


class TestRequestStop:
    def test_loop_none_just_clears_running_flag(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        controller._running = True  # noqa: SLF001
        controller.request_stop()
        assert controller._running is False  # noqa: SLF001

    def test_loop_running_schedules_loop_stop(self, qapp: QApplication, tmp_path: Path) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(tmp_path)
        controller._loop = loop  # noqa: SLF001
        controller._running = True  # noqa: SLF001

        controller.request_stop()

        assert controller._running is False  # noqa: SLF001
        loop.call_soon_threadsafe.assert_called_once_with(loop.stop)


# ---------------------------------------------------------------------------
# _process_line — synchronous parse + dispatch
# ---------------------------------------------------------------------------


class TestProcessLine:
    def test_malformed_json_silently_dropped(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        # Must not raise.
        controller._process_line("{not json")  # noqa: SLF001

    def test_dns_event_emits_activity(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        captured = _capture(controller, "activity_logged")

        controller._process_line(  # noqa: SLF001
            json.dumps({"event_type": "dns", "src_ip": "1.1.1.1", "dest_ip": "8.8.8.8"})
        )

        assert len(captured) == 1
        # Tuple is (time, event, details).
        _, event, details = captured[0]
        assert event == "DNS"
        assert details == "1.1.1.1 -> 8.8.8.8"

    def test_non_alert_event_returns_without_processing(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """Only ``alert`` events get pipelined — flow events stop after Activity."""
        controller = _make_controller(tmp_path)
        controller._process_line(  # noqa: SLF001
            json.dumps({"event_type": "tls", "src_ip": "1.1.1.1", "dest_ip": "8.8.8.8"})
        )
        assert controller._alert_count == 0  # noqa: SLF001

    def test_alert_event_parses_and_schedules_pipeline_task(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        # Close the scheduled coroutine on mock invocation so we do
        # not leak a never-awaited coroutine warning. In production
        # the real loop awaits it; the test only cares that
        # ``create_task`` was called with the right coroutine.
        loop.create_task = MagicMock(side_effect=lambda coro: coro.close())
        controller = _make_controller(tmp_path)
        controller._loop = loop  # noqa: SLF001

        controller._process_line(_eve_alert_json())  # noqa: SLF001

        assert controller._alert_count == 1  # noqa: SLF001
        loop.create_task.assert_called_once()

    def test_alert_event_with_unparseable_alert_logs_warning(
        self, qapp: QApplication, tmp_path: Path, caplog: Any
    ) -> None:
        """v0.6 regression — when ``parse_eve_alert`` returns None, log
        the offending keys so the operator can investigate.

        ``wardsoar.core.logger.setup_logger`` sets ``ward_soar.propagate
        = False`` once any other test triggers it, which black-holes
        records before they reach pytest's root caplog handler. We
        flip propagation back on for the duration of the assertion.
        """
        import logging

        controller = _make_controller(tmp_path)
        ward_logger = logging.getLogger("ward_soar")
        previous_propagate = ward_logger.propagate
        ward_logger.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="ward_soar.ui.controllers.pipeline"):
                controller._process_line(  # noqa: SLF001
                    json.dumps({"event_type": "alert", "alert": {"missing": "fields"}})
                )
        finally:
            ward_logger.propagate = previous_propagate

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("parse_eve_alert returned None" in r.getMessage() for r in warnings)
        assert controller._alert_count == 0  # noqa: SLF001

    def test_alert_event_without_loop_raises(self, qapp: QApplication, tmp_path: Path) -> None:
        """Defensive: a parsed alert with no loop is a programmer error."""
        controller = _make_controller(tmp_path)
        with pytest.raises(RuntimeError, match="Event loop not initialized"):
            controller._process_line(_eve_alert_json())  # noqa: SLF001


# ---------------------------------------------------------------------------
# _process_new_lines — file polling
# ---------------------------------------------------------------------------


class TestProcessNewLines:
    def test_missing_file_silently_returns(self, qapp: QApplication, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        # Must not raise even though the path does not exist.
        controller._process_new_lines(tmp_path / "missing.json")  # noqa: SLF001

    def test_no_new_data_short_circuits(self, qapp: QApplication, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("first line\n")
        controller = _make_controller(tmp_path)
        controller._last_position = eve_file.stat().st_size  # noqa: SLF001

        # No new bytes since _last_position; must not call _process_line.
        controller._process_new_lines(eve_file)  # noqa: SLF001
        assert controller._alert_count == 0  # noqa: SLF001

    def test_new_lines_dispatched_to_process_line(self, qapp: QApplication, tmp_path: Path) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        # Same trick as test_alert_event_parses_and_schedules_pipeline_task:
        # close each scheduled coroutine to avoid an unawaited warning.
        loop.create_task = MagicMock(side_effect=lambda coro: coro.close())
        controller = _make_controller(tmp_path)
        controller._loop = loop  # noqa: SLF001

        eve_file = tmp_path / "eve.json"
        # Two valid alert lines + a blank line that must be skipped.
        with eve_file.open("a", encoding="utf-8") as f:
            for _ in range(2):
                # ``\n\n`` produces a blank line that the loop must skip.
                f.write(_eve_alert_json() + "\n\n")

        controller._process_new_lines(eve_file)  # noqa: SLF001
        assert controller._alert_count == 2  # noqa: SLF001


# ---------------------------------------------------------------------------
# _run_healthchecks_async
# ---------------------------------------------------------------------------


class TestRunHealthchecksAsync:
    @pytest.mark.asyncio
    async def test_healthy_does_not_emit_activity_row(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        controller = _make_controller(tmp_path)
        result = MagicMock(component="suricata")
        result.status = MagicMock(value="healthy")
        controller._healthchecker.run_all_checks = AsyncMock(return_value=[result])  # noqa: SLF001
        controller._healthchecker.get_overall_status = MagicMock(  # noqa: SLF001
            return_value=MagicMock(value="healthy")
        )
        activity = _capture(controller, "activity_logged")
        health = _capture(controller, "health_updated")

        await controller._run_healthchecks_async()  # noqa: SLF001

        assert health  # one health_updated emission per result
        assert all(
            "Health" not in args[1] for args in activity
        ), "healthy status must not produce an Activity row"

    @pytest.mark.asyncio
    async def test_degraded_emits_one_activity_row(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        controller = _make_controller(tmp_path)
        result = MagicMock(component="claude_api")
        result.status = MagicMock(value="degraded")
        controller._healthchecker.run_all_checks = AsyncMock(return_value=[result])  # noqa: SLF001
        controller._healthchecker.get_overall_status = MagicMock(  # noqa: SLF001
            return_value=MagicMock(value="degraded")
        )
        activity = _capture(controller, "activity_logged")

        await controller._run_healthchecks_async()  # noqa: SLF001

        health_rows = [args for args in activity if args[1] == "Health"]
        assert len(health_rows) == 1
        assert "degraded" in health_rows[0][2]

    @pytest.mark.asyncio
    async def test_exception_swallowed_does_not_propagate(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """Healthcheck failure must never crash the worker."""
        controller = _make_controller(tmp_path)
        controller._healthchecker.run_all_checks = AsyncMock(  # noqa: SLF001
            side_effect=RuntimeError("hc failed")
        )
        # Must not raise.
        await controller._run_healthchecks_async()  # noqa: SLF001


# ---------------------------------------------------------------------------
# _build_ip_enrichment_for — fail-safe
# ---------------------------------------------------------------------------


class TestBuildIpEnrichmentFor:
    @pytest.mark.asyncio
    async def test_underlying_failure_returns_none(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """Enrichment is best-effort — a failure must not break the
        hot path (we return None and the UI renders a minimal
        Identity block)."""
        from unittest.mock import patch

        pipeline = MagicMock()
        controller = _make_controller(tmp_path, pipeline=pipeline)

        with patch(
            "wardsoar.pc.ui.controllers.pipeline_controller.build_ip_enrichment_async",
            side_effect=RuntimeError("intel down"),
        ):
            result = await controller._build_ip_enrichment_for("1.2.3.4")  # noqa: SLF001

        assert result is None


# ---------------------------------------------------------------------------
# _process_alert_async — the hot path
# ---------------------------------------------------------------------------


class TestProcessAlertAsync:
    @pytest.mark.asyncio
    async def test_permission_error_logged_and_swallowed(
        self, qapp: QApplication, tmp_path: Path, caplog: Any
    ) -> None:
        import logging

        pipeline = MagicMock()
        pipeline.process_alert = AsyncMock(side_effect=PermissionError("no perm"))
        controller = _make_controller(tmp_path, pipeline=pipeline)
        captured = _capture(controller, "activity_logged")

        # See test_alert_event_with_unparseable_alert_logs_warning:
        # ``ward_soar.propagate`` is flipped to False once
        # ``setup_logger`` runs in another test, so we flip it back
        # for the duration of this assertion.
        ward_logger = logging.getLogger("ward_soar")
        previous_propagate = ward_logger.propagate
        ward_logger.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="ward_soar.ui.controllers.pipeline"):
                await controller._process_alert_async(_make_alert())  # noqa: SLF001
        finally:
            ward_logger.propagate = previous_propagate

        # PermissionError is logged WARNING but does NOT emit an
        # ERROR activity row — those are reserved for unexpected
        # failures.
        assert any("permission error" in r.getMessage().lower() for r in caplog.records)
        assert not any(args[1] == "ERROR" for args in captured)

    @pytest.mark.asyncio
    async def test_generic_exception_emits_error_activity(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        pipeline = MagicMock()
        pipeline.process_alert = AsyncMock(side_effect=RuntimeError("boom"))
        controller = _make_controller(tmp_path, pipeline=pipeline)
        captured = _capture(controller, "activity_logged")

        await controller._process_alert_async(_make_alert())  # noqa: SLF001

        error_rows = [args for args in captured if args[1] == "ERROR"]
        assert len(error_rows) == 1
        assert "boom" in error_rows[0][2]

    @pytest.mark.asyncio
    async def test_filtered_result_emits_alert_and_persists(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        from unittest.mock import patch

        filter_meta = {}
        filter_obj = MagicMock()
        filter_obj.get_sid_metadata = MagicMock(return_value=filter_meta)
        pipeline = MagicMock()
        pipeline._filter = filter_obj
        pipeline.process_alert = AsyncMock(
            return_value=FilteredResult(reason="known false positive")
        )
        controller = _make_controller(tmp_path, pipeline=pipeline)
        alerts = _capture(controller, "alert_received")

        with patch(
            "wardsoar.pc.ui.controllers.pipeline_controller.build_ip_enrichment_async",
            new=AsyncMock(return_value={"asn": "AS_X"}),
        ):
            await controller._process_alert_async(_make_alert())  # noqa: SLF001

        assert controller._filtered_count == 1  # noqa: SLF001
        assert len(alerts) == 1
        payload = alerts[0][0]
        assert payload["verdict"] == "filtered"
        assert payload["src_ip"] == "1.2.3.4"
        assert "_full" in payload  # detail-view payload built

        # Persisted to history.
        history = controller._history_controller.load_alert_history()  # noqa: SLF001
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_decision_record_with_block_emits_ip_blocked(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        from unittest.mock import patch

        from wardsoar.core.models import DecisionRecord

        action = ResponseAction(action_type=BlockAction.IP_BLOCK, success=True, target_ip="1.2.3.4")
        analysis = ThreatAnalysis(verdict=ThreatVerdict.CONFIRMED, confidence=0.9, reasoning="bad")
        record = MagicMock(spec=DecisionRecord)
        record.alert = _make_alert()
        record.analysis = analysis
        record.actions_taken = [action]
        record.pipeline_duration_ms = 42

        pipeline = MagicMock()
        pipeline.process_alert = AsyncMock(return_value=record)
        controller = _make_controller(tmp_path, pipeline=pipeline)
        controller._alert_count = 1  # noqa: SLF001 — set by _process_line normally
        alerts = _capture(controller, "alert_received")
        blocks = _capture(controller, "ip_blocked")
        metrics = _capture(controller, "metrics_updated")

        with (
            patch(
                "wardsoar.pc.ui.controllers.pipeline_controller.build_ip_enrichment_async",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "wardsoar.pc.ui.controllers.pipeline_controller.serialise_decision_record",
                return_value={"summary": "test"},
            ),
        ):
            await controller._process_alert_async(record.alert)  # noqa: SLF001

        assert controller._processed_count == 1  # noqa: SLF001
        assert controller._blocked_count == 1  # noqa: SLF001
        assert len(alerts) == 1
        assert len(blocks) == 1
        assert blocks[0][0]["ip"] == "1.2.3.4"
        assert metrics, "metrics_updated must be emitted on every DecisionRecord"

    @pytest.mark.asyncio
    async def test_decision_record_without_block_does_not_emit_ip_blocked(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        from unittest.mock import patch

        from wardsoar.core.models import DecisionRecord

        record = MagicMock(spec=DecisionRecord)
        record.alert = _make_alert()
        record.analysis = ThreatAnalysis(
            verdict=ThreatVerdict.BENIGN, confidence=0.95, reasoning="ok"
        )
        record.actions_taken = []
        record.pipeline_duration_ms = 12

        pipeline = MagicMock()
        pipeline.process_alert = AsyncMock(return_value=record)
        controller = _make_controller(tmp_path, pipeline=pipeline)
        controller._alert_count = 1  # noqa: SLF001
        blocks = _capture(controller, "ip_blocked")

        with (
            patch(
                "wardsoar.pc.ui.controllers.pipeline_controller.build_ip_enrichment_async",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "wardsoar.pc.ui.controllers.pipeline_controller.serialise_decision_record",
                return_value={},
            ),
        ):
            await controller._process_alert_async(record.alert)  # noqa: SLF001

        assert controller._blocked_count == 0  # noqa: SLF001
        assert blocks == []

    @pytest.mark.asyncio
    async def test_unexpected_result_type_raises_typeerror(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        pipeline = MagicMock()
        pipeline.process_alert = AsyncMock(return_value="not-a-known-type")
        controller = _make_controller(tmp_path, pipeline=pipeline)

        with pytest.raises(TypeError, match="Expected DecisionRecord"):
            await controller._process_alert_async(_make_alert())  # noqa: SLF001


# ---------------------------------------------------------------------------
# _alerts_stats_purge_loop — the once-then-24h cycle
# ---------------------------------------------------------------------------


class TestAlertsStatsPurgeLoop:
    @pytest.mark.asyncio
    async def test_initial_purge_runs_then_loop_exits_when_running_flips(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        controller = _make_controller(tmp_path)
        controller._running = False  # noqa: SLF001 — the loop will exit immediately
        store = MagicMock()

        await controller._alerts_stats_purge_loop(store)  # noqa: SLF001

        # Initial purge MUST always run regardless of _running.
        store.purge_older_than.assert_called_once()

    @pytest.mark.asyncio
    async def test_initial_purge_swallows_exceptions(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        controller = _make_controller(tmp_path)
        controller._running = False  # noqa: SLF001
        store = MagicMock()
        store.purge_older_than = MagicMock(side_effect=RuntimeError("disk gone"))

        # Must not raise.
        await controller._alerts_stats_purge_loop(store)  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_periodic_purge_swallows_exceptions(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """The 24h cycle path: a periodic purge that raises must
        not break the loop. Patch ``asyncio.sleep`` to flip
        ``_running`` so the loop exits after one tick."""
        from unittest.mock import patch

        controller = _make_controller(tmp_path)
        controller._running = True  # noqa: SLF001
        store = MagicMock()
        # The first call (initial purge) succeeds; the second call
        # (periodic purge after sleep) raises.
        store.purge_older_than = MagicMock(side_effect=[None, RuntimeError("disk full")])

        async def _flip_running(_: float) -> None:
            controller._running = False  # noqa: SLF001

        with patch("asyncio.sleep", new=_flip_running):
            await controller._alerts_stats_purge_loop(store)  # noqa: SLF001

        # Both purge attempts ran (initial + periodic) and neither
        # propagated.
        assert store.purge_older_than.call_count == 2


# ---------------------------------------------------------------------------
# Misc — _none_coroutine and _maybe_run_healthchecks_async cadence
# ---------------------------------------------------------------------------


class TestNoneCoroutine:
    @pytest.mark.asyncio
    async def test_returns_none(self, qapp: QApplication) -> None:
        """Trivial helper used by ``asyncio.gather`` branches that
        only need one of the two IP enrichments — must return None
        without raising or doing any work."""
        from wardsoar.pc.ui.controllers.pipeline_controller import _none_coroutine

        assert await _none_coroutine() is None


class TestMaybeRunHealthchecks:
    @pytest.mark.asyncio
    async def test_skips_when_interval_not_elapsed(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        """A second healthcheck within ``health_interval_s`` must be
        skipped — otherwise we burn API calls and Activity rows on
        what should be a 5-minute cadence."""
        controller = _make_controller(tmp_path)
        controller._healthchecker.run_all_checks = AsyncMock(return_value=[])  # noqa: SLF001
        controller._healthchecker.get_overall_status = MagicMock(  # noqa: SLF001
            return_value=MagicMock(value="healthy")
        )

        # First call: runs.
        await controller._maybe_run_healthchecks_async()  # noqa: SLF001
        first_calls = controller._healthchecker.run_all_checks.await_count  # noqa: SLF001
        assert first_calls == 1

        # Second call right after: must NOT run (interval = 300 s).
        await controller._maybe_run_healthchecks_async()  # noqa: SLF001
        assert controller._healthchecker.run_all_checks.await_count == 1  # noqa: SLF001


class TestMainLoop:
    """The async main loop is hard to test as a whole (it runs
    forever) but the SSH and file-missing branches both have
    deterministic exits we can drive."""

    @pytest.mark.asyncio
    async def test_ssh_mode_emits_status_and_activity_then_exits(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        from unittest.mock import patch

        controller = _make_controller(tmp_path, mode="ssh")
        controller._healthchecker.run_all_checks = AsyncMock(return_value=[])  # noqa: SLF001
        controller._healthchecker.get_overall_status = MagicMock(  # noqa: SLF001
            return_value=MagicMock(value="healthy")
        )
        controller._running = True  # noqa: SLF001
        status_emissions = _capture(controller, "status_changed")
        activity_emissions = _capture(controller, "activity_logged")

        async def _flip_running(_: float) -> None:
            controller._running = False  # noqa: SLF001

        with patch("asyncio.sleep", new=_flip_running):
            await controller._main_loop()  # noqa: SLF001

        # Status must report Operational + the mode label.
        assert any(args[0] == "Operational" and args[1] == "Monitor" for args in status_emissions)
        # Activity must include the SSH-mode start banner.
        assert any("SSH mode" in args[2] for args in activity_emissions)

    @pytest.mark.asyncio
    async def test_file_mode_missing_eve_emits_warning_and_returns(
        self, qapp: QApplication, tmp_path: Path
    ) -> None:
        controller = _make_controller(
            tmp_path,
            mode="file",
            eve_path=str(tmp_path / "absent" / "eve.json"),
        )
        controller._healthchecker.run_all_checks = AsyncMock(return_value=[])  # noqa: SLF001
        controller._healthchecker.get_overall_status = MagicMock(  # noqa: SLF001
            return_value=MagicMock(value="healthy")
        )
        controller._running = True  # noqa: SLF001
        activity_emissions = _capture(controller, "activity_logged")

        # No need to patch sleep: missing-file branch returns
        # immediately without entering the polling loop.
        await controller._main_loop()  # noqa: SLF001

        assert any(
            args[1] == "Warning" and "EVE file not found" in args[2] for args in activity_emissions
        )
