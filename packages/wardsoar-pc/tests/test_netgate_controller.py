"""Tests for :class:`wardsoar.pc.ui.controllers.NetgateController`.

The controller was extracted from ``EngineWorker`` in v0.22.14
(refactor V3.3). It is the largest of the three controllers
extracted to date: 6 async / threadsafe request methods, 1
synchronous-on-the-loop request method, 2 sync helpers, and 6 Qt
signals to forward from the worker.

Coverage focus:

* **Six failure-payload shapes** — each signal has a different
  fail-safe shape, all preserved bit-for-bit from the legacy
  in-place implementation.
* **Async execution paths** — success / exception, all fail-safe.
* **Sync-on-loop path** — ``request_reset_cleanup`` schedules a
  plain callable via ``call_soon_threadsafe`` (no
  ``create_task``), unlike the other 5 async requests.
* **Sync helpers** — ``applicable_fix_ids`` and
  ``preview_custom_rules`` bypass the loop entirely.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.pc.ui.controllers import NetgateController

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


def _make_controller(pipeline: Any, loop: Any) -> NetgateController:
    return NetgateController(pipeline=pipeline, loop_provider=lambda: loop)


def _capture(controller: NetgateController, signal_name: str) -> list:
    """Connect a list spy to ``signal_name`` and return the list."""
    captured: list = []
    getattr(controller, signal_name).connect(lambda payload: captured.append(payload))
    return captured


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_all_six_signals_exist(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        for name in (
            "audit_completed",
            "baseline_established",
            "tamper_check_completed",
            "apply_completed",
            "custom_rules_deployed",
            "reset_cleanup_completed",
        ):
            assert hasattr(controller, name), f"missing signal: {name}"

    def test_loop_provider_is_called_lazily(self, qapp: QApplication) -> None:
        calls = {"count": 0}

        def provider() -> Any:
            calls["count"] += 1
            return None

        controller = NetgateController(pipeline=MagicMock(), loop_provider=provider)
        assert calls["count"] == 0  # init must NOT call the provider

        # Each async-request method exercises the provider exactly once.
        controller.request_audit()
        controller.request_establish_baseline()
        controller.request_tamper_check()
        controller.request_apply(fix_ids=["x"])
        controller.request_deploy_custom_rules()
        controller.request_reset_cleanup()
        assert calls["count"] == 6

        # Sync helpers MUST NOT touch the loop.
        controller.applicable_fix_ids = (  # type: ignore[method-assign]
            lambda: set()
        )  # avoid touching real netgate_apply
        controller.preview_custom_rules()  # touches pipeline only
        assert calls["count"] == 6


# ---------------------------------------------------------------------------
# Sync helpers — no loop, no signal
# ---------------------------------------------------------------------------


class TestSyncHelpers:
    def test_preview_custom_rules_delegates_to_pipeline(self, qapp: QApplication) -> None:
        bundle = MagicMock(name="rules_bundle")
        pipeline = MagicMock()
        pipeline.preview_custom_rules = MagicMock(return_value=bundle)
        controller = _make_controller(pipeline=pipeline, loop=None)

        result = controller.preview_custom_rules()

        assert result is bundle
        pipeline.preview_custom_rules.assert_called_once_with()

    def test_applicable_fix_ids_returns_a_set(self, qapp: QApplication) -> None:
        """Pure delegate to ``wardsoar.core.netgate_apply.applicable_fix_ids``.

        We assert the return type / non-empty-ness rather than exact
        contents so the test does not break every time the safe-apply
        layer learns about a new fix id.
        """
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        result = controller.applicable_fix_ids()
        assert isinstance(result, set)
        # Sanity: every entry is a non-empty string id.
        for fix_id in result:
            assert isinstance(fix_id, str) and fix_id


# ---------------------------------------------------------------------------
# request_audit
# ---------------------------------------------------------------------------


class TestRequestAudit:
    def test_loop_none_emits_synthetic_failure_with_audit_shape(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "audit_completed")

        controller.request_audit()

        assert captured[0] == {
            "error": "Engine not running",
            "findings": [],
            "ssh_reachable": False,
        }

    def test_loop_running_schedules_task_and_does_not_emit_yet(self, qapp: QApplication) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(pipeline=MagicMock(), loop=loop)
        captured = _capture(controller, "audit_completed")

        controller.request_audit()

        assert captured == []
        loop.call_soon_threadsafe.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_audit_success_emits_to_dict(self, qapp: QApplication) -> None:
        audit_result = MagicMock()
        audit_result.to_dict = MagicMock(
            return_value={"findings": [{"id": "fix_1"}], "ssh_reachable": True}
        )
        pipeline = MagicMock()
        pipeline.audit_netgate = AsyncMock(return_value=audit_result)
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "audit_completed")

        await controller._execute_audit()

        assert captured[0] == {"findings": [{"id": "fix_1"}], "ssh_reachable": True}
        pipeline.audit_netgate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_audit_exception_emits_failure_payload(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.audit_netgate = AsyncMock(side_effect=RuntimeError("ssh boom"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "audit_completed")

        await controller._execute_audit()

        assert captured[0] == {
            "error": "ssh boom",
            "findings": [],
            "ssh_reachable": False,
        }


# ---------------------------------------------------------------------------
# request_establish_baseline
# ---------------------------------------------------------------------------


class TestRequestEstablishBaseline:
    def test_loop_none_emits_minimal_failure(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "baseline_established")

        controller.request_establish_baseline()

        assert captured[0] == {"error": "Engine not running"}

    @pytest.mark.asyncio
    async def test_execute_success_emits_captured_metadata(self, qapp: QApplication) -> None:
        baseline = MagicMock()
        baseline.captured_at = "2026-04-25T10:00:00Z"
        baseline.host = "netgate.local"
        baseline.entries = [object(), object(), object()]
        pipeline = MagicMock()
        pipeline.establish_netgate_baseline = AsyncMock(return_value=baseline)
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "baseline_established")

        await controller._execute_establish_baseline()

        assert captured[0] == {
            "captured_at": "2026-04-25T10:00:00Z",
            "host": "netgate.local",
            "entries": 3,
        }

    @pytest.mark.asyncio
    async def test_execute_exception_emits_failure(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.establish_netgate_baseline = AsyncMock(
            side_effect=RuntimeError("baseline ssh dead")
        )
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "baseline_established")

        await controller._execute_establish_baseline()

        assert captured[0] == {"error": "baseline ssh dead"}


# ---------------------------------------------------------------------------
# request_tamper_check
# ---------------------------------------------------------------------------


class TestRequestTamperCheck:
    def test_loop_none_emits_failure_with_tamper_shape(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "tamper_check_completed")

        controller.request_tamper_check()

        assert captured[0] == {
            "error": "Engine not running",
            "findings": [],
            "baseline_present": False,
        }

    @pytest.mark.asyncio
    async def test_execute_success_emits_to_dict(self, qapp: QApplication) -> None:
        tamper = MagicMock()
        tamper.to_dict = MagicMock(
            return_value={"findings": [{"diff": "rule X removed"}], "baseline_present": True}
        )
        pipeline = MagicMock()
        pipeline.check_netgate_tampering = AsyncMock(return_value=tamper)
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "tamper_check_completed")

        await controller._execute_tamper_check()

        assert captured[0]["baseline_present"] is True
        assert captured[0]["findings"] == [{"diff": "rule X removed"}]

    @pytest.mark.asyncio
    async def test_execute_exception_emits_failure(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.check_netgate_tampering = AsyncMock(side_effect=ValueError("baseline corrupt"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "tamper_check_completed")

        await controller._execute_tamper_check()

        assert captured[0] == {
            "error": "baseline corrupt",
            "findings": [],
            "baseline_present": False,
        }


# ---------------------------------------------------------------------------
# request_apply
# ---------------------------------------------------------------------------


class TestRequestApply:
    def test_loop_none_emits_failure_per_fix_id(self, qapp: QApplication) -> None:
        """Each requested fix_id gets its own failure entry — the UI
        relies on this to render per-row errors in the audit table."""
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "apply_completed")

        controller.request_apply(fix_ids=["fix_a", "fix_b", "fix_c"])

        payload = captured[0]
        assert isinstance(payload, list)
        assert len(payload) == 3
        for entry, expected_id in zip(payload, ["fix_a", "fix_b", "fix_c"]):
            assert entry == {
                "success": False,
                "error": "Engine not running",
                "fix_id": expected_id,
            }

    def test_loop_none_with_empty_fix_ids_emits_empty_list(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "apply_completed")

        controller.request_apply(fix_ids=[])

        assert captured[0] == []

    @pytest.mark.asyncio
    async def test_execute_success_emits_per_outcome_to_dict(self, qapp: QApplication) -> None:
        outcome_a = MagicMock()
        outcome_a.to_dict = MagicMock(return_value={"success": True, "fix_id": "fix_a"})
        outcome_b = MagicMock()
        outcome_b.to_dict = MagicMock(return_value={"success": True, "fix_id": "fix_b"})
        pipeline = MagicMock()
        pipeline.apply_netgate_fixes = AsyncMock(return_value=[outcome_a, outcome_b])
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "apply_completed")

        await controller._execute_apply(fix_ids=["fix_a", "fix_b"])

        assert captured[0] == [
            {"success": True, "fix_id": "fix_a"},
            {"success": True, "fix_id": "fix_b"},
        ]
        pipeline.apply_netgate_fixes.assert_awaited_once_with(["fix_a", "fix_b"])

    @pytest.mark.asyncio
    async def test_execute_exception_emits_single_failure_entry(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.apply_netgate_fixes = AsyncMock(side_effect=RuntimeError("apply blew up"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "apply_completed")

        await controller._execute_apply(fix_ids=["fix_a"])

        # Legacy behaviour: a hard failure collapses to a single
        # synthetic entry with fix_id="?", not one entry per
        # requested fix_id. UI renders a single error row.
        assert captured[0] == [{"success": False, "error": "apply blew up", "fix_id": "?"}]


# ---------------------------------------------------------------------------
# request_deploy_custom_rules
# ---------------------------------------------------------------------------


class TestRequestDeployCustomRules:
    def test_loop_none_emits_failure_with_zero_rule_count(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "custom_rules_deployed")

        controller.request_deploy_custom_rules()

        assert captured[0] == {
            "success": False,
            "error": "Engine not running",
            "rule_count": 0,
        }

    @pytest.mark.asyncio
    async def test_execute_success_combines_deploy_and_preview(self, qapp: QApplication) -> None:
        deploy_result = MagicMock()
        deploy_result.success = True
        deploy_result.bytes_written = 4096
        deploy_result.remote_path = "/usr/local/etc/suricata/rules/wardsoar.rules"
        deploy_result.error = None

        bundle = MagicMock()
        bundle.rules = [object()] * 12

        pipeline = MagicMock()
        pipeline.deploy_custom_rules = AsyncMock(return_value=deploy_result)
        pipeline.preview_custom_rules = MagicMock(return_value=bundle)

        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "custom_rules_deployed")

        await controller._execute_deploy_custom_rules()

        assert captured[0] == {
            "success": True,
            "bytes_written": 4096,
            "remote_path": "/usr/local/etc/suricata/rules/wardsoar.rules",
            "rule_count": 12,
            "error": None,
        }

    @pytest.mark.asyncio
    async def test_execute_exception_emits_failure(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.deploy_custom_rules = AsyncMock(side_effect=RuntimeError("scp failed"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "custom_rules_deployed")

        await controller._execute_deploy_custom_rules()

        assert captured[0] == {
            "success": False,
            "error": "scp failed",
            "rule_count": 0,
        }


# ---------------------------------------------------------------------------
# request_reset_cleanup — sync on the loop thread
# ---------------------------------------------------------------------------


class TestRequestResetCleanup:
    def test_loop_none_emits_full_failure_payload(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "reset_cleanup_completed")

        controller.request_reset_cleanup()

        assert captured[0] == {
            "error": "Engine not running",
            "baseline_removed": False,
            "block_entries_purged": 0,
            "trusted_entries_purged": 0,
            "errors": ["Engine not running"],
            "message": "Engine not running — retry once the pipeline is started.",
        }

    def test_loop_running_schedules_sync_callable(self, qapp: QApplication) -> None:
        """Unlike the 5 async requests, this one schedules a plain
        callable (not a ``create_task`` wrapper) since the underlying
        pipeline op is synchronous filesystem work."""
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(pipeline=MagicMock(), loop=loop)
        captured = _capture(controller, "reset_cleanup_completed")

        controller.request_reset_cleanup()

        assert captured == []
        loop.call_soon_threadsafe.assert_called_once_with(controller._execute_reset_cleanup)

    def test_execute_success_emits_formatted_message(self, qapp: QApplication) -> None:
        result = MagicMock()
        result.baseline_removed = True
        result.block_entries_purged = 7
        result.trusted_entries_purged = 2
        result.errors = []

        pipeline = MagicMock()
        pipeline.cleanup_netgate_state = MagicMock(return_value=result)

        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "reset_cleanup_completed")

        controller._execute_reset_cleanup()

        payload = captured[0]
        assert payload["baseline_removed"] is True
        assert payload["block_entries_purged"] == 7
        assert payload["trusted_entries_purged"] == 2
        assert payload["errors"] == []
        # The actual ``format_result_for_display`` is exercised — we
        # only assert it produced a non-empty string the UI can show.
        assert isinstance(payload["message"], str) and payload["message"]

    def test_execute_exception_emits_failure_with_message(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.cleanup_netgate_state = MagicMock(side_effect=OSError("permission denied"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "reset_cleanup_completed")

        controller._execute_reset_cleanup()

        assert captured[0] == {
            "baseline_removed": False,
            "block_entries_purged": 0,
            "trusted_entries_purged": 0,
            "errors": ["permission denied"],
            "message": "Cleanup failed: permission denied",
        }


# ---------------------------------------------------------------------------
# End-to-end: sync layer hands a coroutine to a real loop
# ---------------------------------------------------------------------------


class TestSyncToAsyncBridge:
    """End-to-end coverage of the schedule lambdas inside each
    request method.

    These tests catch a class of bugs the unit tests cannot see
    (e.g. wrong scheduling primitive, coroutine never awaited,
    wrong async function name typo'd in the lambda, signal not
    connected). They also flush the four otherwise-uncovered
    ``loop.create_task(self._execute_X())`` lambda bodies from the
    coverage report so the controller stays at 100%.
    """

    @staticmethod
    async def _drain() -> None:
        """Yield twice so ``call_soon_threadsafe`` lambda fires AND
        the spawned task gets a chance to run to completion."""
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_request_audit_runs_to_completion_on_real_loop(
        self, qapp: QApplication
    ) -> None:
        audit_result = MagicMock()
        audit_result.to_dict = MagicMock(return_value={"ssh_reachable": True, "findings": []})
        pipeline = MagicMock()
        pipeline.audit_netgate = AsyncMock(return_value=audit_result)
        loop = asyncio.get_event_loop()
        controller = _make_controller(pipeline=pipeline, loop=loop)
        captured = _capture(controller, "audit_completed")

        controller.request_audit()
        await self._drain()

        assert len(captured) == 1
        assert captured[0]["ssh_reachable"] is True

    @pytest.mark.asyncio
    async def test_request_establish_baseline_runs_to_completion_on_real_loop(
        self, qapp: QApplication
    ) -> None:
        baseline = MagicMock(captured_at="2026-04-25T12:00:00Z", host="ng.local")
        baseline.entries = [object()]
        pipeline = MagicMock()
        pipeline.establish_netgate_baseline = AsyncMock(return_value=baseline)
        controller = _make_controller(pipeline=pipeline, loop=asyncio.get_event_loop())
        captured = _capture(controller, "baseline_established")

        controller.request_establish_baseline()
        await self._drain()

        assert captured[0]["host"] == "ng.local"
        assert captured[0]["entries"] == 1

    @pytest.mark.asyncio
    async def test_request_tamper_check_runs_to_completion_on_real_loop(
        self, qapp: QApplication
    ) -> None:
        tamper = MagicMock()
        tamper.to_dict = MagicMock(return_value={"baseline_present": True, "findings": []})
        pipeline = MagicMock()
        pipeline.check_netgate_tampering = AsyncMock(return_value=tamper)
        controller = _make_controller(pipeline=pipeline, loop=asyncio.get_event_loop())
        captured = _capture(controller, "tamper_check_completed")

        controller.request_tamper_check()
        await self._drain()

        assert captured[0]["baseline_present"] is True

    @pytest.mark.asyncio
    async def test_request_apply_runs_to_completion_on_real_loop(
        self, qapp: QApplication
    ) -> None:
        outcome = MagicMock()
        outcome.to_dict = MagicMock(return_value={"success": True, "fix_id": "fix_a"})
        pipeline = MagicMock()
        pipeline.apply_netgate_fixes = AsyncMock(return_value=[outcome])
        controller = _make_controller(pipeline=pipeline, loop=asyncio.get_event_loop())
        captured = _capture(controller, "apply_completed")

        controller.request_apply(fix_ids=["fix_a"])
        await self._drain()

        assert captured[0] == [{"success": True, "fix_id": "fix_a"}]
        pipeline.apply_netgate_fixes.assert_awaited_once_with(["fix_a"])

    @pytest.mark.asyncio
    async def test_request_deploy_custom_rules_runs_to_completion_on_real_loop(
        self, qapp: QApplication
    ) -> None:
        deploy_result = MagicMock(
            success=True, bytes_written=42, remote_path="/x.rules", error=None
        )
        bundle = MagicMock()
        bundle.rules = []
        pipeline = MagicMock()
        pipeline.deploy_custom_rules = AsyncMock(return_value=deploy_result)
        pipeline.preview_custom_rules = MagicMock(return_value=bundle)
        controller = _make_controller(pipeline=pipeline, loop=asyncio.get_event_loop())
        captured = _capture(controller, "custom_rules_deployed")

        controller.request_deploy_custom_rules()
        await self._drain()

        assert captured[0]["success"] is True
        assert captured[0]["bytes_written"] == 42
