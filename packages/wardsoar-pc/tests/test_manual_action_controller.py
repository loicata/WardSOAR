"""Tests for :class:`wardsoar.pc.ui.controllers.ManualActionController`.

The controller was extracted from ``EngineWorker`` in v0.22.13
(refactor V3.4). The async closures that previously lived inside
``request_rollback`` / ``request_manual_block`` were promoted to
plain async methods (``_execute_rollback`` / ``_execute_manual_block``)
so tests can ``await`` them directly without spinning a real event
loop.

Coverage focus:

* **Loop-not-running paths** — synthetic failure must be emitted
  synchronously so the UI does not wait on a signal that will
  never come.
* **Async execution paths** — success / refusal / exception, all
  fail-safe (no exception ever propagates from the controller).
* **Signal forwarding** — ``rollback_completed`` /
  ``manual_block_completed`` payloads keep the legacy shape so
  ``app.py`` and the alerts view do not need to change.
* **Synthetic verdict** — manual block goes through the full
  Responder safety stack; the synthetic ``ThreatAnalysis`` must
  carry CONFIRMED + 0.99 confidence + the operator's reasoning.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.core.models import BlockAction, ResponseAction, ThreatAnalysis, ThreatVerdict
from wardsoar.core.rollback import RollbackResult
from wardsoar.pc.ui.controllers import ManualActionController

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Reuse / create a QApplication for the test module.

    Signal/slot machinery requires a Qt application object even
    though we never show a widget. ``QObject`` itself does not
    need it but the connect/emit plumbing under the hood does.
    """
    import sys

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def _make_controller(pipeline: Any, loop: Any) -> ManualActionController:
    """Build a controller with a fixed ``loop`` returned by the provider."""
    return ManualActionController(pipeline=pipeline, loop_provider=lambda: loop)


def _capture(controller: ManualActionController, signal_name: str) -> list[dict]:
    """Connect a list spy to ``signal_name`` and return the list."""
    captured: list[dict] = []
    getattr(controller, signal_name).connect(lambda payload: captured.append(payload))
    return captured


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_signals_exist(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        assert hasattr(controller, "rollback_completed")
        assert hasattr(controller, "manual_block_completed")

    def test_loop_provider_is_called_lazily(self, qapp: QApplication) -> None:
        """The provider must be called per-request, not cached at init."""
        calls = {"count": 0}

        def provider() -> Any:
            calls["count"] += 1
            return None

        controller = ManualActionController(pipeline=MagicMock(), loop_provider=provider)
        assert calls["count"] == 0  # init must NOT call the provider

        controller.request_rollback(ip="1.2.3.4")
        assert calls["count"] == 1

        controller.request_manual_block(ip="1.2.3.4")
        assert calls["count"] == 2


# ---------------------------------------------------------------------------
# request_rollback — sync layer
# ---------------------------------------------------------------------------


class TestRequestRollback:
    def test_loop_none_emits_synthetic_failure(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "rollback_completed")

        controller.request_rollback(ip="1.2.3.4")

        assert len(captured) == 1
        assert captured[0] == {
            "ip": "1.2.3.4",
            "success": False,
            "error": "Engine not running",
        }

    def test_loop_not_running_emits_synthetic_failure(self, qapp: QApplication) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=False)
        controller = _make_controller(pipeline=MagicMock(), loop=loop)
        captured = _capture(controller, "rollback_completed")

        controller.request_rollback(ip="1.2.3.4")

        assert captured[0]["error"] == "Engine not running"
        # Crucially: the loop must NOT receive a scheduling call when
        # it is not running, otherwise the task is queued against a
        # dead loop and silently leaks.
        loop.call_soon_threadsafe.assert_not_called()

    def test_loop_running_schedules_task_and_does_not_emit_yet(self, qapp: QApplication) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(pipeline=MagicMock(), loop=loop)
        captured = _capture(controller, "rollback_completed")

        controller.request_rollback(
            ip="1.2.3.4", signature_id=2210054, reason="Operator says false positive"
        )

        # The sync layer schedules but never emits — the emit happens
        # inside the async ``_execute_rollback`` once the awaited
        # rollback returns.
        assert captured == []
        loop.call_soon_threadsafe.assert_called_once()


# ---------------------------------------------------------------------------
# _execute_rollback — async layer
# ---------------------------------------------------------------------------


class TestExecuteRollback:
    @pytest.mark.asyncio
    async def test_success_emits_asdict_result(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.rollback_block = AsyncMock(
            return_value=RollbackResult(
                ip="1.2.3.4",
                success=True,
                unblocked_at="2026-04-25T10:00:00Z",
                signature_id=2210054,
                reason="Operator click",
            )
        )
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "rollback_completed")

        await controller._execute_rollback(
            ip="1.2.3.4", signature_id=2210054, reason="Operator click"
        )

        assert len(captured) == 1
        payload = captured[0]
        assert payload["ip"] == "1.2.3.4"
        assert payload["success"] is True
        assert payload["unblocked_at"] == "2026-04-25T10:00:00Z"
        assert payload["signature_id"] == 2210054

        pipeline.rollback_block.assert_awaited_once_with(
            ip="1.2.3.4", signature_id=2210054, reason="Operator click"
        )

    @pytest.mark.asyncio
    async def test_exception_emits_failure_payload_and_does_not_raise(
        self, qapp: QApplication
    ) -> None:
        pipeline = MagicMock()
        pipeline.rollback_block = AsyncMock(side_effect=RuntimeError("ssh dead"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "rollback_completed")

        # Must NOT raise — fail-safe contract.
        await controller._execute_rollback(ip="1.2.3.4", signature_id=None, reason=None)

        assert captured[0] == {
            "ip": "1.2.3.4",
            "success": False,
            "error": "ssh dead",
        }


# ---------------------------------------------------------------------------
# request_manual_block — sync layer
# ---------------------------------------------------------------------------


class TestRequestManualBlock:
    def test_loop_none_emits_synthetic_failure(self, qapp: QApplication) -> None:
        controller = _make_controller(pipeline=MagicMock(), loop=None)
        captured = _capture(controller, "manual_block_completed")

        controller.request_manual_block(ip="1.2.3.4")

        assert captured[0] == {
            "ip": "1.2.3.4",
            "success": False,
            "reason": "Engine not running",
        }

    def test_loop_running_schedules_task_and_does_not_emit_yet(self, qapp: QApplication) -> None:
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        controller = _make_controller(pipeline=MagicMock(), loop=loop)
        captured = _capture(controller, "manual_block_completed")

        controller.request_manual_block(ip="1.2.3.4", operator_notes="Looks bad")

        assert captured == []
        loop.call_soon_threadsafe.assert_called_once()


# ---------------------------------------------------------------------------
# _execute_manual_block — async layer
# ---------------------------------------------------------------------------


class TestExecuteManualBlock:
    @pytest.mark.asyncio
    async def test_block_success_emits_pfsense_message(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(
            return_value=[ResponseAction(action_type=BlockAction.IP_BLOCK, success=True)]
        )
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "manual_block_completed")

        await controller._execute_manual_block(ip="1.2.3.4", signature_id=None, operator_notes="")

        assert captured[0] == {
            "ip": "1.2.3.4",
            "success": True,
            "reason": "Block installed on pfSense.",
        }

    @pytest.mark.asyncio
    async def test_block_refused_surfaces_responder_error_message(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(
            return_value=[
                ResponseAction(
                    action_type=BlockAction.IP_BLOCK,
                    success=False,
                    error_message="IP is on the operator whitelist",
                )
            ]
        )
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "manual_block_completed")

        await controller._execute_manual_block(ip="10.0.0.1", signature_id=None, operator_notes="")

        assert captured[0] == {
            "ip": "10.0.0.1",
            "success": False,
            "reason": "IP is on the operator whitelist",
        }

    @pytest.mark.asyncio
    async def test_no_actions_returns_default_refusal(self, qapp: QApplication) -> None:
        """Empty action list → generic safety-rail refusal message."""
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(return_value=[])
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "manual_block_completed")

        await controller._execute_manual_block(ip="1.2.3.4", signature_id=None, operator_notes="")

        assert captured[0]["success"] is False
        assert "safety rule refused" in captured[0]["reason"]

    @pytest.mark.asyncio
    async def test_none_actions_returns_default_refusal(self, qapp: QApplication) -> None:
        """``None`` from responder must be treated like an empty list."""
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(return_value=None)
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "manual_block_completed")

        await controller._execute_manual_block(ip="1.2.3.4", signature_id=None, operator_notes="")

        assert captured[0]["success"] is False

    @pytest.mark.asyncio
    async def test_exception_emits_failure_payload_and_does_not_raise(
        self, qapp: QApplication
    ) -> None:
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(side_effect=RuntimeError("pfsense down"))
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())
        captured = _capture(controller, "manual_block_completed")

        await controller._execute_manual_block(ip="1.2.3.4", signature_id=None, operator_notes="")

        assert captured[0] == {
            "ip": "1.2.3.4",
            "success": False,
            "reason": "pfsense down",
        }

    @pytest.mark.asyncio
    async def test_synthetic_verdict_is_confirmed_high_confidence(self, qapp: QApplication) -> None:
        """The Responder must see CONFIRMED + 0.99 + Manual review prefix."""
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(return_value=[])
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())

        await controller._execute_manual_block(
            ip="1.2.3.4",
            signature_id=2210054,
            operator_notes="Logged into known C2",
        )

        call_args = pipeline._responder.respond.await_args
        synthetic: ThreatAnalysis = call_args.args[0]
        assert synthetic.verdict == ThreatVerdict.CONFIRMED
        assert synthetic.confidence == 0.99
        assert synthetic.reasoning.startswith("[Manual review]")
        assert "Logged into known C2" in synthetic.reasoning
        assert synthetic.recommended_actions == ["ip_block"]

        # Positional args after the synthetic verdict: ip, then process_id /
        # asn_info as kwargs.
        assert call_args.args[1] == "1.2.3.4"
        assert call_args.kwargs == {"process_id": None, "asn_info": None}

    @pytest.mark.asyncio
    async def test_empty_operator_notes_uses_default_reasoning(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline._responder = MagicMock()
        pipeline._responder.respond = AsyncMock(return_value=[])
        controller = _make_controller(pipeline=pipeline, loop=MagicMock())

        # Whitespace-only notes must trigger the default reasoning, not be
        # passed through verbatim.
        await controller._execute_manual_block(
            ip="1.2.3.4", signature_id=None, operator_notes="   \n\t  "
        )

        synthetic: ThreatAnalysis = pipeline._responder.respond.await_args.args[0]
        assert "Operator manually overrode" in synthetic.reasoning


# ---------------------------------------------------------------------------
# End-to-end with a real (in-thread) event loop
# ---------------------------------------------------------------------------


class TestSyncToAsyncBridge:
    """Verify the sync layer correctly hands a coroutine to the async loop.

    Other tests stub the loop and exercise the async layer directly;
    this one runs both halves in the same call to catch a class of
    bugs the unit tests cannot see (e.g. coroutine never awaited,
    wrong scheduling primitive).
    """

    @pytest.mark.asyncio
    async def test_request_rollback_actually_runs_to_completion(self, qapp: QApplication) -> None:
        pipeline = MagicMock()
        pipeline.rollback_block = AsyncMock(return_value=RollbackResult(ip="1.2.3.4", success=True))
        loop = asyncio.get_event_loop()
        controller = _make_controller(pipeline=pipeline, loop=loop)
        captured = _capture(controller, "rollback_completed")

        controller.request_rollback(ip="1.2.3.4")
        # Yield twice: once for ``call_soon_threadsafe`` to fire the
        # scheduling lambda, once for the ``create_task`` coroutine
        # to actually run to completion.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert len(captured) == 1
        assert captured[0]["ip"] == "1.2.3.4"
        assert captured[0]["success"] is True
