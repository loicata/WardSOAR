"""Operator-driven actions on alerts — rollback and manual block.

Owns the two operator-initiated commands that bypass the automatic
pipeline:

* **Rollback** — "Unblock IP" button on the alerts table. Removes a
  pfSense block previously installed by the Responder.
* **Manual block** — "Confirm threat" decision in the Manual Review
  dialog. Synthesises a CONFIRMED verdict and runs it through the
  full Responder safety stack (whitelist / CDN allowlist / rate
  limit) so a careless click cannot bypass the safety rails.

Extracted from ``EngineWorker`` (V3.4, v0.22.13) so the operator-
action concern can be tested without a ``QThread`` and a full async
event loop. The controller is a ``QObject`` because the outcome
must be surfaced via Qt signals — the views connect to them; the
``EngineWorker`` façade re-emits them for backward compatibility.

Thread model: the operator clicks happen on the Qt main thread.
The actual rollback / responder calls are async and live on the
worker's asyncio loop. We marshal between the two via
``loop.call_soon_threadsafe(loop.create_task(...))`` exactly like
the legacy implementation did.

The controller does **not** own the loop — it borrows it through a
``loop_provider`` callable that returns the current loop (or
``None`` if the worker hasn't started yet). This keeps the
controller decoupled from the worker's lifecycle and lets the
loop reference be created lazily inside ``EngineWorker.run()``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from typing import Any, Callable, Optional

from PySide6.QtCore import QObject, Signal

from wardsoar.core.models import ThreatAnalysis, ThreatVerdict

logger = logging.getLogger("ward_soar.ui.controllers.manual_action")


class ManualActionController(QObject):
    """Run operator-initiated rollback and manual-block requests.

    Args:
        pipeline: The :class:`~wardsoar.pc.main.Pipeline` instance
            that owns the Responder and the rollback machinery.
            Typed as ``Any`` because the import would create a
            cycle (``wardsoar.pc.main`` imports controllers
            indirectly through ``wardsoar.pc.ui``).
        loop_provider: Returns the asyncio event loop the worker
            is running on, or ``None`` if the worker hasn't started
            yet. Called every time the controller needs the loop —
            never cached — so the controller keeps working if the
            worker is restarted.
    """

    #: Outcome of an "Unblock IP" click. Payload mirrors the
    #: legacy ``EngineWorker.rollback_completed`` signal:
    #: ``{"ip", "success", "error"?, "signature_id"?, ...}``.
    rollback_completed = Signal(dict)

    #: Outcome of a Manual Review CONFIRMED override. Payload:
    #: ``{"ip", "success", "reason"}``. ``success`` is ``False``
    #: when a safety rail (whitelist / CDN / rate limit) refused
    #: the block — ``reason`` carries the human-readable cause.
    manual_block_completed = Signal(dict)

    def __init__(
        self,
        pipeline: Any,
        loop_provider: Callable[[], Optional[asyncio.AbstractEventLoop]],
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._pipeline = pipeline
        self._loop_provider = loop_provider

    # ------------------------------------------------------------------
    # Public API — called from the Qt main thread.
    # ------------------------------------------------------------------

    def request_rollback(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Queue a rollback on the worker's event loop.

        Thread-safe: intended to be called from the Qt main thread
        in response to an "Unblock IP" button click. Schedules the
        async rollback and emits :attr:`rollback_completed` when
        finished. If the worker has not started yet, surfaces a
        synthetic failure immediately so the UI does not wait
        forever on a signal that will never come.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.rollback_completed.emit(
                {
                    "ip": ip,
                    "success": False,
                    "error": "Engine not running",
                }
            )
            return

        # Coroutine is created *inside* the lambda so it only exists
        # when the loop actually picks it up. Creating it eagerly
        # before ``call_soon_threadsafe`` would leak a never-awaited
        # coroutine if the scheduling never fires (e.g. loop dies
        # between the is_running() check and the threadsafe call).
        loop.call_soon_threadsafe(
            lambda: loop.create_task(
                self._execute_rollback(ip=ip, signature_id=signature_id, reason=reason)
            )
        )

    def request_manual_block(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        operator_notes: str = "",
    ) -> None:
        """Ask the Responder to block ``ip`` on behalf of the operator.

        Triggered by the Manual Review dialog when the operator
        overrides a verdict to CONFIRMED. We synthesise a
        :class:`ThreatAnalysis(verdict=CONFIRMED, confidence=0.99)`
        with the operator's notes in the reasoning, then delegate
        to ``Responder.respond`` so every safety rail runs
        (whitelist, CDN allowlist, rate limit). The outcome is
        emitted via :attr:`manual_block_completed`.

        Thread-safe — called from the Qt main thread.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.manual_block_completed.emit(
                {"ip": ip, "success": False, "reason": "Engine not running"}
            )
            return

        # See request_rollback for why the coroutine is built inside
        # the lambda rather than ahead of time.
        loop.call_soon_threadsafe(
            lambda: loop.create_task(
                self._execute_manual_block(
                    ip=ip, signature_id=signature_id, operator_notes=operator_notes
                )
            )
        )

    # ------------------------------------------------------------------
    # Async workers — extracted from the legacy ``_run()`` closures so
    # tests can ``await`` them directly without spinning an event loop
    # of their own. Both are fail-safe: any exception is logged and
    # surfaced as a signal payload — never propagated.
    # ------------------------------------------------------------------

    async def _execute_rollback(
        self,
        ip: str,
        signature_id: Optional[int],
        reason: Optional[str],
    ) -> None:
        try:
            result = await self._pipeline.rollback_block(
                ip=ip,
                signature_id=signature_id,
                reason=reason,
            )
            payload: dict[str, Any] = asdict(result)
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Rollback request failed for %s", ip)
            payload = {"ip": ip, "success": False, "error": str(exc)}
        self.rollback_completed.emit(payload)

    async def _execute_manual_block(
        self,
        ip: str,
        signature_id: Optional[int],
        operator_notes: str,
    ) -> None:
        try:
            reasoning = (
                operator_notes.strip()
                or "Operator manually overrode the pipeline verdict to CONFIRMED."
            )
            synthetic = ThreatAnalysis(
                verdict=ThreatVerdict.CONFIRMED,
                confidence=0.99,
                reasoning=f"[Manual review] {reasoning}",
                recommended_actions=["ip_block"],
            )
            actions = await self._pipeline._responder.respond(  # noqa: SLF001
                synthetic,
                ip,
                process_id=None,
                asn_info=None,
            )
            blocked = any(
                a.action_type.value in ("ip_block", "ip_port_block") and a.success
                for a in (actions or [])
            )
            if blocked:
                outcome = "Block installed on pfSense."
            else:
                refused = next(
                    (a.error_message for a in (actions or []) if a.error_message),
                    "A safety rule refused the block (whitelist / CDN / rate limit).",
                )
                outcome = refused
            payload: dict[str, Any] = {"ip": ip, "success": blocked, "reason": outcome}
        except Exception as exc:  # noqa: BLE001 — defensive
            logger.exception("Manual block request failed for %s", ip)
            payload = {"ip": ip, "success": False, "reason": str(exc)}
        self.manual_block_completed.emit(payload)
