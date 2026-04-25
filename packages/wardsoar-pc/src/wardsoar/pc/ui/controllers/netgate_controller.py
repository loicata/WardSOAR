"""Netgate operations — audit, baseline, tamper, apply, deploy, reset cleanup.

Owns the operator-facing actions exposed by the *Netgate* tab:

* **Audit** — run the SSH-based audit against the appliance.
* **Establish baseline** / **tamper check** — capture and diff the
  appliance's state to detect unauthorised changes.
* **Safe-apply** — execute the checked audit findings with the
  guard-rail subset of fixes the operator opted into.
* **Deploy custom rules** — push the WardSOAR custom Suricata
  rules to the Netgate.
* **Reset cleanup** — purge WardSOAR-side state tied to a Netgate
  that was just factory-reset (sync filesystem ops).

Plus two synchronous helpers the UI calls directly to populate
widgets before any async work starts:

* :meth:`applicable_fix_ids` — list of fix ids the safe-apply layer
  knows about. Used by the audit table to enable / disable the
  per-finding checkboxes.
* :meth:`preview_custom_rules` — build the rules bundle in-process
  for the preview dialog (no SSH).

Extracted from ``EngineWorker`` (V3.3, v0.22.14) to make the Netgate
concern testable without a full ``QThread`` event loop. Same
pattern as :class:`HistoryController` (V3.2) and
:class:`ManualActionController` (V3.4): the controller owns its
six signals, ``EngineWorker`` re-exposes them via Qt
signal-to-signal connections so existing callers in ``app.py``
(see ``app.py:528-568``) keep working unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional

from PySide6.QtCore import QObject, Signal

logger = logging.getLogger("ward_soar.ui.controllers.netgate")


class NetgateController(QObject):
    """Run Netgate appliance operations on behalf of the UI.

    Args:
        pipeline: The :class:`~wardsoar.pc.main.Pipeline` instance
            that owns the Netgate audit / baseline / apply machinery.
            Typed as ``Any`` to avoid an import cycle through
            ``wardsoar.pc.main``.
        loop_provider: Returns the asyncio event loop the worker
            is running on, or ``None`` if the worker hasn't started
            yet. Called every time the controller needs the loop —
            never cached — so the controller keeps working if the
            worker is restarted.
    """

    #: Outcome of an audit run. Payload is the serialised
    #: :class:`~wardsoar.core.netgate_audit.AuditResult` dict, or
    #: ``{"error", "findings": [], "ssh_reachable": False}`` on
    #: failure.
    audit_completed = Signal(dict)

    #: Outcome of a baseline capture. Payload:
    #: ``{"captured_at", "host", "entries"}`` on success,
    #: ``{"error"}`` on failure.
    baseline_established = Signal(dict)

    #: Outcome of a tamper check. Payload is the serialised
    #: :class:`~wardsoar.core.netgate_tamper.TamperResult` dict, or
    #: ``{"error", "findings": [], "baseline_present": False}`` on
    #: failure.
    tamper_check_completed = Signal(dict)

    #: Outcome of safe-apply. Payload is a list of serialised
    #: :class:`~wardsoar.core.netgate_apply.SafeApplyResult` dicts,
    #: one per fix id processed. On total failure the list contains
    #: a single ``{"success": False, "error", "fix_id"}`` entry.
    apply_completed = Signal(list)

    #: Outcome of deploying custom Suricata rules. Payload:
    #: ``{"success", "bytes_written", "remote_path", "rule_count",
    #: "error"}``.
    custom_rules_deployed = Signal(dict)

    #: Outcome of post-reset cleanup. Payload:
    #: ``{"baseline_removed", "block_entries_purged",
    #: "trusted_entries_purged", "errors", "message"}``.
    reset_cleanup_completed = Signal(dict)

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
    # Synchronous helpers — no loop, no signal, called directly by the UI.
    # ------------------------------------------------------------------

    def applicable_fix_ids(self) -> set[str]:
        """List of fix ids the safe-apply layer knows about.

        The UI calls this to decide which checkboxes are active in
        the audit findings table. Pure in-process — no SSH.
        """
        from wardsoar.core.netgate_apply import applicable_fix_ids

        return applicable_fix_ids()

    def preview_custom_rules(self) -> Any:
        """Build the rules bundle synchronously for the preview dialog.

        The UI calls this from the GUI thread to show a preview
        before the operator decides to deploy. Since it does not
        touch SSH it is safe to run outside the worker loop.
        """
        return self._pipeline.preview_custom_rules()

    # ------------------------------------------------------------------
    # Async / threadsafe public API — called from the Qt main thread.
    # ------------------------------------------------------------------

    def request_audit(self) -> None:
        """Kick off a Netgate audit on the worker's event loop.

        Thread-safe — called when the operator clicks "Run Check"
        in the Netgate tab. The audit issues ~10 SSH commands
        (~5-15 s on a healthy Netgate); the result is emitted as
        a serialised dict on :attr:`audit_completed`.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.audit_completed.emit(
                {"error": "Engine not running", "findings": [], "ssh_reachable": False}
            )
            return

        loop.call_soon_threadsafe(lambda: loop.create_task(self._execute_audit()))

    def request_establish_baseline(self) -> None:
        """Capture a fresh tamper baseline on the worker's event loop.

        Thread-safe — called when the operator clicks *Establish /
        Re-bless baseline* in the Netgate tab. Emits
        :attr:`baseline_established` when done.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.baseline_established.emit({"error": "Engine not running"})
            return

        loop.call_soon_threadsafe(lambda: loop.create_task(self._execute_establish_baseline()))

    def request_tamper_check(self) -> None:
        """Diff the current Netgate state against the stored baseline.

        Emits :attr:`tamper_check_completed` with a serialised
        :class:`~wardsoar.core.netgate_tamper.TamperResult` dict.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.tamper_check_completed.emit(
                {"error": "Engine not running", "findings": [], "baseline_present": False}
            )
            return

        loop.call_soon_threadsafe(lambda: loop.create_task(self._execute_tamper_check()))

    def request_apply(self, fix_ids: list[str]) -> None:
        """Run safe-apply for the checked audit findings.

        Emits :attr:`apply_completed` when the whole list is
        processed, with one :class:`SafeApplyResult` dict per fix
        id attempted. Stops on first hard failure with no rollback —
        the result list then ends early.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.apply_completed.emit(
                [
                    {"success": False, "error": "Engine not running", "fix_id": fid}
                    for fid in fix_ids
                ]
            )
            return

        loop.call_soon_threadsafe(lambda: loop.create_task(self._execute_apply(fix_ids)))

    def request_deploy_custom_rules(self) -> None:
        """Push the WardSOAR custom Suricata rules to the Netgate.

        Emits :attr:`custom_rules_deployed` on completion.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.custom_rules_deployed.emit(
                {"success": False, "error": "Engine not running", "rule_count": 0}
            )
            return

        loop.call_soon_threadsafe(lambda: loop.create_task(self._execute_deploy_custom_rules()))

    def request_reset_cleanup(self) -> None:
        """Purge WardSOAR state tied to a Netgate that just got reset.

        Synchronous on the pipeline side (pure filesystem ops), but
        the invocation is still marshalled through the worker's
        event loop so the UI thread never touches non-Qt state
        directly. Emits :attr:`reset_cleanup_completed` with a dict
        of counters plus a pre-formatted ``message`` the UI can
        display verbatim.
        """
        loop = self._loop_provider()
        if loop is None or not loop.is_running():
            self.reset_cleanup_completed.emit(
                {
                    "error": "Engine not running",
                    "baseline_removed": False,
                    "block_entries_purged": 0,
                    "trusted_entries_purged": 0,
                    "errors": ["Engine not running"],
                    "message": "Engine not running — retry once the pipeline is started.",
                }
            )
            return

        loop.call_soon_threadsafe(self._execute_reset_cleanup)

    # ------------------------------------------------------------------
    # Workers — extracted from the legacy ``_run()`` closures so tests
    # can ``await`` (or call) them directly without spinning an event
    # loop of their own. All are fail-safe: any exception is logged
    # and surfaced as a signal payload — never propagated.
    # ------------------------------------------------------------------

    async def _execute_audit(self) -> None:
        try:
            result = await self._pipeline.audit_netgate()
            payload: dict[str, Any] = result.to_dict()
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Netgate audit request failed")
            payload = {"error": str(exc), "findings": [], "ssh_reachable": False}
        self.audit_completed.emit(payload)

    async def _execute_establish_baseline(self) -> None:
        try:
            baseline = await self._pipeline.establish_netgate_baseline()
            payload: dict[str, Any] = {
                "captured_at": baseline.captured_at,
                "host": baseline.host,
                "entries": len(baseline.entries),
            }
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Netgate baseline establishment failed")
            payload = {"error": str(exc)}
        self.baseline_established.emit(payload)

    async def _execute_tamper_check(self) -> None:
        try:
            result = await self._pipeline.check_netgate_tampering()
            payload: dict[str, Any] = result.to_dict()
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Netgate tamper check failed")
            payload = {"error": str(exc), "findings": [], "baseline_present": False}
        self.tamper_check_completed.emit(payload)

    async def _execute_apply(self, fix_ids: list[str]) -> None:
        try:
            outcomes = await self._pipeline.apply_netgate_fixes(fix_ids)
            payload: list[dict[str, Any]] = [r.to_dict() for r in outcomes]
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Netgate safe-apply failed")
            payload = [{"success": False, "error": str(exc), "fix_id": "?"}]
        self.apply_completed.emit(payload)

    async def _execute_deploy_custom_rules(self) -> None:
        try:
            result = await self._pipeline.deploy_custom_rules()
            bundle = self._pipeline.preview_custom_rules()
            payload: dict[str, Any] = {
                "success": result.success,
                "bytes_written": result.bytes_written,
                "remote_path": result.remote_path,
                "rule_count": len(bundle.rules),
                "error": result.error,
            }
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Deploy custom rules failed")
            payload = {"success": False, "error": str(exc), "rule_count": 0}
        self.custom_rules_deployed.emit(payload)

    def _execute_reset_cleanup(self) -> None:
        """Synchronous worker — runs on the event loop thread.

        ``cleanup_netgate_state()`` is pure filesystem and does not
        need to be awaited. We still hop onto the loop thread (via
        ``call_soon_threadsafe(self._execute_reset_cleanup)``) so the
        invariant "all pipeline ops happen on the worker thread"
        holds.
        """
        from wardsoar.core.netgate_reset import format_result_for_display

        try:
            result = self._pipeline.cleanup_netgate_state()
            payload: dict[str, Any] = {
                "baseline_removed": result.baseline_removed,
                "block_entries_purged": result.block_entries_purged,
                "trusted_entries_purged": result.trusted_entries_purged,
                "errors": list(result.errors),
                "message": format_result_for_display(result),
            }
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.exception("Netgate reset cleanup failed")
            payload = {
                "baseline_removed": False,
                "block_entries_purged": 0,
                "trusted_entries_purged": 0,
                "errors": [str(exc)],
                "message": f"Cleanup failed: {exc}",
            }
        self.reset_cleanup_completed.emit(payload)
