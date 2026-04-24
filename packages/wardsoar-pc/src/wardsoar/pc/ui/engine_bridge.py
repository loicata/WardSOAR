"""Bridge between the WardSOAR engine and the Qt UI.

Runs the EVE JSON watcher in a QThread and routes alerts through
the full 13-step Pipeline (Filter → Dedup → Cache → PreScore →
Collector → Forensics → VT → Analyzer → Confirmer → Responder →
Logger → Cache Store).

Uses ``loop.run_forever()`` with ``create_task()`` so that alert
processing, healthchecks and file polling all run concurrently
without blocking the Qt main thread.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from PySide6.QtCore import QThread, Signal

from wardsoar.core.alert_enrichment import build_filtered_enriched, serialise_decision_record
from wardsoar.core.intel.manager import IntelManager
from wardsoar.core.ip_enrichment import build_ip_enrichment_async
from wardsoar.pc.healthcheck import HealthChecker
from src.main import FilteredResult
from wardsoar.core.models import DecisionRecord
from wardsoar.core.watcher import EveJsonWatcher

if TYPE_CHECKING:
    from src.main import Pipeline

logger = logging.getLogger("ward_soar.ui.engine_bridge")


async def _none_coroutine() -> None:
    """Helper used by :func:`asyncio.gather` branches that resolve to
    ``None`` without actually running any code.

    Keeps the call-site readable when only one of the two IP
    enrichments is needed (dest_ip missing or identical to src).
    """
    return None


class EngineWorker(QThread):
    """Background worker that routes alerts through the full Pipeline.

    The worker owns an asyncio event loop driven by ``run_forever()``.
    All I/O-bound work (pipeline, healthchecks) runs as async tasks so
    they never block each other or starve the Qt event loop of GIL time.

    Signals:
        alert_received: Emitted with alert display data dict.
        metrics_updated: Emitted with metrics dict.
        activity_logged: Emitted with (time, event, details) tuple.
        status_changed: Emitted with (status, mode) tuple.
        health_updated: Emitted with (component, status) tuple.
    """

    alert_received = Signal(dict)
    metrics_updated = Signal(dict)
    activity_logged = Signal(str, str, str)
    status_changed = Signal(str, str)
    health_updated = Signal(str, str)
    # Rollback outcome: emitted after the user clicked "Unblock IP" and the
    # pipeline has executed the full rollback (success or failure).
    # Payload shape: {"ip", "success", "error", "signature_id", ...}.
    rollback_completed = Signal(dict)
    # Netgate audit result (Phase 7a). Emitted once per Run Check click
    # with a serialised :class:`~src.netgate_audit.AuditResult` dict so
    # the UI can be consumed in-process without importing the dataclass.
    netgate_audit_completed = Signal(dict)
    # Tamper-detection signals (Phase 7g).
    # baseline_established payload: {captured_at, host, entries, error?}
    # tamper_check_completed  payload: serialised
    #     :class:`~src.netgate_tamper.TamperResult` dict.
    netgate_baseline_established = Signal(dict)
    netgate_tamper_check_completed = Signal(dict)
    # Custom rules deploy (Phase 7c). Payload: {success, bytes_written,
    # remote_path, rule_count, error?}.
    netgate_custom_rules_deployed = Signal(dict)
    # Emitted when the Responder actually blocks an IP on pfSense (v0.6.4).
    # Payload: {ip, signature, verdict, confidence, mode}. The tray
    # manager listens to it to show a Windows toast — after the
    # v0.6.3 incident where WardSOAR silently blocked its own
    # machine, every block now triggers a visible notification.
    ip_blocked = Signal(dict)
    # Netgate Apply-selected (Phase 7b, v0.7.1). Payload is the list
    # of serialised :class:`~src.netgate_apply.SafeApplyResult` dicts.
    netgate_apply_completed = Signal(list)
    # Manual-review actionable block (v0.17.1). Emitted after the
    # operator set CONFIRMED on an alert via the Manual Review
    # dialog and the Responder processed the block request.
    # Payload: ``{"ip", "success", "reason"}`` \u2014 ``success`` is
    # True when pfSense actually got the block, False when a safety
    # rail (whitelist / CDN allowlist / rate limit) refused it.
    manual_block_completed = Signal(dict)
    # Post-Netgate-reset cleanup (bootstrap track for a factory-reset
    # box). Payload: {"baseline_removed", "block_entries_purged",
    # "trusted_entries_purged", "errors", "message"}.
    netgate_reset_cleanup_completed = Signal(dict)

    def __init__(
        self,
        pipeline: Pipeline,
        eve_path: str,
        mode: str = "file",
        ward_mode: str = "monitor",
        healthcheck_cfg: Optional[dict[str, Any]] = None,
        parent: Optional[Any] = None,
    ) -> None:
        super().__init__(parent)
        self._pipeline = pipeline
        self._eve_path = eve_path
        # ``mode`` is the watcher transport (file | ssh). ``ward_mode`` is
        # the Responder policy (monitor | protect | hard_protect) — two
        # different axes that happen to share the word "mode".
        self._mode = mode
        self._ward_mode = ward_mode
        self._running = False
        self._last_position = 0
        self._alert_count = 0
        self._filtered_count = 0
        self._blocked_count = 0
        self._processed_count = 0

        # Async event loop — created in run(), used by create_task()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Alert history file for persistence across restarts
        from src.config import get_data_dir

        self._history_path = get_data_dir() / "logs" / "alerts_history.jsonl"
        self._history_path.parent.mkdir(parents=True, exist_ok=True)

        # v0.11.0 — central intelligence feeds manager. Built at
        # construction so the registries can load their on-disk
        # snapshots eagerly. The periodic refresh is started from
        # :meth:`run` once the event loop is live.
        self._intel_manager = IntelManager(cache_dir=get_data_dir() / "intel_feeds")

        # Initialize healthchecker
        hc_cfg = healthcheck_cfg or {}
        hc_cfg["eve_json_path"] = eve_path
        self._healthchecker = HealthChecker(hc_cfg)
        self._health_interval: int = hc_cfg.get("interval_seconds", 300)

    def run(self) -> None:
        """Thread entry — start the async event loop with run_forever()."""
        self._running = True

        # Ensure TMPDIR points to a writable directory for asyncssh key loading
        import os
        import tempfile

        from src.config import get_data_dir

        app_tmp = get_data_dir() / "tmp"
        app_tmp.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(app_tmp)
        os.environ["TEMP"] = str(app_tmp)
        os.environ["TMP"] = str(app_tmp)
        tempfile.tempdir = str(app_tmp)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Schedule the main monitoring coroutine
        self._loop.create_task(self._main_loop())

        # v0.11.0 — start the intelligence feeds background refresh.
        # The manager triggers a first pass immediately and then
        # walks the registries every 5 minutes, refreshing only
        # those whose cache has exceeded their own interval.
        self._loop.create_task(self._intel_manager.start_background_refresh())

        # Level-2 process attribution buffer. The pipeline built the
        # buffer and wired it into the ForensicAnalyzer; we just have
        # to start its async task once the event loop is live.
        buffer = getattr(self._pipeline, "_conn_buffer", None)
        if buffer is not None:
            self._loop.create_task(buffer.start())

        # Longitudinal alerts-stats store (v0.22). Background flush
        # task persists the in-memory queue to SQLite every 5 s.
        alerts_stats = getattr(self._pipeline, "_alerts_stats", None)
        if alerts_stats is not None:
            self._loop.create_task(alerts_stats.start())
            self._loop.create_task(self._alerts_stats_purge_loop(alerts_stats))

        # run_forever() processes all tasks concurrently
        try:
            self._loop.run_forever()
        finally:
            # Signal the intel manager to stop before cancelling tasks.
            self._intel_manager.stop()
            # Cancel remaining tasks on shutdown
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    def stop(self) -> None:
        """Stop the worker — thread-safe, callable from the main thread."""
        self._running = False
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    async def _alerts_stats_purge_loop(self, store: Any) -> None:
        """Periodic purge of expired occurrences in the alerts stats DB.

        Runs once right after startup (so a stale DB is cleaned on
        relaunch) and then every 24 h. The purge is fully local,
        cheap and idempotent; any error is swallowed so the purge
        loop never takes the worker down.
        """
        import asyncio as _aio

        # Initial purge on startup.
        try:
            store.purge_older_than()
        except Exception:  # noqa: BLE001 — purge must not break the worker
            logger.debug("alerts_stats: initial purge raised", exc_info=True)

        while self._running:
            try:
                await _aio.sleep(24 * 3600)
            except _aio.CancelledError:
                break
            try:
                store.purge_older_than()
            except Exception:  # noqa: BLE001 — periodic purge is best-effort
                logger.debug("alerts_stats: periodic purge raised", exc_info=True)

    def request_netgate_establish_baseline(self) -> None:
        """Capture a fresh tamper baseline on the worker's event loop.

        Thread-safe — called when the operator clicks *Establish /
        Re-bless baseline* in the Netgate tab. Emits
        :attr:`netgate_baseline_established` when done.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_baseline_established.emit({"error": "Engine not running"})
            return

        async def _run() -> None:
            try:
                baseline = await self._pipeline.establish_netgate_baseline()
                payload = {
                    "captured_at": baseline.captured_at,
                    "host": baseline.host,
                    "entries": len(baseline.entries),
                }
            except Exception as exc:  # noqa: BLE001 — surface any failure
                logger.exception("Netgate baseline establishment failed")
                payload = {"error": str(exc)}
            self.netgate_baseline_established.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def request_netgate_tamper_check(self) -> None:
        """Diff the current Netgate state against the stored baseline.

        Emits :attr:`netgate_tamper_check_completed` with a serialised
        :class:`~src.netgate_tamper.TamperResult` dict.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_tamper_check_completed.emit(
                {"error": "Engine not running", "findings": [], "baseline_present": False}
            )
            return

        async def _run() -> None:
            try:
                result = await self._pipeline.check_netgate_tampering()
                payload = result.to_dict()
            except Exception as exc:  # noqa: BLE001 — surface any failure
                logger.exception("Netgate tamper check failed")
                payload = {"error": str(exc), "findings": [], "baseline_present": False}
            self.netgate_tamper_check_completed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def request_netgate_reset_cleanup(self) -> None:
        """Purge WardSOAR state tied to a Netgate that just got reset.

        Synchronous on the pipeline side (pure filesystem ops), but the
        invocation is still marshalled through the worker's event loop
        so the UI thread never touches non-Qt state directly. Emits
        :attr:`netgate_reset_cleanup_completed` with a dict of counters
        plus a pre-formatted ``message`` the UI can display verbatim.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_reset_cleanup_completed.emit(
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

        def _run() -> None:
            from src.netgate_reset import format_result_for_display

            try:
                result = self._pipeline.cleanup_netgate_state()
                payload = {
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
            self.netgate_reset_cleanup_completed.emit(payload)

        self._loop.call_soon_threadsafe(_run)

    def request_netgate_apply(self, fix_ids: list[str]) -> None:
        """Run safe-apply for the checked audit findings.

        Emits :attr:`netgate_apply_completed` when the whole list is
        processed, with one :class:`SafeApplyResult` dict per fix id
        attempted. Stops on first hard failure with no rollback — the
        result list then ends early.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_apply_completed.emit(
                [
                    {"success": False, "error": "Engine not running", "fix_id": fid}
                    for fid in fix_ids
                ]
            )
            return

        async def _run() -> None:
            try:
                outcomes = await self._pipeline.apply_netgate_fixes(fix_ids)
                payload = [r.to_dict() for r in outcomes]
            except Exception as exc:  # noqa: BLE001 -- surface any failure
                logger.exception("Netgate safe-apply failed")
                payload = [{"success": False, "error": str(exc), "fix_id": "?"}]
            self.netgate_apply_completed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def netgate_applicable_fix_ids(self) -> set[str]:
        """Synchronous helper the UI calls to decide which checkboxes are active."""
        from src.netgate_apply import applicable_fix_ids

        return applicable_fix_ids()

    def request_deploy_custom_rules(self) -> None:
        """Push the WardSOAR custom Suricata rules to the Netgate.

        Emits :attr:`netgate_custom_rules_deployed` on completion.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_custom_rules_deployed.emit(
                {"success": False, "error": "Engine not running", "rule_count": 0}
            )
            return

        async def _run() -> None:
            try:
                result = await self._pipeline.deploy_custom_rules()
                bundle = self._pipeline.preview_custom_rules()
                payload = {
                    "success": result.success,
                    "bytes_written": result.bytes_written,
                    "remote_path": result.remote_path,
                    "rule_count": len(bundle.rules),
                    "error": result.error,
                }
            except Exception as exc:  # noqa: BLE001 — surface any failure
                logger.exception("Deploy custom rules failed")
                payload = {"success": False, "error": str(exc), "rule_count": 0}
            self.netgate_custom_rules_deployed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def preview_custom_rules(self) -> "Any":
        """Build the rules bundle *synchronously* (pure in-process).

        The UI calls this from the GUI thread to show the preview
        dialog before the operator decides to deploy. Since it does
        not touch SSH it is safe to run outside the worker loop.
        """
        return self._pipeline.preview_custom_rules()

    def request_netgate_audit(self) -> None:
        """Kick off a Netgate audit on the worker's event loop.

        Thread-safe — called from the Qt main thread when the operator
        clicks "Run Check" in the Netgate tab. The audit runs
        asynchronously (it issues ~10 SSH commands, ~5–15 seconds on
        a healthy Netgate) and the result is emitted as a serialised
        dict on :attr:`netgate_audit_completed`.
        """
        if self._loop is None or not self._loop.is_running():
            self.netgate_audit_completed.emit(
                {"error": "Engine not running", "findings": [], "ssh_reachable": False}
            )
            return

        async def _run() -> None:
            try:
                result = await self._pipeline.audit_netgate()
                payload = result.to_dict()
            except Exception as exc:  # noqa: BLE001 — surface any failure
                logger.exception("Netgate audit request failed")
                payload = {"error": str(exc), "findings": [], "ssh_reachable": False}
            self.netgate_audit_completed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def request_rollback(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Queue a rollback on the worker's event loop.

        Thread-safe: intended to be called from the Qt main thread in
        response to an "Unblock IP" button click. Schedules the async
        rollback and emits ``rollback_completed`` when finished.
        """
        if self._loop is None or not self._loop.is_running():
            # Worker not started — nothing to do; surface a synthetic failure.
            self.rollback_completed.emit(
                {
                    "ip": ip,
                    "success": False,
                    "error": "Engine not running",
                }
            )
            return

        async def _run() -> None:
            try:
                result = await self._pipeline.rollback_block(
                    ip=ip,
                    signature_id=signature_id,
                    reason=reason,
                )
                from dataclasses import asdict

                payload = asdict(result)
            except Exception as exc:  # noqa: BLE001 — surface any failure
                logger.exception("Rollback request failed for %s", ip)
                payload = {"ip": ip, "success": False, "error": str(exc)}
            self.rollback_completed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

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

        Thread-safe \u2014 called from the Qt main thread.
        """
        if self._loop is None or not self._loop.is_running():
            self.manual_block_completed.emit(
                {"ip": ip, "success": False, "reason": "Engine not running"}
            )
            return

        async def _run() -> None:
            try:
                from src.models import ThreatAnalysis, ThreatVerdict

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
                    reason = "Block installed on pfSense."
                else:
                    refused = next(
                        (a.error_message for a in (actions or []) if a.error_message),
                        "A safety rule refused the block (whitelist / CDN / rate limit).",
                    )
                    reason = refused
                payload = {"ip": ip, "success": blocked, "reason": reason}
            except Exception as exc:  # noqa: BLE001 \u2014 defensive
                logger.exception("Manual block request failed for %s", ip)
                payload = {"ip": ip, "success": False, "reason": str(exc)}
            self.manual_block_completed.emit(payload)

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(_run()))  # type: ignore[union-attr]

    def _persist_alert(self, alert_data: dict[str, Any]) -> None:
        """Append an alert to the history file for persistence across restarts."""
        try:
            # Add ISO timestamp for proper time-based filtering on reload
            entry = dict(alert_data)
            entry["_ts"] = datetime.now(timezone.utc).isoformat()
            with open(self._history_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            logger.debug("Failed to persist alert to history", exc_info=True)

    @property
    def history_path(self) -> Path:
        """Path of the active ``alerts_history.jsonl`` file.

        Exposed so :class:`WardApp` can run :func:`rotate_if_needed`
        at startup without reaching into a private attribute.
        """
        return self._history_path

    def load_alert_history(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Load persisted alerts from the active history file.

        v0.22.1 — the active file is bounded to the current calendar
        month by :func:`rotate_if_needed`. A busy month can still
        reach thousands of entries, so the UI pages through it:
        200 at startup, then 200 more on each "Load older" click.

        Args:
            limit: Cap on returned entries. ``None`` = no cap
                (load everything). The UI uses 200 on startup.
            offset: Skip the last ``offset`` entries before applying
                ``limit``. Lets the UI page backward through the
                month without re-parsing the whole file each click.

        Returns:
            List of alert data dicts, most recent last. Empty on
            any read / parse error (fail-safe).
        """
        alerts: list[dict[str, Any]] = []
        if not self._history_path.exists():
            return alerts
        try:
            with open(self._history_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            logger.warning("Failed to load alert history", exc_info=True)
            return alerts

        if offset:
            alerts = alerts[: len(alerts) - offset] if offset < len(alerts) else []
        if limit is not None and limit >= 0 and limit < len(alerts):
            alerts = alerts[-limit:]
        return alerts

    def load_history_page(
        self, older_than_count: int, page_size: int = 200
    ) -> list[dict[str, Any]]:
        """Paginate older entries of the current month on operator request.

        Args:
            older_than_count: Number of entries the UI already has
                displayed (offset from the end of the active file).
            page_size: How many entries to return.

        Returns:
            The next ``page_size`` entries older than the current
            view. Empty when the active file (current month) is
            exhausted — the UI then falls back to the Archives
            menu for past months.
        """
        return self.load_alert_history(limit=page_size, offset=older_than_count)

    def list_history_archives(self) -> list[dict[str, Any]]:
        """Return the available monthly archives, newest first.

        Used by the UI "Archives" menu. Each entry carries the
        archive path, the ``YYYY-MM`` month and the compressed
        size so the dropdown can render "March 2026 — 42 kB".
        """
        from src.history_rotator import list_archives

        infos = list_archives(self._history_path)
        # v0.22.1 — archives are now monthly; expose the field as
        # ``month`` (``YYYY-MM``) so the UI label can read "March 2026"
        # rather than try to parse a dashed date.
        return [
            {"path": info.path, "month": info.month_iso, "size_bytes": info.size_bytes}
            for info in infos
        ]

    def load_history_from_archive(
        self, archive_path: str, limit: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Read a gzipped archive and return its alerts.

        Args:
            archive_path: Path as returned by
                :meth:`list_history_archives`.
            limit: Cap on returned entries. ``None`` = the whole archive.

        Returns:
            List of alert dicts. Malformed archive → empty list.
        """
        from pathlib import Path as _Path

        from src.history_rotator import load_archive

        raw_lines = load_archive(_Path(archive_path), limit=limit)
        alerts: list[dict[str, Any]] = []
        for line in raw_lines:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return alerts

    def on_ssh_line(self, line: str) -> None:
        """Process a line received from the SSH streamer (cross-thread safe)."""
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._process_line, line)

    # ----------------------------------------------------------------
    # Main async loop
    # ----------------------------------------------------------------

    async def _main_loop(self) -> None:
        """Main monitoring coroutine — file polling + periodic healthchecks."""
        mode_label = {
            "monitor": "Monitor",
            "protect": "Protect",
            "hard_protect": "Hard Protect",
        }.get(self._ward_mode, "Monitor")
        mode_info = f"Pipeline: 13-step — Mode: {mode_label}"

        # Initial healthcheck
        await self._run_healthchecks_async()

        if self._mode == "ssh":
            self.status_changed.emit("Operational", mode_label)
            self.activity_logged.emit(
                datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "System",
                f"Engine started (SSH mode) — {mode_info}",
            )
            # SSH mode: just run periodic healthchecks
            while self._running:
                await asyncio.sleep(1)
                await self._maybe_run_healthchecks_async()
            return

        # File mode: poll local EVE JSON file
        eve_file = Path(self._eve_path)

        if not eve_file.exists():
            logger.warning("EVE JSON file not found: %s", self._eve_path)
            self.activity_logged.emit(
                datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "Warning",
                f"EVE file not found: {self._eve_path}",
            )
            return

        self._last_position = eve_file.stat().st_size
        self.status_changed.emit("Operational", mode_label)
        self.activity_logged.emit(
            datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "System",
            f"Watcher started (file mode) — {mode_info}",
        )

        while self._running:
            self._process_new_lines(eve_file)
            await self._maybe_run_healthchecks_async()
            await asyncio.sleep(2)

    # ----------------------------------------------------------------
    # Healthchecks (async)
    # ----------------------------------------------------------------

    async def _maybe_run_healthchecks_async(self) -> None:
        """Run healthchecks if enough time has passed since last run."""
        loop = asyncio.get_running_loop()
        now = loop.time()
        if not hasattr(self, "_last_health_time"):
            self._last_health_time: float = 0.0
        if now - self._last_health_time >= self._health_interval:
            await self._run_healthchecks_async()

    async def _run_healthchecks_async(self) -> None:
        """Run all healthchecks concurrently and emit results."""
        loop = asyncio.get_running_loop()
        self._last_health_time = loop.time()
        try:
            results = await self._healthchecker.run_all_checks()
            for result in results:
                self.health_updated.emit(result.component, result.status.value)

            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            overall = self._healthchecker.get_overall_status().value
            # v0.8.6 B2: only surface in the Activity tab when
            # something is off. A healthy check every 5 minutes is
            # noise — if the operator wants to know the last check
            # ran, the Dashboard "Health" widget already shows it.
            # Degraded / failed statuses still raise an Activity
            # entry so any sanity regression is visible.
            if overall.lower() != "healthy":
                self.activity_logged.emit(ts, "Health", f"Check complete — {overall}")
        except Exception as exc:
            logger.warning("Healthcheck failed: %s", exc)

    # ----------------------------------------------------------------
    # Alert processing
    # ----------------------------------------------------------------

    def _process_new_lines(self, eve_file: Path) -> None:
        """Read and process new lines from the EVE JSON file."""
        try:
            current_size = eve_file.stat().st_size
            if current_size <= self._last_position:
                return

            with open(eve_file, "r", encoding="utf-8") as f:
                f.seek(self._last_position)
                new_data = f.read()
                self._last_position = f.tell()
        except OSError:
            return

        for line in new_data.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            self._process_line(stripped)

    def _process_line(self, line: str) -> None:
        """Parse a single EVE JSON line and schedule pipeline processing."""
        try:
            raw_event: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            return

        event_type = raw_event.get("event_type", "")

        # Log network event types as activity.
        #
        # v0.8.6 — ``alert`` is deliberately excluded here. The
        # previous behaviour emitted a generic "IDS Alert: src -> dest"
        # row *before* the pipeline decided what to do with the
        # alert, and then a second row (FILTERED / PIPELINE) a few
        # milliseconds later once the verdict was in. With multiple
        # alerts arriving in the same second, the initial row carried
        # only ``src -> dest`` — no SID, no signature — so the
        # operator could not tell which subsequent FILTERED /
        # PIPELINE line matched which IDS Alert. We now emit a single
        # row per alert, from the pipeline completion path, with
        # both endpoints AND the signature in one place. See the
        # FILTERED / PIPELINE emissions below for the new format.
        if event_type in ("dns", "tls", "ssh", "http"):
            src = raw_event.get("src_ip", "?")
            dest = raw_event.get("dest_ip", "?")
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.activity_logged.emit(ts, event_type.upper(), f"{src} -> {dest}")

        # Only process alert events
        if event_type != "alert":
            return

        alert = EveJsonWatcher.parse_eve_alert(raw_event)
        if alert is None:
            alert_sub = raw_event.get("alert")
            sub_keys = list(alert_sub.keys()) if isinstance(alert_sub, dict) else "missing"
            logger.warning(
                "parse_eve_alert returned None — keys: %s, alert: %s",
                list(raw_event.keys()),
                sub_keys,
            )
            return

        self._alert_count += 1
        logger.info(
            "Alert parsed: %s -> %s sig=%s", alert.src_ip, alert.dest_ip, alert.alert_signature_id
        )

        # Schedule as an async task — non-blocking!
        if self._loop is None:
            raise RuntimeError("Event loop not initialized — call start() first")
        self._loop.create_task(self._process_alert_async(alert))

    async def _build_ip_enrichment_for(self, ip: str) -> Any:
        """Wrap :func:`src.ip_enrichment.build_ip_enrichment_async` with the
        pipeline's existing registries.

        All dependencies are pulled out of the ``Pipeline`` instance
        we already hold a reference to. v0.12.0: the enrichment is
        now async because HTTP reputation clients (VirusTotal,
        AbuseIPDB, GreyNoise, OTX) need an asyncio context. Failures
        are caught so the Alert Detail enrichment never crashes the
        hot path \u2014 we return ``None`` and the UI renders a minimal
        Identity block from the raw alert fields.
        """
        pipeline = self._pipeline

        # Build a thin ``lookup`` adapter over the ASN enricher's
        # SQLite cache. The enricher exposes an async ``lookup`` that
        # triggers an HTTP call on miss — we want cache-only here so
        # the enrichment stays synchronous and cheap.
        asn_cache_lookup: Any = None
        try:
            enr = getattr(pipeline, "_asn_enricher", None)
            if enr is not None and hasattr(enr, "_cache_lookup"):
                asn_cache_lookup = enr._cache_lookup  # noqa: SLF001
            elif enr is not None and hasattr(enr, "_cache"):
                asn_cache_lookup = enr._cache.get  # noqa: SLF001
        except Exception:  # noqa: BLE001
            asn_cache_lookup = None

        try:
            return await build_ip_enrichment_async(
                ip,
                asn_cache_lookup=asn_cache_lookup,
                cdn_allowlist=getattr(pipeline, "_cdn_allowlist", None),
                suspect_asn_registry=getattr(pipeline, "_suspect_asns", None),
                bad_actor_registry=getattr(pipeline, "_known_bad_actors", None),
                tor_exit_registry=getattr(pipeline, "_tor_exit_fetcher", None),
                # v0.11.0 — feed the IntelManager built during the
                # worker's construction. Its registries are already
                # populated from their on-disk snapshots, so even a
                # newly-received alert benefits from the last known
                # good data before the first background refresh runs.
                intel_manager=self._intel_manager,
                history_path=self._history_path,
                do_rdns=True,
            )
        except Exception:  # noqa: BLE001 — the enrichment is best-effort
            logger.debug(
                "IP enrichment for %s failed, falling back to minimal detail",
                ip,
                exc_info=True,
            )
            return None

    async def _process_alert_async(self, alert: Any) -> None:
        """Process a single alert through the pipeline (async task)."""
        logger.info("Pipeline starting for %s -> %s", alert.src_ip, alert.dest_ip)
        try:
            result = await self._pipeline.process_alert(alert)
            logger.info(
                "Pipeline completed for %s — result type: %s", alert.src_ip, type(result).__name__
            )
        except PermissionError as exc:
            logger.warning("Pipeline permission error for %s: %s", alert.src_ip, exc)
            return
        except Exception as exc:
            logger.error("Pipeline error for %s: %s", alert.src_ip, exc, exc_info=True)
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.activity_logged.emit(ts, "ERROR", f"Pipeline failed: {exc}")
            return

        if isinstance(result, FilteredResult):
            self._filtered_count += 1

            # v0.12.0 \u2014 enrichment is now async (HTTP reputation
            # clients). v0.15.0 \u2014 enrich BOTH src and dest so the
            # Alert Detail view can surface "who's on both ends of
            # the flow". Run both in parallel to keep wall time low.
            (
                filtered_ip_enrichment,
                filtered_dest_ip_enrichment,
            ) = await asyncio.gather(
                self._build_ip_enrichment_for(alert.src_ip),
                (
                    self._build_ip_enrichment_for(alert.dest_ip)
                    if alert.dest_ip
                    else _none_coroutine()
                ),
            )

            # Emit filtered alert to Alerts view
            filtered_data = {
                "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": alert.src_ip,
                "signature": alert.alert_signature,
                "verdict": "filtered",
                "score": "—",
                "severity": str(alert.alert_severity.value),
                "src_port": str(alert.src_port),
                "dest_ip": alert.dest_ip,
                "dest_port": str(alert.dest_port),
                "proto": alert.proto,
                "category": alert.alert_category,
                "signature_id": str(alert.alert_signature_id),
                "confidence": "—",
                "reasoning": result.reason,
                "actions": [],
                "pipeline_ms": "0",
                # v0.9.0 — the full enriched payload the detail
                # view reads. For filtered alerts this is minimal
                # (no DecisionRecord, no enrichment) but it still
                # ships the raw Suricata fields + filter reason +
                # inferred pipeline trace so the detail screen
                # can render N/A sections cleanly.
                "_full": build_filtered_enriched(
                    alert,
                    result.reason,
                    # v0.9.5 — surface the YAML entry (signature_name,
                    # operator reason, added/review dates) to the detail
                    # view so its Filter specific-details paragraph can
                    # quote the operator verbatim. SID-match only for
                    # now; category / pair metadata are not yet surfaced.
                    filter_meta=self._pipeline._filter.get_sid_metadata(alert.alert_signature_id),
                    # v0.10.0 — IP ownership & reputation snapshot.
                    # Best-effort: if the enrichment fails, the UI
                    # still renders a minimal Identity block.
                    ip_enrichment=filtered_ip_enrichment,
                    dest_ip_enrichment=filtered_dest_ip_enrichment,
                ),
            }
            self.alert_received.emit(filtered_data)
            self._persist_alert(filtered_data)
            # v0.8.6 B2: per-alert activity rows removed from the
            # System Activity tab — the alert is already fully
            # visible in the Alerts tab (with a detail panel).
            # Activity is now a pure system-event journal.
            return

        if not isinstance(result, DecisionRecord):
            raise TypeError(f"Expected DecisionRecord, got {type(result).__name__}")
        record = result
        self._processed_count += 1

        # Extract verdict info
        verdict = "inconclusive"
        confidence = "—"
        reasoning = ""
        if record.analysis:
            verdict = record.analysis.verdict.value
            confidence = f"{record.analysis.confidence:.0%}"
            reasoning = record.analysis.reasoning

        if record.actions_taken:
            self._blocked_count += 1

        # v0.12.0 \u2014 enrichment is now async. v0.15.0 \u2014 enrich BOTH
        # src and dest. Run in parallel to keep wall time bounded by
        # the slowest response.
        (
            analyzed_ip_enrichment,
            analyzed_dest_ip_enrichment,
        ) = await asyncio.gather(
            self._build_ip_enrichment_for(record.alert.src_ip),
            (
                self._build_ip_enrichment_for(record.alert.dest_ip)
                if record.alert.dest_ip
                else _none_coroutine()
            ),
        )

        # Emit alert for UI
        alert_data = {
            "time": record.alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": record.alert.src_ip,
            "signature": record.alert.alert_signature,
            "verdict": verdict,
            "score": str(record.alert.alert_severity.value * 20),
            "severity": str(record.alert.alert_severity.value),
            "src_port": str(record.alert.src_port),
            "dest_ip": record.alert.dest_ip,
            "dest_port": str(record.alert.dest_port),
            "proto": record.alert.proto,
            "category": record.alert.alert_category,
            "signature_id": str(record.alert.alert_signature_id),
            "confidence": confidence,
            "reasoning": reasoning,
            "actions": [a.action_type.value for a in record.actions_taken],
            "pipeline_ms": str(record.pipeline_duration_ms),
            # v0.9.0 — full DecisionRecord serialised for the detail
            # view. The alerts-list render path ignores this key
            # (backward compat), and ``load_alert_history`` just
            # passes it through.
            "_full": serialise_decision_record(
                record,
                ip_enrichment=analyzed_ip_enrichment,
                dest_ip_enrichment=analyzed_dest_ip_enrichment,
            ),
        }
        self.alert_received.emit(alert_data)
        self._persist_alert(alert_data)

        # v0.6.4 — surface every successful IP block as a distinct
        # signal so the tray manager can pop a toast. Without this the
        # operator had no way to learn WardSOAR had just taken their
        # own machine offline.
        for action in record.actions_taken:
            if action.action_type.value == "ip_block" and action.success and action.target_ip:
                self.ip_blocked.emit(
                    {
                        "ip": action.target_ip,
                        "signature": record.alert.alert_signature,
                        "verdict": verdict,
                        "confidence": confidence,
                    }
                )
                break

        # Update metrics
        self.metrics_updated.emit(
            {
                "alerts_today": self._alert_count,
                "blocked_today": self._blocked_count,
                "fp_rate": (
                    self._filtered_count / self._alert_count if self._alert_count > 0 else 0.0
                ),
                "queue_depth": 0,
            }
        )

        # v0.8.6 B2: the per-alert PIPELINE row used to emit here is
        # gone. The Alerts tab carries the full record (with detail
        # panel for drill-down). Activity stays system-level only.
