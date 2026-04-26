"""EVE pipeline ingestion + processing + healthcheck loop.

Owns the cohesive concern that drives every alert from raw EVE
JSON line to a UI-ready ``alert_received`` emission:

* **Lifecycle** — owns the asyncio event loop. The QThread entry
  point in :class:`~wardsoar.pc.ui.engine_bridge.EngineWorker`
  delegates to :meth:`bootstrap_in_thread`; thread-safe stop is
  exposed via :meth:`request_stop`.
* **Ingestion** — file polling (file mode) or cross-thread
  callback from the SSH streamer (ssh mode) via
  :meth:`on_ssh_line`. Both end up scheduling
  :meth:`_process_line` on the worker loop.
* **Processing** — :meth:`_process_alert_async` runs the full
  pipeline, builds the IP enrichment in parallel for both
  endpoints, serialises the verdict, and emits the right Qt
  signals.
* **Healthchecks** — periodic background task that wraps
  :class:`~wardsoar.pc.healthcheck.HealthChecker`.
* **Background tasks** — IntelManager refresh, level-2 process
  attribution buffer, alerts_stats flush + purge.

Extracted from ``EngineWorker`` (V3.5, v0.22.16). Last of the
four planned extractions: ``EngineWorker`` becomes a thin QThread
shell that creates every controller and forwards their signals
back to the worker for backward compatibility with ``app.py`` /
the views.

Threading model
---------------
The controller is a ``QObject``, NOT a ``QThread``. The worker's
``QThread.run()`` is the only place we cross into the background
thread; once inside, we hand control to
:meth:`bootstrap_in_thread`, which:

1. Creates the asyncio event loop.
2. Schedules :meth:`_main_loop` and the supporting background
   tasks (intel manager refresh, conn buffer, alerts_stats).
3. Calls ``loop.run_forever()`` so the loop drives every async
   operation until :meth:`request_stop` is called from the Qt
   main thread.

Sibling controllers (``ManualActionController``,
``NetgateController``) borrow this loop through the ``loop``
property — they hold a ``loop_provider`` callback that returns
``self.loop`` at call time, which is ``None`` before the worker
starts and the live loop afterwards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QObject, Signal

from wardsoar.core.alert_enrichment import build_filtered_enriched, serialise_decision_record
from wardsoar.core.config import get_data_dir
from wardsoar.core.ip_enrichment import build_ip_enrichment_async
from wardsoar.core.models import DecisionRecord
from wardsoar.core.watcher import EveJsonWatcher
from wardsoar.pc.main import FilteredResult
from wardsoar.pc.ui.controllers.history_controller import HistoryController

logger = logging.getLogger("ward_soar.ui.controllers.pipeline")


async def _none_coroutine() -> None:
    """Placeholder coroutine for ``asyncio.gather`` branches that
    only need one of two IP enrichments (dest_ip missing or equal
    to src). Returns ``None`` without doing any work.
    """
    return None


class PipelineController(QObject):
    """Drive the full alert pipeline from ingestion to UI emission.

    Args:
        pipeline: The :class:`~wardsoar.pc.main.Pipeline` instance.
            Typed as ``Any`` to avoid an import cycle.
        eve_path: Path to the local EVE JSON file (only used in
            file mode; ignored in ssh mode but still passed to
            ``HealthChecker``).
        mode: Watcher transport — ``"file"`` polls the local
            ``eve.json`` file, ``"ssh"`` consumes lines pushed
            via :meth:`on_ssh_line`.
        ward_mode: Responder policy — ``"monitor"``, ``"protect"``
            or ``"hard_protect"``. Drives a label only; the actual
            policy lives inside the Responder.
        history_controller: Used to persist every emitted alert.
        intel_manager: Started in :meth:`bootstrap_in_thread` and
            stopped in the cleanup ``finally`` block. Also passed
            to the per-alert IP enrichment so alerts benefit from
            cached intel without waiting for the next refresh.
        healthchecker: Wrapped by the periodic healthcheck loop.
        health_interval_s: Seconds between two healthcheck runs.
    """

    #: Emitted with the alert display data dict for the Alerts view.
    alert_received = Signal(dict)

    #: Emitted with the rolling metrics dict for the Dashboard.
    metrics_updated = Signal(dict)

    #: Emitted with ``(time, event, details)`` for the System
    #: Activity tab.
    activity_logged = Signal(str, str, str)

    #: Emitted with ``(status, mode)`` for the status bar / tray.
    status_changed = Signal(str, str)

    #: Emitted with ``(component, status_value)`` per healthcheck
    #: result.
    health_updated = Signal(str, str)

    #: Emitted when the Responder actually blocks an IP. Payload:
    #: ``{"ip", "signature", "verdict", "confidence"}``. The tray
    #: manager listens to this to pop a Windows toast — added
    #: after the v0.6.3 incident where WardSOAR silently blocked
    #: its own machine.
    ip_blocked = Signal(dict)

    def __init__(
        self,
        pipeline: Any,
        eve_path: str,
        mode: str,
        ward_mode: str,
        history_controller: HistoryController,
        intel_manager: Any,
        healthchecker: Any,
        health_interval_s: int,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._pipeline = pipeline
        self._eve_path = eve_path
        self._mode = mode
        self._ward_mode = ward_mode
        self._history_controller = history_controller
        self._intel_manager = intel_manager
        self._healthchecker = healthchecker
        self._health_interval = health_interval_s

        # Lifecycle state.
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Counters (reset to zero each time the worker is rebuilt).
        self._last_position = 0
        self._alert_count = 0
        self._filtered_count = 0
        self._blocked_count = 0
        self._processed_count = 0
        self._last_health_time: float = 0.0

    # ------------------------------------------------------------------
    # Lifecycle — called by the QThread shell from EngineWorker
    # ------------------------------------------------------------------

    @property
    def loop(self) -> Optional[asyncio.AbstractEventLoop]:
        """Active event loop, or ``None`` before :meth:`bootstrap_in_thread`.

        Sibling controllers (``ManualActionController``,
        ``NetgateController``) read this through their
        ``loop_provider`` callback so they always see the current
        state — never a cached reference that would survive a
        worker restart.
        """
        return self._loop

    def bootstrap_in_thread(self) -> None:
        """Run the worker loop. Blocks until :meth:`request_stop`.

        Must be called from inside ``EngineWorker.QThread.run()`` —
        this is where we cross into the background thread. The
        method:

        1. Pins ``TMPDIR`` to a writable per-app directory so
           asyncssh's key loader does not fail on locked-down
           Windows installs.
        2. Creates a fresh asyncio loop and schedules every
           background task the pipeline needs.
        3. Calls ``loop.run_forever()`` until the operator stops
           the worker.
        4. Cancels remaining tasks cleanly on shutdown.
        """
        self._running = True

        # Ensure TMPDIR points to a writable directory for
        # asyncssh key loading. On locked-down Windows installs the
        # default %TEMP% can be read-only for the service account,
        # which made asyncssh fall back to writing in the package
        # directory — surfaced in v0.6 as random "permission
        # denied" failures during the SSH handshake.
        app_tmp = get_data_dir() / "tmp"
        app_tmp.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(app_tmp)
        os.environ["TEMP"] = str(app_tmp)
        os.environ["TMP"] = str(app_tmp)
        tempfile.tempdir = str(app_tmp)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Main monitoring coroutine.
        self._loop.create_task(self._main_loop())

        # v0.11.0 — start the intelligence feeds background
        # refresh. The manager triggers a first pass immediately
        # and then walks the registries every 5 minutes,
        # refreshing only those whose cache has exceeded their own
        # interval.
        self._loop.create_task(self._intel_manager.start_background_refresh())

        # Level-2 process attribution buffer. The pipeline built
        # the buffer and wired it into the ForensicAnalyzer; we
        # just have to start its async task once the event loop is
        # live.
        buffer = getattr(self._pipeline, "_conn_buffer", None)
        if buffer is not None:
            self._loop.create_task(buffer.start())

        # Longitudinal alerts-stats store (v0.22). Background
        # flush task persists the in-memory queue to SQLite every
        # 5 s.
        alerts_stats = getattr(self._pipeline, "_alerts_stats", None)
        if alerts_stats is not None:
            self._loop.create_task(alerts_stats.start())
            self._loop.create_task(self._alerts_stats_purge_loop(alerts_stats))

        # run_forever() processes all tasks concurrently.
        try:
            self._loop.run_forever()
        finally:
            # Signal the intel manager to stop before cancelling
            # tasks so its background refresh exits cleanly.
            self._intel_manager.stop()
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    def request_stop(self) -> None:
        """Stop the controller — thread-safe, callable from the main thread.

        Sets the ``_running`` flag so the file-poll / healthcheck
        loops break out, then asks the loop to stop. The
        ``finally`` block in :meth:`bootstrap_in_thread` then
        cancels every outstanding task.
        """
        self._running = False
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    def on_alert_event(self, event: dict[str, Any]) -> None:
        """Receive a parsed EVE event from a :class:`RemoteAgent` stream.

        Called from the :class:`AgentStreamConsumer` thread (Phase 3b.5
        replacement for the legacy :meth:`on_ssh_line` raw-line entry).
        The agent has already parsed the JSON line into a dict, so we
        skip the JSON-decode pass and dispatch directly. Cross-thread
        marshalling to the controller's asyncio loop keeps the event
        on the same context as :meth:`_process_alert_async`.
        """
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._dispatch_event, event)

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def _alerts_stats_purge_loop(self, store: Any) -> None:
        """Periodic purge of expired occurrences in the alerts stats DB.

        Runs once right after startup (so a stale DB is cleaned on
        relaunch) and then every 24 h. The purge is fully local,
        cheap and idempotent; any error is swallowed so the purge
        loop never takes the worker down.
        """
        # Initial purge on startup.
        try:
            store.purge_older_than()
        except Exception:  # noqa: BLE001 — purge must not break the worker
            logger.debug("alerts_stats: initial purge raised", exc_info=True)

        while self._running:
            try:
                await asyncio.sleep(24 * 3600)
            except asyncio.CancelledError:
                break
            try:
                store.purge_older_than()
            except Exception:  # noqa: BLE001 — periodic purge is best-effort
                logger.debug("alerts_stats: periodic purge raised", exc_info=True)

    async def _main_loop(self) -> None:
        """Main monitoring coroutine — file polling + periodic healthchecks."""
        mode_label = {
            "monitor": "Monitor",
            "protect": "Protect",
            "hard_protect": "Hard Protect",
        }.get(self._ward_mode, "Monitor")
        mode_info = f"Pipeline: 13-step — Mode: {mode_label}"

        # Initial healthcheck.
        await self._run_healthchecks_async()

        if self._mode == "ssh":
            self.status_changed.emit("Operational", mode_label)
            self.activity_logged.emit(
                datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "System",
                f"Engine started (SSH mode) — {mode_info}",
            )
            # SSH mode: just run periodic healthchecks.
            while self._running:
                await asyncio.sleep(1)
                await self._maybe_run_healthchecks_async()
            return

        # File mode: poll local EVE JSON file.
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

    # ------------------------------------------------------------------
    # Healthchecks
    # ------------------------------------------------------------------

    async def _maybe_run_healthchecks_async(self) -> None:
        """Run healthchecks if enough time has passed since last run."""
        loop = asyncio.get_running_loop()
        now = loop.time()
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
            # something is off. A healthy check every 5 minutes
            # is noise — if the operator wants to know the last
            # check ran, the Dashboard "Health" widget already
            # shows it. Degraded / failed statuses still raise
            # an Activity entry so any sanity regression is
            # visible.
            if overall.lower() != "healthy":
                self.activity_logged.emit(ts, "Health", f"Check complete — {overall}")
        except Exception as exc:  # noqa: BLE001 — healthcheck must not crash
            logger.warning("Healthcheck failed: %s", exc)

    # ------------------------------------------------------------------
    # Alert processing
    # ------------------------------------------------------------------

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
        """Parse a single EVE JSON line and schedule pipeline processing.

        Used by the file-watcher path (:meth:`_process_new_lines`) which
        reads raw bytes off disk. The SSH path now goes through
        :meth:`on_alert_event` with an already-parsed dict.
        """
        try:
            raw_event: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            return
        self._dispatch_event(raw_event)

    def _dispatch_event(self, raw_event: dict[str, Any]) -> None:
        """Activity-log network events; route alerts to the async pipeline.

        Shared dispatch point used by both the file-poll path
        (:meth:`_process_line` after JSON parse) and the agent-stream
        path (:meth:`on_alert_event`, already parsed by the agent).
        """
        event_type = raw_event.get("event_type", "")

        # Log network event types as activity.
        #
        # v0.8.6 — ``alert`` is deliberately excluded here. The
        # previous behaviour emitted a generic "IDS Alert: src ->
        # dest" row *before* the pipeline decided what to do with
        # the alert, and then a second row (FILTERED / PIPELINE) a
        # few milliseconds later once the verdict was in. With
        # multiple alerts arriving in the same second, the initial
        # row carried only ``src -> dest`` — no SID, no signature
        # — so the operator could not tell which subsequent
        # FILTERED / PIPELINE line matched which IDS Alert. We now
        # emit a single row per alert, from the pipeline
        # completion path, with both endpoints AND the signature
        # in one place. See the FILTERED / PIPELINE emissions
        # below for the new format.
        if event_type in ("dns", "tls", "ssh", "http"):
            src = raw_event.get("src_ip", "?")
            dest = raw_event.get("dest_ip", "?")
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.activity_logged.emit(ts, event_type.upper(), f"{src} -> {dest}")

        # Only process alert events.
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
            "Alert parsed: %s -> %s sig=%s",
            alert.src_ip,
            alert.dest_ip,
            alert.alert_signature_id,
        )

        # Schedule as an async task — non-blocking!
        if self._loop is None:
            raise RuntimeError("Event loop not initialized — call bootstrap_in_thread() first")
        self._loop.create_task(self._process_alert_async(alert))

    async def _build_ip_enrichment_for(self, ip: str) -> Any:
        """Wrap :func:`build_ip_enrichment_async` with the pipeline's registries.

        All dependencies are pulled out of the ``Pipeline``
        instance we hold a reference to. v0.12.0: the enrichment
        is async because HTTP reputation clients (VirusTotal,
        AbuseIPDB, GreyNoise, OTX) need an asyncio context.
        Failures are caught so the Alert Detail enrichment never
        crashes the hot path — we return ``None`` and the UI
        renders a minimal Identity block from the raw alert
        fields.
        """
        pipeline = self._pipeline

        # Build a thin ``lookup`` adapter over the ASN enricher's
        # SQLite cache. The enricher exposes an async ``lookup``
        # that triggers an HTTP call on miss — we want cache-only
        # here so the enrichment stays synchronous and cheap.
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
                # v0.11.0 — feed the IntelManager built during
                # the worker's construction. Its registries are
                # already populated from their on-disk snapshots,
                # so even a newly-received alert benefits from the
                # last known good data before the first background
                # refresh runs.
                intel_manager=self._intel_manager,
                history_path=self._history_controller.history_path,
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
                "Pipeline completed for %s — result type: %s",
                alert.src_ip,
                type(result).__name__,
            )
        except PermissionError as exc:
            logger.warning("Pipeline permission error for %s: %s", alert.src_ip, exc)
            return
        except Exception as exc:  # noqa: BLE001 — surface any failure
            logger.error("Pipeline error for %s: %s", alert.src_ip, exc, exc_info=True)
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.activity_logged.emit(ts, "ERROR", f"Pipeline failed: {exc}")
            return

        if isinstance(result, FilteredResult):
            self._filtered_count += 1

            # v0.12.0 — enrichment is now async (HTTP reputation
            # clients). v0.15.0 — enrich BOTH src and dest so the
            # Alert Detail view can surface "who's on both ends
            # of the flow". Run both in parallel to keep wall time
            # low.
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

            # Emit filtered alert to Alerts view.
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
                    # v0.9.5 — surface the YAML entry
                    # (signature_name, operator reason, added /
                    # review dates) to the detail view so its
                    # Filter specific-details paragraph can quote
                    # the operator verbatim. SID-match only for
                    # now; category / pair metadata are not yet
                    # surfaced.
                    filter_meta=self._pipeline._filter.get_sid_metadata(  # noqa: SLF001
                        alert.alert_signature_id
                    ),
                    # v0.10.0 — IP ownership & reputation
                    # snapshot. Best-effort: if the enrichment
                    # fails, the UI still renders a minimal
                    # Identity block.
                    ip_enrichment=filtered_ip_enrichment,
                    dest_ip_enrichment=filtered_dest_ip_enrichment,
                ),
            }
            self.alert_received.emit(filtered_data)
            self._history_controller.persist_alert(filtered_data)
            # v0.8.6 B2: per-alert activity rows removed from the
            # System Activity tab — the alert is already fully
            # visible in the Alerts tab (with a detail panel).
            # Activity is now a pure system-event journal.
            return

        if not isinstance(result, DecisionRecord):
            raise TypeError(f"Expected DecisionRecord, got {type(result).__name__}")
        record = result
        self._processed_count += 1

        # Extract verdict info.
        verdict = "inconclusive"
        confidence = "—"
        reasoning = ""
        if record.analysis:
            verdict = record.analysis.verdict.value
            confidence = f"{record.analysis.confidence:.0%}"
            reasoning = record.analysis.reasoning

        if record.actions_taken:
            self._blocked_count += 1

        # v0.12.0 — enrichment is now async. v0.15.0 — enrich
        # BOTH src and dest. Run in parallel to keep wall time
        # bounded by the slowest response.
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

        # Dual-source corroboration surface (Step 11 of
        # project_dual_suricata_sync.md). Hoisted to the top-level
        # ``alert_data`` so the Activity tab and Dashboard widget
        # do not need to dig into ``_full`` — the serialised
        # DecisionRecord is the source of truth, but the UI hot
        # path stays cheap.
        corroboration_value: str | None = (
            record.source_corroboration.value if record.source_corroboration else None
        )
        divergence_explanation: str | None = (
            record.divergence_findings.explanation if record.divergence_findings else None
        )
        divergence_unexplained: bool = bool(
            record.divergence_findings is not None and not record.divergence_findings.is_explained
        )
        verdict_pre_bump_value: str | None = (
            record.verdict_pre_bump.value if record.verdict_pre_bump else None
        )

        # Emit alert for UI.
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
            # Step 11 — dual-source corroboration surface.
            "source_corroboration": corroboration_value,
            "divergence_explanation": divergence_explanation,
            "divergence_unexplained": divergence_unexplained,
            "verdict_pre_bump": verdict_pre_bump_value,
            # v0.9.0 — full DecisionRecord serialised for the
            # detail view. The alerts-list render path ignores
            # this key (backward compat), and
            # ``load_alert_history`` just passes it through.
            "_full": serialise_decision_record(
                record,
                ip_enrichment=analyzed_ip_enrichment,
                dest_ip_enrichment=analyzed_dest_ip_enrichment,
            ),
        }
        self.alert_received.emit(alert_data)
        self._history_controller.persist_alert(alert_data)

        # v0.6.4 — surface every successful IP block as a distinct
        # signal so the tray manager can pop a toast. Without this
        # the operator had no way to learn WardSOAR had just taken
        # their own machine offline.
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

        # Update metrics.
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

        # v0.8.6 B2: the per-alert PIPELINE row used to emit here
        # is gone. The Alerts tab carries the full record (with
        # detail panel for drill-down). Activity stays system-
        # level only.
