"""Thin ``QThread`` lifecycle shell that owns the four UI controllers.

After refactor V3 (v0.22.12 → v0.22.16) every cohesive concern
that used to live inside the 1067-SLOC ``EngineWorker`` god-class
has been extracted into its own controller in
``packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/``:

* :class:`~wardsoar.pc.ui.controllers.HistoryController` (V3.2,
  v0.22.12) — JSONL persistence + monthly archive lookup.
* :class:`~wardsoar.pc.ui.controllers.ManualActionController` (V3.4,
  v0.22.13) — operator-driven rollback + manual block requests.
* :class:`~wardsoar.pc.ui.controllers.NetgateController` (V3.3,
  v0.22.14) — appliance audit / baseline / tamper / apply / deploy
  / reset-cleanup.
* :class:`~wardsoar.pc.ui.controllers.PipelineController` (V3.5,
  v0.22.16) — EVE ingestion + processing + healthcheck loop. Owns
  the asyncio event loop.

``EngineWorker`` is now a QThread shell that:

1. Builds every controller and the pipeline-side helpers
   (history, intel manager, healthchecker).
2. Forwards each controller signal to a like-named worker signal
   so existing ``connect()`` calls in ``app.py`` keep working
   unchanged.
3. Hands control to ``PipelineController.bootstrap_in_thread()``
   from inside ``QThread.run()``.

No business logic lives here anymore — every public method is a
one-line delegate to the right controller.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from PySide6.QtCore import QThread, Signal

from wardsoar.core.intel.manager import IntelManager
from wardsoar.pc.healthcheck import HealthChecker
from wardsoar.pc.ui.controllers import (
    HistoryController,
    ManualActionController,
    NetgateController,
    PipelineController,
)

if TYPE_CHECKING:
    from wardsoar.pc.main import Pipeline


class EngineWorker(QThread):
    """QThread shell that owns the four UI controllers.

    The thread itself only exists so the controllers can run an
    asyncio event loop off the Qt main thread — every other
    concern lives in a controller. Signals are kept here for
    backward compatibility with the (many) external ``connect()``
    calls in ``app.py`` and the views; each one is connected
    signal-to-signal to its source controller in :meth:`__init__`.

    Signals:
        alert_received (dict): forwarded from PipelineController.
        metrics_updated (dict): forwarded from PipelineController.
        activity_logged (str, str, str): forwarded from PipelineController.
        status_changed (str, str): forwarded from PipelineController.
        health_updated (str, str): forwarded from PipelineController.
        ip_blocked (dict): forwarded from PipelineController.
        rollback_completed (dict): forwarded from ManualActionController.
        manual_block_completed (dict): forwarded from ManualActionController.
        netgate_audit_completed (dict): forwarded from NetgateController.
        netgate_baseline_established (dict): forwarded from NetgateController.
        netgate_tamper_check_completed (dict): forwarded from NetgateController.
        netgate_apply_completed (list): forwarded from NetgateController.
        netgate_custom_rules_deployed (dict): forwarded from NetgateController.
        netgate_reset_cleanup_completed (dict): forwarded from NetgateController.
    """

    # Pipeline signals (V3.5).
    alert_received = Signal(dict)
    metrics_updated = Signal(dict)
    activity_logged = Signal(str, str, str)
    status_changed = Signal(str, str)
    health_updated = Signal(str, str)
    ip_blocked = Signal(dict)

    # Manual-action signals (V3.4).
    rollback_completed = Signal(dict)
    manual_block_completed = Signal(dict)

    # Netgate signals (V3.3).
    netgate_audit_completed = Signal(dict)
    netgate_baseline_established = Signal(dict)
    netgate_tamper_check_completed = Signal(dict)
    netgate_custom_rules_deployed = Signal(dict)
    netgate_apply_completed = Signal(list)
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

        # Pipeline-side helpers — owned by the worker so they can
        # be reused across controllers without duplicate
        # construction. ``get_data_dir()`` is read-once at startup
        # so the operator's APPDATA layout is consistent across
        # restarts.
        from wardsoar.core.config import get_data_dir

        self._history_controller = HistoryController(
            get_data_dir() / "logs" / "alerts_history.jsonl"
        )

        intel_manager = IntelManager(cache_dir=get_data_dir() / "intel_feeds")

        hc_cfg = healthcheck_cfg or {}
        hc_cfg["eve_json_path"] = eve_path
        healthchecker = HealthChecker(hc_cfg)
        health_interval = int(hc_cfg.get("interval_seconds", 300))

        # Pipeline controller — owns the event loop the other
        # controllers borrow through their ``loop_provider``.
        self._pipeline_controller = PipelineController(
            pipeline=pipeline,
            eve_path=eve_path,
            mode=mode,
            ward_mode=ward_mode,
            history_controller=self._history_controller,
            intel_manager=intel_manager,
            healthchecker=healthchecker,
            health_interval_s=health_interval,
            parent=self,
        )
        self._pipeline_controller.alert_received.connect(self.alert_received)
        self._pipeline_controller.metrics_updated.connect(self.metrics_updated)
        self._pipeline_controller.activity_logged.connect(self.activity_logged)
        self._pipeline_controller.status_changed.connect(self.status_changed)
        self._pipeline_controller.health_updated.connect(self.health_updated)
        self._pipeline_controller.ip_blocked.connect(self.ip_blocked)

        # Loop provider for the sibling controllers — reads the
        # pipeline controller's loop at every call so it always
        # sees the current state (None before the worker starts,
        # the live loop afterwards, None again after stop).
        def loop_provider() -> Any:
            return self._pipeline_controller.loop

        self._manual_action_controller = ManualActionController(
            pipeline=pipeline,
            loop_provider=loop_provider,
            parent=self,
        )
        self._manual_action_controller.rollback_completed.connect(self.rollback_completed)
        self._manual_action_controller.manual_block_completed.connect(self.manual_block_completed)

        self._netgate_controller = NetgateController(
            pipeline=pipeline,
            loop_provider=loop_provider,
            parent=self,
        )
        self._netgate_controller.audit_completed.connect(self.netgate_audit_completed)
        self._netgate_controller.baseline_established.connect(self.netgate_baseline_established)
        self._netgate_controller.tamper_check_completed.connect(self.netgate_tamper_check_completed)
        self._netgate_controller.apply_completed.connect(self.netgate_apply_completed)
        self._netgate_controller.custom_rules_deployed.connect(self.netgate_custom_rules_deployed)
        self._netgate_controller.reset_cleanup_completed.connect(
            self.netgate_reset_cleanup_completed
        )

    # ------------------------------------------------------------------
    # QThread lifecycle — delegates to PipelineController
    # ------------------------------------------------------------------

    def run(self) -> None:
        """QThread entry — delegate to :meth:`PipelineController.bootstrap_in_thread`."""
        self._pipeline_controller.bootstrap_in_thread()

    def stop(self) -> None:
        """Stop the worker — thread-safe, callable from the main thread."""
        self._pipeline_controller.request_stop()

    def on_ssh_line(self, line: str) -> None:
        """Process a line received from the SSH streamer (cross-thread safe)."""
        self._pipeline_controller.on_ssh_line(line)

    # ------------------------------------------------------------------
    # Netgate façade — delegates to :class:`NetgateController` (V3.3).
    # ------------------------------------------------------------------

    def request_netgate_audit(self) -> None:
        """Delegate to :meth:`NetgateController.request_audit`."""
        self._netgate_controller.request_audit()

    def request_netgate_establish_baseline(self) -> None:
        """Delegate to :meth:`NetgateController.request_establish_baseline`."""
        self._netgate_controller.request_establish_baseline()

    def request_netgate_tamper_check(self) -> None:
        """Delegate to :meth:`NetgateController.request_tamper_check`."""
        self._netgate_controller.request_tamper_check()

    def request_netgate_apply(self, fix_ids: list[str]) -> None:
        """Delegate to :meth:`NetgateController.request_apply`."""
        self._netgate_controller.request_apply(fix_ids)

    def request_deploy_custom_rules(self) -> None:
        """Delegate to :meth:`NetgateController.request_deploy_custom_rules`."""
        self._netgate_controller.request_deploy_custom_rules()

    def request_netgate_reset_cleanup(self) -> None:
        """Delegate to :meth:`NetgateController.request_reset_cleanup`."""
        self._netgate_controller.request_reset_cleanup()

    def netgate_applicable_fix_ids(self) -> set[str]:
        """Delegate to :meth:`NetgateController.applicable_fix_ids`."""
        return self._netgate_controller.applicable_fix_ids()

    def preview_custom_rules(self) -> "Any":
        """Delegate to :meth:`NetgateController.preview_custom_rules`."""
        return self._netgate_controller.preview_custom_rules()

    # ------------------------------------------------------------------
    # Manual-action façade — delegates to :class:`ManualActionController` (V3.4).
    # ------------------------------------------------------------------

    def request_rollback(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Delegate to :meth:`ManualActionController.request_rollback`."""
        self._manual_action_controller.request_rollback(
            ip=ip, signature_id=signature_id, reason=reason
        )

    def request_manual_block(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        operator_notes: str = "",
    ) -> None:
        """Delegate to :meth:`ManualActionController.request_manual_block`."""
        self._manual_action_controller.request_manual_block(
            ip=ip, signature_id=signature_id, operator_notes=operator_notes
        )

    # ------------------------------------------------------------------
    # History façade — delegates to :class:`HistoryController` (V3.2).
    # ------------------------------------------------------------------

    @property
    def history_path(self) -> Path:
        """Path of the active ``alerts_history.jsonl`` file."""
        return self._history_controller.history_path

    def load_alert_history(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Delegate to :meth:`HistoryController.load_alert_history`."""
        return self._history_controller.load_alert_history(limit=limit, offset=offset)

    def load_history_page(
        self, older_than_count: int, page_size: int = 200
    ) -> list[dict[str, Any]]:
        """Delegate to :meth:`HistoryController.load_history_page`."""
        return self._history_controller.load_history_page(
            older_than_count=older_than_count, page_size=page_size
        )

    def list_history_archives(self) -> list[dict[str, Any]]:
        """Delegate to :meth:`HistoryController.list_history_archives`."""
        return self._history_controller.list_history_archives()

    def load_history_from_archive(
        self, archive_path: str, limit: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Delegate to :meth:`HistoryController.load_history_from_archive`."""
        return self._history_controller.load_history_from_archive(
            archive_path=archive_path, limit=limit
        )
