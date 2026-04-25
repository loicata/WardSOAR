"""UI <-> core bridge controllers.

This subpackage holds thin adapters that connect ``wardsoar.core``
business logic to the Qt presentation layer. Each controller wraps
one cohesive concern and exposes Qt signals/slots that the views
can connect to.

Status (v0.22.16, 2026-04-25): refactor V3 complete.
:class:`HistoryController` owns the ``alerts_history.jsonl``
lifecycle (V3.2). :class:`ManualActionController` owns operator-
driven rollback and manual-block requests (V3.4).
:class:`NetgateController` owns the Netgate audit / baseline /
tamper / apply / deploy / reset-cleanup actions (V3.3).
:class:`PipelineController` owns the EVE ingestion + processing +
healthcheck loop (V3.5). All four are consumed by
:class:`~wardsoar.pc.ui.engine_bridge.EngineWorker` through
delegation; ``EngineWorker`` is now a thin ``QThread`` lifecycle
shell that creates the controllers and forwards their fourteen
signals back for backward compatibility with ``app.py``.
"""

from __future__ import annotations

from wardsoar.pc.ui.controllers.history_controller import HistoryController
from wardsoar.pc.ui.controllers.manual_action_controller import ManualActionController
from wardsoar.pc.ui.controllers.netgate_controller import NetgateController
from wardsoar.pc.ui.controllers.pipeline_controller import PipelineController

__all__ = [
    "HistoryController",
    "ManualActionController",
    "NetgateController",
    "PipelineController",
]
