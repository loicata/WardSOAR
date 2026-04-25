"""UI <-> core bridge controllers.

This subpackage holds thin adapters that connect ``wardsoar.core``
business logic to the Qt presentation layer. Each controller wraps
one cohesive concern (Netgate ops, history loading, EVE pipeline,
manual actions) and exposes Qt signals/slots that the views can
connect to.

Status (v0.22.13, 2026-04-25): two controllers extracted.
:class:`HistoryController` owns the ``alerts_history.jsonl`` lifecycle
(V3.2). :class:`ManualActionController` owns operator-driven rollback
and manual-block requests (V3.4). Both are consumed by
:class:`~wardsoar.pc.ui.engine_bridge.EngineWorker` through delegation.
The remaining concerns (Netgate ops, EVE pipeline) are still in the
legacy ``EngineWorker`` god-class; see ``README.md`` in this directory
for the migration plan.
"""

from __future__ import annotations

from wardsoar.pc.ui.controllers.history_controller import HistoryController
from wardsoar.pc.ui.controllers.manual_action_controller import ManualActionController

__all__ = ["HistoryController", "ManualActionController"]
