"""UI <-> core bridge controllers.

This subpackage holds thin adapters that connect ``wardsoar.core``
business logic to the Qt presentation layer. Each controller wraps
one cohesive concern (Netgate ops, history loading, EVE pipeline,
manual actions) and exposes Qt signals/slots that the views can
connect to.

Status (v0.22.12, 2026-04-25): first extraction landed.
:class:`HistoryController` owns the ``alerts_history.jsonl`` lifecycle
and is consumed by :class:`~wardsoar.pc.ui.engine_bridge.EngineWorker`
through delegation. The remaining concerns (Netgate ops, manual
actions, EVE pipeline) are still in the legacy 1067-SLOC
``EngineWorker`` god-class; see ``README.md`` in this directory for
the migration plan.
"""

from __future__ import annotations

from wardsoar.pc.ui.controllers.history_controller import HistoryController

__all__ = ["HistoryController"]
