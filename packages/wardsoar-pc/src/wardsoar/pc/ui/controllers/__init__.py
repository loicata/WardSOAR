"""UI <-> core bridge controllers.

This subpackage holds thin adapters that connect ``wardsoar.core``
business logic to the Qt presentation layer. Each controller wraps
one cohesive concern and exposes Qt signals/slots that the views
can connect to.

Status (v0.22.14, 2026-04-25): three controllers extracted.
:class:`HistoryController` owns the ``alerts_history.jsonl``
lifecycle (V3.2). :class:`ManualActionController` owns operator-
driven rollback and manual-block requests (V3.4).
:class:`NetgateController` owns the Netgate audit / baseline /
tamper / apply / deploy / reset-cleanup actions plus two sync
helpers (V3.3). All three are consumed by
:class:`~wardsoar.pc.ui.engine_bridge.EngineWorker` through
delegation. The remaining concern (EVE pipeline V3.5) is still in
the legacy ``EngineWorker`` god-class; see ``README.md`` in this
directory for the migration plan.
"""

from __future__ import annotations

from wardsoar.pc.ui.controllers.history_controller import HistoryController
from wardsoar.pc.ui.controllers.manual_action_controller import ManualActionController
from wardsoar.pc.ui.controllers.netgate_controller import NetgateController

__all__ = ["HistoryController", "ManualActionController", "NetgateController"]
