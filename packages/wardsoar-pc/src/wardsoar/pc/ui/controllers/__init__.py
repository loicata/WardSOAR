"""UI ↔ core bridge controllers.

This subpackage holds thin adapters that connect ``wardsoar.core``
business logic to the Qt presentation layer. Each controller wraps
one cohesive concern (Netgate ops, history loading, EVE pipeline,
manual actions) and exposes Qt signals/slots that the views can
connect to.

Status (2026-04-25): scaffolding only. The legacy 1067-SLOC
``EngineWorker`` god-class in ``ui/engine_bridge.py`` still owns all
the bridge logic. Controllers will be extracted into this package
progressively, one concern per commit. See ``README.md`` in this
directory for the migration plan.
"""

from __future__ import annotations
