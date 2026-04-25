# `ui/controllers/` — UI ↔ core bridge layer

This directory is the **only place** in the PC codebase where Qt
signals/slots are allowed to wrap calls into `wardsoar.core` business
logic. Views (`ui/views/*.py`) import controllers; controllers import
core; **views never import core directly**.

Status as of 2026-04-25: **scaffolding only**. The legacy
[`engine_bridge.py`](../engine_bridge.py) (1 067 SLOC, single
`EngineWorker(QThread)` class) still owns every bridge concern.
This README is the migration plan.

## Why split

`EngineWorker` mixes four orthogonal concerns:

| Concern | SLOC | Methods (line range in engine_bridge.py) |
|---------|-----:|------------------------------------------|
| Netgate operations | ~250 | `request_netgate_*`, `netgate_applicable_fix_ids`, `request_deploy_custom_rules`, `preview_custom_rules` (lines 240–432) |
| History / persistence | ~150 | `_persist_alert`, `history_path`, `load_alert_history`, `load_history_page`, `list_history_archives`, `load_history_from_archive` (lines 538–663) |
| EVE / pipeline processing | ~300 | `run`, `on_ssh_line`, `_process_new_lines`, `_process_line` (lines 151–207, 665–~960) |
| Manual actions | ~100 | `request_rollback`, `request_manual_block` (lines 434–536) |

A god-class makes per-concern testing impossible: you cannot
exercise the rollback path without spinning up a full SSH stream,
and you cannot test the history loader without instantiating a
QThread. Splitting unlocks unit tests and lets each concern evolve
independently.

## Migration pattern — façade with delegation

To keep the migration risk-free, `EngineWorker` stays the **public
API** for views and `app.py`. Internally, it owns instances of the
controllers and delegates to them. No view changes required during
the migration.

```python
class EngineWorker(QThread):
    def __init__(self, ...):
        super().__init__(...)
        self._netgate_controller = NetgateController(...)
        self._history_controller = HistoryController(...)
        # ...

    def request_netgate_audit(self) -> None:
        self._netgate_controller.request_audit()
        # signals re-emitted on EngineWorker for backward compat
```

Once all four controllers are extracted, a follow-up commit can
flip views to import the controllers directly and demote
`EngineWorker` to a thin lifecycle manager.

## Migration order

Recommended sequence (each step = one commit + tests + release):

1. **`history_controller.py`** — easiest. Pure data loading, no
   threading, no Qt signals beyond returning lists. Touches:
   `_persist_alert`, `history_path`, `load_alert_history`,
   `load_history_page`, `list_history_archives`,
   `load_history_from_archive`.

2. **`netgate_controller.py`** — well-bounded. All `request_netgate_*`
   methods become `NetgateController.request_*`. Existing signals
   on `EngineWorker` (`baseline_established`, `tamper_checked`,
   `audit_completed`, etc.) get redefined on the controller and
   re-emitted by the worker for the migration window.

3. **`manual_action_controller.py`** — small. `request_rollback` +
   `request_manual_block`. Uses `wardsoar.core.responder` and
   `wardsoar.core.rollback`.

4. **`pipeline_controller.py`** — biggest, last. Owns the SSH-line
   ingestion (`on_ssh_line`, `_process_*`) and the QThread `run`
   loop. After this, `EngineWorker` becomes a thin shell that just
   coordinates the four controllers.

## Coverage targets

Per [CLAUDE.md §10](../../../../../../CLAUDE.md):

- `ui/controllers/` aims for **80%** coverage (vs `ui/views/` at 70%).
- Controllers should be testable without a full `QApplication` —
  they wrap core, which is Qt-free, so the only Qt surface is
  signal definitions. Use `QSignalSpy` from `pytest-qt` (or a
  hand-rolled list-based spy) to test signal emission.

## Naming convention

- Module name: `<concern>_controller.py` (singular, snake_case).
- Class name: `<Concern>Controller` (PascalCase).
- One controller per file. Do not bundle two concerns to "save a
  file" — the whole point is to undo the god-class.

## What goes in a controller and what doesn't

**In a controller**:
- Calls into `wardsoar.core` API.
- Qt signal definitions for view consumption.
- Translation from core return types to view-friendly DTOs.
- Threading orchestration (`QThread.run`, `QtCore.QObject.moveToThread`).

**NOT in a controller**:
- Widget construction (lives in `ui/views/`, `ui/widgets/`).
- Business logic (lives in `wardsoar.core`).
- Direct `subprocess`/`win32api` calls (lives in `wardsoar.pc.*`
  non-ui modules; the controller only orchestrates).
- Persistence formats — JSON layout, CSV columns, etc. belong in
  core (`wardsoar.core.history_rotator`, etc.).
