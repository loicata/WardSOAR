# Releases — WardSOAR

Every official MSI shipped is listed here with its SHA-256. Use this
to verify the installer you downloaded against the canonical hash.

The MSI itself is **not** committed to the repository (`dist/` is
gitignored). Binary artefacts are attached to the GitHub Releases
page:

- https://github.com/loicata/WardSOAR/releases

To verify an MSI:

```powershell
certutil -hashfile .\WardSOAR_X.Y.Z.msi SHA256
# Compare the output to the entry below.
```

---

## v0.22.15 — 2026-04-25

Smarter handling of HTTP 429 ("Too Many Requests") responses from
intel feed APIs. The legacy code treated a 429 as a generic
failure and waited for 5 consecutive failures before opening the
circuit breaker — wasting four more requests against an API that
was already explicitly asking us to back off.

- **File**: `WardSOAR_0.22.15.msi`
- **Size**: 95.8 MB
- **SHA-256**: `1df02dcef78a6df70b82a5231d77d5f5bcd4018a377db1e3e34e63940a5d1d80`
- **Tests**: 1370 green, 2 skipped (+16 — 6 parser tests + 6
  end-to-end 429 tests + minor refactor of 4 existing tests)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

### What's new — for the operator

The single recurring `intel.greynoise: HTTP error on X: Client
error '429 Too Many Requests'` WARNING is gone. A 429 now logs
once at INFO level (`intel.greynoise: rate limited (429) on X —
suppressing calls for 60s`) and the breaker opens immediately.
Subsequent intel calls during the cooldown are silently skipped —
no log spam.

The same logic applies to every other reputation client
(VirusTotal, AbuseIPDB, AlienVault OTX) since the fix lives in
the shared base class.

### What's new — for contributors

- New helper `_parse_retry_after_seconds(header)` in
  `packages/wardsoar-core/src/wardsoar/core/intel/http_client_base.py`.
  Handles both forms allowed by RFC 7231:
  - integer seconds: `"60"`
  - HTTP-date: `"Wed, 21 Oct 2026 07:28:00 GMT"`
  - clamps to `0 < value <= 24h` so a malformed or hostile
    Retry-After value cannot lock the client out for a week
- New class constant
  `_RATE_LIMIT_DEFAULT_COOLDOWN_S: float = 60.0` — the cooldown
  used when the server did not return a `Retry-After` header.
  Matches the typical per-minute granularity of free tiers.
- New method `_open_breaker_for_rate_limit(ip, retry_after_header)`.
  Trips the breaker immediately, honours `Retry-After` when
  present, extends (never shrinks) any existing breaker window,
  and extends the per-IP negative cache to at least the cooldown
  duration.
- `query_ip` now catches `httpx.HTTPStatusError` *before* the
  generic `httpx.HTTPError` handler. Status code 429 routes to
  `_open_breaker_for_rate_limit` and returns; everything else
  falls through to the existing 5-strike rule.
- 12 new tests:
  - `TestParseRetryAfter` — 6 unit tests (int / HTTP-date / past /
    missing / malformed / 24h cap)
  - 6 integration tests for the 429 path (immediate trip, honours
    `Retry-After`, default cooldown, INFO log level, breaker
    window extends-only, negative cache extension)
- 4 existing tests refactored to use a new `_GenericFailingClient`
  (raising `RemoteProtocolError`) so the 5-strike rule for
  non-429 failures is still exercised. The original
  `_FailingClient` (raising 429) is now repurposed for the new
  rate-limit tests with an optional `retry_after` parameter.

### Why this matters

Production observation on 2026-04-25 (post-v0.22.14 install):
```
12:24:21 WARNING http_client_base: intel.greynoise: HTTP error on
160.79.104.10: Client error '429 Too Many Requests' for url
'https://api.greynoise.io/v3/community/...'
```
Single 429 → single WARNING → 4 more wasted requests (for any
other IP that came in during the next ~minute) before the
breaker opened. With this fix:
- One 429 → INFO log → breaker opens for 60 s (or whatever the
  API specified)
- Zero wasted requests on other IPs during the cooldown
- WARNING level reserved for genuine errors the operator should
  investigate (5xx, timeouts, parse failures)

---

## v0.22.14 — 2026-04-25

Third UI-controller extraction (refactor V3.3) — the largest one
yet. The Netgate appliance operations move to a new
`NetgateController`. Six Qt signals to forward, eight methods
extracted (six async + one sync-on-loop + two sync helpers). Same
façade-with-delegation pattern as V3.2 / V3.4; behaviour is
preserved end to end.

- **File**: `WardSOAR_0.22.14.msi`
- **Size**: 95.8 MB
- **SHA-256**: `ed725a49aa5c6ab55171888f645ee6ce12250a08e908d6f165ef650b0c109503`
- **Tests**: 1354 green, 2 skipped (+26 — full unit coverage of
  the new controller including 5 sync→async bridge tests on a
  real asyncio loop, one per async request method)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass
- **Coverage**: `wardsoar.pc.ui.controllers` package now at **100%**
  (3 controllers: HistoryController + ManualActionController +
  NetgateController, target was 80%)

### What's new — for contributors

- New module
  `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/netgate_controller.py`
  (327 SLOC). Owns:
  - 6 async-or-threadsafe request methods (`request_audit`,
    `request_establish_baseline`, `request_tamper_check`,
    `request_apply`, `request_deploy_custom_rules`,
    `request_reset_cleanup`)
  - 6 corresponding `_execute_*` workers (5 async + 1 sync —
    `_execute_reset_cleanup` is sync because the underlying
    pipeline op is pure filesystem)
  - 2 synchronous helpers the UI calls directly:
    `applicable_fix_ids` and `preview_custom_rules`
  - 6 Qt signals: `audit_completed`, `baseline_established`,
    `tamper_check_completed`, `apply_completed`,
    `custom_rules_deployed`, `reset_cleanup_completed`
- `EngineWorker.__init__` instantiates `NetgateController` and
  forwards all six signals via Qt signal-to-signal connections
  so the existing `connect()` calls in `app.py:528-568` keep
  working unchanged.
- `EngineWorker.request_netgate_*`, `netgate_applicable_fix_ids`,
  and `preview_custom_rules` become one-line delegates.
- All six failure-payload shapes are preserved bit-for-bit from
  the legacy in-place implementation (each signal had a custom
  fail-safe shape — `audit_completed` carries `findings: []` and
  `ssh_reachable: False`, `baseline_established` only carries
  `error`, `apply_completed` returns one entry per requested
  fix_id, etc.).
- New test file
  `packages/wardsoar-pc/tests/test_netgate_controller.py` with 30
  test methods. Notable: 5 sync→async bridge tests (one per
  async request method) drive a real asyncio loop end-to-end so
  the lambda bodies inside `call_soon_threadsafe` are actually
  exercised — closes a gap that pure mock-based tests would
  leave at 96% coverage.

### Why this matters

V3.3 is the largest extraction in the migration plan
(~250 SLOC moved out of `EngineWorker`). The pattern was already
validated on V3.2 (Qt-free) and V3.4 (Qt + 2 signals), so this
extraction was mechanical: same façade, same lazy `loop_provider`,
same coroutine-inside-the-lambda discipline, same
signal-to-signal forwarding. The only new mechanic is the
mixed sync/async surface — `request_reset_cleanup` schedules a
plain callable while the other five schedule a coroutine — and
the test suite covers both paths explicitly.

### `EngineWorker` SLOC trajectory

- v0.22.11 (pre-refactor): **1067 SLOC**
- v0.22.12 (after V3.2):     989 SLOC (-78)
- v0.22.13 (after V3.4):     933 SLOC (-134 vs origin)
- **v0.22.14 (after V3.3):   806 SLOC (-261 vs origin, -25%)**

One concern left to extract — V3.5 `PipelineController` (~300 SLOC,
the `QThread.run` loop + `on_ssh_line` + `_process_*`). After
that, `EngineWorker` becomes a thin lifecycle shell that
coordinates the four controllers.

---

## v0.22.13 — 2026-04-25

Second UI-controller extraction (refactor V3.4). Operator-driven
rollback and manual-block requests move to a new
`ManualActionController`. Behaviour is preserved end to end; only
the call structure changes.

- **File**: `WardSOAR_0.22.13.msi`
- **Size**: 95.8 MB
- **SHA-256**: `48ad040805549c4ab963f9bfb34f0c163b456861798c689a5d87fc547fcff97d`
- **Tests**: 1328 green, 2 skipped (+17 — full unit coverage of
  the new controller using mocked loops + a real-loop sync-to-async
  bridge test)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass
- **Coverage**: `wardsoar.pc.ui.controllers` package now at **100%**
  (HistoryController + ManualActionController, target was 80%)

### What's new — for contributors

- New module
  `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/manual_action_controller.py`
  (223 SLOC). Owns `request_rollback` and `request_manual_block`
  plus the corresponding async workers (`_execute_rollback`,
  `_execute_manual_block`) and the two Qt signals
  (`rollback_completed`, `manual_block_completed`).
- `EngineWorker.__init__` now instantiates `ManualActionController`
  and forwards both signals via Qt signal-to-signal connections
  (`controller.rollback_completed.connect(self.rollback_completed)`)
  so existing `connect()` calls in `app.py` keep working unchanged.
- `EngineWorker.request_rollback` / `request_manual_block` become
  one-line delegates (each ~3 lines).
- The async closure (`_run()`) that previously lived inside each
  request method was promoted to a real method
  (`_execute_rollback` / `_execute_manual_block`). This is a small
  testability refactor: tests can now `await` the async layer
  directly without having to spin up an event loop.
- New test file
  `packages/wardsoar-pc/tests/test_manual_action_controller.py`
  with 17 test methods across construction, sync-layer fail-safe
  paths (loop None / not running), async-layer outcomes (success,
  refusal, exception), the synthetic CONFIRMED verdict structure,
  and an end-to-end sync→async bridge test using a real asyncio
  loop.

### Why this matters

V3.4 validates the façade-with-delegation pattern on a second
concern that — unlike V3.2 — needs Qt signal forwarding.
Confirmed:
1. Signal-to-signal `connect()` is enough; no manual re-emit slot
   needed.
2. The loop reference can be borrowed lazily through a
   `loop_provider` callback so the controller does not need to
   know about the worker's lifecycle.
3. Promoting closures to methods is a strict win for testability
   without changing observable behaviour.

The pattern is now ready to be applied to the two remaining
concerns (Netgate ops V3.3 ~250 SLOC, EVE pipeline V3.5 ~300 SLOC).

### `EngineWorker` SLOC trajectory

- v0.22.11 (pre-refactor): **1067 SLOC**
- v0.22.12 (after V3.2): 989 SLOC (-78)
- **v0.22.13 (after V3.4): 933 SLOC (-134 vs origin, -56 vs prev)**

---

## v0.22.12 — 2026-04-25

First UI-controller extraction (refactor V3.2). The legacy
1067-SLOC `EngineWorker` god-class loses its history-persistence
concern to a new `HistoryController`. Behaviour is preserved end
to end; only the call structure changes.

- **File**: `WardSOAR_0.22.12.msi`
- **Size**: 95.8 MB
- **SHA-256**: `b6ce45180ad32b21b91349d98812afb1a5cba65a749a03c338d0a642485667df`
- **Tests**: 1311 green, 2 skipped (+30 — full unit coverage of
  the new controller, no QApplication needed)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

### What's new — for contributors

- New module
  `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/history_controller.py`
  (175 SLOC). Owns `alerts_history.jsonl` persistence and the
  monthly archive lookup helpers. Pure Python, no Qt — therefore
  unit-testable without a `QApplication`.
- `EngineWorker.__init__` now instantiates `HistoryController` and
  stores it as `self._history_controller`. The five public methods
  (`history_path`, `load_alert_history`, `load_history_page`,
  `list_history_archives`, `load_history_from_archive`) become
  one-line delegates so `app.py` and the alerts view do not need
  to change.
- Internal call sites that previously did `self._persist_alert(...)`
  now go through `self._history_controller.persist_alert(...)`.
- New test file
  `packages/wardsoar-pc/tests/test_history_controller.py` with 29
  test methods across construction, persistence, pagination, IO
  fail-safe behaviour, archive listing and archive round-trip.

### Why this matters

Splitting the god-class is the prerequisite for unit-testing each
concern in isolation and for opening the door to per-controller
evolution (Netgate ops, manual actions, EVE pipeline) without
risking regressions on the others. The history concern was the
easiest of the four (no threading, no Qt signals) and serves as
the template for the next three controllers in the migration plan
(see `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/README.md`).

### Documented quirk preserved

- `load_alert_history(limit=0)` returns the full list (because
  `alerts[-0:]` is `alerts[0:]` in Python). The UI never calls the
  loader with 0 — the contract is "pass `None` or a positive int".
  The test suite explicitly does not assert any behaviour at zero
  so the quirk can be fixed later without churning tests.

---

## v0.22.11 — 2026-04-25

UI architecture decision and enforcement (no functional change).
WardSOAR keeps a 100 % native PySide6 + Fluent Design UI; business
logic stays Qt-free. Three enforcement mechanisms now sit on top
of the layering, and the coverage baseline is captured for future
work.

- **File**: `WardSOAR_0.22.11.msi`
- **Size**: 95.8 MB
- **SHA-256**: `013498c499c3af2394ed16e62d0f196386d997b4597984ec46e5ed5b04db734a`
- **Tests**: 1281 green, 2 skipped (+2 from v0.22.10 — the
  `test_manual_reviews.py` split kept the same count of assertions
  but added the architectural guard rail)
- **Quality gates**: black, ruff (with new TID251 banned-api),
  mypy --strict, bandit, pip-audit — all pass

### What's new — for contributors

- `[tool.ruff.lint.flake8-tidy-imports.banned-api]` in
  `pyproject.toml` rejects `from PySide6` / `from qfluentwidgets`
  imports anywhere outside `packages/wardsoar-pc/.../ui/`.
- New architectural test
  `packages/wardsoar-core/tests/test_architecture.py` runs in
  every CI sweep and on every pre-commit. Sanity-checked by a
  guard that fails if the scanner sees fewer than 50 files
  (catches misconfigured paths).
- New `.pre-commit-config.yaml` runs the five quality gates on
  every commit (black, ruff, mypy --strict, bandit, plus the
  architectural test). pip-audit is wired as a manual stage.
  Install once with `.venv\Scripts\pre-commit install`.
- New `[tool.coverage]` configuration in `pyproject.toml`.
  Baseline captured in `docs/COVERAGE.md` (core 85.7 %, pc-non-ui
  ~85 %, pc.ui ~52 %). Per-layer targets documented.
- New `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/`
  scaffolding with a migration plan (README.md). The legacy
  `EngineWorker` god-class will be split into thematic controllers
  in follow-up commits.

### Real bug surfaced and fixed by the new test

- `test_manual_reviews.py` mixed Qt dialog tests with core storage
  tests. Split into:
  - `packages/wardsoar-core/tests/test_manual_reviews.py` (storage
    only, Qt-free)
  - `packages/wardsoar-pc/tests/test_manual_review_dialog.py`
    (Qt dialog, with `qapp` fixture)

### Stale code cleaned up

- `setup_wizard.py:1116` had `from src import win_paths` left over
  from the pre-monorepo layout. Replaced with
  `from wardsoar.pc import win_paths`. This was masked because
  `mypy --strict` had not been run on the full pc src tree before.

### No breaking changes
Operators upgrading from v0.22.10 see no behaviour difference.
Configuration files, MSI install path, uninstall procedure and
shipped UI text are all unchanged.

### Documentation
- `CLAUDE.md` gets section 10 ("UI architecture & layering").
- `docs/ARCHITECTURE.md` gets section 5.9 (decision log entry).
- `docs/COVERAGE.md` (new) tracks per-layer coverage and roadmap.
- `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/README.md`
  documents the migration plan for the EngineWorker split.

---

## v0.22.10 — 2026-04-25

Fix the About dialog that displayed ``v0.0.1`` on a v0.22.9 install.
The dialog was importing ``__version__`` from ``wardsoar.core`` (a
skeleton placeholder) instead of ``wardsoar.pc`` (the source of truth
read by ``pyproject.toml`` and WiX). The placeholder is now removed
from ``wardsoar.core/__init__.py`` so the same accident cannot recur.

- **File**: `WardSOAR_0.22.10.msi`
- **Size**: 95.8 MB
- **SHA-256**: `5855b1447ffc14868fec89ca20ef658b94a091e5a8a5fd237493297ce6dd404e`
- **Tests**: 1279 green, 2 skipped (+2 from v0.22.9)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit — all pass

### What's changed
- `about_dialog.py:22` — import switched from
  `from wardsoar.core import __version__` to
  `from wardsoar.pc import __version__`.
- `wardsoar.core/__init__.py` — placeholder `__version__ = "0.0.1"`
  removed; the docstring now warns future contributors not to
  reintroduce one. The shipped product version lives on
  `wardsoar.pc` only.
- 2 new tests in `test_ui.py::TestAboutDialog`:
  - dialog imports the pc-package version
  - constructed dialog displays it (regression coverage)
- 2 skeleton tests updated to match the new contract
  (``core`` no longer has ``__version__``).

### No breaking changes
The fix only affects the About dialog text; pipeline, decisions,
configuration files, MSI install path and uninstall procedure are
unchanged.

---

## v0.22.9 — 2026-04-25

Fail-safe guard logs (RFC1918 / whitelist / trusted_temp) downgraded
to DEBUG when the verdict is BENIGN. WARNING was misleading on a
verdict where no block was about to be issued — the v0.22.8 first-day
production logs showed 1 spurious entry on a STUN traversal alert
(192.168.2.100 → Cloudflare 3478/UDP) and 33 occurrences of
benign + private-IP across the full historical log.

- **File**: `WardSOAR_0.22.9.msi`
- **Size**: 95.8 MB
- **SHA-256**: `87ded4c81fee80b44399ee0b6545c15c89dd010e634e6f0fa67bb5c972623507`
- **Tests**: 1277 green, 2 skipped (+8 from v0.22.8)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit — all pass

### What's changed
- Three guards in `responder.respond` (RFC1918 / whitelist /
  trusted_temp) now log at DEBUG when `analysis.verdict == BENIGN`,
  WARNING otherwise. The block decision itself (`BlockAction.NONE`
  returned, no firewall write) is unchanged in all paths.
- 8 new caplog tests cover the level matrix per gate × verdict.
- New test fixture restores logger propagation that `setup_logging`
  disables — surfaced as a flaky-suite bug during the regression
  sweep, fixed in test scope only.

### No breaking changes
Operators upgrading from v0.22.8 see strictly less log noise and
identical decision behaviour. Configuration files, MSI install path
and uninstall procedure are unchanged.

---

## v0.22.8 — 2026-04-24

Monorepo refactor complete. No functional change over v0.22.7 — this
release is the first to ship the new layout where the application
code lives under ``packages/wardsoar-pc/`` and the cross-platform
core under ``packages/wardsoar-core/``. The legacy ``src/`` tree is
gone from the source distribution.

- **File**: `WardSOAR_0.22.8.msi`
- **Size**: 95.8 MB
- **SHA-256**: `2e146e108773b3276cf6c29177c3de01796a0b7443e46c224a7dbe1001d399c9`
- **Tests**: 1269 green, 2 skipped
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit — all pass

### What's new
- Two-package monorepo layout (``wardsoar-core`` +
  ``wardsoar-pc``) built as a ``uv`` workspace. Third skeleton
  (``wardsoar-virus-sniff``) in place for the future appliance.
- Core is OS-agnostic: no Windows-specific import left
  inside ``wardsoar.core``.
- Two modules reclassified from core → pc: ``single_instance`` (uses
  pywin32 named-mutex) and ``ssh_streamer`` (inherits from
  ``PySide6.QtCore.QThread``).
- ``get_data_dir()`` walks up for ``packages/`` as the monorepo
  marker, with ``WARDSOAR_DATA_DIR`` env override for tests.

### Fixes re-shipped (inherited from v0.22.7)
All 9 bug fixes from the v0.22.7 session ride along: DPAPI
post-block crash, pfSense ``.tmp`` race, blocking idempotence,
intel circuit breaker + negative cache, OTX empty error messages,
threatfox schema drift, Claude credit-exhausted breaker, forensics
NoneType guard, SSH retry.

### Breaking changes for developers
The legacy ``src/`` package is gone. Any external script importing
``from src.X import Y`` must switch to ``from wardsoar.core.X`` or
``from wardsoar.pc.X`` as appropriate. See
``docs/MONOREPO.md`` for the layout.

---

## v0.22.7 — 2026-04-24

First public release. Ships after a session of 9 bug fixes caught by
log triage (see the v0.22.7 commit message for details).

- **File**: `WardSOAR_0.22.7.msi`
- **Size**: 95.8 MB
- **SHA-256**: `65c9f32ef1430cff9dc5e1152ac2f2ca66b67f0669a90f4efcfc6cd1ff2da340`
- **Tests**: 1267 green (+25 regression added this session)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit — all pass

### Fixes included
1. Deep-analysis crash (DPAPI post-block) — manifest returned from
   memory, directory sealed after deep analysis completes.
2. pfSense race condition on the `.tmp` staging path — async lock
   on `PfSenseSSH` + unique `.tmp.<pid>.<ns>` suffix.
3. Duplicate block for the same IP — `is_blocked` pre-check,
   `idempotent=True` flag on `ResponseAction`, rate-limiter not
   charged.
4. Intel clients pounding a failing API — circuit breaker + per-IP
   negative cache in `HttpReputationClient` base class.
5. `intel.alienvault_otx: HTTP error on X:` with empty reason —
   fallback to exception class name.
6. ThreatFox refresh yielding 0 indicators — parser now reads the
   current `ioc_value` / `first_seen_utc` keys with legacy fallback.
7. Analyzer hammering Claude after "credit balance too low" —
   analyzer-side circuit breaker with extended cooldown on
   credit-exhausted.
8. `'NoneType' object has no attribute 'strip'` — `subprocess.run`
   may return `stdout=None` on a crashed child; guarded in 6 call
   sites.
9. SSH to pfSense failing on transient network blips — bounded retry
   with exponential backoff on `_run_cmd`.

---

<!--
Template for future releases:

## vX.Y.Z — YYYY-MM-DD

- **File**: `WardSOAR_X.Y.Z.msi`
- **Size**: NN MB
- **SHA-256**: `…`
- **Tests**: NNNN green
- **Quality gates**: all pass

### Highlights
- …
-->
