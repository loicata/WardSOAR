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

## v0.22.20 — 2026-04-25

Adds the upstream `SourcesQuestionnaire` — a four-screen pre-wizard
that asks the operator three Yes/No questions before the detailed
config wizard runs:

  1. Do you have a Netgate pfSense on this LAN?
  2. Do you have a Virus Sniff (Raspberry Pi) appliance?
  3. Install Suricata locally on this PC?

…with a recap screen that flags coverage gaps (loopback / VPN traffic
not visible to a Netgate-only setup; Netgate + Virus Sniff runtime
exclusivity; standalone-PC LAN-blindness, etc.).

The questionnaire enforces the "≥1 source" invariant from the
2026-04-24 architecture decision: if the operator answers No to both
remote-agent questions, the local Suricata radio is force-checked and
locked. The answers persist as a top-level `sources:` key in
`config.yaml` and are passed to the existing `SetupWizard` so it can
skip pages whose inputs only matter for an unselected source — the
pfSense SSH page is hidden when Netgate=No, for example.

Operators who already have a `config.yaml` (every existing install)
are not affected: the new flow only runs on first-launch when no
config exists, and the legacy detailed wizard still works exactly the
same when invoked without a `sources` argument.

### What changed

- **New module**:
  `packages/wardsoar-pc/src/wardsoar/pc/ui/sources_questionnaire.py`
  — `SourceChoices` dataclass + `SourcesQuestionnaire` QDialog (four
  pages, forced-Yes rule, recap with coverage warnings, finish-time
  guard against the impossible "no source" state).
- **`wardsoar.pc.ui.app`** — first-run flow now opens the
  `SourcesQuestionnaire` first; cancel exits the app the same way it
  did with the legacy wizard cancel. The `SetupWizard` is then
  constructed with `sources=questionnaire.choices`.
- **`wardsoar.pc.ui.setup_wizard`** — `SetupWizard.__init__` accepts
  an optional `sources: SourceChoices`. Pages whose inputs are
  irrelevant for the chosen sources are skipped via `_go_next` /
  `_go_back` walks (today: pfSense SSH page when Netgate=No). The
  generated `config.yaml` includes a `sources:` block when the
  questionnaire ran. When `sources=None` (legacy / test invocation)
  every page is shown — exactly as before.
- **20 new tests** (`tests/test_sources_questionnaire.py`):
  `SourceChoices` invariants and warnings (8) + `SourcesQuestionnaire`
  Qt behaviour (12: construction, defaults, forced-Yes rule,
  navigation, recap rendering, finish guard).

### What's NOT in this release

- The `RemoteAgentRegistry` is **not yet driven by the `sources:`
  key**. `Pipeline.__init__` still constructs `NetgateAgent`
  unconditionally from `responder.pfsense.*` env / config keys. A
  follow-up will wire the registry to the `sources:` block so that
  Netgate=No actually skips the agent instantiation at runtime.
- No "Sources" panel in the Settings view yet — for now the
  `sources:` key is editable via the existing ConfigView YAML editor.
- Local Suricata + Windows Firewall + Npcap download — separate
  follow-up work; the questionnaire collects the choice but the
  installer / blocker code is not in this release.

- **File**: `WardSOAR_0.22.20.msi`
- **Size**: 95.8 MB
- **SHA-256**: `ae8236b36a462a4a38df46f7c57124605e97fa7f20f7adb7d9b9e68dfaded722`
- **Tests**: 1453 green, 2 skipped (+20 for the new questionnaire
  module)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

---

## v0.22.19 — 2026-04-25

Phase 3b.3.2 of the monorepo refactor — the four Netgate-specific
modules (`netgate_audit`, `netgate_tamper`, `netgate_apply`,
`netgate_custom_rules`) and `Pipeline.__init__` now consume the
concrete `NetgateAgent` directly. The temporary `NetgateAgent.ssh`
escape hatch added in v0.22.17 is gone, and the free-function helpers
`migrate_alias_to_urltable(ssh)` / `apply_suricata_runmode(ssh)` are
now reached through the agent's own methods inside the apply layer.

Also fixes the MSI upgrade UX: starting with this release the wizard
no longer offers the misleading "Repair / Remove" dialog when the
operator double-clicks a newer MSI. The Show conditions in
`WixUI_InstallDir` could not be overridden in WiX v4, so the UI was
switched to `WixUI_Minimal` (welcome+EULA → progress → done, no
maintenance dialog at all). The MajorUpgrade schedule was also moved
to `afterInstallExecute` so the HKCU `AutoStartRunKey` Run-key entry
the new install writes is no longer wiped by the old uninstall's
component reference-count drop.

### What changed

- **`wardsoar.core.netgate_audit`** — `NetgateAuditor.__init__` and
  `run_audit()` take `NetgateAgent` instead of `PfSenseSSH`. The
  audit handlers call `agent.run_read_only(cmd, timeout=...)` exactly
  like before — same surface, different concrete type.
- **`wardsoar.core.netgate_tamper`** — `NetgateTamperDetector.__init__`
  takes `NetgateAgent`; same `run_read_only` consumption pattern.
- **`wardsoar.core.netgate_apply`** — every shipped handler
  (`_apply_*`, `_verify_*`) and the `NetgateApplier` itself now take
  `NetgateAgent`. The two Netgate-specific handlers
  (`_apply_migrate_alias_to_urltable`,
  `_apply_suricata_runmode_workers`) call the agent's own methods
  (`agent.migrate_alias_to_urltable()`,
  `agent.apply_suricata_runmode("workers")`) instead of the
  free-function helpers — those helpers are still public and
  importable for the agent's internal use.
- **`wardsoar.core.netgate_custom_rules`** — `deploy_bundle()` takes
  `NetgateAgent`.
- **`wardsoar.pc.main`** — `Pipeline.__init__` passes
  `self._netgate_agent` directly to every Netgate-specific call site
  (audit / tamper / apply / custom_rules). The `.ssh` indirection is
  gone.
- **`wardsoar.core.remote_agents.netgate_agent`** — the temporary
  `ssh` property is removed. The underlying `PfSenseSSH` is now a
  pure implementation detail.
- **`installer/ward.wxs`** — `WixUI_Minimal`,
  `MajorUpgrade Schedule="afterInstallExecute"`, post-install launch
  custom action condition widened to `NOT Installed OR
  WIX_UPGRADE_DETECTED`. End-to-end upgrade smoke-test will happen
  naturally with the next release.

- **File**: `WardSOAR_0.22.19.msi`
- **Size**: 95.8 MB
- **SHA-256**: `c81c3a681a075c3e3ae891a7469b0696ad3bfdd1b406a10f9212bf0fc194db75`
- **Tests**: 1433 green, 2 skipped (-1 vs v0.22.18: the obsolete
  `TestSshEscapeHatch::test_ssh_property_returns_underlying_transport`
  test was removed)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

### What's NOT in this release

`stream_alerts()` abstraction stays out of scope until the Virus
Sniff appliance lands and we have a second concrete agent to validate
the design against (Phase 3b.4).

---

## v0.22.18 — 2026-04-25

Phase 3b.3 of the monorepo refactor — pipeline call sites now consume
the `RemoteAgent` protocol type instead of the concrete `PfSenseSSH`
class. The runtime behaviour is identical (the only `RemoteAgent`
shipped today is `NetgateAgent`, which wraps `PfSenseSSH`), but the
typing change means swapping in a future agent (Virus Sniff Pi,
third-party sensor) requires zero modification to `responder`,
`rule_manager`, or `healthcheck`.

### What changed

- `wardsoar.core.responder.ThreatResponder.__init__` — `ssh` parameter
  type widened from `PfSenseSSH` to `RemoteAgent`. The hot path
  (block / unblock / is-blocked / list) only ever calls the protocol
  surface, so no behaviour change.
- `wardsoar.core.rule_manager.RuleManager.__init__` — same widening on
  the `ssh` parameter. The cleanup loop and emergency unblock only call
  protocol methods.
- `wardsoar.pc.healthcheck.HealthChecker.__init__` — `pfsense_ssh`
  parameter type widened from `PfSenseSSH | None` to
  `RemoteAgent | None`. The healthcheck only calls
  `RemoteAgent.check_status()`.
- `wardsoar.pc.main.Pipeline.__init__` — now constructs
  `NetgateAgent.from_credentials(...)` instead of a bare `PfSenseSSH`.
  The single instance feeds the responder / rule_manager / healthcheck
  (as a `RemoteAgent`) and the four Netgate-specific modules
  (`netgate_audit`, `netgate_tamper`, `netgate_apply`,
  `netgate_custom_rules`) which still consume the underlying
  `PfSenseSSH` via the temporary `NetgateAgent.ssh` escape hatch.

### What's NOT in this release

The four Netgate-specific modules (`netgate_audit`, `netgate_tamper`,
`netgate_apply`, `netgate_custom_rules`) still take a raw `PfSenseSSH`.
A follow-up will migrate them to consume `NetgateAgent` directly so the
`NetgateAgent.ssh` escape hatch can be removed.

The streaming abstraction (`stream_alerts()`) is also still pfSense-shaped
and stays out of scope until the Virus Sniff appliance lands and we have
a second concrete agent to validate the design against (Phase 3b.4).

- **File**: `WardSOAR_0.22.18.msi`
- **Size**: 95.8 MB
- **SHA-256**: `7c5f6c5cf06665df5259a8837dd8854283f5e8826fd98f5b14fa222ec893a69f`
- **Tests**: 1434 green, 2 skipped (zero regression vs v0.22.17 — the
  change is type-system-only and existing `MagicMock(spec=PfSenseSSH)`
  fixtures still satisfy the `RemoteAgent` protocol structurally)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

---

## v0.22.17 — 2026-04-25

Two unrelated improvements bundled in one release: a stale startup
banner is fixed, and the `RemoteAgent` abstraction (Phase 3b.1 + 3b.2
of the monorepo refactor) lands as additive scaffolding.

**Startup banner fix.** `main.py` had hard-coded `"WardSOAR v0.5
(Phase 5+6 online)"` in the pipeline-init banner since the v0.22.7
public release — nine releases of stale text in every operator's log.
The banner now reads from `wardsoar.pc.__version__` like the About
dialog does, and a regression test prevents the literal `"v0.5"` /
`"Phase 5+6"` from coming back.

**`RemoteAgent` scaffolding (Phase 3b.1 + 3b.2).** Two new modules
land under `packages/wardsoar-core/src/wardsoar/core/remote_agents/`:

- `protocol.py` — runtime-checkable `RemoteAgent` protocol with the
  five async operations every agent must implement (`check_status`,
  `add_to_blocklist`, `remove_from_blocklist`, `is_blocked`,
  `list_blocklist`). Fail-safe by contract: implementations must catch
  transport errors internally and return `False` / empty list rather
  than raising.
- `registry.py` — small `RemoteAgentRegistry` (register / unregister /
  get / all_agents / names / `__len__` / `__contains__`) with an
  `isinstance(..., RemoteAgent)` guard at registration time.
- `netgate_agent.py` — concrete `NetgateAgent` that wraps the existing
  `PfSenseSSH` transport via composition. Exposes the protocol surface
  plus three Netgate-specific operations (`run_read_only`,
  `apply_suricata_runmode`, `migrate_alias_to_urltable`) and a
  temporary `ssh` property as an escape hatch for the legacy call
  sites (audit / tamper / apply) until Phase 3b.3 migrates them to
  consume the protocol type directly.

This release is **purely additive**: no existing call site changed,
`PfSenseSSH` and the free-function helpers stay public and importable.
Phase 3b.3 (responder / rule_manager / audit migration to consume the
protocol) ships separately so the riskier change can be reviewed and
rolled back independently.

- **File**: `WardSOAR_0.22.17.msi`
- **Size**: 95.8 MB
- **SHA-256**: `e661175da2aa775e1f835316963b6c1db1cb4ed17cce673d9be419138be18fc1`
- **Tests**: 1434 green, 2 skipped (+35 vs v0.22.16: 14 protocol +
  registry tests, 15 NetgateAgent delegation tests, 1 banner
  regression test, +5 collected from new files)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass

### What's new — for contributors

- New protocol contract in `wardsoar.core.remote_agents.protocol`. Any
  future agent (Virus Sniff Pi, third-party sensor) implements this
  one type; pipeline code consumes the protocol, not concrete classes.
- `NetgateAgent.from_credentials(...)` factory for the common path;
  inject a pre-built `PfSenseSSH` directly in tests to control the
  transport's lifecycle.
- The `ssh` property on `NetgateAgent` is intentional, not a leak —
  it lets the audit / tamper / apply layers keep using their existing
  free-function helpers during Phase 3b.3's incremental migration.
  It will be removed once every call site takes the protocol.

### What's NOT in this release

- No call site migration. `responder`, `rule_manager`, `netgate_audit`,
  `netgate_tamper`, `netgate_apply`, `healthcheck`, and `main.py` still
  consume `PfSenseSSH` directly. Phase 3b.3 will migrate them.
- No streaming abstraction. EVE alert ingestion still goes through
  `ssh_streamer` / `pipeline_controller` and is pfSense-shaped. A
  formal `stream_alerts()` protocol method will be added once the
  Virus Sniff appliance lands and we have a second concrete agent to
  validate the design against (Phase 3b.4).

---

## v0.22.16 — 2026-04-25

Final UI-controller extraction (refactor V3.5) — `EngineWorker`
is now a thin `QThread` lifecycle shell. The pipeline-processing
concern (EVE ingestion + alert routing + healthcheck loop +
asyncio loop ownership) moves to a new `PipelineController`.

**Refactor V3 complete.** The 1067-SLOC god-class is gone:
`EngineWorker` is down to 292 SLOC (-73%) of signal forwarding
and one-line delegates. Every cohesive concern lives in its own
controller under `wardsoar.pc.ui.controllers/`.

- **File**: `WardSOAR_0.22.16.msi`
- **Size**: 95.8 MB
- **SHA-256**: `1fcdbde739ce141b2256e0a4b5c26681e0b6e5cee3df3178b4dad73aa6b26893`
- **Tests**: 1399 green, 2 skipped (+29 — full unit coverage of
  the new controller including async paths, healthcheck cadence,
  fail-safe guards, and the cross-thread entry points)
- **Quality gates**: black, ruff, mypy --strict, bandit, pip-audit
  — all pass
- **Coverage**: `wardsoar.pc.ui.controllers` package: **91.3 %**
  (4 controllers, 458 statements; HistoryController +
  ManualActionController + NetgateController at 100 %,
  PipelineController at 83.1 % — the missing 17 % is
  `bootstrap_in_thread` + the file-poll loop body, deterministic
  only with a real thread)

### What's new — for contributors

- New module
  `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/pipeline_controller.py`
  (711 SLOC). Owns:
  - **6 Qt signals** (`alert_received`, `metrics_updated`,
    `activity_logged`, `status_changed`, `health_updated`,
    `ip_blocked`).
  - **Lifecycle**: `bootstrap_in_thread()` (called from
    `EngineWorker.QThread.run()`) — creates the asyncio loop,
    schedules the main coroutine + intel manager refresh +
    process-attribution buffer + alerts-stats flush + purge,
    then `loop.run_forever()` until `request_stop()` is called.
  - **Cross-thread entry**: `on_ssh_line(line)` — marshals via
    `loop.call_soon_threadsafe(_process_line, line)`.
  - **Processing**: `_process_line` → `_process_alert_async`
    (filtered / decision branches, IP enrichment in parallel for
    src + dest, history persistence, ip_blocked toast trigger).
  - **Healthchecks**: `_run_healthchecks_async` +
    `_maybe_run_healthchecks_async` — periodic run with the
    300 s default interval; only emit Activity rows on
    degraded / failed.
  - **Background**: `_alerts_stats_purge_loop` — initial purge +
    24 h cadence, fail-safe to never crash the worker.
  - **`loop` property** — sibling controllers borrow the loop
    through their `loop_provider` callback so they always see
    the current state (`None` before start, live afterwards,
    `None` again after stop).
- `EngineWorker` becomes a **thin QThread shell** (292 SLOC):
  - Builds `HistoryController`, `IntelManager`, `HealthChecker`,
    then `PipelineController` (which becomes the loop owner),
    then `ManualActionController` and `NetgateController` (which
    borrow the pipeline controller's loop via a closure).
  - Forwards all 14 controller signals signal-to-signal so
    existing `connect()` calls in `app.py` and the views keep
    working unchanged.
  - `run()`, `stop()`, `on_ssh_line()` are 1-line delegates to
    `PipelineController`. The other 14 public methods are
    1-line delegates to history / manual / netgate controllers.
- `app.py:1177` updated: `self._engine._ward_mode = ...` →
  `self._engine._pipeline_controller._ward_mode = ...` (the
  attribute moved with the extraction).
- Two existing tests in `test_ui.py` updated to reach into
  `worker._pipeline_controller._loop` /
  `worker._pipeline_controller._healthchecker` instead of the
  legacy attributes on `EngineWorker`.
- New test file
  `packages/wardsoar-pc/tests/test_pipeline_controller.py` with
  34 test methods across construction, cross-thread entry
  points, request_stop, sync processing (`_process_line` /
  `_process_new_lines`), async processing (
  `_process_alert_async` for both result types + permission /
  generic exception fail-safe paths), healthcheck cadence,
  alerts_stats purge loop, IP enrichment fail-safe, and
  `_main_loop` ssh + missing-file branches. Two of them flip
  `ward_soar.propagate` back to True for the duration of a
  `caplog` assertion — the `wardsoar.core.logger.setup_logger`
  initialisation (run by some other tests) sets it to False,
  which black-holes records before they reach the root caplog
  handler.

### EngineWorker SLOC trajectory — refactor V3 complete

| Version | SLOC | Δ vs origine | Δ vs précédent |
|---------|-----:|-------------:|---------------:|
| v0.22.11 (pre-refactor)        | 1067 |     — |     — |
| v0.22.12 (after V3.2 History)  |  989 |   -78 |   -78 |
| v0.22.13 (after V3.4 Manual)   |  933 |  -134 |   -56 |
| v0.22.14 (after V3.3 Netgate)  |  806 |  -261 |  -127 |
| **v0.22.16 (after V3.5 Pipeline)** | **292** | **-775** | **-514** |

`EngineWorker` is now exclusively signal forwarding + one-line
delegates. Zero business logic. Refactor V3 — done.

### Why this matters

Splitting the god-class was about *enabling* per-concern
unit testing. The four controllers can now be exercised
without spinning up a real `QThread` or `QApplication` (where
not strictly required by Qt signal machinery), which means:
- 105+ controller tests run in ~3 s
- 91.3 % combined coverage (vs ~52 % when everything was inside
  `EngineWorker` and only end-to-end-testable)
- Each concern can evolve independently: a future change to the
  Netgate-apply safety rails has zero risk of breaking the
  history-loading code path

### Documented limitation

`PipelineController.bootstrap_in_thread()` and the file-mode
polling loop are not unit-tested directly — they would require
spinning a real thread and a real loop, which is what the
`TestActivityViewEventShape` integration tests in `test_ui.py`
already do at the `EngineWorker` level. Coverage on the
controller stays at 83.1 % (above the 80 % target) thanks to the
remaining 30+ tests on the request-style methods.

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
