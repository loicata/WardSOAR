# Test coverage — baseline and roadmap

This file tracks the state of test coverage per architectural layer
and the progress toward the targets set by the UI layering decision
([CLAUDE.md section 10](../CLAUDE.md), [ARCHITECTURE.md §5.9](ARCHITECTURE.md)).

Targets are aspirational. They are **not yet enforced** via
``pytest --cov-fail-under`` — the project ships with the baseline
below and improves toward the targets one module at a time. Once a
layer reaches its target, ``--cov-fail-under=NN`` will be wired into
the pre-commit / CI gates so the layer cannot regress.

## Targets

| Layer | Target | Why |
|-------|--------|-----|
| `wardsoar.core` | 90% | Cross-platform business logic, decision pipeline. Stability is critical. |
| `wardsoar.pc.ui.controllers` | 80% | The bridge between core and Qt; thin and easily testable once it exists (V3 of the UI layering work). |
| `wardsoar.pc.ui` (widgets/views) | 70% | Qt widgets are harder to unit-test; visual checks complement automated tests. |
| `wardsoar.pc` (non-ui) | 80% | Windows business logic (forensics, local AV, Sysmon). |

## Baseline — measured 2026-04-25

Run with:
```powershell
.venv\Scripts\pytest packages/wardsoar-core/tests/ --cov=wardsoar.core --cov-report=term
.venv\Scripts\pytest packages/wardsoar-pc/tests/   --cov=wardsoar.pc   --cov-report=term
```

### `wardsoar.core` — 85.7% (target 90%, gap −4.3)

Modules below their cohort average (worth attention):

| Module | Coverage | Notes |
|--------|---------:|-------|
| `intel/ipinfo_pro.py` | 41.7% | HTTP client, sparse mock paths |
| `intel/greynoise.py` | 58.3% | HTTP client |
| `intel/spamhaus_drop.py` | 59.7% | Feed parser |
| `intel/honeypot.py` | 61.8% | Feed manager |
| `intel/manager.py` | 65.0% | Orchestrator across intel sources |
| `intel/abuseipdb.py` | 66.7% | HTTP client |
| `intel/virustotal_client.py` | 68.4% | HTTP client |
| `intel/censys_client.py` | 69.2% | HTTP client |
| `intel/base.py` | 69.9% | HTTP client base — used everywhere |
| `watcher.py` | 70.3% | EVE JSON tail, hard to test deterministically |
| `intel/xforce.py` | 71.7% | HTTP client |
| `intel/securitytrails.py` | 71.1% | HTTP client |
| `ip_enrichment.py` | 73.7% | Aggregator over intel sources |
| `asn_enricher.py` | 73.8% | ASN cache + lookup |
| `intel/shodan_client.py` | 74.4% | HTTP client |
| `netgate_apply.py` | 77.6% | pfSense apply orchestrator |
| `intel/alienvault_otx.py` | 77.8% | HTTP client |
| `prescorer_feedback.py` | 78.8% | Feedback loop persistence |
| `analyzer.py` | 79.4% | Claude API client (CRITICAL — should be 90%+) |

The `intel/` family is the dominant gap. A focused pass adding error-path
tests (timeout, 500, 429, malformed JSON) for each HTTP client would
move the whole layer above 90%. Estimated effort: 1 day.

### `wardsoar.pc` (non-ui, ~85% aggregate) — at or near target

| Module | Coverage |
|--------|---------:|
| `process_risk.py` | 80.2% |
| `process_risk_cache.py` | 92.0% |
| `process_snapshot_buffer.py` | 93.9% |
| `svchost_resolver.py` | 92.2% |
| `sysmon_events.py` | 94.0% |
| `sysmon_installer.py` | 91.8% |
| `sysmon_probe.py` | 100% |
| `win_paths.py` | 100% |
| `main.py` | 68.7% — pipeline orchestrator, hard to mock end-to-end |
| `single_instance.py` | 68.0% — Windows mutex semantics |

### `wardsoar.pc.ui` — ~52% (target 70%, gap −18)

Critical modules under-covered:

| Module | Coverage | Action |
|--------|---------:|--------|
| `ui/setup_wizard.py` | **0.0%** | Never tested. Bootstrap flow — needs at least smoke tests on each wizard page constructor. |
| `ui/ssh_streamer.py` | 20.8% | Live EVE stream over SSH; needs a fake transport. |
| `ui/engine_bridge.py` | 22.3% | The 1067-SLOC pipeline ↔ Qt bridge. Will be split into `ui/controllers/` (V3). Coverage will rise naturally as the bridge is decomposed. |
| `ui/app.py` | 32.6% | Main window construction; tests cover TrayManager only. |
| `ui/views/netgate.py` | 57.9% | Audit + apply UI (1365 SLOC). |
| `ui/views/config_view.py` | 61.8% | |
| `ui/views/activity_view.py` | 63.3% | |
| `ui/views/alerts.py` | 64.9% | |
| `ui/views/keys_view.py` | 73.6% | At target |
| `ui/views/alert_detail.py` | 78.5% | At target |
| `ui/views/dashboard.py` | 81.1% | At target |
| `ui/views/about_dialog.py` | 93.3% | At target (regression coverage from v0.22.10) |
| `ui/views/replay_view.py` | 100% | At target |

## Roadmap

1. **V2 of UI layering work (2026-04-25)** — baseline captured (this file).
2. **V3 of UI layering work** — split `engine_bridge.py` into
   `ui/controllers/`. Coverage of the bridge layer rises mechanically
   because the controllers will be small and individually testable.
3. **Phase 9 hardening** — add `hypothesis` + `mutmut`, write
   property-based and mutation tests for CRITICAL modules
   (`responder.py`, `analyzer.py`, `pfsense_ssh.py`,
   `forensic_report.py`, `prescorer.py`, `deduplicator.py`,
   `filter.py`, `decision_cache.py`).
4. **`intel/` HTTP client coverage pass** — same template applied to
   each client (timeout / 500 / 429 / parse error) lifts core to 90%.
   ~1 day of focused work.
5. **`setup_wizard.py` smoke tests** — at least one test per wizard
   page constructor with the shared `qapp` fixture, asserting the
   page renders without raising. ~half a day.
6. **Activate `--cov-fail-under` per layer in pre-commit / CI** as
   each layer reaches its target.

## How to read this file

Coverage numbers go up as we add tests. A regression (any layer
dropping more than 1 point) is a red flag — investigate before
merging the change that caused it.

When updating this file, use:

```powershell
.venv\Scripts\pytest packages/wardsoar-core/tests/ --cov=wardsoar.core --cov-report=term-missing
.venv\Scripts\pytest packages/wardsoar-pc/tests/   --cov=wardsoar.pc   --cov-report=term-missing
```

The full HTML report (per-line drill-down):

```powershell
.venv\Scripts\pytest packages/ --cov=wardsoar --cov-report=html
# Open htmlcov/index.html
```
