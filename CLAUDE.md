## ── SECTIONS "ROBUSTESSE MAXIMALE" À AJOUTER ──

### 0. Language policy — English only

All source code, UI strings, inline comments, docstrings, log messages,
exception messages, README files inside evidence bundles, commit messages,
pull-request descriptions, and test names MUST be in English. No
French in anything that ships in the product.

**Rationale**
- WardSOAR evidence is consumed by law-enforcement and international
  forensic analysts; French-only artefacts would slow investigations
  and break cross-reference against MITRE ATT&CK and STIX 2.1 tooling.
- The codebase stays maintainable by any security analyst worldwide.
- Log parsing, grep, future SIEM ingestion all assume English tokens.

**Exceptions** (French is allowed here):
- The operator's private notes under
  `C:\Users\loica\.claude\projects\F--Documents-loicata-WardSOAR\memory\`
  (not shipped with the product).
- Conversation with the assistant — replies mirror the operator's
  language, but any code / commit / UI text produced from that
  conversation remains in English.
- `CLAUDE.md` section headers that were already in French at project
  creation may stay French; new sections are added in English.

**How to enforce**
- Any edit to `src/`, `tests/`, `config/*.yaml` comments, `installer/`,
  or `scripts/` must be in English.
- When translating existing French content, prefer a direct fix over
  a // TODO note; the rule applies retroactively.


### 1. Nouvelle section : Static Security Analysis (après Quality Standards > Code Style)

## Static Security Analysis — Automated on Every Change

### Tools
| Tool | Purpose | Command |
|------|---------|---------|
| bandit | Detect security anti-patterns in Python code | `bandit -r src/ -ll` |
| pip-audit | Check dependencies for known CVEs | `pip-audit -r requirements.txt` |

### Rules
- bandit + pip-audit MUST pass before any commit (same status as black/ruff/mypy)
- Any bandit finding of severity MEDIUM or above MUST be fixed immediately
- Any bandit finding of severity LOW MUST be documented with `# nosec` + justification if intentionally ignored
- Any CVE found by pip-audit MUST be reported to the developer immediately,
  even if the fix is to pin a different version

### Integration into Step 6 — QUALITY checks (updated)
```
black --check --line-length 100 src/ tests/    # formatting
ruff check src/ tests/                          # linting
mypy src/ --strict                              # type checking
bandit -r src/ -ll                              # security scan
pip-audit -r requirements.txt                   # dependency CVE check
```
ALL FIVE must pass before considering the work complete.

### Hook addition
```json
{
  "PostToolUse": [
    {
      "matcher": "Write(*.py)",
      "command": "black --check --line-length 100 $FILE && ruff check $FILE && bandit -ll $FILE"
    }
  ]
}
```

### Dependency addition
Add to `requirements-dev.txt`: `bandit`, `pip-audit`


### 2. Nouvelle section : End-to-End Integration Tests

## End-to-End Integration Tests

### Purpose
Unit tests verify each module in isolation. Integration tests verify
that the full pipeline produces correct outcomes when all modules work together.

### Test scenarios (minimum required set)
| Scenario | Input | Expected outcome |
|----------|-------|------------------|
| True positive — high confidence | Simulated Suricata alert with known malicious IP | Alert passes all 13 stages → pfSense block API called → audit log complete |
| True negative — known false positive | Alert matching known_false_positives.yaml | Suppressed at Filter (stage 1) → no API calls → logged as suppressed |
| True negative — low prescorer score | Alert with severity 3, no reputation data | Stopped at PreScorer (stage 4) → no Claude API call → logged as low_priority |
| Borderline — confirmer disagrees | Alert with confidence 0.6 from Analyzer | Sent to Confirmer → disagreement → logged as INCONCLUSIVE → no block |
| Whitelist protection | Alert from whitelisted IP with confidence 0.99 | Passes all analysis → Responder refuses to block → logged with reason |
| Duplicate flood | 50 identical alerts in 1 second | Deduplicator groups them → only 1 analysis call → 1 decision logged |
| Infrastructure failure | Claude API returns 500 | Fail-safe activates → no block → error logged → pipeline continues |
| Rate limit protection | 25 block requests in 1 hour (limit: 20) | First 20 executed → last 5 rejected → rate limit warning logged |

### Rules
- Integration tests live in `tests/integration/` (separate from unit tests)
- All external services (pfSense API, Claude API, VirusTotal) are mocked
  at the HTTP boundary (use `httpx` mock, not module-level mocks)
- Each test runs the FULL pipeline from alert injection to final logging
- Integration tests are slower — run separately: `pytest tests/integration/ -v`
- Integration tests MUST NOT share state — each test starts with a clean pipeline
- The Replay module should be usable to drive integration tests from saved alert files

### When to run
- After completing any new pipeline module
- After any interface change between modules
- Before any release milestone
- Full suite mandatory in Phase 9 (Integration & Hardening)


### 3. Nouvelle section : Idempotence Guarantee

## Idempotence — Safe Reprocessing

### Principle
If the same alert is processed twice (crash recovery, network retry, duplicate delivery),
the system MUST produce the same outcome without side effects:
- No duplicate pfSense block rules for the same IP
- No duplicate notifications (email/Telegram)
- No duplicate forensic reports
- No duplicate entries in decision log (or clearly marked as reprocessed)

### Implementation requirements
| Module | Idempotence mechanism |
|--------|----------------------|
| Responder | Before blocking: check if IP already has active rule → skip if exists |
| Notifier | Track notification hash (alert_id + verdict) → skip if already sent |
| ForensicReport | Check if report ZIP for this alert_id already exists → skip or append |
| DecisionCache | Store is naturally idempotent (overwrite with same verdict) |
| Logger | Duplicate log entries are acceptable but MUST be flagged with `reprocessed: true` |

### Tests
For each module above, write explicit idempotence tests:
```python
async def test_responder_does_not_double_block():
    """Processing the same alert twice must not create duplicate block rules."""
    responder = Responder(...)
    await responder.block(alert)
    await responder.block(alert)  # same alert again
    assert pfsense_mock.block_call_count == 1
```

### Criticality
Idempotence failures are **severity HIGH** — they cause:
- Duplicate firewall rules (rule table pollution)
- Notification spam (operator fatigue → ignored alerts)
- Forensic evidence contamination (duplicate reports with different timestamps)


### 4. Nouvelle section : Timeout Discipline

## Timeout Discipline — Every External Call Has a Deadline

### Rule
Every call to an external service MUST have an explicit timeout.
No external call is allowed to block the pipeline indefinitely.

### Timeout budget
| External service | Timeout | On timeout action |
|-----------------|---------|-------------------|
| pfSense REST API | 10s | Log error → skip block → continue pipeline |
| Claude API (Analyzer) | 30s | Log error → mark as INCONCLUSIVE → no block |
| Claude API (Confirmer) | 30s | Log error → use Analyzer verdict alone |
| VirusTotal API | 15s | Log warning → continue without VT data |
| Telegram notification | 5s | Log warning → continue (best-effort) |
| Email notification | 10s | Log warning → continue (best-effort) |

### Rules
- Timeouts are defined as named constants in `config.py`, not hardcoded
- Every timeout MUST have a corresponding test that simulates `httpx.TimeoutException`
- The fail-safe behavior on timeout MUST be identical to the behavior on error
  (log → no block → continue)
- Total pipeline timeout for a single alert: 120s max — if exceeded,
  log as `pipeline_timeout` and move to next alert


### 5. Nouvelle section : State Machine Validation (Phase 9)

## State Machine Validation — Alert Lifecycle Integrity

> NOTE: This section is targeted for Phase 9 (Integration & Hardening).
> It is documented here so that module developers anticipate it from Phase 1.

### Alert states
```
RECEIVED → FILTERED_OUT
RECEIVED → DEDUPLICATED (merged into existing group)
RECEIVED → SCORED_LOW (PreScorer below threshold)
RECEIVED → ENRICHED → ANALYZED → CONFIRMED_THREAT → BLOCKED
RECEIVED → ENRICHED → ANALYZED → CONFIRMED_THREAT → BLOCK_REFUSED (whitelist/rate limit)
RECEIVED → ENRICHED → ANALYZED → BORDERLINE → CONFIRMED → BLOCKED
RECEIVED → ENRICHED → ANALYZED → BORDERLINE → CONFIRMED → INCONCLUSIVE
RECEIVED → ENRICHED → ANALYZED → BENIGN
RECEIVED → ENRICHED → ANALYSIS_FAILED → INCONCLUSIVE (fail-safe)
```

### Illegal transitions (MUST be impossible)
- FILTERED_OUT → BLOCKED (filtered alerts can never be blocked)
- SCORED_LOW → BLOCKED (low-score alerts can never be blocked)
- BENIGN → BLOCKED (benign verdict can never lead to blocking)
- Any state → BLOCKED without passing through ANALYZED (no block without analysis)
- RECEIVED → BLOCKED (no direct blocking without the full pipeline)

### Implementation
- The `AlertState` enum in `models.py` MUST define all valid states
- State transitions MUST be validated in a central `transition(alert, new_state)` function
- Any illegal transition raises `IllegalStateTransition` (a custom exception)
- Every state transition is logged with the previous and new state

### Testing
- Test every valid transition path
- Test every illegal transition (must raise exception)
- Use Hypothesis stateful testing to explore random sequences of transitions


### 6. Nouvelle section : Forensic Report Snapshot Testing (Phase 9)

## Forensic Report Snapshot Testing

> NOTE: Targeted for Phase 9. Document here for awareness.

### Purpose
The forensic evidence ZIP has a strict structure expected by law enforcement.
Snapshot testing ensures the structure never drifts unintentionally.

### What to snapshot
- ZIP file listing (all filenames and directory structure)
- README.md structure (section headers, required fields present)
- SHA-256 checksum format (correct hex length, one per file)
- No secret patterns in any file (re-verify after every change)

### Tool
Use `pytest-snapshot` or manual golden-file comparison:
```python
def test_forensic_report_structure(snapshot, sample_alert):
    report = generate_forensic_report(sample_alert)
    file_listing = sorted(zipfile.ZipFile(report).namelist())
    assert file_listing == snapshot
```

### Rules
- Snapshot updates require explicit developer approval (`--snapshot-update`)
- Any snapshot change triggers a mandatory review of the forensic report format
- Snapshot tests are in addition to, not a replacement for, content validation tests


### 7. Nouvelle section : Opus Cross-Review

## Opus Cross-Review — CRITICAL Modules Only

### Process
After a CRITICAL module passes ALL quality gates (Steps 1–8, double-pass,
property-based tests, mutation testing), submit the complete module
(source + tests) to Claude Opus for an adversarial security review.

### Opus review prompt template
```
You are a senior security auditor reviewing a Python module that controls
a production firewall. Your job is to find vulnerabilities, logic errors,
race conditions, and ways to bypass safety mechanisms.

Module: {module_name}
Purpose: {module_description}
Criticality: CRITICAL — errors can block legitimate traffic or miss real attacks

Source code:
{source_code}

Test code:
{test_code}

Instructions:
1. List every potential vulnerability, ranked by severity
2. For each: describe the attack scenario, the impact, and a fix
3. Identify any missing test cases
4. Verify that fail-safe behavior is correct in all error paths
5. Check for race conditions in async code
6. Verify that whitelist/rate-limit protections cannot be bypassed
```

### When to use
- After completing each of the 8 CRITICAL modules
- After any significant refactoring of a CRITICAL module
- Before Phase 9 integration milestone

### Rules
- Opus review findings are treated as bugs — each one gets a test + fix
- Opus review is NOT a replacement for the developer's own review
- Cost/time budget: ~1 Opus call per CRITICAL module (~8 calls total for the project)


### 8. Mise à jour : Updated Dependency Lists

### requirements-dev.txt additions
```
# Static security analysis
bandit
pip-audit

# Property-based testing
hypothesis

# Mutation testing
mutmut

# Snapshot testing (Phase 9)
pytest-snapshot
```

### 9. Mise à jour : Updated Step 7 Self-Review Checklist

Add these items to the existing Step 7 checklist:

- [ ] Every external call has an explicit timeout (see Timeout Discipline table)
- [ ] Timeout fail-safe behavior is tested
- [ ] Module is idempotent — reprocessing the same input produces no side effects
- [ ] Idempotence is tested explicitly
- [ ] bandit reports no findings of severity MEDIUM or above
- [ ] For CRITICAL modules: Pass 2 (adversary review) completed and findings documented
- [ ] For CRITICAL modules: property-based tests cover key invariants
- [ ] For CRITICAL modules: mutation score ≥ 85%
- [ ] Any new module touches PySide6/qfluentwidgets only if it lives under
      `packages/wardsoar-pc/src/wardsoar/pc/ui/` (UI layering — see section 10)


### 10. UI architecture & layering — native Qt only, business logic Qt-free

## UI layering — PySide6 only inside ``ui/``

### Decision (2026-04-25)
WardSOAR keeps a 100% native PySide6 + Fluent Design UI
(``PySide6-Fluent-Widgets``, GPL-3.0, license-compatible).

- **No webview, no QWebEngineView, no local HTTP server.**
  Eliminates the local network attack surface (CSRF, DNS rebinding,
  XSS through Suricata payloads) and saves ~150 MB on the MSI by
  not bundling Chromium.
- **Strict separation of business logic and presentation.**
  PySide6 / qfluentwidgets imports are forbidden anywhere except
  ``packages/wardsoar-pc/src/wardsoar/pc/ui/``.

### Layer contract

| Layer | Path | Imports allowed |
|-------|------|-----------------|
| core (cross-platform) | `packages/wardsoar-core/src/wardsoar/core/` | stdlib, `wardsoar.core.*`, third-party non-Qt |
| pc (Windows-specific business logic) | `packages/wardsoar-pc/src/wardsoar/pc/` (excluding `ui/`) | as core + pywin32, WMI, Sysmon, YARA, Defender |
| ui (presentation) | `packages/wardsoar-pc/src/wardsoar/pc/ui/` | everything above + PySide6, qfluentwidgets, shiboken6 |
| controllers (UI ↔ core bridge) | `packages/wardsoar-pc/src/wardsoar/pc/ui/controllers/` | as ui — but should be the only place where Qt signals/slots wrap core API |

Modules outside ``ui/`` MUST NOT contain ``from PySide6`` or
``import PySide6``. Same for ``qfluentwidgets``, ``PyQt5``,
``PyQt6``, ``shiboken6``.

### Enforcement (automated)

| Mechanism | Location |
|-----------|----------|
| Architectural test | `packages/wardsoar-core/tests/test_architecture.py` (regex scan; fails the suite if Qt is imported anywhere outside `ui/`) |
| Lint rule | `[tool.ruff.lint.flake8-tidy-imports.banned-api]` in `pyproject.toml` (TID251) — ruff fails the build if any source file outside `ui/` imports the banned modules |
| Pre-commit hook | `.pre-commit-config.yaml` runs ruff + the architecture test on every commit |

To activate the pre-commit hook locally after cloning:

```powershell
.venv\Scripts\pip install pre-commit
.venv\Scripts\pre-commit install
```

Run a CI-equivalent sweep manually:

```powershell
.venv\Scripts\pre-commit run --all-files
.venv\Scripts\pre-commit run --hook-stage manual pip-audit
```

### Coverage targets per layer

| Layer | Minimum coverage |
|-------|------------------|
| `wardsoar.core` | **90%** |
| `wardsoar.pc.ui.controllers` | **80%** |
| `wardsoar.pc.ui` (widgets/views) | **70%** |
| `wardsoar.pc` (non-ui Windows logic) | **80%** |

Configured in ``pyproject.toml`` ``[tool.coverage]`` (cf. section 11
of this file). The pre-commit hook does not gate on coverage today
(too slow); the project CI gates on these thresholds.

### Justification

This separation preserves three options at no immediate cost:
1. Unit-testing core business logic without a `QApplication`.
2. Reusing core modules in other loicata products
   (Virus Sniff appliance — Linux ARM64, no Qt).
3. Exposing a future API surface without untangling presentation
   from logic.
