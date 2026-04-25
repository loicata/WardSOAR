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
