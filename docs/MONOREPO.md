# Monorepo layout

> Created in Phase 0 of the monorepo refactor, 2026-04-24.
> See `ARCHITECTURE.md` section 3 for the decision rationale.

---

## Structure

```
WardSOAR/
|-- packages/
|   |-- wardsoar-core/              cross-platform (Linux + Windows)
|   |   |-- pyproject.toml
|   |   |-- src/wardsoar/core/
|   |   |-- tests/
|   |   `-- README.md
|   |
|   |-- wardsoar-pc/                Windows-only (WardSOAR PC)
|   |   |-- pyproject.toml
|   |   |-- src/wardsoar/pc/
|   |   |-- tests/
|   |   `-- README.md
|   |
|   `-- wardsoar-virus-sniff/       Linux ARM64 (Virus Sniff appliance)
|       |-- pyproject.toml
|       |-- src/wardsoar/vs/
|       |-- tests/
|       `-- README.md
|
|-- src/                            legacy — being migrated into packages/
|-- tests/                          legacy — being migrated into packages/*/tests
|
|-- pyproject.toml                  workspace root (uv workspace declaration)
|-- requirements.txt                legacy, kept until MSI build path is migrated
`-- requirements-dev.txt            legacy
```

## Namespace packaging

All three packages contribute to the same top-level Python namespace
`wardsoar` using **PEP 420 implicit namespace packages**:

| Package | Importable as |
|---|---|
| `wardsoar-core` | `from wardsoar.core import ...` |
| `wardsoar-pc` | `from wardsoar.pc import ...` |
| `wardsoar-virus-sniff` | `from wardsoar.vs import ...` |

There is intentionally **no** `src/wardsoar/__init__.py` in any
package so installers do not fight over the namespace root.

## Dev workflow

### Option A — `uv` (recommended once adopted)

```bash
# Install all workspace members in editable mode
uv sync

# Run the full suite
uv run pytest

# Run one package's tests
uv run --package wardsoar-core pytest packages/wardsoar-core/tests
```

### Option B — pip (works today with the existing `.venv`)

```bash
# Editable install of every package
.venv/Scripts/pip install \
    -e packages/wardsoar-core \
    -e packages/wardsoar-pc \
    -e packages/wardsoar-virus-sniff

# Run each test suite
.venv/Scripts/pytest packages/wardsoar-core/tests
.venv/Scripts/pytest packages/wardsoar-pc/tests
.venv/Scripts/pytest packages/wardsoar-virus-sniff/tests

# Legacy tests (while migration is in progress)
.venv/Scripts/pytest tests
```

## Migration plan

The legacy `src/` layout is progressively moved into the `packages/`
layout. The phases are:

| Phase | Scope | Status |
|---|---|---|
| 0 | Skeleton structure + workspace setup | **done** (2026-04-24) |
| 1 | Extract `wardsoar-core` (models, analyzer, intel, pipeline, `pfsense_ssh` -> `RemoteAgent`) | pending |
| 2 | Extract `wardsoar-pc` (forensics, UI, DPAPI, local_av, setup wizard) | pending |
| 3 | Introduce OS-agnostic abstractions (`LocalForensicsProvider`, `LocalBlocker`, `CredentialStore`) in core; implement Windows versions in pc | pending |
| 4 | Populate `wardsoar-virus-sniff` (web UI, routing, provisioning) | pending, after Suricata-on-PC integration |

During phases 1-3:
- The legacy `src/` keeps building the MSI and running the pipeline.
- Code is moved, not copied — each module migrated is deleted from
  `src/` in the same commit that creates its new home.
- Tests move with their code.
- Every commit keeps `pytest packages/` and `pytest tests` both
  green.

## Why the split

- **Build targets are fundamentally different**: MSI for Windows PC,
  SD/SSD image for Linux ARM64. Mixing them would force the MSI to
  ship bytes that do not apply and the appliance to ship bytes it
  must not run.
- **Dependency graphs are disjoint**: PySide6 + pywin32 on one side,
  Flask/FastAPI + nftables on the other. Splitting the dependency
  files prevents accidental cross-imports that would not survive
  platform migration.
- **Release cadence will desynchronise**: once Virus Sniff ships, its
  releases should not be gated on the desktop application and
  vice-versa. Independent `pyproject.toml` and version numbers are
  what allow that.

Alternatives considered and rejected: a single project with
`extras_require = {"pc": [...], "vs": [...]}` (Option 1 — fragile for
build targets); flat namespace like `wardsoar_core / wardsoar_pc`
(Option 3 — no real decoupling). See `ARCHITECTURE.md` section 5 for
the full reasoning.

## Future tooling decisions

Still to be decided as the migration progresses:

- **uv as the default tool** — currently installed in the local
  `.venv` for experimentation. The build script (`scripts/build.ps1`)
  will switch to `uv` once the migration is complete.
- **Linting scope** — black / ruff / mypy are run across the whole
  tree today. Each package will likely gain its own lint config so
  Windows-only vs. Linux-only type stubs can differ.
- **CI** — no CI yet. When added, each package should have its own
  job matrix (core: Linux + Windows; pc: Windows only; virus-sniff:
  Linux ARM64 only).
