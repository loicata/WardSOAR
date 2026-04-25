"""Architectural enforcement — UI layering decision (2026-04-25).

WardSOAR keeps a 100% native PySide6 + Fluent Design UI. Business
logic (Suricata parsing, triage, SOAR playbooks, forensics, reporting)
must not import PySide6 / qfluentwidgets so it stays:

- testable without a QApplication
- reusable in non-Qt contexts (Virus Sniff appliance, future CLI/API)
- decoupled from the presentation layer

The only place allowed to import Qt is
``packages/wardsoar-pc/src/wardsoar/pc/ui/``. Anywhere else under the
three package src trees fails this test.

If you genuinely need a Qt-touching module, move it under ``ui/``,
or split the Qt usage into a thin controller that lives in
``ui/controllers/``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

PACKAGE_SRC_DIRS = [
    REPO_ROOT / "packages" / "wardsoar-core" / "src" / "wardsoar" / "core",
    REPO_ROOT / "packages" / "wardsoar-pc" / "src" / "wardsoar" / "pc",
    REPO_ROOT / "packages" / "wardsoar-virus-sniff" / "src" / "wardsoar" / "vs",
]

UI_ALLOWLIST = REPO_ROOT / "packages" / "wardsoar-pc" / "src" / "wardsoar" / "pc" / "ui"

BANNED_TOP_LEVEL_MODULES = ("PySide6", "PyQt5", "PyQt6", "qfluentwidgets", "shiboken6")

# Skip runtime / build dirs that may sit inside src/ trees (sealed
# evidence, PyInstaller build, egg-info). These are gitignored but
# remain on disk and would crash rglob with PermissionError.
_SKIP_DIRS = {
    "__pycache__",
    "evidence",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

_BAN_RE = re.compile(
    r"^\s*(?:from|import)\s+("
    + "|".join(re.escape(m) for m in BANNED_TOP_LEVEL_MODULES)
    + r")(?:\.[\w.]*)?\b",
    re.MULTILINE,
)


def _gather_python_files() -> list[Path]:
    files: list[Path] = []
    for src in PACKAGE_SRC_DIRS:
        if not src.is_dir():
            continue
        for root, dirs, filenames in os.walk(src):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = Path(root) / fn
                try:
                    path.relative_to(UI_ALLOWLIST)
                    continue  # ui/ subtree is the one place Qt is allowed
                except ValueError:
                    pass
                files.append(path)
    return files


def test_no_qt_imports_outside_ui() -> None:
    """Scan every .py outside ``ui/`` for banned Qt/Fluent imports.

    Adding a Qt-touching module under non-ui paths is a red flag:
    either move it into ``wardsoar.pc.ui``, or refactor the Qt usage
    into a thin controller that lives in ``ui/controllers/``.
    """
    offenders: list[str] = []
    for path in _gather_python_files():
        text = path.read_text(encoding="utf-8")
        for match in _BAN_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"  {path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0).strip()}")

    assert not offenders, (
        "Qt/Fluent imports found outside packages/wardsoar-pc/.../ui/:\n"
        + "\n".join(offenders)
        + "\n\nMove the Qt code into wardsoar.pc.ui or split the module "
        "(see docs/ARCHITECTURE.md — 'UI layering')."
    )


def test_scan_finds_at_least_one_file() -> None:
    """Sanity check — make sure the scanner is actually walking the tree.

    A subtle path or ``_SKIP_DIRS`` change could silently make the
    main test scan zero files and falsely pass. This guard rail
    prevents that regression.
    """
    files = _gather_python_files()
    assert len(files) > 50, (
        f"Architecture scanner saw only {len(files)} files — "
        "PACKAGE_SRC_DIRS or _SKIP_DIRS likely misconfigured."
    )
