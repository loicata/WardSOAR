"""Shared pytest configuration for wardsoar-core tests.

Isolates every test from the operator's real data directory. Without
this, tests that touch ``user_false_positives``, ``config``, or any
module calling ``get_data_dir()`` end up reading / writing the live
``%APPDATA%\\WardSOAR`` (or repo-root) state, which makes the results
operator-dependent. Setting ``WARDSOAR_DATA_DIR`` to a pytest tmp
directory scopes every write to a per-session throwaway location.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Point ``get_data_dir()`` at a disposable directory for the test."""
    sandbox = tmp_path_factory.mktemp("wardsoar_data", numbered=True)
    monkeypatch.setenv("WARDSOAR_DATA_DIR", str(sandbox))
    return sandbox
