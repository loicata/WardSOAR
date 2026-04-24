"""Shared pytest configuration for wardsoar-pc tests.

Same rationale as wardsoar-core's conftest: isolate every test from
the operator's real ``%APPDATA%\\WardSOAR`` so running the suite
does not pollute live alerts, evidence, tracker state, or config
overlays.
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
