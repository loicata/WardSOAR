"""Smoke test — confirms the wardsoar-pc skeleton is importable and
that the ``wardsoar`` namespace is shared with wardsoar-core without
collision."""

from __future__ import annotations

import os

import pytest


def test_import_package() -> None:
    from wardsoar import pc

    assert pc.__version__ == "0.0.1"


@pytest.mark.skipif(os.name != "nt", reason="wardsoar-pc only meaningful on Windows")
def test_namespace_shared_with_core() -> None:
    """Importing both siblings under the same ``wardsoar`` namespace
    must not raise — this is the whole point of the implicit namespace
    package layout."""
    from wardsoar import core, pc

    assert core.__version__
    assert pc.__version__
