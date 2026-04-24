"""Smoke test — confirms the Virus Sniff skeleton is importable.
The full test suite will grow as the appliance is implemented on
Linux; for now we just make sure the namespace and packaging are
sound."""

from __future__ import annotations


def test_import_package() -> None:
    from wardsoar import vs

    assert vs.__version__ == "0.0.1"
