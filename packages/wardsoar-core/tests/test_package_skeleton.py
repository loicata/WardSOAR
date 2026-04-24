"""Smoke test — confirms the package is importable before any real code
lands. Prevents the skeleton from regressing silently while we build
the migration around it."""

from __future__ import annotations


def test_import_package() -> None:
    from wardsoar import core

    assert core.__version__ == "0.0.1"


def test_namespace_is_implicit() -> None:
    """The ``wardsoar`` namespace must be a PEP 420 implicit namespace
    package so wardsoar-pc and wardsoar-virus-sniff can contribute to
    it without colliding at install time."""
    import wardsoar

    # Implicit namespaces have no ``__file__`` (nothing to load).
    assert not hasattr(wardsoar, "__file__") or wardsoar.__file__ is None
