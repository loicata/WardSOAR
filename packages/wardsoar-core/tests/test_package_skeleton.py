"""Smoke test — confirms the package is importable before any real code
lands. Prevents the skeleton from regressing silently while we build
the migration around it."""

from __future__ import annotations


def test_import_package() -> None:
    """The wardsoar.core namespace package is importable.

    Historically asserted ``core.__version__ == "0.0.1"`` (skeleton
    placeholder). Removed in v0.22.10 because that placeholder was
    accidentally surfaced on the About dialog as ``v0.0.1``; the
    shipped product version lives on :mod:`wardsoar.pc`.
    """
    from wardsoar import core

    assert core is not None
    assert not hasattr(core, "__version__"), (
        "wardsoar.core must not expose __version__ — the shipped "
        "version belongs on wardsoar.pc (read by pyproject.toml + WiX)."
    )


def test_namespace_is_implicit() -> None:
    """The ``wardsoar`` namespace must be a PEP 420 implicit namespace
    package so wardsoar-pc and wardsoar-virus-sniff can contribute to
    it without colliding at install time."""
    import wardsoar

    # Implicit namespaces have no ``__file__`` (nothing to load).
    assert not hasattr(wardsoar, "__file__") or wardsoar.__file__ is None
