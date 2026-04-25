"""WardSOAR core — cross-platform pipeline and models.

This package is the portable foundation. It must run unmodified on
Windows (WardSOAR PC) and Linux ARM64 (Virus Sniff). Any import of a
platform-specific module (``win32api``, ``wmi``, ``PySide6``,
``Flask``, ``nftables``, etc.) belongs in a sibling package, not here.

No module-level ``__version__`` is exposed here on purpose: the
shipped product version lives in :mod:`wardsoar.pc` (the package the
MSI installs) and is read from there for display, packaging and WiX.
A leftover ``__version__ = "0.0.1"`` placeholder once lived in this
file and was accidentally surfaced in the About dialog as ``v0.0.1``
on the v0.22.9 install — fixed by importing from ``wardsoar.pc``
instead. Don't reintroduce a placeholder here.
"""
