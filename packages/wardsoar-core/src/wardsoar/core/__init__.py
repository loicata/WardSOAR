"""WardSOAR core — cross-platform pipeline and models.

This package is the portable foundation. It must run unmodified on
Windows (WardSOAR PC) and Linux ARM64 (Virus Sniff). Any import of a
platform-specific module (``win32api``, ``wmi``, ``PySide6``,
``Flask``, ``nftables``, etc.) belongs in a sibling package, not here.

The package is currently a skeleton. Modules will be migrated in from
the legacy ``src/`` layout in the upcoming refactor phases.
"""

__version__ = "0.0.1"
