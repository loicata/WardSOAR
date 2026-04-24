"""Legacy shim for ``wardsoar.pc.forensic``.

Re-exports the canonical package so ``from src.forensic.X import Y``
keeps working during the monorepo migration.
"""

from __future__ import annotations

from wardsoar.pc.forensic import *  # noqa: F401,F403
