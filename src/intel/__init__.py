"""Legacy shim for ``wardsoar.core.intel`` (and submodules).

Re-exports the canonical package so ``from src.intel.X import Y``
keeps working during the monorepo migration. Each submodule has its
own sibling shim that re-exports its public symbols.
"""

from __future__ import annotations

from wardsoar.core.intel import *  # noqa: F401,F403
