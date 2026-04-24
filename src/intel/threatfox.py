"""Legacy shim for ``wardsoar.core.intel.threatfox``.

Re-exports the canonical module so existing ``from src.intel.threatfox
import ...`` calls keep working during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.intel.threatfox import *  # noqa: F401,F403
