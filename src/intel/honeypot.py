"""Legacy shim for ``wardsoar.core.intel.honeypot``.

Re-exports the canonical module so existing ``from src.intel.honeypot
import ...`` calls keep working during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.intel.honeypot import *  # noqa: F401,F403
