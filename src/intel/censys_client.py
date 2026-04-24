"""Legacy shim for ``wardsoar.core.intel.censys_client``.

Re-exports the canonical module so existing ``from src.intel.censys_client
import ...`` calls keep working during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.intel.censys_client import *  # noqa: F401,F403
