"""Legacy shim for ``wardsoar.core.intel.http_client_base``.

Re-exports the canonical module so existing ``from src.intel.http_client_base
import ...`` calls keep working during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.intel.http_client_base import *  # noqa: F401,F403
