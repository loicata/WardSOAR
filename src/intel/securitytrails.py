"""Legacy shim for ``wardsoar.core.intel.securitytrails``.

Re-exports the canonical module so existing ``from src.intel.securitytrails
import ...`` calls keep working during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.intel.securitytrails import *  # noqa: F401,F403
