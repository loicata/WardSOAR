"""Legacy shim for ``wardsoar.core.change_manager``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.change_manager import *  # noqa: F401,F403
