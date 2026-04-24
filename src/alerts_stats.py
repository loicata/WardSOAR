"""Legacy shim for ``wardsoar.core.alerts_stats``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.alerts_stats import *  # noqa: F401,F403
