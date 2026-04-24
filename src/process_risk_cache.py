"""Legacy shim for ``wardsoar.pc.process_risk_cache``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.process_risk_cache import *  # noqa: F401,F403
