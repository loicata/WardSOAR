"""Legacy shim for ``wardsoar.core.analyzer``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.analyzer import *  # noqa: F401,F403
