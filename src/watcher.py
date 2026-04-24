"""Legacy shim for ``wardsoar.core.watcher``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.watcher import *  # noqa: F401,F403
