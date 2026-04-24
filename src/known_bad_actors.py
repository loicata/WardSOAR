"""Legacy shim for ``wardsoar.core.known_bad_actors``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.known_bad_actors import *  # noqa: F401,F403
