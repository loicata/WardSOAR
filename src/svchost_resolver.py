"""Legacy shim for ``wardsoar.pc.svchost_resolver``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.svchost_resolver import *  # noqa: F401,F403
