"""Legacy shim for ``wardsoar.pc.forensic.manifest``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.forensic.manifest import *  # noqa: F401,F403
