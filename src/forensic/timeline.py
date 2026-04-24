"""Legacy shim for ``wardsoar.pc.forensic.timeline``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.forensic.timeline import *  # noqa: F401,F403
