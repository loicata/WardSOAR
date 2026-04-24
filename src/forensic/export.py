"""Legacy shim for ``wardsoar.pc.forensic.export``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.forensic.export import *  # noqa: F401,F403
