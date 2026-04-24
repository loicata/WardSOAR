"""Legacy shim for ``wardsoar.pc.forensic.encryption``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.forensic.encryption import *  # noqa: F401,F403
