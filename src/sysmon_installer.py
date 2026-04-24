"""Legacy shim for ``wardsoar.pc.sysmon_installer``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.sysmon_installer import *  # noqa: F401,F403
