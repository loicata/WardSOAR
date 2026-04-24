"""Legacy shim for ``wardsoar.core.bootstrap_checklist``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.bootstrap_checklist import *  # noqa: F401,F403
