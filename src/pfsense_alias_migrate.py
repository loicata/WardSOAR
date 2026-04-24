"""Legacy shim for ``wardsoar.core.remote_agents.pfsense_alias_migrate``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.remote_agents.pfsense_alias_migrate import *  # noqa: F401,F403
