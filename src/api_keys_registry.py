"""Legacy shim for ``wardsoar.core.api_keys_registry``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.core.api_keys_registry import *  # noqa: F401,F403
