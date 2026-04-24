"""Legacy shim for ``wardsoar.pc.process_snapshot_buffer``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.process_snapshot_buffer import *  # noqa: F401,F403
