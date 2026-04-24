"""Legacy shim for ``wardsoar.pc.forensic.report_pdf``.

Re-exports the canonical module during the monorepo migration.
Remove once every caller has switched to the canonical path.
"""

from __future__ import annotations

from wardsoar.pc.forensic.report_pdf import *  # noqa: F401,F403
