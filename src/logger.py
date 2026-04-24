"""Legacy import shim for ``wardsoar.core.logger``.

Re-exports the canonical module so ``from src.logger import ...``
keeps working during the monorepo migration. Remove once every
caller has switched to ``wardsoar.core.logger``.
"""

from __future__ import annotations

from wardsoar.core.logger import (
    JSONFormatter,
    log_decision,
    setup_logging,
)

__all__ = [
    "JSONFormatter",
    "log_decision",
    "setup_logging",
]
