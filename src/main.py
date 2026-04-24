"""Legacy shim for ``wardsoar.pc.main``.

Preserved for backwards-compatible imports (``from src.main import
Pipeline``, ``from src.main import main``) while the monorepo
migration finishes. The MSI entry point in
``installer/ward.spec`` still points here until that file is
updated to target ``wardsoar.pc.main`` directly.
"""

from __future__ import annotations

from wardsoar.pc.main import *  # noqa: F401,F403
from wardsoar.pc.main import FilteredResult, Pipeline, main  # explicit

__all__ = ["FilteredResult", "Pipeline", "main"]
