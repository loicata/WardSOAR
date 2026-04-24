"""Legacy import shim for ``wardsoar.core.models``.

This file stays in place during the monorepo migration so that
unmigrated callers (``from src.models import ...``) keep working
while the canonical location moves to ``wardsoar.core.models``.

The shim re-exports every public symbol explicitly so ``mypy
--strict`` stays happy and IDE "go to definition" jumps straight to
the canonical file.

Remove this file once every caller uses ``wardsoar.core.models``.
"""

from __future__ import annotations

from wardsoar.core.models import (
    BlockAction,
    DecisionRecord,
    ForensicResult,
    IPReputation,
    NetworkContext,
    ResponseAction,
    SuricataAlert,
    SuricataAlertSeverity,
    SysmonEvent,
    ThreatAnalysis,
    ThreatVerdict,
    VirusTotalResult,
    WardMode,
)

__all__ = [
    "BlockAction",
    "DecisionRecord",
    "ForensicResult",
    "IPReputation",
    "NetworkContext",
    "ResponseAction",
    "SuricataAlert",
    "SuricataAlertSeverity",
    "SysmonEvent",
    "ThreatAnalysis",
    "ThreatVerdict",
    "VirusTotalResult",
    "WardMode",
]
