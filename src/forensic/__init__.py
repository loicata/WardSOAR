"""Post-block forensic acquisition and chain-of-custody.

Kicks in after `ThreatResponder` successfully adds an IP to the pfSense
blocklist. The goal is to freeze volatile evidence (process list,
network state, DNS cache…) before it changes, write it to a protected
evidence directory, and produce a signed-ish manifest so the operator
or an external expert can reason about the incident later.

Philosophy (see docs/architecture.md §3):
    - Quick phase = acquisition only, no analysis, no LLM.
    - Chain of custody: every artefact SHA-256'd at write time.
    - Fail-safe: an acquisition step may degrade (missing permission,
      PowerShell unavailable) but must never crash the pipeline.

Public API:
    - QuickAcquisitionManager: entry point wired from Pipeline.
    - ForensicManifest: artefact index + hashes.
    - ProtectedEvidenceStorage: write-only evidence directory.
"""

from __future__ import annotations

from src.forensic.acquisition import VolatileAcquirer
from src.forensic.attack_mapper import AttackMapper, TechniqueMatch
from src.forensic.deep_orchestrator import (
    DeepAnalysisOrchestrator,
    DeepAnalysisResult,
)
from src.forensic.export import DeepReportExporter, ExportBundleResult
from src.forensic.ioc_extractor import IocExtractor
from src.forensic.manifest import ForensicManifest, ManifestEntry
from src.forensic.orchestrator import (
    QuickAcquisitionManager,
    QuickAcquisitionResult,
)
from src.forensic.storage import ProtectedEvidenceStorage
from src.forensic.timeline import TimelineBuilder, TimelineEntry

__all__ = [
    "AttackMapper",
    "DeepAnalysisOrchestrator",
    "DeepAnalysisResult",
    "DeepReportExporter",
    "ExportBundleResult",
    "ForensicManifest",
    "IocExtractor",
    "ManifestEntry",
    "ProtectedEvidenceStorage",
    "QuickAcquisitionManager",
    "QuickAcquisitionResult",
    "TechniqueMatch",
    "TimelineBuilder",
    "TimelineEntry",
    "VolatileAcquirer",
]
