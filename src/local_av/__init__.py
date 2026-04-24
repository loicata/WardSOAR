"""Privacy-first local AV cascade.

Runs local scanners (Windows Defender, YARA) before reaching out to
VirusTotal. A positive verdict from a local scanner short-circuits the
cascade, so no hash is leaked to VT for files we can already judge.

The orchestrator exposes a single entry point, `FileScanOrchestrator.scan`,
that mirrors the original `VirusTotalClient.check_file` signature, making
it a drop-in replacement in the pipeline.
"""

from __future__ import annotations

from src.local_av.defender import DefenderScanner
from src.local_av.orchestrator import FileScanOrchestrator
from src.local_av.yara_scanner import YaraScanner

__all__ = ["DefenderScanner", "FileScanOrchestrator", "YaraScanner"]
