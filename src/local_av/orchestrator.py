"""Cascade orchestrator: Defender → YARA → VirusTotal.

Privacy-first philosophy: every stage is local except the last. A positive
verdict from Defender or YARA short-circuits the cascade so the file's
hash never leaves the machine. VirusTotal is queried only when both
local scanners are silent or unavailable.

Entry point mirrors `VirusTotalClient.check_file` — the pipeline can
swap the client for an orchestrator without further changes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from src.local_av.defender import DefenderScanner
from src.local_av.yara_scanner import YaraScanner
from src.models import VirusTotalResult
from src.virustotal import VirusTotalClient

logger = logging.getLogger("ward_soar.local_av")


class FileScanOrchestrator:
    """Drive the privacy-first scan cascade for a single file.

    Args:
        defender: Windows Defender scanner (stage 1).
        yara: YARA scanner (stage 2).
        vt_client: VirusTotal client (stage 3, online).
    """

    def __init__(
        self,
        defender: DefenderScanner,
        yara: YaraScanner,
        vt_client: VirusTotalClient,
    ) -> None:
        self._defender = defender
        self._yara = yara
        self._vt = vt_client

    async def check_file(self, file_path: str) -> Optional[VirusTotalResult]:
        """Run the cascade; return the first positive verdict or VT result.

        Args:
            file_path: Path to the file to scan.

        Returns:
            VirusTotalResult with `lookup_type` set to the winning stage,
            or None if every stage declined (scanners disabled / failed /
            clean plus VT silent).
        """
        path = Path(file_path)
        if not path.is_file():
            logger.debug("Cascade skipped — file not found: %s", file_path)
            return None

        # Hash once up-front. Every stage needs it (Defender embeds it in
        # its result, YARA embeds it in its result, VT uses it as cache
        # key and API parameter).
        try:
            file_hash = VirusTotalClient.compute_sha256(file_path)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.warning("Cascade aborted — cannot hash %s: %s", file_path, exc)
            return None

        # Stage 1 — Windows Defender (offline, authoritative on detection)
        defender_verdict = await self._defender.scan(file_path, file_hash)
        if defender_verdict is not None and defender_verdict.is_malicious:
            logger.info("Cascade stopped at Defender for %s", file_path)
            return defender_verdict

        # Stage 2 — YARA rules (offline, fast)
        yara_verdict = await self._yara.scan(file_path, file_hash)
        if yara_verdict is not None and yara_verdict.is_malicious:
            logger.info("Cascade stopped at YARA for %s", file_path)
            return yara_verdict

        # Stage 3 — VirusTotal (online, cached, rate-limited).
        # We reach this only when both local scanners were silent — i.e.
        # we have genuine uncertainty worth spending a VT quota unit on.
        vt_verdict = await self._vt.lookup_hash(file_hash)
        if vt_verdict is not None:
            logger.debug("Cascade: VT verdict for %s", file_path)
            return vt_verdict

        # If Defender returned a "clean" verdict (non-None, not malicious),
        # surface it as the final answer rather than None — that's useful
        # context for the Analyzer.
        if defender_verdict is not None:
            return defender_verdict

        return None

    async def scan_files(self, files: list[dict[str, Any]]) -> list[VirusTotalResult]:
        """Run the cascade on every file; return only positive / clean verdicts.

        Args:
            files: List of file dicts as produced by
                   `ForensicAnalyzer.find_suspicious_files` (each with "path").

        Returns:
            Non-empty VirusTotalResult entries. None responses are dropped.
        """
        results: list[VirusTotalResult] = []
        for entry in files:
            path = entry.get("path")
            if not path:
                continue
            verdict = await self.check_file(path)
            if verdict is not None:
                results.append(verdict)
        return results
