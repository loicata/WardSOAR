"""Windows Defender local file scanner.

Wraps `MpCmdRun.exe -Scan -ScanType 3 -File <path>` to obtain a verdict
without sending data to a remote service. This is the first stage of the
privacy-first cascade.

Return codes (from Microsoft docs):
    0  → No threat detected
    2  → Threat(s) found and remediated
    >0 → Error or threat present

We treat a non-zero exit code combined with threat-name output as a
positive detection, and a zero exit code as clean.

Fail-safe: any error (Defender not installed, disabled by policy, SYSTEM
access denied) returns None so the cascade can continue to YARA / VT.
"""

from __future__ import annotations

import logging
import re
import subprocess  # nosec B404 — required to invoke Windows Defender CLI; hardcoded args
from pathlib import Path
from subprocess import (  # nosec B404 — exception classes, not execution
    CompletedProcess,
    TimeoutExpired,
)
from typing import Any, Optional

from wardsoar.pc import win_paths
from wardsoar.core.models import VirusTotalResult

logger = logging.getLogger("ward_soar.defender")


DEFAULT_TIMEOUT_SECONDS = 60

# MpCmdRun emits a line like "Threat  : <ThreatName>" on detection.
_THREAT_LINE_RE = re.compile(r"^Threat\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)


class DefenderScanner:
    """Invoke Windows Defender on a single file and parse the verdict.

    Args:
        config: Defender configuration dict from config.yaml.
                Supported keys:
                    enabled (bool) — default True
                    timeout_seconds (int) — default 60
                    mpcmdrun_path (str) — override path to MpCmdRun.exe
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        cfg = config or {}
        self._enabled: bool = bool(cfg.get("enabled", True))
        self._timeout: int = int(cfg.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
        self._mpcmdrun: str = str(cfg.get("mpcmdrun_path", win_paths.MPCMDRUN))
        # Cache the availability check — no point retrying MpCmdRun lookup
        # on every alert.
        self._available = self._probe_available()

    def _probe_available(self) -> bool:
        """Check at startup whether MpCmdRun.exe is present and usable."""
        if not self._enabled:
            return False
        if not Path(self._mpcmdrun).is_file():
            logger.warning(
                "Defender scanner disabled: MpCmdRun.exe not found at %s",
                self._mpcmdrun,
            )
            return False
        return True

    async def scan(self, file_path: str, file_hash: str) -> Optional[VirusTotalResult]:
        """Scan a file with Windows Defender.

        Args:
            file_path: Absolute path to the file to scan.
            file_hash: Pre-computed SHA-256 of the file (reused in the result).

        Returns:
            VirusTotalResult tagged with lookup_type="defender" on detection,
            a clean VirusTotalResult if Defender says no threat, or None if
            Defender is unavailable or the scan failed.
        """
        if not self._available:
            return None

        try:
            result = await self._run_mpcmdrun(file_path)
        except (TimeoutExpired, OSError, FileNotFoundError) as exc:
            logger.warning("Defender scan failed for %s: %s", file_path, exc)
            return None

        threat_name = self._extract_threat_name(result.stdout or "")

        if threat_name:
            logger.info(
                "Defender detection: %s (threat=%s, rc=%d)",
                file_path,
                threat_name,
                result.returncode,
            )
            return VirusTotalResult(
                file_hash=file_hash,
                file_name=Path(file_path).name,
                detection_count=1,
                total_engines=1,
                detection_ratio=1.0,
                is_malicious=True,
                threat_labels=[f"defender:{threat_name}"],
                lookup_type="defender",
            )

        if result.returncode == 0:
            logger.debug("Defender: clean verdict for %s", file_path)
            return VirusTotalResult(
                file_hash=file_hash,
                file_name=Path(file_path).name,
                detection_count=0,
                total_engines=1,
                detection_ratio=0.0,
                is_malicious=False,
                threat_labels=[],
                lookup_type="defender",
            )

        # Non-zero exit without a parsed threat name → inconclusive, fail-safe.
        logger.debug("Defender: inconclusive scan of %s (rc=%d)", file_path, result.returncode)
        return None

    async def _run_mpcmdrun(self, file_path: str) -> CompletedProcess[str]:
        """Invoke MpCmdRun synchronously (subprocess.run wrapped to look async).

        The scan itself blocks for a few hundred ms, which is comparable to
        awaiting an async call — we don't bother with asyncio.subprocess
        because MpCmdRun does not stream anything useful.
        """
        return subprocess.run(  # nosec B603 — absolute path, hardcoded args, file_path validated upstream
            [
                self._mpcmdrun,
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                file_path,
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            timeout=self._timeout,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )

    @staticmethod
    def _extract_threat_name(stdout: str) -> Optional[str]:
        """Pull the first threat name out of MpCmdRun stdout, or None."""
        match = _THREAT_LINE_RE.search(stdout)
        if match:
            return match.group(1).strip()
        return None
