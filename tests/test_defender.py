"""Tests for WardSOAR Windows Defender scanner.

Defender is the first stage of the privacy-first cascade. A false "clean"
verdict can let malware through, so we test the full range of exit codes
and output formats.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from src.local_av.defender import DefenderScanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout: str, returncode: int = 0) -> CompletedProcess[str]:
    """Build a CompletedProcess that MpCmdRun would have returned."""
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture
def fake_mpcmdrun(tmp_path: Path) -> Path:
    """Create a file that acts as the 'MpCmdRun.exe present' sentinel."""
    path = tmp_path / "MpCmdRun.exe"
    path.write_bytes(b"")  # Content ignored — only the presence check matters
    return path


# ---------------------------------------------------------------------------
# Availability / init
# ---------------------------------------------------------------------------


class TestAvailability:
    """Tests for scanner availability detection."""

    def test_disabled_in_config(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"enabled": False, "mpcmdrun_path": str(fake_mpcmdrun)})
        assert scanner._available is False

    def test_missing_binary_disables(self, tmp_path: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(tmp_path / "nope.exe")})
        assert scanner._available is False

    def test_present_binary_enables(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun)})
        assert scanner._available is True


# ---------------------------------------------------------------------------
# Threat extraction
# ---------------------------------------------------------------------------


class TestThreatExtraction:
    """Tests for _extract_threat_name static method."""

    def test_detects_threat_line(self) -> None:
        output = (
            "Scanning C:\\temp\\sample.exe\n"
            "Threat  : Virus:Win32/Contoso.Test\n"
            "Scan finished.\n"
        )
        assert DefenderScanner._extract_threat_name(output) == "Virus:Win32/Contoso.Test"

    def test_no_threat_line(self) -> None:
        output = "Scanning C:\\temp\\clean.exe\nScan finished.\n"
        assert DefenderScanner._extract_threat_name(output) is None

    def test_case_insensitive(self) -> None:
        output = "threat : malware.something\n"
        assert DefenderScanner._extract_threat_name(output) == "malware.something"


# ---------------------------------------------------------------------------
# scan() — verdict mapping
# ---------------------------------------------------------------------------


class TestScan:
    """Tests for DefenderScanner.scan()."""

    @pytest.mark.asyncio
    async def test_unavailable_returns_none(self, tmp_path: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(tmp_path / "absent.exe")})
        result = await scanner.scan("C:\\some\\file.exe", "a" * 64)
        assert result is None

    @pytest.mark.asyncio
    async def test_threat_detected(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun)})

        with patch("src.local_av.defender.subprocess") as mock_sub:
            mock_sub.run.return_value = _completed("Threat  : TrojanTest\n", returncode=2)
            mock_sub.CREATE_NO_WINDOW = 0x08000000

            result = await scanner.scan("C:\\temp\\malware.exe", "a" * 64)

        assert result is not None
        assert result.is_malicious is True
        assert result.threat_labels == ["defender:TrojanTest"]
        assert result.lookup_type == "defender"

    @pytest.mark.asyncio
    async def test_clean_verdict(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun)})

        with patch("src.local_av.defender.subprocess") as mock_sub:
            mock_sub.run.return_value = _completed("No threats found.\n", returncode=0)
            mock_sub.CREATE_NO_WINDOW = 0x08000000

            result = await scanner.scan("C:\\temp\\clean.exe", "b" * 64)

        assert result is not None
        assert result.is_malicious is False
        assert result.threat_labels == []
        assert result.lookup_type == "defender"

    @pytest.mark.asyncio
    async def test_inconclusive_returns_none(self, fake_mpcmdrun: Path) -> None:
        """Non-zero rc without parseable threat name → fail-safe None."""
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun)})

        with patch("src.local_av.defender.subprocess") as mock_sub:
            mock_sub.run.return_value = _completed("ERROR: Engine busy\n", returncode=1)
            mock_sub.CREATE_NO_WINDOW = 0x08000000

            result = await scanner.scan("C:\\temp\\x.exe", "c" * 64)

        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun), "timeout_seconds": 1})

        with patch("src.local_av.defender.subprocess") as mock_sub:
            mock_sub.run.side_effect = TimeoutExpired(cmd="MpCmdRun", timeout=1)
            mock_sub.CREATE_NO_WINDOW = 0x08000000

            result = await scanner.scan("C:\\temp\\x.exe", "d" * 64)

        assert result is None

    @pytest.mark.asyncio
    async def test_os_error_returns_none(self, fake_mpcmdrun: Path) -> None:
        scanner = DefenderScanner({"mpcmdrun_path": str(fake_mpcmdrun)})

        with patch("src.local_av.defender.subprocess") as mock_sub:
            mock_sub.run.side_effect = OSError("Access denied")
            mock_sub.CREATE_NO_WINDOW = 0x08000000

            result = await scanner.scan("C:\\temp\\x.exe", "e" * 64)

        assert result is None
