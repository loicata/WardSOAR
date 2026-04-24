"""Tests for the FileScanOrchestrator cascade.

Verifies the Defender → YARA → VirusTotal ordering and the short-circuit
behavior that keeps hashes off the wire whenever a local stage has already
produced a verdict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.pc.local_av.orchestrator import FileScanOrchestrator
from wardsoar.core.models import VirusTotalResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verdict(
    malicious: bool,
    lookup_type: str,
    file_hash: str = "a" * 64,
    labels: Optional[list[str]] = None,
) -> VirusTotalResult:
    return VirusTotalResult(
        file_hash=file_hash,
        detection_count=1 if malicious else 0,
        total_engines=1,
        detection_ratio=1.0 if malicious else 0.0,
        is_malicious=malicious,
        threat_labels=labels or [],
        lookup_type=lookup_type,
    )


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Real file on disk so the orchestrator's hash step succeeds."""
    path = tmp_path / "sample.exe"
    path.write_bytes(b"deadbeef" * 128)
    return path


def _make_orchestrator(
    defender_result: Optional[VirusTotalResult] = None,
    yara_result: Optional[VirusTotalResult] = None,
    vt_result: Optional[VirusTotalResult] = None,
) -> tuple[FileScanOrchestrator, MagicMock, MagicMock, MagicMock]:
    """Wire the orchestrator with mocked scanners returning canned verdicts."""
    defender = MagicMock()
    defender.scan = AsyncMock(return_value=defender_result)

    yara = MagicMock()
    yara.scan = AsyncMock(return_value=yara_result)

    vt = MagicMock()
    vt.lookup_hash = AsyncMock(return_value=vt_result)

    orchestrator = FileScanOrchestrator(
        defender=defender, yara=yara, vt_client=vt  # type: ignore[arg-type]
    )
    return orchestrator, defender, yara, vt


# ---------------------------------------------------------------------------
# Cascade behavior
# ---------------------------------------------------------------------------


class TestCascade:
    """Tests for the end-to-end cascade logic."""

    @pytest.mark.asyncio
    async def test_defender_detection_short_circuits(self, sample_file: Path) -> None:
        """Defender says malicious → YARA and VT must NOT be consulted."""
        orchestrator, defender, yara, vt = _make_orchestrator(
            defender_result=_verdict(malicious=True, lookup_type="defender")
        )

        result = await orchestrator.check_file(str(sample_file))

        assert result is not None
        assert result.lookup_type == "defender"
        defender.scan.assert_awaited_once()
        yara.scan.assert_not_awaited()
        vt.lookup_hash.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_yara_match_short_circuits_vt(self, sample_file: Path) -> None:
        """YARA match after Defender clean → VT must NOT be consulted."""
        orchestrator, defender, yara, vt = _make_orchestrator(
            defender_result=_verdict(malicious=False, lookup_type="defender"),
            yara_result=_verdict(malicious=True, lookup_type="yara", labels=["yara:test_rule"]),
        )

        result = await orchestrator.check_file(str(sample_file))

        assert result is not None
        assert result.lookup_type == "yara"
        defender.scan.assert_awaited_once()
        yara.scan.assert_awaited_once()
        vt.lookup_hash.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_all_clean_falls_through_to_vt(self, sample_file: Path) -> None:
        """Both locals silent → VT is queried as last resort."""
        vt_response = _verdict(malicious=True, lookup_type="hash")
        orchestrator, defender, yara, vt = _make_orchestrator(
            defender_result=None,
            yara_result=None,
            vt_result=vt_response,
        )

        result = await orchestrator.check_file(str(sample_file))

        assert result is vt_response
        vt.lookup_hash.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_defender_clean_yara_silent_vt_silent(self, sample_file: Path) -> None:
        """Surface Defender's clean verdict instead of returning None when VT has nothing."""
        defender_clean = _verdict(malicious=False, lookup_type="defender")
        orchestrator, defender, yara, vt = _make_orchestrator(
            defender_result=defender_clean,
            yara_result=None,
            vt_result=None,
        )

        result = await orchestrator.check_file(str(sample_file))

        assert result is not None
        assert result.lookup_type == "defender"
        assert result.is_malicious is False

    @pytest.mark.asyncio
    async def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        orchestrator, defender, yara, vt = _make_orchestrator()
        result = await orchestrator.check_file(str(tmp_path / "does_not_exist.exe"))

        assert result is None
        defender.scan.assert_not_awaited()
        yara.scan.assert_not_awaited()
        vt.lookup_hash.assert_not_awaited()


# ---------------------------------------------------------------------------
# Batch scan
# ---------------------------------------------------------------------------


class TestScanFiles:
    """Tests for the batch scan_files helper."""

    @pytest.mark.asyncio
    async def test_filters_none_results(self, sample_file: Path, tmp_path: Path) -> None:
        """None verdicts are dropped; present ones are kept."""
        orchestrator, _, _, vt = _make_orchestrator(vt_result=None)

        missing = tmp_path / "ghost.exe"
        files = [
            {"path": str(sample_file)},
            {"path": str(missing)},
            {},  # no "path" key
        ]

        results = await orchestrator.scan_files(files)

        # sample_file → Defender/YARA both None, VT None → no entry
        # missing → Path.is_file() False → None, skipped
        # entry without "path" → skipped
        assert results == []

    @pytest.mark.asyncio
    async def test_collects_positive_verdicts(self, sample_file: Path) -> None:
        malicious = _verdict(malicious=True, lookup_type="defender")
        orchestrator, _, _, _ = _make_orchestrator(defender_result=malicious)

        results = await orchestrator.scan_files([{"path": str(sample_file)}])

        assert len(results) == 1
        assert results[0].lookup_type == "defender"
