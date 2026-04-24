"""Tests for WardSOAR alert replay and simulation.

Replay is HIGH (85% coverage). No real blocking actions are executed.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import (
    DecisionRecord,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)
from src.replay import AlertReplayer, ReplayResult, ReplaySession

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    verdict: ThreatVerdict = ThreatVerdict.CONFIRMED,
    confidence: float = 0.85,
    src_ip: str = "10.0.0.1",
    sig_id: int = 1000,
) -> DecisionRecord:
    """Create a test DecisionRecord."""
    alert = SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=sig_id,
        alert_severity=SuricataAlertSeverity.HIGH,
    )
    return DecisionRecord(
        record_id="rec-001",
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        alert=alert,
        analysis=ThreatAnalysis(verdict=verdict, confidence=confidence, reasoning="Test"),
    )


def _write_decision_log(path: Path, records: list[DecisionRecord]) -> None:
    """Write decision records to a JSONL file."""
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(record.model_dump_json() + "\n")


# ---------------------------------------------------------------------------
# ReplayResult tests
# ---------------------------------------------------------------------------


class TestReplayResult:
    """Tests for ReplayResult dataclass."""

    def test_construction(self) -> None:
        record = _make_record()
        result = ReplayResult(
            original_record=record,
            replay_verdict=ThreatVerdict.BENIGN,
            replay_confidence=0.3,
            verdict_changed=True,
            original_verdict=ThreatVerdict.CONFIRMED,
        )
        assert result.verdict_changed is True


# ---------------------------------------------------------------------------
# load_decision_log tests
# ---------------------------------------------------------------------------


class TestLoadDecisionLog:
    """Tests for AlertReplayer.load_decision_log."""

    @pytest.mark.asyncio
    async def test_load_records(self, tmp_path: Path) -> None:
        log_file = tmp_path / "decisions.jsonl"
        records = [_make_record(), _make_record(ThreatVerdict.BENIGN, 0.2)]
        _write_decision_log(log_file, records)

        replayer = AlertReplayer({"decision_log_path": str(log_file)})
        loaded = await replayer.load_decision_log()
        assert len(loaded) == 2

    @pytest.mark.asyncio
    async def test_load_with_date_filter(self, tmp_path: Path) -> None:
        log_file = tmp_path / "decisions.jsonl"
        records = [_make_record()]
        _write_decision_log(log_file, records)

        replayer = AlertReplayer({"decision_log_path": str(log_file)})
        loaded = await replayer.load_decision_log(
            start_date=datetime(2026, 3, 14, tzinfo=timezone.utc),
            end_date=datetime(2026, 3, 16, tzinfo=timezone.utc),
        )
        assert len(loaded) == 1

    @pytest.mark.asyncio
    async def test_load_with_verdict_filter(self, tmp_path: Path) -> None:
        log_file = tmp_path / "decisions.jsonl"
        records = [_make_record(ThreatVerdict.CONFIRMED), _make_record(ThreatVerdict.BENIGN, 0.2)]
        _write_decision_log(log_file, records)

        replayer = AlertReplayer({"decision_log_path": str(log_file)})
        loaded = await replayer.load_decision_log(verdict_filter=ThreatVerdict.CONFIRMED)
        assert len(loaded) == 1

    @pytest.mark.asyncio
    async def test_load_missing_file(self) -> None:
        replayer = AlertReplayer({"decision_log_path": "/nonexistent/file.jsonl"})
        loaded = await replayer.load_decision_log()
        assert loaded == []

    @pytest.mark.asyncio
    async def test_load_corrupt_lines_skipped(self, tmp_path: Path) -> None:
        log_file = tmp_path / "decisions.jsonl"
        record = _make_record()
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")
            f.write("not valid json\n")
            f.write(record.model_dump_json() + "\n")

        replayer = AlertReplayer({"decision_log_path": str(log_file)})
        loaded = await replayer.load_decision_log()
        assert len(loaded) == 2


# ---------------------------------------------------------------------------
# replay_alert tests
# ---------------------------------------------------------------------------


class TestReplayAlert:
    """Tests for AlertReplayer.replay_alert."""

    @pytest.mark.asyncio
    async def test_replay_produces_result(self) -> None:
        replayer = AlertReplayer({})
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        result = await replayer.replay_alert(record)
        assert isinstance(result, ReplayResult)
        assert result.original_verdict == ThreatVerdict.CONFIRMED

    @pytest.mark.asyncio
    async def test_replay_without_analysis(self) -> None:
        """Record without analysis should still produce a result."""
        record = _make_record()
        record.analysis = None
        replayer = AlertReplayer({})
        result = await replayer.replay_alert(record)
        assert isinstance(result, ReplayResult)

    @pytest.mark.asyncio
    async def test_replay_without_reanalyze_uses_original(self) -> None:
        """Without reanalyze flag, original verdict is reused."""
        replayer = AlertReplayer({})
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        result = await replayer.replay_alert(record, reanalyze=False)
        assert result.replay_verdict == ThreatVerdict.CONFIRMED
        assert result.verdict_changed is False

    @pytest.mark.asyncio
    async def test_replay_with_reanalyze_calls_analyzer(self) -> None:
        """With reanalyze=True and analyzer, Claude re-analysis should run."""
        mock_analyzer = MagicMock()
        new_analysis = ThreatAnalysis(
            verdict=ThreatVerdict.BENIGN, confidence=0.3, reasoning="Re-analyzed"
        )
        mock_analyzer.analyze = AsyncMock(return_value=new_analysis)

        replayer = AlertReplayer({}, analyzer=mock_analyzer)
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        result = await replayer.replay_alert(record, reanalyze=True)

        assert result.replay_verdict == ThreatVerdict.BENIGN
        assert result.replay_confidence == 0.3
        assert result.verdict_changed is True
        mock_analyzer.analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_replay_reanalyze_without_analyzer_uses_original(self) -> None:
        """reanalyze=True without analyzer should fall back to original."""
        replayer = AlertReplayer({})  # No analyzer
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        result = await replayer.replay_alert(record, reanalyze=True)
        assert result.replay_verdict == ThreatVerdict.CONFIRMED
        assert result.verdict_changed is False

    @pytest.mark.asyncio
    async def test_replay_reanalyze_api_failure_uses_original(self) -> None:
        """If re-analysis fails, original verdict should be used."""
        mock_analyzer = MagicMock()
        mock_analyzer.analyze = AsyncMock(side_effect=RuntimeError("API down"))

        replayer = AlertReplayer({}, analyzer=mock_analyzer)
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        result = await replayer.replay_alert(record, reanalyze=True)

        assert result.replay_verdict == ThreatVerdict.CONFIRMED
        assert result.verdict_changed is False


# ---------------------------------------------------------------------------
# replay_batch tests
# ---------------------------------------------------------------------------


class TestReplayBatch:
    """Tests for AlertReplayer.replay_batch."""

    @pytest.mark.asyncio
    async def test_batch_produces_session(self) -> None:
        replayer = AlertReplayer({})
        records = [_make_record(), _make_record(ThreatVerdict.BENIGN, 0.2)]
        session = await replayer.replay_batch(records)
        assert isinstance(session, ReplaySession)
        assert session.total_alerts == 2
        assert session.completed is True
        assert len(session.results) == 2

    @pytest.mark.asyncio
    async def test_empty_batch(self) -> None:
        replayer = AlertReplayer({})
        session = await replayer.replay_batch([])
        assert session.total_alerts == 0
        assert session.completed is True


# ---------------------------------------------------------------------------
# compute_impact_report tests
# ---------------------------------------------------------------------------


class TestComputeImpactReport:
    """Tests for AlertReplayer.compute_impact_report."""

    def test_impact_report(self) -> None:
        replayer = AlertReplayer({})
        record = _make_record(ThreatVerdict.CONFIRMED, 0.85)
        session = ReplaySession(
            session_id="test-session",
            total_alerts=2,
            results=[
                ReplayResult(
                    original_record=record,
                    replay_verdict=ThreatVerdict.BENIGN,
                    replay_confidence=0.2,
                    verdict_changed=True,
                    original_verdict=ThreatVerdict.CONFIRMED,
                ),
                ReplayResult(
                    original_record=record,
                    replay_verdict=ThreatVerdict.CONFIRMED,
                    replay_confidence=0.9,
                    verdict_changed=False,
                    original_verdict=ThreatVerdict.CONFIRMED,
                ),
            ],
            verdict_changes=1,
            completed=True,
        )
        report = replayer.compute_impact_report(session)
        assert report["total_replayed"] == 2
        assert report["verdict_changes"] == 1
        assert "new_blocks" in report
        assert "removed_blocks" in report
