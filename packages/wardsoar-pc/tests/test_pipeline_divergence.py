"""Integration tests for stages 0.5 (Investigator) and 9.5 (Bumper).

These tests exercise ``Pipeline.process_alert`` end-to-end with the
heavy components mocked (filter, deduplicator, decision_cache,
collector, forensics, analyzer). They verify the *contract* of
the dual-source pipeline integration:

  Stage 0.5 — DivergenceInvestigator
    * Reads ``source_corroboration`` from ``alert.raw_event``.
    * Runs the investigator only for DIVERGENCE_A / DIVERGENCE_B.
    * Skips investigation for SINGLE_SOURCE / MATCH_CONFIRMED /
      *_PENDING / None.
    * Investigation failure (raised exception) does not break the
      pipeline.

  Stage 9.5 — DivergenceVerdictBumper
    * BENIGN + unexplained findings -> SUSPICIOUS in DecisionRecord.
    * SUSPICIOUS + unexplained findings -> CONFIRMED.
    * Benign explanation (loopback / VPN / LAN-only) -> verdict
      unchanged, ``verdict_pre_bump`` is None.
    * Pre-bump verdict recorded in DecisionRecord.

  DecisionRecord
    * Carries ``source_corroboration``, ``divergence_findings`` and
      ``verdict_pre_bump`` for downstream audit consumers.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.config import AppConfig, WhitelistConfig
from wardsoar.core.models import (
    DivergenceFindings,
    ForensicResult,
    NetworkContext,
    SourceCorroboration,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)
from wardsoar.pc.main import Pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    corroboration: SourceCorroboration | None = None,
    secondary_event: dict[str, Any] | None = None,
) -> SuricataAlert:
    """Build a SuricataAlert with optional dual-source tags injected."""
    raw_event: dict[str, Any] = {
        "timestamp": "2026-04-26T10:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "192.168.1.100",
        "alert": {"signature_id": 1000, "signature": "ET TEST"},
    }
    if corroboration is not None:
        raw_event["source_corroboration"] = corroboration.value
    if secondary_event is not None:
        raw_event["secondary_event"] = secondary_event
    return SuricataAlert(
        timestamp=datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET TEST",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
        raw_event=raw_event,
    )


def _make_pipeline() -> Pipeline:
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "test-key",
            "PFSENSE_API_URL": "https://192.168.1.1/api/v1",
            "PFSENSE_API_KEY": "test-key",
            "PFSENSE_API_SECRET": "test-secret",
        },
    ):
        config = AppConfig(
            responder={"dry_run": True, "max_blocks_per_hour": 20},
            prescorer={
                "enabled": True,
                "mode": "learning",
                "min_score_for_analysis": 15,
            },
            sources={"netgate": True, "suricata_local": True},
        )
        whitelist = WhitelistConfig(ips={"192.168.1.1"})
        return Pipeline(config, whitelist)


def _patch_heavy_components(
    pipeline: Pipeline,
    analyzer_verdict: ThreatVerdict = ThreatVerdict.BENIGN,
    analyzer_confidence: float = 0.2,
) -> None:
    """Mock everything between stage 0.5 and stage 9.5 so the test
    can isolate the wiring of the investigator + bumper."""
    pipeline._filter.should_suppress = MagicMock(return_value=False)  # type: ignore[method-assign]
    mock_group = MagicMock()
    mock_group.count = 1
    pipeline._deduplicator.process_alert = MagicMock(return_value=mock_group)  # type: ignore[method-assign]
    pipeline._decision_cache.lookup = MagicMock(return_value=None)  # type: ignore[method-assign]
    pipeline._collector.collect = AsyncMock(return_value=NetworkContext())  # type: ignore[method-assign]
    pipeline._forensics.analyze = AsyncMock(return_value=ForensicResult())  # type: ignore[method-assign]
    pipeline._analyzer = MagicMock()  # type: ignore[assignment]
    pipeline._analyzer.analyze = AsyncMock(
        return_value=ThreatAnalysis(
            verdict=analyzer_verdict,
            confidence=analyzer_confidence,
            reasoning="mock",
        )
    )


# ---------------------------------------------------------------------------
# Pipeline.__init__ wires the investigator
# ---------------------------------------------------------------------------


class TestPipelineInitInvestigator:
    def test_investigator_attribute_present(self) -> None:
        pipeline = _make_pipeline()
        assert hasattr(pipeline, "_divergence_investigator")
        assert pipeline._divergence_investigator is not None

    def test_investigator_uses_pipeline_conn_buffer(self) -> None:
        # The investigator reuses the existing rolling NetConnections
        # buffer rather than allocating its own — same psutil cost
        # amortised across the pipeline.
        pipeline = _make_pipeline()
        inv = pipeline._divergence_investigator
        # The investigator stores the buffer in a private attribute;
        # the contract is that it points to the same object.
        assert inv._netconns is pipeline._conn_buffer  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Stage 0.5 — investigator dispatch
# ---------------------------------------------------------------------------


class TestStage05InvestigatorDispatch:
    @pytest.mark.asyncio
    async def test_no_corroboration_skips_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock()  # type: ignore[method-assign]
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(_make_alert(corroboration=None))
        pipeline._divergence_investigator.investigate.assert_not_called()

    @pytest.mark.asyncio
    async def test_single_source_skips_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock()  # type: ignore[method-assign]
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.SINGLE_SOURCE)
            )
        pipeline._divergence_investigator.investigate.assert_not_called()

    @pytest.mark.asyncio
    async def test_match_confirmed_skips_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock()  # type: ignore[method-assign]
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.MATCH_CONFIRMED)
            )
        pipeline._divergence_investigator.investigate.assert_not_called()

    @pytest.mark.asyncio
    async def test_pending_skips_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock()  # type: ignore[method-assign]
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.MATCH_PENDING)
            )
        pipeline._divergence_investigator.investigate.assert_not_called()

    @pytest.mark.asyncio
    async def test_divergence_a_runs_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "loopback"],
                is_explained=False,
                explanation="unexplained",
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        pipeline._divergence_investigator.investigate.assert_called_once()
        # Verify the investigator received the right corroboration value.
        kwargs = pipeline._divergence_investigator.investigate.call_args.kwargs
        assert kwargs["corroboration"] == SourceCorroboration.DIVERGENCE_A

    @pytest.mark.asyncio
    async def test_divergence_b_runs_investigation(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "loopback"],
                is_explained=True,
                explanation="loopback_traffic",
                is_loopback=True,
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_B)
            )
        pipeline._divergence_investigator.investigate.assert_called_once()
        kwargs = pipeline._divergence_investigator.investigate.call_args.kwargs
        assert kwargs["corroboration"] == SourceCorroboration.DIVERGENCE_B

    @pytest.mark.asyncio
    async def test_secondary_event_passed_through(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings()
        )
        secondary = {"src_ip": "10.0.0.1", "dest_ip": "192.168.1.100"}
        with patch("wardsoar.pc.main.log_decision"):
            await pipeline.process_alert(
                _make_alert(
                    corroboration=SourceCorroboration.DIVERGENCE_A,
                    secondary_event=secondary,
                )
            )
        kwargs = pipeline._divergence_investigator.investigate.call_args.kwargs
        assert kwargs["secondary_event"] == secondary

    @pytest.mark.asyncio
    async def test_invalid_corroboration_value_does_not_raise(self) -> None:
        # A typoed / malformed corroboration in raw_event must not
        # break the pipeline. The unknown value is ignored, the
        # investigator skipped, processing continues.
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock()  # type: ignore[method-assign]
        alert = _make_alert(corroboration=None)
        alert.raw_event["source_corroboration"] = "not_a_real_value"
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(alert)
        assert result is not None
        pipeline._divergence_investigator.investigate.assert_not_called()

    @pytest.mark.asyncio
    async def test_investigator_exception_does_not_break_pipeline(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("simulated investigator failure")
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        # Pipeline finished successfully; record produced.
        assert result is not None
        assert getattr(result, "analysis", None) is not None
        # Findings are None because the investigator raised.
        assert result.divergence_findings is None  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Stage 9.5 — verdict bumping
# ---------------------------------------------------------------------------


class TestStage95VerdictBumping:
    @pytest.mark.asyncio
    async def test_unexplained_bumps_benign_to_suspicious(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline, analyzer_verdict=ThreatVerdict.BENIGN)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "loopback"],
                is_explained=False,
                explanation="unexplained",
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.analysis is not None  # type: ignore[union-attr]
        assert result.analysis.verdict == ThreatVerdict.SUSPICIOUS  # type: ignore[union-attr]
        assert result.verdict_pre_bump == ThreatVerdict.BENIGN  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_suricata_dead_bumps_suspicious_to_confirmed(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline, analyzer_verdict=ThreatVerdict.SUSPICIOUS)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "suricata_alive"],
                is_explained=True,
                explanation="suricata_local_dead",
                suricata_local_state="dead",
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.analysis is not None  # type: ignore[union-attr]
        assert result.analysis.verdict == ThreatVerdict.CONFIRMED  # type: ignore[union-attr]
        assert result.verdict_pre_bump == ThreatVerdict.SUSPICIOUS  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_loopback_explanation_does_not_bump(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline, analyzer_verdict=ThreatVerdict.BENIGN)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "loopback"],
                is_explained=True,
                explanation="loopback_traffic",
                is_loopback=True,
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_B)
            )
        assert result is not None
        assert result.analysis is not None  # type: ignore[union-attr]
        # No bump applied — verdict identical, pre-bump None.
        assert result.analysis.verdict == ThreatVerdict.BENIGN  # type: ignore[union-attr]
        assert result.verdict_pre_bump is None  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_vpn_explanation_does_not_bump(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline, analyzer_verdict=ThreatVerdict.SUSPICIOUS)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "vpn"],
                is_explained=True,
                explanation="vpn_traffic",
                is_vpn=True,
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.analysis is not None  # type: ignore[union-attr]
        assert result.analysis.verdict == ThreatVerdict.SUSPICIOUS  # type: ignore[union-attr]
        assert result.verdict_pre_bump is None  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_confirmed_already_at_top_does_not_bump(self) -> None:
        # CONFIRMED + unexplained findings → still CONFIRMED.
        # verdict_pre_bump remains None because the verdict didn't
        # actually change.
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline, analyzer_verdict=ThreatVerdict.CONFIRMED)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot", "loopback"],
                is_explained=False,
                explanation="unexplained",
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.analysis is not None  # type: ignore[union-attr]
        assert result.analysis.verdict == ThreatVerdict.CONFIRMED  # type: ignore[union-attr]
        assert result.verdict_pre_bump is None  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# DecisionRecord — dual-source audit fields populated
# ---------------------------------------------------------------------------


class TestDecisionRecordAuditFields:
    @pytest.mark.asyncio
    async def test_record_carries_corroboration(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=DivergenceFindings(
                checks_run=["snapshot"],
                is_explained=True,
                explanation="loopback_traffic",
            )
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.source_corroboration == SourceCorroboration.DIVERGENCE_A  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_record_carries_findings(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        findings = DivergenceFindings(
            checks_run=["snapshot", "loopback"],
            is_explained=True,
            explanation="loopback_traffic",
            is_loopback=True,
        )
        pipeline._divergence_investigator.investigate = AsyncMock(  # type: ignore[method-assign]
            return_value=findings,
        )
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(
                _make_alert(corroboration=SourceCorroboration.DIVERGENCE_A)
            )
        assert result is not None
        assert result.divergence_findings is not None  # type: ignore[union-attr]
        assert result.divergence_findings.explanation == "loopback_traffic"  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_no_corroboration_yields_none_audit_fields(self) -> None:
        pipeline = _make_pipeline()
        _patch_heavy_components(pipeline)
        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(_make_alert(corroboration=None))
        assert result is not None
        assert result.source_corroboration is None  # type: ignore[union-attr]
        assert result.divergence_findings is None  # type: ignore[union-attr]
        assert result.verdict_pre_bump is None  # type: ignore[union-attr]
