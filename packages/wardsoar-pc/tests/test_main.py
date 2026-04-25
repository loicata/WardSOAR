"""Tests for WardSOAR pipeline orchestration.

main.py is STANDARD (80% coverage). Tests verify the pipeline
wiring and processing flow with mocked components.
"""

import logging
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.config import AppConfig, WhitelistConfig
from wardsoar.pc.main import FilteredResult, Pipeline
from wardsoar.core.models import (
    ForensicResult,
    NetworkContext,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert() -> SuricataAlert:
    """Create a test alert."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


def _make_pipeline() -> Pipeline:
    """Create a Pipeline with default config and mocked API keys."""
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
            prescorer={"enabled": True, "mode": "learning", "min_score_for_analysis": 15},
        )
        whitelist = WhitelistConfig(ips={"192.168.1.1"})
        return Pipeline(config, whitelist)


# ---------------------------------------------------------------------------
# Pipeline init tests
# ---------------------------------------------------------------------------


class TestPipelineInit:
    """Tests for Pipeline initialization."""

    def test_construction(self) -> None:
        pipeline = _make_pipeline()
        assert pipeline._filter is not None
        assert pipeline._deduplicator is not None
        assert pipeline._prescorer is not None


# ---------------------------------------------------------------------------
# Startup banner tests
# ---------------------------------------------------------------------------


class TestStartupBanner:
    """Regression for the v0.22.16 audit: ``main.py`` hardcoded
    ``"WardSOAR v0.5 (Phase 5+6 online)"`` in the startup banner
    instead of using the real ``wardsoar.pc.__version__``. The banner
    had been stale across 9+ public releases (since v0.22.7).
    """

    def test_banner_uses_real_pc_version(self, caplog: pytest.LogCaptureFixture) -> None:
        """Pipeline init logs the actual pc-package version, not 'v0.5'."""
        from wardsoar.pc import __version__ as pc_version

        # The ``ward_soar`` logger has propagation disabled by
        # ``setup_logger``; flip it on for the duration of the assertion
        # so caplog can see the records emitted under that root.
        ward_logger = logging.getLogger("ward_soar")
        previous_propagate = ward_logger.propagate
        ward_logger.propagate = True
        try:
            with caplog.at_level(logging.INFO, logger="ward_soar.main"):
                _make_pipeline()
        finally:
            ward_logger.propagate = previous_propagate

        banner_lines = [
            r.getMessage() for r in caplog.records if "Pipeline initialised" in r.getMessage()
        ]
        assert banner_lines, "expected at least one 'Pipeline initialised' log entry"
        assert all(pc_version in line for line in banner_lines), banner_lines
        assert all("v0.5" not in line for line in banner_lines), banner_lines
        assert all("Phase 5+6" not in line for line in banner_lines), banner_lines


# ---------------------------------------------------------------------------
# Pipeline process_alert tests
# ---------------------------------------------------------------------------


class TestProcessAlert:
    """Tests for Pipeline.process_alert."""

    @pytest.mark.asyncio
    async def test_filtered_alert_returns_filtered_result(self) -> None:
        pipeline = _make_pipeline()
        pipeline._filter.should_suppress = MagicMock(return_value=True)  # type: ignore[method-assign]

        result = await pipeline.process_alert(_make_alert())
        assert isinstance(result, FilteredResult)
        assert "false positive" in result.reason

    @pytest.mark.asyncio
    async def test_deduplicated_alert_returns_filtered_result(self) -> None:
        pipeline = _make_pipeline()
        pipeline._filter.should_suppress = MagicMock(return_value=False)  # type: ignore[method-assign]
        pipeline._deduplicator.process_alert = MagicMock(return_value=None)  # type: ignore[method-assign]

        result = await pipeline.process_alert(_make_alert())
        assert isinstance(result, FilteredResult)
        assert "dedup" in result.reason

    @pytest.mark.asyncio
    async def test_full_pipeline_benign(self) -> None:
        pipeline = _make_pipeline()
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
                verdict=ThreatVerdict.BENIGN,
                confidence=0.2,
                reasoning="Normal traffic",
            )
        )

        with patch("wardsoar.pc.main.log_decision"):
            result = await pipeline.process_alert(_make_alert())

        assert result is not None
        assert result.analysis is not None
        assert result.analysis.verdict == ThreatVerdict.BENIGN
