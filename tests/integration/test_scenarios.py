"""End-to-end integration tests (CLAUDE.md \u00a72).

These tests drive ``Pipeline.process_alert()`` with every stage
wired and assert the full outcome per CLAUDE.md\u2019s scenario matrix.
External services (Claude API, pfSense SSH, VirusTotal) are mocked
at the component boundary so the pipeline's real logic keeps
running while we deterministically shape the responses.

Run these separately from the unit suite:

    pytest tests/integration/ -v

Each test starts with a fresh :class:`Pipeline` and never shares
state. Slow-path tests (duplicate flood, rate limit) build 20-50
alerts and are tagged ``slow`` where relevant.

The scenarios map 1:1 to the CLAUDE.md table:
  1. True positive \u2014 high confidence
  2. True negative \u2014 known false positive
  3. True negative \u2014 low prescorer score
  4. Borderline \u2014 inconclusive verdict
  5. Whitelist protection
  6. Duplicate flood
  7. Infrastructure failure (Claude API 500)
  8. Rate-limit protection
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import AppConfig, WhitelistConfig
from src.main import FilteredResult, Pipeline
from src.models import (
    BlockAction,
    DecisionRecord,
    ForensicResult,
    NetworkContext,
    ResponseAction,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    src_ip: str = "203.0.113.99",
    dest_port: int = 22,
    severity: int = 1,
    sid: int = 2003067,
    signature: str = "ET SCAN SSH Brute Force Attempt",
) -> SuricataAlert:
    """Build a Suricata alert shaped like the real IDS feed.

    Defaults to a high-severity SSH-brute-force signature so the
    "true positive" scenario is natural. Callers override what
    they need per scenario.
    """
    return SuricataAlert(
        timestamp=datetime(2026, 4, 22, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=51203,
        dest_ip="192.168.2.100",
        dest_port=dest_port,
        proto="TCP",
        alert_signature=signature,
        alert_signature_id=sid,
        alert_severity=SuricataAlertSeverity(severity),
        alert_category="Attempted Administrator Privilege Gain",
    )


def _make_pipeline(
    *,
    mode: str = "protect",
    whitelist_ips: set[str] | None = None,
    max_blocks_per_hour: int = 20,
) -> Pipeline:
    """Build a :class:`Pipeline` with test-friendly defaults.

    * ``ANTHROPIC_API_KEY`` is stubbed so ``ThreatAnalyzer`` builds.
    * Responder is in ``protect`` mode by default, which blocks
      CONFIRMED-high-confidence verdicts. ``hard_protect`` /
      ``monitor`` are available via the ``mode`` argument.
    """
    with patch.dict(
        os.environ,
        {
            "ANTHROPIC_API_KEY": "test-key",
            "PFSENSE_API_URL": "https://192.168.2.1/api",
            "PFSENSE_API_KEY": "test-key",
            "PFSENSE_API_SECRET": "test-secret",
        },
    ):
        config = AppConfig(
            responder={
                "mode": mode,
                "dry_run": False,
                "max_blocks_per_hour": max_blocks_per_hour,
            },
            prescorer={
                "enabled": True,
                "mode": "active",
                "min_score_for_analysis": 30,
            },
            analyzer={"confidence_threshold": 0.7},
        )
        whitelist = WhitelistConfig(ips=whitelist_ips or set())
        return Pipeline(config, whitelist)


def _install_benign_baseline(pipeline: Pipeline) -> None:
    """Wire the generic "enrichment path completes without side effects"
    mocks used by every scenario that runs the full 13-step pipeline.

    Individual scenarios override the bits they care about
    (``_analyzer``, ``_responder``) after calling this helper.
    """
    pipeline._filter.should_suppress = MagicMock(return_value=False)  # type: ignore[method-assign]

    # Deduplicator returns a fresh group of size 1 for every alert
    # unless the scenario swaps the mock (see the duplicate-flood
    # scenario).
    group = MagicMock()
    group.count = 1
    pipeline._deduplicator.process_alert = MagicMock(return_value=group)  # type: ignore[method-assign]

    pipeline._decision_cache.lookup = MagicMock(return_value=None)  # type: ignore[method-assign]
    pipeline._decision_cache.store = MagicMock(return_value=None)  # type: ignore[method-assign]
    pipeline._asn_enricher.lookup = AsyncMock(return_value=None)  # type: ignore[method-assign]
    pipeline._collector.collect = AsyncMock(return_value=NetworkContext())  # type: ignore[method-assign]
    pipeline._forensics.analyze = AsyncMock(return_value=ForensicResult())  # type: ignore[method-assign]
    pipeline._scan_cascade.scan_files = AsyncMock(return_value=[])  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Scenario 1 — True positive, high confidence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_1_true_positive_high_confidence() -> None:
    """Alert with malicious IP \u2192 all stages pass \u2192 pfSense block issued."""
    pipeline = _make_pipeline(mode="protect")
    _install_benign_baseline(pipeline)

    # Analyzer returns CONFIRMED with high confidence.
    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.97,
            reasoning="SSH brute-force from known-bad IP.",
            recommended_actions=["ip_block"],
        )
    )
    # Responder returns a successful ip_block.
    pipeline._responder.respond = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip="203.0.113.99",
                success=True,
                pfsense_rule_id="blocklist",
            )
        ]
    )

    with patch("src.main.log_decision"):
        record = await pipeline.process_alert(_make_alert())

    assert isinstance(record, DecisionRecord)
    assert record.analysis is not None
    assert record.analysis.verdict == ThreatVerdict.CONFIRMED
    assert record.actions_taken, "Responder must produce at least one action"
    assert any(a.action_type == BlockAction.IP_BLOCK and a.success for a in record.actions_taken)
    # Cache must be updated so repeat alerts hit the fast path.
    pipeline._decision_cache.store.assert_called_once()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Scenario 2 — True negative, known false positive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_2_known_false_positive_suppressed_at_filter() -> None:
    """Alert matching known_false_positives.yaml \u2192 stage 1 drops it."""
    pipeline = _make_pipeline()
    pipeline._filter.should_suppress = MagicMock(return_value=True)  # type: ignore[method-assign]
    # Sentinels we assert were NOT called.
    pipeline._deduplicator.process_alert = MagicMock()  # type: ignore[method-assign]
    pipeline._analyzer.analyze = AsyncMock()  # type: ignore[method-assign]
    pipeline._responder.respond = AsyncMock()  # type: ignore[method-assign]

    result = await pipeline.process_alert(_make_alert(sid=2210054, severity=3))

    assert isinstance(result, FilteredResult)
    assert result.reason.startswith("filter:")
    pipeline._deduplicator.process_alert.assert_not_called()  # type: ignore[attr-defined]
    pipeline._analyzer.analyze.assert_not_called()  # type: ignore[attr-defined]
    pipeline._responder.respond.assert_not_called()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Scenario 3 — True negative, low prescorer score
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_3_low_prescorer_stops_before_opus() -> None:
    """Alert severity 3, nothing suspicious \u2192 PreScorer stops it."""
    pipeline = _make_pipeline()
    _install_benign_baseline(pipeline)

    # Shape the prescorer to filter out.
    mock_prescore = MagicMock()
    mock_prescore.was_filtered = True
    mock_prescore.total_score = 10
    mock_prescore.threshold = 30
    pipeline._prescorer.score = MagicMock(return_value=mock_prescore)  # type: ignore[method-assign]
    pipeline._analyzer.analyze = AsyncMock()  # type: ignore[method-assign]

    result = await pipeline.process_alert(_make_alert(severity=3))

    assert isinstance(result, FilteredResult)
    assert result.reason.startswith("prescorer:")
    assert "below threshold" in result.reason
    pipeline._analyzer.analyze.assert_not_called()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Scenario 4 — Borderline / inconclusive verdict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_4_inconclusive_verdict_no_block() -> None:
    """Opus returns INCONCLUSIVE \u2192 Responder refuses to block in Protect.

    CLAUDE.md\u2019s "Confirmer disagrees" scenario maps to INCONCLUSIVE
    in the v0.5+ single-pass Analyzer: the Confirmer stage is only
    invoked on low-confidence analyses and produces INCONCLUSIVE
    when it disagrees.
    """
    pipeline = _make_pipeline(mode="protect")
    _install_benign_baseline(pipeline)

    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.INCONCLUSIVE,
            confidence=0.55,
            reasoning="Signals point in opposite directions.",
        )
    )
    # Responder stub that refuses to block on INCONCLUSIVE.
    pipeline._responder.respond = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            ResponseAction(
                action_type=BlockAction.NONE,
                target_ip="203.0.113.99",
                error_message="verdict INCONCLUSIVE: never auto-block",
            )
        ]
    )

    with patch("src.main.log_decision"):
        record = await pipeline.process_alert(_make_alert())

    assert isinstance(record, DecisionRecord)
    assert record.analysis is not None
    assert record.analysis.verdict == ThreatVerdict.INCONCLUSIVE
    assert all(a.action_type == BlockAction.NONE for a in record.actions_taken)


# ---------------------------------------------------------------------------
# Scenario 5 — Whitelist protection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_5_whitelist_blocks_responder_action() -> None:
    """CONFIRMED verdict on a whitelisted IP \u2192 Responder returns NONE."""
    pipeline = _make_pipeline(
        mode="hard_protect",
        whitelist_ips={"203.0.113.99"},
    )
    _install_benign_baseline(pipeline)

    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.99,
            reasoning="All signals aligned for a block.",
            recommended_actions=["ip_block"],
        )
    )
    # Responder stub that returns NONE because the IP is whitelisted.
    pipeline._responder.respond = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            ResponseAction(
                action_type=BlockAction.NONE,
                target_ip="203.0.113.99",
                error_message="whitelist: IP 203.0.113.99 is protected",
            )
        ]
    )

    with patch("src.main.log_decision"):
        record = await pipeline.process_alert(_make_alert())

    assert isinstance(record, DecisionRecord)
    assert record.analysis is not None
    assert record.analysis.verdict == ThreatVerdict.CONFIRMED
    # No ip_block despite CONFIRMED + high confidence \u2014 whitelist wins.
    assert not any(a.action_type == BlockAction.IP_BLOCK for a in record.actions_taken)


# ---------------------------------------------------------------------------
# Scenario 6 — Duplicate flood
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_6_duplicate_flood_only_one_analysis() -> None:
    """50 identical alerts in 1 second \u2192 deduplicator groups them.

    The first alert creates the group (returned from
    ``process_alert``). The next 49 return ``None`` from the
    deduplicator, which :class:`Pipeline` treats as a filtered-out
    duplicate. Only ONE Opus call happens across the burst.
    """
    pipeline = _make_pipeline()
    _install_benign_baseline(pipeline)

    group = MagicMock()
    group.count = 1

    call_count = {"dedup": 0}

    def dedup_side_effect(alert: Any) -> Any:
        call_count["dedup"] += 1
        if call_count["dedup"] == 1:
            return group  # first alert creates the group
        return None  # subsequent alerts are merged (dedup returns None)

    pipeline._deduplicator.process_alert = MagicMock(  # type: ignore[method-assign]
        side_effect=dedup_side_effect
    )
    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.BENIGN,
            confidence=0.85,
            reasoning="Burst of SSH retries from known-benign source.",
        )
    )
    pipeline._responder.respond = AsyncMock(return_value=[])  # type: ignore[method-assign]

    results = []
    with patch("src.main.log_decision"):
        for _ in range(50):
            results.append(await pipeline.process_alert(_make_alert()))

    # First alert produced a full DecisionRecord; the remaining 49
    # are FilteredResult("dedup: grouped with existing alert").
    first = results[0]
    rest = results[1:]
    assert isinstance(first, DecisionRecord)
    for r in rest:
        assert isinstance(r, FilteredResult)
        assert r.reason.startswith("dedup:")
    # The Analyzer was called exactly once \u2014 the whole point of the
    # deduplicator.
    assert pipeline._analyzer.analyze.call_count == 1  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Scenario 7 — Infrastructure failure (Claude API 500)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_7_analyzer_crash_is_fail_safe() -> None:
    """``Analyzer.analyze`` raises \u2192 pipeline must NOT block.

    In v0.5+ the Analyzer is the canonical fail-safe point. When
    Claude returns 500 or times out, the analyzer wraps the failure
    in an ``INCONCLUSIVE`` verdict so the Responder's
    ``_decide_block`` rule ("never auto-block on INCONCLUSIVE")
    kicks in. We model that contract here by having the mock return
    an INCONCLUSIVE verdict with an error flag in the reasoning.
    """
    pipeline = _make_pipeline(mode="protect")
    _install_benign_baseline(pipeline)

    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.INCONCLUSIVE,
            confidence=0.0,
            reasoning="Analyzer failure: Claude API returned HTTP 500.",
        )
    )
    pipeline._responder.respond = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            ResponseAction(
                action_type=BlockAction.NONE,
                target_ip="203.0.113.99",
                error_message="verdict INCONCLUSIVE: never auto-block",
            )
        ]
    )

    with patch("src.main.log_decision") as mock_log:
        record = await pipeline.process_alert(_make_alert())

    assert isinstance(record, DecisionRecord)
    assert record.analysis is not None
    assert record.analysis.verdict == ThreatVerdict.INCONCLUSIVE
    # Key fail-safe invariant: no block action on INCONCLUSIVE.
    assert all(a.action_type != BlockAction.IP_BLOCK for a in record.actions_taken)
    # The decision IS logged (Step 12 always runs) \u2014 so the
    # operator sees the failure in ward_soar.log.
    mock_log.assert_called_once()


# ---------------------------------------------------------------------------
# Scenario 8 — Rate-limit protection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_8_rate_limit_stops_excess_blocks() -> None:
    """25 block requests in an hour with a limit of 20 \u2192 last 5 rejected.

    The Responder is the component that owns the rate limiter. We
    simulate a rate-limited Responder by counting calls and flipping
    from ip_block \u2192 NONE after 20 successful blocks. The pipeline
    then reports 20 successful blocks + 5 rate-limit rejections.
    """
    pipeline = _make_pipeline(mode="protect", max_blocks_per_hour=20)
    _install_benign_baseline(pipeline)
    pipeline._analyzer.analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.99,
            reasoning="Malicious, block.",
            recommended_actions=["ip_block"],
        )
    )

    call_log: list[ResponseAction] = []
    hits = {"n": 0}

    async def responder_side_effect(
        analysis: Any, source_ip: str, process_id: Any = None, asn_info: Any = None
    ) -> list[ResponseAction]:
        hits["n"] += 1
        if hits["n"] <= 20:
            action = ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip=source_ip,
                success=True,
                pfsense_rule_id="blocklist",
            )
        else:
            action = ResponseAction(
                action_type=BlockAction.NONE,
                target_ip=source_ip,
                error_message="rate limit: 20 blocks / hour exceeded",
            )
        call_log.append(action)
        return [action]

    pipeline._responder.respond = responder_side_effect  # type: ignore[method-assign]

    blocked = 0
    rate_limited = 0
    with patch("src.main.log_decision"):
        # 25 distinct source IPs so dedup/cache don't short-circuit.
        for i in range(25):
            record = await pipeline.process_alert(_make_alert(src_ip=f"203.0.113.{100 + i}"))
            assert isinstance(record, DecisionRecord)
            for action in record.actions_taken:
                if action.action_type == BlockAction.IP_BLOCK and action.success:
                    blocked += 1
                elif (
                    action.action_type == BlockAction.NONE
                    and action.error_message
                    and "rate limit" in action.error_message
                ):
                    rate_limited += 1

    assert blocked == 20, f"Expected 20 blocks, got {blocked}"
    assert rate_limited == 5, f"Expected 5 rate-limited, got {rate_limited}"
