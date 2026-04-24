"""Tests for WardSOAR threat analyzer (Claude API).

Analyzer is CRITICAL (95% coverage). All API calls are mocked.
Fail-safe: API errors return INCONCLUSIVE verdict.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzer import ThreatAnalyzer
from src.models import (
    ForensicResult,
    NetworkContext,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatVerdict,
    VirusTotalResult,
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
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


VALID_API_RESPONSE = json.dumps(
    {
        "verdict": "confirmed",
        "confidence": 0.85,
        "reasoning": "Strong IOC match with known malware pattern",
        "recommended_actions": ["block_ip", "kill_process"],
        "ioc_summary": "C2 communication detected",
        "false_positive_indicators": [],
    }
)

BENIGN_API_RESPONSE = json.dumps(
    {
        "verdict": "benign",
        "confidence": 0.2,
        "reasoning": "Normal Windows Update traffic",
        "recommended_actions": [],
        "ioc_summary": "",
        "false_positive_indicators": ["Known Microsoft IP", "Expected update behavior"],
    }
)


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestThreatAnalyzerInit:
    """Tests for ThreatAnalyzer initialization."""

    def test_missing_api_key_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                ThreatAnalyzer({})

    def test_valid_init(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})
            assert analyzer._model == "claude-opus-4-7"

    def test_custom_model(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({"model": "claude-opus-4-20250514"})
            assert analyzer._model == "claude-opus-4-20250514"


# ---------------------------------------------------------------------------
# _build_analysis_prompt tests
# ---------------------------------------------------------------------------


class TestBuildAnalysisPrompt:
    """Tests for ThreatAnalyzer._build_analysis_prompt."""

    def test_prompt_contains_alert_data(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})
        alert = _make_alert()
        prompt = analyzer._build_analysis_prompt(alert, None, None, None)
        assert "10.0.0.1" in prompt
        assert "2024897" in prompt
        assert "ET MALWARE Test" in prompt

    def test_prompt_with_network_context(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})
        alert = _make_alert()
        ctx = NetworkContext(active_connections=[{"remote_ip": "10.0.0.1", "pid": 1234}])
        prompt = analyzer._build_analysis_prompt(alert, ctx, None, None)
        assert "active_connections" in prompt or "10.0.0.1" in prompt

    def test_prompt_with_forensic_result(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})
        alert = _make_alert()
        forensic = ForensicResult(suspect_processes=[{"pid": 1234, "name": "malware.exe"}])
        prompt = analyzer._build_analysis_prompt(alert, None, forensic, None)
        assert "malware.exe" in prompt

    def test_prompt_with_vt_results(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})
        alert = _make_alert()
        vt = [
            VirusTotalResult(
                file_hash="abc123",
                detection_count=10,
                total_engines=70,
                is_malicious=True,
            )
        ]
        prompt = analyzer._build_analysis_prompt(alert, None, None, vt)
        assert "abc123" in prompt


# ---------------------------------------------------------------------------
# analyze tests
# ---------------------------------------------------------------------------


class TestAnalyze:
    """Tests for ThreatAnalyzer.analyze."""

    @pytest.mark.asyncio
    async def test_successful_analysis(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        with patch("src.analyzer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_msg = MagicMock()
            mock_msg.content = [MagicMock(text=VALID_API_RESPONSE)]
            mock_client.messages.create.return_value = mock_msg
            mock_anthropic.Anthropic.return_value = mock_client

            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.CONFIRMED
        assert result.confidence == 0.85
        assert "IOC" in result.reasoning

    @pytest.mark.asyncio
    async def test_benign_analysis(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        with patch("src.analyzer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_msg = MagicMock()
            mock_msg.content = [MagicMock(text=BENIGN_API_RESPONSE)]
            mock_client.messages.create.return_value = mock_msg
            mock_anthropic.Anthropic.return_value = mock_client

            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.BENIGN
        assert result.confidence == 0.2

    @pytest.mark.asyncio
    async def test_api_error_returns_inconclusive(self) -> None:
        """Fail-safe: API errors must return INCONCLUSIVE, never crash.

        Patches only ``anthropic.Anthropic`` (the constructor) so the
        module's real exception classes remain available to ``except``.
        """
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("API down")

        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client):
            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.INCONCLUSIVE
        assert "error" in result.reasoning.lower() or "fail" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_api_timeout_returns_inconclusive(self) -> None:
        """CLAUDE.md §4 — on httpx timeout, fail-safe to INCONCLUSIVE.

        The Anthropic SDK raises ``APITimeoutError`` when the configured
        per-request timeout elapses. Treat it exactly like any other
        transient failure: retry inside ``_call_with_retry`` and, once
        the budget is exhausted, fall back to INCONCLUSIVE rather than
        letting the exception escape the pipeline.
        """
        import anthropic
        import httpx

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        # Force the retry loop to take its fastest path so the test stays
        # under a second. With the patched constants we retry once after
        # a negligible delay, then surface the timeout.
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APITimeoutError(
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        )

        with (
            patch("src.analyzer.anthropic.Anthropic", return_value=mock_client),
            patch("src.analyzer._MAX_API_RETRIES", 1),
            patch("src.analyzer._RETRY_BASE_DELAY_SECONDS", 0),
        ):
            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.INCONCLUSIVE
        assert result.confidence == 0.0
        # Two attempts = initial call + one retry, both raising timeout.
        assert mock_client.messages.create.call_count == 2

    def test_anthropic_client_is_built_with_explicit_timeout(self) -> None:
        """Regression for CLAUDE.md §4: the SDK default is 600 s, which
        would let a hung call stall the pipeline for ten minutes. The
        analyzer must pass an explicit timeout when constructing the
        client."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text=VALID_API_RESPONSE)]
        mock_client.messages.create.return_value = mock_msg

        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client) as ctor:
            import asyncio as _asyncio

            _asyncio.run(analyzer.analyze(_make_alert()))

        # The ctor was called at least once (retries rebuild the client
        # each attempt), every call must carry the explicit timeout kwarg.
        assert ctor.call_count >= 1
        for call in ctor.call_args_list:
            assert "timeout" in call.kwargs
            assert call.kwargs["timeout"] == 30.0

    @pytest.mark.asyncio
    async def test_invalid_json_response_returns_inconclusive(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        with patch("src.analyzer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_msg = MagicMock()
            mock_msg.content = [MagicMock(text="Not valid JSON at all")]
            mock_client.messages.create.return_value = mock_msg
            mock_anthropic.Anthropic.return_value = mock_client

            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_analyze_with_full_context(self) -> None:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        with patch("src.analyzer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_msg = MagicMock()
            mock_msg.content = [MagicMock(text=VALID_API_RESPONSE)]
            mock_client.messages.create.return_value = mock_msg
            mock_anthropic.Anthropic.return_value = mock_client

            result = await analyzer.analyze(
                alert=_make_alert(),
                network_context=NetworkContext(),
                forensic_result=ForensicResult(),
                vt_results=[],
            )

        assert result.verdict == ThreatVerdict.CONFIRMED

    @pytest.mark.asyncio
    async def test_loads_external_prompt_if_configured(self, tmp_path: Path) -> None:
        """If external prompt file exists, it should be used."""
        prompt_file = tmp_path / "analyzer_system.txt"
        prompt_file.write_text("Custom system prompt for testing.", encoding="utf-8")

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({"system_prompt_file": str(prompt_file)})

        assert analyzer._system_prompt == "Custom system prompt for testing."


# ===========================================================================
# Circuit breaker (2026-04-20 credit-exhausted incident)
# ===========================================================================


class TestAnalyzerCircuitBreaker:
    """Regression for the 2026-04-20 12:46 → 14:48 "credit balance too
    low" incident: 42 Claude API calls hit the same 400 over two hours,
    because the analyzer kept trying once per alert with no circuit
    protection. Each failure now increments a counter; a specific
    "credit exhausted" path trips the breaker immediately with a longer
    cooldown than the generic threshold."""

    @staticmethod
    def _make_analyzer() -> "ThreatAnalyzer":
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            return ThreatAnalyzer({})

    @pytest.mark.asyncio
    async def test_credit_exhausted_opens_circuit_on_first_failure(self) -> None:
        """A single "credit balance too low" error must trip the
        breaker right away — retrying every 15 min would burn one
        more 4xx per alert until the operator recharges."""
        import anthropic
        import httpx

        analyzer = self._make_analyzer()

        # 400 invalid_request_error with the credit-exhausted message.
        request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        response = httpx.Response(status_code=400, request=request)
        credit_exc = anthropic.BadRequestError(
            "Your credit balance is too low to access the Anthropic API.",
            response=response,
            body={
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "Your credit balance is too low to access the Anthropic API.",
                },
            },
        )

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = credit_exc

        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client):
            # First call fails and trips the breaker.
            result1 = await analyzer.analyze(_make_alert())
            assert result1.verdict == ThreatVerdict.INCONCLUSIVE
            assert mock_client.messages.create.call_count == 1

            # Breaker open → second call does NOT reach the API.
            result2 = await analyzer.analyze(_make_alert())
            assert result2.verdict == ThreatVerdict.INCONCLUSIVE
            assert "circuit breaker" in result2.reasoning.lower()
            assert "credit" in result2.reasoning.lower()
            assert mock_client.messages.create.call_count == 1  # unchanged

    @pytest.mark.asyncio
    async def test_generic_failures_trip_circuit_after_threshold(self) -> None:
        """Non-credit deterministic failures must not trip on the first
        failure — we allow the retry loop to exhaust and accumulate N
        consecutive failures before tripping. Otherwise a single
        transient glitch would silence analysis for 15 min."""
        from src.analyzer import _CIRCUIT_BREAKER_THRESHOLD

        analyzer = self._make_analyzer()

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("transient glitch")

        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client):
            for i in range(_CIRCUIT_BREAKER_THRESHOLD):
                result = await analyzer.analyze(_make_alert())
                assert result.verdict == ThreatVerdict.INCONCLUSIVE
            # Threshold just reached → next call is short-circuited.
            call_count_before_open = mock_client.messages.create.call_count
            result = await analyzer.analyze(_make_alert())
            assert result.verdict == ThreatVerdict.INCONCLUSIVE
            assert "circuit breaker" in result.reasoning.lower()
            assert mock_client.messages.create.call_count == call_count_before_open

    @pytest.mark.asyncio
    async def test_successful_call_resets_consecutive_failures(self) -> None:
        """One successful call must close the circuit so a single
        recovered blip does not leave the client at the edge of
        tripping on the next alert."""
        analyzer = self._make_analyzer()

        # One failure.
        mock_client_fail = MagicMock()
        mock_client_fail.messages.create.side_effect = RuntimeError("blip")
        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client_fail):
            await analyzer.analyze(_make_alert())
        assert analyzer._consecutive_failures == 1

        # Then a success.
        mock_client_ok = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text=VALID_API_RESPONSE)]
        mock_client_ok.messages.create.return_value = mock_msg
        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client_ok):
            result = await analyzer.analyze(_make_alert())
        assert result.verdict == ThreatVerdict.CONFIRMED
        assert analyzer._consecutive_failures == 0
        assert analyzer._circuit_open_until == 0.0

    @pytest.mark.asyncio
    async def test_circuit_closes_after_cooldown_elapses(self) -> None:
        """After the cooldown window has elapsed, the next alert gets
        a fresh attempt on the API — the breaker is closed again."""
        analyzer = self._make_analyzer()

        # Trip the breaker manually to avoid waiting for the threshold.
        analyzer._consecutive_failures = 3
        analyzer._circuit_open_until = 1.0  # already in the past
        analyzer._circuit_reason = "artificial"

        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text=VALID_API_RESPONSE)]
        mock_client.messages.create.return_value = mock_msg

        with patch("src.analyzer.anthropic.Anthropic", return_value=mock_client):
            result = await analyzer.analyze(_make_alert())

        assert result.verdict == ThreatVerdict.CONFIRMED
        # Success reset the state.
        assert analyzer._consecutive_failures == 0
        assert analyzer._circuit_open_until == 0.0


# ===========================================================================
# Context pruning + adaptive budget (v0.7.0)
#
# These functions are what kept the daily Opus spend from staying at
# $42/day on a home deployment. Every test in this block is a guard
# against regressing the cost model — if any assertion flips, the
# analyzer is likely shipping data it should have dropped.
# ===========================================================================


class TestRenderProcessRiskSection:
    """Helper that turns suspect_processes[].risk into prompt text.

    Ensures the per-process verdicts survive the character-budget
    truncation Opus sees on SEV-3 alerts (the JSON dump of
    forensic_result is clipped; this plain-text block goes after it
    so the information is always available).
    """

    def _fr_with_risk(self, **risk_overrides: object) -> ForensicResult:
        default_risk = {
            "score": 85,
            "verdict": "malicious",
            "signature_status": "valid",
            "signature_signer": "Microsoft Corporation",
            "parent_name": "winword.exe",
            "signals": [
                "PowerShell -EncodedCommand argument",
                "Parent winword.exe spawning powershell.exe is a classic attack pattern",
            ],
        }
        default_risk.update(risk_overrides)
        return ForensicResult(
            suspect_processes=[
                {
                    "pid": 1234,
                    "name": "powershell.exe",
                    "exe": "x",
                    "cmdline": [],
                    "risk": default_risk,
                },
            ],
        )

    def test_section_contains_pid_verdict_and_signals(self) -> None:
        from src.analyzer import _render_process_risk_section

        out = _render_process_risk_section(self._fr_with_risk())

        assert "Process attribution & risk" in out
        assert "powershell.exe" in out
        assert "PID 1234" in out
        assert "MALICIOUS" in out
        assert "85/100" in out
        assert "Microsoft Corporation" in out
        assert "winword.exe" in out
        assert "EncodedCommand" in out

    def test_returns_empty_when_no_risk_block(self) -> None:
        """A process without a ``risk`` dict should not leak an empty row."""
        from src.analyzer import _render_process_risk_section

        fr = ForensicResult(
            suspect_processes=[{"pid": 1, "name": "x.exe"}],
        )
        assert _render_process_risk_section(fr) == ""

    def test_returns_empty_when_no_processes(self) -> None:
        from src.analyzer import _render_process_risk_section

        assert _render_process_risk_section(ForensicResult()) == ""

    def test_includes_services_for_svchost(self) -> None:
        from src.analyzer import _render_process_risk_section

        fr = ForensicResult(
            suspect_processes=[
                {
                    "pid": 1234,
                    "name": "svchost.exe",
                    "services": ["BITS", "Dnscache"],
                    "risk": {
                        "score": 10,
                        "verdict": "benign",
                        "signature_status": "valid",
                        "signature_signer": "Microsoft Corporation",
                        "parent_name": "services.exe",
                        "signals": ["Signed by trusted publisher: Microsoft Corporation"],
                    },
                }
            ],
        )
        out = _render_process_risk_section(fr)
        assert "BITS" in out and "Dnscache" in out


class TestBudgetForSeverity:
    """Budget table must always return the severity's numbers — and a
    sensible default for exotic severity values."""

    def test_sev1_gets_the_largest_budget(self) -> None:
        from src.analyzer import _budget_for
        from src.models import SuricataAlert, SuricataAlertSeverity

        alert = SuricataAlert(
            timestamp=datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=1,
            dest_ip="10.0.0.2",
            dest_port=2,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        b = _budget_for(alert)
        assert b["network"] >= 10000
        assert b["forensic"] >= 10000

    def test_sev3_is_smaller_than_sev1(self) -> None:
        from src.analyzer import _budget_for
        from src.models import SuricataAlert, SuricataAlertSeverity

        sev1 = SuricataAlert(
            timestamp=datetime(2026, 4, 20, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=1,
            dest_ip="10.0.0.2",
            dest_port=2,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        sev3 = sev1.model_copy(update={"alert_severity": SuricataAlertSeverity.LOW})
        assert _budget_for(sev3)["network"] < _budget_for(sev1)["network"]
        assert _budget_for(sev3)["forensic"] < _budget_for(sev1)["forensic"]


class TestPruneNetworkContext:
    """Dead / uninteresting network slices must disappear before we
    spend tokens on them."""

    def test_drops_time_wait_and_close_wait(self) -> None:
        from src.analyzer import _prune_network_context
        from src.models import NetworkContext

        ctx = NetworkContext(
            active_connections=[
                {"state": "ESTABLISHED", "dst": "203.0.113.1:443"},
                {"state": "TIME_WAIT", "dst": "203.0.113.2:443"},
                {"state": "CLOSE_WAIT", "dst": "203.0.113.3:443"},
                {"state": "LISTEN", "dst": "0.0.0.0:80"},
                {"state": "FIN_WAIT_2", "dst": "203.0.113.4:443"},
            ],
        )
        pruned = _prune_network_context(ctx)
        states = [c["state"] for c in pruned.active_connections]
        assert "ESTABLISHED" in states
        assert "LISTEN" in states
        assert "TIME_WAIT" not in states
        assert "CLOSE_WAIT" not in states
        assert "FIN_WAIT_2" not in states

    def test_keeps_connections_with_missing_state(self) -> None:
        """Some collectors omit ``state`` for UDP — we keep them."""
        from src.analyzer import _prune_network_context
        from src.models import NetworkContext

        ctx = NetworkContext(
            active_connections=[
                {"proto": "udp", "dst": "10.0.0.53:53"},
                {"state": "", "dst": "10.0.0.54:53"},
            ]
        )
        pruned = _prune_network_context(ctx)
        assert len(pruned.active_connections) == 2

    def test_dns_cache_is_capped(self) -> None:
        from src.analyzer import _prune_network_context
        from src.models import NetworkContext

        ctx = NetworkContext(
            dns_cache=[{"host": f"h{i}.example.", "ip": "10.0.0.1"} for i in range(50)]
        )
        pruned = _prune_network_context(ctx)
        assert len(pruned.dns_cache) == 20
        # Most recent entries retained.
        assert pruned.dns_cache[-1]["host"] == "h49.example."

    def test_arp_and_reputation_preserved(self) -> None:
        from src.analyzer import _prune_network_context
        from src.models import IPReputation, NetworkContext

        ctx = NetworkContext(
            arp_cache=[{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}],
            ip_reputation=IPReputation(ip="203.0.113.1", is_known_malicious=True),
        )
        pruned = _prune_network_context(ctx)
        assert len(pruned.arp_cache) == 1
        assert pruned.ip_reputation is not None
        assert pruned.ip_reputation.is_known_malicious is True


class TestPruneForensicResult:
    """Forensic sysmon / windows-event pruning — time based, fail-open."""

    def _alert_time(self) -> datetime:
        return datetime(2026, 4, 20, 19, 0, 0, tzinfo=timezone.utc)

    def test_drops_sysmon_events_older_than_five_minutes(self) -> None:
        from src.analyzer import _prune_forensic_result
        from src.models import ForensicResult, SysmonEvent

        at = self._alert_time()
        old = SysmonEvent(event_id=1, timestamp=at - timedelta(hours=1), description="old")
        recent = SysmonEvent(event_id=2, timestamp=at - timedelta(seconds=30), description="recent")
        fr = ForensicResult(sysmon_events=[old, recent])
        pruned = _prune_forensic_result(fr, at)
        ids = [e.event_id for e in pruned.sysmon_events]
        assert 2 in ids
        assert 1 not in ids

    def test_keeps_sysmon_events_without_timestamp_when_alert_time_missing(self) -> None:
        """Fail-open: no alert time means we cannot reason about
        recency, so we keep everything (capped only by list size)."""
        from src.analyzer import _prune_forensic_result, _MAX_WINDOWS_EVENTS
        from src.models import ForensicResult, SysmonEvent

        events = [
            SysmonEvent(
                event_id=i,
                timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
                description="x",
            )
            for i in range(_MAX_WINDOWS_EVENTS + 5)
        ]
        fr = ForensicResult(sysmon_events=events)
        pruned = _prune_forensic_result(fr, None)
        assert len(pruned.sysmon_events) == _MAX_WINDOWS_EVENTS

    def test_windows_events_timestamp_filtering(self) -> None:
        from src.analyzer import _prune_forensic_result
        from src.models import ForensicResult

        at = self._alert_time()
        fr = ForensicResult(
            windows_events=[
                {"EventID": 1, "timestamp": (at - timedelta(hours=2)).isoformat()},
                {"EventID": 2, "timestamp": (at - timedelta(minutes=1)).isoformat()},
                {"EventID": 3},  # no timestamp — kept (fail-open)
                {"EventID": 4, "TimeCreated": (at - timedelta(minutes=10)).isoformat()},
            ]
        )
        pruned = _prune_forensic_result(fr, at)
        ids = [e["EventID"] for e in pruned.windows_events]
        assert 1 not in ids  # too old
        assert 4 not in ids  # too old, via TimeCreated
        assert 2 in ids
        assert 3 in ids  # kept because no timestamp

    def test_naive_alert_time_is_treated_as_utc(self) -> None:
        """Operator-provided alert timestamps sometimes arrive naive.
        We must still filter correctly rather than silently keeping
        everything."""
        from src.analyzer import _prune_forensic_result
        from src.models import ForensicResult, SysmonEvent

        at_naive = datetime(2026, 4, 20, 19, 0, 0)  # no tzinfo
        at_utc = at_naive.replace(tzinfo=timezone.utc)
        old = SysmonEvent(
            event_id=1,
            timestamp=at_utc - timedelta(hours=1),
            description="old",
        )
        fr = ForensicResult(sysmon_events=[old])
        pruned = _prune_forensic_result(fr, at_naive)
        assert pruned.sysmon_events == []  # old event still dropped

    def test_preserved_sections(self) -> None:
        from src.analyzer import _prune_forensic_result
        from src.models import ForensicResult

        fr = ForensicResult(
            suspect_processes=[{"pid": 1}],
            suspicious_files=[{"path": "a"}],
            registry_anomalies=[{"key": "x"}],
            process_tree=[{"pid": 1, "children": []}],
        )
        pruned = _prune_forensic_result(fr, self._alert_time())
        assert pruned.suspect_processes == [{"pid": 1}]
        assert pruned.suspicious_files == [{"path": "a"}]
        assert pruned.registry_anomalies == [{"key": "x"}]
        assert pruned.process_tree == [{"pid": 1, "children": []}]


class TestAsAwareUtc:
    """The timestamp coercer is load-bearing for the forensic pruner
    — it must never crash on operator-provided strings."""

    def test_iso_with_z_suffix(self) -> None:
        from src.analyzer import _as_aware_utc

        result = _as_aware_utc("2026-04-20T19:00:00Z")
        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2026

    def test_iso_with_offset(self) -> None:
        from src.analyzer import _as_aware_utc

        result = _as_aware_utc("2026-04-20T19:00:00+02:00")
        assert result is not None

    def test_naive_datetime_promoted_to_utc(self) -> None:
        from src.analyzer import _as_aware_utc

        result = _as_aware_utc(datetime(2026, 4, 20, 19, 0, 0))
        assert result is not None
        assert result.tzinfo is timezone.utc

    def test_garbage_returns_none(self) -> None:
        from src.analyzer import _as_aware_utc

        assert _as_aware_utc("not a date") is None
        assert _as_aware_utc("") is None
        assert _as_aware_utc(None) is None
        assert _as_aware_utc(12345) is None


class TestAdaptiveBudgetEndToEnd:
    """End-to-end: SEV-1 and SEV-3 on the same payload should produce
    prompts of very different sizes, and both should stay well under
    Opus's context limit."""

    def _huge_context(self) -> tuple[NetworkContext, ForensicResult]:
        """Build a payload that would blow the 195 K token budget if
        serialised verbatim."""
        from src.models import NetworkContext, ForensicResult, SysmonEvent

        alert_time = datetime(2026, 4, 20, 19, 0, 0, tzinfo=timezone.utc)
        ctx = NetworkContext(
            active_connections=[
                {"state": "ESTABLISHED", "dst": f"203.0.113.{i}:443"} for i in range(500)
            ],
            dns_cache=[{"host": f"h{i}.example.", "ip": "1.1.1.1"} for i in range(500)],
        )
        fr = ForensicResult(
            sysmon_events=[
                SysmonEvent(
                    event_id=i,
                    timestamp=alert_time - timedelta(seconds=i),
                    description="x" * 200,
                )
                for i in range(1000)
            ],
            windows_events=[{"EventID": i, "data": "y" * 500} for i in range(500)],
        )
        return ctx, fr

    def test_sev1_prompt_is_larger_than_sev3(self) -> None:
        from src.analyzer import ThreatAnalyzer
        from src.models import SuricataAlert, SuricataAlertSeverity

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        ctx, fr = self._huge_context()

        sev1 = SuricataAlert(
            timestamp=datetime(2026, 4, 20, 19, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=1,
            dest_ip="10.0.0.2",
            dest_port=2,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        sev3 = sev1.model_copy(update={"alert_severity": SuricataAlertSeverity.LOW})

        prompt_sev1 = analyzer._build_analysis_prompt(sev1, ctx, fr, None)
        prompt_sev3 = analyzer._build_analysis_prompt(sev3, ctx, fr, None)

        assert len(prompt_sev3) < len(prompt_sev1)

    def test_sev3_prompt_is_bounded(self) -> None:
        """A flood of connections and events must not produce a huge
        prompt on SEV-3."""
        from src.analyzer import ThreatAnalyzer
        from src.models import SuricataAlert, SuricataAlertSeverity

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        ctx, fr = self._huge_context()
        sev3 = SuricataAlert(
            timestamp=datetime(2026, 4, 20, 19, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=1,
            dest_ip="10.0.0.2",
            dest_port=2,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.LOW,
        )

        prompt = analyzer._build_analysis_prompt(sev3, ctx, fr, None)
        # network 3000 + forensic 4000 + alert header (~250) +
        # instructions block (~250) + markdown overhead — very
        # comfortably under 10 K characters.
        assert len(prompt) < 10_000

    def test_pruning_removes_time_wait_before_budget(self) -> None:
        """Dead connections must not eat into the budget."""
        from src.analyzer import ThreatAnalyzer
        from src.models import NetworkContext, SuricataAlert, SuricataAlertSeverity

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            analyzer = ThreatAnalyzer({})

        ctx = NetworkContext(
            active_connections=[
                {"state": "TIME_WAIT", "dst": f"10.0.0.{i}:443"} for i in range(200)
            ]
            + [{"state": "ESTABLISHED", "dst": "203.0.113.1:443"}]
        )
        sev1 = SuricataAlert(
            timestamp=datetime(2026, 4, 20, 19, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=1,
            dest_ip="10.0.0.2",
            dest_port=2,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        prompt = analyzer._build_analysis_prompt(sev1, ctx, None, None)
        # The single ESTABLISHED entry survives; the 200 TIME_WAIT do
        # not occupy any space.
        assert "203.0.113.1" in prompt
        assert "TIME_WAIT" not in prompt
