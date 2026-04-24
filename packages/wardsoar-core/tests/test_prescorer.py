"""Tests for WardSOAR alert pre-scoring.

PreScorer is HIGH (85% coverage). Safety-critical: the threshold
can NEVER exceed MAX_ALLOWED_THRESHOLD (30). Learning mode NEVER filters.
"""

from datetime import datetime, timezone

import pytest

from wardsoar.core.models import IPReputation, SuricataAlert, SuricataAlertSeverity
from wardsoar.core.prescorer import MAX_ALLOWED_THRESHOLD, AlertPreScorer, PreScoreResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(severity: SuricataAlertSeverity = SuricataAlertSeverity.HIGH) -> SuricataAlert:
    """Create a test alert with configurable severity."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test Alert",
        alert_signature_id=2024897,
        alert_severity=severity,
    )


DEFAULT_WEIGHTS = {
    "severity_1": 40,
    "severity_2": 25,
    "severity_3": 10,
    "ip_known_malicious": 30,
    "ip_unknown": 10,
    "multiple_signatures": 20,
    "suspicious_port": 15,
    "sysmon_process_match": 25,
    "outside_business_hours": 10,
    "burst_alert": 20,
}


def _default_config(mode: str = "learning", threshold: int = 15) -> dict:
    """Create a default PreScorer config."""
    return {
        "enabled": True,
        "mode": mode,
        "min_score_for_analysis": threshold,
        "min_guaranteed_score": 10,
        "weights": DEFAULT_WEIGHTS,
        "log_all_scores": True,
    }


# ---------------------------------------------------------------------------
# Safety guardrail tests
# ---------------------------------------------------------------------------


class TestPreScorerSafety:
    """Tests for PreScorer safety constraints."""

    def test_max_threshold_constant(self) -> None:
        assert MAX_ALLOWED_THRESHOLD == 30

    def test_threshold_above_max_raises(self) -> None:
        with pytest.raises(ValueError, match="exceeds safety maximum"):
            AlertPreScorer({"min_score_for_analysis": 31})

    def test_threshold_at_max_is_allowed(self) -> None:
        scorer = AlertPreScorer(_default_config(threshold=30))
        assert scorer._threshold == 30

    def test_default_mode_is_learning(self) -> None:
        scorer = AlertPreScorer({"enabled": True})
        assert scorer.mode == "learning"


# ---------------------------------------------------------------------------
# PreScoreResult tests
# ---------------------------------------------------------------------------


class TestPreScoreResult:
    """Tests for PreScoreResult behavior."""

    def test_learning_mode_always_analyzes(self) -> None:
        result = PreScoreResult(total_score=0, factors={}, threshold=15, mode="learning")
        assert result.should_analyze is True
        assert result.was_filtered is False

    def test_active_mode_above_threshold(self) -> None:
        result = PreScoreResult(total_score=20, factors={}, threshold=15, mode="active")
        assert result.should_analyze is True
        assert result.was_filtered is False

    def test_active_mode_below_threshold(self) -> None:
        result = PreScoreResult(total_score=10, factors={}, threshold=15, mode="active")
        assert result.should_analyze is False
        assert result.was_filtered is True

    def test_active_mode_at_threshold(self) -> None:
        result = PreScoreResult(total_score=15, factors={}, threshold=15, mode="active")
        assert result.should_analyze is True


# ---------------------------------------------------------------------------
# Scoring logic tests
# ---------------------------------------------------------------------------


class TestScoring:
    """Tests for AlertPreScorer.score."""

    def test_severity_1_scores_high(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.HIGH)
        result = scorer.score(alert)
        assert result.total_score >= 40  # severity_1 weight alone

    def test_severity_3_scores_low(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert)
        assert result.total_score >= 10  # min_guaranteed + severity_3

    def test_severity_1_always_passes_threshold(self) -> None:
        """A single severity_1 alert must ALWAYS pass, even at max threshold."""
        scorer = AlertPreScorer(_default_config(mode="active", threshold=30))
        alert = _make_alert(SuricataAlertSeverity.HIGH)
        result = scorer.score(alert)
        assert result.should_analyze is True

    def test_ip_reputation_malicious_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        rep = IPReputation(ip="10.0.0.1", is_known_malicious=True)
        result = scorer.score(alert, ip_reputation=rep)
        assert "ip_known_malicious" in result.factors

    def test_ip_reputation_unknown_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        rep = IPReputation(ip="10.0.0.1", is_known_malicious=False)
        result = scorer.score(alert, ip_reputation=rep)
        assert "ip_unknown" in result.factors

    def test_suspicious_port_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert, is_suspicious_port=True)
        assert "suspicious_port" in result.factors

    def test_sysmon_match_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert, has_sysmon_match=True)
        assert "sysmon_process_match" in result.factors

    def test_outside_hours_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert, is_outside_hours=True)
        assert "outside_business_hours" in result.factors

    def test_burst_alert_adds_score(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert, alert_group_size=5)
        assert "burst_alert" in result.factors

    def test_no_burst_for_single_alert(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert, alert_group_size=1)
        assert "burst_alert" not in result.factors

    def test_learning_mode_never_filters(self) -> None:
        scorer = AlertPreScorer(_default_config(mode="learning", threshold=30))
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert)
        assert result.should_analyze is True
        assert result.was_filtered is False

    def test_active_mode_filters_low_score(self) -> None:
        scorer = AlertPreScorer(_default_config(mode="active", threshold=25))
        alert = _make_alert(SuricataAlertSeverity.LOW)
        # severity_3 = 10, no other factors → total ~10, below 25
        result = scorer.score(alert)
        assert result.should_analyze is False
        assert result.was_filtered is True

    def test_disabled_scorer_always_analyzes(self) -> None:
        scorer = AlertPreScorer({"enabled": False})
        alert = _make_alert(SuricataAlertSeverity.LOW)
        result = scorer.score(alert)
        assert result.should_analyze is True

    def test_all_factors_combined(self) -> None:
        scorer = AlertPreScorer(_default_config())
        alert = _make_alert(SuricataAlertSeverity.HIGH)
        rep = IPReputation(ip="10.0.0.1", is_known_malicious=True)
        result = scorer.score(
            alert,
            ip_reputation=rep,
            alert_group_size=5,
            has_sysmon_match=True,
            is_suspicious_port=True,
            is_outside_hours=True,
        )
        # Should have a very high score with all factors
        assert result.total_score > 100
        assert len(result.factors) >= 5
