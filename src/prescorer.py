"""Pre-score alerts locally before sending to Claude API.

Computes a weighted threat score based on multiple factors
(severity, IP reputation, port suspicion, Sysmon matches, etc.)
to filter out low-priority alerts and save API calls.

DESIGN PHILOSOPHY — CONSERVATIVE BY DEFAULT:
The prescorer exists to reduce noise, NOT to make security decisions.
It is always safer to send an alert to Claude than to filter it out.
A prescorer that lets everything through = wasted API calls (acceptable).
A prescorer that filters a real threat = critical failure (unacceptable).

The prescorer starts in "learning" mode where it computes scores
but never filters. Switch to "active" mode ONLY after reviewing
the decision log and confirming the threshold is safe.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from src.known_bad_actors import ActorMatch
from src.models import IPReputation, SuricataAlert
from src.prescorer_feedback import PreScorerFeedbackStore
from src.suspect_asns import AsnClassification

logger = logging.getLogger("ward_soar.prescorer")

# Absolute ceiling for min_score_for_analysis — safety guardrail.
# Even in active mode, the threshold cannot exceed this value.
# This ensures that a single severity_1 alert always passes.
MAX_ALLOWED_THRESHOLD = 30

# Default scoring weights
_DEFAULT_WEIGHTS: dict[str, int] = {
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


class PreScoreResult:
    """Result of local pre-scoring.

    Attributes:
        total_score: Weighted score total.
        factors: Dict of individual scoring factors and their contributions.
        should_analyze: Whether the score meets the threshold for Claude API analysis.
        was_filtered: Whether the alert was actually filtered (False in learning mode).
    """

    def __init__(
        self,
        total_score: int,
        factors: dict[str, int],
        threshold: int,
        mode: str,
    ) -> None:
        self.total_score = total_score
        self.factors = factors
        self.threshold = threshold
        self.mode = mode
        # In learning mode, should_analyze is ALWAYS True
        self.should_analyze = True if mode == "learning" else total_score >= threshold
        self.was_filtered = not self.should_analyze


class AlertPreScorer:
    """Compute weighted threat scores for alerts before Claude API call.

    Args:
        config: PreScorer configuration dict from config.yaml.

    Raises:
        ValueError: If min_score_for_analysis exceeds MAX_ALLOWED_THRESHOLD.
    """

    def __init__(
        self,
        config: dict[str, Any],
        feedback_store: Optional[PreScorerFeedbackStore] = None,
    ) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._mode: str = config.get("mode", "learning")
        self._threshold: int = config.get("min_score_for_analysis", 15)
        self._min_guaranteed_score: int = config.get("min_guaranteed_score", 10)
        self._weights: dict[str, int] = config.get("weights", _DEFAULT_WEIGHTS)
        self._log_all_scores: bool = config.get("log_all_scores", True)
        # Optional feedback loop: user rollbacks reduce the score of the
        # originating signature on subsequent alerts. Left None in tests
        # that don't exercise that code path.
        self._feedback = feedback_store

        # Safety guardrail: prevent dangerously high thresholds
        if self._threshold > MAX_ALLOWED_THRESHOLD:
            raise ValueError(
                f"min_score_for_analysis ({self._threshold}) exceeds safety maximum "
                f"({MAX_ALLOWED_THRESHOLD}). A threshold this high risks filtering "
                f"real threats. Lower it or provide justification."
            )

    @property
    def mode(self) -> str:
        """Current operating mode: 'learning' or 'active'."""
        return self._mode

    def _score_severity(self, alert: SuricataAlert) -> tuple[str, int]:
        """Score based on Suricata alert severity.

        Args:
            alert: The alert to score.

        Returns:
            Tuple of (factor_name, score_value).
        """
        severity_key = f"severity_{alert.alert_severity.value}"
        score = self._weights.get(severity_key, 0)
        return severity_key, score

    def _score_ip_reputation(self, ip_reputation: Optional[IPReputation]) -> tuple[str, int]:
        """Score based on IP reputation data.

        Args:
            ip_reputation: IP reputation data, if available.

        Returns:
            Tuple of (factor_name, score_value).
        """
        if ip_reputation is None:
            return "", 0
        if ip_reputation.is_known_malicious:
            return "ip_known_malicious", self._weights.get("ip_known_malicious", 0)
        return "ip_unknown", self._weights.get("ip_unknown", 0)

    def score(
        self,
        alert: SuricataAlert,
        ip_reputation: Optional[IPReputation] = None,
        alert_group_size: int = 1,
        has_sysmon_match: bool = False,
        is_suspicious_port: bool = False,
        is_outside_hours: bool = False,
        asn_classification: Optional[AsnClassification] = None,
        known_actor_match: Optional[ActorMatch] = None,
        process_risk_verdict: Optional[str] = None,
        history_signals: Optional[Any] = None,
    ) -> PreScoreResult:
        """Compute a weighted threat score for an alert.

        In learning mode, the score is computed and logged but the alert
        is NEVER filtered — should_analyze is always True.

        Args:
            alert: The Suricata alert to score.
            ip_reputation: IP reputation data if available.
            alert_group_size: Number of alerts in the dedup group.
            has_sysmon_match: Whether Sysmon found a matching process.
            is_suspicious_port: Whether the port is in the suspicious list.
            is_outside_hours: Whether the alert is outside business hours.

        Returns:
            PreScoreResult with score, factors, and analysis recommendation.
        """
        if not self._enabled:
            return PreScoreResult(total_score=0, factors={}, threshold=0, mode="learning")

        factors: dict[str, int] = {}

        # Severity score
        sev_name, sev_score = self._score_severity(alert)
        if sev_score > 0:
            factors[sev_name] = sev_score

        # IP reputation score
        rep_name, rep_score = self._score_ip_reputation(ip_reputation)
        if rep_name and rep_score > 0:
            factors[rep_name] = rep_score

        # Suspicious port
        if is_suspicious_port:
            factors["suspicious_port"] = self._weights.get("suspicious_port", 0)

        # Sysmon process match
        if has_sysmon_match:
            factors["sysmon_process_match"] = self._weights.get("sysmon_process_match", 0)

        # Outside business hours
        if is_outside_hours:
            factors["outside_business_hours"] = self._weights.get("outside_business_hours", 0)

        # Burst alert (group size > 1)
        if alert_group_size > 1:
            factors["burst_alert"] = self._weights.get("burst_alert", 0)

        # Threat-actor-aware: an IP on a VPN / proxy / Tor ASN adds
        # weight independently of reputation lists. A fresh exit node
        # with a clean AbuseIPDB score is still traffic from an
        # anonymisation service. See docs/architecture.md § Phase 4.5
        # and src/suspect_asns.py for the category weights.
        if asn_classification is not None and asn_classification.total_weight > 0:
            factors["anonymization_risk"] = asn_classification.weight
            if asn_classification.priority_country_bonus > 0:
                factors["priority_country"] = asn_classification.priority_country_bonus

        # Known adversary IOC (Phase 4.6) — a match against the operator's
        # curated known-bad-actors list pushes the score high enough on
        # its own to trigger Opus review, so any contact with confirmed
        # infrastructure gets adjudicated rather than silently dropped.
        if known_actor_match is not None:
            factors["known_bad_actor"] = known_actor_match.weight

        # Local process risk (v0.20.3) — verdicts from
        # :mod:`src.process_risk` for the process attributed to this
        # flow. Strong positive signal on malicious / suspicious (we
        # want Opus to adjudicate); mild negative on benign so a flow
        # from a trusted Microsoft-signed binary gets filtered with
        # more confidence.
        if process_risk_verdict == "malicious":
            factors["process_risk_malicious"] = 40
        elif process_risk_verdict == "suspicious":
            factors["process_risk_suspicious"] = 20
        elif process_risk_verdict == "benign":
            factors["process_risk_benign"] = -10
        # ``unknown`` contributes nothing — that is the default for
        # any alert whose flow we could not attribute to a PID.

        # Longitudinal history signals (v0.22 alerts_stats) — pattern
        # detection over a week-long window. Three factors:
        #   * ``regularity`` ≥ 0.8 → beacon-like cadence, bump score
        #     so Opus gets called even if other signals are tame.
        #   * ``novelty`` → first time we see this SID/IP this week,
        #     mild bump to force a look.
        #   * ``stable benign for ≥20 occurrences`` → strong prior, can
        #     subtract a bit so the analyser is not called on the 21st
        #     identical benign alert.
        if history_signals is not None:
            reg = getattr(history_signals, "regularity", None)
            if reg is not None and reg >= 0.8 and history_signals.total_count >= 10:
                factors["history_beacon_like"] = 15
            if getattr(history_signals, "novelty", False):
                factors["history_novelty"] = 10
            stab = getattr(history_signals, "verdict_stability", 0.0)
            dom = getattr(history_signals, "dominant_verdict", "")
            if stab >= 0.9 and dom == "benign" and history_signals.total_count >= 20:
                factors["history_stable_benign"] = -10

        total_score = sum(factors.values())

        # User-feedback delta (from past rollbacks on this signature).
        # Recorded as a factor so the score log shows why the adjustment
        # happened.
        if self._feedback is not None:
            feedback_delta = self._feedback.get_delta(alert.alert_signature_id)
            if feedback_delta != 0:
                factors["user_feedback"] = feedback_delta
                total_score += feedback_delta

        result = PreScoreResult(
            total_score=total_score,
            factors=factors,
            threshold=self._threshold,
            mode=self._mode,
        )

        if self._log_all_scores:
            logger.info(
                "PreScore: SID %d from %s — score=%d threshold=%d "
                "should_analyze=%s mode=%s factors=%s",
                alert.alert_signature_id,
                alert.src_ip,
                total_score,
                self._threshold,
                result.should_analyze,
                self._mode,
                factors,
            )

        return result
