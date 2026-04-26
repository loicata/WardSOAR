"""Unit tests for the divergence verdict bumper (Q3 doctrine).

Covers:
  - should_bump: every branch (None, empty checks_run, each explanation)
  - bump_verdict: every verdict on the ladder, with and without bump
  - Idempotence: bumping a non-divergent finding twice changes nothing
  - Logging: INFO emitted on actual bump, DEBUG on no-op-at-top
"""

from __future__ import annotations

import logging
from typing import Optional

import pytest

from wardsoar.core.divergence_verdict_bumper import bump_verdict, should_bump
from wardsoar.core.models import DivergenceFindings, ThreatVerdict

# ---------------------------------------------------------------------------
# Fixtures: minimal findings that exercise each Q3 branch.
# ---------------------------------------------------------------------------


def _findings_unexplained() -> DivergenceFindings:
    """Findings as produced by the investigator when no check matched."""
    return DivergenceFindings(
        checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
        is_explained=False,
        explanation="unexplained",
    )


def _findings_suricata_dead() -> DivergenceFindings:
    """Findings when the local Suricata was found dead during the event."""
    return DivergenceFindings(
        checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
        is_explained=True,
        explanation="suricata_local_dead",
        suricata_local_state="dead",
    )


def _findings_loopback() -> DivergenceFindings:
    return DivergenceFindings(
        checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
        is_explained=True,
        explanation="loopback_traffic",
        is_loopback=True,
    )


def _findings_vpn() -> DivergenceFindings:
    return DivergenceFindings(
        checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
        is_explained=True,
        explanation="vpn_traffic",
        is_vpn=True,
    )


def _findings_lan_only() -> DivergenceFindings:
    return DivergenceFindings(
        checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
        is_explained=True,
        explanation="lan_only_traffic",
        is_lan_only=True,
    )


def _findings_default_empty() -> DivergenceFindings:
    """Findings as produced for non-divergent corroboration (defaults)."""
    return DivergenceFindings()


# ---------------------------------------------------------------------------
# should_bump: branch coverage
# ---------------------------------------------------------------------------


class TestShouldBump:
    def test_none_findings_returns_false(self) -> None:
        assert should_bump(None) is False

    def test_empty_checks_run_returns_false(self) -> None:
        # Defaults from a non-divergent corroboration (SINGLE_SOURCE,
        # MATCH_CONFIRMED, MATCH_PENDING). Empty checks_run is the
        # signal that the investigator did NOT actually run.
        findings = _findings_default_empty()
        assert findings.checks_run == []
        assert should_bump(findings) is False

    def test_unexplained_returns_true(self) -> None:
        assert should_bump(_findings_unexplained()) is True

    def test_suricata_dead_returns_true(self) -> None:
        assert should_bump(_findings_suricata_dead()) is True

    def test_loopback_returns_false(self) -> None:
        assert should_bump(_findings_loopback()) is False

    def test_vpn_returns_false(self) -> None:
        assert should_bump(_findings_vpn()) is False

    def test_lan_only_returns_false(self) -> None:
        assert should_bump(_findings_lan_only()) is False

    def test_unknown_explanation_returns_false(self) -> None:
        # Any explanation not in the trigger set is treated as
        # benign-by-default — fail-safe: a typo or new explanation
        # added later does NOT silently escalate verdicts.
        findings = DivergenceFindings(
            checks_run=["snapshot"],
            is_explained=True,
            explanation="some_future_explanation",
        )
        assert should_bump(findings) is False


# ---------------------------------------------------------------------------
# bump_verdict: ladder coverage with bumping triggers
# ---------------------------------------------------------------------------


class TestBumpLadderWhenBumping:
    """Verdict transitions when findings warrant a bump."""

    def test_benign_bumps_to_suspicious(self) -> None:
        result = bump_verdict(ThreatVerdict.BENIGN, _findings_unexplained())
        assert result == ThreatVerdict.SUSPICIOUS

    def test_suspicious_bumps_to_confirmed(self) -> None:
        result = bump_verdict(ThreatVerdict.SUSPICIOUS, _findings_unexplained())
        assert result == ThreatVerdict.CONFIRMED

    def test_confirmed_stays_confirmed(self) -> None:
        # CONFIRMED is already the maximum — no logical step above.
        result = bump_verdict(ThreatVerdict.CONFIRMED, _findings_unexplained())
        assert result == ThreatVerdict.CONFIRMED

    def test_inconclusive_stays_inconclusive(self) -> None:
        # INCONCLUSIVE has no logical step above — escalating
        # "we don't know" to a positive verdict is not defensible.
        result = bump_verdict(ThreatVerdict.INCONCLUSIVE, _findings_unexplained())
        assert result == ThreatVerdict.INCONCLUSIVE

    def test_suricata_dead_bumps_benign(self) -> None:
        result = bump_verdict(ThreatVerdict.BENIGN, _findings_suricata_dead())
        assert result == ThreatVerdict.SUSPICIOUS

    def test_suricata_dead_bumps_suspicious(self) -> None:
        result = bump_verdict(ThreatVerdict.SUSPICIOUS, _findings_suricata_dead())
        assert result == ThreatVerdict.CONFIRMED


# ---------------------------------------------------------------------------
# bump_verdict: no-bump cases (every verdict, every benign finding)
# ---------------------------------------------------------------------------


class TestBumpLadderWhenNotBumping:
    """No bump applies — verdict returned unchanged at every level."""

    @pytest.mark.parametrize(
        "verdict",
        [
            ThreatVerdict.BENIGN,
            ThreatVerdict.SUSPICIOUS,
            ThreatVerdict.CONFIRMED,
            ThreatVerdict.INCONCLUSIVE,
        ],
    )
    def test_none_findings_leaves_verdict_unchanged(self, verdict: ThreatVerdict) -> None:
        assert bump_verdict(verdict, None) == verdict

    @pytest.mark.parametrize(
        "verdict",
        [
            ThreatVerdict.BENIGN,
            ThreatVerdict.SUSPICIOUS,
            ThreatVerdict.CONFIRMED,
            ThreatVerdict.INCONCLUSIVE,
        ],
    )
    def test_empty_findings_leaves_verdict_unchanged(self, verdict: ThreatVerdict) -> None:
        # Default DivergenceFindings() — non-divergent corroboration.
        assert bump_verdict(verdict, _findings_default_empty()) == verdict

    @pytest.mark.parametrize(
        "verdict",
        [
            ThreatVerdict.BENIGN,
            ThreatVerdict.SUSPICIOUS,
            ThreatVerdict.CONFIRMED,
            ThreatVerdict.INCONCLUSIVE,
        ],
    )
    def test_loopback_leaves_verdict_unchanged(self, verdict: ThreatVerdict) -> None:
        assert bump_verdict(verdict, _findings_loopback()) == verdict

    @pytest.mark.parametrize(
        "verdict",
        [
            ThreatVerdict.BENIGN,
            ThreatVerdict.SUSPICIOUS,
            ThreatVerdict.CONFIRMED,
            ThreatVerdict.INCONCLUSIVE,
        ],
    )
    def test_vpn_leaves_verdict_unchanged(self, verdict: ThreatVerdict) -> None:
        assert bump_verdict(verdict, _findings_vpn()) == verdict

    @pytest.mark.parametrize(
        "verdict",
        [
            ThreatVerdict.BENIGN,
            ThreatVerdict.SUSPICIOUS,
            ThreatVerdict.CONFIRMED,
            ThreatVerdict.INCONCLUSIVE,
        ],
    )
    def test_lan_only_leaves_verdict_unchanged(self, verdict: ThreatVerdict) -> None:
        assert bump_verdict(verdict, _findings_lan_only()) == verdict


# ---------------------------------------------------------------------------
# Idempotence + purity: bumping the same input twice yields the same result.
# ---------------------------------------------------------------------------


class TestPurity:
    """The bumper is a pure function: same input => same output, no side effects."""

    def test_bumping_twice_yields_same_result(self) -> None:
        findings = _findings_unexplained()
        once = bump_verdict(ThreatVerdict.BENIGN, findings)
        twice = bump_verdict(ThreatVerdict.BENIGN, findings)
        assert once == twice == ThreatVerdict.SUSPICIOUS

    def test_findings_object_is_not_mutated(self) -> None:
        findings = _findings_unexplained()
        snapshot_before = findings.model_dump()
        _ = bump_verdict(ThreatVerdict.BENIGN, findings)
        assert findings.model_dump() == snapshot_before

    def test_chain_bumping_walks_the_ladder(self) -> None:
        # Calling bump on the previous result repeatedly must walk
        # the ladder one notch at a time and stop at CONFIRMED.
        findings = _findings_unexplained()
        v1 = bump_verdict(ThreatVerdict.BENIGN, findings)
        v2 = bump_verdict(v1, findings)
        v3 = bump_verdict(v2, findings)
        assert v1 == ThreatVerdict.SUSPICIOUS
        assert v2 == ThreatVerdict.CONFIRMED
        assert v3 == ThreatVerdict.CONFIRMED  # already max


# ---------------------------------------------------------------------------
# Logging: verify INFO line on actual bump, DEBUG line on no-op-at-top.
# ---------------------------------------------------------------------------


class TestLogging:
    def test_actual_bump_logs_info(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger="wardsoar.core.divergence_verdict_bumper")
        bump_verdict(ThreatVerdict.BENIGN, _findings_unexplained())
        assert any(
            "bumping verdict benign -> suspicious" in record.message
            and record.levelno == logging.INFO
            for record in caplog.records
        )

    def test_no_bump_emits_no_info(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger="wardsoar.core.divergence_verdict_bumper")
        bump_verdict(ThreatVerdict.BENIGN, _findings_loopback())
        assert not any(
            "bumping verdict" in record.message and record.levelno == logging.INFO
            for record in caplog.records
        )

    def test_top_of_ladder_emits_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG, logger="wardsoar.core.divergence_verdict_bumper")
        bump_verdict(ThreatVerdict.CONFIRMED, _findings_unexplained())
        assert any(
            "no logical bump" in record.message and record.levelno == logging.DEBUG
            for record in caplog.records
        )

    def test_log_line_includes_explanation(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger="wardsoar.core.divergence_verdict_bumper")
        bump_verdict(ThreatVerdict.SUSPICIOUS, _findings_suricata_dead())
        assert any("explanation=suricata_local_dead" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Defensive: invariant — bumper never returns a verdict not in the enum.
# ---------------------------------------------------------------------------


class TestInvariants:
    def test_output_is_always_a_valid_threatverdict(self) -> None:
        for verdict in ThreatVerdict:
            for findings_factory in (
                _findings_unexplained,
                _findings_suricata_dead,
                _findings_loopback,
                _findings_vpn,
                _findings_lan_only,
                _findings_default_empty,
                lambda: None,  # type: ignore[return-value]
            ):
                findings: Optional[DivergenceFindings] = findings_factory()
                result = bump_verdict(verdict, findings)
                assert isinstance(result, ThreatVerdict)
                assert result in ThreatVerdict

    def test_bump_never_decreases_verdict(self) -> None:
        # Severity ranking: BENIGN < SUSPICIOUS < CONFIRMED.
        # INCONCLUSIVE sits outside the linear ladder and is never
        # changed by the bumper.
        ranking = {
            ThreatVerdict.BENIGN: 0,
            ThreatVerdict.SUSPICIOUS: 1,
            ThreatVerdict.CONFIRMED: 2,
            ThreatVerdict.INCONCLUSIVE: -1,  # outside the ladder
        }
        for verdict in (ThreatVerdict.BENIGN, ThreatVerdict.SUSPICIOUS, ThreatVerdict.CONFIRMED):
            for findings in (
                _findings_unexplained(),
                _findings_suricata_dead(),
                _findings_loopback(),
                _findings_vpn(),
                _findings_lan_only(),
            ):
                result = bump_verdict(verdict, findings)
                assert ranking[result] >= ranking[verdict], (
                    f"verdict {verdict.value} demoted to {result.value} "
                    f"with explanation={findings.explanation}"
                )
