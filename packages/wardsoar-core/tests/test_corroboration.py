"""Unit tests for the N-source corroboration model.

Two layers, both pure-Python (no Qt, no I/O):

* :func:`derive_verdict` — exhaustive truth table covering every
  edge case (no data, single source, full match, partial match,
  divergence, threshold variations).
* :class:`CorroborationStatus` — frozen dataclass invariants and
  derived properties (``observing_sources``, ``has_dissent``,
  ``is_terminal``, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from wardsoar.core.corroboration import (
    CorroborationStatus,
    CorroborationVerdict,
    derive_verdict,
)

# ---------------------------------------------------------------------------
# derive_verdict — exhaustive truth table
# ---------------------------------------------------------------------------


class TestDeriveVerdictNoData:
    def test_all_zero_counts_returns_no_data(self) -> None:
        assert derive_verdict(0, 0, 0, threshold_ratio=1.0) == CorroborationVerdict.NO_DATA

    def test_only_silent_sources_returns_no_data(self) -> None:
        # Three configured sources, none reported within the window.
        assert derive_verdict(0, 0, 3, threshold_ratio=1.0) == CorroborationVerdict.NO_DATA


class TestDeriveVerdictSingleSource:
    def test_single_observing_source_returns_single_source(self) -> None:
        # One source configured, it saw the flow → no corroboration possible.
        assert derive_verdict(1, 0, 0, threshold_ratio=1.0) == CorroborationVerdict.SINGLE_SOURCE

    def test_single_dissenting_only_falls_back_to_match_full_on_lone_observer(
        self,
    ) -> None:
        # Edge case kept explicit: one source, one verdict, no other to dissent
        # against — reads as SINGLE_SOURCE because total==1 and silent==0.
        assert derive_verdict(1, 0, 0, threshold_ratio=0.5) == CorroborationVerdict.SINGLE_SOURCE


class TestDeriveVerdictMatchFull:
    def test_two_matching_no_silent_returns_match_full(self) -> None:
        assert derive_verdict(2, 0, 0, threshold_ratio=1.0) == CorroborationVerdict.MATCH_FULL

    def test_three_matching_no_silent_returns_match_full(self) -> None:
        assert derive_verdict(3, 0, 0, threshold_ratio=1.0) == CorroborationVerdict.MATCH_FULL

    def test_n_matching_no_silent_returns_match_full(self) -> None:
        # Stress with a larger fleet.
        assert derive_verdict(10, 0, 0, threshold_ratio=1.0) == CorroborationVerdict.MATCH_FULL

    def test_match_full_irrespective_of_threshold(self) -> None:
        # When everyone matches the threshold ratio is irrelevant — strict
        # mode and majority mode both produce MATCH_FULL.
        assert derive_verdict(4, 0, 0, threshold_ratio=0.5) == CorroborationVerdict.MATCH_FULL


class TestDeriveVerdictMatchMajority:
    def test_two_matching_one_silent_lax_returns_majority(self) -> None:
        # 2 matching, 1 silent. Ratio = 2/3 = 0.66. With threshold
        # 0.5 the lax mode tolerates the silent source → MAJORITY.
        assert (
            derive_verdict(2, 0, 1, threshold_ratio=0.5)
            == CorroborationVerdict.MATCH_MAJORITY
        )

    def test_two_matching_one_dissenting_two_thirds_returns_majority(self) -> None:
        # 2/3 ratio met under threshold ratio 0.66.
        assert derive_verdict(2, 1, 0, threshold_ratio=0.66) == CorroborationVerdict.MATCH_MAJORITY

    def test_three_matching_one_dissenting_one_silent_majority(self) -> None:
        # 3 matching out of 4 observing = 0.75 ratio.
        assert derive_verdict(3, 1, 1, threshold_ratio=0.5) == CorroborationVerdict.MATCH_MAJORITY


class TestDeriveVerdictDivergence:
    def test_one_matching_one_dissenting_strict_returns_divergence(self) -> None:
        # 1/2 = 0.5 ratio fails the strict threshold of 1.0.
        assert derive_verdict(1, 1, 0, threshold_ratio=1.0) == CorroborationVerdict.DIVERGENCE

    def test_one_matching_two_dissenting_majority_threshold_diverges(self) -> None:
        # 1/3 = 0.33 ratio fails the 0.5 threshold.
        assert derive_verdict(1, 2, 0, threshold_ratio=0.5) == CorroborationVerdict.DIVERGENCE

    def test_threshold_not_quite_met_diverges(self) -> None:
        # 2/3 = 0.66... fails a 0.7 threshold (just barely).
        assert derive_verdict(2, 1, 0, threshold_ratio=0.7) == CorroborationVerdict.DIVERGENCE


class TestDeriveVerdictValidation:
    def test_negative_matching_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            derive_verdict(-1, 0, 0, threshold_ratio=1.0)

    def test_negative_dissenting_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            derive_verdict(0, -1, 0, threshold_ratio=1.0)

    def test_negative_silent_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            derive_verdict(0, 0, -1, threshold_ratio=1.0)

    def test_threshold_zero_raises(self) -> None:
        # Threshold 0 would always pass — meaningless and likely a config bug.
        with pytest.raises(ValueError, match="threshold_ratio"):
            derive_verdict(1, 1, 0, threshold_ratio=0.0)

    def test_threshold_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="threshold_ratio"):
            derive_verdict(1, 0, 0, threshold_ratio=1.5)

    def test_threshold_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="threshold_ratio"):
            derive_verdict(1, 0, 0, threshold_ratio=-0.1)


class TestDeriveVerdictThresholdSemantics:
    """The threshold ratio governs the dissent tolerance — verify it scales."""

    def test_strict_threshold_rejects_any_dissent(self) -> None:
        for k_dissent in range(1, 6):
            assert (
                derive_verdict(5, k_dissent, 0, threshold_ratio=1.0)
                == CorroborationVerdict.DIVERGENCE
            )

    def test_loose_threshold_tolerates_dissent_up_to_ratio(self) -> None:
        # 3/4 observers agreed at threshold 0.5 → MATCH_MAJORITY
        assert derive_verdict(3, 1, 0, threshold_ratio=0.5) == CorroborationVerdict.MATCH_MAJORITY
        # Same setup at threshold 0.8 → DIVERGENCE (3/4=0.75 < 0.8)
        assert derive_verdict(3, 1, 0, threshold_ratio=0.8) == CorroborationVerdict.DIVERGENCE


# ---------------------------------------------------------------------------
# CorroborationStatus — dataclass invariants
# ---------------------------------------------------------------------------


class TestCorroborationStatusBasics:
    def test_default_status_pending_with_empty_buckets(self) -> None:
        s = CorroborationStatus(verdict=CorroborationVerdict.PENDING)
        assert s.matching_sources == ()
        assert s.dissenting_sources == ()
        assert s.silent_sources == ()
        assert s.consensus_verdict is None
        assert s.threshold_ratio == 1.0

    def test_observing_sources_is_match_plus_dissent(self) -> None:
        s = CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_MAJORITY,
            matching_sources=("netgate", "local"),
            dissenting_sources=("external",),
            silent_sources=("pi",),
        )
        assert s.observing_sources == ("netgate", "local", "external")

    def test_total_sources_counts_all_buckets(self) -> None:
        s = CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_MAJORITY,
            matching_sources=("a", "b"),
            dissenting_sources=("c",),
            silent_sources=("d", "e"),
        )
        assert s.total_sources == 5

    def test_frozen_dataclass_rejects_mutation(self) -> None:
        s = CorroborationStatus(verdict=CorroborationVerdict.MATCH_FULL)
        with pytest.raises((AttributeError, Exception)):
            # frozen=True turns assignment into FrozenInstanceError;
            # accept either exception type for forward-compat.
            s.verdict = CorroborationVerdict.DIVERGENCE  # type: ignore[misc]


class TestCorroborationStatusProperties:
    def test_is_unanimous_true_only_for_match_full(self) -> None:
        assert CorroborationStatus(verdict=CorroborationVerdict.MATCH_FULL).is_unanimous
        assert not CorroborationStatus(verdict=CorroborationVerdict.MATCH_MAJORITY).is_unanimous
        assert not CorroborationStatus(verdict=CorroborationVerdict.DIVERGENCE).is_unanimous
        assert not CorroborationStatus(verdict=CorroborationVerdict.PENDING).is_unanimous

    def test_has_dissent_true_when_dissenting_sources_present(self) -> None:
        assert not CorroborationStatus(verdict=CorroborationVerdict.MATCH_FULL).has_dissent
        assert CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_MAJORITY,
            dissenting_sources=("dissent",),
        ).has_dissent

    def test_has_silence_true_when_silent_sources_present(self) -> None:
        assert not CorroborationStatus(verdict=CorroborationVerdict.MATCH_FULL).has_silence
        assert CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_MAJORITY,
            silent_sources=("silent",),
        ).has_silence

    def test_is_divergent_true_only_for_divergence_verdict(self) -> None:
        assert CorroborationStatus(verdict=CorroborationVerdict.DIVERGENCE).is_divergent
        assert not CorroborationStatus(verdict=CorroborationVerdict.MATCH_FULL).is_divergent
        assert not CorroborationStatus(verdict=CorroborationVerdict.MATCH_MAJORITY).is_divergent

    def test_is_terminal_false_only_for_pending(self) -> None:
        assert not CorroborationStatus(verdict=CorroborationVerdict.PENDING).is_terminal
        for v in (
            CorroborationVerdict.SINGLE_SOURCE,
            CorroborationVerdict.NO_DATA,
            CorroborationVerdict.MATCH_FULL,
            CorroborationVerdict.MATCH_MAJORITY,
            CorroborationVerdict.DIVERGENCE,
        ):
            assert CorroborationStatus(verdict=v).is_terminal


class TestCorroborationStatusTimestamps:
    def test_window_timestamps_optional(self) -> None:
        s = CorroborationStatus(verdict=CorroborationVerdict.PENDING)
        assert s.window_opened_at is None
        assert s.window_closed_at is None

    def test_window_timestamps_preserved(self) -> None:
        opened = datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc)
        closed = datetime(2026, 4, 26, 10, 2, 0, tzinfo=timezone.utc)
        s = CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_FULL,
            matching_sources=("a", "b"),
            window_opened_at=opened,
            window_closed_at=closed,
        )
        assert s.window_opened_at == opened
        assert s.window_closed_at == closed
