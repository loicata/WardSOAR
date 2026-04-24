"""Tests for the PreScorer feedback store.

Feedback is the teeth behind rollback: a missing or buggy delta means
the next identical alert scores exactly the same as the one the user
just unblocked, and the loop starts over.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.prescorer_feedback import (
    DEFAULT_MAX_AGE_DAYS,
    ROLLBACK_DELTA,
    PreScorerFeedbackStore,
)


class TestFeedbackAdd:
    """Tests for add_feedback / get_delta round-trips."""

    def test_default_delta_is_zero(self, tmp_path: Path) -> None:
        store = PreScorerFeedbackStore(persist_path=tmp_path / "fb.json")
        assert store.get_delta(12345) == 0

    def test_add_feedback_sets_delta(self, tmp_path: Path) -> None:
        store = PreScorerFeedbackStore(persist_path=tmp_path / "fb.json")
        cumulative = store.add_feedback(2024897, ROLLBACK_DELTA)
        assert cumulative == ROLLBACK_DELTA
        assert store.get_delta(2024897) == ROLLBACK_DELTA

    def test_add_feedback_accumulates(self, tmp_path: Path) -> None:
        """Two rollbacks on the same SID must stack."""
        store = PreScorerFeedbackStore(persist_path=tmp_path / "fb.json")
        store.add_feedback(1, -20)
        cumulative = store.add_feedback(1, -20)
        assert cumulative == -40
        assert store.get_delta(1) == -40

    def test_rollback_delta_matches_architecture(self) -> None:
        # docs/architecture.md §4.3 mandates -20.
        assert ROLLBACK_DELTA == -20


class TestExpiry:
    """Tests for age-based pruning."""

    def test_load_prunes_stale_entries(self, tmp_path: Path) -> None:
        """Entries older than max_age are dropped at load time."""
        path = tmp_path / "fb.json"
        stale_timestamp = int(time.time()) - (DEFAULT_MAX_AGE_DAYS * 24 * 3600 + 60)
        path.write_text(
            json.dumps(
                {
                    "100": {"delta": -20, "updated_at": stale_timestamp},
                    "200": {"delta": -10, "updated_at": int(time.time())},
                }
            ),
            encoding="utf-8",
        )

        store = PreScorerFeedbackStore(persist_path=path)
        assert store.get_delta(100) == 0
        assert store.get_delta(200) == -10

    def test_cleanup_expired_after_ttl_shrink(self, tmp_path: Path) -> None:
        """Starting with fresh entries, shrinking max_age_days lets cleanup prune them.

        Simulates what happens when an operator lowers the TTL config on a
        live store.
        """
        path = tmp_path / "fb.json"
        store = PreScorerFeedbackStore(persist_path=path, max_age_days=30)
        store.add_feedback(100, -20)
        store.add_feedback(200, -20)

        # Give the clock a full second so `now - updated_at > 0`.
        time.sleep(1.1)

        # Reopen with a zero-day TTL — every entry is now stale.
        tight = PreScorerFeedbackStore(persist_path=path, max_age_days=0)
        assert tight.snapshot() == {}


class TestPersistence:
    """Tests that deltas survive restarts."""

    def test_deltas_persist(self, tmp_path: Path) -> None:
        path = tmp_path / "fb.json"
        s1 = PreScorerFeedbackStore(persist_path=path)
        s1.add_feedback(12345, -20)

        s2 = PreScorerFeedbackStore(persist_path=path)
        assert s2.get_delta(12345) == -20

    def test_corrupt_file_does_not_raise(self, tmp_path: Path) -> None:
        path = tmp_path / "fb.json"
        path.write_text("<<invalid>>", encoding="utf-8")

        store = PreScorerFeedbackStore(persist_path=path)
        assert store.snapshot() == {}
