"""Tests for the Manual Review workflow (v0.16.0).

Covers the storage layer (append / load / merge) and the Qt
dialog's submission signal. The dialog tests use the shared qapp
fixture from :mod:`tests.test_ui`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.core.manual_reviews import (
    ManualReview,
    append_review,
    default_store_path,
    load_reviews,
    merge_into_history,
    new_review,
)
from src.ui.views.alerts import ManualReviewDialog

# ---------------------------------------------------------------------------
# Storage layer
# ---------------------------------------------------------------------------


class TestStorage:
    def test_new_review_sets_reviewed_at(self) -> None:
        review = new_review(
            alert_ts="2026-04-22T05:00:26+00:00",
            original_verdict="filtered",
            operator_verdict="suspicious",
            notes="looks like scanning",
        )
        assert review.alert_ts == "2026-04-22T05:00:26+00:00"
        assert review.operator_verdict == "suspicious"
        assert review.reviewed_at != ""

    def test_append_then_load(self, tmp_path: Path) -> None:
        store = tmp_path / "reviews.jsonl"
        append_review(
            store,
            new_review(
                "2026-04-22T05:00:26+00:00",
                "filtered",
                "confirmed",
                "bad actor",
            ),
        )
        append_review(
            store,
            new_review(
                "2026-04-22T06:30:00+00:00",
                "benign",
                "",
                "just a note",
            ),
        )
        index = load_reviews(store)
        assert set(index.keys()) == {
            "2026-04-22T05:00:26+00:00",
            "2026-04-22T06:30:00+00:00",
        }
        assert index["2026-04-22T05:00:26+00:00"].operator_verdict == "confirmed"

    def test_latest_review_wins(self, tmp_path: Path) -> None:
        """Re-reviewing an alert overwrites the previous entry at load time."""
        store = tmp_path / "reviews.jsonl"
        append_review(
            store,
            ManualReview(
                alert_ts="same-key",
                original_verdict="filtered",
                operator_verdict="benign",
                notes="first review",
                reviewed_at="2026-04-22T01:00:00+00:00",
            ),
        )
        append_review(
            store,
            ManualReview(
                alert_ts="same-key",
                original_verdict="filtered",
                operator_verdict="confirmed",
                notes="i was wrong, this is real",
                reviewed_at="2026-04-22T02:00:00+00:00",
            ),
        )
        index = load_reviews(store)
        assert index["same-key"].operator_verdict == "confirmed"
        assert "wrong" in index["same-key"].notes

    def test_corrupt_line_is_skipped(self, tmp_path: Path) -> None:
        store = tmp_path / "reviews.jsonl"
        store.write_text(
            "not-json\n"
            '{"alert_ts":"abc","original_verdict":"filtered","operator_verdict":"benign",'
            '"notes":"valid","reviewed_at":"2026-04-22T00:00:00+00:00"}\n',
            encoding="utf-8",
        )
        index = load_reviews(store)
        assert set(index.keys()) == {"abc"}

    def test_missing_file_yields_empty(self, tmp_path: Path) -> None:
        assert load_reviews(tmp_path / "nope.jsonl") == {}

    def test_default_store_path_under_logs(self, tmp_path: Path) -> None:
        assert default_store_path(tmp_path) == tmp_path / "logs" / "manual_reviews.jsonl"


class TestMerge:
    def test_merge_attaches_review_to_matching_alert(self) -> None:
        history: list[dict[str, object]] = [
            {"_ts": "a", "src_ip": "1.1.1.1", "verdict": "filtered"},
            {"_ts": "b", "src_ip": "2.2.2.2", "verdict": "benign"},
            {"_ts": "c", "src_ip": "3.3.3.3", "verdict": "confirmed"},
        ]
        reviews = {
            "a": ManualReview(
                alert_ts="a",
                original_verdict="filtered",
                operator_verdict="confirmed",
                notes="",
                reviewed_at="",
            )
        }
        merge_into_history(history, reviews)
        assert history[0].get("manual_review") is not None
        assert history[1].get("manual_review") is None
        assert history[2].get("manual_review") is None

    def test_merge_handles_alerts_without_ts(self) -> None:
        history: list[dict[str, object]] = [
            {"src_ip": "1.1.1.1"},
            {"_ts": "", "src_ip": "2.2.2.2"},
        ]
        merge_into_history(
            history,
            {
                "": ManualReview(
                    alert_ts="",
                    original_verdict="",
                    operator_verdict="",
                    notes="",
                    reviewed_at="",
                )
            },
        )
        # Alerts without a valid _ts must not be matched.
        for alert in history:
            assert "manual_review" not in alert


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------


@pytest.fixture
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        import sys

        app = QApplication(sys.argv)
    return app


class TestManualReviewDialog:
    def _record(self) -> dict[str, Any]:
        return {
            "_ts": "2026-04-22T05:00:26+00:00",
            "src_ip": "185.199.109.133",
            "dest_ip": "192.168.2.100",
            "signature": "SURICATA STREAM excessive retransmissions",
            "signature_id": "2210054",
            "verdict": "filtered",
        }

    def test_emits_verdict_and_notes(self, qapp: QApplication) -> None:
        dialog = ManualReviewDialog(self._record())
        captured: list[tuple[str, str, str, str]] = []
        dialog.review_submitted.connect(lambda a, b, c, d: captured.append((a, b, c, d)))
        # Pick "Confirmed" (index 1 in the _MANUAL_VERDICT_CHOICES tuple).
        dialog._verdict_combo.setCurrentIndex(1)
        dialog._notes_edit.setPlainText("This IP is clearly malicious.")
        dialog._on_save_clicked()
        assert captured == [
            (
                "2026-04-22T05:00:26+00:00",
                "filtered",
                "confirmed",
                "This IP is clearly malicious.",
            )
        ]

    def test_refuses_empty_submission(self, qapp: QApplication) -> None:
        """Operator must pick an override OR write a note."""
        dialog = ManualReviewDialog(self._record())
        received: list[tuple[str, str, str, str]] = []
        dialog.review_submitted.connect(lambda a, b, c, d: received.append((a, b, c, d)))
        dialog._verdict_combo.setCurrentIndex(0)  # keep-original sentinel
        dialog._notes_edit.setPlainText("")
        dialog._on_save_clicked()
        assert received == []  # nothing emitted

    def test_note_only_submission_is_valid(self, qapp: QApplication) -> None:
        dialog = ManualReviewDialog(self._record())
        received: list[tuple[str, str, str, str]] = []
        dialog.review_submitted.connect(lambda a, b, c, d: received.append((a, b, c, d)))
        dialog._verdict_combo.setCurrentIndex(0)  # keep-original
        dialog._notes_edit.setPlainText("Just a note, verdict is fine.")
        dialog._on_save_clicked()
        assert len(received) == 1
        assert received[0][2] == ""  # empty operator_verdict
        assert "note" in received[0][3].lower()
