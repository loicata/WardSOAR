"""Tests for the Manual Review Qt dialog (v0.16.0).

Split off from ``packages/wardsoar-core/tests/test_manual_reviews.py``
in v0.22.11 so the core storage tests no longer drag Qt into
``wardsoar.core``'s test scope (UI layering decision —
see ``docs/ARCHITECTURE.md``).
"""

from __future__ import annotations

from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.pc.ui.views.alerts import ManualReviewDialog


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
        dialog._verdict_combo.setCurrentIndex(0)
        dialog._notes_edit.setPlainText("")
        dialog._on_save_clicked()
        assert received == []

    def test_note_only_submission_is_valid(self, qapp: QApplication) -> None:
        dialog = ManualReviewDialog(self._record())
        received: list[tuple[str, str, str, str]] = []
        dialog.review_submitted.connect(lambda a, b, c, d: received.append((a, b, c, d)))
        dialog._verdict_combo.setCurrentIndex(0)
        dialog._notes_edit.setPlainText("Just a note, verdict is fine.")
        dialog._on_save_clicked()
        assert len(received) == 1
        assert received[0][2] == ""
        assert "note" in received[0][3].lower()
