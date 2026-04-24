"""Tests for ``src.user_false_positives``.

The user overlay is written by the Alert Detail view's "Add SID to
filter" button. Regressions in these tests would mean the UI either
silently fails to persist the SID, corrupts the overlay YAML, or
accidentally overwrites the operator's hand-edits.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest
import yaml

from wardsoar.core.user_false_positives import append_sid, list_sids, user_overlay_path


@pytest.fixture
def overlay_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Redirect the overlay path into a temp directory for each test.

    Monkey-patches ``src.config.get_data_dir`` so the module computes
    its overlay path under the temp dir. That keeps tests hermetic and
    avoids polluting the operator's real APPDATA during local dev.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr("src.config.get_data_dir", lambda: data_dir)
    yield data_dir / "config" / "known_false_positives_user.yaml"


class TestAppendSid:
    def test_creates_file_on_first_call(self, overlay_tmp: Path) -> None:
        assert not overlay_tmp.exists()
        ok, msg = append_sid(2210054, signature="STREAM excessive retransmissions")
        assert ok is True
        assert overlay_tmp.is_file()
        # The parent directory was created on our behalf.
        assert overlay_tmp.parent.is_dir()

    def test_produces_readable_yaml(self, overlay_tmp: Path) -> None:
        append_sid(2210054, signature="STREAM excessive retransmissions")
        with open(overlay_tmp, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert "suppressed_signatures" in data
        entries = data["suppressed_signatures"]
        assert len(entries) == 1
        assert entries[0]["signature_id"] == 2210054
        # The note field carries the signature name + a timestamp so
        # an operator hand-editing the file later can recognise the
        # entry without digging through log history.
        assert "STREAM excessive retransmissions" in entries[0]["note"]

    def test_idempotent_same_sid(self, overlay_tmp: Path) -> None:
        """Clicking the button twice for the same SID must not create
        duplicate entries — the overlay should contain the SID exactly
        once, and the second call reports already-present."""
        append_sid(2210054)
        ok, msg = append_sid(2210054)
        assert ok is True
        assert "already" in msg.lower()
        assert list_sids() == [2210054]

    def test_multiple_sids_coexist(self, overlay_tmp: Path) -> None:
        append_sid(2210054, signature="STREAM excessive retransmissions")
        append_sid(2210050, signature="STREAM reassembly overlap")
        append_sid(2017928, signature="ET INFO torproject lookup")
        assert sorted(list_sids()) == [2017928, 2210050, 2210054]

    def test_rejects_invalid_sid(self, overlay_tmp: Path) -> None:
        """Zero and negative SIDs are clearly bogus — the UI should
        never submit them but we belt-and-brace just in case."""
        ok, msg = append_sid(0)
        assert ok is False
        assert "invalid" in msg.lower()
        ok, msg = append_sid(-5)
        assert ok is False

    def test_preserves_existing_entries_on_append(self, overlay_tmp: Path) -> None:
        """An operator may hand-edit the overlay with richer notes or
        extra fields. Appending from the UI MUST preserve everything
        the hand-edit put in — we only append, never rewrite."""
        overlay_tmp.parent.mkdir(parents=True, exist_ok=True)
        overlay_tmp.write_text(
            yaml.safe_dump(
                {
                    "suppressed_signatures": [
                        {
                            "signature_id": 1234567,
                            "note": "Hand-curated on 2026-01-01 — do not auto-remove",
                            "custom_field": "preserved",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        append_sid(2210054)
        with open(overlay_tmp, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        sids = {e["signature_id"] for e in data["suppressed_signatures"]}
        assert sids == {1234567, 2210054}
        # The hand-curated note survived.
        hand = next(e for e in data["suppressed_signatures"] if e["signature_id"] == 1234567)
        assert hand["custom_field"] == "preserved"
        assert "Hand-curated" in hand["note"]

    def test_tolerates_corrupt_overlay(self, overlay_tmp: Path) -> None:
        """A corrupt overlay (hand-edit gone wrong) must NOT crash the
        UI button. We reset to empty + append the new SID; the operator
        can recover by editing their YAML if the previous entries
        mattered."""
        overlay_tmp.parent.mkdir(parents=True, exist_ok=True)
        overlay_tmp.write_text("this is {{{ not valid yaml", encoding="utf-8")
        ok, msg = append_sid(2210054)
        assert ok is True
        assert list_sids() == [2210054]


class TestOverlayPath:
    def test_is_under_data_dir(self) -> None:
        """The overlay lives in ``<data_dir>/config/``, a user-writable
        location. The bundled read-only copy in ``Program Files``
        stays untouched."""
        with patch("wardsoar.core.config.get_data_dir", return_value=Path("C:/tmp/wardsoar")):
            path = user_overlay_path()
        assert "known_false_positives_user.yaml" in str(path)
        assert "config" in path.parent.name
