"""Tests for :class:`wardsoar.pc.ui.controllers.HistoryController`.

The controller was extracted from ``EngineWorker`` in v0.22.12
(refactor V3.2). The whole point of the extraction is that the
persistence layer is now Qt-free and can be unit-tested without a
``QApplication`` — every test here runs in a plain pytest process.

Coverage focus:

* Round-trip — what we ``persist_alert`` we can ``load_alert_history``.
* Pagination — ``limit`` / ``offset`` semantics expected by the
  alerts view ("Load older" cursor walks backward through the file).
* Fail-safe — IO failures, missing files, malformed JSONL lines must
  never raise; pipeline correctness depends on the controller never
  crashing the worker thread.
* Archive reads — real gzipped archives written by hand are decoded
  through :func:`wardsoar.core.history_rotator.load_archive`, which
  the controller wraps.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.pc.ui.controllers import HistoryController

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_controller(tmp_path: Path) -> HistoryController:
    """Build a controller pointing at a fresh history file under ``tmp_path``."""
    return HistoryController(tmp_path / "logs" / "alerts_history.jsonl")


def _read_jsonl(path: Path) -> list[dict]:
    """Read every JSON object from a JSONL file (test helper)."""
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        """The parent dir must be auto-created so the first persist call works."""
        history_path = tmp_path / "deep" / "nested" / "alerts_history.jsonl"
        assert not history_path.parent.exists()
        HistoryController(history_path)
        assert history_path.parent.is_dir()

    def test_does_not_create_history_file_eagerly(self, tmp_path: Path) -> None:
        """Empty install case: no file on disk until the first alert lands."""
        history_path = tmp_path / "logs" / "alerts_history.jsonl"
        HistoryController(history_path)
        assert not history_path.exists()

    def test_history_path_property_exposes_input(self, tmp_path: Path) -> None:
        history_path = tmp_path / "logs" / "alerts_history.jsonl"
        controller = HistoryController(history_path)
        assert controller.history_path == history_path


# ---------------------------------------------------------------------------
# persist_alert
# ---------------------------------------------------------------------------


class TestPersistAlert:
    def test_writes_entry_with_iso_timestamp(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        controller.persist_alert({"src_ip": "1.2.3.4", "verdict": "malicious"})

        entries = _read_jsonl(controller.history_path)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["src_ip"] == "1.2.3.4"
        assert entry["verdict"] == "malicious"
        # _ts is added by the controller and must be parseable as ISO-8601 UTC.
        parsed = datetime.fromisoformat(entry["_ts"])
        assert parsed.tzinfo is not None

    def test_appends_in_arrival_order(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(5):
            controller.persist_alert({"sid": sid})
        entries = _read_jsonl(controller.history_path)
        assert [e["sid"] for e in entries] == [0, 1, 2, 3, 4]

    def test_does_not_mutate_input_dict(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        original = {"src_ip": "1.2.3.4"}
        controller.persist_alert(original)
        # The controller copies before adding _ts; caller's dict stays clean.
        assert "_ts" not in original

    def test_serialises_non_json_safe_values_with_default(self, tmp_path: Path) -> None:
        """``json.dumps(default=str)`` must keep non-JSON values from crashing."""
        controller = _make_controller(tmp_path)
        controller.persist_alert({"when": datetime(2026, 4, 25, 12, tzinfo=timezone.utc)})
        entries = _read_jsonl(controller.history_path)
        assert entries[0]["when"].startswith("2026-04-25")

    def test_swallowed_io_error_does_not_raise(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Disk-full / permission errors must be logged, never propagated."""
        controller = _make_controller(tmp_path)

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(
            "wardsoar.pc.ui.controllers.history_controller.open", boom, raising=False
        )
        controller.persist_alert({"sid": 1})  # must not raise


# ---------------------------------------------------------------------------
# load_alert_history
# ---------------------------------------------------------------------------


class TestLoadAlertHistory:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        assert controller.load_alert_history() == []

    def test_returns_all_entries_by_default(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(10):
            controller.persist_alert({"sid": sid})
        result = controller.load_alert_history()
        assert [e["sid"] for e in result] == list(range(10))

    def test_limit_returns_last_n_entries(self, tmp_path: Path) -> None:
        """The UI loads the most recent 200 at startup."""
        controller = _make_controller(tmp_path)
        for sid in range(10):
            controller.persist_alert({"sid": sid})
        result = controller.load_alert_history(limit=3)
        assert [e["sid"] for e in result] == [7, 8, 9]

    def test_offset_skips_from_the_end(self, tmp_path: Path) -> None:
        """Offset = ``older_than_count`` from the alerts-view perspective."""
        controller = _make_controller(tmp_path)
        for sid in range(10):
            controller.persist_alert({"sid": sid})
        result = controller.load_alert_history(offset=3)
        assert [e["sid"] for e in result] == [0, 1, 2, 3, 4, 5, 6]

    def test_offset_plus_limit_pages_backward(self, tmp_path: Path) -> None:
        """Simulate a "Load older" click after the first page of 3."""
        controller = _make_controller(tmp_path)
        for sid in range(10):
            controller.persist_alert({"sid": sid})
        # First page already shows sids 7,8,9 (limit=3). Next page = next 3 older.
        result = controller.load_alert_history(limit=3, offset=3)
        assert [e["sid"] for e in result] == [4, 5, 6]

    def test_offset_larger_than_file_returns_empty(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(3):
            controller.persist_alert({"sid": sid})
        assert controller.load_alert_history(offset=10) == []

    def test_limit_larger_than_file_returns_all(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(3):
            controller.persist_alert({"sid": sid})
        result = controller.load_alert_history(limit=999)
        assert len(result) == 3

    def test_negative_limit_loads_everything(self, tmp_path: Path) -> None:
        """Negative limit is treated as "no cap" — matches legacy behaviour.

        ``limit=0`` is intentionally not tested: ``alerts[-0:]`` is
        ``alerts[0:]`` in Python, so a zero limit currently returns
        the full list. The UI never calls the loader with 0; the
        contract is "pass ``None`` or a positive int". Behaviour at
        zero is undefined and preserved as-is from the legacy
        ``EngineWorker`` implementation.
        """
        controller = _make_controller(tmp_path)
        for sid in range(3):
            controller.persist_alert({"sid": sid})
        result = controller.load_alert_history(limit=-1)
        assert len(result) == 3

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        """A truncated write must not poison the rest of the file."""
        controller = _make_controller(tmp_path)
        controller.persist_alert({"sid": 0})
        with controller.history_path.open("a", encoding="utf-8") as f:
            f.write("{not-valid-json\n")
        controller.persist_alert({"sid": 2})

        result = controller.load_alert_history()
        assert [e["sid"] for e in result] == [0, 2]

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        with controller.history_path.open("w", encoding="utf-8") as f:
            f.write('{"sid": 1}\n\n\n{"sid": 2}\n')
        result = controller.load_alert_history()
        assert [e["sid"] for e in result] == [1, 2]

    def test_io_error_returns_empty(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable file (permission denied, etc.) yields an empty list."""
        controller = _make_controller(tmp_path)
        controller.persist_alert({"sid": 0})

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("permission denied")

        monkeypatch.setattr(
            "wardsoar.pc.ui.controllers.history_controller.open", boom, raising=False
        )
        assert controller.load_alert_history() == []


# ---------------------------------------------------------------------------
# load_history_page
# ---------------------------------------------------------------------------


class TestLoadHistoryPage:
    def test_delegates_to_load_alert_history(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(20):
            controller.persist_alert({"sid": sid})
        # First batch (already-visible 5 newest entries) comes from
        # ``load_alert_history(limit=5)``. The next batch fetched
        # via ``load_history_page(older_than_count=5, page_size=5)``
        # must be the 5 immediately older entries.
        first = controller.load_alert_history(limit=5)
        assert [e["sid"] for e in first] == [15, 16, 17, 18, 19]
        next_page = controller.load_history_page(older_than_count=5, page_size=5)
        assert [e["sid"] for e in next_page] == [10, 11, 12, 13, 14]

    def test_default_page_size_is_200(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        for sid in range(250):
            controller.persist_alert({"sid": sid})
        page = controller.load_history_page(older_than_count=0)
        assert len(page) == 200
        # Most recent 200 means sids 50..249.
        assert page[0]["sid"] == 50
        assert page[-1]["sid"] == 249


# ---------------------------------------------------------------------------
# list_history_archives
# ---------------------------------------------------------------------------


class TestListHistoryArchives:
    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        assert controller.list_history_archives() == []

    def test_lists_real_gzipped_siblings(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        # Create two monthly archives next to the active file.
        for month in ("2026-02", "2026-03"):
            archive = controller.history_path.parent / f"alerts_history.{month}.jsonl.gz"
            with gzip.open(archive, "wt", encoding="utf-8") as f:
                f.write('{"sid": 1}\n')
        result = controller.list_history_archives()
        assert len(result) == 2
        # Newest first per ``list_archives`` contract.
        assert result[0]["month"] == "2026-03"
        assert result[1]["month"] == "2026-02"
        # Each entry must carry the three keys consumed by the UI.
        for info in result:
            assert set(info.keys()) == {"path", "month", "size_bytes"}
            assert info["size_bytes"] > 0
            assert info["path"].endswith(".jsonl.gz")

    def test_ignores_non_archive_files(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        # Junk file with a similar name must not be picked up.
        (controller.history_path.parent / "alerts_history.txt").write_text("nope")
        # Bad month suffix → not a valid archive name.
        archive = controller.history_path.parent / "alerts_history.NOT-A-MONTH.jsonl.gz"
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            f.write('{"sid": 1}\n')
        assert controller.list_history_archives() == []


# ---------------------------------------------------------------------------
# load_history_from_archive
# ---------------------------------------------------------------------------


class TestLoadHistoryFromArchive:
    def test_round_trips_a_gzipped_archive(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        archive = controller.history_path.parent / "alerts_history.2026-03.jsonl.gz"
        payload = [{"sid": i, "src_ip": f"10.0.0.{i}"} for i in range(3)]
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            for entry in payload:
                f.write(json.dumps(entry) + "\n")

        result = controller.load_history_from_archive(str(archive))
        assert result == payload

    def test_limit_caps_returned_entries(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        archive = controller.history_path.parent / "alerts_history.2026-03.jsonl.gz"
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            for i in range(10):
                f.write(json.dumps({"sid": i}) + "\n")

        result = controller.load_history_from_archive(str(archive), limit=4)
        assert len(result) == 4

    def test_missing_archive_returns_empty(self, tmp_path: Path) -> None:
        controller = _make_controller(tmp_path)
        result = controller.load_history_from_archive(str(tmp_path / "nope.jsonl.gz"))
        assert result == []

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        """An archive corrupted at one line keeps the surrounding entries."""
        controller = _make_controller(tmp_path)
        archive = controller.history_path.parent / "alerts_history.2026-03.jsonl.gz"
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            f.write(json.dumps({"sid": 1}) + "\n")
            f.write("{not-valid-json\n")
            f.write(json.dumps({"sid": 3}) + "\n")
        result = controller.load_history_from_archive(str(archive))
        assert [e["sid"] for e in result] == [1, 3]


# ---------------------------------------------------------------------------
# Integration with list_history_archives → load_history_from_archive
# ---------------------------------------------------------------------------


class TestArchiveRoundTrip:
    def test_listed_archives_can_be_loaded(self, tmp_path: Path) -> None:
        """End-to-end: write archive, list it, load it back via the controller."""
        controller = _make_controller(tmp_path)
        archive = controller.history_path.parent / "alerts_history.2026-03.jsonl.gz"
        payload = [{"sid": i} for i in range(5)]
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            for entry in payload:
                f.write(json.dumps(entry) + "\n")

        listed = controller.list_history_archives()
        assert len(listed) == 1
        loaded = controller.load_history_from_archive(listed[0]["path"])
        assert loaded == payload
