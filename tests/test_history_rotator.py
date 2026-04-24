"""Tests for :mod:`src.history_rotator` — calendar-based monthly rotation.

The rotator moves past-month entries out of the active file into
monthly archives. Tests focus on the invariants that matter for
the operator:

1. **Data survival** — every byte that was in the active file is
   still accessible after rotation (either kept because it belongs
   to the current month, or moved into the archive of its month).
2. **Idempotence** — running the rotator twice in a row is a no-op.
3. **No overlap** — the active file and the archives never contain
   the same entry.

They also cover the archive listing consumed by the alerts view
Archives menu.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.history_rotator import (
    ArchiveInfo,
    RotationResult,
    list_archives,
    load_archive,
    purge_old_archives,
    rotate_if_needed,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _month_offset(now: datetime, months_back: int) -> datetime:
    """Return a datetime ``months_back`` calendar months before ``now``.

    Day-of-month is clamped to 15 so we never land on 31 → 30 traps.
    """
    year = now.year
    month = now.month - months_back
    while month <= 0:
        month += 12
        year -= 1
    return datetime(year, month, 15, 12, 0, 0, tzinfo=timezone.utc)


def _write_entry(f, ts: datetime, sid: int) -> None:  # type: ignore[no-untyped-def]
    entry = {"sid": sid, "src_ip": "1.2.3.4", "_ts": ts.isoformat()}
    f.write(json.dumps(entry) + "\n")


def _seed_multi_month(path: Path, now: datetime) -> None:
    """Seed ``path`` with a mix of current-month + past-month lines."""
    current = now
    prev_month = _month_offset(now, 1)
    two_months_ago = _month_offset(now, 2)
    with path.open("w", encoding="utf-8") as f:
        for sid in range(3):
            _write_entry(f, two_months_ago, sid)
        for sid in range(3, 8):
            _write_entry(f, prev_month, sid)
        for sid in range(8, 15):
            _write_entry(f, current, sid)


def _read_gzip_jsons(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _read_active_jsons(path: Path) -> list[dict]:
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# rotate_if_needed — calendar split
# ---------------------------------------------------------------------------


class TestRotateIfNeeded:
    def test_missing_file_returns_empty_result(self, tmp_path: Path) -> None:
        result = rotate_if_needed(tmp_path / "absent.jsonl")
        assert result == RotationResult(rotated=False, lines_before=0, lines_after=0)

    def test_all_current_month_is_noop(self, tmp_path: Path) -> None:
        """An active file that already contains only current-month entries is untouched."""
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        with history.open("w", encoding="utf-8") as f:
            for sid in range(10):
                _write_entry(f, now, sid)
        result = rotate_if_needed(history)
        assert result.rotated is False
        assert result.lines_before == 10
        assert result.lines_after == 10
        assert result.archive_paths == []
        # Active file untouched
        assert len(_read_active_jsons(history)) == 10

    def test_past_month_entries_move_to_archive(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        _seed_multi_month(history, now)
        result = rotate_if_needed(history)
        assert result.rotated is True
        assert result.lines_before == 15
        assert result.lines_after == 7  # the 7 current-month entries
        # Two months produced → two archive paths
        assert len(result.archive_paths) == 2

    def test_no_overlap_between_active_and_archives(self, tmp_path: Path) -> None:
        """The same SID can NEVER appear in both the active file and an archive."""
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        _seed_multi_month(history, now)
        result = rotate_if_needed(history)

        active_sids = {e["sid"] for e in _read_active_jsons(history)}
        archive_sids: set[int] = set()
        for apath in result.archive_paths:
            archive_sids.update(e["sid"] for e in _read_gzip_jsons(Path(apath)))

        assert active_sids.isdisjoint(archive_sids)
        assert active_sids | archive_sids == set(range(15))

    def test_archive_filenames_are_monthly(self, tmp_path: Path) -> None:
        """Each archive is named ``alerts_history.YYYY-MM.jsonl.gz``."""
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        _seed_multi_month(history, now)
        result = rotate_if_needed(history)
        for apath in result.archive_paths:
            name = Path(apath).name
            assert name.startswith("alerts_history.")
            assert name.endswith(".jsonl.gz")
            month_part = name[len("alerts_history.") : -len(".jsonl.gz")]
            datetime.strptime(month_part, "%Y-%m")  # raises if malformed

    def test_rotation_is_idempotent(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        _seed_multi_month(history, now)
        r1 = rotate_if_needed(history)
        r2 = rotate_if_needed(history)
        assert r1.rotated is True
        assert r2.rotated is False
        assert r2.lines_before == r1.lines_after
        assert r2.lines_after == r1.lines_after

    def test_second_rotation_same_month_appends_to_archive(self, tmp_path: Path) -> None:
        """Two rotations that target the same past month concatenate.

        We simulate this by rotating, then re-seeding the active
        file with fresh past-month entries and rotating again. The
        prior-month archive must end up containing both batches.
        """
        history = tmp_path / "alerts_history.jsonl"
        now = datetime.now(timezone.utc)
        prev_month = _month_offset(now, 1)

        # First round — 5 prior-month entries.
        with history.open("w", encoding="utf-8") as f:
            for sid in range(5):
                _write_entry(f, prev_month, sid)
        r1 = rotate_if_needed(history)
        assert r1.rotated is True
        assert len(r1.archive_paths) == 1

        # Second round — 3 more prior-month entries added to the active
        # file (perhaps recovered from a late-arriving backlog).
        with history.open("a", encoding="utf-8") as f:
            for sid in range(5, 8):
                _write_entry(f, prev_month, sid)
        r2 = rotate_if_needed(history)
        assert r2.rotated is True
        assert r2.archive_paths == r1.archive_paths
        # Same archive now carries all 8 entries.
        archived = _read_gzip_jsons(Path(r1.archive_paths[0]))
        assert sorted(e["sid"] for e in archived) == list(range(8))

    def test_legacy_entry_without_timestamp_stays_active(self, tmp_path: Path) -> None:
        """A line missing ``_ts`` / ``time`` is assumed current-month.

        Safer than attempting to guess the month: the entry simply
        remains in the active file and the next rotation might move
        it if a future version ever infers a month.
        """
        history = tmp_path / "alerts_history.jsonl"
        with history.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"sid": 1}) + "\n")  # no timestamp
        result = rotate_if_needed(history)
        assert result.rotated is False
        assert result.lines_after == 1

    def test_malformed_line_stays_active(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        history.write_text("not a json line\n", encoding="utf-8")
        result = rotate_if_needed(history)
        assert result.rotated is False
        # The junk line is preserved — we never throw data away.
        assert history.read_text(encoding="utf-8").strip() == "not a json line"


# ---------------------------------------------------------------------------
# list_archives
# ---------------------------------------------------------------------------


class TestListArchives:
    def test_returns_empty_when_dir_missing(self, tmp_path: Path) -> None:
        history = tmp_path / "no_such_dir" / "alerts_history.jsonl"
        assert list_archives(history) == []

    def test_returns_empty_when_no_archives(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        assert list_archives(history) == []

    def test_skips_non_month_siblings(self, tmp_path: Path) -> None:
        """Legacy ``YYYY-MM-DD`` archives and other junk are ignored.

        The operator can still unzip them manually; they just don't
        appear in the Archives menu so the list stays clean.
        """
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        (tmp_path / "alerts_history.nonsense.jsonl.gz").write_bytes(b"")
        (tmp_path / "alerts_history.2026-04-15.jsonl.gz").write_bytes(b"")  # legacy day
        (tmp_path / "alerts_history.2026-04.jsonl.gz").write_bytes(b"")  # current
        names = [a.month_iso for a in list_archives(history)]
        assert names == ["2026-04"]

    def test_sorted_newest_first(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        for month in ("2026-01", "2026-04", "2025-12"):
            (tmp_path / f"alerts_history.{month}.jsonl.gz").write_bytes(b"")
        months = [a.month_iso for a in list_archives(history)]
        assert months == ["2026-04", "2026-01", "2025-12"]

    def test_age_days_is_non_negative(self, tmp_path: Path) -> None:
        """Future-dated archives (clock skew) report age 0, not a negative."""
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        future = datetime.now(timezone.utc).date() + timedelta(days=40)
        month = future.strftime("%Y-%m")
        (tmp_path / f"alerts_history.{month}.jsonl.gz").write_bytes(b"")
        infos = list_archives(history)
        assert len(infos) == 1
        assert infos[0].age_days == 0

    def test_age_days_reflects_past_months(self, tmp_path: Path) -> None:
        """A ~90-day-old archive reports an age roughly in that range."""
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        today = datetime.now(timezone.utc).date()
        past = today - timedelta(days=90)
        month = past.strftime("%Y-%m")
        (tmp_path / f"alerts_history.{month}.jsonl.gz").write_bytes(b"")
        infos = list_archives(history)
        assert len(infos) == 1
        assert 60 <= infos[0].age_days <= 120


# ---------------------------------------------------------------------------
# load_archive
# ---------------------------------------------------------------------------


class TestLoadArchive:
    def test_roundtrip_without_limit(self, tmp_path: Path) -> None:
        archive = tmp_path / "alerts_history.2026-04.jsonl.gz"
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            for i in range(5):
                f.write(json.dumps({"sid": i}) + "\n")
        lines = load_archive(archive)
        assert len(lines) == 5
        assert json.loads(lines[0])["sid"] == 0

    def test_limit_returns_tail(self, tmp_path: Path) -> None:
        archive = tmp_path / "alerts_history.2026-04.jsonl.gz"
        with gzip.open(archive, "wt", encoding="utf-8") as f:
            for i in range(10):
                f.write(json.dumps({"sid": i}) + "\n")
        lines = load_archive(archive, limit=3)
        assert len(lines) == 3
        assert json.loads(lines[0])["sid"] == 7
        assert json.loads(lines[-1])["sid"] == 9

    def test_missing_archive_returns_empty(self, tmp_path: Path) -> None:
        assert load_archive(tmp_path / "missing.jsonl.gz") == []

    def test_corrupt_archive_returns_empty(self, tmp_path: Path) -> None:
        archive = tmp_path / "alerts_history.2026-04.jsonl.gz"
        archive.write_bytes(b"this is not gzip")
        assert load_archive(archive) == []


# ---------------------------------------------------------------------------
# purge_old_archives — manual tool only
# ---------------------------------------------------------------------------


class TestPurgeOldArchives:
    def test_deletes_only_beyond_retention(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        today = datetime.now(timezone.utc).date()
        recent_month = today.strftime("%Y-%m")
        old_month = (today - timedelta(days=400)).strftime("%Y-%m")
        (tmp_path / f"alerts_history.{recent_month}.jsonl.gz").write_bytes(b"")
        (tmp_path / f"alerts_history.{old_month}.jsonl.gz").write_bytes(b"")

        deleted = purge_old_archives(history, retention_days=365)
        assert deleted == 1
        remaining = [a.month_iso for a in list_archives(history)]
        assert remaining == [recent_month]

    def test_retention_zero_is_noop(self, tmp_path: Path) -> None:
        """Zero / negative retention must not wipe archives — safety rail."""
        history = tmp_path / "alerts_history.jsonl"
        history.touch()
        old_month = (datetime.now(timezone.utc).date() - timedelta(days=500)).strftime("%Y-%m")
        (tmp_path / f"alerts_history.{old_month}.jsonl.gz").write_bytes(b"")
        assert purge_old_archives(history, retention_days=0) == 0
        assert len(list_archives(history)) == 1


class TestDataclasses:
    def test_rotation_result_is_frozen(self) -> None:
        r = RotationResult(rotated=True, lines_before=100, lines_after=50)
        with pytest.raises(Exception):
            r.rotated = False  # type: ignore[misc]

    def test_archive_info_is_frozen(self) -> None:
        a = ArchiveInfo(path="p", month_iso="2026-01", size_bytes=0, age_days=0)
        with pytest.raises(Exception):
            a.age_days = 1  # type: ignore[misc]
