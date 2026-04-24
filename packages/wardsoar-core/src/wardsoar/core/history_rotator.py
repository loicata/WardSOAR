"""Calendar-based rotation of ``alerts_history.jsonl``.

The alerts history file grows linearly with the number of processed
Suricata alerts — one JSON line per alert. Reloading the whole file
at startup inflated the alerts-tab launch time (measured 15 s for
1 700 rows on a mid-range Windows box in 2026).

v0.22.1 switched from size-capped to **calendar-based** rotation so
the data model matches how operators think about their history:

    * The active file ``alerts_history.jsonl`` holds *only* entries
      from the current calendar month (UTC). The UI loads the 200
      most-recent entries at startup and paginates the rest in
      tranches of 200 ("Load older"). A busy 28th of the month
      with a few thousand alerts therefore does not stall the
      launch: the pagination cursor stays inside the running month.
    * Entries from any past month are moved to a monthly archive
      ``alerts_history.<YYYY-MM>.jsonl.gz`` next to the active file,
      gzip-compressed (~10× ratio on JSON). One file per month,
      exactly: no overlap with the active file, no fragmentation.
    * The UI lists every past-month archive in the "Archives" menu
      of the alerts view. Clicking an entry decompresses the whole
      month and appends its alerts to the table in a single batch.

Rotation runs once at every WardSOAR startup. When a long-running
session crosses midnight on the last day of a month, the in-progress
alerts stay in the active file until the next start — they are not
mis-placed; the rotator picks them up on the following launch and
moves them to the now-past month's archive.

Fail-safe: any IO error leaves the active file untouched and logs
a warning. The pipeline never depends on the rotation; it is purely
a UX optimisation.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("ward_soar.history_rotator")


@dataclass(frozen=True)
class RotationResult:
    """Outcome of :func:`rotate_if_needed`.

    Attributes:
        rotated: ``True`` when any past-month entry was moved to an
            archive. ``False`` when the active file only contained
            current-month entries (common case after the first
            startup of a new month).
        lines_before: Line count in the active file before rotation.
        lines_after: Line count in the active file after rotation
            (equals the number of current-month entries kept).
        archive_paths: Paths of the monthly archives that received
            past-month entries — typically 0 or 1, occasionally more
            (e.g. on the first run after a multi-month downtime).
    """

    rotated: bool
    lines_before: int
    lines_after: int
    archive_paths: list[str] = field(default_factory=list)


def rotate_if_needed(history_path: Path) -> RotationResult:
    """Split ``history_path`` so it keeps only current-month entries.

    Idempotent: calling it twice in a row is a no-op — the second
    call sees only current-month lines and returns immediately.

    Args:
        history_path: Absolute path to ``alerts_history.jsonl``.

    Returns:
        :class:`RotationResult` reporting how many entries were moved
        and into which archives.
    """
    if not history_path.is_file():
        return RotationResult(rotated=False, lines_before=0, lines_after=0)

    current_month = _month_key(datetime.now(timezone.utc))

    current_lines: list[bytes] = []
    past_batches: dict[str, list[bytes]] = {}
    total_before = 0

    try:
        with history_path.open("rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                total_before += 1
                month = _month_of_entry(raw, default=current_month)
                if month == current_month:
                    current_lines.append(raw)
                else:
                    past_batches.setdefault(month, []).append(raw)
    except OSError as exc:
        logger.warning("alerts_history rotation failed on read: %s", exc)
        return RotationResult(rotated=False, lines_before=0, lines_after=0)

    if not past_batches:
        return RotationResult(
            rotated=False,
            lines_before=total_before,
            lines_after=total_before,
        )

    archive_paths: list[str] = []
    try:
        for month, lines in past_batches.items():
            archive_path = _append_month_archive(history_path, month, lines)
            archive_paths.append(str(archive_path))
    except OSError as exc:
        logger.warning("alerts_history rotation failed on archive write: %s", exc)
        # Active file is still intact — we bail out before rewriting it.
        return RotationResult(
            rotated=False,
            lines_before=total_before,
            lines_after=total_before,
        )

    try:
        _rewrite_active(history_path, current_lines)
    except OSError as exc:
        logger.warning("alerts_history rotation failed on rewrite: %s", exc)
        return RotationResult(
            rotated=False,
            lines_before=total_before,
            lines_after=total_before,
            archive_paths=archive_paths,
        )

    logger.info(
        "alerts_history rotated: %d → %d lines (archived %d across %d month(s))",
        total_before,
        len(current_lines),
        total_before - len(current_lines),
        len(archive_paths),
    )
    return RotationResult(
        rotated=True,
        lines_before=total_before,
        lines_after=len(current_lines),
        archive_paths=archive_paths,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _month_key(dt: datetime) -> str:
    """UTC ``YYYY-MM`` key for any datetime."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m")


def _month_of_entry(raw_line: bytes, *, default: str) -> str:
    """Extract the ``YYYY-MM`` key from a persisted alert line.

    Persistence adds an ISO-8601 ``_ts`` field to every entry (see
    :meth:`EngineWorker._persist_alert`). A well-formed timestamp
    starts with ``YYYY-MM-DD`` so the first 7 characters are the
    month key. Anything unparseable falls back to ``default`` so we
    never drop data just because a legacy entry is missing the
    timestamp field.
    """
    try:
        obj = json.loads(raw_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default
    if not isinstance(obj, dict):
        return default
    ts = obj.get("_ts") or obj.get("time") or ""
    if isinstance(ts, str) and len(ts) >= 7 and ts[4] == "-":
        candidate = ts[:7]
        try:
            datetime.strptime(candidate, "%Y-%m")
            return candidate
        except ValueError:
            return default
    return default


def _append_month_archive(history_path: Path, month: str, lines: list[bytes]) -> Path:
    """Append ``lines`` to the monthly gzipped archive for ``month``.

    Archive name is ``alerts_history.<YYYY-MM>.jsonl.gz`` next to
    the active file. gzip handles concatenated streams transparently
    so appending across multiple rotations ends up readable as a
    single logical file by ``gunzip``.
    """
    archive_path = history_path.with_name(f"{history_path.stem}.{month}.jsonl.gz")
    with gzip.open(archive_path, "ab") as dst:
        for line in lines:
            dst.write(line)
    return archive_path


def _rewrite_active(history_path: Path, current_lines: list[bytes]) -> None:
    """Atomically rewrite ``history_path`` with only ``current_lines``.

    Uses a temp file next to the target + ``os.replace`` so either
    the rewrite completes and the file is replaced or the temp is
    cleaned up and the original stays intact.
    """
    tmp_path = history_path.with_suffix(history_path.suffix + ".rotating.tmp")
    with tmp_path.open("wb") as dst:
        for line in current_lines:
            dst.write(line)

    # Preserve mtime so anything that keyed off "last appended" does
    # not misinterpret the rotation as fresh activity.
    try:
        stats = history_path.stat()
    except OSError:
        stats = None

    os.replace(tmp_path, history_path)

    if stats is not None:
        try:
            os.utime(history_path, ns=(stats.st_atime_ns, stats.st_mtime_ns))
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Archive listing + purge
# ---------------------------------------------------------------------------


#: Default retention for :func:`purge_old_archives` *if* the operator
#: ever calls it explicitly. The pipeline, the UI and the installer
#: NEVER invoke the purge — archives are kept indefinitely so that a
#: forensic analyst can pull any alert from any past month.
#: The function stays in the module only as a manual tool.
DEFAULT_RETENTION_DAYS = 365


@dataclass(frozen=True)
class ArchiveInfo:
    """Summary of a monthly archive on disk.

    Attributes:
        path: Absolute path of the ``.jsonl.gz`` archive.
        month_iso: ``YYYY-MM`` extracted from the filename (ISO 8601
            year-month).
        size_bytes: File size on disk (compressed).
        age_days: Days between today and the **first** of ``month_iso``
            (UTC). 0 for archives of future months (clock skew).
    """

    path: str
    month_iso: str
    size_bytes: int
    age_days: int


def list_archives(history_path: Path) -> list[ArchiveInfo]:
    """Return all ``alerts_history.<YYYY-MM>.jsonl.gz`` siblings of ``history_path``.

    Sorted newest-first so the Archives menu renders the most
    recently completed month at the top.
    """
    stem = history_path.stem  # "alerts_history"
    directory = history_path.parent
    if not directory.is_dir():
        return []

    archives: list[ArchiveInfo] = []
    today = datetime.now(timezone.utc).date()
    prefix = f"{stem}."
    suffix = ".jsonl.gz"
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        if not (name.startswith(prefix) and name.endswith(suffix)):
            continue
        month_part = name[len(prefix) : -len(suffix)]
        try:
            arch_month = datetime.strptime(month_part, "%Y-%m").date()
        except ValueError:
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        age_days = max(0, (today - arch_month).days)
        archives.append(
            ArchiveInfo(
                path=str(entry),
                month_iso=month_part,
                size_bytes=size,
                age_days=age_days,
            )
        )

    archives.sort(key=lambda a: a.month_iso, reverse=True)
    return archives


def purge_old_archives(
    history_path: Path,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    """Delete archives older than ``retention_days``.

    Returns the number of archives actually removed. Fail-safe: any
    filesystem error is logged but does not raise so the startup
    flow never aborts on a purge issue.
    """
    if retention_days <= 0:
        return 0
    deleted = 0
    for arch in list_archives(history_path):
        if arch.age_days <= retention_days:
            continue
        try:
            os.unlink(arch.path)
            deleted += 1
            logger.info("alerts_history archive purged (age %dd): %s", arch.age_days, arch.path)
        except OSError as exc:
            logger.warning("Could not purge archive %s: %s", arch.path, exc)
    return deleted


def load_archive(archive_path: Path, limit: int | None = None) -> list[str]:
    """Read the gzipped archive and return up to ``limit`` JSONL lines.

    When ``limit`` is ``None`` the whole archive is returned. The UI
    typically asks for the whole archive since each monthly file is
    already bounded; the ``limit`` parameter is kept for flexibility.

    Never raises — malformed archives return an empty list.
    """
    if not archive_path.is_file():
        return []
    try:
        with gzip.open(archive_path, "rt", encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
    except (OSError, gzip.BadGzipFile) as exc:
        logger.warning("Could not load archive %s: %s", archive_path, exc)
        return []
    if limit is not None and limit >= 0:
        return lines[-limit:]
    return lines


__all__ = (
    "ArchiveInfo",
    "DEFAULT_RETENTION_DAYS",
    "RotationResult",
    "list_archives",
    "load_archive",
    "purge_old_archives",
    "rotate_if_needed",
)
