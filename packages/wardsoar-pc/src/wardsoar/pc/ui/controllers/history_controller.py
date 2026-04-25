"""Alert history persistence and retrieval — Qt-free controller.

Owns ``alerts_history.jsonl`` and the monthly archive lookup helpers
that the alerts view needs at startup and on "Load older" / "Open
archive" clicks. Extracted from ``EngineWorker`` (V3.2, v0.22.12) so
that the persistence layer can be unit-tested without spinning up a
``QApplication`` or a ``QThread`` event loop.

This controller intentionally exposes no Qt signals — every method is
either fire-and-forget (``persist_alert``) or returns plain Python
data (the loaders return lists of dicts). The view connects them
synchronously via the :class:`~wardsoar.pc.ui.engine_bridge.EngineWorker`
façade, which keeps the public API stable for ``app.py`` and the
existing ``views/*`` modules.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from wardsoar.core.history_rotator import list_archives, load_archive

logger = logging.getLogger("ward_soar.ui.controllers.history")


class HistoryController:
    """Persist and load alert history entries on local disk.

    The active file is a JSONL stream. One line per alert, appended
    in arrival order. Calendar-based rotation is the responsibility
    of :mod:`wardsoar.core.history_rotator` — the controller only
    writes/reads the active file and exposes the archive listing and
    archive-loading helpers.

    Args:
        history_path: Absolute path to the active
            ``alerts_history.jsonl`` file. The parent directory is
            created on construction so that the first
            :meth:`persist_alert` call cannot fail with
            ``FileNotFoundError`` on a fresh install.
    """

    def __init__(self, history_path: Path) -> None:
        self._history_path = history_path
        self._history_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def history_path(self) -> Path:
        """Path of the active ``alerts_history.jsonl`` file.

        Exposed so that startup code can run
        :func:`~wardsoar.core.history_rotator.rotate_if_needed` against
        it without reaching into a private attribute, and so that the
        IP-enrichment helper can mark which entries have already been
        seen by reading from the same source of truth.
        """
        return self._history_path

    def persist_alert(self, alert_data: dict[str, Any]) -> None:
        """Append an alert to the history file for persistence across restarts.

        Adds an ISO-8601 ``_ts`` field so the alerts view can render a
        full ``YYYY-MM-DD HH:MM:SS`` timestamp even for entries that
        only stored ``HH:MM:SS`` in the legacy ``time`` field
        (pre-v0.22.3). All errors are swallowed and logged at debug
        level — persistence is best-effort and must never crash the
        pipeline.
        """
        try:
            entry = dict(alert_data)
            entry["_ts"] = datetime.now(timezone.utc).isoformat()
            with open(self._history_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            logger.debug("Failed to persist alert to history", exc_info=True)

    def load_alert_history(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Load persisted alerts from the active history file.

        v0.22.1 — the active file is bounded to the current calendar
        month by :func:`~wardsoar.core.history_rotator.rotate_if_needed`.
        A busy month can still reach thousands of entries, so the UI
        pages through it: 200 at startup, then 200 more on each
        "Load older" click.

        Args:
            limit: Cap on returned entries. ``None`` = no cap
                (load everything). The UI uses 200 on startup.
            offset: Skip the last ``offset`` entries before applying
                ``limit``. Lets the UI page backward through the
                month without re-parsing the whole file each click.

        Returns:
            List of alert data dicts, most recent last. Empty on
            any read / parse error (fail-safe).
        """
        alerts: list[dict[str, Any]] = []
        if not self._history_path.exists():
            return alerts
        try:
            with open(self._history_path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            logger.warning("Failed to load alert history", exc_info=True)
            return alerts

        if offset:
            alerts = alerts[: len(alerts) - offset] if offset < len(alerts) else []
        if limit is not None and limit >= 0 and limit < len(alerts):
            alerts = alerts[-limit:]
        return alerts

    def load_history_page(
        self, older_than_count: int, page_size: int = 200
    ) -> list[dict[str, Any]]:
        """Paginate older entries of the current month on operator request.

        Args:
            older_than_count: Number of entries the UI already has
                displayed (offset from the end of the active file).
            page_size: How many entries to return.

        Returns:
            The next ``page_size`` entries older than the current
            view. Empty when the active file (current month) is
            exhausted — the UI then falls back to the Archives
            menu for past months.
        """
        return self.load_alert_history(limit=page_size, offset=older_than_count)

    def list_history_archives(self) -> list[dict[str, Any]]:
        """Return the available monthly archives, newest first.

        Used by the UI "Archives" menu. Each entry carries the
        archive path, the ``YYYY-MM`` month and the compressed
        size so the dropdown can render "March 2026 — 42 kB".
        """
        infos = list_archives(self._history_path)
        return [
            {"path": info.path, "month": info.month_iso, "size_bytes": info.size_bytes}
            for info in infos
        ]

    def load_history_from_archive(
        self, archive_path: str, limit: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Read a gzipped archive and return its alerts.

        Args:
            archive_path: Path as returned by
                :meth:`list_history_archives`.
            limit: Cap on returned entries. ``None`` = the whole archive.

        Returns:
            List of alert dicts. Malformed archive → empty list.
        """
        raw_lines = load_archive(Path(archive_path), limit=limit)
        alerts: list[dict[str, Any]] = []
        for line in raw_lines:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return alerts
