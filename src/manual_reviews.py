"""Operator-written verdict overrides on top of persisted alerts.

Alerts in ``alerts_history.jsonl`` are immutable \u2014 we never rewrite
that file in place (it grows to tens of thousands of lines and
rewriting per-review would be both slow and risky). Manual reviews
are therefore stored in a separate append-only file,
``%APPDATA%\\WardSOAR\\logs\\manual_reviews.jsonl``. At load time
the shell merges the two so every alert record carries its own
``manual_review`` dict when an override exists.

Design rules
------------
1. One line per review event, JSON. The shell keeps only the
   latest per alert at load time (multiple re-reviews produce
   multiple lines \u2014 the last wins).
2. Alerts are keyed by their persisted ``_ts`` ISO-8601
   timestamp. It is always present (written by
   :meth:`EngineWorker._persist_alert`) and is unique per
   emission.
3. This module has zero UI / Qt imports so it can be exercised
   in pure-python tests without the Qt event loop.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("ward_soar.manual_reviews")


@dataclass(frozen=True)
class ManualReview:
    """One operator override of a previously-persisted alert.

    Attributes:
        alert_ts: The ``_ts`` of the target alert in
            ``alerts_history.jsonl``. Used as the join key.
        original_verdict: Verdict emitted by the pipeline. Quoted
            back in the UI ("Overridden: filtered \u2192 confirmed").
        operator_verdict: New verdict chosen by the operator.
            Accepts ``confirmed`` / ``suspicious`` / ``benign`` /
            ``inconclusive`` / ``filtered``, or ``""`` when the
            operator keeps the original verdict and only adds
            a note.
        notes: Free-text justification. Shown verbatim in the
            Alert Detail "Manual review" section.
        reviewed_at: ISO-8601 timestamp of the override (UTC).
    """

    alert_ts: str
    original_verdict: str
    operator_verdict: str
    notes: str
    reviewed_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def append_review(path: Path, review: ManualReview) -> None:
    """Append one review event to the storage file.

    The file is created (parents too) if missing. Failures are
    caught and logged \u2014 an override that fails to persist is
    surfaced in the log but does not crash the caller.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(review.to_dict()) + "\n")
    except OSError:
        logger.warning("Could not append review to %s", path, exc_info=True)


def load_reviews(path: Path) -> dict[str, ManualReview]:
    """Load every review from the storage file.

    Returns a mapping ``alert_ts -> ManualReview`` with only the
    latest review kept when the operator re-reviewed an alert
    multiple times. Missing file returns an empty dict. Corrupt
    lines are skipped with a debug-level log.
    """
    index: dict[str, ManualReview] = {}
    if not path.exists():
        return index
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Skipped corrupt review line: %s", line[:80])
                    continue
                alert_ts = str(payload.get("alert_ts", ""))
                if not alert_ts:
                    continue
                index[alert_ts] = ManualReview(
                    alert_ts=alert_ts,
                    original_verdict=str(payload.get("original_verdict", "")),
                    operator_verdict=str(payload.get("operator_verdict", "")),
                    notes=str(payload.get("notes", "")),
                    reviewed_at=str(payload.get("reviewed_at", "")),
                )
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
    return index


def merge_into_history(
    history: list[dict[str, object]],
    reviews: dict[str, ManualReview],
) -> list[dict[str, object]]:
    """Attach review data to matching alerts.

    Mutates each dict in ``history`` in place (sets a
    ``manual_review`` key on matching entries) and returns the
    same list for chaining convenience. Alerts with no matching
    review are left untouched.
    """
    for alert in history:
        ts = str(alert.get("_ts", ""))
        if not ts:
            continue
        review = reviews.get(ts)
        if review is None:
            continue
        alert["manual_review"] = review.to_dict()
    return history


def new_review(
    alert_ts: str,
    original_verdict: str,
    operator_verdict: str,
    notes: str,
) -> ManualReview:
    """Factory: build a :class:`ManualReview` with ``reviewed_at`` set to now."""
    return ManualReview(
        alert_ts=alert_ts,
        original_verdict=original_verdict,
        operator_verdict=operator_verdict,
        notes=notes,
        reviewed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def default_store_path(data_dir: Path) -> Path:
    """Resolve the canonical path inside ``%APPDATA%\\WardSOAR``."""
    return data_dir / "logs" / "manual_reviews.jsonl"


__all__ = [
    "ManualReview",
    "append_review",
    "default_store_path",
    "load_reviews",
    "merge_into_history",
    "new_review",
]
