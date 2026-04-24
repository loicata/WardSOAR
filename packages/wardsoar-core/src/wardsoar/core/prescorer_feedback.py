"""Persistent score deltas applied by the PreScorer.

When the user rolls back a block, the signature that triggered it
becomes slightly less trustworthy for the future — the PreScorer
should give it a negative bias so the next identical alert has a
harder time reaching the LLM.

Contract:
    - Deltas are keyed by Suricata signature ID (SID) — an integer.
    - A delta is a signed int added to the total score before threshold.
    - Deltas decay: entries older than `max_age_days` are pruned so
      legitimate new detections aren't permanently weakened by an old
      rollback.
    - All writes are JSON-persisted so deltas survive restarts.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from threading import Lock

logger = logging.getLogger("ward_soar.prescorer_feedback")


# Default age at which a feedback entry is forgotten.
DEFAULT_MAX_AGE_DAYS = 30

# The rollback feedback signal — moderate, not overwhelming.
# Architecture doc §4.3 mandates -20 per rollback.
ROLLBACK_DELTA = -20


class PreScorerFeedbackStore:
    """Persistent store for signature-keyed score deltas.

    Args:
        persist_path: JSON file backing the store.
        max_age_days: Deltas older than this are pruned on load and cleanup.
    """

    def __init__(
        self,
        persist_path: Path,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        self._path = persist_path
        self._max_age_seconds = max_age_days * 24 * 3600
        self._lock = Lock()
        # Schema: {sid: {"delta": int, "updated_at": unix_seconds}}
        self._entries: dict[int, dict[str, int]] = {}
        self._load()

    def _load(self) -> None:
        """Read persisted entries. Prune stale ones on the way in."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("feedback: failed to load %s: %s", self._path, exc)
            return

        if not isinstance(raw, dict):
            return

        now = int(time.time())
        for sid_str, data in raw.items():
            if not isinstance(data, dict):
                continue
            try:
                sid = int(sid_str)
                delta = int(data.get("delta", 0))
                updated_at = int(data.get("updated_at", 0))
            except (TypeError, ValueError):
                continue
            if now - updated_at > self._max_age_seconds:
                continue
            self._entries[sid] = {"delta": delta, "updated_at": updated_at}

        logger.debug("feedback: loaded %d active entries", len(self._entries))

    def _save(self) -> None:
        """Flush to disk. Called under self._lock."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # JSON object keys must be strings.
            serializable = {str(sid): entry for sid, entry in self._entries.items()}
            self._path.write_text(
                json.dumps(serializable, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("feedback: failed to save %s: %s", self._path, exc)

    def add_feedback(self, sid: int, delta: int) -> int:
        """Apply an additive delta for a given signature.

        If a delta already exists, the new delta is summed. The store tracks
        the *cumulative* bias, not a history of events.

        Args:
            sid: Suricata signature ID.
            delta: Signed integer to add. Negative biases the score down.

        Returns:
            The new cumulative delta for this signature.
        """
        now = int(time.time())
        with self._lock:
            existing = self._entries.get(sid)
            current = existing["delta"] if existing else 0
            new_delta = current + int(delta)
            self._entries[sid] = {"delta": new_delta, "updated_at": now}
            self._save()

        logger.info(
            "feedback: SID %d delta %+d → cumulative %+d",
            sid,
            delta,
            new_delta,
        )
        return new_delta

    def get_delta(self, sid: int) -> int:
        """Return the current delta for a SID, or 0 if none.

        Expired entries return 0 and are pruned lazily.
        """
        now = int(time.time())
        with self._lock:
            entry = self._entries.get(sid)
            if entry is None:
                return 0
            if now - entry["updated_at"] > self._max_age_seconds:
                del self._entries[sid]
                self._save()
                return 0
            return int(entry["delta"])

    def cleanup_expired(self) -> int:
        """Prune all entries older than max_age_days. Returns count removed."""
        now = int(time.time())
        with self._lock:
            expired = [
                sid
                for sid, entry in self._entries.items()
                if now - entry["updated_at"] > self._max_age_seconds
            ]
            for sid in expired:
                del self._entries[sid]
            if expired:
                self._save()
        return len(expired)

    def snapshot(self) -> dict[int, int]:
        """Return a {sid: delta} copy for introspection."""
        with self._lock:
            return {sid: entry["delta"] for sid, entry in self._entries.items()}
