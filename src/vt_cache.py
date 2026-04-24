"""Local SQLite cache and rate limiter for VirusTotal lookups.

Purpose:
    - Avoid re-querying VirusTotal for hashes already seen recently
      (the free tier allows only 500 req/day, 4 req/min).
    - Enforce rate limits in-process rather than relying on the
      remote 429 response, which wastes quota and introduces latency.
    - Reduce hash leakage to Google (each query reveals a file hash).

Design:
    - SQLite for persistence across restarts. Single file, no daemon.
    - Separate TTLs for malicious vs clean verdicts (malicious results
      are stable over time; clean results are re-checked more often in
      case a new detection appears).
    - Per-minute semaphore and per-day counter for rate limiting.
    - Fail-safe: any cache/DB error degrades to "no cache" mode rather
      than breaking the pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

from src.models import VirusTotalResult

logger = logging.getLogger("ward_soar.vt_cache")


# Default TTLs (seconds)
DEFAULT_TTL_MALICIOUS = 7 * 24 * 3600  # 7 days
DEFAULT_TTL_CLEAN = 24 * 3600  # 1 day

# Free tier rate limits
DEFAULT_MAX_PER_MINUTE = 4
DEFAULT_MAX_PER_DAY = 500


class VTCache:
    """SQLite-backed cache for VirusTotal verdicts with rate limiting.

    Args:
        db_path: Path to SQLite file. Parent directory is created if needed.
        ttl_malicious: TTL (seconds) for malicious verdicts.
        ttl_clean: TTL (seconds) for clean (non-malicious) verdicts.
        max_per_minute: Max VT API calls per rolling minute.
        max_per_day: Max VT API calls per UTC day.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS vt_cache (
        file_hash TEXT PRIMARY KEY,
        is_malicious INTEGER NOT NULL,
        detection_count INTEGER NOT NULL,
        total_engines INTEGER NOT NULL,
        detection_ratio REAL NOT NULL,
        threat_labels TEXT NOT NULL,
        cached_at INTEGER NOT NULL,
        ttl_seconds INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cached_at ON vt_cache(cached_at);

    CREATE TABLE IF NOT EXISTS vt_rate_limit (
        day TEXT PRIMARY KEY,
        call_count INTEGER NOT NULL
    );
    """

    def __init__(
        self,
        db_path: Path,
        ttl_malicious: int = DEFAULT_TTL_MALICIOUS,
        ttl_clean: int = DEFAULT_TTL_CLEAN,
        max_per_minute: int = DEFAULT_MAX_PER_MINUTE,
        max_per_day: int = DEFAULT_MAX_PER_DAY,
    ) -> None:
        self._db_path = db_path
        self._ttl_malicious = ttl_malicious
        self._ttl_clean = ttl_clean
        self._max_per_minute = max_per_minute
        self._max_per_day = max_per_day

        # Sliding window of the last N call timestamps (monotonic seconds).
        # Used to enforce per-minute limit without locking SQLite on every call.
        self._recent_calls: list[float] = []
        self._call_lock = asyncio.Lock()

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection with sane defaults."""
        conn = sqlite3.connect(
            self._db_path,
            timeout=5.0,
            isolation_level=None,  # autocommit; we use explicit transactions when needed
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        """Create tables on first run."""
        try:
            with self._connect() as conn:
                conn.executescript(self._SCHEMA)
        except sqlite3.Error:
            logger.warning("VT cache: schema init failed, cache disabled", exc_info=True)

    def lookup(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Return a cached verdict if present and not expired.

        Args:
            file_hash: SHA-256 hash of the file.

        Returns:
            VirusTotalResult if a fresh entry exists, else None.
        """
        now = int(time.time())
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT is_malicious, detection_count, total_engines, "
                    "detection_ratio, threat_labels, cached_at, ttl_seconds "
                    "FROM vt_cache WHERE file_hash = ?",
                    (file_hash,),
                ).fetchone()
        except sqlite3.Error:
            logger.debug("VT cache: lookup failed for %s", file_hash[:16], exc_info=True)
            return None

        if row is None:
            return None

        is_malicious, det_count, total, ratio, labels_json, cached_at, ttl = row
        if now - cached_at > ttl:
            # Expired — caller will re-query VT and then store()
            return None

        try:
            labels = json.loads(labels_json) if labels_json else []
        except (json.JSONDecodeError, TypeError):
            labels = []

        return VirusTotalResult(
            file_hash=file_hash,
            detection_count=int(det_count),
            total_engines=int(total),
            detection_ratio=float(ratio),
            is_malicious=bool(is_malicious),
            threat_labels=list(labels),
            lookup_type="hash",
        )

    def store(self, result: VirusTotalResult) -> None:
        """Persist a verdict in the cache with an appropriate TTL.

        Args:
            result: The VirusTotal verdict to cache.
        """
        ttl = self._ttl_malicious if result.is_malicious else self._ttl_clean
        labels_json = json.dumps(list(result.threat_labels))
        now = int(time.time())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vt_cache ("
                    "file_hash, is_malicious, detection_count, total_engines, "
                    "detection_ratio, threat_labels, cached_at, ttl_seconds"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        result.file_hash,
                        1 if result.is_malicious else 0,
                        result.detection_count,
                        result.total_engines,
                        result.detection_ratio,
                        labels_json,
                        now,
                        ttl,
                    ),
                )
        except sqlite3.Error:
            logger.warning("VT cache: store failed for %s", result.file_hash[:16], exc_info=True)

    async def can_call_api(self) -> bool:
        """Check whether a fresh VT API call is allowed right now.

        Enforces both rolling-minute and per-day limits. Returns False
        without raising if either limit would be exceeded.
        """
        async with self._call_lock:
            # Sliding-minute check
            now = time.monotonic()
            self._recent_calls = [t for t in self._recent_calls if now - t < 60.0]
            if len(self._recent_calls) >= self._max_per_minute:
                logger.info("VT rate limit: per-minute quota reached")
                return False

            # Per-day check
            today = time.strftime("%Y-%m-%d", time.gmtime())
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        "SELECT call_count FROM vt_rate_limit WHERE day = ?",
                        (today,),
                    ).fetchone()
                    daily_count = int(row[0]) if row else 0
            except sqlite3.Error:
                logger.debug("VT rate limit: daily counter read failed", exc_info=True)
                daily_count = 0

            if daily_count >= self._max_per_day:
                logger.warning("VT rate limit: per-day quota reached (%d)", daily_count)
                return False

            return True

    async def record_call(self) -> None:
        """Account for a VT API call just made. Must be paired with can_call_api().

        Updates the rolling-minute window and the persistent daily counter.
        """
        async with self._call_lock:
            self._recent_calls.append(time.monotonic())

            today = time.strftime("%Y-%m-%d", time.gmtime())
            try:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO vt_rate_limit (day, call_count) VALUES (?, 1) "
                        "ON CONFLICT(day) DO UPDATE SET call_count = call_count + 1",
                        (today,),
                    )
            except sqlite3.Error:
                logger.debug("VT rate limit: daily counter write failed", exc_info=True)

    def cleanup_expired(self) -> int:
        """Delete cache entries whose TTL has elapsed.

        Returns:
            Number of rows deleted.
        """
        now = int(time.time())
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM vt_cache WHERE cached_at + ttl_seconds < ?",
                    (now,),
                )
                deleted = cursor.rowcount
        except sqlite3.Error:
            logger.debug("VT cache: cleanup failed", exc_info=True)
            return 0

        if deleted:
            logger.info("VT cache: purged %d expired entries", deleted)
        return int(deleted)
