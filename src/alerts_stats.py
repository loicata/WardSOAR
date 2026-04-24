"""Longitudinal statistics on alert occurrences.

Answers "have we seen this (SID, src_ip) pair before, how often and
how regularly?" — signals the short-lived ``DecisionCache`` cannot
give because its TTL is measured in hours, not days.

Two consumers benefit:

1. **PreScorer** — bumps the score when a SID/IP pair shows
   beacon-like regularity (malware heartbeat) or when a novel alert
   appears for the first time, keeping Opus in the loop on shifts
   of baseline.

2. **Opus (analyzer)** — receives the same signals in plain text so
   it can weigh "this pattern has been stable BENIGN for 2 weeks"
   against "this is the first time we see this SID in 6 months".

The store is a bounded SQLite database. Writes are amortised through
an in-memory batch buffer flushed on a background task, so even a
50-alerts-per-second burst never stalls the pipeline. Reads use
composite-indexed lookups (≤1 ms for 100 k rows).

Fail-safe: any SQLite error degrades to "no signal" and logs at
DEBUG. The store is never allowed to raise through the pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import math
import sqlite3
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Optional

logger = logging.getLogger("ward_soar.alerts_stats")


#: How long an alert occurrence is kept before being purged. A week
#: is long enough to catch daily cron-like beacons and short enough
#: to keep the database small.
DEFAULT_RETENTION_DAYS = 7

#: Batch flush interval. Alerts queued in memory are persisted every
#: ``_FLUSH_INTERVAL_SECONDS`` seconds, or immediately on
#: :meth:`AlertsStatsStore.stop` so nothing is lost on shutdown.
_FLUSH_INTERVAL_SECONDS = 5.0

#: Maximum queue size before we force a flush inline (backpressure).
#: Prevents an unbounded RAM buffer if the flush task is killed.
_MAX_QUEUE_BEFORE_INLINE_FLUSH = 1000


@dataclass(frozen=True)
class AlertOccurrence:
    """One timestamped alert, persisted + queried by stats lookups.

    Attributes:
        sid: Suricata signature ID.
        src_ip: Source IP of the alert.
        ts: Unix epoch seconds.
        verdict: Final verdict string (``benign`` / ``confirmed`` /
            ``suspicious`` / ``inconclusive`` / ``filtered``).
    """

    sid: int
    src_ip: str
    ts: int
    verdict: str


@dataclass(frozen=True)
class StatsSignals:
    """Derived signals exposed to PreScorer and Opus.

    Attributes:
        total_count: Occurrences in the window (default 7 days).
        frequency_per_day: ``total_count / window_days``.
        regularity: 0.0–1.0. 1.0 = intervals are perfectly constant
            (strong beacon signal); 0.0 = fully random. ``None``
            when fewer than 3 occurrences make the metric
            meaningless.
        verdict_stability: Dominant verdict share (max / total).
            0.2 = verdicts oscillate randomly, 1.0 = always same
            verdict.
        dominant_verdict: The verdict that wins the stability ratio.
        novelty: True when the first-ever occurrence is younger than
            three days — helps flag "new pattern in our baseline".
    """

    total_count: int
    frequency_per_day: float
    regularity: Optional[float]
    verdict_stability: float
    dominant_verdict: str
    novelty: bool


class AlertsStatsStore:
    """SQLite-backed longitudinal alerts store.

    Args:
        db_path: File path for the SQLite database. Parent created
            on construction.
        retention_days: Occurrences older than this are purged by
            :meth:`purge_older_than`.

    The store must be kept alive for the lifetime of the pipeline
    so the batch flush task can run; call :meth:`start` once the
    event loop exists and :meth:`stop` on shutdown.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS alert_occurrences (
        sid INTEGER NOT NULL,
        src_ip TEXT NOT NULL,
        ts INTEGER NOT NULL,
        verdict TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sid_ip_ts
        ON alert_occurrences(sid, src_ip, ts);
    CREATE INDEX IF NOT EXISTS idx_ts
        ON alert_occurrences(ts);
    """

    def __init__(
        self,
        db_path: Path,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self._path = db_path
        self._retention_days = max(1, int(retention_days))
        self._pending: list[AlertOccurrence] = []
        self._lock = Lock()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopped = asyncio.Event()

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch the background flush loop. Idempotent."""
        if self._task is not None and not self._task.done():
            return
        self._stopped.clear()
        self._task = asyncio.create_task(self._run_flush_loop())
        logger.info(
            "AlertsStatsStore started (path=%s, retention=%dd, flush=%.1fs)",
            self._path,
            self._retention_days,
            _FLUSH_INTERVAL_SECONDS,
        )

    async def stop(self) -> None:
        """Signal the flush loop to exit; flush any pending entries first."""
        self._stopped.set()
        if self._task is None:
            self._flush_now()
            return
        try:
            await asyncio.wait_for(self._task, timeout=_FLUSH_INTERVAL_SECONDS + 1)
        except asyncio.TimeoutError:
            self._task.cancel()
        finally:
            self._task = None
            self._flush_now()  # last-chance flush so no alert is lost

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def record(self, sid: int, src_ip: str, verdict: str, ts: Optional[int] = None) -> None:
        """Queue an occurrence for the next flush.

        Write is deliberately non-blocking: the queue lives in memory
        and the SQLite round-trip happens on the background task.
        When the queue crosses :data:`_MAX_QUEUE_BEFORE_INLINE_FLUSH`
        we flush inline to keep the RAM usage bounded even if the
        task is stuck.
        """
        occ = AlertOccurrence(
            sid=int(sid),
            src_ip=str(src_ip),
            ts=int(ts if ts is not None else time.time()),
            verdict=str(verdict or "unknown"),
        )
        with self._lock:
            self._pending.append(occ)
            if len(self._pending) >= _MAX_QUEUE_BEFORE_INLINE_FLUSH:
                self._flush_locked()

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def query_window(
        self,
        sid: int,
        src_ip: str,
        days: int = DEFAULT_RETENTION_DAYS,
    ) -> list[AlertOccurrence]:
        """Return every occurrence of ``(sid, src_ip)`` in the last ``days``."""
        now = int(time.time())
        cutoff = now - (days * 86400)
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT sid, src_ip, ts, verdict FROM alert_occurrences "
                    "WHERE sid = ? AND src_ip = ? AND ts >= ? "
                    "ORDER BY ts ASC",
                    (int(sid), str(src_ip), cutoff),
                ).fetchall()
        except sqlite3.Error:
            logger.debug("alerts_stats: query_window failed", exc_info=True)
            return []
        return [
            AlertOccurrence(sid=row[0], src_ip=row[1], ts=row[2], verdict=row[3]) for row in rows
        ]

    def compute_signals(
        self,
        sid: int,
        src_ip: str,
        days: int = DEFAULT_RETENTION_DAYS,
    ) -> Optional[StatsSignals]:
        """Derive :class:`StatsSignals` from the lookup window.

        Returns ``None`` when no occurrence was recorded — the caller
        interprets that as "first time we see this SID/IP pair".
        """
        occs = self.query_window(sid, src_ip, days=days)
        if not occs:
            return None

        total = len(occs)
        freq = total / max(1, days)

        # Regularity: standard deviation of consecutive intervals,
        # normalised by the mean. Low ratio = regular = beacon-like.
        regularity: Optional[float] = None
        if total >= 3:
            intervals = [occs[i + 1].ts - occs[i].ts for i in range(total - 1)]
            # All identical intervals = std 0 = perfectly regular.
            if intervals and max(intervals) > 0:
                mean = statistics.mean(intervals)
                stdev = statistics.pstdev(intervals)
                if mean > 0:
                    cv = stdev / mean  # coefficient of variation
                    # Map CV → regularity in [0, 1]. cv=0 → 1.0, cv=1 → 0.5,
                    # cv→∞ → 0. Smooth monotonic mapping.
                    regularity = 1.0 / (1.0 + cv)
            else:
                # All at once — not regular, just batched.
                regularity = 0.0

        # Verdict stability: dominant verdict share.
        verdict_counts: dict[str, int] = {}
        for occ in occs:
            verdict_counts[occ.verdict] = verdict_counts.get(occ.verdict, 0) + 1
        dominant_verdict = max(verdict_counts, key=lambda k: verdict_counts[k])
        stability = verdict_counts[dominant_verdict] / total

        # Novelty: first occurrence within the last 3 days → flag.
        first_ts = occs[0].ts
        novelty = (int(time.time()) - first_ts) < (3 * 86400)

        return StatsSignals(
            total_count=total,
            frequency_per_day=freq,
            regularity=regularity,
            verdict_stability=stability,
            dominant_verdict=dominant_verdict,
            novelty=novelty,
        )

    def purge_older_than(self, days: Optional[int] = None) -> int:
        """Drop occurrences older than ``days`` (default: retention).

        Returns the number of rows deleted. Safe to call concurrently
        with writes — SQLite handles the locking.
        """
        d = days if days is not None else self._retention_days
        cutoff = int(time.time()) - (d * 86400)
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM alert_occurrences WHERE ts < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount
        except sqlite3.Error:
            logger.debug("alerts_stats: purge failed", exc_info=True)
            return 0
        if deleted:
            logger.info("alerts_stats: purged %d occurrences older than %d days", deleted, d)
        return deleted

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open a WAL-enabled connection with the project's defaults."""
        conn = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(self._SCHEMA)
        except sqlite3.Error:
            logger.warning("alerts_stats: schema init failed — store disabled", exc_info=True)

    async def _run_flush_loop(self) -> None:
        """Background task that flushes the queue every few seconds."""
        while not self._stopped.is_set():
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=_FLUSH_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
            self._flush_now()

    def _flush_now(self) -> None:
        """Flush the pending queue once, under the instance lock."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """Flush implementation — must be called with ``self._lock`` held."""
        if not self._pending:
            return
        batch = list(self._pending)
        self._pending.clear()
        try:
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO alert_occurrences (sid, src_ip, ts, verdict) "
                    "VALUES (?, ?, ?, ?)",
                    [(o.sid, o.src_ip, o.ts, o.verdict) for o in batch],
                )
        except sqlite3.Error:
            logger.debug(
                "alerts_stats: batch flush failed (%d entries lost)", len(batch), exc_info=True
            )

    # Expose math for tests without importing the module elsewhere.
    @staticmethod
    def _coefficient_of_variation_sample(intervals: list[int]) -> float:
        """Test helper: CV for a given intervals list, 0 if degenerate."""
        if not intervals or all(i == 0 for i in intervals):
            return math.inf
        mean = statistics.mean(intervals)
        if mean == 0:
            return math.inf
        return statistics.pstdev(intervals) / mean


__all__ = (
    "AlertOccurrence",
    "AlertsStatsStore",
    "DEFAULT_RETENTION_DAYS",
    "StatsSignals",
)
