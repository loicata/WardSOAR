"""TTL cache for :func:`src.process_risk.scan_process` results.

Scoring a process takes ~60-100 ms (PowerShell Authenticode call
plus a few psutil queries). Scoring the *same* PID dozens of times
per minute — what happens during a STUN / STREAM retransmission
burst from ``chrome.exe`` — wastes CPU and lights up the fan.

This cache memoises the :class:`ProcessRiskResult` for a short
window. The key is ``(pid, create_time)`` so that a PID reused by
the OS for a completely different process (rare but possible)
forces a fresh scan instead of inheriting the old verdict.

Thread-safe: the pipeline calls it from the asyncio worker while
the ForensicAnalyzer may also read it from a separate task.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

import psutil
from psutil import AccessDenied, NoSuchProcess

from src.process_risk import ProcessRiskResult, scan_process

logger = logging.getLogger("ward_soar.process_risk_cache")


#: Default cache TTL. Five minutes covers the typical burst of
#: Suricata alerts on a single flow while still catching a legitimate
#: binary-replace-and-restart (attacker swaps the exe, re-launches
#: under the same process name — fresh scan after 5 min).
_DEFAULT_TTL_SECONDS = 300.0


@dataclass(frozen=True)
class _CacheEntry:
    """One memoised scoring result.

    Attributes:
        result: The :class:`ProcessRiskResult` produced by
            :func:`scan_process` at ``cached_at``.
        cached_at: ``time.monotonic()`` when we stored the entry.
            Used to evict after the TTL.
        create_time: ``psutil.Process.create_time()`` recorded at
            scan time. PID reuse is detected by comparing a fresh
            ``create_time`` against this stamp — identical PID but
            different ``create_time`` ⇒ it is a new process, the
            old verdict does not apply.
    """

    result: ProcessRiskResult
    cached_at: float
    create_time: float


class ProcessRiskCache:
    """Keyed by PID; evicted after :data:`_DEFAULT_TTL_SECONDS`.

    Args:
        ttl_seconds: Entries older than this are refreshed on the
            next lookup. Default five minutes.
    """

    def __init__(self, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> None:
        self._entries: dict[int, _CacheEntry] = {}
        self._ttl = max(1.0, float(ttl_seconds))
        self._lock = Lock()

    def size(self) -> int:
        """Number of entries currently cached (for tests / diagnostics)."""
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        """Wipe the cache — useful on pipeline teardown."""
        with self._lock:
            self._entries.clear()

    def get_or_scan(self, pid: int) -> ProcessRiskResult:
        """Return the cached verdict, refreshing when stale.

        Behaviour:
            1. If a non-expired entry exists and its stored
               ``create_time`` matches the current PID's create time,
               return it (cache hit).
            2. Otherwise run :func:`scan_process`, store the fresh
               result, and return it.

        PID reuse detection: when ``psutil`` gives a different
        ``create_time`` for the same PID, the previous entry is
        treated as stale and replaced.

        Never raises. A failure to observe ``create_time`` (process
        exited between the cache lookup and the scan) falls back on
        the TTL-based freshness check alone.
        """
        current_ctime = _safe_create_time(pid)
        now = time.monotonic()

        with self._lock:
            entry = self._entries.get(pid)
            if entry is not None and (now - entry.cached_at) <= self._ttl:
                # Same process? If we could read create_time and it
                # matches, we are sure. If we could not read it, we
                # trust the TTL and accept the entry.
                if current_ctime is None or current_ctime == entry.create_time:
                    return entry.result

        # Miss / stale / reused PID — score fresh.
        result = scan_process(pid)
        # ``current_ctime`` may have been None at the top; fetch once
        # more after the scan so we bind the entry to whatever
        # create_time existed at scan time.
        if current_ctime is None:
            current_ctime = _safe_create_time(pid) or 0.0

        with self._lock:
            self._entries[pid] = _CacheEntry(
                result=result,
                cached_at=now,
                create_time=current_ctime,
            )
        return result

    def invalidate(self, pid: int) -> None:
        """Remove a specific PID from the cache.

        Useful when something external (e.g. an operator action)
        hints that the entry may be stale before the TTL elapses.
        """
        with self._lock:
            self._entries.pop(pid, None)


def _safe_create_time(pid: int) -> Optional[float]:
    """Return ``psutil.Process(pid).create_time()`` or ``None`` on failure."""
    try:
        return float(psutil.Process(pid).create_time())
    except (NoSuchProcess, AccessDenied, OSError):
        return None


__all__ = ("ProcessRiskCache",)
