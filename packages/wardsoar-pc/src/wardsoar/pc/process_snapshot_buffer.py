"""Rolling snapshot of ``psutil.net_connections`` for flow attribution.

Level 2 of the process-attribution stack (level 1 is 5-tuple live
match, level 3 is Sysmon Event 3). Purpose: catch flows that are
already closed by the time the Suricata alert reaches the forensic
step, but were still open a few seconds before.

A background task takes a snapshot every :data:`_SNAPSHOT_INTERVAL`
seconds and keeps the last :data:`_RETENTION_SECONDS` of history in
a bounded deque. Snapshots are intentionally tiny — just the set of
``(pid, laddr_port, raddr_ip, raddr_port)`` tuples — so memory use
stays flat even on hosts with thousands of sockets per second.

The buffer is fail-safe: a snapshot that raises (permission denied,
os error) is skipped without aborting the task. The matcher accepts
calls even before the first snapshot has landed.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Deque, Optional

import psutil

from wardsoar.pc.forensics import FlowKey

logger = logging.getLogger("ward_soar.process_snapshot_buffer")


#: Seconds between two snapshots. Two seconds is the sweet spot: fine
#: enough to catch flows that live ≥1–2 s (HTTP GET, DNS resolution,
#: short TCP handshakes), cheap enough to run indefinitely.
_SNAPSHOT_INTERVAL = 2.0

#: How much history we keep. 60 seconds covers the delay between a
#: Suricata alert hitting ``eve.json`` on the Netgate and the
#: forensic module reading it on the PC side (typically <2 s but we
#: want a comfortable margin for overloaded pipelines).
_RETENTION_SECONDS = 60.0


@dataclass(frozen=True)
class _ConnTuple:
    """Minimal subset of ``psutil._common.sconn`` we keep in history.

    We deliberately drop ``laddr.ip`` (the local IP never helps to
    disambiguate — the flow key already gives us that) and every
    status / family / type field. The 4-tuple below is enough for
    :func:`_conn_matches_flow` to reach a decision, and keeping the
    record narrow bounds memory growth.
    """

    pid: int
    local_port: int
    remote_ip: str = ""
    remote_port: int = 0


@dataclass(frozen=True)
class Snapshot:
    """One timestamped batch of live connections."""

    captured_at: float  # ``time.monotonic()`` — we only care about deltas
    connections: tuple[_ConnTuple, ...] = field(default_factory=tuple)


class NetConnectionsBuffer:
    """Background rolling-history of active sockets.

    Args:
        interval_seconds: Delay between two snapshots.
        retention_seconds: How much history the buffer keeps.

    Usage::

        buffer = NetConnectionsBuffer()
        await buffer.start()
        # ... later, from the forensic step ...
        pids = buffer.pids_matching(flow)
        await buffer.stop()
    """

    def __init__(
        self,
        interval_seconds: float = _SNAPSHOT_INTERVAL,
        retention_seconds: float = _RETENTION_SECONDS,
    ) -> None:
        # 50 ms is the absolute floor — fast enough for tests that
        # want to see two ticks in under a second, slow enough to
        # protect against an accidental busy-loop if a zero slips in.
        self._interval = max(0.05, float(interval_seconds))
        self._retention = max(self._interval, float(retention_seconds))
        max_entries = max(1, int(self._retention / self._interval) + 1)
        self._snapshots: Deque[Snapshot] = deque(maxlen=max_entries)
        self._lock = Lock()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopped = asyncio.Event()

    async def start(self) -> None:
        """Launch the snapshot loop. Safe to call twice (no-op second time)."""
        if self._task is not None and not self._task.done():
            return
        self._stopped.clear()
        self._task = asyncio.create_task(self._run())
        logger.info(
            "NetConnectionsBuffer started (interval=%.1fs, retention=%.1fs, max=%d)",
            self._interval,
            self._retention,
            self._snapshots.maxlen,
        )

    async def stop(self) -> None:
        """Request the snapshot loop to exit and wait for it to finish."""
        self._stopped.set()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._task, timeout=self._interval + 1)
        except asyncio.TimeoutError:
            self._task.cancel()
        finally:
            self._task = None

    def snapshot_count(self) -> int:
        """Return how many snapshots are currently retained (for tests)."""
        with self._lock:
            return len(self._snapshots)

    def pids_matching(self, flow: FlowKey) -> set[int]:
        """Return every PID whose past snapshot carried the 5-tuple flow.

        The lookup scans the whole retention window — if the flow was
        alive at any captured instant we still attribute. For very
        short-lived flows (UDP bursts < interval) a miss is still
        possible; level 3 (Sysmon Event 3) is the definitive source
        for those.
        """
        pids: set[int] = set()
        with self._lock:
            snapshots = list(self._snapshots)
        for snap in snapshots:
            for conn in snap.connections:
                if _conn_tuple_matches(conn, flow):
                    pids.add(conn.pid)
        return pids

    async def _run(self) -> None:
        """Inner loop — one snapshot every ``interval_seconds``."""
        while not self._stopped.is_set():
            try:
                snap = self._capture()
            except Exception:  # noqa: BLE001 — the task must never die
                logger.debug("net_connections snapshot raised", exc_info=True)
            else:
                with self._lock:
                    self._snapshots.append(snap)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass  # regular tick — loop again

    def _capture(self) -> Snapshot:
        """Read psutil once and distill into ``_ConnTuple`` records."""
        import time

        try:
            raw = psutil.net_connections(kind="inet")
        except (PermissionError, OSError):
            logger.debug("net_connections denied or failed")
            return Snapshot(captured_at=time.monotonic(), connections=())

        tuples: list[_ConnTuple] = []
        for conn in raw:
            if conn.pid is None:
                continue
            laddr = getattr(conn, "laddr", None)
            if laddr is None or not hasattr(laddr, "port"):
                continue
            raddr = getattr(conn, "raddr", None)
            remote_ip = str(raddr.ip) if raddr and hasattr(raddr, "ip") else ""
            remote_port = int(raddr.port) if raddr and hasattr(raddr, "port") else 0
            tuples.append(
                _ConnTuple(
                    pid=int(conn.pid),
                    local_port=int(laddr.port),
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                )
            )
        return Snapshot(captured_at=time.monotonic(), connections=tuple(tuples))


def _conn_tuple_matches(conn: _ConnTuple, flow: FlowKey) -> bool:
    """Variant of :func:`forensics._conn_matches_flow` for stored tuples.

    Kept separate from the live-socket matcher because ``_ConnTuple``
    uses plain strings / ints rather than psutil's ``sconn``
    structure — it lets the live matcher stay naive about the
    historical form and vice versa.
    """
    if conn.local_port != flow.local_port:
        return False
    if not conn.remote_ip:
        return not flow.pc_is_initiator  # same listener-only semantics
    return conn.remote_ip == flow.remote_ip and conn.remote_port == flow.remote_port


# Re-export the helper names for tests that want to monkeypatch them.
__all__: tuple[str, ...] = (
    "NetConnectionsBuffer",
    "Snapshot",
    "_ConnTuple",
    "_conn_tuple_matches",
    "attach_buffer_to_analyzer",
)


# Adaptor used by ForensicAnalyzer — typed through Any so importing
# forensics does not force a circular dependency on this module.
def attach_buffer_to_analyzer(analyzer: Any, buffer: NetConnectionsBuffer) -> None:
    """Wire a buffer into an already-built :class:`ForensicAnalyzer`.

    Kept as a free function so callers (Pipeline, tests) avoid reaching
    into the analyzer's private attributes.
    """
    analyzer._conn_buffer = buffer  # noqa: SLF001 — intentional injection hook
