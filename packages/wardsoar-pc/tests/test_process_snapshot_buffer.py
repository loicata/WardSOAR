"""Tests for the rolling ``psutil.net_connections`` snapshot buffer."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from wardsoar.pc.forensics import FlowKey
from wardsoar.pc.process_snapshot_buffer import (
    NetConnectionsBuffer,
    Snapshot,
    _ConnTuple,
    _RETENTION_SECONDS,
    _conn_tuple_matches,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _outbound_flow() -> FlowKey:
    return FlowKey(
        local_ip="192.168.2.100",
        local_port=55555,
        remote_ip="162.159.207.0",
        remote_port=443,
        proto="TCP",
        pc_is_initiator=True,
    )


def _inbound_flow() -> FlowKey:
    return FlowKey(
        local_ip="192.168.2.100",
        local_port=22,
        remote_ip="203.0.113.5",
        remote_port=40000,
        proto="TCP",
        pc_is_initiator=False,
    )


def _fake_psutil_conn(
    pid: int,
    laddr_port: int,
    raddr_ip: str = "",
    raddr_port: int = 0,
) -> MagicMock:
    conn = MagicMock()
    conn.pid = pid
    conn.laddr = MagicMock(port=laddr_port, ip="0.0.0.0")
    if raddr_ip:
        conn.raddr = MagicMock(ip=raddr_ip, port=raddr_port)
    else:
        conn.raddr = None
    return conn


# ---------------------------------------------------------------------------
# Tuple matching
# ---------------------------------------------------------------------------


class TestConnTupleMatches:
    def test_exact_outbound_match(self) -> None:
        conn = _ConnTuple(pid=1, local_port=55555, remote_ip="162.159.207.0", remote_port=443)
        assert _conn_tuple_matches(conn, _outbound_flow()) is True

    def test_wrong_remote_port_rejected(self) -> None:
        conn = _ConnTuple(pid=1, local_port=55555, remote_ip="162.159.207.0", remote_port=8080)
        assert _conn_tuple_matches(conn, _outbound_flow()) is False

    def test_inbound_listener_only_matches(self) -> None:
        conn = _ConnTuple(pid=1, local_port=22)
        assert _conn_tuple_matches(conn, _inbound_flow()) is True

    def test_outbound_without_raddr_rejected(self) -> None:
        conn = _ConnTuple(pid=1, local_port=55555)
        assert _conn_tuple_matches(conn, _outbound_flow()) is False


# ---------------------------------------------------------------------------
# Snapshot capture
# ---------------------------------------------------------------------------


class TestCaptureSnapshot:
    def test_capture_keeps_valid_connections(self) -> None:
        buffer = NetConnectionsBuffer()
        with patch(
            "wardsoar.pc.process_snapshot_buffer.psutil.net_connections",
            return_value=[
                _fake_psutil_conn(pid=10, laddr_port=55555, raddr_ip="1.2.3.4", raddr_port=443),
                _fake_psutil_conn(pid=20, laddr_port=22),  # listener
                _fake_psutil_conn(pid=None, laddr_port=99),  # pid=None skipped
            ],
        ):
            snap = buffer._capture()

        assert isinstance(snap, Snapshot)
        recorded = {c.pid for c in snap.connections}
        assert recorded == {10, 20}

    def test_capture_returns_empty_on_permission_error(self) -> None:
        buffer = NetConnectionsBuffer()
        with patch(
            "wardsoar.pc.process_snapshot_buffer.psutil.net_connections",
            side_effect=PermissionError("denied"),
        ):
            snap = buffer._capture()
        assert snap.connections == ()


# ---------------------------------------------------------------------------
# pids_matching()
# ---------------------------------------------------------------------------


class TestPidsMatching:
    @staticmethod
    def _seed(buffer: NetConnectionsBuffer, *snaps: Snapshot) -> None:
        with buffer._lock:
            buffer._snapshots.extend(snaps)

    def test_finds_pid_in_historic_snapshot(self) -> None:
        buffer = NetConnectionsBuffer()
        self._seed(
            buffer,
            Snapshot(
                captured_at=0.0,
                connections=(
                    _ConnTuple(
                        pid=7777, local_port=55555, remote_ip="162.159.207.0", remote_port=443
                    ),
                ),
            ),
        )
        assert buffer.pids_matching(_outbound_flow()) == {7777}

    def test_unions_across_multiple_snapshots(self) -> None:
        buffer = NetConnectionsBuffer()
        self._seed(
            buffer,
            Snapshot(
                captured_at=0.0,
                connections=(
                    _ConnTuple(pid=1, local_port=55555, remote_ip="162.159.207.0", remote_port=443),
                ),
            ),
            Snapshot(
                captured_at=1.0,
                connections=(
                    _ConnTuple(pid=2, local_port=55555, remote_ip="162.159.207.0", remote_port=443),
                ),
            ),
        )
        assert buffer.pids_matching(_outbound_flow()) == {1, 2}

    def test_empty_buffer_returns_empty_set(self) -> None:
        buffer = NetConnectionsBuffer()
        assert buffer.pids_matching(_outbound_flow()) == set()

    def test_ignores_non_matching_entries(self) -> None:
        buffer = NetConnectionsBuffer()
        self._seed(
            buffer,
            Snapshot(
                captured_at=0.0,
                connections=(
                    _ConnTuple(pid=1, local_port=4444, remote_ip="9.9.9.9", remote_port=443),
                ),
            ),
        )
        assert buffer.pids_matching(_outbound_flow()) == set()


# ---------------------------------------------------------------------------
# start() / stop() lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stops_cleanly(self) -> None:
        buffer = NetConnectionsBuffer(interval_seconds=0.5, retention_seconds=1.0)
        with patch(
            "wardsoar.pc.process_snapshot_buffer.psutil.net_connections",
            return_value=[],
        ):
            await buffer.start()
            # Let the loop run at least one tick.
            await asyncio.sleep(0.1)
            await buffer.stop()

        assert buffer._task is None

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self) -> None:
        buffer = NetConnectionsBuffer(interval_seconds=0.5, retention_seconds=1.0)
        with patch(
            "wardsoar.pc.process_snapshot_buffer.psutil.net_connections",
            return_value=[],
        ):
            await buffer.start()
            first_task = buffer._task
            await buffer.start()
            assert buffer._task is first_task
            await buffer.stop()

    @pytest.mark.asyncio
    async def test_buffer_eventually_contains_snapshots(self) -> None:
        buffer = NetConnectionsBuffer(interval_seconds=0.05, retention_seconds=0.3)
        with patch(
            "wardsoar.pc.process_snapshot_buffer.psutil.net_connections",
            return_value=[
                _fake_psutil_conn(pid=42, laddr_port=55555, raddr_ip="1.2.3.4", raddr_port=443),
            ],
        ):
            await buffer.start()
            # Three ticks at 50ms = ~150ms should be plenty.
            await asyncio.sleep(0.2)
            count = buffer.snapshot_count()
            await buffer.stop()

        assert count >= 2  # at least the initial capture + one tick

    def test_retention_bounds_deque(self) -> None:
        """Deque max length = retention / interval + 1."""
        buffer = NetConnectionsBuffer(interval_seconds=1.0, retention_seconds=5.0)
        assert buffer._snapshots.maxlen == 6

    def test_default_retention_covers_dual_suricata_window(self) -> None:
        """Default retention must be >= dual_suricata reconciliation
        window (120 s default) + investigator margin.

        Doctrine (project_dual_suricata_sync.md Q1):
        when a divergence is declared at window expiration (T+120s),
        the DivergenceInvestigator reaches back to T+0 to snapshot
        what the host was doing — the buffer must still hold that
        history. Pinning this invariant in a test catches any future
        regression where someone shrinks the buffer without
        considering the correlator dependency.
        """
        # Configurable upper bound for the reconciliation window
        # documented in the memo: 180 s.
        max_reconciliation_window_s = 180.0
        # Investigator + log pipeline margin: another 60 s is
        # comfortable.
        investigator_margin_s = 60.0
        assert _RETENTION_SECONDS >= max_reconciliation_window_s + investigator_margin_s, (
            f"Default retention {_RETENTION_SECONDS}s is too short to cover "
            f"the dual_suricata reconciliation window ({max_reconciliation_window_s}s) "
            f"plus investigator margin ({investigator_margin_s}s). See "
            f"project_dual_suricata_sync.md Q1."
        )
