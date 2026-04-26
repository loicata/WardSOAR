"""Tests for WardSOAR pfSense SSH integration and block tracker.

PfSenseSSH and BlockTracker are CRITICAL (95% coverage).
All asyncssh calls are mocked.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker, PfSenseSSH

# ---------------------------------------------------------------------------
# PfSenseSSH tests
# ---------------------------------------------------------------------------


def _make_ssh() -> PfSenseSSH:
    """Create a test PfSenseSSH instance."""
    return PfSenseSSH(
        host="192.168.2.1",
        ssh_user="admin",
        ssh_key_path="/tmp/test_key",
        ssh_port=22,
        blocklist_table="blocklist",
    )


def _mock_ssh_result(stdout: str = "", stderr: str = "", exit_status: int = 0) -> MagicMock:
    """Create a mock SSH completed process."""
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.exit_status = exit_status
    return result


class TestPfSenseSSHRunCmd:
    """Tests for PfSenseSSH._run_cmd."""

    @pytest.mark.asyncio
    async def test_successful_command(self) -> None:
        ssh = _make_ssh()
        mock_result = _mock_ssh_result(stdout="OK\n")
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)

        with patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_asyncssh.connect.return_value.__aexit__ = AsyncMock(return_value=None)

            success, output = await ssh._run_cmd("echo OK")
        assert success is True
        assert "OK" in output

    @pytest.mark.asyncio
    async def test_failed_command(self) -> None:
        ssh = _make_ssh()
        mock_result = _mock_ssh_result(stderr="error", exit_status=1)
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)

        with patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_asyncssh.connect.return_value.__aexit__ = AsyncMock(return_value=None)

            success, output = await ssh._run_cmd("bad_cmd")
        assert success is False

    @pytest.mark.asyncio
    async def test_connection_error(self) -> None:
        ssh = _make_ssh()
        # Zero the retry delay so we don't spend 3 seconds waiting for the
        # backoff between three identical OSError raises.
        with (
            patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh,
            patch("wardsoar.core.remote_agents.pfsense_ssh._SSH_RETRY_BASE_DELAY_S", 0.0),
        ):
            # Make the context manager itself raise OSError
            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(side_effect=OSError("Connection refused"))
            cm.__aexit__ = AsyncMock(return_value=None)
            mock_asyncssh.connect.return_value = cm

            success, output = await ssh._run_cmd("echo test")
        assert success is False
        assert "Connection refused" in output

    @pytest.mark.asyncio
    async def test_transient_failure_recovers_on_retry(self) -> None:
        """Regression for the 2026-04 176.126.240.84 incidents
        (four ``Connection lost`` / ``[WinError 10053] aborted`` /
        ``SSH timeout`` lines on a single IP). A transient SSH error
        on the first attempt must not cost the block — the retry
        succeeds on the second connect and the caller sees success.
        """
        ssh = _make_ssh()
        mock_result = _mock_ssh_result(stdout="ok\n")
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)

        # First connect raises ConnectionResetError (a real OSError
        # subclass asyncssh surfaces on aborted TCP); second connect
        # returns a working session.
        first_cm = AsyncMock()
        first_cm.__aenter__ = AsyncMock(
            side_effect=ConnectionResetError("[WinError 10053] aborted")
        )
        first_cm.__aexit__ = AsyncMock(return_value=None)
        second_cm = AsyncMock()
        second_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        second_cm.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh,
            patch("wardsoar.core.remote_agents.pfsense_ssh._SSH_RETRY_BASE_DELAY_S", 0.0),
        ):
            mock_asyncssh.connect.side_effect = [first_cm, second_cm]

            success, output = await ssh._run_cmd("pfctl -t blocklist -T add 1.2.3.4")

        assert success is True
        assert "ok" in output
        # Two connect attempts — the retry happened.
        assert mock_asyncssh.connect.call_count == 2

    @pytest.mark.asyncio
    async def test_non_zero_exit_is_not_retried(self) -> None:
        """A command that runs successfully but returns a non-zero
        exit status is an authoritative "pfctl disagreed" — retrying
        would only burn SSH round-trips. The contract is: one
        attempt, the caller surfaces stderr as the real error."""
        ssh = _make_ssh()
        mock_result = _mock_ssh_result(stderr="table does not exist", exit_status=1)
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)

        with (
            patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh,
            patch("wardsoar.core.remote_agents.pfsense_ssh._SSH_RETRY_BASE_DELAY_S", 0.0),
        ):
            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=mock_conn)
            cm.__aexit__ = AsyncMock(return_value=None)
            mock_asyncssh.connect.return_value = cm

            success, output = await ssh._run_cmd("pfctl -t missing -T show")

        assert success is False
        assert "table does not exist" in output
        # Single SSH connect — a command-level error must not trigger retry.
        assert mock_asyncssh.connect.call_count == 1


class _AsyncIterLines:
    """Tiny async iterator over a list of strings.

    ``asyncssh``'s real ``process.stdout`` yields decoded lines as a
    native async iterator. Mocking it with ``AsyncMock`` doesn't quite
    work because ``async for`` calls ``__aiter__`` / ``__anext__``
    rather than awaiting individual coroutines. This class provides
    the right shape with deterministic data.
    """

    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)

    def __aiter__(self) -> "_AsyncIterLines":
        return self

    async def __anext__(self) -> str:
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


class TestPfSenseSSHStreamAlerts:
    """``stream_alerts`` opens a long-lived SSH session, runs ``tail -f``
    on the remote eve.json, and yields parsed JSON events. Reconnection
    on transport error is automatic; non-JSON lines are dropped."""

    @pytest.mark.asyncio
    async def test_yields_parsed_events_and_drops_invalid_lines(self) -> None:
        ssh = _make_ssh()
        lines = [
            '{"event_type": "alert", "src_ip": "203.0.113.7"}\n',
            '{"event_type": "alert", "src_ip": "198.51.100.4"}\n',
            "not valid json\n",  # silently dropped
            "\n",  # whitespace-only, dropped
            '"a string, not a dict"\n',  # JSON-valid but not a dict — dropped
            '{"event_type": "stats"}\n',
        ]

        mock_process = MagicMock()
        mock_process.stdout = _AsyncIterLines(lines)
        process_cm = AsyncMock()
        process_cm.__aenter__ = AsyncMock(return_value=mock_process)
        process_cm.__aexit__ = AsyncMock(return_value=None)

        mock_conn = MagicMock()
        mock_conn.create_process = MagicMock(return_value=process_cm)
        conn_cm = AsyncMock()
        conn_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        conn_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect.return_value = conn_cm
            collected: list[dict[str, Any]] = []
            # The async generator would re-connect indefinitely once the
            # mock stdout is exhausted; the consumer breaks after the
            # third valid event so the generator is ``aclose()``-d cleanly.
            async for event in ssh.stream_alerts():  # type: ignore[union-attr]
                collected.append(event)
                if len(collected) == 3:
                    break

        assert collected == [
            {"event_type": "alert", "src_ip": "203.0.113.7"},
            {"event_type": "alert", "src_ip": "198.51.100.4"},
            {"event_type": "stats"},
        ]
        # Verify the issued shell command targets the operator-supplied
        # path with single-quote escaping (defence against shell metas).
        cmd = mock_conn.create_process.call_args[0][0]
        assert cmd.startswith("tail -n 0 -f '")
        assert "/var/log/suricata/eve.json" in cmd

    @pytest.mark.asyncio
    async def test_reconnects_on_transport_error(self) -> None:
        """First ``asyncssh.connect`` raises (network blip / appliance
        reload); the generator must back off and reconnect, then yield
        events normally on the second attempt."""
        ssh = _make_ssh()

        # First attempt: connect raises before yielding anything.
        first_cm = AsyncMock()
        first_cm.__aenter__ = AsyncMock(side_effect=OSError("Connection lost"))
        first_cm.__aexit__ = AsyncMock(return_value=None)

        # Second attempt: succeeds and yields one event before EOF.
        mock_process = MagicMock()
        mock_process.stdout = _AsyncIterLines(['{"event_type": "alert"}\n'])
        process_cm = AsyncMock()
        process_cm.__aenter__ = AsyncMock(return_value=mock_process)
        process_cm.__aexit__ = AsyncMock(return_value=None)
        mock_conn = MagicMock()
        mock_conn.create_process = MagicMock(return_value=process_cm)
        second_cm = AsyncMock()
        second_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        second_cm.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh,
            patch("wardsoar.core.remote_agents.pfsense_ssh._STREAM_MIN_RETRY_DELAY_S", 0.0),
            patch("wardsoar.core.remote_agents.pfsense_ssh._STREAM_MAX_RETRY_DELAY_S", 0.0),
        ):
            mock_asyncssh.connect.side_effect = [first_cm, second_cm]
            collected: list[dict[str, Any]] = []
            async for event in ssh.stream_alerts():  # type: ignore[union-attr]
                collected.append(event)
                if collected:  # break right after the recovery yields
                    break

        assert collected == [{"event_type": "alert"}]
        assert mock_asyncssh.connect.call_count == 2

    @pytest.mark.asyncio
    async def test_local_addr_is_forwarded_to_asyncssh(self) -> None:
        """When the operator supplies a ``local_addr`` (LAN IP to bind to,
        e.g. to bypass a VPN tunnel), it must reach ``asyncssh.connect``
        as the documented ``(addr, port)`` tuple."""
        ssh = _make_ssh()

        mock_process = MagicMock()
        mock_process.stdout = _AsyncIterLines(['{"k": 1}\n'])
        process_cm = AsyncMock()
        process_cm.__aenter__ = AsyncMock(return_value=mock_process)
        process_cm.__aexit__ = AsyncMock(return_value=None)
        mock_conn = MagicMock()
        mock_conn.create_process = MagicMock(return_value=process_cm)
        conn_cm = AsyncMock()
        conn_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        conn_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("wardsoar.core.remote_agents.pfsense_ssh.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect.return_value = conn_cm
            async for _event in ssh.stream_alerts(local_addr="192.168.2.100"):  # type: ignore[union-attr]
                break

        kwargs = mock_asyncssh.connect.call_args.kwargs
        assert kwargs["local_addr"] == ("192.168.2.100", 0)


class TestPfSenseSSHBlocklist:
    """Tests for PfSenseSSH blocklist operations.

    Phase 7h (v0.8.0): blocks are now file-backed via
    :class:`src.pfsense_aliastable.PersistentBlocklist`, so every
    ``add`` / ``remove`` batch issues (1) a ``cat`` of the alias file,
    (2) a ``mkdir``, (3) an atomic write, and (4) a ``pfctl -T
    replace``. The old in-memory ``pfctl -T add`` path is gone — it
    was the reason Netflix kept escaping Hard Protect overnight.
    """

    @pytest.mark.asyncio
    async def test_add_to_blocklist_success(self) -> None:
        ssh = _make_ssh()
        # File starts empty. Every subsequent SSH command succeeds —
        # this default matches a freshly migrated Netgate.
        ssh._run_cmd = AsyncMock(return_value=(True, ""))  # type: ignore[method-assign]
        result = await ssh.add_to_blocklist("10.0.0.1")
        assert result is True
        # The batch includes the pfctl replace — the live table stays
        # in sync with the file on disk without waiting for the next
        # pfSense reload cycle.
        commands = [call.args[0] for call in ssh._run_cmd.call_args_list]
        assert any("pfctl -t blocklist -T replace" in c for c in commands)

    @pytest.mark.asyncio
    async def test_add_to_blocklist_already_present_still_syncs(self) -> None:
        """v0.8.0 semantics: re-adding an IP that is already in the
        file still triggers a pfctl replace so the live table is
        guaranteed to match the file. This is the cheapest recovery
        path if pfSense reloaded between two WardSOAR calls."""
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "10.0.0.1\n"))  # type: ignore[method-assign]
        result = await ssh.add_to_blocklist("10.0.0.1")
        assert result is True
        commands = [call.args[0] for call in ssh._run_cmd.call_args_list]
        assert any("pfctl -t blocklist -T replace" in c for c in commands)

    @pytest.mark.asyncio
    async def test_add_to_blocklist_invalid_ip(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock()  # type: ignore[method-assign]
        result = await ssh.add_to_blocklist("not-an-ip")
        assert result is False
        # Validation rejects the call before any SSH is attempted.
        assert ssh._run_cmd.call_count == 0

    @pytest.mark.asyncio
    async def test_remove_from_blocklist_success(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "10.0.0.1\n"))  # type: ignore[method-assign]
        result = await ssh.remove_from_blocklist("10.0.0.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_remove_from_blocklist_not_present(self) -> None:
        """Idempotent remove: absent IP still triggers a pfctl replace
        so the caller knows the file and live table agree afterwards."""
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "10.0.0.2\n"))  # type: ignore[method-assign]
        result = await ssh.remove_from_blocklist("10.0.0.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_is_blocked_true(self) -> None:
        """``is_blocked`` now consults the alias file — the file is
        authoritative post-migration."""
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "10.0.0.1\n10.0.0.2\n"))  # type: ignore[method-assign]
        result = await ssh.is_blocked("10.0.0.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_is_blocked_false(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "10.0.0.99\n"))  # type: ignore[method-assign]
        result = await ssh.is_blocked("10.0.0.1")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_blocklist(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(  # type: ignore[method-assign]
            return_value=(True, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")
        )
        result = await ssh.list_blocklist()
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    @pytest.mark.asyncio
    async def test_list_blocklist_empty(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, ""))  # type: ignore[method-assign]
        result = await ssh.list_blocklist()
        assert result == []

    @pytest.mark.asyncio
    async def test_check_status_healthy(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(True, "Status: Enabled"))  # type: ignore[method-assign]
        reachable, msg = await ssh.check_status()
        assert reachable is True

    @pytest.mark.asyncio
    async def test_check_status_failed(self) -> None:
        ssh = _make_ssh()
        ssh._run_cmd = AsyncMock(return_value=(False, "timeout"))  # type: ignore[method-assign]
        reachable, msg = await ssh.check_status()
        assert reachable is False

    @pytest.mark.asyncio
    async def test_kill_process_on_target_raises_not_implemented(self) -> None:
        """``PfSenseSSH`` is the SSH transport and pfSense itself is a
        router with no host process table to manipulate. The Protocol
        method exists only to keep ``MagicMock(spec=PfSenseSSH)`` test
        fixtures conformant — it must always raise ``NotImplementedError``.
        """
        ssh = _make_ssh()
        with pytest.raises(NotImplementedError, match="does not co-reside"):
            await ssh.kill_process_on_target(1234)

    @pytest.mark.asyncio
    async def test_concurrent_adds_are_serialised(self) -> None:
        """Regression for the 2026-04-23 22:40 incident.

        Two concurrent ``add_to_blocklist`` calls used to race on the
        shared ``wardsoar_blocklist.txt.tmp`` staging path: the first
        writer's ``mv`` renamed the tmp, the second writer's ``mv``
        then failed with "No such file or directory" and the target IP
        never made it onto pfSense. The write lock on PfSenseSSH
        serialises the two calls so each runs its full SSH batch
        before the other starts.
        """
        import asyncio

        ssh = _make_ssh()

        # Each SSH command yields the loop so a second concurrent task
        # has every chance to interleave if the lock is missing. The
        # mock still returns success so the flow completes.
        in_flight = 0
        max_in_flight = 0

        async def _slow_run(cmd: str, timeout: int = 10) -> tuple[bool, str]:
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0)  # force a reschedule
            in_flight -= 1
            return (True, "")

        ssh._run_cmd = _slow_run  # type: ignore[method-assign]

        await asyncio.gather(
            ssh.add_to_blocklist("10.0.0.1"),
            ssh.add_to_blocklist("10.0.0.2"),
        )

        # Only one SSH batch may be in flight at a time when the lock
        # is held. Without the lock this counter reaches 2.
        assert max_in_flight == 1

    @pytest.mark.asyncio
    async def test_add_and_remove_are_serialised(self) -> None:
        """Same serialisation guarantee across add/remove combinations.

        Mixing an ``add`` with a concurrent ``remove`` would otherwise
        hit the same tmp-path race as two concurrent adds.
        """
        import asyncio

        ssh = _make_ssh()

        in_flight = 0
        max_in_flight = 0

        async def _slow_run(cmd: str, timeout: int = 10) -> tuple[bool, str]:
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0)
            in_flight -= 1
            # Return a non-empty file so remove has something to act on.
            return (True, "10.0.0.1\n")

        ssh._run_cmd = _slow_run  # type: ignore[method-assign]

        await asyncio.gather(
            ssh.add_to_blocklist("10.0.0.2"),
            ssh.remove_from_blocklist("10.0.0.1"),
        )

        assert max_in_flight == 1


class TestIPValidation:
    """Tests for IP validation in PfSenseSSH."""

    def test_valid_ipv4(self) -> None:
        assert PfSenseSSH._validate_ip("10.0.0.1") is True

    def test_valid_ipv6(self) -> None:
        assert PfSenseSSH._validate_ip("::1") is True

    def test_invalid_ip(self) -> None:
        assert PfSenseSSH._validate_ip("not-an-ip") is False

    def test_command_injection_attempt(self) -> None:
        assert PfSenseSSH._validate_ip("10.0.0.1; rm -rf /") is False


# ---------------------------------------------------------------------------
# BlockTracker tests
# ---------------------------------------------------------------------------


class TestBlockTracker:
    """Tests for BlockTracker."""

    def test_record_and_get(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "blocks.json")
        tracker.record_block("10.0.0.1")
        bt = tracker.get_block_time("10.0.0.1")
        assert bt is not None
        assert (datetime.now(timezone.utc) - bt).total_seconds() < 5

    def test_remove_block(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "blocks.json")
        tracker.record_block("10.0.0.1")
        tracker.remove_block("10.0.0.1")
        assert tracker.get_block_time("10.0.0.1") is None

    def test_get_expired_ips(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "blocks.json")
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        tracker._blocks["10.0.0.1"] = old_time
        tracker._blocks["10.0.0.2"] = datetime.now(timezone.utc).isoformat()
        expired = tracker.get_expired_ips(max_hours=24)
        assert "10.0.0.1" in expired
        assert "10.0.0.2" not in expired

    def test_persistence(self, tmp_path: Path) -> None:
        path = tmp_path / "blocks.json"
        tracker1 = BlockTracker(persist_path=path)
        tracker1.record_block("10.0.0.1")

        tracker2 = BlockTracker(persist_path=path)
        assert tracker2.get_block_time("10.0.0.1") is not None

    def test_reconcile(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "blocks.json")
        tracker.record_block("10.0.0.1")  # In tracker, will be in active
        tracker.record_block("10.0.0.2")  # In tracker, NOT in active (stale)

        tracker.reconcile(active_ips=["10.0.0.1", "10.0.0.3"])

        assert tracker.get_block_time("10.0.0.1") is not None
        assert tracker.get_block_time("10.0.0.2") is None  # Removed
        assert tracker.get_block_time("10.0.0.3") is not None  # Added

    def test_get_all_blocks(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "blocks.json")
        tracker.record_block("10.0.0.1")
        tracker.record_block("10.0.0.2")
        all_blocks = tracker.get_all_blocks()
        assert len(all_blocks) == 2

    def test_corrupt_file_handled(self, tmp_path: Path) -> None:
        path = tmp_path / "blocks.json"
        path.write_text("not json", encoding="utf-8")
        tracker = BlockTracker(persist_path=path)
        assert tracker.get_all_blocks() == {}

    def test_missing_file_ok(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "nonexistent.json")
        assert tracker.get_all_blocks() == {}
