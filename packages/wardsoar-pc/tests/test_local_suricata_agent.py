"""Tests for :class:`LocalSuricataAgent`.

Exercises:

* RemoteAgent Protocol conformance (isinstance check + method names)
* Lifecycle delegation to ``SuricataProcess`` (startup/shutdown
  call through)
* Enforcement delegation to ``WindowsFirewallBlocker`` (composition)
* ``stream_alerts`` tail-follow on a real eve.json file: history
  not replayed, new appends yielded, JSON parsing, JSON-line drop
  on bad input, file-missing recovery
* ``check_status`` outcomes (process dead / file missing / file
  stale / healthy)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

if sys.platform != "win32":  # pragma: no cover — non-Windows skip
    pytest.skip("local_suricata_agent is Windows-only", allow_module_level=True)

from wardsoar.core.remote_agents import RemoteAgent  # noqa: E402
from wardsoar.pc.local_suricata import SuricataProcess  # noqa: E402
from wardsoar.pc.local_suricata_agent import LocalSuricataAgent  # noqa: E402
from wardsoar.pc.windows_firewall import WindowsFirewallBlocker  # noqa: E402


def _make_agent(
    eve_path: Path,
    is_running: bool = True,
) -> tuple[LocalSuricataAgent, MagicMock, MagicMock]:
    """Build a LocalSuricataAgent with mocked process + blocker.

    Returns the (agent, process_mock, blocker_mock) so individual
    tests can assert on delegations / inject behaviour.
    """
    proc_mock = MagicMock(spec=SuricataProcess)
    proc_mock.is_running.return_value = is_running
    proc_mock.eve_path = eve_path
    proc_mock.start = AsyncMock(return_value=True)
    proc_mock.stop = AsyncMock(return_value=True)

    blocker_mock = MagicMock(spec=WindowsFirewallBlocker)
    blocker_mock.add_to_blocklist = AsyncMock(return_value=True)
    blocker_mock.remove_from_blocklist = AsyncMock(return_value=True)
    blocker_mock.is_blocked = AsyncMock(return_value=False)
    blocker_mock.list_blocklist = AsyncMock(return_value=[])
    blocker_mock.kill_process_on_target = AsyncMock(return_value=(True, "evil.exe"))

    agent = LocalSuricataAgent(process=proc_mock, blocker=blocker_mock, poll_interval_s=0.05)
    return agent, proc_mock, blocker_mock


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_satisfies_remote_agent_protocol(self, tmp_path: Path) -> None:
        agent, _proc, _blocker = _make_agent(tmp_path / "eve.json")
        assert isinstance(agent, RemoteAgent)


# ---------------------------------------------------------------------------
# Lifecycle delegation
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_startup_starts_process(self, tmp_path: Path) -> None:
        agent, proc, _blocker = _make_agent(tmp_path / "eve.json")
        await agent.startup()
        proc.start.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_shutdown_stops_process(self, tmp_path: Path) -> None:
        agent, proc, _blocker = _make_agent(tmp_path / "eve.json")
        await agent.shutdown()
        proc.stop.assert_awaited_once_with()

    def test_eve_path_property(self, tmp_path: Path) -> None:
        agent, _proc, _blocker = _make_agent(tmp_path / "logs" / "eve.json")
        assert agent.eve_path == tmp_path / "logs" / "eve.json"


# ---------------------------------------------------------------------------
# Enforcement delegation (RemoteAgent protocol minus stream_alerts)
# ---------------------------------------------------------------------------


class TestEnforcementDelegation:
    @pytest.mark.asyncio
    async def test_add_to_blocklist_delegates(self, tmp_path: Path) -> None:
        agent, _proc, blocker = _make_agent(tmp_path / "eve.json")
        result = await agent.add_to_blocklist("203.0.113.7")
        assert result is True
        blocker.add_to_blocklist.assert_awaited_once_with("203.0.113.7")

    @pytest.mark.asyncio
    async def test_remove_from_blocklist_delegates(self, tmp_path: Path) -> None:
        agent, _proc, blocker = _make_agent(tmp_path / "eve.json")
        result = await agent.remove_from_blocklist("203.0.113.7")
        assert result is True
        blocker.remove_from_blocklist.assert_awaited_once_with("203.0.113.7")

    @pytest.mark.asyncio
    async def test_is_blocked_delegates(self, tmp_path: Path) -> None:
        agent, _proc, blocker = _make_agent(tmp_path / "eve.json")
        blocker.is_blocked.return_value = True
        result = await agent.is_blocked("203.0.113.7")
        assert result is True
        blocker.is_blocked.assert_awaited_once_with("203.0.113.7")

    @pytest.mark.asyncio
    async def test_list_blocklist_delegates(self, tmp_path: Path) -> None:
        agent, _proc, blocker = _make_agent(tmp_path / "eve.json")
        blocker.list_blocklist.return_value = ["203.0.113.7", "198.51.100.4"]
        result = await agent.list_blocklist()
        assert result == ["203.0.113.7", "198.51.100.4"]
        blocker.list_blocklist.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_kill_process_delegates_co_resident(self, tmp_path: Path) -> None:
        """Co-resident topology: kill is meaningful (unlike NetgateAgent
        which raises NotImplementedError)."""
        agent, _proc, blocker = _make_agent(tmp_path / "eve.json")
        ok, name = await agent.kill_process_on_target(1234)
        assert ok is True
        assert name == "evil.exe"
        blocker.kill_process_on_target.assert_awaited_once_with(1234)


# ---------------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------------


class TestCheckStatus:
    @pytest.mark.asyncio
    async def test_reports_dead_when_process_not_running(self, tmp_path: Path) -> None:
        agent, proc, _blocker = _make_agent(tmp_path / "eve.json", is_running=False)
        ok, message = await agent.check_status()
        assert ok is False
        assert "not running" in message.lower()

    @pytest.mark.asyncio
    async def test_reports_missing_when_eve_absent(self, tmp_path: Path) -> None:
        agent, _proc, _blocker = _make_agent(tmp_path / "eve.json")
        ok, message = await agent.check_status()
        assert ok is False
        assert "eve.json not found" in message

    @pytest.mark.asyncio
    async def test_reports_stale_when_eve_old(self, tmp_path: Path) -> None:
        eve = tmp_path / "eve.json"
        eve.write_bytes(b"")
        # Force mtime to 5 minutes ago — beyond the 120s threshold.
        old_ts = time.time() - 300
        import os

        os.utime(eve, (old_ts, old_ts))
        agent, _proc, _blocker = _make_agent(eve)
        ok, message = await agent.check_status()
        assert ok is False
        assert "stale" in message.lower()

    @pytest.mark.asyncio
    async def test_reports_healthy_when_eve_fresh(self, tmp_path: Path) -> None:
        eve = tmp_path / "eve.json"
        eve.write_bytes(b"")  # mtime = now
        agent, _proc, _blocker = _make_agent(eve)
        ok, message = await agent.check_status()
        assert ok is True
        assert "fresh" in message.lower()


# ---------------------------------------------------------------------------
# stream_alerts — tail-follow real file
# ---------------------------------------------------------------------------


class TestStreamAlerts:
    @pytest.mark.asyncio
    async def test_history_not_replayed_on_startup(self, tmp_path: Path) -> None:
        """The agent positions its read offset at end-of-file at
        connect time — historical events sitting in eve.json are
        skipped (we behave like ``tail -n 0 -f``)."""
        eve = tmp_path / "eve.json"
        # Pre-existing history.
        eve.write_text(
            json.dumps({"event_type": "alert", "id": "OLD"})
            + "\n"
            + json.dumps({"event_type": "alert", "id": "OLDER"})
            + "\n",
            encoding="utf-8",
        )
        agent, _proc, _blocker = _make_agent(eve)

        async def _consume_one() -> dict[str, Any] | None:
            async for event in agent.stream_alerts():
                return event
            return None

        # Drive the consumer concurrently with the writer; append a
        # NEW event after a short delay.
        consumer_task = asyncio.create_task(_consume_one())
        await asyncio.sleep(0.1)
        with eve.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event_type": "alert", "id": "NEW"}) + "\n")
        result = await asyncio.wait_for(consumer_task, timeout=2.0)
        assert result is not None
        assert result["id"] == "NEW"  # never sees OLD or OLDER

    @pytest.mark.asyncio
    async def test_yields_appended_events_in_order(self, tmp_path: Path) -> None:
        eve = tmp_path / "eve.json"
        eve.write_text("", encoding="utf-8")
        agent, _proc, _blocker = _make_agent(eve)

        collected: list[dict[str, Any]] = []

        async def _consume() -> None:
            async for event in agent.stream_alerts():
                collected.append(event)
                if len(collected) == 3:
                    break

        consumer_task = asyncio.create_task(_consume())
        await asyncio.sleep(0.1)
        with eve.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event_type": "alert", "id": 1}) + "\n")
            f.write(json.dumps({"event_type": "alert", "id": 2}) + "\n")
            f.write(json.dumps({"event_type": "alert", "id": 3}) + "\n")
        await asyncio.wait_for(consumer_task, timeout=2.0)
        assert [e["id"] for e in collected] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_invalid_json_lines_dropped(self, tmp_path: Path) -> None:
        eve = tmp_path / "eve.json"
        eve.write_text("", encoding="utf-8")
        agent, _proc, _blocker = _make_agent(eve)

        collected: list[dict[str, Any]] = []

        async def _consume() -> None:
            async for event in agent.stream_alerts():
                collected.append(event)
                if collected:
                    break

        consumer_task = asyncio.create_task(_consume())
        await asyncio.sleep(0.1)
        with eve.open("a", encoding="utf-8") as f:
            f.write("not valid json\n")
            f.write('["a list, valid JSON but not a dict"]\n')
            f.write(json.dumps({"event_type": "alert"}) + "\n")
        await asyncio.wait_for(consumer_task, timeout=2.0)
        # Only the valid dict made it through.
        assert collected == [{"event_type": "alert"}]

    @pytest.mark.asyncio
    async def test_file_rotation_resets_offset(self, tmp_path: Path) -> None:
        """When eve.json shrinks (new file after rotation), the agent
        resets its offset and starts reading from the new beginning."""
        eve = tmp_path / "eve.json"
        # Pre-existing content so the initial offset is non-zero.
        eve.write_text("x" * 5000 + "\n", encoding="utf-8")
        agent, _proc, _blocker = _make_agent(eve)

        collected: list[dict[str, Any]] = []

        async def _consume() -> None:
            async for event in agent.stream_alerts():
                collected.append(event)
                if collected:
                    break

        consumer_task = asyncio.create_task(_consume())
        await asyncio.sleep(0.1)
        # Simulate rotation: replace with a much smaller file.
        eve.write_text(
            json.dumps({"event_type": "alert", "id": "POST_ROTATE"}) + "\n",
            encoding="utf-8",
        )
        await asyncio.wait_for(consumer_task, timeout=2.0)
        assert collected[0]["id"] == "POST_ROTATE"

    @pytest.mark.asyncio
    async def test_missing_file_recovery(self, tmp_path: Path) -> None:
        """If eve.json doesn't exist when stream_alerts starts, the
        agent waits for it to appear and resumes the tail."""
        eve = tmp_path / "eve.json"
        # Don't create it — simulate Suricata still booting.
        agent, _proc, _blocker = _make_agent(eve)

        collected: list[dict[str, Any]] = []

        async def _consume() -> None:
            async for event in agent.stream_alerts():
                collected.append(event)
                if collected:
                    break

        consumer_task = asyncio.create_task(_consume())
        await asyncio.sleep(0.1)
        # Suricata starts and writes the first event.
        eve.write_text(
            json.dumps({"event_type": "alert", "id": "POST_BOOT"}) + "\n",
            encoding="utf-8",
        )
        # Bypass the 5 s missing-file backoff by patching it.
        await asyncio.wait_for(consumer_task, timeout=20.0)
        assert collected[0]["id"] == "POST_BOOT"
