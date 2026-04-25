"""Tests for the ``NetgateAgent`` wrapper (Phase 3b.2).

The wrapper is pure delegation by design, so the tests focus on:

  * structural conformance to the ``RemoteAgent`` protocol;
  * the ``from_credentials`` factory builds the right SSH transport;
  * every method forwards arguments and return values to the wrapped
    transport / free helper without mutation;
  * the ``ssh`` escape hatch exposes the underlying transport so the
    legacy call sites (audit / tamper / apply) keep working until
    Phase 3b.3 migrates them.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.remote_agents import NetgateAgent, RemoteAgent
from wardsoar.core.remote_agents.pfsense_alias_migrate import AliasMigrationResult
from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH
from wardsoar.core.remote_agents.pfsense_suricata_tune import SuricataTuneResult


def _ssh_mock() -> MagicMock:
    """Return a ``PfSenseSSH``-shaped mock with all methods as ``AsyncMock``."""
    mock = MagicMock(spec=PfSenseSSH)
    mock.check_status = AsyncMock()
    mock.add_to_blocklist = AsyncMock()
    mock.remove_from_blocklist = AsyncMock()
    mock.is_blocked = AsyncMock()
    mock.list_blocklist = AsyncMock()
    mock.run_read_only = AsyncMock()
    return mock


# ---------------------------------------------------------------------------
# Structural conformance
# ---------------------------------------------------------------------------


class TestNetgateAgentProtocol:
    """The wrapper must satisfy the generic ``RemoteAgent`` contract."""

    def test_satisfies_remote_agent_protocol(self) -> None:
        agent = NetgateAgent(_ssh_mock())
        assert isinstance(agent, RemoteAgent)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class TestNetgateAgentFactory:
    """``from_credentials`` is the path most call sites should take."""

    def test_from_credentials_builds_pfsense_ssh(self) -> None:
        agent = NetgateAgent.from_credentials(
            host="192.0.2.10",
            ssh_user="admin",
            ssh_key_path="/dev/null",
        )
        assert isinstance(agent.ssh, PfSenseSSH)
        # The underlying transport carries the supplied parameters.
        assert agent.ssh._host == "192.0.2.10"  # noqa: SLF001 — intentional readback
        assert agent.ssh._user == "admin"  # noqa: SLF001 — intentional readback

    def test_from_credentials_passes_optional_args(self) -> None:
        agent = NetgateAgent.from_credentials(
            host="192.0.2.10",
            ssh_user="admin",
            ssh_key_path="/dev/null",
            ssh_port=2222,
            blocklist_table="custom_table",
        )
        assert agent.ssh._port == 2222  # noqa: SLF001 — intentional readback
        assert agent.ssh._table == "custom_table"  # noqa: SLF001 — intentional readback


# ---------------------------------------------------------------------------
# Protocol method delegation
# ---------------------------------------------------------------------------


class TestRemoteAgentDelegation:
    """Each protocol method must forward to the wrapped ``PfSenseSSH``."""

    @pytest.mark.asyncio
    async def test_check_status_delegates(self) -> None:
        ssh = _ssh_mock()
        ssh.check_status.return_value = (True, "ok")
        agent = NetgateAgent(ssh)

        result = await agent.check_status()

        assert result == (True, "ok")
        ssh.check_status.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_add_to_blocklist_delegates(self) -> None:
        ssh = _ssh_mock()
        ssh.add_to_blocklist.return_value = True
        agent = NetgateAgent(ssh)

        result = await agent.add_to_blocklist("203.0.113.42")

        assert result is True
        ssh.add_to_blocklist.assert_awaited_once_with("203.0.113.42")

    @pytest.mark.asyncio
    async def test_remove_from_blocklist_delegates(self) -> None:
        ssh = _ssh_mock()
        ssh.remove_from_blocklist.return_value = True
        agent = NetgateAgent(ssh)

        result = await agent.remove_from_blocklist("203.0.113.42")

        assert result is True
        ssh.remove_from_blocklist.assert_awaited_once_with("203.0.113.42")

    @pytest.mark.asyncio
    async def test_is_blocked_delegates(self) -> None:
        ssh = _ssh_mock()
        ssh.is_blocked.return_value = True
        agent = NetgateAgent(ssh)

        result = await agent.is_blocked("203.0.113.42")

        assert result is True
        ssh.is_blocked.assert_awaited_once_with("203.0.113.42")

    @pytest.mark.asyncio
    async def test_list_blocklist_delegates(self) -> None:
        ssh = _ssh_mock()
        ssh.list_blocklist.return_value = ["203.0.113.42", "198.51.100.7"]
        agent = NetgateAgent(ssh)

        result = await agent.list_blocklist()

        assert result == ["203.0.113.42", "198.51.100.7"]
        ssh.list_blocklist.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Netgate-specific operations
# ---------------------------------------------------------------------------


class TestNetgateSpecificOperations:
    """``run_read_only``, ``apply_suricata_runmode`` and ``migrate_alias_to_urltable``."""

    @pytest.mark.asyncio
    async def test_run_read_only_delegates_with_default_timeout(self) -> None:
        ssh = _ssh_mock()
        ssh.run_read_only.return_value = (True, "stdout")
        agent = NetgateAgent(ssh)

        result = await agent.run_read_only("pfctl -s info")

        assert result == (True, "stdout")
        ssh.run_read_only.assert_awaited_once_with("pfctl -s info", timeout=10)

    @pytest.mark.asyncio
    async def test_run_read_only_passes_explicit_timeout(self) -> None:
        ssh = _ssh_mock()
        ssh.run_read_only.return_value = (True, "stdout")
        agent = NetgateAgent(ssh)

        await agent.run_read_only("pfctl -s rules", timeout=30)

        ssh.run_read_only.assert_awaited_once_with("pfctl -s rules", timeout=30)

    @pytest.mark.asyncio
    async def test_apply_suricata_runmode_delegates(self) -> None:
        ssh = _ssh_mock()
        agent = NetgateAgent(ssh)
        expected = SuricataTuneResult(
            success=True,
            instances_changed=1,
            message="runmode flipped",
        )

        with patch(
            "wardsoar.core.remote_agents.netgate_agent.apply_suricata_runmode",
            new=AsyncMock(return_value=expected),
        ) as mock_fn:
            result = await agent.apply_suricata_runmode("workers")

        assert result is expected
        mock_fn.assert_awaited_once_with(ssh, "workers")

    @pytest.mark.asyncio
    async def test_apply_suricata_runmode_uses_default_target(self) -> None:
        ssh = _ssh_mock()
        agent = NetgateAgent(ssh)
        expected = SuricataTuneResult(success=True, instances_changed=1, message="ok")

        with patch(
            "wardsoar.core.remote_agents.netgate_agent.apply_suricata_runmode",
            new=AsyncMock(return_value=expected),
        ) as mock_fn:
            await agent.apply_suricata_runmode()

        mock_fn.assert_awaited_once_with(ssh, "workers")

    @pytest.mark.asyncio
    async def test_migrate_alias_to_urltable_delegates(self) -> None:
        ssh = _ssh_mock()
        agent = NetgateAgent(ssh)
        expected = AliasMigrationResult(
            success=True,
            preserved_entries=3,
            message="migrated",
        )

        with patch(
            "wardsoar.core.remote_agents.netgate_agent.migrate_alias_to_urltable",
            new=AsyncMock(return_value=expected),
        ) as mock_fn:
            result = await agent.migrate_alias_to_urltable("custom_alias")

        assert result is expected
        mock_fn.assert_awaited_once_with(ssh, "custom_alias")

    @pytest.mark.asyncio
    async def test_migrate_alias_to_urltable_uses_default_alias(self) -> None:
        ssh = _ssh_mock()
        agent = NetgateAgent(ssh)
        expected = AliasMigrationResult(success=True, preserved_entries=0, message="ok")

        with patch(
            "wardsoar.core.remote_agents.netgate_agent.migrate_alias_to_urltable",
            new=AsyncMock(return_value=expected),
        ) as mock_fn:
            await agent.migrate_alias_to_urltable()

        mock_fn.assert_awaited_once_with(ssh, "blocklist")


# ---------------------------------------------------------------------------
# Escape hatch
# ---------------------------------------------------------------------------


class TestSshEscapeHatch:
    """The ``ssh`` property exposes the wrapped transport for legacy call sites."""

    def test_ssh_property_returns_underlying_transport(self) -> None:
        ssh = _ssh_mock()
        agent = NetgateAgent(ssh)
        assert agent.ssh is ssh
