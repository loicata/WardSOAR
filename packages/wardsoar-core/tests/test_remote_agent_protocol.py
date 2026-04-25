"""Tests for the ``RemoteAgent`` protocol and registry (Phase 3b.1).

These tests exercise the structural contract and the small registry
that bookkeeps live agents. They do NOT exercise any concrete agent's
behaviour — that stays covered by ``test_pfsense_ssh.py`` and the
forthcoming ``test_netgate_agent.py`` (Phase 3b.2).
"""

from __future__ import annotations

import pytest

from wardsoar.core.remote_agents import RemoteAgent, RemoteAgentRegistry
from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH


class _FakeAgent:
    """Minimal in-memory ``RemoteAgent`` stand-in for registry tests.

    Mirrors the protocol surface exactly so ``isinstance`` accepts it
    without dragging an asyncssh-bound real agent into pure unit tests.
    Defaults to "off-host" semantics for ``kill_process_on_target`` —
    individual tests can override the method on the instance when they
    need the co-resident success branch.
    """

    def __init__(self) -> None:
        self._blocked: set[str] = set()

    async def check_status(self) -> tuple[bool, str]:
        return True, "fake agent reachable"

    async def add_to_blocklist(self, ip: str) -> bool:
        self._blocked.add(ip)
        return True

    async def remove_from_blocklist(self, ip: str) -> bool:
        self._blocked.discard(ip)
        return True

    async def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    async def list_blocklist(self) -> list[str]:
        return list(self._blocked)

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        raise NotImplementedError("FakeAgent off-host by default")


class _NotAnAgent:
    """Concrete class missing all of the protocol methods."""


# ---------------------------------------------------------------------------
# Protocol surface tests
# ---------------------------------------------------------------------------


class TestRemoteAgentProtocol:
    """The protocol is a runtime-checkable structural contract."""

    def test_pfsense_ssh_satisfies_protocol(self) -> None:
        """The existing pfSense SSH agent already has the right shape."""
        ssh = PfSenseSSH(
            host="192.0.2.1",
            ssh_user="admin",
            ssh_key_path="/dev/null",
        )
        assert isinstance(ssh, RemoteAgent)

    def test_fake_agent_satisfies_protocol(self) -> None:
        """The minimal in-memory fake exposes the full surface."""
        assert isinstance(_FakeAgent(), RemoteAgent)

    def test_arbitrary_object_does_not_satisfy_protocol(self) -> None:
        """A class missing the methods is rejected by ``isinstance``."""
        assert not isinstance(_NotAnAgent(), RemoteAgent)
        assert not isinstance(object(), RemoteAgent)

    def test_protocol_method_names(self) -> None:
        """All six operations are part of the public protocol surface."""
        expected = {
            "check_status",
            "add_to_blocklist",
            "remove_from_blocklist",
            "is_blocked",
            "list_blocklist",
            "kill_process_on_target",
        }
        # ``Protocol`` exposes its members on the class via ``__dict__``;
        # filter out the typing internals that start with an underscore.
        actual = {name for name in vars(RemoteAgent) if not name.startswith("_")}
        assert expected.issubset(actual), expected - actual

    @pytest.mark.asyncio
    async def test_fake_agent_off_host_kill_raises(self) -> None:
        """The default ``_FakeAgent`` mirrors off-host semantics — the
        concrete agents that don't co-reside with the target host
        (NetgateAgent, NoOpAgent, future VsAgent) raise
        ``NotImplementedError`` from ``kill_process_on_target`` rather
        than silently returning False, so accidental cross-host kills
        become architecturally impossible.
        """
        agent = _FakeAgent()
        with pytest.raises(NotImplementedError):
            await agent.kill_process_on_target(1234)


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------


class TestRemoteAgentRegistry:
    """Behaviour of the small registry shared by the wizard and pipeline."""

    def test_register_and_get(self) -> None:
        registry = RemoteAgentRegistry()
        agent = _FakeAgent()
        registry.register("netgate", agent)
        assert registry.get("netgate") is agent

    def test_get_unknown_returns_none(self) -> None:
        assert RemoteAgentRegistry().get("nope") is None

    def test_register_replaces_existing(self) -> None:
        """Re-registering an existing name swaps the instance."""
        registry = RemoteAgentRegistry()
        first = _FakeAgent()
        second = _FakeAgent()
        registry.register("netgate", first)
        registry.register("netgate", second)
        assert registry.get("netgate") is second
        assert len(registry) == 1

    def test_register_rejects_non_agent(self) -> None:
        registry = RemoteAgentRegistry()
        with pytest.raises(TypeError, match="does not implement RemoteAgent"):
            registry.register("bad", _NotAnAgent())  # type: ignore[arg-type]

    def test_register_rejects_empty_name(self) -> None:
        registry = RemoteAgentRegistry()
        with pytest.raises(ValueError, match="non-empty string"):
            registry.register("", _FakeAgent())
        with pytest.raises(ValueError, match="non-empty string"):
            registry.register("   ", _FakeAgent())

    def test_unregister_returns_true_on_hit(self) -> None:
        registry = RemoteAgentRegistry()
        registry.register("netgate", _FakeAgent())
        assert registry.unregister("netgate") is True
        assert registry.get("netgate") is None

    def test_unregister_returns_false_on_miss(self) -> None:
        assert RemoteAgentRegistry().unregister("never-registered") is False

    def test_all_agents_returns_snapshot(self) -> None:
        """Mutating the returned dict does not affect the registry."""
        registry = RemoteAgentRegistry()
        registry.register("netgate", _FakeAgent())
        snapshot = registry.all_agents()
        snapshot.clear()
        assert registry.get("netgate") is not None

    def test_names(self) -> None:
        registry = RemoteAgentRegistry()
        registry.register("netgate", _FakeAgent())
        registry.register("virus_sniff", _FakeAgent())
        assert sorted(registry.names()) == ["netgate", "virus_sniff"]

    def test_len_and_contains(self) -> None:
        registry = RemoteAgentRegistry()
        assert len(registry) == 0
        assert "netgate" not in registry
        registry.register("netgate", _FakeAgent())
        assert len(registry) == 1
        assert "netgate" in registry
        assert "virus_sniff" not in registry
        # Non-string keys never match.
        assert 42 not in registry  # type: ignore[operator]
