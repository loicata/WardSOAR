"""Tests for the ``WindowsFirewallBlocker`` (v0.22.22).

The blocker shells out to ``netsh advfirewall firewall``. Tests mock
the subprocess invocation at the boundary so no real Windows
Firewall rules are touched.

The mock is plugged in by replacing the synchronous ``subprocess.run``
with a callable that records the args and returns a programmable
``CompletedProcess``-like object — this matches the surface the
blocker actually depends on (returncode + stdout + stderr) and lets
each test pre-program the netsh outcome it wants to exercise.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from wardsoar.core.remote_agents import RemoteAgent
from wardsoar.pc.windows_firewall import (
    _RULE_PREFIX,
    WindowsFirewallBlocker,
    _validate_ip,
)


@pytest.fixture
def fake_run(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[Any], list[list[str]]]:
    """Replace ``subprocess.run`` with a programmable stub.

    Returns a helper that, when called with a return-value provider,
    installs the stub and yields the recorded invocation list.

    Two provider styles are accepted:
      * a single ``CompletedProcess``-like result reused for every call;
      * a callable taking the args list and returning a result, so a
        test can vary the response per command.
    """

    def install(provider: Any) -> list[list[str]]:
        recorded: list[list[str]] = []

        def _run(args: list[str], **kwargs: Any) -> Any:
            recorded.append(list(args))
            if callable(provider) and not isinstance(provider, MagicMock):
                return provider(args)
            return provider

        monkeypatch.setattr("wardsoar.pc.windows_firewall.subprocess.run", _run)
        return recorded

    return install


def _ok(stdout: str = "") -> Any:
    """Stand-in for a successful ``CompletedProcess``."""
    return MagicMock(returncode=0, stdout=stdout, stderr="")


def _fail(message: str = "boom", returncode: int = 1) -> Any:
    """Stand-in for a failed ``CompletedProcess``."""
    return MagicMock(returncode=returncode, stdout="", stderr=message)


# ---------------------------------------------------------------------------
# Static guards
# ---------------------------------------------------------------------------


class TestValidateIp:
    def test_accepts_ipv4(self) -> None:
        assert _validate_ip("192.0.2.1") is True

    def test_accepts_ipv6(self) -> None:
        assert _validate_ip("::1") is True

    def test_rejects_garbage(self) -> None:
        assert _validate_ip("not-an-ip") is False
        assert _validate_ip("") is False
        assert _validate_ip("192.0.2.1; rm -rf /") is False


class TestProtocol:
    def test_satisfies_remote_agent_protocol(self) -> None:
        assert isinstance(WindowsFirewallBlocker(), RemoteAgent)


# ---------------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------------


class TestCheckStatus:
    @pytest.mark.asyncio
    async def test_reports_reachable_when_netsh_succeeds(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        fake_run(_ok())
        ok, message = await WindowsFirewallBlocker().check_status()
        assert ok is True
        assert "reachable" in message.lower()

    @pytest.mark.asyncio
    async def test_reports_unreachable_when_netsh_fails(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        fake_run(_fail("firewall service not running"))
        ok, message = await WindowsFirewallBlocker().check_status()
        assert ok is False
        assert "unreachable" in message.lower()


# ---------------------------------------------------------------------------
# add_to_blocklist
# ---------------------------------------------------------------------------


class TestAddToBlocklist:
    @pytest.mark.asyncio
    async def test_invalid_ip_refuses_without_netsh(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        recorded = fake_run(_ok())
        result = await WindowsFirewallBlocker().add_to_blocklist("not-an-ip")
        assert result is False
        assert recorded == []  # netsh never invoked

    @pytest.mark.asyncio
    async def test_creates_one_rule_per_direction(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        recorded = fake_run(_ok())
        result = await WindowsFirewallBlocker().add_to_blocklist("203.0.113.7")
        assert result is True
        assert len(recorded) == 2
        # Inbound first, outbound second — the order matters for the
        # is_blocked() short-circuit on the inbound rule.
        in_args, out_args = recorded
        assert "dir=in" in in_args
        assert "dir=out" in out_args
        for args in recorded:
            assert "remoteip=203.0.113.7" in args
            assert "action=block" in args
            assert any(a.startswith(f"name={_RULE_PREFIX}203.0.113.7_") for a in args)

    @pytest.mark.asyncio
    async def test_returns_false_when_one_direction_fails(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        # Inbound succeeds, outbound fails — overall result must be
        # False so the caller knows the block is incomplete.
        results = iter([_ok(), _fail("access denied")])
        fake_run(lambda _args: next(results))
        result = await WindowsFirewallBlocker().add_to_blocklist("203.0.113.7")
        assert result is False


# ---------------------------------------------------------------------------
# remove_from_blocklist
# ---------------------------------------------------------------------------


class TestRemoveFromBlocklist:
    @pytest.mark.asyncio
    async def test_invalid_ip_refuses(self, fake_run: Callable[[Any], list[list[str]]]) -> None:
        recorded = fake_run(_ok())
        assert await WindowsFirewallBlocker().remove_from_blocklist("nope") is False
        assert recorded == []

    @pytest.mark.asyncio
    async def test_removes_both_directions(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        recorded = fake_run(_ok())
        result = await WindowsFirewallBlocker().remove_from_blocklist("203.0.113.7")
        assert result is True
        assert len(recorded) == 2
        for args in recorded:
            assert "delete" in args
            assert "rule" in args

    @pytest.mark.asyncio
    async def test_treats_no_rules_match_as_success(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        """``netsh delete`` returns non-zero when the rule does not
        exist; we treat that as success because "the IP is no longer
        blocked" is the contract this method promises."""
        # Both calls return the netsh "no match" diagnostic.
        no_match = MagicMock(
            returncode=1,
            stdout="No rules match the specified criteria.",
            stderr="",
        )
        fake_run(no_match)
        result = await WindowsFirewallBlocker().remove_from_blocklist("203.0.113.7")
        assert result is True


# ---------------------------------------------------------------------------
# is_blocked
# ---------------------------------------------------------------------------


class TestIsBlocked:
    @pytest.mark.asyncio
    async def test_invalid_ip_returns_false(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        recorded = fake_run(_ok())
        assert await WindowsFirewallBlocker().is_blocked("nope") is False
        assert recorded == []

    @pytest.mark.asyncio
    async def test_returns_true_when_inbound_rule_exists(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        # Inbound show succeeds — short-circuit, second call never made.
        recorded = fake_run(_ok("Rule Name: WardSOAR_block_203.0.113.7_in"))
        result = await WindowsFirewallBlocker().is_blocked("203.0.113.7")
        assert result is True
        assert len(recorded) == 1  # outbound check skipped

    @pytest.mark.asyncio
    async def test_returns_true_when_only_outbound_rule_exists(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        results = iter(
            [
                _fail("No rules match the specified criteria"),
                _ok("Rule Name: WardSOAR_block_203.0.113.7_out"),
            ]
        )
        fake_run(lambda _args: next(results))
        assert await WindowsFirewallBlocker().is_blocked("203.0.113.7") is True

    @pytest.mark.asyncio
    async def test_returns_false_when_no_rules_match(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        fake_run(_fail("No rules match the specified criteria"))
        assert await WindowsFirewallBlocker().is_blocked("203.0.113.7") is False


# ---------------------------------------------------------------------------
# list_blocklist
# ---------------------------------------------------------------------------


class TestListBlocklist:
    @pytest.mark.asyncio
    async def test_returns_unique_sorted_ips(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        netsh_output = "\n".join(
            [
                "Rule Name:                    Some other rule",
                "Enabled:                      Yes",
                "",
                "Rule Name:                    WardSOAR_block_203.0.113.42_in",
                "Enabled:                      Yes",
                "",
                "Rule Name:                    WardSOAR_block_198.51.100.7_in",
                "Enabled:                      Yes",
                "",
                "Rule Name:                    WardSOAR_block_203.0.113.42_in",
                "Enabled:                      Yes",  # duplicate — set dedup
            ]
        )
        fake_run(_ok(netsh_output))
        result = await WindowsFirewallBlocker().list_blocklist()
        assert result == ["198.51.100.7", "203.0.113.42"]

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_wardsoar_rules(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        fake_run(_ok("Rule Name: Some other rule"))
        assert await WindowsFirewallBlocker().list_blocklist() == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_netsh_failure(
        self, fake_run: Callable[[Any], list[list[str]]]
    ) -> None:
        fake_run(_fail("access denied"))
        assert await WindowsFirewallBlocker().list_blocklist() == []


# ---------------------------------------------------------------------------
# Subprocess error fail-safety
# ---------------------------------------------------------------------------


class TestSubprocessFailSafe:
    """The blocker must catch every subprocess error and stay alive."""

    @pytest.mark.asyncio
    async def test_file_not_found_is_caught(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*_args: Any, **_kwargs: Any) -> Any:
            raise FileNotFoundError("netsh.exe not found")

        monkeypatch.setattr("wardsoar.pc.windows_firewall.subprocess.run", _raise)
        ok, message = await WindowsFirewallBlocker().check_status()
        assert ok is False
        assert "not found" in message.lower()

    @pytest.mark.asyncio
    async def test_timeout_is_caught(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*_args: Any, **_kwargs: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd="netsh", timeout=10.0)

        monkeypatch.setattr("wardsoar.pc.windows_firewall.subprocess.run", _raise)
        ok, message = await WindowsFirewallBlocker().check_status()
        assert ok is False
        assert "timeout" in message.lower()


# ---------------------------------------------------------------------------
# kill_process_on_target — co-resident agent, real psutil interaction
# ---------------------------------------------------------------------------


class TestKillProcessOnTarget:
    """``WindowsFirewallBlocker`` runs on the same Windows host as the
    process to kill, so it owns the ``psutil`` interaction. We mock
    ``psutil.Process`` to keep the test deterministic without spawning
    real processes."""

    @pytest.mark.asyncio
    async def test_successful_terminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The happy path: psutil resolves the PID, we read its name,
        terminate it, and return ``(True, name)`` to the responder."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "malware.exe"
        monkeypatch.setattr(
            "wardsoar.pc.windows_firewall.psutil.Process",
            MagicMock(return_value=mock_proc),
        )

        success, message = await WindowsFirewallBlocker().kill_process_on_target(1234)

        assert success is True
        assert message == "malware.exe"
        mock_proc.terminate.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_no_such_process_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lookup race: between alert detection and kill, the process
        already exited. Surface a ``(False, message)`` so the responder
        logs the miss without crashing the pipeline."""
        import psutil as real_psutil

        def _raise_no_such(_pid: int) -> Any:
            raise real_psutil.NoSuchProcess(99999)

        monkeypatch.setattr(
            "wardsoar.pc.windows_firewall.psutil.Process",
            _raise_no_such,
        )

        success, message = await WindowsFirewallBlocker().kill_process_on_target(99999)

        assert success is False
        assert "99999" in message or "no process" in message.lower()

    @pytest.mark.asyncio
    async def test_access_denied_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Privilege escalation refused: the operator launched WardSOAR
        non-elevated and the OS denies the terminate. Same fail-safe
        contract — return ``(False, message)`` for the responder to log."""
        import psutil as real_psutil

        def _raise_denied(_pid: int) -> Any:
            raise real_psutil.AccessDenied(1234)

        monkeypatch.setattr(
            "wardsoar.pc.windows_firewall.psutil.Process",
            _raise_denied,
        )

        success, message = await WindowsFirewallBlocker().kill_process_on_target(1234)

        assert success is False


class TestStreamAlerts:
    """``WindowsFirewallBlocker`` is sink-only today — its alert stream
    must terminate immediately so ``async for`` consumers don't hang
    waiting for a source it doesn't have."""

    @pytest.mark.asyncio
    async def test_stream_yields_nothing(self) -> None:
        events: list[dict[str, object]] = []
        async for event in WindowsFirewallBlocker().stream_alerts():
            events.append(event)
        assert events == []
