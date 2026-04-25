"""Tests for the ``NoOpAgent`` stub (v0.22.21).

The agent has no I/O — every method returns the documented "no remote
enforcement available" outcome. Tests focus on:

  * structural conformance to the ``RemoteAgent`` protocol;
  * the documented return values (False on add, True on remove,
    empty on list, ``(False, msg)`` on check_status);
  * the WARNING log on add_to_blocklist so operators can correlate
    skipped blocks with the no-op mode.
"""

from __future__ import annotations

import logging

import pytest

from wardsoar.core.remote_agents import NoOpAgent, RemoteAgent


class TestNoOpAgentProtocol:
    def test_satisfies_remote_agent_protocol(self) -> None:
        assert isinstance(NoOpAgent(), RemoteAgent)


class TestNoOpAgentBehaviour:
    @pytest.mark.asyncio
    async def test_check_status_reports_disabled(self) -> None:
        ok, message = await NoOpAgent().check_status()
        assert ok is False
        assert "no remote agent" in message.lower()

    @pytest.mark.asyncio
    async def test_add_to_blocklist_returns_false(self) -> None:
        assert await NoOpAgent().add_to_blocklist("203.0.113.7") is False

    @pytest.mark.asyncio
    async def test_add_to_blocklist_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        ward_logger = logging.getLogger("ward_soar")
        previous_propagate = ward_logger.propagate
        ward_logger.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="ward_soar.remote_agents.no_op"):
                await NoOpAgent().add_to_blocklist("203.0.113.7")
        finally:
            ward_logger.propagate = previous_propagate

        warning_messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("no_op_agent" in m for m in warning_messages)
        assert any("203.0.113.7" in m for m in warning_messages)

    @pytest.mark.asyncio
    async def test_remove_returns_true_to_keep_cleanup_quiet(self) -> None:
        """Removing from a list that does not exist is a successful no-op
        — otherwise the periodic rule_manager cleanup would log a
        warning on every sweep."""
        assert await NoOpAgent().remove_from_blocklist("203.0.113.7") is True

    @pytest.mark.asyncio
    async def test_is_blocked_returns_false(self) -> None:
        assert await NoOpAgent().is_blocked("203.0.113.7") is False

    @pytest.mark.asyncio
    async def test_list_blocklist_returns_empty(self) -> None:
        assert await NoOpAgent().list_blocklist() == []

    @pytest.mark.asyncio
    async def test_kill_process_on_target_raises_not_implemented(self) -> None:
        """The no-op agent has no host, so a kill request must surface
        ``NotImplementedError`` and let the responder skip the action.
        """
        with pytest.raises(NotImplementedError, match="no target host"):
            await NoOpAgent().kill_process_on_target(1234)
