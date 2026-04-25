"""Tests for WardSOAR threat responder.

Responder is CRITICAL (95% coverage). Controls a production firewall.
Key safety tests: whitelist enforcement, rate limiting, dry-run mode,
fail-safe on errors.
"""

import logging
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.config import WhitelistConfig
from wardsoar.core.models import BlockAction, ResponseAction, ThreatAnalysis, ThreatVerdict
from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker, PfSenseSSH
from wardsoar.core.responder import RateLimiter, ThreatResponder
from wardsoar.core.trusted_temp import TrustedTempRegistry


@pytest.fixture(autouse=True)
def _ensure_responder_logger_propagation() -> Iterator[None]:
    """Force the ``ward_soar`` logger to propagate so caplog captures records.

    ``setup_logging`` sets ``propagate = False`` on the parent logger
    (logger.py:55) to avoid duplicate output. When test_logger.py runs
    before this module in the full suite, the flag persists and breaks
    caplog capture for ``ward_soar.responder``. We restore propagation
    for the duration of each test.
    """
    parent = logging.getLogger("ward_soar")
    saved = parent.propagate
    parent.propagate = True
    yield
    parent.propagate = saved


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analysis(
    verdict: ThreatVerdict = ThreatVerdict.CONFIRMED,
    confidence: float = 0.85,
) -> ThreatAnalysis:
    """Create a test ThreatAnalysis."""
    return ThreatAnalysis(verdict=verdict, confidence=confidence, reasoning="Test")


def _make_whitelist(ips: set[str] | None = None) -> WhitelistConfig:
    """Create a test whitelist."""
    return WhitelistConfig(ips=ips or {"192.168.1.1", "192.168.1.100"})


def _make_responder(
    dry_run: bool = True,
    whitelist: WhitelistConfig | None = None,
    tmp_path: Path | None = None,
) -> ThreatResponder:
    """Create a test ThreatResponder with mocked SSH."""
    ssh = MagicMock(spec=PfSenseSSH)
    ssh.add_to_blocklist = AsyncMock(return_value=True)
    ssh.remove_from_blocklist = AsyncMock(return_value=True)
    ssh.is_blocked = AsyncMock(return_value=False)
    ssh.list_blocklist = AsyncMock(return_value=[])
    # Default kill behaviour: pretend the agent is co-resident and the
    # kill always succeeds. Individual tests override via AsyncMock or
    # by setting ``side_effect=NotImplementedError(...)`` when they
    # exercise the off-host branch.
    ssh.kill_process_on_target = AsyncMock(return_value=(True, "test_proc"))

    tracker_path = (tmp_path or Path("/tmp")) / "test_blocks.json"
    tracker = BlockTracker(persist_path=tracker_path)

    return ThreatResponder(
        config={"dry_run": dry_run, "block_duration_hours": 24, "max_blocks_per_hour": 20},
        whitelist=whitelist or _make_whitelist(),
        ssh=ssh,
        tracker=tracker,
    )


# ---------------------------------------------------------------------------
# RateLimiter tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_allows_within_limit(self) -> None:
        rl = RateLimiter(max_per_hour=5)
        for _ in range(5):
            assert rl.can_block() is True
            rl.record_action()

    def test_blocks_over_limit(self) -> None:
        rl = RateLimiter(max_per_hour=2)
        rl.record_action()
        rl.record_action()
        assert rl.can_block() is False

    def test_old_actions_expire(self) -> None:
        rl = RateLimiter(max_per_hour=1)
        rl.record_action()
        # Manually set action to be old
        rl._actions[0] = datetime.now(timezone.utc) - timedelta(hours=2)
        assert rl.can_block() is True

    def test_empty_limiter(self) -> None:
        rl = RateLimiter(max_per_hour=20)
        assert rl.can_block() is True


# ---------------------------------------------------------------------------
# ThreatResponder.respond tests — CRITICAL SAFETY TESTS
# ---------------------------------------------------------------------------


class TestRespond:
    """Tests for ThreatResponder.respond — the most critical function."""

    @pytest.mark.asyncio
    async def test_dry_run_does_not_block(self, tmp_path: Path) -> None:
        """In dry-run mode, NO blocking action should be executed."""
        responder = _make_responder(dry_run=True, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.9)

        actions = await responder.respond(analysis, "185.199.108.153")

        for action in actions:
            assert action.action_type == BlockAction.NONE
        assert all(not a.success for a in actions if a.action_type != BlockAction.NONE)

    @pytest.mark.asyncio
    async def test_whitelist_prevents_blocking(self, tmp_path: Path) -> None:
        """Whitelisted IPs must NEVER be blocked — P0 safety requirement."""
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.95)

        # Gateway IP is whitelisted
        actions = await responder.respond(analysis, "192.168.1.1")

        blocked = [a for a in actions if a.action_type == BlockAction.IP_BLOCK and a.success]
        assert len(blocked) == 0

    @pytest.mark.asyncio
    async def test_benign_verdict_no_action(self, tmp_path: Path) -> None:
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.BENIGN, 0.2)

        actions = await responder.respond(analysis, "185.199.108.153")
        assert all(a.action_type == BlockAction.NONE for a in actions)

    @pytest.mark.asyncio
    async def test_inconclusive_no_action(self, tmp_path: Path) -> None:
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.INCONCLUSIVE, 0.5)

        actions = await responder.respond(analysis, "185.199.108.153")
        assert all(a.action_type == BlockAction.NONE for a in actions)

    @pytest.mark.asyncio
    async def test_low_confidence_no_block(self, tmp_path: Path) -> None:
        """Below confidence threshold, do not block even if verdict is confirmed."""
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.5)

        actions = await responder.respond(analysis, "185.199.108.153", confidence_threshold=0.7)
        blocked = [a for a in actions if a.action_type == BlockAction.IP_BLOCK and a.success]
        assert len(blocked) == 0

    @pytest.mark.asyncio
    async def test_rate_limit_prevents_blocking(self, tmp_path: Path) -> None:
        """When rate limit is exceeded, do not block."""
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        # Exhaust rate limiter
        for _ in range(20):
            responder._rate_limiter.record_action()

        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.9)
        actions = await responder.respond(analysis, "185.199.108.153")

        blocked = [a for a in actions if a.action_type == BlockAction.IP_BLOCK and a.success]
        assert len(blocked) == 0

    @pytest.mark.asyncio
    async def test_confirmed_high_confidence_blocks(self, tmp_path: Path) -> None:
        """Confirmed threat with high confidence should trigger block."""
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        responder.block_ip_pfsense = AsyncMock(  # type: ignore[method-assign]
            return_value=ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip="185.199.108.153",
                success=True,
                executed_at=datetime.now(timezone.utc),
            )
        )

        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.9)
        actions = await responder.respond(analysis, "185.199.108.153")

        blocked = [a for a in actions if a.action_type == BlockAction.IP_BLOCK and a.success]
        assert len(blocked) == 1

    @pytest.mark.asyncio
    async def test_confirmed_with_process_kill(self, tmp_path: Path) -> None:
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        responder.block_ip_pfsense = AsyncMock(  # type: ignore[method-assign]
            return_value=ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip="185.199.108.153",
                success=True,
            )
        )
        responder.kill_local_process = AsyncMock(  # type: ignore[method-assign]
            return_value=ResponseAction(
                action_type=BlockAction.PROCESS_KILL,
                target_process_id=1234,
                success=True,
            )
        )

        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.9)
        actions = await responder.respond(analysis, "185.199.108.153", process_id=1234)

        action_types = [a.action_type for a in actions]
        assert BlockAction.IP_BLOCK in action_types
        assert BlockAction.PROCESS_KILL in action_types

    @pytest.mark.asyncio
    async def test_rfc1918_guard_refuses_private_ip(self, tmp_path: Path) -> None:
        """RFC1918 guard refuses to block a private IP regardless of verdict.

        Defense in depth: blocking 192.168.x.x would silence the
        operator's own LAN. Guard is unconditional, runs before
        whitelist and rate-limiter.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.99)

        actions = await responder.respond(analysis, "192.168.2.100")

        assert all(a.action_type == BlockAction.NONE for a in actions)
        assert any("RFC1918" in (a.error_message or "") for a in actions)

    @pytest.mark.asyncio
    async def test_rfc1918_guard_logs_debug_on_benign(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On BENIGN verdict, the RFC1918 guard logs at DEBUG, not WARNING.

        No block was about to be issued, so a WARNING level is
        misleading and pollutes operator dashboards. Observed in
        production v0.22.8 logs (STUN traffic generated 33 false
        warnings over 5 days).
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.BENIGN, 0.95)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            await responder.respond(analysis, "192.168.2.100")

        rfc_records = [r for r in caplog.records if "RFC1918 GUARD" in r.getMessage()]
        assert len(rfc_records) == 1
        assert rfc_records[0].levelno == logging.DEBUG

    @pytest.mark.asyncio
    async def test_rfc1918_guard_logs_warning_on_confirmed(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On CONFIRMED verdict, the RFC1918 guard logs at WARNING.

        A block was wanted — the guard genuinely saved the operator
        from blocking their own LAN. Operator should see this in
        dashboards as a near-miss event.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.99)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            await responder.respond(analysis, "192.168.2.100")

        rfc_records = [r for r in caplog.records if "RFC1918 GUARD" in r.getMessage()]
        assert len(rfc_records) == 1
        assert rfc_records[0].levelno == logging.WARNING

    @pytest.mark.asyncio
    async def test_rfc1918_guard_logs_warning_on_inconclusive(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On INCONCLUSIVE verdict, the RFC1918 guard logs at WARNING.

        INCONCLUSIVE in HARD_PROTECT mode would block — same near-miss
        semantics as CONFIRMED. Only BENIGN is downgraded to DEBUG.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.INCONCLUSIVE, 0.0)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            await responder.respond(analysis, "192.168.2.100")

        rfc_records = [r for r in caplog.records if "RFC1918 GUARD" in r.getMessage()]
        assert len(rfc_records) == 1
        assert rfc_records[0].levelno == logging.WARNING

    @pytest.mark.asyncio
    async def test_whitelist_logs_debug_on_benign(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On BENIGN verdict, the whitelist gate logs at DEBUG, not WARNING.

        No block was about to be issued. Same rationale as the
        RFC1918 guard.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.BENIGN, 0.5)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            # 192.168.1.1 is in the default test whitelist; RFC1918 fires
            # first, so use a non-private whitelisted IP for this test.
            responder._whitelist = WhitelistConfig(ips={"185.199.108.153"})
            await responder.respond(analysis, "185.199.108.153")

        records = [r for r in caplog.records if "WHITELIST BLOCK" in r.getMessage()]
        assert len(records) == 1
        assert records[0].levelno == logging.DEBUG

    @pytest.mark.asyncio
    async def test_whitelist_logs_warning_on_confirmed(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On CONFIRMED verdict, the whitelist gate logs at WARNING.

        A block was wanted — the whitelist genuinely prevented it.
        Operator should see this as a near-miss event in dashboards.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.95)
        responder._whitelist = WhitelistConfig(ips={"185.199.108.153"})

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            await responder.respond(analysis, "185.199.108.153")

        records = [r for r in caplog.records if "WHITELIST BLOCK" in r.getMessage()]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING

    @pytest.mark.asyncio
    async def test_trusted_temp_logs_debug_on_benign(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On BENIGN verdict, the trusted_temp gate logs at DEBUG.

        Same rationale: no block was wanted, no real flapping risk to
        flag. WARNING was misleading for the operator.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        trusted = MagicMock(spec=TrustedTempRegistry)
        trusted.is_trusted.return_value = True
        responder._trusted_temp = trusted
        analysis = _make_analysis(ThreatVerdict.BENIGN, 0.5)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            # Public IP that is neither RFC1918 nor whitelisted, only trusted_temp
            await responder.respond(analysis, "203.0.113.5")

        records = [r for r in caplog.records if "TRUSTED_TEMP" in r.getMessage()]
        assert len(records) == 1
        assert records[0].levelno == logging.DEBUG

    @pytest.mark.asyncio
    async def test_trusted_temp_logs_warning_on_confirmed(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """On CONFIRMED verdict, the trusted_temp gate logs at WARNING.

        The operator just rolled back this IP and now WardSOAR wants
        to re-block on a confirmed threat — that is a real flapping
        signal worth surfacing.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        trusted = MagicMock(spec=TrustedTempRegistry)
        trusted.is_trusted.return_value = True
        responder._trusted_temp = trusted
        analysis = _make_analysis(ThreatVerdict.CONFIRMED, 0.95)

        with caplog.at_level(logging.DEBUG, logger="ward_soar.responder"):
            await responder.respond(analysis, "203.0.113.5")

        records = [r for r in caplog.records if "TRUSTED_TEMP" in r.getMessage()]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING


# ---------------------------------------------------------------------------
# block_ip_pfsense tests
# ---------------------------------------------------------------------------


class TestBlockIpPfsense:
    """Tests for ThreatResponder.block_ip_pfsense."""

    @pytest.mark.asyncio
    async def test_successful_block(self, tmp_path: Path) -> None:
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        result = await responder.block_ip_pfsense("185.199.108.153")
        assert result.success is True
        assert result.action_type == BlockAction.IP_BLOCK
        assert result.target_ip == "185.199.108.153"
        # Verify tracker was updated
        assert responder._tracker.get_block_time("185.199.108.153") is not None

    @pytest.mark.asyncio
    async def test_ssh_error_returns_failed(self, tmp_path: Path) -> None:
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        responder._ssh.add_to_blocklist = AsyncMock(return_value=False)
        responder._ssh.is_blocked = AsyncMock(return_value=False)
        result = await responder.block_ip_pfsense("185.199.108.153")
        assert result.success is False
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_already_blocked_short_circuits(self, tmp_path: Path) -> None:
        """Regression for the 2026-04-23 22:40 duplicate-block incident.

        Two concurrent alerts on the same IP produced two ``Blocked IP``
        log lines within two seconds and overwrote the block tracker's
        original timestamp. ``block_ip_pfsense`` now pre-checks the
        alias file; if the IP is already listed, it returns an
        ``idempotent=True`` action without touching the tracker or the
        SSH ``add`` path.
        """
        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        responder._ssh.is_blocked = AsyncMock(return_value=True)
        responder._ssh.add_to_blocklist = AsyncMock(return_value=True)

        result = await responder.block_ip_pfsense("185.199.108.153")

        assert result.success is True
        assert result.idempotent is True
        # add_to_blocklist is never reached — the pre-check short-circuits.
        responder._ssh.add_to_blocklist.assert_not_awaited()
        # The tracker is left untouched so the original block time is
        # preserved; recording again would overwrite it with ``now()``.
        assert responder._tracker.get_block_time("185.199.108.153") is None

    @pytest.mark.asyncio
    async def test_idempotent_block_does_not_charge_rate_limiter(self, tmp_path: Path) -> None:
        """A no-op idempotent skip must not consume the per-hour budget.

        Otherwise a burst of duplicate alerts on a single already-blocked
        IP could exhaust the limiter and prevent genuine blocks on the
        next fresh alert.
        """
        from wardsoar.core.analyzer import ThreatAnalyzer  # noqa: F401 — keep imports grouped
        from wardsoar.core.models import (
            SuricataAlert,
            SuricataAlertSeverity,
            ThreatAnalysis,
            ThreatVerdict,
        )

        responder = _make_responder(dry_run=False, tmp_path=tmp_path)
        responder._mode = responder._mode.__class__("hard_protect")
        responder._ssh.is_blocked = AsyncMock(return_value=True)

        alert = SuricataAlert(
            timestamp=datetime.now(timezone.utc),
            src_ip="185.199.108.153",
            src_port=1234,
            dest_ip="192.168.2.100",
            dest_port=443,
            proto="TCP",
            alert_signature="ET MALWARE Test",
            alert_signature_id=2024897,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        analysis = ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.95,
            reasoning="test",
        )

        before = len(responder._rate_limiter._actions)  # noqa: SLF001
        actions = await responder.respond(analysis, alert.src_ip)
        after = len(responder._rate_limiter._actions)  # noqa: SLF001

        assert any(a.idempotent for a in actions)
        # Rate limit counter unchanged because no mutation happened.
        assert after == before


# ---------------------------------------------------------------------------
# kill_local_process tests
# ---------------------------------------------------------------------------


class TestKillLocalProcess:
    """Tests for ThreatResponder.kill_local_process.

    The actual kill is delegated to ``RemoteAgent.kill_process_on_target``
    so the responder no longer touches ``psutil`` directly. These tests
    drive the three branches the responder must distinguish:

    * agent reports success → ``ResponseAction(PROCESS_KILL, success=True)``
    * agent reports local failure → ``ResponseAction(PROCESS_KILL, success=False)``
    * agent raises ``NotImplementedError`` (off-host) → ``ResponseAction(NONE, success=False)``
    """

    @pytest.mark.asyncio
    async def test_successful_kill(self, tmp_path: Path) -> None:
        responder = _make_responder(tmp_path=tmp_path)
        responder._ssh.kill_process_on_target = AsyncMock(  # type: ignore[method-assign]
            return_value=(True, "malware.exe")
        )

        result = await responder.kill_local_process(1234)
        assert result.success is True
        assert result.action_type == BlockAction.PROCESS_KILL
        assert result.target_process_id == 1234

    @pytest.mark.asyncio
    async def test_nonexistent_process(self, tmp_path: Path) -> None:
        responder = _make_responder(tmp_path=tmp_path)
        responder._ssh.kill_process_on_target = AsyncMock(  # type: ignore[method-assign]
            return_value=(False, "process 99999 no longer exists")
        )

        result = await responder.kill_local_process(99999)
        assert result.success is False
        assert result.action_type == BlockAction.PROCESS_KILL
        assert result.error_message == "process 99999 no longer exists"

    @pytest.mark.asyncio
    async def test_off_host_agent_skips_kill(self, tmp_path: Path) -> None:
        """An off-host agent (Netgate, NoOp, future VS) raises
        ``NotImplementedError`` from ``kill_process_on_target``. The
        responder must catch it, return a ``BlockAction.NONE`` action,
        and never propagate the exception — the IP block stays applied,
        the kill is simply skipped.
        """
        responder = _make_responder(tmp_path=tmp_path)
        responder._ssh.kill_process_on_target = AsyncMock(  # type: ignore[method-assign]
            side_effect=NotImplementedError("agent off-host")
        )

        result = await responder.kill_local_process(4321)
        assert result.success is False
        assert result.action_type == BlockAction.NONE
        assert result.target_process_id == 4321
        assert "kill skipped" in (result.error_message or "")


# ---------------------------------------------------------------------------
# get_active_blocks tests
# ---------------------------------------------------------------------------


class TestGetActiveBlocks:
    """Tests for ThreatResponder.get_active_blocks."""

    @pytest.mark.asyncio
    async def test_returns_blocks(self, tmp_path: Path) -> None:
        responder = _make_responder(tmp_path=tmp_path)
        responder._ssh.list_blocklist = AsyncMock(return_value=["185.199.108.153", "10.0.0.2"])
        responder._tracker.record_block("185.199.108.153")

        result = await responder.get_active_blocks()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["ip"] == "185.199.108.153"
        assert result[0]["blocked_at"] is not None

    @pytest.mark.asyncio
    async def test_ssh_error_returns_empty(self, tmp_path: Path) -> None:
        responder = _make_responder(tmp_path=tmp_path)
        responder._ssh.list_blocklist = AsyncMock(side_effect=OSError("fail"))

        result = await responder.get_active_blocks()
        assert result == []
