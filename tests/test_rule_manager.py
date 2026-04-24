"""Tests for WardSOAR pfSense rule lifecycle manager.

RuleManager is CRITICAL (95% coverage). All pfSense SSH calls are mocked.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import WhitelistConfig
from src.pfsense_ssh import BlockTracker, PfSenseSSH
from src.rule_manager import RuleManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_whitelist() -> WhitelistConfig:
    """Create a test whitelist."""
    return WhitelistConfig(ips={"192.168.1.1", "192.168.1.100"})


def _make_manager(tmp_path: Path) -> RuleManager:
    """Create a test RuleManager with mocked SSH."""
    ssh = MagicMock(spec=PfSenseSSH)
    ssh.add_to_blocklist = AsyncMock(return_value=True)
    ssh.remove_from_blocklist = AsyncMock(return_value=True)
    ssh.is_blocked = AsyncMock(return_value=False)
    ssh.list_blocklist = AsyncMock(return_value=[])

    tracker = BlockTracker(persist_path=tmp_path / "blocks.json")

    return RuleManager(
        config={"cleanup_interval_minutes": 15},
        whitelist=_make_whitelist(),
        ssh=ssh,
        tracker=tracker,
        block_duration_hours=24,
    )


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestRuleManagerInit:
    """Tests for RuleManager initialization."""

    def test_construction(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        assert mgr._cleanup_interval == 15
        assert mgr._block_duration_hours == 24


# ---------------------------------------------------------------------------
# cleanup_expired_rules tests
# ---------------------------------------------------------------------------


class TestCleanupExpiredRules:
    """Tests for RuleManager.cleanup_expired_rules."""

    @pytest.mark.asyncio
    async def test_removes_expired_blocks(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        # Add an expired block
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        mgr._tracker._blocks["10.0.0.1"] = old_time
        # Add a fresh block
        mgr._tracker._blocks["10.0.0.2"] = datetime.now(timezone.utc).isoformat()

        result = await mgr.cleanup_expired_rules()
        assert "10.0.0.1" in result
        assert "10.0.0.2" not in result
        mgr._ssh.remove_from_blocklist.assert_called_once_with("10.0.0.1")

    @pytest.mark.asyncio
    async def test_ssh_failure_skips_removal(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        mgr._tracker._blocks["10.0.0.1"] = old_time
        mgr._ssh.remove_from_blocklist = AsyncMock(return_value=False)

        result = await mgr.cleanup_expired_rules()
        assert result == []
        # Tracker should NOT have removed the entry since SSH failed
        assert mgr._tracker.get_block_time("10.0.0.1") is not None

    @pytest.mark.asyncio
    async def test_no_expired_blocks(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._tracker._blocks["10.0.0.1"] = datetime.now(timezone.utc).isoformat()

        result = await mgr.cleanup_expired_rules()
        assert result == []


# ---------------------------------------------------------------------------
# verify_coherence tests
# ---------------------------------------------------------------------------


class TestVerifyCoherence:
    """Tests for RuleManager.verify_coherence."""

    @pytest.mark.asyncio
    async def test_returns_coherence_report(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._ssh.list_blocklist = AsyncMock(return_value=[])

        result = await mgr.verify_coherence()
        assert "whitelist_violations" in result

    @pytest.mark.asyncio
    async def test_detects_whitelist_violation(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._ssh.list_blocklist = AsyncMock(return_value=["192.168.1.1"])

        result = await mgr.verify_coherence()
        assert len(result["whitelist_violations"]) > 0
        assert "192.168.1.1" in result["whitelist_violations"]

    @pytest.mark.asyncio
    async def test_reconciles_tracker(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._tracker.record_block("10.0.0.1")  # In tracker
        mgr._ssh.list_blocklist = AsyncMock(return_value=["10.0.0.2"])  # Only 10.0.0.2 in pf

        await mgr.verify_coherence()
        # After reconcile: 10.0.0.1 removed from tracker, 10.0.0.2 added
        assert mgr._tracker.get_block_time("10.0.0.1") is None
        assert mgr._tracker.get_block_time("10.0.0.2") is not None


# ---------------------------------------------------------------------------
# emergency_unblock tests
# ---------------------------------------------------------------------------


class TestEmergencyUnblock:
    """Tests for RuleManager.emergency_unblock."""

    @pytest.mark.asyncio
    async def test_successful_unblock(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._tracker.record_block("10.0.0.1")

        result = await mgr.emergency_unblock("10.0.0.1")
        assert result is True
        mgr._ssh.remove_from_blocklist.assert_called_once_with("10.0.0.1")
        assert mgr._tracker.get_block_time("10.0.0.1") is None

    @pytest.mark.asyncio
    async def test_ssh_failure_returns_false(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        mgr._ssh.remove_from_blocklist = AsyncMock(return_value=False)

        result = await mgr.emergency_unblock("10.0.0.1")
        assert result is False
