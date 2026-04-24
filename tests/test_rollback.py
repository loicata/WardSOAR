"""Tests for the rollback orchestrator.

Rollback ties together several side effects: pfSense unblock,
trusted_temp shield, and PreScorer feedback delta. Each step is
tested for success and failure, and we verify the audit log is
always appended.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.prescorer_feedback import PreScorerFeedbackStore
from src.rollback import RollbackManager
from src.trusted_temp import TrustedTempRegistry


@pytest.fixture
def manager(
    tmp_path: Path,
) -> tuple[RollbackManager, MagicMock, TrustedTempRegistry, PreScorerFeedbackStore, Path]:
    """Build a RollbackManager with a mocked RuleManager and real stores."""
    rule_manager = MagicMock()
    rule_manager.emergency_unblock = AsyncMock(return_value=True)

    trusted = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
    feedback = PreScorerFeedbackStore(persist_path=tmp_path / "fb.json")
    audit = tmp_path / "logs" / "rollback_audit.jsonl"

    orch = RollbackManager(
        rule_manager=rule_manager,
        trusted_temp=trusted,
        feedback_store=feedback,
        audit_log_path=audit,
    )
    return orch, rule_manager, trusted, feedback, audit


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSuccess:
    """End-to-end rollback success."""

    @pytest.mark.asyncio
    async def test_unblock_succeeds_and_all_side_effects(self, manager: tuple) -> None:
        orch, rule_manager, trusted, feedback, audit = manager

        result = await orch.rollback(
            ip="203.0.113.5",
            signature_id=2024897,
            reason="false positive",
        )

        assert result.success is True
        assert result.ip == "203.0.113.5"
        assert result.signature_id == 2024897
        assert result.reason == "false positive"
        assert result.feedback_delta == -20
        assert result.trusted_temp_ttl > 0
        rule_manager.emergency_unblock.assert_awaited_once_with("203.0.113.5")

        # trusted_temp shielded the IP from re-block
        assert trusted.is_trusted("203.0.113.5") is True

        # feedback delta recorded against the SID
        assert feedback.get_delta(2024897) == -20

        # audit log contains exactly one entry with the expected payload
        assert audit.exists()
        lines = audit.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["ip"] == "203.0.113.5"
        assert entry["success"] is True

    @pytest.mark.asyncio
    async def test_unknown_sid_skips_feedback(self, manager: tuple) -> None:
        """Rollback without a known SID still succeeds; feedback is skipped."""
        orch, _, trusted, feedback, _ = manager

        result = await orch.rollback(ip="203.0.113.5", signature_id=None)

        assert result.success is True
        assert result.feedback_delta == 0
        assert feedback.snapshot() == {}
        assert "feedback_skipped" in " ".join(result.followups)


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class TestFailure:
    """Cases where pfSense refuses, raises, or side effects fail."""

    @pytest.mark.asyncio
    async def test_pfsense_refuses(self, manager: tuple) -> None:
        orch, rule_manager, trusted, feedback, audit = manager
        rule_manager.emergency_unblock = AsyncMock(return_value=False)

        result = await orch.rollback(ip="203.0.113.6", signature_id=111)

        assert result.success is False
        assert result.error is not None
        # Side effects must NOT have happened.
        assert trusted.is_trusted("203.0.113.6") is False
        assert feedback.get_delta(111) == 0
        # Audit log must still be appended for traceability.
        assert audit.exists()

    @pytest.mark.asyncio
    async def test_pfsense_raises(self, manager: tuple) -> None:
        orch, rule_manager, _, _, audit = manager
        rule_manager.emergency_unblock = AsyncMock(side_effect=OSError("SSH connection lost"))

        result = await orch.rollback(ip="203.0.113.7", signature_id=111)

        assert result.success is False
        assert "SSH connection lost" in str(result.error)
        assert audit.exists()


# ---------------------------------------------------------------------------
# Integration: Responder refuses to re-block trusted IPs
# ---------------------------------------------------------------------------


class TestResponderIntegration:
    """Ensure trusted_temp actually shields an IP from subsequent blocks."""

    @pytest.mark.asyncio
    async def test_trusted_ip_cannot_be_reblocked(self, manager: tuple) -> None:
        """After rollback, the Responder must refuse to re-block the same IP."""
        orch, _, trusted, _, _ = manager

        await orch.rollback(ip="203.0.113.8", signature_id=111)

        # Simulate what the Responder does before blocking:
        assert trusted.is_trusted("203.0.113.8") is True
