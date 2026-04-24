"""User-initiated rollback of a pfSense block.

A rollback is the safety valve that makes aggressive auto-blocking
acceptable: if the operator clicks "Unblock IP" in the UI, the system
must undo the block quickly and reliably.

Orchestration (see docs/architecture.md §4.2):
    1. Remove the pfSense rule for the IP.
    2. Add the IP to the trusted_temp registry so the pipeline does
       not immediately re-block it.
    3. Record a negative feedback delta against the signature that
       triggered the block, so future identical alerts are scored lower.
    4. Append a structured entry to the rollback audit log for later
       review (who rolled back what, when, why).

Fail-safe: each step is independent. A failure in step 1 means nothing
else happens (there's nothing to protect against); failures in steps 2-4
are logged but do not mask the fact that the unblock itself succeeded.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.prescorer_feedback import ROLLBACK_DELTA, PreScorerFeedbackStore
from src.rule_manager import RuleManager
from src.trusted_temp import DEFAULT_TTL_SECONDS, TrustedTempRegistry

logger = logging.getLogger("ward_soar.rollback")


@dataclass
class RollbackResult:
    """Outcome of a rollback operation.

    Attributes:
        ip: Target IP address.
        success: True if the pfSense rule was actually removed.
        unblocked_at: ISO timestamp of the successful unblock.
        trusted_temp_ttl: Seconds the IP was added as trusted_temp.
        feedback_delta: Score delta applied to the originating SID (if any).
        signature_id: SID the rollback was associated with (may be None).
        reason: Optional free-text reason from the operator.
        error: Non-empty when ``success`` is False.
    """

    ip: str
    success: bool
    unblocked_at: Optional[str] = None
    trusted_temp_ttl: int = 0
    feedback_delta: int = 0
    signature_id: Optional[int] = None
    reason: Optional[str] = None
    error: Optional[str] = None
    followups: list[str] = field(default_factory=list)


class RollbackManager:
    """Coordinate the full rollback workflow.

    Args:
        rule_manager: Handles the pfSense SSH unblock.
        trusted_temp: IP registry updated on successful unblock.
        feedback_store: PreScorer feedback sink updated on successful unblock.
        audit_log_path: JSON-lines file recording each rollback.
    """

    def __init__(
        self,
        rule_manager: RuleManager,
        trusted_temp: TrustedTempRegistry,
        feedback_store: PreScorerFeedbackStore,
        audit_log_path: Path,
    ) -> None:
        self._rule_manager = rule_manager
        self._trusted_temp = trusted_temp
        self._feedback = feedback_store
        self._audit_path = audit_log_path

    async def rollback(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        reason: Optional[str] = None,
        trusted_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> RollbackResult:
        """Undo a block for ``ip`` end-to-end.

        Args:
            ip: IP to unblock.
            signature_id: SID associated with the original block, if known.
                          Used to apply the feedback delta.
            reason: Optional operator note (appears in the audit log).
            trusted_ttl_seconds: How long to shield the IP from re-blocking.

        Returns:
            A RollbackResult describing exactly what happened.
        """
        # Step 1 — the only step that must succeed.
        try:
            unblocked = await self._rule_manager.emergency_unblock(ip)
        except (OSError, ValueError) as exc:
            logger.exception("Rollback: emergency_unblock raised for %s", ip)
            result = RollbackResult(ip=ip, success=False, error=str(exc))
            self._append_audit(result)
            return result

        if not unblocked:
            result = RollbackResult(
                ip=ip,
                success=False,
                error="pfSense refused to remove the rule",
            )
            self._append_audit(result)
            return result

        now_iso = datetime.now(timezone.utc).isoformat()
        result = RollbackResult(
            ip=ip,
            success=True,
            unblocked_at=now_iso,
            signature_id=signature_id,
            reason=reason,
        )

        # Step 2 — trust shield (best-effort)
        try:
            self._trusted_temp.add(ip, ttl_seconds=trusted_ttl_seconds)
            result.trusted_temp_ttl = trusted_ttl_seconds
        except (OSError, ValueError) as exc:
            logger.warning("Rollback: trusted_temp.add failed for %s: %s", ip, exc)
            result.followups.append(f"trusted_temp_failed: {exc}")

        # Step 3 — feedback loop (only if we know the SID)
        if signature_id is not None:
            try:
                new_delta = self._feedback.add_feedback(signature_id, ROLLBACK_DELTA)
                result.feedback_delta = new_delta
            except (OSError, ValueError) as exc:
                logger.warning(
                    "Rollback: feedback update failed for SID %d: %s",
                    signature_id,
                    exc,
                )
                result.followups.append(f"feedback_failed: {exc}")
        else:
            result.followups.append("feedback_skipped: signature_id unknown")

        # Step 4 — audit log (always attempted)
        self._append_audit(result)

        logger.info(
            "Rollback: %s unblocked (sid=%s, ttl=%ds, delta=%+d)",
            ip,
            signature_id,
            result.trusted_temp_ttl,
            result.feedback_delta,
        )
        return result

    def _append_audit(self, result: RollbackResult) -> None:
        """Append a JSON line to the rollback audit log. Never raises."""
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(asdict(result), default=str)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.error("Rollback: audit log write failed: %s", exc)
