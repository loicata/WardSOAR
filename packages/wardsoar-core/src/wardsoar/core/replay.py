"""Replay alerts from the decision log in simulation mode.

Allows testing configuration changes (thresholds, prompts, baselines)
against real historical alerts WITHOUT affecting the live network.
All actions are simulated and logged separately.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from wardsoar.core.models import DecisionRecord, ThreatVerdict

if TYPE_CHECKING:
    from wardsoar.core.analyzer import ThreatAnalyzer

logger = logging.getLogger("ward_soar.replay")


@dataclass
class ReplayResult:
    """Result of replaying a single alert through the pipeline.

    Attributes:
        original_record: The original decision record from the log.
        replay_verdict: The verdict from the replay.
        replay_confidence: Confidence from the replay.
        verdict_changed: Whether the verdict differs from the original.
        original_verdict: The original verdict for comparison.
    """

    original_record: DecisionRecord
    replay_verdict: ThreatVerdict
    replay_confidence: float
    verdict_changed: bool
    original_verdict: ThreatVerdict


@dataclass
class ReplaySession:
    """A complete replay session with summary statistics.

    Attributes:
        session_id: Unique identifier for this replay.
        started_at: When the replay started.
        total_alerts: Number of alerts replayed.
        results: Individual replay results.
        verdict_changes: Number of verdicts that changed.
        completed: Whether the replay finished.
    """

    session_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_alerts: int = 0
    results: list[ReplayResult] = field(default_factory=list)
    verdict_changes: int = 0
    completed: bool = False


class AlertReplayer:
    """Replay historical alerts in simulation mode.

    Args:
        config: Replay configuration dict from config.yaml.
        analyzer: Optional ThreatAnalyzer for full Claude re-analysis mode.
    """

    def __init__(
        self,
        config: dict[str, Any],
        analyzer: Optional[ThreatAnalyzer] = None,
    ) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._decision_log_path: str = config.get("decision_log_path", "")
        self._analyzer = analyzer

    async def load_decision_log(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        verdict_filter: Optional[ThreatVerdict] = None,
    ) -> list[DecisionRecord]:
        """Load decision records from the log file with optional filters.

        Args:
            start_date: Only include records after this date.
            end_date: Only include records before this date.
            verdict_filter: Only include records with this verdict.

        Returns:
            List of matching DecisionRecord objects.
        """
        path = Path(self._decision_log_path)
        if not path.exists():
            logger.warning("Decision log not found: %s", self._decision_log_path)
            return []

        records: list[DecisionRecord] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = DecisionRecord.model_validate_json(stripped)
                except (json.JSONDecodeError, ValueError):
                    logger.debug("Skipping invalid line in decision log")
                    continue

                if start_date and record.timestamp < start_date:
                    continue
                if end_date and record.timestamp > end_date:
                    continue
                if verdict_filter and record.analysis:
                    if record.analysis.verdict != verdict_filter:
                        continue

                records.append(record)

        logger.info("Loaded %d records from decision log", len(records))
        return records

    async def replay_alert(
        self,
        record: DecisionRecord,
        reanalyze: bool = False,
    ) -> ReplayResult:
        """Replay a single alert through the current pipeline configuration.

        Args:
            record: The original decision record to replay.
            reanalyze: If True and an analyzer is configured, re-run Claude
                analysis on the alert with its original context. If False or
                no analyzer is available, the original verdict is reused.

        Returns:
            ReplayResult comparing original vs replay verdicts.
        """
        original_verdict = ThreatVerdict.INCONCLUSIVE
        original_confidence = 0.0

        if record.analysis:
            original_verdict = record.analysis.verdict
            original_confidence = record.analysis.confidence

        replay_verdict = original_verdict
        replay_confidence = original_confidence

        # Full re-analysis with Claude when requested and analyzer is available
        if reanalyze and self._analyzer is not None:
            try:
                new_analysis = await self._analyzer.analyze(
                    record.alert,
                    record.network_context,
                    record.forensic_result,
                    record.virustotal_results or None,
                )
                replay_verdict = new_analysis.verdict
                replay_confidence = new_analysis.confidence
            except Exception as exc:
                logger.warning("Re-analysis failed for %s: %s", record.record_id, exc)

        return ReplayResult(
            original_record=record,
            replay_verdict=replay_verdict,
            replay_confidence=replay_confidence,
            verdict_changed=(replay_verdict != original_verdict),
            original_verdict=original_verdict,
        )

    async def replay_batch(
        self,
        records: list[DecisionRecord],
        reanalyze: bool = False,
    ) -> ReplaySession:
        """Replay a batch of alerts and produce a summary.

        Args:
            records: List of decision records to replay.

        Returns:
            ReplaySession with all results and statistics.
        """
        session = ReplaySession(
            session_id=str(uuid.uuid4()),
            total_alerts=len(records),
        )

        for record in records:
            result = await self.replay_alert(record, reanalyze=reanalyze)
            session.results.append(result)
            if result.verdict_changed:
                session.verdict_changes += 1

        session.completed = True
        logger.info(
            "Replay session %s completed: %d alerts, %d changes",
            session.session_id,
            session.total_alerts,
            session.verdict_changes,
        )
        return session

    def compute_impact_report(self, session: ReplaySession) -> dict[str, Any]:
        """Compute an impact report for a replay session.

        Args:
            session: Completed replay session.

        Returns:
            Dict with impact statistics.
        """
        new_blocks = 0
        removed_blocks = 0

        for result in session.results:
            if not result.verdict_changed:
                continue
            if result.replay_verdict == ThreatVerdict.CONFIRMED:
                new_blocks += 1
            if result.original_verdict == ThreatVerdict.CONFIRMED:
                removed_blocks += 1

        return {
            "total_replayed": session.total_alerts,
            "verdict_changes": session.verdict_changes,
            "new_blocks": new_blocks,
            "removed_blocks": removed_blocks,
            "change_rate": (
                session.verdict_changes / session.total_alerts if session.total_alerts > 0 else 0.0
            ),
        }
