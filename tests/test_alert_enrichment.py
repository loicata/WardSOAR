"""Tests for ``src.alert_enrichment``.

The enrichment module builds the rich payload consumed by the
v0.9.0 Alert Detail view. Two surfaces to cover:

* ``serialise_decision_record`` — round-trips a full DecisionRecord
  through JSON without losing enum values, datetimes, or nested
  models, and attaches an inferred pipeline trace.
* ``infer_pipeline_trace`` / ``infer_filter_trace`` — builds the
  13-row stage trace the detail view renders.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.alert_enrichment import (
    PIPELINE_STAGES,
    StageTrace,
    build_filtered_enriched,
    infer_filter_trace,
    infer_pipeline_trace,
    serialise_decision_record,
)
from src.models import (
    BlockAction,
    DecisionRecord,
    IPReputation,
    NetworkContext,
    ResponseAction,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
)


def _make_alert(severity: int = 1) -> SuricataAlert:
    return SuricataAlert(
        timestamp=datetime(2026, 4, 21, 15, 42, 11, tzinfo=timezone.utc),
        src_ip="51.161.42.18",
        src_port=51203,
        dest_ip="192.168.2.100",
        dest_port=22,
        proto="TCP",
        alert_signature="ET SCAN SSH Brute Force Attempt",
        alert_signature_id=2003067,
        alert_severity=SuricataAlertSeverity(severity),
        alert_category="Attempted Administrator Privilege Gain",
    )


def _make_decision_record(
    *,
    with_network: bool = True,
    with_analysis: bool = True,
    analysis_confidence: float = 0.97,
    with_block: bool = True,
    severity: int = 1,
) -> DecisionRecord:
    alert = _make_alert(severity=severity)
    network = None
    if with_network:
        network = NetworkContext(
            active_connections=[{"src": "x", "dst": "y"}],
            dns_cache=[{"name": "foo", "ip": "1.2.3.4"}, {"name": "bar", "ip": "5.6.7.8"}],
            arp_cache=[],
            related_alerts=[],
            ip_reputation=IPReputation(
                ip="51.161.42.18",
                abuseipdb_score=91,
                virustotal_detections=62,
                is_known_malicious=True,
                sources=["abuseipdb", "virustotal"],
            ),
        )
    analysis = None
    if with_analysis:
        analysis = ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=analysis_confidence,
            reasoning="This is a clear SSH brute-force attack …",
            recommended_actions=["ip_block"],
        )
    actions: list[ResponseAction] = []
    if with_block:
        actions.append(
            ResponseAction(
                action_type=BlockAction.IP_BLOCK,
                target_ip="51.161.42.18",
                block_duration_hours=24,
                success=True,
                pfsense_rule_id="blocklist",
                executed_at=datetime(2026, 4, 21, 15, 42, 19, tzinfo=timezone.utc),
            )
        )
    return DecisionRecord(
        record_id="f209-b8d7-a5c6-2e4f",
        timestamp=datetime(2026, 4, 21, 15, 42, 11, tzinfo=timezone.utc),
        alert=alert,
        network_context=network,
        analysis=analysis,
        actions_taken=actions,
        pipeline_duration_ms=8312,
    )


# ---------------------------------------------------------------------------
# infer_pipeline_trace — the happy path
# ---------------------------------------------------------------------------


class TestInferPipelineTrace:
    def test_exactly_thirteen_stages(self) -> None:
        """The UI column header says "13 steps" — it must always be 13,
        regardless of which DecisionRecord fields are populated."""
        trace = infer_pipeline_trace(_make_decision_record())
        assert len(trace) == 13
        # Names must match the canonical ordering used by the UI header.
        names = [t.name for t in trace]
        assert tuple(names) == PIPELINE_STAGES

    def test_full_pipeline_everything_passed(self) -> None:
        trace = infer_pipeline_trace(_make_decision_record())
        by_name = {t.name: t for t in trace}
        # Filter through Log should be 'passed' when a block happened.
        assert by_name["Filter"].outcome == "passed"
        assert by_name["Collector"].outcome == "passed"
        assert by_name["VirusTotal"].outcome == "skipped"  # no VT results provided
        assert by_name["Analyzer"].outcome == "passed"
        assert by_name["Responder"].outcome == "passed"
        assert by_name["pfSense API"].outcome == "passed"
        assert by_name["Notifier"].outcome == "passed"
        assert by_name["Log"].outcome == "passed"

    def test_confirmer_skipped_when_analyzer_confident(self) -> None:
        """High-confidence Analyzer (≥ 0.90) means Confirmer doesn't run.
        The trace must explicitly report that it was skipped AND the
        explanation must justify why (threshold comparison)."""
        trace = infer_pipeline_trace(_make_decision_record(analysis_confidence=0.95))
        confirmer = next(t for t in trace if t.name == "Confirmer")
        assert confirmer.outcome == "skipped"
        # Detail carries the actual confidence; explanation justifies
        # against the 90 % threshold.
        assert "95" in confirmer.detail
        assert "90" in confirmer.explanation

    def test_confirmer_runs_on_borderline_confidence(self) -> None:
        trace = infer_pipeline_trace(_make_decision_record(analysis_confidence=0.72))
        confirmer = next(t for t in trace if t.name == "Confirmer")
        assert confirmer.outcome == "passed"
        # The pedagogical explanation mentions the "second opinion"
        # concept; the short detail says the outcome plainly.
        combined = (confirmer.detail + " " + confirmer.explanation).lower()
        assert "second" in combined or "2nd" in combined
        assert "borderline" in combined or "90" in combined

    def test_prescorer_filtered_when_no_enrichment(self) -> None:
        """If the pipeline stopped at PreScorer (score below threshold),
        network_context is None. The trace must reflect that and show
        subsequent stages as skipped, not passed."""
        trace = infer_pipeline_trace(
            _make_decision_record(with_network=False, with_analysis=False, with_block=False)
        )
        by_name = {t.name: t for t in trace}
        assert by_name["PreScorer"].outcome == "filtered"
        assert by_name["Collector"].outcome == "skipped"
        assert by_name["Analyzer"].outcome == "skipped"
        assert by_name["Responder"].outcome == "skipped"
        # Log still runs — the alert IS persisted as a low-score.
        assert by_name["Log"].outcome == "passed"

    def test_pfsense_api_failure_marked_failed(self) -> None:
        """A block_action with success=False must surface as failed
        in the trace so the operator sees the block didn't land."""
        record = _make_decision_record()
        record.actions_taken[0] = ResponseAction(
            action_type=BlockAction.IP_BLOCK,
            target_ip="51.161.42.18",
            success=False,
            error_message="SSH timeout",
        )
        trace = infer_pipeline_trace(record)
        pfsense = next(t for t in trace if t.name == "pfSense API")
        assert pfsense.outcome == "failed"
        assert "SSH timeout" in pfsense.detail

    def test_error_on_record_marks_log_failed(self) -> None:
        """A pipeline-level error must be visible in the trace — the
        ``Log`` row is the last one and we surface the error there so
        the operator sees it at the bottom of the trace."""
        record = _make_decision_record()
        record.error = "Opus timeout after 30s"
        trace = infer_pipeline_trace(record)
        log_row = next(t for t in trace if t.name == "Log")
        assert log_row.outcome == "failed"
        assert "Opus timeout" in log_row.detail


# ---------------------------------------------------------------------------
# infer_filter_trace — Step-1-filtered alerts
# ---------------------------------------------------------------------------


class TestInferFilterTrace:
    def test_thirteen_stages_with_filter_first(self) -> None:
        trace = infer_filter_trace("known false positive (SID 2210050)")
        assert len(trace) == 13
        assert trace[0].name == "Filter"
        assert trace[0].outcome == "filtered"
        assert "known false positive" in trace[0].detail

    def test_all_intermediate_stages_skipped(self) -> None:
        """Everything from Deduplicator to Notifier must be skipped —
        the pipeline bailed at Step 1. Only Log still runs (it's what
        persists the filtered record)."""
        trace = infer_filter_trace("reason")
        by_name = {t.name: t for t in trace}
        for name in (
            "Deduplicator",
            "Correlation",
            "PreScorer",
            "Collector",
            "VirusTotal",
            "Baseline",
            "Analyzer",
            "Confirmer",
            "Responder",
            "pfSense API",
            "Notifier",
        ):
            assert by_name[name].outcome == "skipped", name
        assert by_name["Log"].outcome == "passed"


# ---------------------------------------------------------------------------
# serialise_decision_record — JSON round-trip
# ---------------------------------------------------------------------------


class TestSerialiseDecisionRecord:
    def test_is_json_serialisable_verbatim(self) -> None:
        """Pydantic's model_dump(mode=\"json\") must produce output
        json.dumps accepts without needing ``default=str``. If this
        test regresses it means we re-introduced a non-JSON field
        (e.g. a raw datetime) and the Alerts history file will fail
        to re-load."""
        record = _make_decision_record()
        payload = serialise_decision_record(record)
        dumped = json.dumps(payload)  # must not raise
        # Round-trip: re-read produces the same shape.
        reloaded = json.loads(dumped)
        assert reloaded["record_id"] == record.record_id
        assert reloaded["analysis"]["verdict"] == "confirmed"
        assert reloaded["analysis"]["confidence"] == 0.97

    def test_includes_inferred_pipeline_trace(self) -> None:
        """The UI expects ``pipeline_trace`` as a sibling of the
        record fields so it doesn't have to re-run the inference."""
        record = _make_decision_record()
        payload = serialise_decision_record(record)
        assert "pipeline_trace" in payload
        trace = payload["pipeline_trace"]
        assert isinstance(trace, list)
        assert len(trace) == 13
        # Every entry is a plain dict (no dataclasses leak through).
        for entry in trace:
            assert set(entry) >= {"index", "name", "outcome", "detail"}


# ---------------------------------------------------------------------------
# build_filtered_enriched — filtered alerts
# ---------------------------------------------------------------------------


class TestFilterSourceDetection:
    """v0.9.2 — ``infer_filter_trace`` should identify WHICH stage
    actually filtered the alert (Filter / Deduplicator / Correlation
    / PreScorer) and produce a trace where the earlier stages are
    marked ``passed`` rather than all being lumped as "short-circuited
    at Filter". The operator then sees the correct story of how far
    the alert travelled before being dropped."""

    def test_filter_stage_identified_by_prefix(self) -> None:
        trace = infer_filter_trace("filter: known false positive (SID 2210050)")
        by_name = {t.name: t for t in trace}
        assert by_name["Filter"].outcome == "filtered"
        assert by_name["Deduplicator"].outcome == "skipped"
        assert by_name["PreScorer"].outcome == "skipped"

    def test_prescorer_stage_identified_by_prefix(self) -> None:
        """Regression for the v0.9.1 capture the operator reported: an
        alert filtered at the PreScorer showed every earlier stage as
        'short-circuited at Filter', which is misleading. v0.9.2 must
        show Filter/Deduplicator/Correlation as ``passed`` and mark
        PreScorer as the stage that filtered."""
        trace = infer_filter_trace("prescorer: score 10 below threshold 30")
        by_name = {t.name: t for t in trace}
        assert by_name["Filter"].outcome == "passed"
        assert by_name["Deduplicator"].outcome == "passed"
        assert by_name["Correlation"].outcome == "passed"
        assert by_name["PreScorer"].outcome == "filtered"
        assert "score 10 below threshold 30" in by_name["PreScorer"].detail
        # Everything after PreScorer is skipped.
        assert by_name["Collector"].outcome == "skipped"
        assert by_name["Analyzer"].outcome == "skipped"
        # Log still runs — it's how the alert got persisted.
        assert by_name["Log"].outcome == "passed"

    def test_dedup_stage_identified_by_prefix(self) -> None:
        trace = infer_filter_trace("dedup: grouped with existing alert")
        by_name = {t.name: t for t in trace}
        assert by_name["Filter"].outcome == "passed"
        assert by_name["Deduplicator"].outcome == "filtered"
        assert by_name["Correlation"].outcome == "skipped"

    def test_cache_stage_identified_by_prefix(self) -> None:
        trace = infer_filter_trace("cache: recent benign verdict")
        by_name = {t.name: t for t in trace}
        assert by_name["Filter"].outcome == "passed"
        assert by_name["Deduplicator"].outcome == "passed"
        assert by_name["Correlation"].outcome == "filtered"
        assert by_name["PreScorer"].outcome == "skipped"

    def test_unknown_prefix_falls_back_to_filter(self) -> None:
        """Defensive: a reason without a recognised prefix is treated
        as a Filter-stage decision (the safest fallback — we still
        show the reason, we just attribute it to the most common
        stage)."""
        trace = infer_filter_trace("unrecognised prefix: some reason")
        by_name = {t.name: t for t in trace}
        assert by_name["Filter"].outcome == "filtered"


class TestBuildFilteredEnriched:
    def test_has_minimal_fields_for_detail_view(self) -> None:
        alert = _make_alert()
        payload = build_filtered_enriched(alert, "SID 2210054 in FP list")

        assert payload["filtered"] is True
        assert payload["filter_reason"] == "SID 2210054 in FP list"
        # Raw alert preserved — the detail view shows src/dest/SID
        # even for suppressed alerts.
        assert payload["alert"]["src_ip"] == alert.src_ip
        assert payload["alert"]["alert_signature_id"] == alert.alert_signature_id
        # Trace present, 13 rows, Filter is the first and is 'filtered'.
        assert len(payload["pipeline_trace"]) == 13
        assert payload["pipeline_trace"][0]["name"] == "Filter"
        assert payload["pipeline_trace"][0]["outcome"] == "filtered"


class TestSpecificDetails:
    """v0.9.5 — every stage row carries an alert-specific paragraph
    rendered below the generic explanation. Exercise each path."""

    def test_filter_dismissal_quotes_yaml_meta(self) -> None:
        """Filter-dismissed alerts should quote the operator's YAML
        entry (signature_name, reason, added_date, review_date)."""
        alert = _make_alert(severity=3)
        alert_dict = alert.model_dump(mode="json")
        filter_meta = {
            "signature_id": 2003067,
            "signature_name": "ET SCAN SSH Brute Force Attempt",
            "reason": "Local Ansible bastion probing own fleet — benign",
            "added_date": "2026-03-14",
            "review_date": "2026-09-14",
        }
        trace = infer_filter_trace(
            "filter: known false positive (SID 2003067)",
            alert_dict=alert_dict,
            filter_meta=filter_meta,
        )
        filter_row = trace[0]
        assert filter_row.name == "Filter"
        assert filter_row.outcome == "filtered"
        assert "SID 2003067" in filter_row.specific_details
        assert "ET SCAN SSH Brute Force Attempt" in filter_row.specific_details
        assert "Local Ansible bastion" in filter_row.specific_details
        assert "2026-03-14" in filter_row.specific_details
        assert "2026-09-14" in filter_row.specific_details

    def test_filter_dismissal_without_meta_falls_back(self) -> None:
        """If filter_meta is missing (user overlay without reason),
        specific_details still mentions the SID but explicitly notes
        the absence of the operator reason."""
        alert = _make_alert()
        trace = infer_filter_trace(
            "filter: known false positive (SID 2003067)",
            alert_dict=alert.model_dump(mode="json"),
            filter_meta=None,
        )
        filter_row = trace[0]
        assert "SID 2003067" in filter_row.specific_details
        assert "no operator reason" in filter_row.specific_details.lower()

    def test_skipped_stages_explain_early_dismissal(self) -> None:
        """When the alert was dismissed at Filter, the 10 stages that
        did not run should carry a specific paragraph explaining
        WHICH earlier stage stopped them — not a generic N/A."""
        trace = infer_filter_trace("filter: known false positive (SID 2003067)")
        # Skip first (filter) and last (log); the 11 middle rows are
        # all skipped with a specific detail mentioning 'Filter'.
        for row in trace[1:-1]:
            assert row.outcome == "skipped"
            assert "already dismissed at the Filter stage" in row.specific_details

    def test_prescorer_filtered_attributes_correctly(self) -> None:
        """An alert dropped by PreScorer should mark stages 1..3 as
        passed, stage 4 as filtered, and stages 5..12 as skipped —
        each with a PreScorer-aware specific paragraph."""
        trace = infer_filter_trace(
            "prescorer: score 10 below threshold 30",
            alert_dict=_make_alert().model_dump(mode="json"),
        )
        # Stage 1-3 passed (ran before PreScorer cut the alert).
        for i in (0, 1, 2):
            assert trace[i].outcome == "passed"
            assert trace[i].specific_details  # non-empty
        # Stage 4 is the filtering stage.
        assert trace[3].name == "PreScorer"
        assert trace[3].outcome == "filtered"
        assert "score 10" in trace[3].specific_details.lower()
        # Stage 5-12 skipped, specific paragraph quotes the PreScorer.
        for row in trace[4:-1]:
            assert row.outcome == "skipped"
            assert "prescorer" in row.specific_details.lower()

    def test_analyzer_specific_quotes_full_opus_reasoning(self) -> None:
        """The Analyzer stage's specific paragraph must include the
        full Opus reasoning so the operator sees the decision chain
        without having to scroll to AI REASONING."""
        record = _make_decision_record(analysis_confidence=0.92)
        assert record.analysis is not None
        record.analysis.reasoning = (
            "This alert fired on a legitimate long-lived TLS connection "
            "to Anthropic's API. The Sysmon DNS query confirms the host "
            "resolves to api.anthropic.com. No attack indicators."
        )
        record.analysis.recommended_actions = ["none"]
        trace = infer_pipeline_trace(record)
        analyzer = next(t for t in trace if t.name == "Analyzer")
        assert analyzer.outcome == "passed"
        assert "BENIGN" in analyzer.specific_details or "CONFIRMED" in analyzer.specific_details
        assert "legitimate long-lived TLS connection" in analyzer.specific_details
        assert "api.anthropic.com" in analyzer.specific_details
        assert "Actions recommended by Opus" in analyzer.specific_details

    def test_responder_specific_shows_decision_inputs(self) -> None:
        """Responder's specific paragraph must list the 5 decision
        inputs (verdict, mode, whitelist, CDN allowlist, rate limit)
        so the operator understands which rails were active."""
        record = _make_decision_record(with_block=True)
        trace = infer_pipeline_trace(record)
        responder = next(t for t in trace if t.name == "Responder")
        assert responder.outcome == "passed"
        txt = responder.specific_details
        assert "Analyzer verdict" in txt
        assert "protection mode" in txt.lower()
        assert "whitelist" in txt.lower()
        assert "cdn allowlist" in txt.lower() or "cdn safe-list" in txt.lower()
        assert "rate limit" in txt.lower()

    def test_responder_noblock_branch_explains_which_rail_won(self) -> None:
        """When no block is installed despite a CONFIRMED verdict, the
        paragraph must list the overriding rails so the operator knows
        why."""
        record = _make_decision_record(with_block=False)
        assert record.analysis is not None
        assert record.analysis.verdict == ThreatVerdict.CONFIRMED
        trace = infer_pipeline_trace(record)
        responder = next(t for t in trace if t.name == "Responder")
        assert responder.outcome == "passed"
        assert "HOLD OFF" in responder.specific_details
        # The CONFIRMED/SUSPICIOUS branch mentions the safety rails.
        assert "safety rails" in responder.specific_details.lower()

    def test_build_filtered_enriched_carries_filter_meta(self) -> None:
        """The persisted ``_full`` dict should include filter_meta
        alongside the trace so the detail view has the YAML entry at
        hand without a second lookup."""
        alert = _make_alert()
        meta = {"signature_name": "X", "reason": "Y"}
        payload = build_filtered_enriched(
            alert,
            "filter: known false positive (SID 2003067)",
            filter_meta=meta,
        )
        assert payload["filter_meta"] == meta
        filter_row = payload["pipeline_trace"][0]
        assert "Y" in filter_row["specific_details"]


class TestDestIpEnrichment:
    """v0.15.0 \u2014 the ``_full`` payload can carry a second
    ``dest_ip_enrichment`` dict so the Alert Detail view renders
    ownership + reputation for the destination IP too.
    """

    def test_filtered_payload_carries_both_enrichments(self) -> None:
        alert = _make_alert()
        src_e = {"ip": "1.2.3.4", "identity": {"asn": 1}, "reputation": []}
        dst_e = {"ip": "5.6.7.8", "identity": {"asn": 2}, "reputation": []}
        payload = build_filtered_enriched(
            alert,
            "filter: known false positive (SID 2003067)",
            ip_enrichment=src_e,
            dest_ip_enrichment=dst_e,
        )
        assert payload["ip_enrichment"]["ip"] == "1.2.3.4"
        assert payload["dest_ip_enrichment"]["ip"] == "5.6.7.8"

    def test_filtered_payload_without_dest_omits_key(self) -> None:
        """Backward compat: alerts without a dest enrichment should
        not carry a ``dest_ip_enrichment`` key at all (the UI falls
        back to source-only rendering)."""
        alert = _make_alert()
        payload = build_filtered_enriched(
            alert,
            "filter: known false positive (SID 2003067)",
            ip_enrichment={"ip": "1.2.3.4"},
        )
        assert "ip_enrichment" in payload
        assert "dest_ip_enrichment" not in payload

    def test_decision_record_payload_carries_both(self) -> None:
        record = _make_decision_record(with_block=False)
        src_e = {"ip": record.alert.src_ip, "identity": {"asn": 1}}
        dst_e = {"ip": record.alert.dest_ip, "identity": {"asn": 2}}
        payload = serialise_decision_record(
            record,
            ip_enrichment=src_e,
            dest_ip_enrichment=dst_e,
        )
        assert payload["ip_enrichment"]["identity"]["asn"] == 1
        assert payload["dest_ip_enrichment"]["identity"]["asn"] == 2


def test_stagetrace_is_frozen() -> None:
    """StageTrace is intentionally immutable so a UI rendering pass
    cannot mutate a row on the fly."""
    import pytest as _pytest

    trace = StageTrace(1, "Filter", "passed", "ok")
    with _pytest.raises((AttributeError, TypeError, Exception)):
        trace.outcome = "failed"  # type: ignore[misc]
