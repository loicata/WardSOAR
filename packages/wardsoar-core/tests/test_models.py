"""Tests for WardSOAR data models.

Covers: enums, Pydantic model construction, validation,
serialization, default values, and forward references.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from wardsoar.core.models import (
    BlockAction,
    DecisionRecord,
    DivergenceFindings,
    ForensicResult,
    IPReputation,
    NetworkContext,
    ResponseAction,
    SourceCorroboration,
    SuricataAlert,
    SuricataAlertSeverity,
    SysmonEvent,
    ThreatAnalysis,
    ThreatVerdict,
    VirusTotalResult,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_timestamp() -> datetime:
    """Return a fixed UTC timestamp for reproducible tests."""
    return datetime(2026, 3, 15, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture()
def sample_alert(sample_timestamp: datetime) -> SuricataAlert:
    """Return a minimal valid SuricataAlert."""
    return SuricataAlert(
        timestamp=sample_timestamp,
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Known Malicious Domain",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestSuricataAlertSeverity:
    """Tests for SuricataAlertSeverity enum."""

    def test_severity_values(self) -> None:
        assert SuricataAlertSeverity.HIGH == 1
        assert SuricataAlertSeverity.MEDIUM == 2
        assert SuricataAlertSeverity.LOW == 3

    def test_severity_is_int(self) -> None:
        assert isinstance(SuricataAlertSeverity.HIGH, int)


class TestThreatVerdict:
    """Tests for ThreatVerdict enum."""

    def test_verdict_values(self) -> None:
        assert ThreatVerdict.CONFIRMED == "confirmed"
        assert ThreatVerdict.SUSPICIOUS == "suspicious"
        assert ThreatVerdict.BENIGN == "benign"
        assert ThreatVerdict.INCONCLUSIVE == "inconclusive"

    def test_verdict_is_str(self) -> None:
        assert isinstance(ThreatVerdict.CONFIRMED, str)


class TestBlockAction:
    """Tests for BlockAction enum."""

    def test_action_values(self) -> None:
        assert BlockAction.IP_BLOCK == "ip_block"
        assert BlockAction.IP_PORT_BLOCK == "ip_port_block"
        assert BlockAction.PROCESS_KILL == "process_kill"
        assert BlockAction.NONE == "none"


# ---------------------------------------------------------------------------
# SuricataAlert tests
# ---------------------------------------------------------------------------


class TestSuricataAlert:
    """Tests for SuricataAlert model."""

    def test_construction_minimal(self, sample_alert: SuricataAlert) -> None:
        assert sample_alert.src_ip == "10.0.0.1"
        assert sample_alert.dest_port == 443
        assert sample_alert.alert_severity == SuricataAlertSeverity.HIGH

    def test_default_values(self, sample_alert: SuricataAlert) -> None:
        assert sample_alert.alert_category == ""
        assert sample_alert.alert_action == "allowed"
        assert sample_alert.payload is None
        assert sample_alert.flow_id is None
        assert sample_alert.raw_event == {}

    def test_with_optional_fields(self, sample_timestamp: datetime) -> None:
        alert = SuricataAlert(
            timestamp=sample_timestamp,
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="192.168.1.100",
            dest_port=443,
            proto="TCP",
            alert_signature="Test",
            alert_signature_id=1000,
            alert_severity=SuricataAlertSeverity.LOW,
            alert_category="Misc Activity",
            payload="dGVzdA==",
            flow_id=123456789,
            raw_event={"key": "value"},
        )
        assert alert.alert_category == "Misc Activity"
        assert alert.payload == "dGVzdA=="
        assert alert.flow_id == 123456789
        assert alert.raw_event == {"key": "value"}

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            SuricataAlert(  # type: ignore[call-arg]
                timestamp=datetime.now(timezone.utc),
                src_ip="10.0.0.1",
                # missing src_port and other required fields
            )

    def test_serialization_roundtrip(self, sample_alert: SuricataAlert) -> None:
        json_str = sample_alert.model_dump_json()
        restored = SuricataAlert.model_validate_json(json_str)
        assert restored == sample_alert


# ---------------------------------------------------------------------------
# IPReputation tests
# ---------------------------------------------------------------------------


class TestIPReputation:
    """Tests for IPReputation model."""

    def test_construction(self) -> None:
        rep = IPReputation(ip="1.2.3.4")
        assert rep.ip == "1.2.3.4"
        assert rep.is_known_malicious is False
        assert rep.sources == []

    def test_with_scores(self) -> None:
        rep = IPReputation(
            ip="1.2.3.4",
            abuseipdb_score=95,
            virustotal_detections=12,
            is_known_malicious=True,
            sources=["abuseipdb", "virustotal"],
        )
        assert rep.abuseipdb_score == 95
        assert rep.is_known_malicious is True
        assert len(rep.sources) == 2


# ---------------------------------------------------------------------------
# NetworkContext tests
# ---------------------------------------------------------------------------


class TestNetworkContext:
    """Tests for NetworkContext model with forward reference to IPReputation."""

    def test_empty_construction(self) -> None:
        ctx = NetworkContext()
        assert ctx.active_connections == []
        assert ctx.dns_cache == []
        assert ctx.arp_cache == []
        assert ctx.related_alerts == []
        assert ctx.ip_reputation is None

    def test_with_ip_reputation(self) -> None:
        rep = IPReputation(ip="1.2.3.4", is_known_malicious=True)
        ctx = NetworkContext(ip_reputation=rep)
        assert ctx.ip_reputation is not None
        assert ctx.ip_reputation.ip == "1.2.3.4"

    def test_with_related_alerts(self, sample_alert: SuricataAlert) -> None:
        ctx = NetworkContext(related_alerts=[sample_alert])
        assert len(ctx.related_alerts) == 1
        assert ctx.related_alerts[0].src_ip == "10.0.0.1"

    def test_serialization_roundtrip(self) -> None:
        rep = IPReputation(ip="1.2.3.4")
        ctx = NetworkContext(
            active_connections=[{"local": "10.0.0.1:443", "remote": "1.2.3.4:54321"}],
            ip_reputation=rep,
        )
        json_str = ctx.model_dump_json()
        restored = NetworkContext.model_validate_json(json_str)
        assert restored.ip_reputation is not None
        assert restored.ip_reputation.ip == "1.2.3.4"


# ---------------------------------------------------------------------------
# SysmonEvent tests
# ---------------------------------------------------------------------------


class TestSysmonEvent:
    """Tests for SysmonEvent model."""

    def test_construction(self, sample_timestamp: datetime) -> None:
        event = SysmonEvent(
            event_id=3,
            timestamp=sample_timestamp,
            description="Network connection detected",
            process_name="chrome.exe",
            destination_ip="1.2.3.4",
            destination_port=443,
        )
        assert event.event_id == 3
        assert event.process_name == "chrome.exe"

    def test_defaults(self, sample_timestamp: datetime) -> None:
        event = SysmonEvent(
            event_id=1,
            timestamp=sample_timestamp,
            description="Process created",
        )
        assert event.process_name is None
        assert event.file_hash is None
        assert event.raw_event == {}


# ---------------------------------------------------------------------------
# ForensicResult tests
# ---------------------------------------------------------------------------


class TestForensicResult:
    """Tests for ForensicResult model."""

    def test_empty_construction(self) -> None:
        result = ForensicResult()
        assert result.suspect_processes == []
        assert result.sysmon_events == []
        assert result.suspicious_files == []
        assert result.registry_anomalies == []
        assert result.windows_events == []
        assert result.process_tree == []


# ---------------------------------------------------------------------------
# VirusTotalResult tests
# ---------------------------------------------------------------------------


class TestVirusTotalResult:
    """Tests for VirusTotalResult model."""

    def test_construction(self) -> None:
        vt = VirusTotalResult(
            file_hash="abc123",
            detection_count=5,
            total_engines=70,
            detection_ratio=5 / 70,
            is_malicious=True,
            threat_labels=["trojan", "backdoor"],
        )
        assert vt.is_malicious is True
        assert len(vt.threat_labels) == 2

    def test_defaults(self) -> None:
        vt = VirusTotalResult(file_hash="abc123")
        assert vt.detection_count == 0
        assert vt.is_malicious is False
        assert vt.lookup_type == "hash"


# ---------------------------------------------------------------------------
# ThreatAnalysis tests
# ---------------------------------------------------------------------------


class TestThreatAnalysis:
    """Tests for ThreatAnalysis model with confidence constraints."""

    def test_valid_construction(self) -> None:
        analysis = ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.85,
            reasoning="Strong IOC match",
        )
        assert analysis.verdict == ThreatVerdict.CONFIRMED
        assert analysis.confidence == 0.85

    def test_confidence_at_boundaries(self) -> None:
        low = ThreatAnalysis(
            verdict=ThreatVerdict.BENIGN,
            confidence=0.0,
            reasoning="No indicators",
        )
        high = ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=1.0,
            reasoning="Full match",
        )
        assert low.confidence == 0.0
        assert high.confidence == 1.0

    def test_confidence_below_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatAnalysis(
                verdict=ThreatVerdict.BENIGN,
                confidence=-0.1,
                reasoning="Invalid",
            )

    def test_confidence_above_one_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatAnalysis(
                verdict=ThreatVerdict.CONFIRMED,
                confidence=1.1,
                reasoning="Invalid",
            )

    def test_defaults(self) -> None:
        analysis = ThreatAnalysis(
            verdict=ThreatVerdict.INCONCLUSIVE,
            confidence=0.5,
            reasoning="Uncertain",
        )
        assert analysis.recommended_actions == []
        assert analysis.ioc_summary == ""
        assert analysis.false_positive_indicators == []


# ---------------------------------------------------------------------------
# ResponseAction tests
# ---------------------------------------------------------------------------


class TestResponseAction:
    """Tests for ResponseAction model."""

    def test_construction(self) -> None:
        action = ResponseAction(
            action_type=BlockAction.IP_BLOCK,
            target_ip="1.2.3.4",
            success=True,
        )
        assert action.action_type == BlockAction.IP_BLOCK
        assert action.block_duration_hours == 24

    def test_none_action(self) -> None:
        action = ResponseAction(action_type=BlockAction.NONE)
        assert action.target_ip is None
        assert action.success is False


# ---------------------------------------------------------------------------
# DecisionRecord tests
# ---------------------------------------------------------------------------


class TestDecisionRecord:
    """Tests for DecisionRecord model (full audit trail)."""

    def test_construction(self, sample_alert: SuricataAlert, sample_timestamp: datetime) -> None:
        record = DecisionRecord(
            record_id="rec-001",
            timestamp=sample_timestamp,
            alert=sample_alert,
        )
        assert record.record_id == "rec-001"
        assert record.network_context is None
        assert record.analysis is None
        assert record.actions_taken == []
        assert record.pipeline_duration_ms == 0
        assert record.error is None

    def test_full_record_serialization(
        self, sample_alert: SuricataAlert, sample_timestamp: datetime
    ) -> None:
        analysis = ThreatAnalysis(
            verdict=ThreatVerdict.CONFIRMED,
            confidence=0.9,
            reasoning="Malicious traffic",
        )
        action = ResponseAction(
            action_type=BlockAction.IP_BLOCK,
            target_ip="10.0.0.1",
            success=True,
            executed_at=sample_timestamp,
        )
        record = DecisionRecord(
            record_id="rec-002",
            timestamp=sample_timestamp,
            alert=sample_alert,
            analysis=analysis,
            actions_taken=[action],
            pipeline_duration_ms=1500,
        )
        json_str = record.model_dump_json()
        restored = DecisionRecord.model_validate_json(json_str)
        assert restored.record_id == "rec-002"
        assert restored.analysis is not None
        assert restored.analysis.verdict == ThreatVerdict.CONFIRMED
        assert len(restored.actions_taken) == 1
        assert restored.actions_taken[0].success is True


# ---------------------------------------------------------------------------
# Dual-Suricata corroboration (configs 3 and 5)
# ---------------------------------------------------------------------------


class TestSourceCorroboration:
    """The 6-state enum tagging dual-source alerts.

    See ``project_dual_suricata_sync.md`` for the doctrine. The
    invariants below pin the lifecycle so a future refactor cannot
    accidentally rename / reorder values that downstream code parses
    by string match.
    """

    def test_string_values_are_stable(self) -> None:
        """Downstream code (logs, JSON, UI tags) parses these strings.
        Renaming them is a breaking change."""
        assert SourceCorroboration.SINGLE_SOURCE.value == "single_source"
        assert SourceCorroboration.MATCH_PENDING.value == "match_pending"
        assert SourceCorroboration.DIVERGENCE_PENDING.value == "divergence_pending"
        assert SourceCorroboration.MATCH_CONFIRMED.value == "match_confirmed"
        assert SourceCorroboration.DIVERGENCE_A.value == "divergence_a"
        assert SourceCorroboration.DIVERGENCE_B.value == "divergence_b"

    def test_six_states_exhaustively(self) -> None:
        """All six lifecycle states are exposed — no more, no less."""
        states = {member.value for member in SourceCorroboration}
        assert states == {
            "single_source",
            "match_pending",
            "divergence_pending",
            "match_confirmed",
            "divergence_a",
            "divergence_b",
        }

    def test_is_str_enum(self) -> None:
        """The value is the string literal — important for JSON
        serialisation and string comparisons in log filters."""
        assert SourceCorroboration.MATCH_CONFIRMED == "match_confirmed"
        assert isinstance(SourceCorroboration.MATCH_CONFIRMED.value, str)


class TestDivergenceFindings:
    """Output of the ``DivergenceInvestigator`` for divergent alerts."""

    def test_construction_with_all_defaults(self) -> None:
        """The dataclass is fully default-constructible — useful when
        the investigator skips a divergent event (e.g. all checks
        timed out) and we still need an attached object."""
        findings = DivergenceFindings()
        assert findings.checks_run == []
        assert findings.is_explained is False
        assert findings.explanation == "unexplained"
        assert findings.snapshot_summary == {}
        assert findings.sysmon_correlation == []
        assert findings.suricata_local_state == "unknown"
        assert findings.is_loopback is False
        assert findings.is_vpn is False
        assert findings.is_lan_only is False

    def test_construction_with_explanation_loopback(self) -> None:
        """Loopback traffic is the canonical "explained" divergence —
        local Suricata sees it, external can't (by topology). Verdict
        bumper must NOT bump these."""
        findings = DivergenceFindings(
            checks_run=["loopback", "snapshot"],
            is_explained=True,
            explanation="loopback_traffic",
            is_loopback=True,
        )
        assert findings.is_explained is True
        assert findings.explanation == "loopback_traffic"
        assert findings.is_loopback is True

    def test_construction_with_explanation_suricata_local_dead(self) -> None:
        """When local Suricata is dead, the explanation is "explained"
        in the sense that we know why — but the verdict bumper STILL
        bumps because a dead local Suricata is a high-signal anomaly
        (the operator must notice and react)."""
        findings = DivergenceFindings(
            checks_run=["suricata_alive"],
            is_explained=True,
            explanation="suricata_local_dead",
            suricata_local_state="dead",
        )
        assert findings.is_explained is True
        assert findings.explanation == "suricata_local_dead"
        assert findings.suricata_local_state == "dead"

    def test_construction_unexplained(self) -> None:
        """Unexplained divergence — every check ran but no
        topological / known-failure cause was found. This is the case
        that bumps the verdict in the doctrine (Q3 β nuanced)."""
        findings = DivergenceFindings(
            checks_run=["snapshot", "sysmon", "suricata_alive", "loopback", "vpn", "lan_only"],
            is_explained=False,
            explanation="unexplained",
        )
        assert findings.is_explained is False
        assert findings.explanation == "unexplained"

    def test_serialization_roundtrip(self) -> None:
        """Findings must survive JSON serialisation for the forensic
        log + dashboard widget filtering."""
        original = DivergenceFindings(
            checks_run=["snapshot", "loopback"],
            is_explained=True,
            explanation="loopback_traffic",
            snapshot_summary={"pids": [1234, 5678]},
            sysmon_correlation=[{"event_id": 3, "pid": 1234}],
            suricata_local_state="running",
            is_loopback=True,
        )
        json_str = original.model_dump_json()
        restored = DivergenceFindings.model_validate_json(json_str)
        assert restored == original

    def test_default_explanation_token_matches_unexplained(self) -> None:
        """The default ``"unexplained"`` token is what the verdict
        bumper triggers on. Renaming it to something else breaks the
        bumper. Pin the literal so renames are caught here."""
        findings = DivergenceFindings()
        assert findings.explanation == "unexplained"
