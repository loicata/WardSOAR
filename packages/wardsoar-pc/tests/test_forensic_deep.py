"""Tests for the deep forensic analysis pipeline (Phase 6).

Covers each analysis stage independently plus the end-to-end
:class:`DeepAnalysisOrchestrator`. The Opus call is always mocked —
we want deterministic test runs, not real API spend.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.pc.forensic.attack_mapper import AttackMapper, TechniqueMatch
from wardsoar.pc.forensic.deep_orchestrator import DeepAnalysisOrchestrator
from wardsoar.pc.forensic.export import DeepReportExporter, default_zip_name
from wardsoar.pc.forensic.ioc_extractor import IocExtractor, to_csv, to_stix_bundle
from wardsoar.pc.forensic.manifest import ForensicManifest, ManifestEntry
from wardsoar.pc.forensic.report_pdf import build_report_pdf
from wardsoar.pc.forensic.storage import ProtectedEvidenceStorage
from wardsoar.pc.forensic.timeline import TimelineBuilder, to_plaso_csv
from wardsoar.core.models import (
    DecisionRecord,
    ForensicResult,
    IPReputation,
    NetworkContext,
    ResponseAction,
    BlockAction,
    SuricataAlert,
    SuricataAlertSeverity,
    SysmonEvent,
    ThreatAnalysis,
    ThreatVerdict,
    VirusTotalResult,
)

# ---------------------------------------------------------------------------
# Helpers — shared fixtures
# ---------------------------------------------------------------------------


def _make_alert() -> SuricataAlert:
    return SuricataAlert(
        timestamp=datetime(2026, 4, 19, 22, 0, 0, tzinfo=timezone.utc),
        src_ip="185.199.108.153",
        src_port=55555,
        dest_ip="192.168.2.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET SCAN Potential SSH Scan",
        alert_signature_id=2024897,
        alert_category="Attempted Reconnaissance",
        alert_severity=SuricataAlertSeverity.HIGH,
    )


def _make_record() -> DecisionRecord:
    """A richly-populated record used across extractor tests."""
    alert = _make_alert()
    net = NetworkContext(
        ip_reputation=IPReputation(
            ip="185.199.108.153", is_known_malicious=True, sources=["AbuseIPDB"]
        ),
        dns_cache=[{"raw": "evil.example.com resolved 185.199.108.153"}],
        arp_cache=[{"raw": "185.199.108.153 00:11:22:33:44:55 ether"}],
        active_connections=[{"remote_ip": "198.51.100.9", "remote_port": 80}],
    )
    fr = ForensicResult(
        suspect_processes=[
            {
                "pid": 1234,
                "name": "powershell.exe",
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "cmdline": "powershell -EncodedCommand AAAA",
            }
        ],
        suspicious_files=[
            {"path": r"C:\Users\test\Downloads\malware.exe", "size": 1024, "modified": 1.7e9}
        ],
        sysmon_events=[
            SysmonEvent(
                event_id=1,
                timestamp=datetime(2026, 4, 19, 21, 59, 50, tzinfo=timezone.utc),
                description="PowerShell execution detected: visit https://bad.example.com",
            )
        ],
        windows_events=[
            {"Id": 4688, "TimeCreated": "2026-04-19T21:59:55", "Message": "Process creation"}
        ],
    )
    vt = VirusTotalResult(
        file_hash="a" * 64,
        file_name="malware.exe",
        detection_count=50,
        total_engines=70,
        detection_ratio=50 / 70,
        is_malicious=True,
        threat_labels=["trojan.downloader"],
        lookup_type="hash",
    )
    analysis = ThreatAnalysis(
        verdict=ThreatVerdict.CONFIRMED,
        confidence=0.92,
        reasoning="Encoded PowerShell command downloading from a malicious IP.",
        recommended_actions=["block_ip"],
        ioc_summary="SID 2024897, IP 185.199.108.153",
    )
    action = ResponseAction(
        action_type=BlockAction.IP_BLOCK,
        target_ip="185.199.108.153",
        block_duration_hours=24,
        success=True,
        executed_at=datetime(2026, 4, 19, 22, 0, 5, tzinfo=timezone.utc),
    )
    return DecisionRecord(
        record_id="deep-test-1",
        timestamp=alert.timestamp,
        alert=alert,
        network_context=net,
        forensic_result=fr,
        virustotal_results=[vt],
        analysis=analysis,
        actions_taken=[action],
    )


# ===========================================================================
# IOC EXTRACTOR
# ===========================================================================


class TestIocExtractor:
    """Observables are normalised, deduplicated and tagged with their source."""

    def test_extracts_expected_types(self) -> None:
        extractor = IocExtractor()
        observables = extractor.extract(_make_record())
        types = {o["type"] for o in observables}

        # Public IPs are kept, private IPs dropped (include_private_ips=False).
        ip_values = {o.get("value") for o in observables if o["type"] in ("ipv4-addr", "ipv6-addr")}
        assert "185.199.108.153" in ip_values
        assert "192.168.2.100" not in ip_values

        # We expect at least the IP + network-traffic + a file from VT.
        assert "ipv4-addr" in types
        assert "network-traffic" in types
        assert "file" in types

        # The VT hash made it through.
        file_hashes = {
            (o.get("hashes") or {}).get("SHA-256") for o in observables if o["type"] == "file"
        }
        assert "a" * 64 in file_hashes

    def test_dedup_is_stable(self) -> None:
        extractor = IocExtractor()
        observables = extractor.extract(_make_record())
        # URL "https://bad.example.com" comes from Sysmon message + is unique.
        urls = [o["value"] for o in observables if o["type"] == "url"]
        assert urls.count("https://bad.example.com") <= 1

    def test_stix_bundle_shape(self) -> None:
        bundle = to_stix_bundle(IocExtractor().extract(_make_record()))
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert isinstance(bundle["objects"], list)

    def test_csv_non_empty(self) -> None:
        csv = to_csv(IocExtractor().extract(_make_record()))
        assert csv.startswith("type,value,source")
        assert "185.199.108.153" in csv


# ===========================================================================
# TIMELINE BUILDER
# ===========================================================================


class TestTimelineBuilder:
    """Timeline rows are sorted, typed, and include every evidence source."""

    def test_sorted_by_timestamp(self) -> None:
        entries = TimelineBuilder().build(_make_record())
        timestamps = [e.timestamp_utc for e in entries]
        assert timestamps == sorted(timestamps)

    def test_includes_each_source(self) -> None:
        sources = {e.source for e in TimelineBuilder().build(_make_record())}
        # Alert, sysmon, windows_event, process, file, responder.
        assert {"alert", "sysmon", "windows_event", "process", "file", "responder"} <= sources

    def test_plaso_csv_has_header_and_rows(self) -> None:
        entries = TimelineBuilder().build(_make_record())
        csv = to_plaso_csv(entries)
        lines = csv.strip().splitlines()
        assert "datetime,timestamp_desc" in lines[0]
        assert len(lines) >= len(entries)  # header + one line per entry


# ===========================================================================
# ATT&CK MAPPER
# ===========================================================================


class TestAttackMapper:
    """Keyword rules produce the expected technique IDs."""

    def test_powershell_execution_matches(self) -> None:
        matches = AttackMapper().map_record(_make_record())
        ids = {m.technique_id for m in matches}
        # Encoded PowerShell → T1059.001.
        assert "T1059.001" in ids

    def test_scan_matches(self) -> None:
        # Our alert signature is "ET SCAN Potential SSH Scan" → T1046.
        ids = {m.technique_id for m in AttackMapper().map_record(_make_record())}
        assert "T1046" in ids

    def test_confidence_bounded(self) -> None:
        for m in AttackMapper().map_record(_make_record()):
            assert 0.0 <= m.confidence <= 1.0
            assert m.triggers, "every match must record which keywords hit"


# ===========================================================================
# PDF BUILDER
# ===========================================================================


class TestPdfBuilder:
    """Generated PDF is a real file starting with the PDF magic bytes."""

    def test_builds_pdf(self, tmp_path: Path) -> None:
        path = tmp_path / "report.pdf"
        build_report_pdf(
            path,
            title="TEST — 185.199.108.153",
            alert_summary={"Source IP": "185.199.108.153", "Signature": "ET SCAN"},
            executive_md="## Executive summary\nHigh-severity scan blocked.",
            technical_md="## Technical analysis\n- encoded powershell\n- vt hash match",
            ioc_rows=[{"type": "ipv4-addr", "value": "185.199.108.153", "_source": "alert"}],
            attack_rows=[
                {
                    "technique_id": "T1046",
                    "name": "Network Service Scanning",
                    "tactic": "Discovery",
                    "confidence": 0.6,
                    "triggers": ["scan", "et scan"],
                }
            ],
            timeline_rows=[
                {
                    "timestamp_utc": "2026-04-19T22:00:00+00:00",
                    "source": "alert",
                    "description": "Suricata alert",
                    "details": {},
                }
            ],
        )
        assert path.is_file()
        assert path.read_bytes().startswith(b"%PDF-")


# ===========================================================================
# EXPORT ZIP
# ===========================================================================


class TestExport:
    """ZIP bundler produces a ZIP with the expected entries."""

    def test_zip_contains_expected_files(self, tmp_path: Path) -> None:
        # Build a fake incident dir with one evidence file.
        incident_dir = tmp_path / "evidence" / "id" / "volatile"
        incident_dir.mkdir(parents=True)
        (incident_dir / "processes.json").write_bytes(b'{"pid": 1}')

        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        exporter = DeepReportExporter(storage=storage, version="0.5.0-test")

        manifest = ForensicManifest(alert_id="id", alert_summary={"src_ip": "185.199.108.153"})
        manifest.add_entry(
            ManifestEntry(
                name="processes.json",
                relative_path="processes.json",
                stored_path="processes.json",
                size_bytes=9,
                sha256="0" * 64,
                type="process_list",
                source="psutil",
            )
        )

        pdf = tmp_path / "REPORT.pdf"
        pdf.write_bytes(b"%PDF-1.4\ndummy")

        out_zip = tmp_path / default_zip_name("185.199.108.153")
        result = exporter.export(
            incident_dir=incident_dir,
            output_zip=out_zip,
            manifest=manifest,
            pdf_path=pdf,
            opus_report_md="# Executive\nbody\n",
            iocs_stix={"type": "bundle", "id": "bundle--x", "objects": []},
            iocs_csv="type,value,source\n",
            timeline_csv="datetime,timestamp_desc\n",
            timeline_json=[],
            attack_matches=[],
            include_evidence=True,
        )

        assert result.zip_path.is_file()
        with zipfile.ZipFile(result.zip_path) as zf:
            names = set(zf.namelist())
        expected = {
            "README.txt",
            "REPORT.pdf",
            "MANIFEST.json",
            "opus_report.md",
            "iocs.stix21.json",
            "iocs.csv",
            "timeline.csv",
            "timeline.json",
            "attack_mapping.json",
        }
        assert expected <= names
        # Evidence tree is bundled.
        assert any(n.startswith("evidence/") for n in names)


# ===========================================================================
# DEEP ORCHESTRATOR
# ===========================================================================


class TestDeepAnalysisOrchestrator:
    """End-to-end: quick manifest + record → full ZIP."""

    @pytest.mark.asyncio
    async def test_run_produces_zip_and_result(self, tmp_path: Path) -> None:
        # Prepare a minimal incident directory with a manifest-pointed file.
        incident_dir = tmp_path / "evidence" / "deep-test-1" / "volatile"
        incident_dir.mkdir(parents=True)
        (incident_dir / "processes.json").write_bytes(b'{"count": 0}')

        manifest = ForensicManifest(
            alert_id="deep-test-1",
            alert_summary={"src_ip": "185.199.108.153", "signature_id": 2024897},
        )
        manifest.add_entry(
            ManifestEntry(
                name="processes.json",
                relative_path="processes.json",
                stored_path="processes.json",
                size_bytes=13,
                sha256="x" * 64,
                type="process_list",
                source="psutil",
            )
        )

        # Mock the ThreatAnalyzer so no real API call happens.
        analyzer = MagicMock()
        analyzer.deep_analyze = AsyncMock(
            return_value=(
                "# Executive summary\nThe host was targeted by a SSH scan.\n\n"
                "## Technical analysis\n- scan\n- encoded powershell\n"
            )
        )

        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        orch = DeepAnalysisOrchestrator(
            analyzer=analyzer,
            storage=storage,
            export_root=tmp_path / "reports",
        )

        result = await orch.run(
            record=_make_record(),
            incident_dir=incident_dir,
            manifest=manifest,
            include_evidence_in_zip=False,
        )

        assert result.zip_path is not None
        assert result.zip_path.is_file()
        assert result.ioc_count > 0
        assert result.technique_count >= 1
        assert result.timeline_entries >= 1
        assert result.opus_report_md.startswith("# Executive summary")

        # Confirm the ZIP contents.
        with zipfile.ZipFile(result.zip_path) as zf:
            names = set(zf.namelist())
            assert "REPORT.pdf" in names
            assert "MANIFEST.json" in names
            manifest_in_zip = json.loads(zf.read("MANIFEST.json").decode("utf-8"))
            assert manifest_in_zip["alert_id"] == "deep-test-1"

    @pytest.mark.asyncio
    async def test_opus_failure_does_not_crash(self, tmp_path: Path) -> None:
        """Opus returning '' must fall back to a canned executive summary."""
        incident_dir = tmp_path / "evidence" / "id" / "volatile"
        incident_dir.mkdir(parents=True)

        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        analyzer = MagicMock()
        analyzer.deep_analyze = AsyncMock(return_value="")

        orch = DeepAnalysisOrchestrator(
            analyzer=analyzer,
            storage=storage,
            export_root=tmp_path / "reports",
        )
        manifest = ForensicManifest(alert_id="id")
        result = await orch.run(
            record=_make_record(),
            incident_dir=incident_dir,
            manifest=manifest,
            include_evidence_in_zip=False,
        )
        assert result.zip_path is not None
        assert any("Opus" in w for w in result.warnings)


# ===========================================================================
# Minor: ensure BlockAction + TechniqueMatch are importable (smoke)
# ===========================================================================


def test_imports_smoke() -> None:
    assert TechniqueMatch is not None
    assert BlockAction is not None
