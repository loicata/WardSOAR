"""Tests for WardSOAR forensic evidence package generator.

ForensicReport is CRITICAL (95% coverage). Key safety tests:
- No API keys in the archive
- All timestamps in UTC
- SHA-256 checksums present
- README is self-contained and in English
"""

import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.core.forensic_report import ForensicReportGenerator
from wardsoar.core.models import (
    BlockAction,
    DecisionRecord,
    ForensicResult,
    NetworkContext,
    ResponseAction,
    SuricataAlert,
    SuricataAlertSeverity,
    ThreatAnalysis,
    ThreatVerdict,
    VirusTotalResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_full_record() -> DecisionRecord:
    """Create a complete DecisionRecord with all evidence."""
    alert = SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
        src_ip="91.12.44.8",
        src_port=54321,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Known C2 Communication",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
        alert_category="A Network Trojan was Detected",
    )
    analysis = ThreatAnalysis(
        verdict=ThreatVerdict.CONFIRMED,
        confidence=0.92,
        reasoning="Strong IOC match with known C2 infrastructure",
        recommended_actions=["block_ip", "kill_process"],
        ioc_summary="C2 beacon to known malicious IP",
    )
    action = ResponseAction(
        action_type=BlockAction.IP_BLOCK,
        target_ip="91.12.44.8",
        success=True,
        block_duration_hours=24,
        executed_at=datetime(2026, 3, 15, 10, 30, 5, tzinfo=timezone.utc),
    )
    return DecisionRecord(
        record_id="rec-forensic-001",
        timestamp=datetime(2026, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
        alert=alert,
        network_context=NetworkContext(
            active_connections=[{"remote_ip": "91.12.44.8", "pid": 1234}],
        ),
        forensic_result=ForensicResult(
            suspect_processes=[{"pid": 1234, "name": "malware.exe"}],
        ),
        virustotal_results=[
            VirusTotalResult(
                file_hash="abc123def456",
                detection_count=15,
                total_engines=70,
                is_malicious=True,
                threat_labels=["trojan.generic"],
            ),
        ],
        analysis=analysis,
        actions_taken=[action],
        pipeline_duration_ms=1500,
    )


# ---------------------------------------------------------------------------
# _redact_config tests
# ---------------------------------------------------------------------------


class TestRedactConfig:
    """Tests for sensitive data redaction."""

    def test_redacts_api_keys(self) -> None:
        config = {"api_key": "sk-secret-123", "name": "test"}
        redacted = ForensicReportGenerator._redact_config(config)
        assert redacted["api_key"] == "[REDACTED]"
        assert redacted["name"] == "test"

    def test_redacts_password(self) -> None:
        config = {"password": "supersecret", "host": "smtp.test.com"}
        redacted = ForensicReportGenerator._redact_config(config)
        assert redacted["password"] == "[REDACTED]"

    def test_redacts_token(self) -> None:
        config = {"telegram_bot_token": "123:ABC", "chat_id": "456"}
        redacted = ForensicReportGenerator._redact_config(config)
        assert redacted["telegram_bot_token"] == "[REDACTED]"

    def test_redacts_secret(self) -> None:
        config = {"pfsense_api_secret": "secret123"}
        redacted = ForensicReportGenerator._redact_config(config)
        assert redacted["pfsense_api_secret"] == "[REDACTED]"

    def test_redacts_nested(self) -> None:
        config = {
            "outer": {
                "api_key": "nested-secret",
                "value": 42,
            }
        }
        redacted = ForensicReportGenerator._redact_config(config)
        assert redacted["outer"]["api_key"] == "[REDACTED]"
        assert redacted["outer"]["value"] == 42

    def test_empty_dict(self) -> None:
        assert ForensicReportGenerator._redact_config({}) == {}


# ---------------------------------------------------------------------------
# _compute_sha256 tests
# ---------------------------------------------------------------------------


class TestComputeSha256:
    """Tests for SHA-256 file hash computation."""

    def test_computes_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello", encoding="utf-8")
        h = ForensicReportGenerator._compute_sha256(f)
        assert len(h) == 64
        assert h.isalnum()


# ---------------------------------------------------------------------------
# generate tests
# ---------------------------------------------------------------------------


class TestGenerate:
    """Tests for ForensicReportGenerator.generate."""

    def test_generates_zip(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

    def test_zip_contains_readme(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert any("README.txt" in n for n in names)

    def test_zip_contains_checksums(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert any("CHECKSUMS.sha256" in n for n in names)

    def test_zip_contains_metadata(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert any("METADATA.json" in n for n in names)

    def test_zip_contains_evidence_directories(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            dirs_found = set()
            for name in names:
                parts = name.split("/")
                if len(parts) > 1:
                    dirs_found.add(parts[1] if parts[0] else parts[0])
            # Check at least some evidence dirs exist
            name_str = " ".join(names)
            assert "01_suricata_alert" in name_str
            assert "05_ai_analysis" in name_str

    def test_readme_in_english(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            readme_name = [n for n in zf.namelist() if "README.txt" in n][0]
            readme = zf.read(readme_name).decode("utf-8")
            assert "FORENSIC REPORT" in readme
            assert "91.12.44.8" in readme

    def test_no_api_keys_in_archive(self, tmp_path: Path) -> None:
        """CRITICAL: No API keys must appear anywhere in the archive."""
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                content = zf.read(name).decode("utf-8", errors="ignore")
                assert "sk-ant-" not in content
                assert "PFSENSE_API_KEY" not in content.replace("[REDACTED]", "")

    def test_record_without_analysis_raises(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        record.analysis = None
        with pytest.raises(ValueError):
            gen.generate(record)

    def test_record_without_actions_raises(self, tmp_path: Path) -> None:
        gen = ForensicReportGenerator({"temp_dir": str(tmp_path)})
        record = _make_full_record()
        record.actions_taken = []
        with pytest.raises(ValueError):
            gen.generate(record)

    def test_suspect_files_included_when_enabled(self, tmp_path: Path) -> None:
        """When include_suspect_files is True, actual files should be copied."""
        # Create a fake suspect file
        suspect_file = tmp_path / "malware.exe"
        suspect_file.write_bytes(b"\x00" * 100)

        gen = ForensicReportGenerator(
            {
                "temp_dir": str(tmp_path / "reports"),
                "include_suspect_files": True,
                "max_suspect_files_size": 1048576,
            }
        )
        record = _make_full_record()
        record.forensic_result = ForensicResult(
            suspect_processes=[{"pid": 1234, "name": "malware.exe"}],
            suspicious_files=[{"path": str(suspect_file), "size": 100, "modified": 0}],
        )
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            has_suspect = any("suspect_files" in n and "MANIFEST.json" in n for n in names)
            assert has_suspect, f"Expected suspect_files/MANIFEST.json in {names}"
            has_copied = any("suspect_files" in n and "malware.exe" in n for n in names)
            assert has_copied, f"Expected copied malware.exe in {names}"

    def test_suspect_files_not_included_when_disabled(self, tmp_path: Path) -> None:
        """When include_suspect_files is False, no files should be copied."""
        suspect_file = tmp_path / "malware.exe"
        suspect_file.write_bytes(b"\x00" * 100)

        gen = ForensicReportGenerator(
            {
                "temp_dir": str(tmp_path / "reports"),
                "include_suspect_files": False,
            }
        )
        record = _make_full_record()
        record.forensic_result = ForensicResult(
            suspect_processes=[{"pid": 1234, "name": "malware.exe"}],
            suspicious_files=[{"path": str(suspect_file), "size": 100, "modified": 0}],
        )
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            has_suspect = any("suspect_files" in n and "MANIFEST.json" in n for n in names)
            assert not has_suspect

    def test_suspect_files_size_budget_enforced(self, tmp_path: Path) -> None:
        """Files exceeding max_suspect_files_size should be skipped."""
        file1 = tmp_path / "small.exe"
        file1.write_bytes(b"\x00" * 50)
        file2 = tmp_path / "big.exe"
        file2.write_bytes(b"\x00" * 200)

        gen = ForensicReportGenerator(
            {
                "temp_dir": str(tmp_path / "reports"),
                "include_suspect_files": True,
                "max_suspect_files_size": 100,  # Only 100 bytes budget
            }
        )
        record = _make_full_record()
        record.forensic_result = ForensicResult(
            suspicious_files=[
                {"path": str(file1), "size": 50, "modified": 0},
                {"path": str(file2), "size": 200, "modified": 0},
            ],
        )
        zip_path = gen.generate(record)

        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            # small.exe should be included, big.exe should be skipped
            has_small = any("small.exe" in n for n in names)
            has_big = any("big.exe" in n for n in names)
            assert has_small
            assert not has_big
