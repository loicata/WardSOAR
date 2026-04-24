"""Tests for WardSOAR EVE JSON watcher.

Watcher is HIGH (85% coverage). Tests cover EVE JSON parsing,
file monitoring, severity filtering, and error handling.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.models import SuricataAlert, SuricataAlertSeverity
from src.watcher import EveJsonWatcher, SshEveWatcher, create_watcher

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _eve_alert_dict(
    src_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dest_ip: str = "192.168.1.100",
    dest_port: int = 443,
    proto: str = "TCP",
    sig_name: str = "ET MALWARE Test",
    sig_id: int = 2024897,
    severity: int = 1,
    category: str = "A Network Trojan was Detected",
) -> dict[str, Any]:
    """Create a raw EVE JSON alert dict as Suricata would produce."""
    return {
        "timestamp": "2026-03-15T10:30:00.000000+0000",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "signature": sig_name,
            "signature_id": sig_id,
            "severity": severity,
            "category": category,
            "action": "allowed",
        },
        "flow_id": 123456789,
    }


# ---------------------------------------------------------------------------
# parse_eve_alert tests
# ---------------------------------------------------------------------------


class TestParseEveAlert:
    """Tests for EveJsonWatcher.parse_eve_alert static method."""

    def test_valid_alert(self) -> None:
        raw = _eve_alert_dict()
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is not None
        assert result.src_ip == "10.0.0.1"
        assert result.dest_port == 443
        assert result.alert_signature_id == 2024897
        assert result.alert_severity == SuricataAlertSeverity.HIGH
        assert result.alert_category == "A Network Trojan was Detected"
        assert result.flow_id == 123456789

    def test_non_alert_event_returns_none(self) -> None:
        raw = {"event_type": "dns", "src_ip": "10.0.0.1"}
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is None

    def test_missing_event_type_returns_none(self) -> None:
        raw = {"src_ip": "10.0.0.1"}
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is None

    def test_missing_alert_section_returns_none(self) -> None:
        raw = {"event_type": "alert", "src_ip": "10.0.0.1"}
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is None

    def test_severity_values(self) -> None:
        for sev_val, expected in [
            (1, SuricataAlertSeverity.HIGH),
            (2, SuricataAlertSeverity.MEDIUM),
            (3, SuricataAlertSeverity.LOW),
        ]:
            raw = _eve_alert_dict(severity=sev_val)
            result = EveJsonWatcher.parse_eve_alert(raw)
            assert result is not None
            assert result.alert_severity == expected

    def test_raw_event_preserved(self) -> None:
        raw = _eve_alert_dict()
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is not None
        assert result.raw_event == raw

    def test_malformed_timestamp_returns_none(self) -> None:
        raw = _eve_alert_dict()
        raw["timestamp"] = "not-a-timestamp"
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is None

    def test_missing_required_field_returns_none(self) -> None:
        raw = _eve_alert_dict()
        del raw["src_ip"]
        result = EveJsonWatcher.parse_eve_alert(raw)
        assert result is None


# ---------------------------------------------------------------------------
# Watcher initialization and start tests
# ---------------------------------------------------------------------------


class TestWatcherInit:
    """Tests for EveJsonWatcher initialization."""

    def test_construction(self, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")
        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=3,
            poll_interval=1.0,
        )
        assert watcher._running is False

    def test_start_with_missing_file_raises(self, tmp_path: Path) -> None:
        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(tmp_path / "missing.json"),
            callback=callback,
        )
        with pytest.raises(FileNotFoundError):
            watcher.start()

    def test_stop(self, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")
        callback = MagicMock()
        watcher = EveJsonWatcher(eve_path=str(eve_file), callback=callback)
        watcher._running = True
        watcher.stop()
        assert watcher._running is False


# ---------------------------------------------------------------------------
# File monitoring tests
# ---------------------------------------------------------------------------


class TestWatcherMonitoring:
    """Tests for EveJsonWatcher file monitoring."""

    def test_process_new_lines_calls_callback(self, tmp_path: Path) -> None:
        """When new alert lines are appended, callback is called."""
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")

        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=3,
        )
        # Simulate start: seek to end
        watcher._last_position = 0

        # Append an alert line
        alert_line = json.dumps(_eve_alert_dict()) + "\n"
        eve_file.write_text(alert_line, encoding="utf-8")

        # Process new lines
        watcher._process_new_lines()
        assert callback.call_count == 1
        called_alert = callback.call_args[0][0]
        assert isinstance(called_alert, SuricataAlert)
        assert called_alert.src_ip == "10.0.0.1"

    def test_severity_filter(self, tmp_path: Path) -> None:
        """Alerts below min_severity should be skipped."""
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")

        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=1,  # Only severity 1
        )
        watcher._last_position = 0

        # severity 3 alert — should be skipped
        alert_line = json.dumps(_eve_alert_dict(severity=3)) + "\n"
        eve_file.write_text(alert_line, encoding="utf-8")

        watcher._process_new_lines()
        assert callback.call_count == 0

    def test_non_json_lines_skipped(self, tmp_path: Path) -> None:
        """Malformed JSON lines should be skipped without crashing."""
        eve_file = tmp_path / "eve.json"
        lines = "not json\n" + json.dumps(_eve_alert_dict()) + "\n"
        eve_file.write_text(lines, encoding="utf-8")

        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=3,
        )
        watcher._last_position = 0
        watcher._process_new_lines()

        # Only the valid alert should trigger callback
        assert callback.call_count == 1

    def test_non_alert_events_skipped(self, tmp_path: Path) -> None:
        """Non-alert events (dns, flow, etc.) should be skipped."""
        eve_file = tmp_path / "eve.json"
        dns_line = json.dumps({"event_type": "dns", "src_ip": "10.0.0.1"}) + "\n"
        eve_file.write_text(dns_line, encoding="utf-8")

        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=3,
        )
        watcher._last_position = 0
        watcher._process_new_lines()
        assert callback.call_count == 0

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        """Empty lines should be skipped."""
        eve_file = tmp_path / "eve.json"
        lines = "\n\n" + json.dumps(_eve_alert_dict()) + "\n\n"
        eve_file.write_text(lines, encoding="utf-8")

        callback = MagicMock()
        watcher = EveJsonWatcher(
            eve_path=str(eve_file),
            callback=callback,
            min_severity=3,
        )
        watcher._last_position = 0
        watcher._process_new_lines()
        assert callback.call_count == 1


# ---------------------------------------------------------------------------
# SshEveWatcher tests
# ---------------------------------------------------------------------------


class TestSshEveWatcher:
    """Tests for SshEveWatcher."""

    def test_construction(self) -> None:
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
        )
        assert watcher._running is False
        assert watcher._pfsense_ip == "192.168.2.1"

    def test_process_line_valid_alert(self) -> None:
        """Valid alert lines should trigger the callback."""
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
            min_severity=3,
        )
        line = json.dumps(_eve_alert_dict())
        watcher._process_line(line)
        assert callback.call_count == 1
        called_alert = callback.call_args[0][0]
        assert isinstance(called_alert, SuricataAlert)

    def test_process_line_non_alert_skipped(self) -> None:
        """Non-alert events should not trigger the callback."""
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
        )
        line = json.dumps({"event_type": "dns", "src_ip": "10.0.0.1"})
        watcher._process_line(line)
        assert callback.call_count == 0

    def test_process_line_invalid_json_skipped(self) -> None:
        """Invalid JSON should not crash."""
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
        )
        watcher._process_line("not json at all")
        assert callback.call_count == 0

    def test_severity_filter(self) -> None:
        """Alerts below min_severity should be filtered out."""
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
            min_severity=1,
        )
        # Severity 3 alert with min_severity=1 should be skipped
        line = json.dumps(_eve_alert_dict(severity=3))
        watcher._process_line(line)
        assert callback.call_count == 0

    def test_stop(self) -> None:
        callback = MagicMock()
        watcher = SshEveWatcher(
            pfsense_ip="192.168.2.1",
            ssh_user="admin",
            ssh_key_path="/path/to/key",
            ssh_port=22,
            remote_eve_path="/var/log/suricata/eve.json",
            callback=callback,
        )
        watcher._running = True
        watcher.stop()
        assert watcher._running is False


# ---------------------------------------------------------------------------
# create_watcher factory tests
# ---------------------------------------------------------------------------


class TestCreateWatcher:
    """Tests for create_watcher factory function."""

    def test_file_mode_returns_eve_watcher(self, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")
        callback = MagicMock()
        config = {"mode": "file", "eve_json_path": str(eve_file)}
        watcher = create_watcher(config, callback)
        assert isinstance(watcher, EveJsonWatcher)

    def test_ssh_mode_returns_ssh_watcher(self) -> None:
        callback = MagicMock()
        config = {
            "mode": "ssh",
            "ssh": {"remote_eve_path": "/var/log/suricata/eve.json"},
            "_network": {"pfsense_ip": "192.168.2.1", "pc_ip": "192.168.2.100"},
            "_responder": {
                "pfsense": {"ssh_user": "admin", "ssh_key_path": "/key", "ssh_port": 22}
            },
        }
        watcher = create_watcher(config, callback)
        assert isinstance(watcher, SshEveWatcher)
        assert watcher._pfsense_ip == "192.168.2.1"

    def test_default_mode_is_file(self, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("", encoding="utf-8")
        callback = MagicMock()
        config = {"eve_json_path": str(eve_file)}
        watcher = create_watcher(config, callback)
        assert isinstance(watcher, EveJsonWatcher)
