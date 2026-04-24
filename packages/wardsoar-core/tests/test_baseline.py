"""Tests for WardSOAR network baseline comparison.

Baseline is HIGH (85% coverage). Fail-safe: if the baseline config
is missing or corrupt, skip baseline check (let alert through).
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.core.baseline import BaselineVerdict, NetworkBaseline
from wardsoar.core.models import SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    dest_ip: str = "1.2.3.4",
    dest_port: int = 443,
    src_ip: str = "192.168.1.100",
) -> SuricataAlert:
    """Create a test alert with configurable dest_ip and dest_port."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=12345,
        dest_ip=dest_ip,
        dest_port=dest_port,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


@pytest.fixture()
def baseline_yaml(tmp_path: Path) -> Path:
    """Create a network_baseline.yaml with test data."""
    bl_file = tmp_path / "network_baseline.yaml"
    bl_file.write_text(
        "internal_services:\n"
        "  - name: 'File Server'\n"
        "    ip: '192.168.1.20'\n"
        "    expected_ports: [445, 139]\n"
        "    description: 'SMB file shares'\n"
        "expected_external_destinations:\n"
        "  - name: 'Anthropic API'\n"
        "    domains: ['api.anthropic.com']\n"
        "    ports: [443]\n"
        "expected_outbound_ports:\n"
        "  - port: 443\n"
        "    protocol: 'TCP'\n"
        "    description: 'HTTPS'\n"
        "  - port: 80\n"
        "    protocol: 'TCP'\n"
        "    description: 'HTTP'\n"
        "  - port: 53\n"
        "    protocol: 'UDP'\n"
        "    description: 'DNS'\n"
        "suspicious_outbound_ports:\n"
        "  - port: 4444\n"
        "    description: 'Metasploit default'\n"
        "  - port: 6667\n"
        "    description: 'IRC C2'\n"
        "  - port: 3389\n"
        "    description: 'RDP outbound'\n",
        encoding="utf-8",
    )
    return bl_file


# ---------------------------------------------------------------------------
# BaselineVerdict tests
# ---------------------------------------------------------------------------


class TestBaselineVerdict:
    """Tests for BaselineVerdict data structure."""

    def test_default_construction(self) -> None:
        verdict = BaselineVerdict()
        assert verdict.is_known_normal is False
        assert verdict.is_known_suspicious is False
        assert verdict.matching_rule is None
        assert verdict.anomaly_details is None

    def test_suspicious_verdict(self) -> None:
        verdict = BaselineVerdict(
            is_known_suspicious=True,
            matching_rule="suspicious_outbound_ports",
            anomaly_details="Port 4444 is a known C2 port",
        )
        assert verdict.is_known_suspicious is True


# ---------------------------------------------------------------------------
# NetworkBaseline init tests
# ---------------------------------------------------------------------------


class TestNetworkBaselineInit:
    """Tests for NetworkBaseline initialization."""

    def test_disabled_baseline(self) -> None:
        bl = NetworkBaseline({"enabled": False})
        assert bl._enabled is False

    def test_enabled_with_valid_config(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        assert bl._enabled is True
        assert 4444 in bl._suspicious_outbound_ports
        assert 6667 in bl._suspicious_outbound_ports
        assert 443 in bl._expected_outbound_ports

    def test_missing_config_file(self, tmp_path: Path) -> None:
        """Fail-safe: missing config should not crash."""
        bl = NetworkBaseline({"enabled": True, "config_file": str(tmp_path / "missing.yaml")})
        assert len(bl._suspicious_outbound_ports) == 0

    def test_corrupt_yaml(self, tmp_path: Path) -> None:
        """Fail-safe: corrupt YAML should not crash."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{invalid", encoding="utf-8")
        bl = NetworkBaseline({"enabled": True, "config_file": str(bad_file)})
        assert len(bl._suspicious_outbound_ports) == 0

    def test_null_sections(self, tmp_path: Path) -> None:
        """Sections that are null should be handled gracefully."""
        bl_file = tmp_path / "null.yaml"
        bl_file.write_text(
            "internal_services:\n"
            "expected_external_destinations:\n"
            "expected_outbound_ports:\n"
            "suspicious_outbound_ports:\n",
            encoding="utf-8",
        )
        bl = NetworkBaseline({"enabled": True, "config_file": str(bl_file)})
        assert len(bl._suspicious_outbound_ports) == 0

    def test_loads_internal_services(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        assert len(bl._internal_services) == 1
        assert bl._internal_services[0]["ip"] == "192.168.1.20"


# ---------------------------------------------------------------------------
# is_suspicious_port tests
# ---------------------------------------------------------------------------


class TestIsSuspiciousPort:
    """Tests for NetworkBaseline.is_suspicious_port."""

    def test_suspicious_port(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        assert bl.is_suspicious_port(4444) is True
        assert bl.is_suspicious_port(6667) is True

    def test_normal_port(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        assert bl.is_suspicious_port(443) is False
        assert bl.is_suspicious_port(80) is False


# ---------------------------------------------------------------------------
# evaluate tests
# ---------------------------------------------------------------------------


class TestEvaluate:
    """Tests for NetworkBaseline.evaluate."""

    def test_disabled_returns_neutral_verdict(self) -> None:
        bl = NetworkBaseline({"enabled": False})
        verdict = bl.evaluate(_make_alert())
        assert verdict.is_known_normal is False
        assert verdict.is_known_suspicious is False

    def test_suspicious_port_detected(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        alert = _make_alert(dest_port=4444)
        verdict = bl.evaluate(alert)
        assert verdict.is_known_suspicious is True

    def test_expected_port_is_normal(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        alert = _make_alert(dest_port=443)
        verdict = bl.evaluate(alert)
        assert verdict.is_known_suspicious is False

    def test_internal_service_expected_port(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        alert = _make_alert(dest_ip="192.168.1.20", dest_port=445)
        verdict = bl.evaluate(alert)
        assert verdict.is_known_normal is True

    def test_internal_service_unexpected_port(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        alert = _make_alert(dest_ip="192.168.1.20", dest_port=8888)
        verdict = bl.evaluate(alert)
        assert verdict.is_known_normal is False

    def test_unknown_traffic(self, baseline_yaml: Path) -> None:
        bl = NetworkBaseline({"enabled": True, "config_file": str(baseline_yaml)})
        alert = _make_alert(dest_ip="5.6.7.8", dest_port=9999)
        verdict = bl.evaluate(alert)
        # Not known normal, not known suspicious (port 9999 not in suspicious list)
        assert verdict.is_known_normal is False
        assert verdict.is_known_suspicious is False
