"""Tests for WardSOAR alert filter (known false positive suppression).

Filter is CRITICAL (95% coverage) — it is the first layer of the
anti-false-positive pipeline. Fail-safe: if the config file is missing
or corrupt, filter NOTHING (let all alerts through).
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.core.filter import AlertFilter
from wardsoar.core.models import SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_alert() -> SuricataAlert:
    """Return a minimal valid SuricataAlert."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Known Malicious",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
        alert_category="A Network Trojan was Detected",
    )


@pytest.fixture()
def fp_yaml(tmp_path: Path) -> Path:
    """Create a known_false_positives.yaml with test entries."""
    fp_file = tmp_path / "known_false_positives.yaml"
    fp_file.write_text(
        "suppressed_signatures:\n"
        "  - signature_id: 2013028\n"
        "    signature_name: 'APT User-Agent'\n"
        "    reason: 'Normal package manager'\n"
        "    added_date: '2026-01-01'\n"
        "    review_date: '2026-07-01'\n"
        "  - signature_id: 2027863\n"
        "    signature_name: 'DNS Query to .cloud'\n"
        "    reason: 'Cloud services'\n"
        "    added_date: '2026-01-01'\n"
        "    review_date: '2026-07-01'\n"
        "suppressed_categories:\n"
        "  - category: 'Not Suspicious Traffic'\n"
        "    reason: 'Informational only'\n"
        "suppressed_pairs:\n"
        "  - signature_id: 2024897\n"
        "    dest_ip: '13.107.42.14'\n"
        "    reason: 'Office 365 telemetry'\n"
        "    added_date: '2026-01-01'\n"
        "    review_date: '2026-07-01'\n",
        encoding="utf-8",
    )
    return fp_file


@pytest.fixture()
def empty_fp_yaml(tmp_path: Path) -> Path:
    """Create a known_false_positives.yaml with empty sections."""
    fp_file = tmp_path / "known_false_positives.yaml"
    fp_file.write_text(
        "suppressed_signatures: []\n" "suppressed_categories: []\n" "suppressed_pairs: []\n",
        encoding="utf-8",
    )
    return fp_file


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------


class TestAlertFilterInit:
    """Tests for AlertFilter initialization."""

    def test_disabled_filter(self) -> None:
        flt = AlertFilter({"enabled": False})
        assert flt._enabled is False

    def test_enabled_with_valid_config(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        assert flt._enabled is True
        assert 2013028 in flt._suppressed_sids
        assert 2027863 in flt._suppressed_sids

    def test_relative_path_resolves_via_bundle_dir(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """Regression test for the v0.6.5 MSI-install bug.

        When the operator leaves ``config_file`` at its default
        relative value, the filter must resolve the YAML against the
        PyInstaller bundle directory first. Without that fallback, a
        frozen installation loaded zero suppressed SIDs because the
        cwd never pointed at ``_internal/``.
        """
        # Arrange: pretend the bundle lives under a throwaway tmp tree
        # containing ``config/known_false_positives.yaml`` with one SID.
        bundle_root = tmp_path / "bundle"
        (bundle_root / "config").mkdir(parents=True)
        (bundle_root / "config" / "known_false_positives.yaml").write_text(
            "suppressed_signatures:\n"
            "  - signature_id: 9999001\n"
            "    signature_name: 'Bundle-only SID'\n"
            "    reason: 'unit test'\n"
            "    added_date: '2026-01-01'\n"
            "    review_date: '2026-07-01'\n",
            encoding="utf-8",
        )

        # The filter module does ``from wardsoar.core.config import
        # get_bundle_dir`` inline, so we patch both the canonical
        # location and the name imported into the filter module.
        import wardsoar.core.config

        monkeypatch.setattr(wardsoar.core.config, "get_bundle_dir", lambda: bundle_root)
        monkeypatch.setattr("wardsoar.core.filter.Path", Path)

        flt = AlertFilter({"enabled": True, "config_file": "config/known_false_positives.yaml"})
        assert 9999001 in flt._suppressed_sids

    def test_enabled_with_missing_file(self, tmp_path: Path) -> None:
        """Fail-safe: missing config file should not crash — filter nothing."""
        flt = AlertFilter({"enabled": True, "config_file": str(tmp_path / "missing.yaml")})
        assert flt._enabled is True
        assert len(flt._suppressed_sids) == 0

    def test_loads_suppressed_categories(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        assert "Not Suspicious Traffic" in flt._suppressed_categories

    def test_loads_suppressed_pairs(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        assert len(flt._suppressed_pairs) == 1
        assert flt._suppressed_pairs[0]["signature_id"] == 2024897
        assert flt._suppressed_pairs[0]["dest_ip"] == "13.107.42.14"

    def test_empty_config_file(self, empty_fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(empty_fp_yaml)})
        assert len(flt._suppressed_sids) == 0
        assert len(flt._suppressed_categories) == 0
        assert len(flt._suppressed_pairs) == 0

    def test_corrupt_yaml_does_not_crash(self, tmp_path: Path) -> None:
        """Fail-safe: corrupt YAML should not crash — filter nothing."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{not valid yaml::::", encoding="utf-8")
        flt = AlertFilter({"enabled": True, "config_file": str(bad_file)})
        assert len(flt._suppressed_sids) == 0

    def test_null_sections_in_yaml(self, tmp_path: Path) -> None:
        """Sections that are null should be handled gracefully."""
        fp_file = tmp_path / "null_sections.yaml"
        fp_file.write_text(
            "suppressed_signatures:\n" "suppressed_categories:\n" "suppressed_pairs:\n",
            encoding="utf-8",
        )
        flt = AlertFilter({"enabled": True, "config_file": str(fp_file)})
        assert len(flt._suppressed_sids) == 0


# ---------------------------------------------------------------------------
# should_suppress tests
# ---------------------------------------------------------------------------


class TestShouldSuppress:
    """Tests for AlertFilter.should_suppress."""

    def test_disabled_filter_never_suppresses(self, sample_alert: SuricataAlert) -> None:
        flt = AlertFilter({"enabled": False})
        assert flt.should_suppress(sample_alert) is False

    def test_suppress_by_signature_id(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        alert = SuricataAlert(
            timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="192.168.1.100",
            dest_port=443,
            proto="TCP",
            alert_signature="APT User-Agent",
            alert_signature_id=2013028,
            alert_severity=SuricataAlertSeverity.LOW,
        )
        assert flt.should_suppress(alert) is True

    def test_no_suppress_unknown_signature(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        alert = SuricataAlert(
            timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="192.168.1.100",
            dest_port=443,
            proto="TCP",
            alert_signature="Unknown Threat",
            alert_signature_id=9999999,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        assert flt.should_suppress(alert) is False

    def test_suppress_by_category(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        alert = SuricataAlert(
            timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="192.168.1.100",
            dest_port=443,
            proto="TCP",
            alert_signature="Some Alert",
            alert_signature_id=9999999,
            alert_severity=SuricataAlertSeverity.LOW,
            alert_category="Not Suspicious Traffic",
        )
        assert flt.should_suppress(alert) is True

    def test_suppress_by_signature_dest_pair(self, fp_yaml: Path) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        alert = SuricataAlert(
            timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="13.107.42.14",
            dest_port=443,
            proto="TCP",
            alert_signature="ET MALWARE Known Malicious",
            alert_signature_id=2024897,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        assert flt.should_suppress(alert) is True

    def test_pair_no_match_different_dest(self, fp_yaml: Path) -> None:
        """Same signature but different dest_ip should NOT suppress."""
        flt = AlertFilter({"enabled": True, "config_file": str(fp_yaml)})
        alert = SuricataAlert(
            timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="1.2.3.4",
            dest_port=443,
            proto="TCP",
            alert_signature="ET MALWARE Known Malicious",
            alert_signature_id=2024897,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        assert flt.should_suppress(alert) is False

    def test_empty_filter_never_suppresses(
        self, empty_fp_yaml: Path, sample_alert: SuricataAlert
    ) -> None:
        flt = AlertFilter({"enabled": True, "config_file": str(empty_fp_yaml)})
        assert flt.should_suppress(sample_alert) is False
