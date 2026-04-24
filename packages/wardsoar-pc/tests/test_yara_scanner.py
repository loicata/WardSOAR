"""Tests for WardSOAR YARA scanner.

The scanner compiles rules once at startup and must stay silent (not
crash) when rules are missing, invalid, or the scan times out.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardsoar.pc.local_av.yara_scanner import YaraScanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Deliberately a non-AV signature. Using the real EICAR string would
# trigger Windows Defender and quarantine the test fixtures before YARA
# can read them (Errno 22 at read time). The cascade's Defender stage has
# its own separate test file.
TEST_PAYLOAD = "WARDSOAR_YARA_TEST_MARKER_9F3A2E6B7C1D"

TEST_RULE = f"""
rule WARDSOAR_Yara_Self_Test
{{
    strings:
        $marker = "{TEST_PAYLOAD}"

    condition:
        $marker
}}
"""


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """Directory containing a single valid rule that matches TEST_PAYLOAD."""
    rules = tmp_path / "yara_rules"
    rules.mkdir()
    (rules / "self_test.yar").write_text(TEST_RULE, encoding="utf-8")
    return rules


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for YaraScanner initialization and rule compilation."""

    def test_disabled_stays_idle(self, rules_dir: Path) -> None:
        scanner = YaraScanner({"enabled": False, "rules_dir": str(rules_dir)})
        assert scanner.is_armed() is False

    def test_missing_directory_stays_idle(self, tmp_path: Path) -> None:
        scanner = YaraScanner({"rules_dir": str(tmp_path / "does_not_exist")})
        assert scanner.is_armed() is False

    def test_empty_directory_stays_idle(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty_rules"
        empty.mkdir()
        scanner = YaraScanner({"rules_dir": str(empty)})
        assert scanner.is_armed() is False

    def test_valid_rule_arms_scanner(self, rules_dir: Path) -> None:
        scanner = YaraScanner({"rules_dir": str(rules_dir)})
        assert scanner.is_armed() is True

    def test_invalid_rule_disables_scanner(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad_rules"
        bad.mkdir()
        (bad / "broken.yar").write_text("rule Broken { this is not yara }\n")

        scanner = YaraScanner({"rules_dir": str(bad)})
        assert scanner.is_armed() is False


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class TestScan:
    """Tests for YaraScanner.scan()."""

    @pytest.mark.asyncio
    async def test_idle_scanner_returns_none(self, tmp_path: Path) -> None:
        scanner = YaraScanner({"rules_dir": str(tmp_path / "nothing")})
        target = tmp_path / "target.exe"
        target.write_bytes(b"anything")

        result = await scanner.scan(str(target), "a" * 64)
        assert result is None

    @pytest.mark.asyncio
    async def test_matching_file_returns_verdict(self, rules_dir: Path, tmp_path: Path) -> None:
        scanner = YaraScanner({"rules_dir": str(rules_dir)})

        target = tmp_path / "sample.bin"
        target.write_text(TEST_PAYLOAD, encoding="utf-8")

        result = await scanner.scan(str(target), "deadbeef" * 8)

        assert result is not None
        assert result.is_malicious is True
        assert result.lookup_type == "yara"
        assert any("WARDSOAR_Yara_Self_Test" in label for label in result.threat_labels)
        assert result.detection_count == 1

    @pytest.mark.asyncio
    async def test_non_matching_file_returns_none(self, rules_dir: Path, tmp_path: Path) -> None:
        scanner = YaraScanner({"rules_dir": str(rules_dir)})

        clean = tmp_path / "clean.txt"
        clean.write_text("Hello, world!", encoding="utf-8")

        result = await scanner.scan(str(clean), "c" * 64)
        assert result is None

    @pytest.mark.asyncio
    async def test_treat_match_as_malicious_false(self, rules_dir: Path, tmp_path: Path) -> None:
        """Config flag lets YARA annotate without vetoing the cascade."""
        scanner = YaraScanner(
            {
                "rules_dir": str(rules_dir),
                "treat_match_as_malicious": False,
            }
        )

        target = tmp_path / "sample.bin"
        target.write_text(TEST_PAYLOAD, encoding="utf-8")

        result = await scanner.scan(str(target), "deadbeef" * 8)

        assert result is not None
        assert result.is_malicious is False
        assert result.threat_labels  # still reports the rule name
