"""Tests for WardSOAR configuration loading and whitelist.

config.py contains CRITICAL security logic (WhitelistConfig.is_whitelisted)
that prevents blocking of infrastructure IPs. Coverage target: 95%.
"""

from pathlib import Path

import pytest

from wardsoar.core.config import (
    AppConfig,
    WhitelistConfig,
    load_config,
    load_env,
    load_whitelist,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def minimal_config_yaml(tmp_path: Path) -> Path:
    """Create a minimal valid config.yaml for testing."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "network:\n"
        "  pfsense_ip: '192.168.1.1'\n"
        "watcher:\n"
        "  eve_json_path: '/tmp/eve.json'\n"
        "responder:\n"
        "  dry_run: true\n",
        encoding="utf-8",
    )
    return config_file


@pytest.fixture()
def full_whitelist_yaml(tmp_path: Path) -> Path:
    """Create a whitelist.yaml with all section types."""
    wl_file = tmp_path / "whitelist.yaml"
    wl_file.write_text(
        "infrastructure:\n"
        "  - ip: '192.168.1.1'\n"
        "    description: 'Gateway'\n"
        "  - ip: '192.168.1.100'\n"
        "    description: 'PC'\n"
        "dns:\n"
        "  - ip: '1.1.1.1'\n"
        "    description: 'Cloudflare'\n"
        "  - ip: '8.8.8.8'\n"
        "    description: 'Google DNS'\n"
        "trusted:\n"
        "  - ip: '10.0.0.50'\n"
        "    description: 'Trusted server'\n"
        "subnets:\n"
        "  - cidr: '10.0.0.0/8'\n"
        "    description: 'Internal'\n"
        "  - cidr: '172.16.0.0/12'\n"
        "    description: 'Private'\n",
        encoding="utf-8",
    )
    return wl_file


@pytest.fixture()
def empty_whitelist_yaml(tmp_path: Path) -> Path:
    """Create a whitelist.yaml with empty sections."""
    wl_file = tmp_path / "whitelist.yaml"
    wl_file.write_text(
        "infrastructure: []\n" "dns: []\n" "trusted: []\n" "subnets: []\n",
        encoding="utf-8",
    )
    return wl_file


# ---------------------------------------------------------------------------
# AppConfig tests
# ---------------------------------------------------------------------------


class TestAppConfig:
    """Tests for AppConfig model."""

    def test_default_construction(self) -> None:
        config = AppConfig()
        assert config.network == {}
        assert config.watcher == {}
        assert config.responder == {}

    def test_construction_with_data(self) -> None:
        config = AppConfig(
            network={"pfsense_ip": "192.168.1.1"},
            responder={"dry_run": True},
        )
        assert config.network["pfsense_ip"] == "192.168.1.1"
        assert config.responder["dry_run"] is True


# ---------------------------------------------------------------------------
# WhitelistConfig tests — CRITICAL SECURITY
# ---------------------------------------------------------------------------


class TestWhitelistConfig:
    """Tests for WhitelistConfig — CRITICAL security component.

    A whitelist bypass is a P0 bug. These tests cover:
    - Exact IP match
    - Subnet membership (CIDR)
    - IPs NOT in whitelist
    - Invalid IP handling (fail-safe: return False)
    - Empty whitelist
    - Edge cases
    """

    def test_exact_ip_match(self) -> None:
        wl = WhitelistConfig(ips={"192.168.1.1", "10.0.0.1"})
        assert wl.is_whitelisted("192.168.1.1") is True
        assert wl.is_whitelisted("10.0.0.1") is True

    def test_ip_not_in_whitelist(self) -> None:
        wl = WhitelistConfig(ips={"192.168.1.1"})
        assert wl.is_whitelisted("1.2.3.4") is False

    def test_subnet_match(self) -> None:
        wl = WhitelistConfig(subnets=["10.0.0.0/8"])
        assert wl.is_whitelisted("10.0.0.1") is True
        assert wl.is_whitelisted("10.255.255.255") is True

    def test_subnet_no_match(self) -> None:
        wl = WhitelistConfig(subnets=["10.0.0.0/8"])
        assert wl.is_whitelisted("11.0.0.1") is False

    def test_multiple_subnets(self) -> None:
        wl = WhitelistConfig(subnets=["10.0.0.0/8", "172.16.0.0/12"])
        assert wl.is_whitelisted("10.0.0.1") is True
        assert wl.is_whitelisted("172.16.0.1") is True
        assert wl.is_whitelisted("192.168.1.1") is False

    def test_exact_ip_takes_priority_over_subnet(self) -> None:
        wl = WhitelistConfig(
            ips={"192.168.1.1"},
            subnets=["10.0.0.0/8"],
        )
        assert wl.is_whitelisted("192.168.1.1") is True

    def test_invalid_ip_returns_false(self) -> None:
        """Fail-safe: invalid IPs must not be whitelisted."""
        wl = WhitelistConfig(ips={"192.168.1.1"}, subnets=["10.0.0.0/8"])
        assert wl.is_whitelisted("not-an-ip") is False

    def test_empty_string_returns_false(self) -> None:
        wl = WhitelistConfig(ips={"192.168.1.1"})
        assert wl.is_whitelisted("") is False

    def test_empty_whitelist(self) -> None:
        wl = WhitelistConfig()
        assert wl.is_whitelisted("192.168.1.1") is False

    def test_ipv6_not_whitelisted_by_default(self) -> None:
        wl = WhitelistConfig(ips={"192.168.1.1"})
        assert wl.is_whitelisted("::1") is False

    def test_single_host_subnet(self) -> None:
        wl = WhitelistConfig(subnets=["192.168.1.1/32"])
        assert wl.is_whitelisted("192.168.1.1") is True
        assert wl.is_whitelisted("192.168.1.2") is False


# ---------------------------------------------------------------------------
# load_config tests
# ---------------------------------------------------------------------------


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_config(self, minimal_config_yaml: Path) -> None:
        config = load_config(minimal_config_yaml)
        assert isinstance(config, AppConfig)
        assert config.network["pfsense_ip"] == "192.168.1.1"

    def test_load_nonexistent_file_creates_default(self, tmp_path: Path) -> None:
        """First launch: missing config creates a default file."""
        config = load_config(tmp_path / "config.yaml")
        assert isinstance(config, AppConfig)

    def test_load_real_config(self) -> None:
        """Load the actual project config.yaml to ensure it parses."""
        config = load_config(Path("config/config.yaml"))
        assert config.network["pfsense_ip"] == "192.168.2.1"
        assert config.responder["dry_run"] is True

    def test_unknown_keys_are_ignored(self, tmp_path: Path) -> None:
        """Pydantic should not fail on unknown keys in YAML."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "network:\n" "  pfsense_ip: '1.1.1.1'\n" "some_future_section:\n" "  key: value\n",
            encoding="utf-8",
        )
        config = load_config(config_file)
        assert config.network["pfsense_ip"] == "1.1.1.1"


# ---------------------------------------------------------------------------
# load_whitelist tests
# ---------------------------------------------------------------------------


class TestLoadWhitelist:
    """Tests for load_whitelist function."""

    def test_load_full_whitelist(self, full_whitelist_yaml: Path) -> None:
        wl = load_whitelist(full_whitelist_yaml)
        assert "192.168.1.1" in wl.ips
        assert "192.168.1.100" in wl.ips
        assert "1.1.1.1" in wl.ips
        assert "8.8.8.8" in wl.ips
        assert "10.0.0.50" in wl.ips
        assert len(wl.subnets) == 2
        assert "10.0.0.0/8" in wl.subnets

    def test_load_empty_whitelist(self, empty_whitelist_yaml: Path) -> None:
        wl = load_whitelist(empty_whitelist_yaml)
        assert len(wl.ips) == 0
        assert len(wl.subnets) == 0

    def test_load_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        """Missing whitelist file returns empty whitelist (fail-safe)."""
        wl = load_whitelist(tmp_path / "nonexistent.yaml")
        assert len(wl.ips) == 0

    def test_load_real_whitelist(self) -> None:
        """Load the actual project whitelist.yaml."""
        wl = load_whitelist(Path("config/whitelist.yaml"))
        assert "192.168.2.1" in wl.ips
        assert "192.168.2.100" in wl.ips

    def test_whitelist_missing_sections(self, tmp_path: Path) -> None:
        """Whitelist with only some sections should still parse."""
        wl_file = tmp_path / "whitelist.yaml"
        wl_file.write_text(
            "infrastructure:\n" "  - ip: '192.168.1.1'\n" "    description: 'GW'\n",
            encoding="utf-8",
        )
        wl = load_whitelist(wl_file)
        assert "192.168.1.1" in wl.ips
        assert len(wl.subnets) == 0

    def test_whitelist_entries_without_ip_key(self, tmp_path: Path) -> None:
        """Entries missing 'ip' key should be silently skipped."""
        wl_file = tmp_path / "whitelist.yaml"
        wl_file.write_text(
            "infrastructure:\n"
            "  - description: 'No IP here'\n"
            "  - ip: '10.0.0.1'\n"
            "    description: 'Has IP'\n",
            encoding="utf-8",
        )
        wl = load_whitelist(wl_file)
        assert "10.0.0.1" in wl.ips
        assert len(wl.ips) == 1

    def test_subnet_entries_without_cidr_key(self, tmp_path: Path) -> None:
        """Subnet entries missing 'cidr' key should be silently skipped."""
        wl_file = tmp_path / "whitelist.yaml"
        wl_file.write_text(
            "infrastructure: []\n"
            "subnets:\n"
            "  - description: 'No CIDR'\n"
            "  - cidr: '10.0.0.0/8'\n"
            "    description: 'Has CIDR'\n",
            encoding="utf-8",
        )
        wl = load_whitelist(wl_file)
        assert len(wl.subnets) == 1


# ---------------------------------------------------------------------------
# load_env tests
# ---------------------------------------------------------------------------


class TestLoadEnv:
    """Tests for load_env function."""

    def test_load_env_does_not_crash(self) -> None:
        """load_env should not raise even if no .env file exists."""
        load_env()
