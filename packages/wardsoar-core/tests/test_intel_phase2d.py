"""Tests for the Phase 2d paid-tier clients (Shodan + SecurityTrails
+ Censys).

Every client is exercised via its ``_verdict_from_raw`` parser;
no real network traffic is generated. Dual-secret Censys gating
is tested separately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardsoar.core.intel.censys_client import CensysClient
from wardsoar.core.intel.http_client_base import IpReputationCache
from wardsoar.core.intel.securitytrails import SecurityTrailsClient
from wardsoar.core.intel.shodan_client import ShodanClient

# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------


class TestShodanParser:
    def _cli(self, tmp_path: Path) -> ShodanClient:
        return ShodanClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_unknown_ip_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unknown": True})
        assert v.level == "clean"
        assert "No exposed service" in v.verdict

    def test_vulnerable_host_is_bad(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "ports": [22, 443],
                "vulns": {
                    "CVE-2023-1234": {"cvss": 9.8, "summary": "..."},
                    "CVE-2021-0001": {"cvss": 7.5, "summary": "..."},
                },
            }
        )
        assert v.level == "bad"
        assert "2 known vulnerability" in v.verdict

    def test_open_ports_without_vulns_is_info(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"ports": [22, 80, 443, 8080, 9090]})
        assert v.level == "info"
        assert "5 open port" in v.verdict
        # Sample shows first 4 ports.
        assert "22, 80, 443, 8080" in v.verdict

    def test_no_ports_no_vulns_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"ports": [], "vulns": {}})
        assert v.level == "clean"


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------


class TestSecurityTrailsParser:
    def _cli(self, tmp_path: Path) -> SecurityTrailsClient:
        return SecurityTrailsClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_unknown_ip(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unknown": True})
        assert v.level == "clean"

    def test_list_of_hostnames(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "hostnames": [
                    "a.example.com",
                    "b.example.com",
                    "c.example.com",
                    "d.example.com",
                    "e.example.com",
                ]
            }
        )
        assert v.level == "info"
        assert "5 historical hostname" in v.verdict
        assert "a.example.com" in v.verdict
        assert "+2 more" in v.verdict

    def test_empty_list_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"hostnames": []})
        assert v.level == "clean"
        assert "No passive-DNS history" in v.verdict

    def test_dict_records_a_format(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "hostnames": {
                    "a": [
                        {"host": "foo.example.com"},
                        {"host": "bar.example.com"},
                    ]
                }
            }
        )
        assert v.level == "info"
        assert "2 historical hostname" in v.verdict


# ---------------------------------------------------------------------------
# Censys
# ---------------------------------------------------------------------------


class TestCensysParser:
    def _cli(self, tmp_path: Path) -> CensysClient:
        return CensysClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_unknown_ip_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unknown": True})
        assert v.level == "clean"
        assert "Not indexed by Censys" in v.verdict

    def test_no_services_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"result": {"services": []}})
        assert v.level == "clean"
        assert "No services observed" in v.verdict

    def test_services_without_labels_is_info(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "result": {
                    "services": [
                        {"port": 443, "certificate": "sha256:abc"},
                        {"port": 80},
                    ]
                }
            }
        )
        assert v.level == "info"
        assert "2 service" in v.verdict
        assert "1 with TLS cert" in v.verdict

    def test_suspicious_label_is_bad(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "result": {
                    "services": [{"port": 443}],
                    "labels": ["c2", "malware"],
                }
            }
        )
        assert v.level == "bad"
        assert "c2" in v.verdict.lower() or "malware" in v.verdict.lower()


class TestCensysDualKey:
    def test_enabled_needs_both_id_and_secret(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv("CENSYS_API_ID", "the-id")
        monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
        client = CensysClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False

        monkeypatch.setenv("CENSYS_API_SECRET", "the-secret")
        assert client.is_enabled() is True
