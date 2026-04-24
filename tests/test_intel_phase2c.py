"""Tests for the Phase 2c clients (IBM X-Force + Project Honey Pot +
ipinfo pro tier).

Every test avoids real network traffic: clients are exercised via
``_verdict_from_raw`` (parsing only) and ``is_enabled`` (env-var
gating). The DNSBL transport in ProjectHoneyPotClient is tested
via its ``_verdict_from_raw`` + the ``_reverse_ip`` helper.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from src.intel.honeypot import ProjectHoneyPotClient, _reverse_ip, _visitor_type_label
from src.intel.http_client_base import IpReputationCache
from src.intel.ipinfo_pro import IpinfoProClient
from src.intel.xforce import XForceClient

# ---------------------------------------------------------------------------
# IBM X-Force
# ---------------------------------------------------------------------------


class TestXForceParser:
    def _cli(self, tmp_path: Path) -> XForceClient:
        return XForceClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_unknown_ip(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unknown": True})
        assert v.level == "unknown"

    def test_low_score_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"score": 1.0, "cats": {"Regional Internet Registry": 100}}
        )
        assert v.level == "clean"
        assert "1.0" in v.verdict

    def test_high_score_with_category(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "score": 8.5,
                "cats": {"Botnet_C_and_C_Servers": 80, "Spam": 40},
            }
        )
        assert v.level == "bad"
        # Spaces replace underscores in the displayed label.
        assert "Botnet C and C Servers" in v.verdict

    def test_medium_score_is_warn(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"score": 4.5, "cats": {"Spam": 30}})
        assert v.level == "warn"


class TestXForceDualKey:
    def test_enabled_needs_both_keys(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv("XFORCE_API_KEY", "user-key")
        monkeypatch.delenv("XFORCE_API_PASSWORD", raising=False)
        client = XForceClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False, "Both secrets are required"

        monkeypatch.setenv("XFORCE_API_PASSWORD", "secret")
        assert client.is_enabled() is True


# ---------------------------------------------------------------------------
# Project Honey Pot
# ---------------------------------------------------------------------------


class TestReverseIp:
    def test_ipv4_reversed(self) -> None:
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_invalid_returns_none(self) -> None:
        assert _reverse_ip("not-an-ip") is None

    def test_ipv6_returns_none(self) -> None:
        assert _reverse_ip("2001:db8::1") is None


class TestVisitorTypeLabel:
    def test_search_engine(self) -> None:
        assert _visitor_type_label(0) == "search engine"

    def test_suspicious_bit(self) -> None:
        assert _visitor_type_label(1) == "suspicious"

    def test_harvester_bit(self) -> None:
        assert _visitor_type_label(2) == "harvester"

    def test_comment_spammer_bit(self) -> None:
        assert _visitor_type_label(4) == "comment spammer"

    def test_combined(self) -> None:
        assert _visitor_type_label(7) == "suspicious + harvester + comment spammer"


class TestHoneyPotParser:
    def _cli(self, tmp_path: Path) -> ProjectHoneyPotClient:
        return ProjectHoneyPotClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_not_listed_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_not_listed": True})
        assert v.level == "clean"
        assert "Not listed" in v.verdict

    def test_ipv6_unsupported(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unsupported": True})
        assert v.level == "unknown"

    def test_high_threat_is_bad(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"days": 2, "threat": 200, "visitor_type": 4, "raw_answer": "127.2.200.4"}
        )
        assert v.level == "bad"
        assert "comment spammer" in v.verdict
        assert "200/255" in v.verdict

    def test_medium_threat_is_warn(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"days": 10, "threat": 64, "visitor_type": 2, "raw_answer": "127.10.64.2"}
        )
        assert v.level == "warn"
        assert "harvester" in v.verdict


# ---------------------------------------------------------------------------
# ipinfo.io pro tier
# ---------------------------------------------------------------------------


class TestIpinfoProPrivacy:
    def _cli(self, tmp_path: Path) -> IpinfoProClient:
        return IpinfoProClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_all_flags_false_returns_false(self, tmp_path: Path) -> None:
        raw = {
            "privacy": {
                "vpn": False,
                "proxy": False,
                "tor": False,
                "relay": False,
                "hosting": False,
            }
        }
        assert IpinfoProClient._privacy_bool_from_raw(raw) is False

    def test_any_flag_true_returns_true(self, tmp_path: Path) -> None:
        raw = {
            "privacy": {
                "vpn": False,
                "proxy": True,  # single hit is enough
                "tor": False,
                "relay": False,
                "hosting": False,
            }
        }
        assert IpinfoProClient._privacy_bool_from_raw(raw) is True

    def test_missing_privacy_dict_returns_none(self, tmp_path: Path) -> None:
        assert IpinfoProClient._privacy_bool_from_raw({}) is None

    def test_disabled_when_env_empty(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv("IPINFO_API_KEY", raising=False)
        client = self._cli(tmp_path)
        assert client.is_enabled() is False

    def test_is_vpn_or_proxy_returns_none_when_disabled(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.delenv("IPINFO_API_KEY", raising=False)
        client = self._cli(tmp_path)
        result = asyncio.new_event_loop().run_until_complete(client.is_vpn_or_proxy("1.2.3.4"))
        assert result is None


# ---------------------------------------------------------------------------
# End-to-end: query_ip cache hit through stubbed fetcher
# ---------------------------------------------------------------------------


class _FakeXForce(XForceClient):
    def __init__(self, cache: IpReputationCache, payload: dict[str, Any]) -> None:
        super().__init__(cache=cache)
        self._payload = payload

    async def _fetch_raw(self, ip: str, api_key: str) -> Any:
        return self._payload


@pytest.mark.asyncio
async def test_xforce_cache_hit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("XFORCE_API_KEY", "key")
    monkeypatch.setenv("XFORCE_API_PASSWORD", "pw")
    payload = {"score": 7.0, "cats": {"Malware": 90}}
    cache = IpReputationCache(db_path=tmp_path / "r.db")
    client = _FakeXForce(cache=cache, payload=payload)
    v1 = await client.query_ip("203.0.113.5")
    assert v1 is not None and v1.level == "bad"

    async def _boom(ip: str, key: str) -> Any:
        raise AssertionError("Second call should hit cache")

    client._fetch_raw = _boom  # type: ignore[method-assign]
    v2 = await client.query_ip("203.0.113.5")
    assert v2 is not None and v2.level == "bad"
