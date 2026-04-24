"""Tests for Phase 4.5 threat-actor-aware scoring.

Covers three modules:
    - src.asn_enricher      (IP → ASN resolver + SQLite cache)
    - src.suspect_asns      (YAML registry + Tor exit handling)
    - src.prescorer         (new anonymization_risk factor)

Network I/O is mocked everywhere; real lookups would be flaky and
leak operator IP data to a third party during CI.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.asn_enricher import AsnEnricher, AsnInfo, NullAsnEnricher, dataclass_to_dict
from wardsoar.core.models import SuricataAlert, SuricataAlertSeverity
from wardsoar.core.prescorer import AlertPreScorer
from wardsoar.core.suspect_asns import (
    AsnClassification,
    SuspectAsnRegistry,
    TorExitFetcher,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


VPN_INFO = AsnInfo(asn=9009, name="M247 Ltd", country="GB", source="ipinfo")
DATACENTER_INFO = AsnInfo(asn=14061, name="DigitalOcean", country="US", source="ipinfo")
UNKNOWN_INFO = AsnInfo(asn=99999, name="Nowhere ISP", country="FR", source="ipinfo")


def _make_alert(src_ip: str = "185.159.157.1") -> SuricataAlert:
    return SuricataAlert(
        timestamp=datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=55555,
        dest_ip="192.168.2.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET SCAN",
        alert_signature_id=1234,
        alert_severity=SuricataAlertSeverity.LOW,
    )


# ===========================================================================
# AsnEnricher — cache behaviour
# ===========================================================================


class TestAsnEnricherCache:
    """The cache layer must be correct on hit, miss, and expiry."""

    @pytest.mark.asyncio
    async def test_lookup_returns_cached_info_without_network(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")
        # Pre-seed the cache via the private write path and confirm that
        # the public lookup returns it without calling any backend.
        enricher._cache_store("1.2.3.4", VPN_INFO)  # noqa: SLF001 — test only

        with (
            patch.object(enricher, "_query_ipinfo", AsyncMock()) as mock_http,
            patch.object(enricher, "_query_cymru", AsyncMock()) as mock_cymru,
        ):
            info = await enricher.lookup("1.2.3.4")

        assert info is not None
        assert info.asn == 9009
        assert info.source == "cache"
        mock_http.assert_not_awaited()
        mock_cymru.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_expired_entry_triggers_refresh(self, tmp_path: Path) -> None:
        """After the TTL elapses, a re-query happens."""
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db", ttl_seconds=0)
        enricher._cache_store("1.2.3.4", VPN_INFO)  # noqa: SLF001
        time.sleep(1.1)

        fresh = AsnInfo(asn=9009, name="M247 refreshed", country="GB", source="ipinfo")
        with patch.object(enricher, "_query_ipinfo", AsyncMock(return_value=fresh)):
            info = await enricher.lookup("1.2.3.4")

        assert info == fresh

    @pytest.mark.asyncio
    async def test_empty_ip_returns_none(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")
        assert await enricher.lookup("") is None


# ===========================================================================
# AsnEnricher — fallback cascade
# ===========================================================================


class TestAsnEnricherCascade:
    """When ipinfo fails we drop through to Team Cymru."""

    @pytest.mark.asyncio
    async def test_cymru_fallback_when_ipinfo_none(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")
        cymru_result = AsnInfo(asn=9009, name="M247", country="GB", source="cymru")

        with (
            patch.object(enricher, "_query_ipinfo", AsyncMock(return_value=None)),
            patch.object(enricher, "_query_cymru", AsyncMock(return_value=cymru_result)),
        ):
            info = await enricher.lookup("2.3.4.5")

        assert info == cymru_result

    @pytest.mark.asyncio
    async def test_both_sources_fail_returns_none(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")
        with (
            patch.object(enricher, "_query_ipinfo", AsyncMock(return_value=None)),
            patch.object(enricher, "_query_cymru", AsyncMock(return_value=None)),
        ):
            info = await enricher.lookup("2.3.4.5")
        assert info is None


# ===========================================================================
# AsnEnricher — Team Cymru response parser
# ===========================================================================


class TestCymruParser:
    """The bulk-verbose response format is stable; our parser must be robust."""

    def test_parses_typical_verbose_line(self) -> None:
        raw = (
            "Bulk mode; whois.cymru.com [2024-01-01 00:00:00 +0000]\n"
            "9009 | 185.159.157.1 | 185.159.157.0/24 | GB | ripencc | M247 LTD\n"
        )
        info = AsnEnricher._parse_cymru_response(raw)
        assert info is not None
        assert info.asn == 9009
        assert info.country == "GB"
        assert "M247" in info.name
        assert info.source == "cymru"

    def test_returns_none_on_garbage(self) -> None:
        assert AsnEnricher._parse_cymru_response("not a valid response") is None


# ===========================================================================
# AsnEnricher — ipinfo.io parser
# ===========================================================================


class TestIpinfoParser:
    """ipinfo's free tier returns "org" as a combined AS+name string."""

    @pytest.mark.asyncio
    async def test_free_tier_org_parsed(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {
            "org": "AS9009 M247 Ltd",
            "country": "GB",
        }

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fake_response)

        with patch("wardsoar.core.asn_enricher.httpx.AsyncClient", return_value=mock_client):
            info = await enricher._query_ipinfo("185.159.157.1")  # noqa: SLF001

        assert info is not None
        assert info.asn == 9009
        assert info.country == "GB"
        assert info.source == "ipinfo"

    @pytest.mark.asyncio
    async def test_paid_tier_asn_object(self, tmp_path: Path) -> None:
        enricher = AsnEnricher(cache_path=tmp_path / "asn.db")

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {
            "asn": {"asn": "AS9009", "name": "M247 Ltd"},
            "country": "GB",
        }

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fake_response)

        with patch("wardsoar.core.asn_enricher.httpx.AsyncClient", return_value=mock_client):
            info = await enricher._query_ipinfo("185.159.157.1")  # noqa: SLF001

        assert info is not None
        assert info.asn == 9009


# ===========================================================================
# NullAsnEnricher — always returns None
# ===========================================================================


class TestNullEnricher:
    """The null enricher exists so callers can skip network I/O cleanly."""

    @pytest.mark.asyncio
    async def test_always_none(self) -> None:
        enricher = NullAsnEnricher()
        assert await enricher.lookup("1.1.1.1") is None


# ===========================================================================
# SuspectAsnRegistry — YAML loading + classification
# ===========================================================================


YAML_WITH_M247 = """
priority_countries: ["GB"]
priority_country_bonus: 10
categories:
  tor_exit:
    weight: 40
    asns: []
  vpn_provider:
    weight: 35
    asns:
      - { asn: 9009, name: "M247 Ltd", country: "GB" }
  datacenter_generic:
    weight: 15
    asns:
      - { asn: 14061, name: "DigitalOcean", country: "US" }
"""


class TestSuspectAsnRegistry:
    """Loading the YAML and classifying ASN info."""

    def test_missing_file_stays_empty(self, tmp_path: Path) -> None:
        registry = SuspectAsnRegistry(config_path=tmp_path / "missing.yaml")
        cls = registry.classify("8.8.8.8", VPN_INFO)
        assert cls.category == "unknown"
        assert cls.weight == 0

    def test_classifies_vpn_with_country_bonus(self, tmp_path: Path) -> None:
        path = tmp_path / "suspect.yaml"
        path.write_text(YAML_WITH_M247, encoding="utf-8")

        registry = SuspectAsnRegistry(config_path=path)
        cls = registry.classify("185.159.157.1", VPN_INFO)
        assert cls.category == "vpn_provider"
        assert cls.weight == 35
        assert cls.priority_country_bonus == 10
        assert cls.total_weight == 45
        assert cls.matched_asn == 9009

    def test_datacenter_without_priority_bonus(self, tmp_path: Path) -> None:
        path = tmp_path / "suspect.yaml"
        path.write_text(YAML_WITH_M247, encoding="utf-8")

        registry = SuspectAsnRegistry(config_path=path)
        cls = registry.classify("8.8.8.8", DATACENTER_INFO)
        assert cls.category == "datacenter_generic"
        assert cls.weight == 15
        assert cls.priority_country_bonus == 0

    def test_unknown_asn_returns_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "suspect.yaml"
        path.write_text(YAML_WITH_M247, encoding="utf-8")

        registry = SuspectAsnRegistry(config_path=path)
        cls = registry.classify("203.0.113.7", UNKNOWN_INFO)
        assert cls.category == "unknown"
        assert cls.weight == 0

    def test_tor_exit_wins_even_without_asn_info(self, tmp_path: Path) -> None:
        path = tmp_path / "suspect.yaml"
        path.write_text(YAML_WITH_M247, encoding="utf-8")
        registry = SuspectAsnRegistry(config_path=path)
        registry.set_tor_exits({"185.100.87.253"})

        cls = registry.classify("185.100.87.253", None)
        assert cls.category == "tor_exit"
        assert cls.weight == 40

    def test_set_tor_exits_rejects_malformed_ips(self, tmp_path: Path) -> None:
        path = tmp_path / "suspect.yaml"
        path.write_text(YAML_WITH_M247, encoding="utf-8")
        registry = SuspectAsnRegistry(config_path=path)

        registry.set_tor_exits({"1.2.3.4", "not-an-ip", "256.1.1.1"})
        assert registry.classify("1.2.3.4", None).category == "tor_exit"
        assert registry.classify("not-an-ip", None).category == "unknown"


# ===========================================================================
# TorExitFetcher
# ===========================================================================


class TestTorExitFetcher:
    """Fetcher respects the refresh interval and pushes IPs to the registry."""

    @pytest.mark.asyncio
    async def test_force_refresh_pushes_list(self, tmp_path: Path) -> None:
        registry = SuspectAsnRegistry(config_path=tmp_path / "x.yaml")
        fetcher = TorExitFetcher(registry=registry, interval_hours=1)

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.text = "1.1.1.1\n2.2.2.2\n\n"

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fake_response)

        with patch("wardsoar.core.suspect_asns.httpx.AsyncClient", return_value=mock_client):
            count = await fetcher.refresh(force=True)

        assert count == 2
        assert registry.classify("1.1.1.1", None).category == "tor_exit"

    @pytest.mark.asyncio
    async def test_refresh_respects_interval(self, tmp_path: Path) -> None:
        """Calling refresh twice in a row within the interval is a no-op."""
        registry = SuspectAsnRegistry(config_path=tmp_path / "x.yaml")
        fetcher = TorExitFetcher(registry=registry, interval_hours=1)

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.text = "1.1.1.1"
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fake_response)

        with patch("wardsoar.core.suspect_asns.httpx.AsyncClient", return_value=mock_client):
            assert await fetcher.refresh(force=True) == 1
            # Second call: should skip without hitting the network.
            assert await fetcher.refresh() == 0


# ===========================================================================
# PreScorer — new anonymization_risk factor
# ===========================================================================


class TestPreScorerAsnIntegration:
    """The PreScorer must honour the new asn_classification argument."""

    def _config(self, threshold: int = 30) -> dict:
        return {
            "enabled": True,
            "mode": "active",
            "min_score_for_analysis": threshold,
            "weights": {"severity_1": 40, "severity_2": 25, "severity_3": 10},
            "log_all_scores": False,
        }

    def test_no_classification_means_no_bonus(self) -> None:
        scorer = AlertPreScorer(self._config())
        result = scorer.score(_make_alert())
        assert "anonymization_risk" not in result.factors

    def test_vpn_classification_passes_threshold(self) -> None:
        scorer = AlertPreScorer(self._config())
        cls = AsnClassification(
            category="vpn_provider",
            weight=35,
            priority_country_bonus=10,
            matched_asn=9009,
            matched_name="M247 Ltd",
        )

        result = scorer.score(_make_alert(), asn_classification=cls)

        assert result.factors.get("anonymization_risk") == 35
        assert result.factors.get("priority_country") == 10
        # Low-severity alert (+10) + VPN (+35) + priority (+10) = 55 ≥ 30.
        assert result.should_analyze is True

    def test_zero_weight_classification_is_noop(self) -> None:
        scorer = AlertPreScorer(self._config())
        cls = AsnClassification(category="unknown", weight=0)
        result = scorer.score(_make_alert(), asn_classification=cls)
        assert "anonymization_risk" not in result.factors


# ===========================================================================
# Helpers
# ===========================================================================


class TestHelpers:
    """Small utility functions."""

    def test_dataclass_to_dict_roundtrip(self) -> None:
        assert dataclass_to_dict(None) == {}
        d = dataclass_to_dict(VPN_INFO)
        assert d["asn"] == 9009
        assert d["country"] == "GB"
        assert d["source"] == "ipinfo"
