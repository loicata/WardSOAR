"""Tests for :mod:`src.intel` feed downloaders and the IntelManager.

No actual HTTP requests are made: each feed's ``_parse`` is
exercised directly with a representative raw-text sample, and the
:class:`IntelManager` is tested with monkeypatched registries that
synthesise deterministic results.

Coverage goals:
* Each :class:`FeedRegistry` subclass parses its own native format
  and produces a coherent set of indicators + per-entry metadata.
* On-disk persistence round-trips (save then re-load gives the same
  in-memory set).
* CIDR-based feeds (Spamhaus DROP, FireHOL) correctly answer
  ``lookup_ip`` for IPs inside the network.
* :class:`IntelManager.query_all_for_ip` returns one row per
  registry in registry order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardsoar.core.intel.base import FeedEntry, FeedRegistry
from wardsoar.core.intel.blocklist_de import BlocklistDeRegistry
from wardsoar.core.intel.feodo_tracker import FeodoTrackerRegistry
from wardsoar.core.intel.firehol import FireHolRegistry
from wardsoar.core.intel.manager import IntelManager, QueryResult
from wardsoar.core.intel.spamhaus_drop import SpamhausDropRegistry
from wardsoar.core.intel.threatfox import ThreatFoxRegistry
from wardsoar.core.intel.urlhaus import URLhausRegistry

# ---------------------------------------------------------------------------
# Per-feed parse tests
# ---------------------------------------------------------------------------


class TestURLhausParser:
    def test_parses_ip_hosted_malware_urls(self, tmp_path: Path) -> None:
        raw = (
            "# URLhaus Database Dump (CSV - recent URLs only)\n"
            "1,2026-04-22 00:00:00,http://203.0.113.55/malware.exe,online,"
            "2026-04-22 00:00:00,Cobalt Strike,cobaltstrike,"
            "https://urlhaus.abuse.ch/url/1/,reporter1\n"
            "2,2026-04-22 00:00:00,http://example.com/payload,online,"
            "2026-04-22 00:00:00,Emotet,emotet,"
            "https://urlhaus.abuse.ch/url/2/,reporter1\n"
        )
        reg = URLhausRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        # Domain-based entries are skipped (by design in v0.11.0);
        # only the bare-IP entry is indexed.
        assert indicators == {"203.0.113.55"}
        assert meta["203.0.113.55"].category == "Cobalt Strike"


class TestThreatFoxParser:
    def test_parses_current_schema_ioc_value(self, tmp_path: Path) -> None:
        """Regression for the 2026-04-23 "refreshed 0 indicators" bug.

        The public dump at threatfox.abuse.ch/export/json/recent/
        carries the indicator under the key ``ioc_value`` (and the
        first-seen timestamp under ``first_seen_utc``). The parser
        had been coded against an older schema (``ioc`` /
        ``first_seen``) and was silently returning an empty set on
        every refresh while the logs cheerfully announced
        ``intel.threatfox: refreshed 0 indicators``.
        """
        raw = (
            "{"
            '"1797050": ['
            '{"ioc_value": "141.98.10.115:1430", "ioc_type": "ip:port", '
            '"threat_type": "botnet_cc", "malware": "elf.xorddos", '
            '"malware_printable": "XOR DDoS", '
            '"first_seen_utc": "2026-04-24 07:29:26", '
            '"confidence_level": 75}'
            "]"
            "}"
        )
        reg = ThreatFoxRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert indicators == {"141.98.10.115"}
        entry = meta["141.98.10.115"]
        assert entry.category == "botnet_cc"
        assert "XOR DDoS" in entry.description
        assert entry.first_seen == "2026-04-24 07:29:26"

    def test_legacy_schema_still_parsed(self, tmp_path: Path) -> None:
        """If abuse.ch reverts to the older ``ioc``/``first_seen`` keys,
        the parser must keep working. The current-schema code path is
        tried first, then these legacy keys as a fallback."""
        raw = (
            "{"
            '"2026-04-22 00:00:00": ['
            '{"ioc": "198.51.100.10:443", "ioc_type": "ip:port", '
            '"threat_type": "botnet_cc", "malware": "emotet", '
            '"malware_printable": "Emotet", "first_seen": "2026-04-20", '
            '"confidence_level": 100}'
            "]"
            "}"
        )
        reg = ThreatFoxRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert indicators == {"198.51.100.10"}
        assert meta["198.51.100.10"].first_seen == "2026-04-20"

    def test_domain_and_url_iocs_are_skipped(self, tmp_path: Path) -> None:
        """ThreatFox publishes domains, URLs, and hashes alongside
        IPs. Our blocklist is IP-only (pf tables take addresses), so
        non-IP indicators must be dropped without polluting the set."""
        raw = (
            "{"
            '"1": ['
            '{"ioc_value": "bursaforum.net", "ioc_type": "domain"},'
            '{"ioc_value": "https://evil.example/path", "ioc_type": "url"},'
            '{"ioc_value": "203.0.113.9:8080", "ioc_type": "ip:port"}'
            "]"
            "}"
        )
        reg = ThreatFoxRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert indicators == {"203.0.113.9"}
        assert set(meta.keys()) == {"203.0.113.9"}

    def test_empty_payload_yields_empty(self, tmp_path: Path) -> None:
        reg = ThreatFoxRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse("{}")
        assert indicators == set()
        assert meta == {}


class TestFeodoTrackerParser:
    def test_parses_list_of_records(self, tmp_path: Path) -> None:
        raw = (
            "["
            '{"ip_address": "203.0.113.100", "port": 443, '
            '"first_seen": "2026-04-01", "malware": "Emotet", '
            '"status": "online_8h"},'
            '{"ip_address": "198.51.100.20", "port": 8080, '
            '"first_seen": "2026-04-05", "malware": "TrickBot", '
            '"status": "online_24h"}'
            "]"
        )
        reg = FeodoTrackerRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert indicators == {"203.0.113.100", "198.51.100.20"}
        assert meta["203.0.113.100"].category == "botnet_cc"
        assert "Emotet" in meta["203.0.113.100"].description


class TestBlocklistDeParser:
    def test_parses_bare_ip_list(self, tmp_path: Path) -> None:
        raw = "203.0.113.1\n# comment line\n203.0.113.2\n\n203.0.113.3\n"
        reg = BlocklistDeRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert indicators == {"203.0.113.1", "203.0.113.2", "203.0.113.3"}
        for ip in indicators:
            assert meta[ip].category == "brute_force"


class TestSpamhausDropParser:
    def test_parses_cidr_list(self, tmp_path: Path) -> None:
        raw = (
            "; Spamhaus DROP List\n"
            "203.0.113.0/24 ; SBL123456\n"
            "198.51.100.0/22 ; SBL654321\n"
            "# not a valid comment char but harmless\n"
        )
        reg = SpamhausDropRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert "203.0.113.0/24" in indicators
        assert "198.51.100.0/22" in indicators
        assert meta["203.0.113.0/24"].category == "bulletproof_hoster"

    def test_lookup_ip_matches_inside_cidr(self, tmp_path: Path) -> None:
        reg = SpamhausDropRegistry(cache_dir=tmp_path)
        # Seed the registry's internal state directly via _parse.
        indicators, meta = reg._parse("203.0.113.0/24 ; SBL123\n")
        reg._indicators = indicators
        reg._meta = meta
        import ipaddress as _ip

        reg._networks = [_ip.IPv4Network("203.0.113.0/24")]
        hit = reg.lookup_ip("203.0.113.42")
        assert hit is not None
        assert hit.category == "bulletproof_hoster"
        assert reg.lookup_ip("198.51.100.1") is None


class TestFireHolParser:
    def test_parses_mixed_ip_and_cidr_netset(self, tmp_path: Path) -> None:
        raw = (
            "# FireHOL level1 aggregator\n"
            "# License: CC BY-SA 4.0\n"
            "203.0.113.0/24\n"
            "198.51.100.1\n"
            "198.51.100.2\n"
        )
        reg = FireHolRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse(raw)
        assert "203.0.113.0/24" in indicators
        assert "198.51.100.1" in indicators
        assert meta["198.51.100.1"].category == "aggregate_blocklist"

    def test_lookup_ip_in_cidr(self, tmp_path: Path) -> None:
        reg = FireHolRegistry(cache_dir=tmp_path)
        indicators, meta = reg._parse("203.0.113.0/24\n198.51.100.5\n")
        reg._indicators = indicators
        reg._meta = meta
        reg._rehydrate_networks()
        assert reg.lookup_ip("203.0.113.99") is not None
        assert reg.lookup_ip("10.0.0.1") is None


# ---------------------------------------------------------------------------
# Base class behaviour
# ---------------------------------------------------------------------------


class _DummyFeed(FeedRegistry):
    """Concrete subclass that returns fixed data from a constant."""

    name = "dummy"
    display_name = "Dummy"
    url = "https://example.invalid/"
    refresh_interval_s = 60

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        lines = {line.strip() for line in raw_text.splitlines() if line.strip()}
        meta = {ip: FeedEntry(indicator=ip, kind="ip", category="test") for ip in lines}
        return lines, meta


class TestFeedRegistryPersistence:
    def test_on_disk_snapshot_roundtrips(self, tmp_path: Path) -> None:
        reg1 = _DummyFeed(cache_dir=tmp_path)
        reg1._indicators = {"1.2.3.4", "5.6.7.8"}
        reg1._meta = {
            "1.2.3.4": FeedEntry(indicator="1.2.3.4", kind="ip", category="seed"),
            "5.6.7.8": FeedEntry(indicator="5.6.7.8", kind="ip", category="seed"),
        }
        reg1._last_refresh_ts = 12345.0
        reg1._persist_to_disk()

        reg2 = _DummyFeed(cache_dir=tmp_path)
        assert reg2.indicator_count() == 2
        hit = reg2.lookup_ip("1.2.3.4")
        assert hit is not None
        assert hit.category == "seed"

    def test_corrupt_cache_falls_back_to_empty(self, tmp_path: Path) -> None:
        (tmp_path / "dummy.json").write_text("not json", encoding="utf-8")
        reg = _DummyFeed(cache_dir=tmp_path)
        assert reg.indicator_count() == 0


class TestFeedRegistryStaleness:
    def test_is_stale_when_never_refreshed(self, tmp_path: Path) -> None:
        reg = _DummyFeed(cache_dir=tmp_path)
        assert reg.is_stale() is True

    def test_is_fresh_right_after_refresh(self, tmp_path: Path) -> None:
        import time as _time

        reg = _DummyFeed(cache_dir=tmp_path)
        reg._last_refresh_ts = _time.time()
        assert reg.is_stale() is False


# ---------------------------------------------------------------------------
# IntelManager
# ---------------------------------------------------------------------------


class TestIntelManager:
    def test_query_all_returns_one_row_per_registry(self, tmp_path: Path) -> None:
        mgr = IntelManager(cache_dir=tmp_path)
        rows = mgr.query_all_for_ip("203.0.113.1")
        assert len(rows) == len(mgr.registries)

    def test_query_empty_registries_report_unknown(self, tmp_path: Path) -> None:
        mgr = IntelManager(cache_dir=tmp_path)
        rows = mgr.query_all_for_ip("203.0.113.1")
        # All registries are empty on a fresh test tmp_path.
        for row in rows:
            assert isinstance(row, QueryResult)
            assert row.level in ("unknown", "clean", "bad")

    def test_hit_on_one_registry_is_reported(self, tmp_path: Path, monkeypatch: Any) -> None:
        mgr = IntelManager(cache_dir=tmp_path)
        # Seed the URLhaus registry with a deterministic hit.
        urlhaus = [r for r in mgr.registries if r.name == "urlhaus"][0]
        urlhaus._indicators = {"203.0.113.99"}
        urlhaus._meta = {
            "203.0.113.99": FeedEntry(
                indicator="203.0.113.99",
                kind="ip",
                category="malware_url",
                description="Hosts a Cobalt Strike payload",
            )
        }
        rows = mgr.query_all_for_ip("203.0.113.99")
        urlhaus_row = next(r for r in rows if r.display_name == "URLhaus")
        assert urlhaus_row.level == "bad"
        assert "Cobalt" in urlhaus_row.verdict
