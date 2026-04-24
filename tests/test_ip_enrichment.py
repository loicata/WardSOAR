"""Tests for the v0.10.0 IP enrichment aggregator.

Covers the purely-local paths that don't need network I/O:
* Private / loopback / reserved IPs are correctly categorised and
  external lookups are skipped.
* Classifier outputs (CDN allowlist, suspect ASNs, bad actors) are
  surfaced into the ``classification`` sub-block and the final-tier
  logic picks the expected outcome.
* The history scan reads ``alerts_history.jsonl`` and aggregates
  counts, first/last seen, and the "ever blocked" flag.
* Manual-check URLs are formatted with the alert's IP.
* ``iso_to_human_delta`` handles valid / invalid / missing input.

Every external dependency (ASN cache, registries, feed downloaders)
is injected as a test stub so the suite runs offline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from src.ip_enrichment import (
    IpEnrichment,
    WardsoarHistory,
    build_ip_enrichment,
    iso_to_human_delta,
)

# ---------------------------------------------------------------------------
# Test stubs
# ---------------------------------------------------------------------------


@dataclass
class _FakeAsnInfo:
    asn: int
    name: str
    country: str
    org: str = ""


class _FakeCdnAllowlist:
    def __init__(self, matched_asn: Optional[int]) -> None:
        self._matched_asn = matched_asn

    def classify_asn(self, asn: Optional[int]) -> Any:
        if asn is not None and asn == self._matched_asn:
            # Match shape of the real CdnMatch dataclass.
            return type(
                "M",
                (),
                {"organisation": "Fastly", "category": "cdn", "asn": asn},
            )()
        return None


class _FakeSuspectAsnRegistry:
    def __init__(self, tier: str = "legitimate") -> None:
        self._tier = tier

    def classify(self, ip: str, info: Any) -> Any:
        return type("C", (), {"tier": self._tier})()


class _FakeBadActorRegistry:
    def __init__(self, label: Optional[str] = None) -> None:
        self._label = label

    def classify_ip(self, ip: str) -> Any:
        if self._label:
            return type("A", (), {"label": self._label})()
        return None


class _FakeTorExitRegistry:
    def __init__(self, exits: set[str]) -> None:
        self._exits = exits

    def contains(self, ip: str) -> bool:
        return ip in self._exits


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCategorisation:
    """Private / special-range IPs must skip external lookups."""

    def test_rfc1918_private_ip_is_private(self) -> None:
        result = build_ip_enrichment(
            "192.168.2.100",
            do_rdns=False,
        )
        assert result.identity.is_private is True
        # Private IPs must not be "Tor exit" — we shouldn't even ask.
        assert result.identity.is_tor_exit is False

    def test_loopback_is_private(self) -> None:
        result = build_ip_enrichment("127.0.0.1", do_rdns=False)
        assert result.identity.is_private is True

    def test_public_ip_is_not_private(self) -> None:
        result = build_ip_enrichment(
            "8.8.8.8",
            do_rdns=False,
        )
        assert result.identity.is_private is False


class TestAsnLookup:
    """ASN info comes from the injected cache lookup callable."""

    def test_asn_cache_hit_is_surfaced(self) -> None:
        def _cache(ip: str) -> _FakeAsnInfo:
            assert ip == "185.199.109.133"
            return _FakeAsnInfo(asn=54113, name="Fastly, Inc.", country="US")

        result = build_ip_enrichment(
            "185.199.109.133",
            asn_cache_lookup=_cache,
            do_rdns=False,
        )
        assert result.identity.asn == 54113
        assert result.identity.asn_name == "Fastly, Inc."
        assert result.identity.country == "US"

    def test_asn_cache_miss_returns_none_fields(self) -> None:
        result = build_ip_enrichment(
            "1.2.3.4",
            asn_cache_lookup=lambda ip: None,
            do_rdns=False,
        )
        assert result.identity.asn is None
        assert result.identity.asn_name is None


class TestClassification:
    """Classifier outputs feed the final-tier logic."""

    def test_cdn_match_yields_legit_tier(self) -> None:
        result = build_ip_enrichment(
            "185.199.109.133",
            asn_cache_lookup=lambda ip: _FakeAsnInfo(asn=54113, name="Fastly, Inc.", country="US"),
            cdn_allowlist=_FakeCdnAllowlist(matched_asn=54113),
            do_rdns=False,
        )
        assert result.classification.cdn_match is not None
        assert "Fastly" in result.classification.cdn_match
        assert result.classification.final_tier == "legit_cdn"

    def test_bad_actor_wins_over_cdn(self) -> None:
        """A known bad actor match MUST override a CDN allowlist hit
        so the operator is never lulled into a false sense of safety."""
        result = build_ip_enrichment(
            "185.199.109.133",
            asn_cache_lookup=lambda ip: _FakeAsnInfo(asn=54113, name="Fastly, Inc.", country="US"),
            cdn_allowlist=_FakeCdnAllowlist(matched_asn=54113),
            bad_actor_registry=_FakeBadActorRegistry(label="Ben-VPS-2026-04"),
            do_rdns=False,
        )
        assert result.classification.final_tier == "confirmed_bad"
        assert "Ben-VPS-2026-04" in result.classification.final_tier_reason

    def test_suspect_asn_when_no_other_match(self) -> None:
        result = build_ip_enrichment(
            "1.2.3.4",
            asn_cache_lookup=lambda ip: _FakeAsnInfo(asn=16276, name="OVH SAS", country="FR"),
            suspect_asn_registry=_FakeSuspectAsnRegistry(tier="suspect"),
            do_rdns=False,
        )
        assert result.classification.suspect_asn == "suspect"
        assert result.classification.final_tier == "suspect"

    def test_private_ip_has_private_local_tier(self) -> None:
        result = build_ip_enrichment("192.168.2.100", do_rdns=False)
        assert result.classification.final_tier == "private_local"


class TestTorExit:
    def test_tor_exit_flag_set_when_ip_matches(self) -> None:
        result = build_ip_enrichment(
            "1.2.3.4",
            tor_exit_registry=_FakeTorExitRegistry({"1.2.3.4"}),
            do_rdns=False,
        )
        assert result.identity.is_tor_exit is True

    def test_tor_exit_flag_false_when_ip_misses(self) -> None:
        result = build_ip_enrichment(
            "1.2.3.4",
            tor_exit_registry=_FakeTorExitRegistry({"9.9.9.9"}),
            do_rdns=False,
        )
        assert result.identity.is_tor_exit is False

    def test_tor_exit_not_checked_for_private_ip(self) -> None:
        """RFC 1918 IPs should never be asked against the Tor list."""

        class _BoomRegistry:
            def contains(self, ip: str) -> bool:
                raise AssertionError("Tor lookup ran for a private IP")

        result = build_ip_enrichment(
            "10.0.0.1",
            tor_exit_registry=_BoomRegistry(),
            do_rdns=False,
        )
        assert result.identity.is_tor_exit is False


class TestHistoryScan:
    """alerts_history.jsonl scan aggregates counts and first/last seen."""

    def _write(self, path: Path, rows: list[dict[str, Any]]) -> None:
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    def test_missing_file_returns_zero_history(self, tmp_path: Path) -> None:
        result = build_ip_enrichment(
            "1.2.3.4",
            history_path=tmp_path / "nope.jsonl",
            do_rdns=False,
        )
        assert result.history == WardsoarHistory()

    def test_aggregates_counts_for_matching_ip(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        self._write(
            history,
            [
                {
                    "src_ip": "1.2.3.4",
                    "dest_ip": "192.168.2.100",
                    "verdict": "filtered",
                    "_ts": "2026-04-20T12:00:00+00:00",
                    "actions": [],
                },
                {
                    "src_ip": "1.2.3.4",
                    "dest_ip": "192.168.2.100",
                    "verdict": "benign",
                    "_ts": "2026-04-22T08:00:00+00:00",
                    "actions": ["none"],
                },
                {
                    "src_ip": "9.9.9.9",
                    "dest_ip": "192.168.2.100",
                    "verdict": "confirmed",
                    "_ts": "2026-04-21T09:00:00+00:00",
                    "actions": ["ip_block"],
                },
            ],
        )
        result = build_ip_enrichment(
            "1.2.3.4",
            history_path=history,
            do_rdns=False,
        )
        assert result.history.total_alerts == 2
        assert result.history.first_seen == "2026-04-20T12:00:00+00:00"
        assert result.history.last_seen == "2026-04-22T08:00:00+00:00"
        assert result.history.breakdown == {"filtered": 1, "benign": 1}
        assert result.history.ever_blocked is False

    def test_ever_blocked_flag_is_true_when_ip_block_action(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        self._write(
            history,
            [
                {
                    "src_ip": "5.6.7.8",
                    "verdict": "confirmed",
                    "_ts": "2026-04-22T09:00:00+00:00",
                    "actions": ["ip_block"],
                }
            ],
        )
        result = build_ip_enrichment(
            "5.6.7.8",
            history_path=history,
            do_rdns=False,
        )
        assert result.history.ever_blocked is True

    def test_corrupt_history_line_is_skipped(self, tmp_path: Path) -> None:
        history = tmp_path / "alerts_history.jsonl"
        with history.open("w", encoding="utf-8") as fh:
            fh.write("this is not JSON\n")
            fh.write(
                json.dumps(
                    {
                        "src_ip": "7.7.7.7",
                        "verdict": "filtered",
                        "_ts": "2026-04-22T09:00:00+00:00",
                    }
                )
                + "\n"
            )
        result = build_ip_enrichment(
            "7.7.7.7",
            history_path=history,
            do_rdns=False,
        )
        assert result.history.total_alerts == 1


class TestManualChecks:
    """The 7 browser click-through URLs are formatted with the IP."""

    def test_manual_checks_contain_formatted_ip(self) -> None:
        result = build_ip_enrichment(
            "8.8.8.8",
            do_rdns=False,
        )
        assert len(result.manual_checks) == 7
        names = [m["name"] for m in result.manual_checks]
        assert "Cisco Talos" in names
        assert "SANS ISC / DShield" in names
        assert "Pulsedive" in names
        for m in result.manual_checks:
            assert "8.8.8.8" in m["url"]

    def test_manual_checks_relevance_tags(self) -> None:
        result = build_ip_enrichment("8.8.8.8", do_rdns=False)
        tags = {m["relevance"] for m in result.manual_checks}
        assert tags == {"high", "medium"}


class TestIsoToHumanDelta:
    def test_none_returns_empty_string(self) -> None:
        assert iso_to_human_delta(None) == ""

    def test_empty_returns_empty_string(self) -> None:
        assert iso_to_human_delta("") == ""

    def test_invalid_returns_input_unchanged(self) -> None:
        assert iso_to_human_delta("not-a-date") == "not-a-date"

    def test_valid_iso_renders_absolute_and_delta(self) -> None:
        out = iso_to_human_delta("2026-04-20T12:00:00+00:00")
        assert "2026-04-20 12:00 UTC" in out
        assert "ago" in out or "today" in out


class TestToDict:
    """The snapshot must be JSON-serialisable for persistence."""

    def test_to_dict_is_json_round_trippable(self) -> None:
        result = build_ip_enrichment(
            "8.8.8.8",
            asn_cache_lookup=lambda ip: _FakeAsnInfo(asn=15169, name="Google LLC", country="US"),
            do_rdns=False,
        )
        assert isinstance(result, IpEnrichment)
        payload = result.to_dict()
        round_tripped = json.loads(json.dumps(payload))
        assert round_tripped["ip"] == "8.8.8.8"
        assert round_tripped["identity"]["asn"] == 15169
        assert isinstance(round_tripped["reputation"], list)
        assert isinstance(round_tripped["manual_checks"], list)
