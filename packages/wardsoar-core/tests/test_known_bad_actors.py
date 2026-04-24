"""Tests for Phase 4.6 — known adversary IOC registry.

Covers two surfaces:

* ``wardsoar.core.known_bad_actors.KnownActorsRegistry`` — YAML loader and
  lookup API (exact IP, CIDR, domain).
* ``wardsoar.core.prescorer.AlertPreScorer`` — the new ``known_bad_actor``
  factor: a single match must add the actor's weight and, at the
  weights shipped in ``known_bad_actors.yaml`` (100), single-handedly
  push the total past ``min_score_for_analysis`` so Opus adjudicates.

The YAML is always built in a ``tmp_path`` — we never touch the
repository copy from tests, so operator-specific IOCs stay out of
CI fixtures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.core.known_bad_actors import ActorMatch, KnownActorsRegistry
from wardsoar.core.models import SuricataAlert, SuricataAlertSeverity
from wardsoar.core.prescorer import AlertPreScorer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


SAMPLE_YAML = """\
schema_version: "1"

actors:
  - id: "ACME-2026-001"
    name: "Test Adversary"
    weight: 100
    reason: "Confirmed adversary per test fixture"
    ips:
      - "203.0.113.4"
    cidrs:
      - "198.51.100.0/24"
    domains:
      - "evil.example"
      - "Attack.Example"
"""


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "known_bad_actors.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _make_alert(src_ip: str = "198.51.100.42") -> SuricataAlert:
    return SuricataAlert(
        timestamp=datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=55555,
        dest_ip="192.168.2.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET SCAN",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.LOW,
    )


# ---------------------------------------------------------------------------
# Registry loader — robustness against bad inputs
# ---------------------------------------------------------------------------


class TestRegistryLoader:
    """An empty registry is always safe: classify_* must return None."""

    def test_missing_file_yields_empty_registry(self, tmp_path: Path) -> None:
        reg = KnownActorsRegistry(tmp_path / "does-not-exist.yaml")
        assert reg.classify_ip("203.0.113.4") is None
        assert reg.classify_domain("evil.example") is None
        assert reg.snapshot() == []

    def test_malformed_yaml_yields_empty_registry(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "actors: [not-a-dict\n  missing_bracket")
        reg = KnownActorsRegistry(path)
        assert reg.snapshot() == []

    def test_top_level_not_dict_is_ignored(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "- just\n- a\n- list\n")
        reg = KnownActorsRegistry(path)
        assert reg.snapshot() == []

    def test_non_dict_actor_entries_are_skipped(self, tmp_path: Path) -> None:
        body = """\
actors:
  - "just-a-string"
  - id: "ONE"
    name: "Valid"
    weight: 50
    reason: "ok"
    ips: ["203.0.113.4"]
"""
        reg = KnownActorsRegistry(_write_yaml(tmp_path, body))
        snap = reg.snapshot()
        assert len(snap) == 1
        assert snap[0]["id"] == "ONE"

    def test_weight_coerces_int_and_defaults_on_garbage(self, tmp_path: Path) -> None:
        body = """\
actors:
  - id: "BAD-WEIGHT"
    name: "x"
    weight: "not-a-number"
    reason: "x"
    ips: ["203.0.113.4"]
"""
        reg = KnownActorsRegistry(_write_yaml(tmp_path, body))
        match = reg.classify_ip("203.0.113.4")
        assert match is not None
        assert match.weight == 0

    def test_invalid_ip_strings_are_dropped_silently(self, tmp_path: Path) -> None:
        body = """\
actors:
  - id: "ONE"
    name: "x"
    weight: 10
    reason: "x"
    ips:
      - "not-an-ip"
      - "203.0.113.4"
    cidrs:
      - "not-a-cidr"
      - "198.51.100.0/24"
"""
        reg = KnownActorsRegistry(_write_yaml(tmp_path, body))
        snap = reg.snapshot()[0]
        # One valid IP, one valid CIDR — bad entries silently skipped.
        assert snap["ips"] == 1
        assert snap["cidrs"] == 1


# ---------------------------------------------------------------------------
# classify_ip — exact + CIDR
# ---------------------------------------------------------------------------


class TestClassifyIp:
    """Lookup must succeed on exact IP, match inside the CIDR, and
    return None for anything else. Invalid inputs are safe no-ops."""

    @pytest.fixture
    def registry(self, tmp_path: Path) -> KnownActorsRegistry:
        return KnownActorsRegistry(_write_yaml(tmp_path, SAMPLE_YAML))

    def test_exact_ip_match(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_ip("203.0.113.4")
        assert isinstance(match, ActorMatch)
        assert match.actor_id == "ACME-2026-001"
        assert match.matched_by == "ip"
        assert match.matched_value == "203.0.113.4"
        assert match.weight == 100

    def test_cidr_match(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_ip("198.51.100.77")
        assert match is not None
        assert match.matched_by == "cidr"
        assert match.matched_value == "198.51.100.0/24"

    def test_outside_cidr_no_match(self, registry: KnownActorsRegistry) -> None:
        assert registry.classify_ip("198.51.101.1") is None

    def test_empty_ip_returns_none(self, registry: KnownActorsRegistry) -> None:
        assert registry.classify_ip("") is None

    def test_invalid_ip_returns_none(self, registry: KnownActorsRegistry) -> None:
        assert registry.classify_ip("not-an-ip") is None

    def test_exact_wins_over_cidr_when_both_defined(self, tmp_path: Path) -> None:
        body = """\
actors:
  - id: "ONE"
    name: "first"
    weight: 5
    reason: "x"
    ips: ["198.51.100.42"]
    cidrs: ["198.51.100.0/24"]
"""
        reg = KnownActorsRegistry(_write_yaml(tmp_path, body))
        match = reg.classify_ip("198.51.100.42")
        assert match is not None
        # Exact-IP entries iterate before CIDRs inside the actor.
        assert match.matched_by == "ip"

    def test_first_actor_wins_on_overlap(self, tmp_path: Path) -> None:
        body = """\
actors:
  - id: "FIRST"
    name: "first"
    weight: 10
    reason: "x"
    cidrs: ["198.51.100.0/24"]
  - id: "SECOND"
    name: "second"
    weight: 20
    reason: "x"
    cidrs: ["198.51.100.0/24"]
"""
        reg = KnownActorsRegistry(_write_yaml(tmp_path, body))
        match = reg.classify_ip("198.51.100.1")
        assert match is not None
        assert match.actor_id == "FIRST"


# ---------------------------------------------------------------------------
# classify_domain
# ---------------------------------------------------------------------------


class TestClassifyDomain:
    """Domain lookup is exact but case-insensitive and tolerant of a
    trailing dot (DNS canonical form)."""

    @pytest.fixture
    def registry(self, tmp_path: Path) -> KnownActorsRegistry:
        return KnownActorsRegistry(_write_yaml(tmp_path, SAMPLE_YAML))

    def test_lowercase_match(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_domain("evil.example")
        assert match is not None
        assert match.matched_by == "domain"

    def test_uppercase_input_is_normalised(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_domain("EVIL.EXAMPLE")
        assert match is not None

    def test_yaml_casing_is_normalised(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_domain("attack.example")
        assert match is not None
        assert match.matched_value == "attack.example"

    def test_trailing_dot_is_stripped(self, registry: KnownActorsRegistry) -> None:
        match = registry.classify_domain("evil.example.")
        assert match is not None

    def test_subdomain_is_not_implicit(self, registry: KnownActorsRegistry) -> None:
        assert registry.classify_domain("foo.evil.example") is None

    def test_empty_domain_returns_none(self, registry: KnownActorsRegistry) -> None:
        assert registry.classify_domain("") is None


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------


class TestReload:
    """reload() must pick up on-disk edits without restarting the app."""

    def test_reload_picks_up_new_entry(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "actors: []\n")
        reg = KnownActorsRegistry(path)
        assert reg.snapshot() == []

        path.write_text(SAMPLE_YAML, encoding="utf-8")
        reg.reload()

        assert reg.classify_ip("203.0.113.4") is not None


# ---------------------------------------------------------------------------
# Shipped YAML — smoke test
# ---------------------------------------------------------------------------


def test_shipped_yaml_loads_cleanly() -> None:
    """The YAML in the repo must parse — otherwise the release is bricked.

    This test loads ``config/known_bad_actors.yaml`` directly and
    checks the registry ends up non-empty. It is a smoke test, not a
    value assertion: the operator edits that file, and CI should not
    flag their edits. We only assert the file still parses as YAML
    with at least one actor.
    """
    repo_root = Path(__file__).resolve().parent.parent
    yaml_path = repo_root / "config" / "known_bad_actors.yaml"
    if not yaml_path.is_file():
        pytest.skip("shipped known_bad_actors.yaml not present in this checkout")

    reg = KnownActorsRegistry(yaml_path)
    snap = reg.snapshot()
    assert len(snap) >= 1, "shipped known_bad_actors.yaml parsed to zero entries"


# ===========================================================================
# PreScorer integration — the factor that actually triggers Opus
# ===========================================================================


DEFAULT_WEIGHTS = {
    "severity_1": 40,
    "severity_2": 25,
    "severity_3": 10,
    "ip_known_malicious": 30,
    "ip_unknown": 10,
    "multiple_signatures": 20,
    "suspicious_port": 15,
    "sysmon_process_match": 25,
    "outside_business_hours": 10,
    "burst_alert": 20,
}


def _prescorer(mode: str = "active", threshold: int = 30) -> AlertPreScorer:
    return AlertPreScorer(
        {
            "enabled": True,
            "mode": mode,
            "min_score_for_analysis": threshold,
            "min_guaranteed_score": 10,
            "weights": DEFAULT_WEIGHTS,
            "log_all_scores": False,
        }
    )


def _actor_match(weight: int = 100) -> ActorMatch:
    return ActorMatch(
        actor_id="TEST-001",
        name="Test Adversary",
        weight=weight,
        reason="Unit test fixture",
        matched_by="ip",
        matched_value="203.0.113.4",
    )


class TestPreScorerKnownActor:
    """A known-actor match must surface as its own factor and the
    weight must land on the total score exactly as configured."""

    def test_factor_is_named_known_bad_actor(self) -> None:
        result = _prescorer().score(_make_alert(), known_actor_match=_actor_match(100))
        assert "known_bad_actor" in result.factors
        assert result.factors["known_bad_actor"] == 100

    def test_known_actor_alone_crosses_threshold(self) -> None:
        """weight=100 on an otherwise-quiet alert must fire Opus in
        active mode at the documented threshold (30)."""
        # Severity 3 only scores 10 — well below the 30 threshold.
        alert = _make_alert()
        no_match = _prescorer(threshold=30).score(alert)
        assert no_match.total_score < 30

        with_match = _prescorer(threshold=30).score(alert, known_actor_match=_actor_match(100))
        assert with_match.total_score >= 30
        assert with_match.should_analyze is True
        assert with_match.was_filtered is False

    def test_no_match_leaves_factor_absent(self) -> None:
        result = _prescorer().score(_make_alert(), known_actor_match=None)
        assert "known_bad_actor" not in result.factors

    def test_low_weight_actor_still_contributes(self) -> None:
        """If the operator grades an actor at a reduced weight (e.g.
        former infrastructure), the match still counts — it just may
        not cross the threshold alone."""
        result = _prescorer(threshold=30).score(_make_alert(), known_actor_match=_actor_match(5))
        assert result.factors["known_bad_actor"] == 5
