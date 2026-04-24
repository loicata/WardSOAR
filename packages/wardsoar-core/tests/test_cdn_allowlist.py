"""Tests for Phase 7e — CDN / major-SaaS allowlist.

Two surfaces:

* :class:`wardsoar.core.cdn_allowlist.CdnAllowlist` — YAML loader + ASN lookup.
* :class:`wardsoar.core.responder.ThreatResponder` — the Hard-Protect bypass
  that swaps to Protect semantics when the source IP's ASN matches
  the allowlist. Verified both as a policy (BENIGN low-conf now
  passes) and as a safety check (CONFIRMED still blocks even on a
  CDN — a compromised CDN is still a threat).

No real network traffic is generated — AsnInfo and responder SSH are
both mocked.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.core.asn_enricher import AsnInfo
from wardsoar.core.cdn_allowlist import CdnAllowlist, CdnMatch
from wardsoar.core.config import WhitelistConfig
from wardsoar.core.models import BlockAction, ResponseAction, ThreatAnalysis, ThreatVerdict
from src.pfsense_ssh import BlockTracker, PfSenseSSH
from src.responder import ThreatResponder

SAMPLE_YAML = """\
schema_version: "1"

allowlisted:
  - asn: 2906
    organisation: "Netflix"
    category: "streaming"
  - asn: 13335
    organisation: "Cloudflare"
    category: "cdn"
  - asn: 8075
    organisation: "Microsoft"
    category: "saas"
"""


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "cdn_allowlist.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _analysis(verdict: ThreatVerdict, confidence: float) -> ThreatAnalysis:
    return ThreatAnalysis(verdict=verdict, confidence=confidence, reasoning="t")


def _asn(asn: int, name: str = "Demo") -> AsnInfo:
    return AsnInfo(asn=asn, name=name, country="US", source="test")


def _responder(
    tmp_path: Path,
    *,
    mode: str = "hard_protect",
    allowlist: CdnAllowlist | None = None,
    hp_threshold: float = 0.99,
) -> ThreatResponder:
    ssh = MagicMock(spec=PfSenseSSH)
    ssh.add_to_blocklist = AsyncMock(return_value=True)
    ssh.remove_from_blocklist = AsyncMock(return_value=True)
    ssh.is_blocked = AsyncMock(return_value=False)
    tracker = BlockTracker(persist_path=tmp_path / "t.json")
    responder = ThreatResponder(
        config={"mode": mode, "block_duration_hours": 24, "max_blocks_per_hour": 20},
        whitelist=WhitelistConfig(ips=set()),
        ssh=ssh,
        tracker=tracker,
        confidence_threshold=0.70,
        hard_protect_benign_threshold=hp_threshold,
        cdn_allowlist=allowlist,
    )
    responder.block_ip_pfsense = AsyncMock(  # type: ignore[method-assign]
        side_effect=lambda ip, duration_hours=24: ResponseAction(
            action_type=BlockAction.IP_BLOCK,
            target_ip=ip,
            block_duration_hours=duration_hours,
            success=True,
            executed_at=datetime.now(timezone.utc),
        )
    )
    return responder


def _blocked(actions: list[ResponseAction]) -> bool:
    return any(a.action_type == BlockAction.IP_BLOCK and a.success for a in actions)


class TestLoader:
    def test_missing_file_is_empty(self, tmp_path: Path) -> None:
        al = CdnAllowlist(tmp_path / "absent.yaml")
        assert len(al) == 0
        assert al.classify_asn(2906) is None

    def test_malformed_yaml_is_empty(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "allowlisted: [not-a-dict\n  missing-bracket")
        al = CdnAllowlist(path)
        assert len(al) == 0

    def test_top_level_wrong_type_is_empty(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "- just\n- a\n- list\n")
        al = CdnAllowlist(path)
        assert len(al) == 0

    def test_valid_file_loads_all(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        assert len(al) == 3
        assert al.classify_asn(2906) == CdnMatch(
            asn=2906, organisation="Netflix", category="streaming"
        )

    def test_duplicate_asn_first_wins(self, tmp_path: Path) -> None:
        body = (
            "allowlisted:\n"
            "  - asn: 2906\n"
            "    organisation: 'Netflix primary'\n"
            "    category: streaming\n"
            "  - asn: 2906\n"
            "    organisation: 'Netflix secondary'\n"
            "    category: cdn\n"
        )
        al = CdnAllowlist(_write_yaml(tmp_path, body))
        match = al.classify_asn(2906)
        assert match is not None
        assert match.organisation == "Netflix primary"

    def test_malformed_rows_are_silently_skipped(self, tmp_path: Path) -> None:
        body = (
            "allowlisted:\n"
            "  - 'just-a-string'\n"
            "  - asn: not-a-number\n"
            "    organisation: Garbage\n"
            "  - asn: 13335\n"
            "    organisation: Cloudflare\n"
            "    category: cdn\n"
        )
        al = CdnAllowlist(_write_yaml(tmp_path, body))
        assert len(al) == 1
        assert al.classify_asn(13335) is not None


class TestClassifyAsn:
    def test_none_returns_none(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        assert al.classify_asn(None) is None

    def test_unknown_asn_returns_none(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        assert al.classify_asn(99999) is None

    def test_non_numeric_input_does_not_raise(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        assert al.classify_asn("garbage") is None  # type: ignore[arg-type]


class TestHardProtectCdnFallback:
    """With an allowlist hit, Hard Protect drops to Protect rules.

    Reference scenario: Firefox → Netflix (AS2906) triggers a
    SURICATA STREAM retransmission alert, Opus returns BENIGN 0.88,
    Hard Protect blocks. With the allowlist, the same verdict passes.
    """

    @pytest.mark.asyncio
    async def test_netflix_benign_low_confidence_is_spared(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        responder = _responder(tmp_path, allowlist=al)
        actions = await responder.respond(
            _analysis(ThreatVerdict.BENIGN, 0.88),
            "37.77.187.134",
            asn_info=_asn(2906, "Netflix Streaming Services"),
        )
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_netflix_confirmed_high_confidence_still_blocks(self, tmp_path: Path) -> None:
        """A compromised CDN is still blockable if Opus confirms."""
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        responder = _responder(tmp_path, allowlist=al)
        actions = await responder.respond(
            _analysis(ThreatVerdict.CONFIRMED, 0.95),
            "37.77.187.134",
            asn_info=_asn(2906, "Netflix Streaming Services"),
        )
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_non_cdn_asn_is_unaffected(self, tmp_path: Path) -> None:
        """OVH (AS16276) stays blocked — the Ben attack vector."""
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        responder = _responder(tmp_path, allowlist=al)
        actions = await responder.respond(
            _analysis(ThreatVerdict.BENIGN, 0.88),
            "51.68.10.42",
            asn_info=_asn(16276, "OVH SAS"),
        )
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_no_asn_info_falls_through_to_strict_rule(self, tmp_path: Path) -> None:
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        responder = _responder(tmp_path, allowlist=al)
        actions = await responder.respond(
            _analysis(ThreatVerdict.BENIGN, 0.88),
            "203.0.113.9",
            asn_info=None,
        )
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_missing_allowlist_preserves_legacy_behaviour(self, tmp_path: Path) -> None:
        responder = _responder(tmp_path, allowlist=None)
        actions = await responder.respond(
            _analysis(ThreatVerdict.BENIGN, 0.88),
            "37.77.187.134",
            asn_info=_asn(2906),
        )
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_cdn_match_on_inconclusive_does_not_block(self, tmp_path: Path) -> None:
        """CDN + INCONCLUSIVE → Protect semantics (no block since not CONFIRMED)."""
        al = CdnAllowlist(_write_yaml(tmp_path, SAMPLE_YAML))
        responder = _responder(tmp_path, allowlist=al)
        actions = await responder.respond(
            _analysis(ThreatVerdict.INCONCLUSIVE, 0.0),
            "37.77.187.134",
            asn_info=_asn(2906),
        )
        assert not _blocked(actions)


class TestShippedAllowlistLoadsCleanly:
    """Smoke-check that ``config/cdn_allowlist.yaml`` in the repo is
    parseable and non-empty."""

    def test_shipped_yaml_non_empty(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        shipped = repo_root / "config" / "cdn_allowlist.yaml"
        if not shipped.is_file():
            pytest.skip("shipped cdn_allowlist.yaml absent from this checkout")
        al = CdnAllowlist(shipped)
        assert len(al) >= 1
        assert al.classify_asn(2906) is not None, "Netflix (AS2906) missing"
        assert al.classify_asn(13335) is not None, "Cloudflare (AS13335) missing"
