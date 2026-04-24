"""Tests for Phase 7 — Hard Protect mode + WardMode enum.

Three surfaces are covered:

* :class:`src.models.WardMode` — enum parsing, including the legacy
  ``dry_run`` bool and arbitrary string casing, since
  :func:`~src.models.WardMode.parse` feeds every config-migration code
  path in the app.
* :class:`src.responder.ThreatResponder` — the mode-dependent block
  decision. The matrix below is the contract: every row is a test.
* Runtime mutability — :meth:`~src.responder.ThreatResponder.set_mode`
  and the two threshold setters, which the UI calls when the operator
  moves a spinbox or clicks the mode button.

Block-decision matrix (safe after whitelist/trusted-temp/rate-limit
filters pass):

    mode          verdict        confidence      expected
    ───────────   ───────────    ──────────      ────────
    monitor       *              *               no block
    protect       CONFIRMED      ≥ conf_thr      BLOCK
    protect       CONFIRMED      < conf_thr      no block
    protect       BENIGN/INCONC  *               no block
    hard_protect  BENIGN         ≥ benign_thr    no block
    hard_protect  BENIGN         < benign_thr    BLOCK
    hard_protect  CONFIRMED      *               BLOCK
    hard_protect  INCONCLUSIVE   *               BLOCK (fail-safe)
    hard_protect  SUSPICIOUS     *               BLOCK

The whitelist + trusted-temp + rate-limit gates are asserted to
remain authoritative in every mode — no escalation path can override
them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.core.config import WhitelistConfig
from wardsoar.core.models import BlockAction, ResponseAction, ThreatAnalysis, ThreatVerdict, WardMode
from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker, PfSenseSSH
from wardsoar.core.responder import ThreatResponder
from wardsoar.core.trusted_temp import TrustedTempRegistry

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _analysis(verdict: ThreatVerdict, confidence: float) -> ThreatAnalysis:
    return ThreatAnalysis(
        verdict=verdict,
        confidence=confidence,
        reasoning="test fixture",
    )


def _responder(
    mode: str = "monitor",
    whitelist_ips: set[str] | None = None,
    trusted: TrustedTempRegistry | None = None,
    tmp_path: Path | None = None,
    confidence_threshold: float = 0.7,
    hard_protect_benign_threshold: float = 0.99,
) -> ThreatResponder:
    """Build a ThreatResponder with mocked SSH + a real BlockTracker."""
    ssh = MagicMock(spec=PfSenseSSH)
    ssh.add_to_blocklist = AsyncMock(return_value=True)
    ssh.remove_from_blocklist = AsyncMock(return_value=True)
    ssh.is_blocked = AsyncMock(return_value=False)
    ssh.list_blocklist = AsyncMock(return_value=[])

    tracker_path = (tmp_path or Path("/tmp")) / "hp_blocks.json"
    tracker = BlockTracker(persist_path=tracker_path)

    wl = WhitelistConfig(ips=whitelist_ips or set())

    responder = ThreatResponder(
        config={
            "mode": mode,
            "block_duration_hours": 24,
            "max_blocks_per_hour": 20,
        },
        whitelist=wl,
        ssh=ssh,
        tracker=tracker,
        trusted_temp=trusted,
        confidence_threshold=confidence_threshold,
        hard_protect_benign_threshold=hard_protect_benign_threshold,
    )
    # Swap the real pfctl call for a stub that reports success without
    # touching a real firewall. Any test exercising block paths reads
    # the ``target_ip`` from the returned ResponseAction.
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
    """True if any successful IP_BLOCK is present in the actions."""
    return any(a.action_type == BlockAction.IP_BLOCK and a.success for a in actions)


# ===========================================================================
# WardMode enum parsing
# ===========================================================================


class TestWardModeParse:
    """:meth:`WardMode.parse` is the single entry point for coercing
    any config value (string, bool, enum) into a valid mode — its
    robustness is load-bearing for the config-migration layer."""

    def test_enum_is_returned_as_is(self) -> None:
        assert WardMode.parse(WardMode.HARD_PROTECT) is WardMode.HARD_PROTECT

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("monitor", WardMode.MONITOR),
            ("PROTECT", WardMode.PROTECT),
            ("hard_protect", WardMode.HARD_PROTECT),
            ("hard-protect", WardMode.HARD_PROTECT),
            ("Hard Protect", WardMode.HARD_PROTECT),
            ("  monitor  ", WardMode.MONITOR),
        ],
    )
    def test_accepts_string_variants(self, raw: str, expected: WardMode) -> None:
        assert WardMode.parse(raw) is expected

    def test_legacy_dry_run_true_becomes_monitor(self) -> None:
        """Older configs use ``dry_run: true`` to mean "never block"."""
        assert WardMode.parse(True) is WardMode.MONITOR

    def test_legacy_dry_run_false_becomes_protect(self) -> None:
        """Older configs use ``dry_run: false`` for today's Protect behaviour."""
        assert WardMode.parse(False) is WardMode.PROTECT

    @pytest.mark.parametrize("raw", [None, "", "nope", 42, object()])
    def test_unknown_values_fail_safe_to_monitor(self, raw: object) -> None:
        """Fail-safe: an unparseable value must never escalate to a blocking mode."""
        assert WardMode.parse(raw) is WardMode.MONITOR


# ===========================================================================
# Responder in MONITOR mode
# ===========================================================================


class TestMonitorMode:
    """MONITOR mode is the universal "do nothing" — no verdict, no
    confidence, no external input can cause a block."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verdict,confidence",
        [
            (ThreatVerdict.CONFIRMED, 0.99),
            (ThreatVerdict.CONFIRMED, 0.70),
            (ThreatVerdict.BENIGN, 0.95),
            (ThreatVerdict.INCONCLUSIVE, 0.0),
            (ThreatVerdict.SUSPICIOUS, 0.85),
        ],
    )
    async def test_never_blocks(
        self,
        tmp_path: Path,
        verdict: ThreatVerdict,
        confidence: float,
    ) -> None:
        responder = _responder(mode="monitor", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(verdict, confidence), "185.199.108.153")
        assert not _blocked(actions)


# ===========================================================================
# Responder in PROTECT mode (legacy behaviour)
# ===========================================================================


class TestProtectMode:
    """PROTECT mode keeps the pre-0.5.5 semantics: block only on a
    CONFIRMED verdict that also clears the confidence threshold."""

    @pytest.mark.asyncio
    async def test_confirmed_high_confidence_blocks(self, tmp_path: Path) -> None:
        responder = _responder(mode="protect", tmp_path=tmp_path)
        actions = await responder.respond(
            _analysis(ThreatVerdict.CONFIRMED, 0.90), "185.199.108.153"
        )
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_confirmed_low_confidence_does_not_block(self, tmp_path: Path) -> None:
        responder = _responder(mode="protect", tmp_path=tmp_path)
        actions = await responder.respond(
            _analysis(ThreatVerdict.CONFIRMED, 0.50), "185.199.108.153"
        )
        assert not _blocked(actions)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verdict",
        [ThreatVerdict.BENIGN, ThreatVerdict.INCONCLUSIVE, ThreatVerdict.SUSPICIOUS],
    )
    async def test_non_confirmed_never_blocks(self, tmp_path: Path, verdict: ThreatVerdict) -> None:
        responder = _responder(mode="protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(verdict, 0.99), "185.199.108.153")
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_per_call_confidence_override(self, tmp_path: Path) -> None:
        """Legacy callers can still pass confidence_threshold=... to respond()."""
        responder = _responder(mode="protect", tmp_path=tmp_path, confidence_threshold=0.9)
        # Instance attribute says 0.9 → would not block at 0.75, but
        # the per-call override of 0.5 should.
        actions = await responder.respond(
            _analysis(ThreatVerdict.CONFIRMED, 0.75),
            "185.199.108.153",
            confidence_threshold=0.5,
        )
        assert _blocked(actions)


# ===========================================================================
# Responder in HARD_PROTECT mode (new doctrine)
# ===========================================================================


class TestHardProtectMode:
    """HARD_PROTECT inverts the burden of proof: Opus must prove
    benignity, otherwise we block."""

    @pytest.mark.asyncio
    async def test_benign_above_threshold_does_not_block(self, tmp_path: Path) -> None:
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.995), "185.199.108.153")
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_benign_at_exact_threshold_does_not_block(self, tmp_path: Path) -> None:
        """Exactly equal to the threshold is "clean enough" — we use ≥, not >."""
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.99), "185.199.108.153")
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_benign_below_threshold_blocks(self, tmp_path: Path) -> None:
        """BENIGN 0.92 is the typical honest Opus output — blocks at 0.99."""
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.92), "185.199.108.153")
        assert _blocked(actions)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verdict,confidence",
        [
            (ThreatVerdict.CONFIRMED, 0.99),
            (ThreatVerdict.CONFIRMED, 0.50),
            (ThreatVerdict.INCONCLUSIVE, 0.0),  # API parse error path
            (ThreatVerdict.INCONCLUSIVE, 0.80),
            (ThreatVerdict.SUSPICIOUS, 0.70),
        ],
    )
    async def test_non_benign_always_blocks(
        self, tmp_path: Path, verdict: ThreatVerdict, confidence: float
    ) -> None:
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(verdict, confidence), "185.199.108.153")
        assert _blocked(actions)

    @pytest.mark.asyncio
    async def test_tunable_threshold_can_relax(self, tmp_path: Path) -> None:
        """Operator can drop the benign threshold to e.g. 0.90 to tame FP noise."""
        responder = _responder(
            mode="hard_protect",
            tmp_path=tmp_path,
            hard_protect_benign_threshold=0.90,
        )
        # Same BENIGN 0.92 as the strict test — now spared.
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.92), "185.199.108.153")
        assert not _blocked(actions)


# ===========================================================================
# Safety guardrails — identical in every mode
# ===========================================================================


class TestRfc1918Guard:
    """v0.6.4 added an unconditional refusal to block RFC 1918,
    loopback and link-local addresses. This guard sits BEFORE the
    whitelist check — the Responder cannot block a private IP even
    when the whitelist is empty and the mode is HARD_PROTECT. The
    regression test scenario is the v0.6.3 incident where the
    operator's own machine (192.168.2.100) went offline because
    Hard Protect returned BENIGN 0.92 < 0.99 threshold and no
    whitelist protected it."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.2.100",  # LAN host (the v0.6.3 regression)
            "192.168.1.1",
            "10.0.0.5",
            "172.16.42.1",
            "127.0.0.1",  # loopback
            "169.254.1.1",  # link-local
        ],
    )
    async def test_rfc1918_never_blocked_even_in_hard_protect(
        self, tmp_path: Path, ip: str
    ) -> None:
        # Empty whitelist — simulate the v0.6.3 incident exactly.
        responder = _responder(
            mode="hard_protect",
            whitelist_ips=set(),
            tmp_path=tmp_path,
        )
        # BENIGN 0.00 would absolutely trigger a block in hard_protect.
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.0), ip)
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_rfc1918_never_blocked_even_on_confirmed(self, tmp_path: Path) -> None:
        """A CONFIRMED verdict at 1.0 on a LAN IP is still refused.

        Rationale: blocking your own LAN equipment wipes out every
        outbound session you have. If a LAN device is genuinely
        compromised the operator reaches for airgap / reimage, not
        pfSense rules. The safest product posture is to never block
        private space at all.
        """
        responder = _responder(mode="protect", tmp_path=tmp_path)
        actions = await responder.respond(_analysis(ThreatVerdict.CONFIRMED, 1.0), "10.0.0.42")
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_public_ip_still_blocks_normally(self, tmp_path: Path) -> None:
        """The guard must NOT over-reach — public IPs keep being blockable."""
        responder = _responder(mode="protect", tmp_path=tmp_path)
        actions = await responder.respond(
            _analysis(ThreatVerdict.CONFIRMED, 0.9), "185.199.108.153"
        )
        assert _blocked(actions)


class TestSafetyGuardrailsUnchanged:
    """Whitelist, trusted-temp, and rate-limit gates must reject a
    block even when the mode would otherwise demand one. HARD_PROTECT
    cannot override them."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["protect", "hard_protect"])
    async def test_whitelist_beats_every_mode(self, tmp_path: Path, mode: str) -> None:
        responder = _responder(
            mode=mode,
            whitelist_ips={"192.168.2.1"},
            tmp_path=tmp_path,
        )
        # Confirmed with maximum confidence — would block in protect;
        # hard_protect would want to block on anything.
        actions = await responder.respond(_analysis(ThreatVerdict.CONFIRMED, 1.0), "192.168.2.1")
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_trusted_temp_beats_hard_protect(self, tmp_path: Path) -> None:
        trusted = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        trusted.add("185.199.108.153", ttl_seconds=60)

        responder = _responder(
            mode="hard_protect",
            trusted=trusted,
            tmp_path=tmp_path,
        )
        # Even BENIGN at 0.00 would normally block in hard_protect.
        actions = await responder.respond(
            _analysis(ThreatVerdict.INCONCLUSIVE, 0.0), "185.199.108.153"
        )
        assert not _blocked(actions)

    @pytest.mark.asyncio
    async def test_rate_limit_beats_hard_protect(self, tmp_path: Path) -> None:
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        # Exhaust the rate limiter.
        for _ in range(20):
            responder._rate_limiter.record_action()
        actions = await responder.respond(
            _analysis(ThreatVerdict.INCONCLUSIVE, 0.0), "185.199.108.153"
        )
        assert not _blocked(actions)


# ===========================================================================
# Runtime mutability — UI touchpoints
# ===========================================================================


class TestRuntimeMutability:
    """The UI never restarts the engine to apply a setting change; it
    calls these setters directly on the live Responder. Smoke-test
    that each setter reaches the right internal attribute and that a
    subsequent ``respond`` call uses the new value."""

    @pytest.mark.asyncio
    async def test_set_mode_applies_live(self, tmp_path: Path) -> None:
        responder = _responder(mode="monitor", tmp_path=tmp_path)
        assert responder.mode is WardMode.MONITOR

        responder.set_mode(WardMode.HARD_PROTECT)
        assert responder.mode is WardMode.HARD_PROTECT

        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.50), "185.199.108.153")
        # Low-confidence BENIGN in HARD_PROTECT → block.
        assert _blocked(actions)

    def test_set_mode_idempotent(self, tmp_path: Path) -> None:
        responder = _responder(mode="protect", tmp_path=tmp_path)
        # Same-value re-set must not raise or spam the log twice — just
        # making sure no state transition happens.
        responder.set_mode(WardMode.PROTECT)
        assert responder.mode is WardMode.PROTECT

    def test_set_confidence_threshold_clamps(self, tmp_path: Path) -> None:
        responder = _responder(mode="protect", tmp_path=tmp_path)
        responder.set_confidence_threshold(1.5)
        assert responder.confidence_threshold == 1.0
        responder.set_confidence_threshold(-0.3)
        assert responder.confidence_threshold == 0.0

    def test_set_hard_protect_benign_threshold_clamps(self, tmp_path: Path) -> None:
        responder = _responder(mode="hard_protect", tmp_path=tmp_path)
        responder.set_hard_protect_benign_threshold(2.0)
        assert responder.hard_protect_benign_threshold == 1.0
        responder.set_hard_protect_benign_threshold(-1.0)
        assert responder.hard_protect_benign_threshold == 0.0

    @pytest.mark.asyncio
    async def test_threshold_change_takes_effect_on_next_alert(self, tmp_path: Path) -> None:
        responder = _responder(
            mode="hard_protect",
            hard_protect_benign_threshold=0.99,
            tmp_path=tmp_path,
        )
        # Before: BENIGN 0.92 → blocks.
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.92), "185.199.108.153")
        assert _blocked(actions)

        # Operator relaxes the threshold through the UI.
        responder.set_hard_protect_benign_threshold(0.90)

        # Same input → no block now.
        actions = await responder.respond(_analysis(ThreatVerdict.BENIGN, 0.92), "185.199.108.153")
        assert not _blocked(actions)


# ===========================================================================
# Legacy ``dry_run`` still understood at construction time
# ===========================================================================


class TestLegacyDryRun:
    """v0.5.4 users (and the existing test_responder.py fixtures) pass
    ``dry_run`` in the config dict — the Responder keeps reading it as
    a fallback so nothing breaks before the migration layer runs."""

    @pytest.mark.asyncio
    async def test_dry_run_true_means_monitor(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "t.json")
        ssh = MagicMock(spec=PfSenseSSH)
        ssh.add_to_blocklist = AsyncMock(return_value=True)

        responder = ThreatResponder(
            config={"dry_run": True, "block_duration_hours": 24, "max_blocks_per_hour": 20},
            whitelist=WhitelistConfig(ips=set()),
            ssh=ssh,
            tracker=tracker,
        )
        assert responder.mode is WardMode.MONITOR

    @pytest.mark.asyncio
    async def test_dry_run_false_means_protect(self, tmp_path: Path) -> None:
        tracker = BlockTracker(persist_path=tmp_path / "t.json")
        ssh = MagicMock(spec=PfSenseSSH)
        ssh.add_to_blocklist = AsyncMock(return_value=True)

        responder = ThreatResponder(
            config={"dry_run": False, "block_duration_hours": 24, "max_blocks_per_hour": 20},
            whitelist=WhitelistConfig(ips=set()),
            ssh=ssh,
            tracker=tracker,
        )
        assert responder.mode is WardMode.PROTECT
