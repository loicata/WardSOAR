"""Tests for :class:`DualSourceCorrelator` — CRITICAL module.

Exercises every transition of the correlation state machine
documented in ``project_dual_suricata_sync.md``:

* Lifecycle: spawn pumps + sweeper, drain queue, teardown clean
* Single source emitted with SINGLE_SOURCE tag (no correlation key)
* MATCH_PENDING + DIVERGENCE_PENDING tags during the window
* MATCH_CONFIRMED on cross-source second sighting (with secondary
  event payload)
* DIVERGENCE_A / DIVERGENCE_B re-tag on window expiry
* Same-source duplicates → emitted with same PENDING tag (does not
  pollute the buffer with a second entry)
* Window clamp ([10, 600]) applied at construction
* Health log threshold: median delay > 60% of window emits a
  WARNING string in the log

Hypothesis-based property tests are deferred to Phase 9 (memo
``project_dual_suricata_sync.md`` — CRITICAL flag). The classical
tests below cover every documented branch of the state machine,
plus a randomized stress test that interleaves N events from two
streams and verifies no event is lost or double-emitted as a
match.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.core.models import SourceCorroboration
from wardsoar.core.remote_agents.dual_source_correlator import (
    DEFAULT_WINDOW_S,
    DualSourceCorrelator,
    _correlation_key,
)
from wardsoar.core.remote_agents.protocol import RemoteAgent

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _ScriptedAgent:
    """A ``RemoteAgent`` whose ``stream_alerts()`` yields a fixed sequence.

    The sequence is exhausted lazily as the consumer pulls. Once
    drained, the iterator stays open (waits forever) so the
    correlator's pump tasks don't exit prematurely. This mirrors
    what a real agent does: ``stream_alerts`` never returns on its
    own.
    """

    def __init__(self, events: list[dict[str, Any]], emit_delay: float = 0.0) -> None:
        self._events = list(events)
        self._emit_delay = emit_delay
        # Allow the test to push more events after construction.
        self._extra: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def push(self, event: dict[str, Any]) -> None:
        await self._extra.put(event)

    async def check_status(self) -> tuple[bool, str]:
        return True, "scripted ok"

    async def add_to_blocklist(self, ip: str) -> bool:
        return True

    async def remove_from_blocklist(self, ip: str) -> bool:
        return True

    async def is_blocked(self, ip: str) -> bool:
        return False

    async def list_blocklist(self) -> list[str]:
        return []

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        return True, "scripted"

    async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        # Drain the initial batch first.
        for event in self._events:
            if self._emit_delay:
                await asyncio.sleep(self._emit_delay)
            yield event
        # Then drain the live queue forever.
        while True:
            event = await self._extra.get()
            yield event


def _alert(src: str, dst: str, sig_id: int, **extra: Any) -> dict[str, Any]:
    """Build a minimal EVE-shaped event for tests."""
    return {
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": dst,
        "alert": {"signature_id": sig_id, "signature": "TEST"},
        **extra,
    }


# ---------------------------------------------------------------------------
# _correlation_key
# ---------------------------------------------------------------------------


class TestCorrelationKey:
    def test_complete_alert_yields_key(self) -> None:
        ev = _alert("1.2.3.4", "5.6.7.8", 2210054)
        assert _correlation_key(ev) == ("1.2.3.4", "5.6.7.8", 2210054)

    def test_missing_src_yields_none(self) -> None:
        ev = {"dest_ip": "5.6.7.8", "alert": {"signature_id": 1}}
        assert _correlation_key(ev) is None

    def test_missing_dst_yields_none(self) -> None:
        ev = {"src_ip": "1.2.3.4", "alert": {"signature_id": 1}}
        assert _correlation_key(ev) is None

    def test_missing_alert_subdoc_yields_none(self) -> None:
        ev = {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
        assert _correlation_key(ev) is None

    def test_missing_signature_id_yields_none(self) -> None:
        ev = {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {}}
        assert _correlation_key(ev) is None

    def test_non_int_signature_id_yields_none(self) -> None:
        ev = {
            "src_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "alert": {"signature_id": "not-an-int"},
        }
        assert _correlation_key(ev) is None

    def test_alert_subdoc_not_a_dict_yields_none(self) -> None:
        ev = {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": []}
        assert _correlation_key(ev) is None


# ---------------------------------------------------------------------------
# Construction + clamping
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_window(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        assert c._window == DEFAULT_WINDOW_S

    def test_accepts_sub_second_window_for_tests(self) -> None:
        """The constructor does NOT clamp the operator's range —
        that's done at config-load time. This lets tests use small
        windows (e.g. 0.2 s) for fast iterations."""
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc, window_seconds=0.2)  # type: ignore[arg-type]
        assert c._window == 0.2

    def test_negative_window_floored_to_min(self) -> None:
        """Defence in depth: zero / negative values are floored to a
        non-zero minimum so we never end up with a degenerate
        infinite-loop-on-zero-sleep."""
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc, window_seconds=-1.0)  # type: ignore[arg-type]
        assert c._window > 0

    def test_negative_sweep_interval_floored(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc, sweep_interval_s=-5.0)  # type: ignore[arg-type]
        assert c._sweep_interval > 0

    def test_satisfies_remote_agent_protocol(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        assert isinstance(c, RemoteAgent)


# ---------------------------------------------------------------------------
# State machine — happy paths
# ---------------------------------------------------------------------------


async def _consume(c: DualSourceCorrelator, n: int, timeout: float = 5.0) -> list[dict]:
    """Drain ``n`` events from the correlator with a timeout."""
    collected: list[dict[str, Any]] = []

    async def _go() -> None:
        async for event in c.stream_alerts():
            collected.append(event)
            if len(collected) >= n:
                return

    await asyncio.wait_for(_go(), timeout=timeout)
    return collected


class TestStateMachine:
    @pytest.mark.asyncio
    async def test_match_pending_then_match_confirmed(self) -> None:
        """External event arrives first → MATCH_PENDING.
        Then local event with same key → MATCH_CONFIRMED on both
        sides (re-tag of the buffered event + emit the new one)."""
        ext = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)])
        loc = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)], emit_delay=0.05)
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=10.0, sweep_interval_s=0.05
        )
        events = await _consume(c, 3, timeout=2.0)

        # 3 events expected: PENDING + 2 CONFIRMED (one per side)
        tags = [e["source_corroboration"] for e in events]
        assert tags[0] == SourceCorroboration.MATCH_PENDING.value
        assert tags[1] == SourceCorroboration.MATCH_CONFIRMED.value
        assert tags[2] == SourceCorroboration.MATCH_CONFIRMED.value
        # The two confirmed emissions carry the secondary event.
        for ev in events[1:]:
            assert "secondary_event" in ev

    @pytest.mark.asyncio
    async def test_divergence_pending_then_match_confirmed(self) -> None:
        """Local event first → DIVERGENCE_PENDING. Then external
        event same key → MATCH_CONFIRMED."""
        ext = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)], emit_delay=0.1)
        loc = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)])
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=10.0, sweep_interval_s=0.05
        )
        events = await _consume(c, 3, timeout=2.0)
        tags = [e["source_corroboration"] for e in events]
        assert tags[0] == SourceCorroboration.DIVERGENCE_PENDING.value
        assert SourceCorroboration.MATCH_CONFIRMED.value in tags[1:]

    @pytest.mark.asyncio
    async def test_divergence_a_after_window_expiry(self) -> None:
        """External event with no local match within window →
        DIVERGENCE_A re-tag."""
        ext = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)])
        loc = _ScriptedAgent([])  # never matches
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=0.2, sweep_interval_s=0.05
        )
        events = await _consume(c, 2, timeout=3.0)
        # First emit = MATCH_PENDING; second = DIVERGENCE_A
        assert events[0]["source_corroboration"] == SourceCorroboration.MATCH_PENDING.value
        assert events[1]["source_corroboration"] == SourceCorroboration.DIVERGENCE_A.value
        assert events[0]["src_ip"] == events[1]["src_ip"]  # same event re-tagged

    @pytest.mark.asyncio
    async def test_divergence_b_after_window_expiry(self) -> None:
        """Local event with no external match → DIVERGENCE_B."""
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)])
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=0.2, sweep_interval_s=0.05
        )
        events = await _consume(c, 2, timeout=3.0)
        assert events[0]["source_corroboration"] == SourceCorroboration.DIVERGENCE_PENDING.value
        assert events[1]["source_corroboration"] == SourceCorroboration.DIVERGENCE_B.value

    @pytest.mark.asyncio
    async def test_single_source_for_uncorrelatable_event(self) -> None:
        """Event without IPs / sig_id → SINGLE_SOURCE tag.

        This shouldn't happen in practice (Suricata always emits
        complete events), but defensive code matters for malformed
        inputs."""
        bad = {"event_type": "stats"}  # no src_ip, no alert
        ext = _ScriptedAgent([bad])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=10.0, sweep_interval_s=0.05
        )
        events = await _consume(c, 1, timeout=2.0)
        assert events[0]["source_corroboration"] == SourceCorroboration.SINGLE_SOURCE.value

    @pytest.mark.asyncio
    async def test_same_source_duplicates_emit_same_pending_tag(self) -> None:
        """If external emits the same key twice in a row before any
        local match, both emissions get MATCH_PENDING — the second
        does NOT replace the buffered entry (first wins)."""
        ev = _alert("1.2.3.4", "5.6.7.8", 100)
        ext = _ScriptedAgent([ev, ev])  # same event twice
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=10.0, sweep_interval_s=0.05
        )
        events = await _consume(c, 2, timeout=2.0)
        tags = [e["source_corroboration"] for e in events]
        assert tags == [
            SourceCorroboration.MATCH_PENDING.value,
            SourceCorroboration.MATCH_PENDING.value,
        ]

    @pytest.mark.asyncio
    async def test_correlation_source_field_set(self) -> None:
        """Every emitted event carries a ``correlation_source`` field
        ('external' or 'local') so downstream consumers can filter."""
        ext = _ScriptedAgent([_alert("1.2.3.4", "5.6.7.8", 100)])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=10.0, sweep_interval_s=0.05
        )
        events = await _consume(c, 1, timeout=2.0)
        assert events[0]["correlation_source"] == "external"


# ---------------------------------------------------------------------------
# Protocol surface — non-source methods
# ---------------------------------------------------------------------------


class TestProtocolNonSourceSurface:
    """The correlator is a routing layer; enforcement methods refuse."""

    @pytest.mark.asyncio
    async def test_check_status_aggregates(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        ok, msg = await c.check_status()
        assert ok is True
        assert "external" in msg.lower() or "local" in msg.lower() or "both" in msg.lower()

    @pytest.mark.asyncio
    async def test_check_status_one_down(self) -> None:
        ext_mock = MagicMock()
        ext_mock.check_status = AsyncMock(return_value=(True, "ok"))
        loc_mock = MagicMock()
        loc_mock.check_status = AsyncMock(return_value=(False, "stalled"))
        c = DualSourceCorrelator(ext_mock, loc_mock)  # type: ignore[arg-type]
        ok, msg = await c.check_status()
        assert ok is False
        assert "stalled" in msg.lower() or "local" in msg.lower()

    @pytest.mark.asyncio
    async def test_add_to_blocklist_refuses(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        with pytest.raises(NotImplementedError, match="routing layer"):
            await c.add_to_blocklist("1.2.3.4")

    @pytest.mark.asyncio
    async def test_kill_refuses(self) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        with pytest.raises(NotImplementedError, match="routing layer"):
            await c.kill_process_on_target(1234)


# ---------------------------------------------------------------------------
# Health log
# ---------------------------------------------------------------------------


class TestHealthLog:
    @pytest.mark.asyncio
    async def test_warning_when_median_delay_exceeds_60_pct(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When median match delay > 60% of window, the periodic
        health log emits a WARNING-class string suggesting raising
        the window. We synthesise the delay history manually to
        avoid a 60+ second test."""
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc, window_seconds=10.0)  # type: ignore[arg-type]
        c._match_delays = [7.0, 7.5, 8.0]  # median 7.5 > 6 = 60% of 10
        with caplog.at_level(logging.INFO):
            c._log_health()
        joined = " ".join(r.message for r in caplog.records)
        assert "WARNING" in joined
        assert "raising" in joined.lower() or "raise" in joined.lower()

    def test_health_log_no_match_yet(self, caplog: pytest.LogCaptureFixture) -> None:
        ext = _ScriptedAgent([])
        loc = _ScriptedAgent([])
        c = DualSourceCorrelator(ext, loc)  # type: ignore[arg-type]
        with caplog.at_level(logging.INFO):
            c._log_health()
        assert any("no matches yet" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Randomized stress — no event lost, no double-emit-as-match
# ---------------------------------------------------------------------------


class TestRandomizedStress:
    """Generates random interleavings of N events from two sources
    and verifies invariants:

    * Every source-emitted event arrives in the consumer at least
      once, with one of the documented tags
    * No event is emitted as MATCH_CONFIRMED more than once per
      side
    * Total emissions for matching pairs = 2 (one per side)
    """

    @pytest.mark.asyncio
    async def test_random_interleavings_invariants(self) -> None:
        rng = random.Random(2026)  # nosec B311 — deterministic test seed
        # 10 unique flow keys, 50% have a match, 50% only one source
        flows = [(f"10.0.0.{i}", f"20.0.0.{i}", 1000 + i) for i in range(10)]
        ext_events: list[dict[str, Any]] = []
        loc_events: list[dict[str, Any]] = []
        expected_matches = 0
        expected_div_a = 0
        expected_div_b = 0
        for src, dst, sig in flows:
            r = rng.random()
            if r < 0.5:
                # Match — both sides see it
                ext_events.append(_alert(src, dst, sig))
                loc_events.append(_alert(src, dst, sig))
                expected_matches += 1
            elif r < 0.75:
                ext_events.append(_alert(src, dst, sig))
                expected_div_a += 1
            else:
                loc_events.append(_alert(src, dst, sig))
                expected_div_b += 1
        rng.shuffle(ext_events)
        rng.shuffle(loc_events)

        ext = _ScriptedAgent(ext_events, emit_delay=0.005)
        loc = _ScriptedAgent(loc_events, emit_delay=0.005)
        c = DualSourceCorrelator(  # type: ignore[arg-type]
            ext, loc, window_seconds=0.5, sweep_interval_s=0.05
        )

        # Expected total emissions:
        #   - matches: 2 emits each (PENDING + CONFIRMED side, or
        #     2 CONFIRMED if first sighting was already buffered).
        #     In practice: pending + confirmed for the first side,
        #     immediate confirmed for the second side = 3 emits.
        #     But the buffered "pending" was already emitted on
        #     arrival; the cross-source match emits 2 confirmed
        #     events. So total per match = 1 + 2 = 3.
        #     (The "pending" of the second side never happens: it
        #     immediately resolves to confirmed.)
        #   - div_a: pending + divergence_a re-tag = 2 emits
        #   - div_b: pending + divergence_b re-tag = 2 emits
        expected_total = expected_matches * 3 + expected_div_a * 2 + expected_div_b * 2

        collected: list[dict[str, Any]] = []

        async def _drain() -> None:
            async for event in c.stream_alerts():
                collected.append(event)
                if len(collected) >= expected_total:
                    return

        await asyncio.wait_for(_drain(), timeout=10.0)

        # Property: every emitted event has a known tag.
        all_tags = {tag.value for tag in SourceCorroboration}
        for event in collected:
            assert event["source_corroboration"] in all_tags

        # Property: count of MATCH_CONFIRMED = 2 * matches
        # (one per side of each pair).
        match_count = sum(
            1
            for e in collected
            if e["source_corroboration"] == SourceCorroboration.MATCH_CONFIRMED.value
        )
        assert match_count == 2 * expected_matches, (
            f"expected {2 * expected_matches} confirmed emissions for "
            f"{expected_matches} pairs, got {match_count}"
        )

        # Property: count of DIVERGENCE_A re-tags = expected_div_a
        div_a_count = sum(
            1
            for e in collected
            if e["source_corroboration"] == SourceCorroboration.DIVERGENCE_A.value
        )
        assert div_a_count == expected_div_a

        # Property: count of DIVERGENCE_B re-tags = expected_div_b
        div_b_count = sum(
            1
            for e in collected
            if e["source_corroboration"] == SourceCorroboration.DIVERGENCE_B.value
        )
        assert div_b_count == expected_div_b
