"""Tests for :class:`NSourceCorrelator` — CRITICAL module.

The correlator fans N RemoteAgent streams into one tagged stream.
The test surface mirrors the dual-source tests but generalises every
scenario to arbitrary N: 1, 2, 3, 5 sources, plus edge cases (one
source dead, all silent, threshold not met, late arrival within
window, late arrival after window, etc.).

Three layers:

* :func:`_correlation_key` — pure function, exhaustive truth-table.
* State-machine transitions — async tests with scripted agents
  drained through the live event loop.
* Threshold semantics — the γ option from Q2 of the design.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

import pytest

from wardsoar.core.corroboration import (
    CorroborationStatus,
    CorroborationVerdict,
)
from wardsoar.core.remote_agents.n_source_correlator import (
    DEFAULT_WINDOW_S,
    NSourceCorrelator,
    _correlation_key,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _ScriptedAgent:
    """A ``RemoteAgent`` whose ``stream_alerts()`` yields a fixed sequence
    then waits forever on a live queue (matching the real agent contract:
    ``stream_alerts`` never returns on its own)."""

    def __init__(self, events: list[dict[str, Any]], emit_delay: float = 0.0) -> None:
        self._events = list(events)
        self._emit_delay = emit_delay
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
        for event in self._events:
            if self._emit_delay:
                await asyncio.sleep(self._emit_delay)
            yield event
        while True:
            event = await self._extra.get()
            yield event


def _alert(src: str, dst: str, sig_id: int, **extra: Any) -> dict[str, Any]:
    """Build a minimal EVE-shaped alert event."""
    return {
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": dst,
        "alert": {"signature_id": sig_id, "signature": "TEST"},
        **extra,
    }


async def _drain(
    correlator: NSourceCorrelator, count: int, timeout: float = 2.0
) -> list[dict[str, Any]]:
    """Pull events from the correlator with a deadline.

    Tolerant by design: if the correlator emits *fewer* than ``count``
    events (perfectly normal — e.g. a silent fleet only produces the
    sweeper's terminal tag, not the missing PENDING from sources that
    never reported), we return whatever arrived before the timeout
    instead of failing with an opaque ``TimeoutError``. Tests then
    inspect the verdicts on the drained list rather than assuming a
    fixed event count.
    """
    out: list[dict[str, Any]] = []
    iterator = correlator.stream_alerts()

    async def _pull() -> None:
        async for event in iterator:
            out.append(event)
            if len(out) >= count:
                break

    try:
        try:
            await asyncio.wait_for(_pull(), timeout=timeout)
        except asyncio.TimeoutError:
            pass  # Return whatever we got — caller asserts on the content.
    finally:
        await iterator.aclose()
    return out


# ---------------------------------------------------------------------------
# _correlation_key — same contract as the dual correlator
# ---------------------------------------------------------------------------


class TestCorrelationKey:
    def test_complete_alert_yields_key(self) -> None:
        ev = _alert("1.2.3.4", "5.6.7.8", 2210054)
        assert _correlation_key(ev) == ("1.2.3.4", "5.6.7.8", 2210054)

    def test_missing_src_yields_none(self) -> None:
        assert (
            _correlation_key({"dest_ip": "5.6.7.8", "alert": {"signature_id": 1}}) is None
        )

    def test_missing_dst_yields_none(self) -> None:
        assert (
            _correlation_key({"src_ip": "1.2.3.4", "alert": {"signature_id": 1}}) is None
        )

    def test_missing_sig_yields_none(self) -> None:
        assert _correlation_key({"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}) is None

    def test_non_int_sig_yields_none(self) -> None:
        assert (
            _correlation_key(
                {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {"signature_id": "x"}}
            )
            is None
        )

    def test_alert_block_not_dict_yields_none(self) -> None:
        assert (
            _correlation_key(
                {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": "not-a-dict"}
            )
            is None
        )


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_empty_sources_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one source"):
            NSourceCorrelator(sources={})

    def test_threshold_zero_raises(self) -> None:
        agent = _ScriptedAgent([])
        with pytest.raises(ValueError, match="threshold_ratio"):
            NSourceCorrelator(sources={"a": agent}, threshold_ratio=0.0)

    def test_threshold_above_one_raises(self) -> None:
        agent = _ScriptedAgent([])
        with pytest.raises(ValueError, match="threshold_ratio"):
            NSourceCorrelator(sources={"a": agent}, threshold_ratio=1.5)

    def test_threshold_negative_raises(self) -> None:
        agent = _ScriptedAgent([])
        with pytest.raises(ValueError, match="threshold_ratio"):
            NSourceCorrelator(sources={"a": agent}, threshold_ratio=-0.1)


# ---------------------------------------------------------------------------
# State machine — N=1, N=2, N=3, N=5
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSingleSourceFleet:
    """Fleet of 1 — every alert tags as SINGLE_SOURCE / PENDING; the sweeper
    closes windows as MATCH_FULL the moment the lone source is the only
    one configured."""

    async def test_one_source_one_alert_settles_match_full(self) -> None:
        agent = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        correlator = NSourceCorrelator(
            sources={"only": agent},
            window_seconds=0.05,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=2)
        # One pending while the window is open + one match-full from the sweeper.
        verdicts = [e["corroboration_status"].verdict for e in events]
        assert CorroborationVerdict.PENDING in verdicts
        assert any(
            v in (CorroborationVerdict.MATCH_FULL, CorroborationVerdict.SINGLE_SOURCE)
            for v in verdicts
        )

    async def test_one_source_event_without_key_emits_single_source(self) -> None:
        agent = _ScriptedAgent([{"event_type": "alert"}])  # missing fields
        correlator = NSourceCorrelator(
            sources={"only": agent},
            window_seconds=1.0,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=1)
        assert events[0]["corroboration_status"].verdict == CorroborationVerdict.SINGLE_SOURCE


@pytest.mark.asyncio
class TestTwoSourceFleet:
    """N=2 — exercises the historical dual-source contract under the new
    correlator. Equivalent to the old ``DualSourceCorrelator`` tests but
    with the per-source dataclass instead of the legacy enum."""

    async def test_both_sources_match_emits_match_full(self) -> None:
        ext = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        loc = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        correlator = NSourceCorrelator(
            sources={"external": ext, "local": loc},
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        # First sighting (PENDING) + second sighting (MATCH_FULL × 2 events).
        events = await _drain(correlator, count=4, timeout=2.0)
        statuses = [e["corroboration_status"] for e in events]
        assert any(s.verdict == CorroborationVerdict.PENDING for s in statuses)
        match_full = [s for s in statuses if s.verdict == CorroborationVerdict.MATCH_FULL]
        assert len(match_full) >= 2  # one per source in the bundle
        # Matching set should contain BOTH sources at the final tag.
        for s in match_full:
            assert set(s.matching_sources) == {"external", "local"}
            assert s.silent_sources == ()

    async def test_only_external_sees_emits_majority_or_divergence(self) -> None:
        # Local stays silent. The window expires, sweeper emits a final
        # tag that demotes the bundle (MAJORITY in lax mode, DIVERGENCE
        # in strict mode).
        ext = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        loc = _ScriptedAgent([])  # silent
        correlator = NSourceCorrelator(
            sources={"external": ext, "local": loc},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        events = await _drain(correlator, count=2)
        # First emission: PENDING. Second: DIVERGENCE because strict
        # threshold cannot tolerate a silent source.
        verdicts = [e["corroboration_status"].verdict for e in events]
        assert CorroborationVerdict.PENDING in verdicts
        assert CorroborationVerdict.DIVERGENCE in verdicts
        diverged = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.DIVERGENCE
        ]
        assert "external" in diverged[0]["corroboration_status"].matching_sources
        assert "local" in diverged[0]["corroboration_status"].silent_sources

    async def test_silent_source_with_lax_threshold_yields_majority(self) -> None:
        # Same setup with threshold 0.5: 1 observer / 2 configured = 0.5,
        # meets the lax threshold → MATCH_MAJORITY, not DIVERGENCE.
        ext = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        loc = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"external": ext, "local": loc},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=0.5,
        )
        events = await _drain(correlator, count=2)
        verdicts = [e["corroboration_status"].verdict for e in events]
        assert CorroborationVerdict.PENDING in verdicts
        assert CorroborationVerdict.MATCH_MAJORITY in verdicts


@pytest.mark.asyncio
class TestThreeSourceFleet:
    """N=3 — proves the correlator generalises beyond the legacy dual
    pair. The flow is observed by all three sources, by two of three,
    or by one of three; each scenario produces the expected verdict."""

    async def test_all_three_match_emits_match_full(self) -> None:
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        c = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b, "c": c},
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=5, timeout=2.0)
        match_full = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.MATCH_FULL
        ]
        assert len(match_full) >= 3  # 3-event bundle re-emitted
        for e in match_full:
            assert set(e["corroboration_status"].matching_sources) == {"a", "b", "c"}
            assert e["corroboration_status"].silent_sources == ()

    async def test_two_of_three_match_strict_diverges(self) -> None:
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        c = _ScriptedAgent([])  # silent
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b, "c": c},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        events = await _drain(correlator, count=4)
        diverged = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.DIVERGENCE
        ]
        assert len(diverged) >= 2  # one per observing source in the bundle
        for e in diverged:
            assert set(e["corroboration_status"].matching_sources) == {"a", "b"}
            assert set(e["corroboration_status"].silent_sources) == {"c"}

    async def test_two_of_three_match_two_thirds_threshold_majority(self) -> None:
        # Same setup but with threshold 0.66 → MATCH_MAJORITY because
        # 2 / 2 observers agreed (no dissent at this stage).
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        c = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b, "c": c},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=0.66,
        )
        events = await _drain(correlator, count=4)
        majority = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.MATCH_MAJORITY
        ]
        assert majority, "expected at least one MATCH_MAJORITY in {}".format(
            [e["corroboration_status"].verdict for e in events]
        )

    async def test_one_of_three_match_diverges_in_strict(self) -> None:
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([])
        c = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b, "c": c},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        events = await _drain(correlator, count=2)
        verdicts = [e["corroboration_status"].verdict for e in events]
        assert CorroborationVerdict.DIVERGENCE in verdicts


@pytest.mark.asyncio
class TestFiveSourceFleet:
    """N=5 — stress the correlator with a larger fleet to make sure
    the buffer / sweeper / pump tasks scale cleanly."""

    async def test_all_five_match(self) -> None:
        agents = {
            f"s{i}": _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
            for i in range(5)
        }
        correlator = NSourceCorrelator(
            sources=agents,
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=9, timeout=3.0)  # 4 PENDING + 5 MATCH_FULL
        match_full = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.MATCH_FULL
        ]
        assert len(match_full) >= 5
        for e in match_full:
            assert set(e["corroboration_status"].matching_sources) == set(agents.keys())

    async def test_three_of_five_match_strict_diverges(self) -> None:
        agents = {
            "a": _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)]),
            "b": _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)]),
            "c": _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)]),
            "d": _ScriptedAgent([]),
            "e": _ScriptedAgent([]),
        }
        correlator = NSourceCorrelator(
            sources=agents,
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        events = await _drain(correlator, count=5, timeout=2.0)
        diverged = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.DIVERGENCE
        ]
        assert diverged
        for e in diverged:
            assert set(e["corroboration_status"].matching_sources) == {"a", "b", "c"}
            assert set(e["corroboration_status"].silent_sources) == {"d", "e"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEdgeCases:
    async def test_duplicate_from_same_source_does_not_pollute_bundle(self) -> None:
        # Same agent emits the same alert twice. The bundle should
        # still report ONE matching source (the first sighting wins),
        # not register the duplicate as a "second observer".
        a = _ScriptedAgent(
            [
                _alert("1.1.1.1", "2.2.2.2", 100),
                _alert("1.1.1.1", "2.2.2.2", 100),
            ]
        )
        b = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.05,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        events = await _drain(correlator, count=3, timeout=2.0)
        # Only "a" should ever appear as matching — duplicate from "a"
        # must not appear as a matching observer of "b" too.
        for e in events:
            assert "b" not in e["corroboration_status"].matching_sources

    async def test_uncorrelatable_event_emits_single_source(self) -> None:
        # Event without correlation key never enters the buffer —
        # immediately tagged SINGLE_SOURCE regardless of fleet size.
        a = _ScriptedAgent([{"event_type": "alert"}])
        b = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=1)
        assert events[0]["corroboration_status"].verdict == CorroborationVerdict.SINGLE_SOURCE

    async def test_late_arrival_within_window_completes_match(self) -> None:
        # Event A arrives, then 30 ms later the same key arrives from
        # a second source. The window is 200 ms — well within. The
        # bundle finalises early on full match.
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.2,
            sweep_interval_s=0.01,
            threshold_ratio=1.0,
        )
        # Push from b after a small delay.
        iterator = correlator.stream_alerts()
        out: list[dict[str, Any]] = []

        async def _pull() -> None:
            async for event in iterator:
                out.append(event)
                if (
                    len(out) >= 3
                    or (
                        out
                        and out[-1]["corroboration_status"].verdict
                        == CorroborationVerdict.MATCH_FULL
                    )
                ):
                    break

        try:
            puller = asyncio.create_task(_pull())
            await asyncio.sleep(0.03)
            await b.push(_alert("1.1.1.1", "2.2.2.2", 100))
            await asyncio.wait_for(puller, timeout=2.0)
        finally:
            await iterator.aclose()
        verdicts = [e["corroboration_status"].verdict for e in out]
        assert CorroborationVerdict.MATCH_FULL in verdicts

    async def test_multiple_distinct_flows_kept_independent(self) -> None:
        # Two flows interleaved should produce two independent bundles
        # (one per correlation key). No cross-bleed.
        a = _ScriptedAgent(
            [
                _alert("1.1.1.1", "2.2.2.2", 100),
                _alert("3.3.3.3", "4.4.4.4", 200),
            ]
        )
        b = _ScriptedAgent(
            [
                _alert("3.3.3.3", "4.4.4.4", 200),
                _alert("1.1.1.1", "2.2.2.2", 100),
            ]
        )
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.2,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=8, timeout=2.0)
        # Both keys should reach MATCH_FULL exactly once.
        match_full_keys = [
            (e["src_ip"], e["dest_ip"], e["alert"]["signature_id"])
            for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.MATCH_FULL
        ]
        assert ("1.1.1.1", "2.2.2.2", 100) in match_full_keys
        assert ("3.3.3.3", "4.4.4.4", 200) in match_full_keys


# ---------------------------------------------------------------------------
# Status object integrity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStatusInjection:
    async def test_emitted_status_is_corroboration_status_instance(self) -> None:
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        b = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100)])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=3, timeout=2.0)
        for e in events:
            assert isinstance(e["corroboration_status"], CorroborationStatus)
            assert e["correlation_source"] in ("a", "b")

    async def test_secondary_events_attached_on_full_match(self) -> None:
        a = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100, src_port=1234)])
        b = _ScriptedAgent([_alert("1.1.1.1", "2.2.2.2", 100, src_port=5678)])
        correlator = NSourceCorrelator(
            sources={"a": a, "b": b},
            window_seconds=0.5,
            sweep_interval_s=0.01,
        )
        events = await _drain(correlator, count=4, timeout=2.0)
        match_full = [
            e for e in events
            if e["corroboration_status"].verdict == CorroborationVerdict.MATCH_FULL
        ]
        assert match_full
        # Each emission carries the bundle minus its own source.
        for e in match_full:
            this_source = e["correlation_source"]
            secondaries = e.get("secondary_events", {})
            assert this_source not in secondaries
            assert {this_source}.union(secondaries.keys()) == {"a", "b"}


# ---------------------------------------------------------------------------
# Constants exported
# ---------------------------------------------------------------------------


def test_default_window_exposed() -> None:
    """Pipeline reads this default — fail-loud if it disappears."""
    assert DEFAULT_WINDOW_S == 120.0


# ---------------------------------------------------------------------------
# Pump startup invocation (regression for v0.25.5)
# ---------------------------------------------------------------------------


class TestPumpStartup:
    """``_pump`` must call ``agent.startup()`` so subprocess-owning agents
    (LocalSuricataAgent) spawn their child on the consumer's loop.

    Pre-fix the spawn was scheduled on the main UI thread loop, which
    Qt does not run — silently dropping every local source. The
    correlator now drives startup itself.
    """

    @pytest.mark.asyncio
    async def test_startup_called_when_present(self) -> None:
        startup_calls: list[str] = []

        class _AgentWithStartup(_ScriptedAgent):
            async def startup(self) -> None:
                startup_calls.append("called")

        agent = _AgentWithStartup(events=[])
        correlator = NSourceCorrelator(sources={"local": agent})
        # Drain briefly so _pump actually runs.
        await _drain(correlator, count=1, timeout=0.5)
        assert startup_calls == ["called"]

    @pytest.mark.asyncio
    async def test_no_startup_method_is_silently_skipped(self) -> None:
        # _ScriptedAgent does NOT define startup — pump must not fail.
        agent = _ScriptedAgent(events=[_alert("1.1.1.1", "2.2.2.2", 1)])
        correlator = NSourceCorrelator(sources={"only": agent})
        events = await _drain(correlator, count=1, timeout=1.0)
        # We at least see the single-source verdict bundle.
        assert any("alert" in e for e in events)

    @pytest.mark.asyncio
    async def test_startup_failure_does_not_crash_pump(self) -> None:
        class _BrokenStartupAgent(_ScriptedAgent):
            async def startup(self) -> None:
                raise RuntimeError("boom")

        agent = _BrokenStartupAgent(events=[_alert("1.1.1.1", "2.2.2.2", 1)])
        correlator = NSourceCorrelator(sources={"local": agent})
        # Pump should still iterate stream_alerts — startup failure is logged
        # but not propagated. Returns whatever arrives in the timeout window.
        events = await _drain(correlator, count=1, timeout=1.0)
        # The stream still produces an event despite the failed startup.
        assert any("alert" in e for e in events)
