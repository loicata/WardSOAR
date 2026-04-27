"""Fan-in N ``RemoteAgent`` streams into 1 with corroboration tags.

Successor to :class:`DualSourceCorrelator`. The dual correlator was
hard-coded to 2 sources (external + local). This one accepts an
arbitrary mapping ``{source_name: agent}`` and produces the same
single-stream output, tagged with a :class:`CorroborationStatus`
that captures the per-source picture (which sources matched, which
stayed silent).

This module is **CRITICAL**: bugs here mean alerts get misrouted,
double-counted, or silently dropped. Every state transition is
enumerated, every output is tagged, the buffer state machine has
explicit invariants, and the test suite exercises N=1, N=2, N=3,
N=5 plus edge cases (one source dead, all silent, threshold not
met, late arrival within window, late arrival after window, etc.).

Doctrine cross-references:
    * Q1 — Window 120 s default, configurable. Buffer soft cap
      protects against pathological input.
    * Q2 β — strict mode (threshold_ratio=1.0) is the default;
      γ — operators can lower the threshold_ratio for noisy fleets.
    * Q3 — divergence findings (loopback / VPN / dead source) are
      surfaced by the downstream DivergenceInvestigator + Bumper,
      not here. The correlator only **tags** events.

Lifecycle (driven by the consumer):
    * ``stream_alerts()`` returns an :class:`AsyncIterator[dict]`
      that the existing :class:`AgentStreamConsumer` consumes
      transparently — same Protocol shape as a single agent.
    * Background tasks pump every source stream concurrently into
      an internal queue, applies the correlation logic, emits.
    * ``aclose()`` on the iterator stops the background pumps and
      drains pending state.

State machine — one buffer entry per correlation key, indexed by
``(src_ip, dest_ip, alert_signature_id)``:

    Event arrives from source S
        │
        ▼
    Compute key
        │
        ├── No key (missing fields) → emit SINGLE_SOURCE for S
        │
        ▼
    Buffer hit?
        ├── No  → buffer the event under {S: event}
        │        emit with verdict=PENDING, matching=(S,)
        │
        └── Yes:
              ├── S already in entry → duplicate / burst
              │   keep first, emit with verdict=PENDING, matching=keys
              │
              └── S not in entry → add it
                  if entry now has every configured source
                      → emit MATCH_FULL for every event in the bundle
                      → evict
                  else
                      → emit PENDING with the updated matching set

    Background sweeper (runs every poll_interval):
        For each buffer entry whose age >= window:
            derive verdict from (matching_count, 0, silent_count)
            emit final-tag event for every event in the bundle
            evict the entry

Backpressure: the internal queue is unbounded by design — the
correlator is a fan-in, not a fan-out, and the consumer (pipeline)
is the bottleneck, not the agents. If a consumer is slow, the
queue grows, and we surface a periodic INFO log so the operator
notices. We do **not** drop events on overflow; that would silently
mask DoS-class detection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

from wardsoar.core.corroboration import (
    CorroborationStatus,
    CorroborationVerdict,
    derive_verdict,
)
from wardsoar.core.remote_agents.protocol import RemoteAgent

logger = logging.getLogger("ward_soar.n_source_correlator")


# Default window length for matching events across N sources.
# Doctrine Q1: 120 s covers a cold-start Suricata + moderate
# network burst. Configurable per instance, with a clamp at the
# consumer level (Pipeline reads YAML and clamps to [30, 180]).
DEFAULT_WINDOW_S: float = 120.0

# How often the background sweeper checks the buffer for expired
# entries. Smaller = faster divergence detection; larger = lower
# CPU overhead. 1 s is a sane default that keeps detection latency
# within ±1 s of the window expiry.
_SWEEP_INTERVAL_S: float = 1.0

# Soft cap on the buffer size before we start logging warnings.
# At 60 events/s sustained input, a 120 s window already implies
# 7,200 entries — we set a comfortable cap above typical maxima
# and surface anything above as "something pathological is
# happening" (DoS, broken source flooding identical alerts, etc.).
_BUFFER_SIZE_SOFT_CAP: int = 50_000

# Periodic log cadence for buffer / queue health metrics. Once
# every minute is plenty for operator awareness without spamming.
_HEALTH_LOG_INTERVAL_S: float = 60.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _correlation_key(event: dict[str, Any]) -> Optional[tuple[str, str, int]]:
    """Compute the correlation key for an EVE event, or ``None`` if uncorrelatable.

    Key = ``(src_ip, dest_ip, alert_signature_id)``. Events without
    an ``alert.signature_id`` or without IP addresses cannot be
    correlated — they are emitted with
    :data:`CorroborationVerdict.SINGLE_SOURCE` regardless of the
    fleet size.
    """
    src = event.get("src_ip")
    dst = event.get("dest_ip")
    alert = event.get("alert") or {}
    if not isinstance(alert, dict):
        return None
    sig = alert.get("signature_id")
    if not isinstance(src, str) or not src:
        return None
    if not isinstance(dst, str) or not dst:
        return None
    if not isinstance(sig, int):
        return None
    return (src, dst, sig)


@dataclass
class _BufferedFlow:
    """One correlation key's bundle of per-source events.

    Stored in :attr:`NSourceCorrelator._buffer`. As more sources
    report on the same flow, ``events`` grows. When ``events`` covers
    every configured source, the bundle is finalised early; otherwise
    the sweeper finalises it when ``arrived_at_monotonic`` exceeds
    the window.

    A bundle is finalised exactly once — :attr:`finalised` flips to
    True the moment the final tag is emitted, so a late arrival
    landing in the same tick as the sweeper does not double-emit.
    """

    events: dict[str, dict[str, Any]]
    arrived_at_monotonic: float
    arrived_at_wall: datetime
    finalised: bool = False


@dataclass
class _Output:
    """Wrapper for events emitted by the correlator."""

    payload: dict[str, Any] = field(default_factory=dict)


class NSourceCorrelator:
    """Correlate N ``RemoteAgent`` streams into a single tagged stream.

    Args:
        sources: Mapping ``{source_name: agent}``. ``source_name`` is
            an opaque identifier (e.g. ``"netgate"``, ``"local"``,
            ``"pi"``, or any operator-chosen string). Every emitted
            event carries the originating source name in the
            corroboration status, so duplicate names are forbidden
            (Python dict semantics enforce that).
        window_seconds: Reconciliation window. Default 120 s.
            Tests pass sub-second values for fast iterations; the
            constructor clamps only against zero/negative so unit
            tests stay flexible. Operator-facing range is enforced
            at config-load time.
        sweep_interval_s: How often the background sweeper checks
            for expired buffer entries.
        threshold_ratio: K/N ratio required for MATCH_MAJORITY when
            the window closes with at least one silent source.
            ``1.0`` (default) = strict mode (silent source → DIVERGENCE).
            ``0.5`` = simple majority (more than half observed → match).

    The correlator implements the same Protocol shape as a single
    :class:`RemoteAgent` (``stream_alerts``) so the consumer
    (:class:`AgentStreamConsumer`) treats it transparently.

    Raises:
        ValueError: when ``sources`` is empty (the correlator only
            makes sense with at least one source — and is most useful
            with two or more).
    """

    def __init__(
        self,
        sources: dict[str, RemoteAgent],
        window_seconds: float = DEFAULT_WINDOW_S,
        sweep_interval_s: float = _SWEEP_INTERVAL_S,
        threshold_ratio: float = 1.0,
    ) -> None:
        if not sources:
            raise ValueError("NSourceCorrelator needs at least one source")
        if not 0.0 < threshold_ratio <= 1.0:
            raise ValueError("threshold_ratio must be in (0.0, 1.0]")
        self._sources: dict[str, RemoteAgent] = dict(sources)
        self._source_names: tuple[str, ...] = tuple(sorted(sources.keys()))
        self._n: int = len(sources)
        self._window = max(0.001, float(window_seconds))
        self._sweep_interval = max(0.001, float(sweep_interval_s))
        self._threshold_ratio = float(threshold_ratio)

        # Buffer of correlation-keyed bundles. Each entry holds the
        # per-source events seen so far for one ``(src, dst, sig)``
        # tuple. O(1) lookup keeps the hot path cheap.
        self._buffer: dict[tuple[str, str, int], _BufferedFlow] = {}

        # Output queue — events ready for the consumer. Unbounded
        # by design (see module docstring).
        self._output: asyncio.Queue[_Output] = asyncio.Queue()

        # Match-delay observation: doctrine Q1 mandates passive
        # auto-tuning. We collect the delay between the first sighting
        # and full corroboration of every confirmed match (in
        # seconds), keep a bounded history, and log the median
        # periodically.
        self._match_delays: list[float] = []
        self._delay_history_cap = 100

        # Source pump tasks + sweeper task — tracked so we can
        # cancel them cleanly on aclose.
        self._tasks: list[asyncio.Task[None]] = []
        self._stopped: bool = False
        self._last_health_log_at: float = 0.0

    # ------------------------------------------------------------------
    # RemoteAgent protocol surface — only stream_alerts is meaningful.
    # ------------------------------------------------------------------

    async def check_status(self) -> tuple[bool, str]:
        """Compose every source's status — healthy iff ALL sources are healthy.

        Reports the worst sub-status so the operator sees the actual
        problem rather than an aggregated "everything is fine".
        """
        statuses = []
        for name, agent in self._sources.items():
            ok, msg = await agent.check_status()
            statuses.append((name, ok, msg))
        all_ok = all(ok for _, ok, _ in statuses)
        if all_ok:
            return True, "all sources OK ({})".format(
                ", ".join(f"{n}: {m}" for n, _, m in statuses)
            )
        down = [(n, m) for n, ok, m in statuses if not ok]
        return False, "{} source(s) down: ".format(len(down)) + ", ".join(
            f"{n}: {m}" for n, m in down
        )

    async def add_to_blocklist(self, ip: str) -> bool:
        raise NotImplementedError("NSourceCorrelator is a source-only routing layer")

    async def remove_from_blocklist(self, ip: str) -> bool:
        raise NotImplementedError("NSourceCorrelator is a source-only routing layer")

    async def is_blocked(self, ip: str) -> bool:
        raise NotImplementedError("NSourceCorrelator is a source-only routing layer")

    async def list_blocklist(self) -> list[str]:
        raise NotImplementedError("NSourceCorrelator is a source-only routing layer")

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        raise NotImplementedError("NSourceCorrelator is a source-only routing layer")

    async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        """Yield correlated EVE events with corroboration status attached.

        Spawns one background pump per source plus a sweeper for
        window expiry. Yields events as they land in the output queue.
        Cleans up tasks on consumer aclose.

        Each yielded dict carries TWO extra fields:

        * ``corroboration_status`` — full
          :class:`CorroborationStatus` instance describing the
          per-source picture (matching, silent, verdict, ratio).
        * ``correlation_source`` — name of the source that emitted
          this particular event (the bundle may emit multiple times
          when the window closes).

        Pipeline downstream sees a regular EVE dict; it can ignore
        these fields if it doesn't care about corroboration.
        """
        self._stopped = False

        # Launch one pump per source and the sweeper. They share the
        # same buffer / output queue, guarded by the asyncio
        # single-threaded model — no lock needed because all buffer
        # operations are synchronous from the loop's perspective.
        self._tasks = [
            asyncio.create_task(self._pump(name, agent)) for name, agent in self._sources.items()
        ]
        self._tasks.append(asyncio.create_task(self._sweep()))

        try:
            while True:
                # Periodic health log even while waiting.
                if time.monotonic() - self._last_health_log_at >= _HEALTH_LOG_INTERVAL_S:
                    self._log_health()
                    self._last_health_log_at = time.monotonic()

                try:
                    item = await asyncio.wait_for(
                        self._output.get(), timeout=_HEALTH_LOG_INTERVAL_S
                    )
                except asyncio.TimeoutError:
                    continue
                yield item.payload
        finally:
            await self._teardown()

    # ------------------------------------------------------------------
    # Internal — pump + correlate + sweep
    # ------------------------------------------------------------------

    async def _pump(self, source_name: str, agent: RemoteAgent) -> None:
        """Drain one source's stream and feed events into the correlation logic.

        Calls ``agent.startup()`` first when the agent exposes one. Some
        agents (e.g. ``LocalSuricataAgent``) own a subprocess that must
        be spawned before ``stream_alerts`` can yield anything; running
        startup on the pump's loop guarantees the subprocess is created
        on the loop that will later read its output. ``startup`` is
        optional on the ``RemoteAgent`` protocol — agents without one
        (Netgate over SSH, NoOpAgent) skip it transparently.
        """
        startup = getattr(agent, "startup", None)
        if startup is not None and callable(startup):
            try:
                result = startup()
                if asyncio.iscoroutine(result):
                    await result
                logger.info("NSourceCorrelator: %s startup completed", source_name)
            except Exception as exc:  # noqa: BLE001 — startup failure must not crash the pump
                detail = str(exc) or type(exc).__name__
                logger.error(
                    "NSourceCorrelator: %s startup failed (%s) — pump still "
                    "tries to consume stream (some agents recover from a missing "
                    "data file once it appears)",
                    source_name,
                    detail,
                )
        try:
            async for event in agent.stream_alerts():
                if self._stopped:
                    break
                self._on_incoming_event(event, source_name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — never crash the correlator
            detail = str(exc) or type(exc).__name__
            logger.error(
                "NSourceCorrelator: %s pump error (%s) — pump exiting",
                source_name,
                detail,
            )

    def _on_incoming_event(self, event: dict[str, Any], source_name: str) -> None:
        """Apply the correlation state machine to an incoming event.

        Synchronous on purpose: every operation is a dict / queue
        access, no I/O. This is what lets the asyncio model give us
        atomic state mutation without locks — concurrent pumps cannot
        interleave a partial update because Python doesn't yield
        mid-method.
        """
        key = _correlation_key(event)
        if key is None:
            # Cannot correlate — emit as single source. The flow lacks
            # the IPs/sig that would let us match it across sources.
            status = CorroborationStatus(
                verdict=CorroborationVerdict.SINGLE_SOURCE,
                matching_sources=(source_name,),
                threshold_ratio=self._threshold_ratio,
            )
            self._emit(event, status, source_name)
            return

        existing = self._buffer.get(key)
        now_mono = time.monotonic()
        now_wall = datetime.now(timezone.utc)

        if existing is None:
            # First sighting — buffer it, emit PENDING.
            self._buffer[key] = _BufferedFlow(
                events={source_name: event},
                arrived_at_monotonic=now_mono,
                arrived_at_wall=now_wall,
            )
            self._emit(
                event,
                self._build_pending_status((source_name,), now_wall),
                source_name,
            )
            self._maybe_warn_buffer_overflow()
            return

        if source_name in existing.events:
            # Same source again before the bundle settled. Could be
            # a duplicate (rule-reload re-emit) or a burst. Keep the
            # first event in the buffer (first-write-wins) and emit
            # the new one with the current pending picture — the
            # pipeline's deduplicator (stage 2) will squash bursts.
            self._emit(
                event,
                self._build_pending_status(
                    tuple(sorted(existing.events.keys())),
                    existing.arrived_at_wall,
                ),
                source_name,
            )
            return

        # New source on a known key — add it and check whether the
        # bundle is now full (every configured source has reported).
        existing.events[source_name] = event
        if len(existing.events) >= self._n:
            self._finalise_bundle(key, existing, now_mono)
            return

        # Still waiting on more sources — emit PENDING with the
        # updated matching set.
        self._emit(
            event,
            self._build_pending_status(
                tuple(sorted(existing.events.keys())),
                existing.arrived_at_wall,
            ),
            source_name,
        )

    async def _sweep(self) -> None:
        """Periodically expire stale buffer entries → emit terminal verdict."""
        try:
            while not self._stopped:
                await asyncio.sleep(self._sweep_interval)
                self._evict_expired()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("NSourceCorrelator: sweeper error: %s", exc)

    def _evict_expired(self) -> None:
        """Walk the buffer, finalise entries whose window expired."""
        now_mono = time.monotonic()
        expired_keys = [
            key
            for key, flow in self._buffer.items()
            if not flow.finalised and now_mono - flow.arrived_at_monotonic >= self._window
        ]
        for key in expired_keys:
            self._finalise_bundle(key, self._buffer[key], now_mono)

    def _finalise_bundle(
        self,
        key: tuple[str, str, int],
        flow: _BufferedFlow,
        now_mono: float,
    ) -> None:
        """Emit a final status for every event in the bundle, then evict.

        Idempotent — :attr:`_BufferedFlow.finalised` guards against a
        late incoming event landing in the same tick as the sweeper.
        """
        if flow.finalised:
            return
        flow.finalised = True

        observing = tuple(sorted(flow.events.keys()))
        silent = tuple(name for name in self._source_names if name not in flow.events)
        verdict = derive_verdict(
            matching=len(observing),
            dissenting=0,
            silent=len(silent),
            threshold_ratio=self._threshold_ratio,
        )
        status = CorroborationStatus(
            verdict=verdict,
            matching_sources=observing,
            silent_sources=silent,
            consensus_verdict="alert",
            threshold_ratio=self._threshold_ratio,
            window_opened_at=flow.arrived_at_wall,
            window_closed_at=datetime.now(timezone.utc),
        )

        # When the window is filled by consecutive arrivals, record
        # the corroboration delay so the operator can see whether the
        # configured window is generous enough.
        if len(observing) >= 2:
            delay = max(0.0, now_mono - flow.arrived_at_monotonic)
            self._record_match_delay(delay)

        # Emit one re-tag per event in the bundle, attaching
        # the bundle's secondary events for the consumer.
        for src_name, event in flow.events.items():
            secondaries = {n: e for n, e in flow.events.items() if n != src_name}
            self._emit(event, status, src_name, secondaries=secondaries)

        del self._buffer[key]

    def _build_pending_status(
        self, matching: tuple[str, ...], opened_at: datetime
    ) -> CorroborationStatus:
        """Compose the pending status emitted while a window is still open."""
        silent_set = set(self._source_names) - set(matching)
        return CorroborationStatus(
            verdict=CorroborationVerdict.PENDING,
            matching_sources=matching,
            silent_sources=tuple(sorted(silent_set)),
            threshold_ratio=self._threshold_ratio,
            window_opened_at=opened_at,
        )

    def _emit(
        self,
        event: dict[str, Any],
        status: CorroborationStatus,
        source_name: str,
        secondaries: Optional[dict[str, dict[str, Any]]] = None,
    ) -> None:
        """Inject corroboration metadata and push the event onto the queue."""
        # Defensive copy so we never mutate the source agent's event in
        # place. Shallow copy is OK because we only add top-level keys.
        payload = dict(event)
        payload["corroboration_status"] = status
        payload["correlation_source"] = source_name
        if secondaries:
            payload["secondary_events"] = {n: dict(e) for n, e in secondaries.items()}
        self._output.put_nowait(_Output(payload=payload))

    def _maybe_warn_buffer_overflow(self) -> None:
        """One soft-cap warning per overflow — operator alerting only."""
        if len(self._buffer) > _BUFFER_SIZE_SOFT_CAP:
            logger.warning(
                "NSourceCorrelator: buffer size %d exceeds soft cap %d "
                "— possible DoS or one-sided source flood",
                len(self._buffer),
                _BUFFER_SIZE_SOFT_CAP,
            )

    def _record_match_delay(self, delay_s: float) -> None:
        """Track the rolling sample of corroboration delays."""
        self._match_delays.append(delay_s)
        if len(self._match_delays) > self._delay_history_cap:
            self._match_delays.pop(0)

    def _log_health(self) -> None:
        """Emit a periodic INFO log with buffer / queue / delay stats."""
        if not self._match_delays:
            logger.info(
                "NSourceCorrelator: sources=%d, buffer=%d, queue=%d, no matches yet",
                self._n,
                len(self._buffer),
                self._output.qsize(),
            )
            return

        sorted_delays = sorted(self._match_delays)
        median = sorted_delays[len(sorted_delays) // 2]
        max_delay = sorted_delays[-1]
        warning = ""
        if median > 0.6 * self._window:
            warning = (
                f" (WARNING: median delay {median:.1f}s exceeds 60% of "
                f"window {self._window:.0f}s — consider raising the window)"
            )
        logger.info(
            "NSourceCorrelator: sources=%d, buffer=%d, queue=%d, "
            "match_delay median=%.2fs max=%.2fs (samples=%d)%s",
            self._n,
            len(self._buffer),
            self._output.qsize(),
            median,
            max_delay,
            len(self._match_delays),
            warning,
        )

    async def _teardown(self) -> None:
        """Cancel pump + sweeper tasks. Idempotent."""
        self._stopped = True
        for task in self._tasks:
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        self._buffer.clear()


__all__ = ("DEFAULT_WINDOW_S", "NSourceCorrelator")
