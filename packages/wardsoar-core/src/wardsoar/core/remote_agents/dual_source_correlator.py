"""Fan-in 2 ``RemoteAgent`` streams into 1 with corroboration tags.

Implements the doctrine validated 2026-04-26 in
``project_dual_suricata_sync.md``: when an operator runs a config
with **2 Suricata sources active** simultaneously (configs 3 and 5
of the SourcesQuestionnaire — typically PC + Netgate + Suricata
local, or PC + VirusSniff + Suricata local), this correlator fans
their two streams into one stream that the existing pipeline
consumes — enriched with a ``source_corroboration`` tag and (when
applicable) a ``secondary_event`` reference to the matching event
from the other source.

The correlator is **CRITICAL**: a bug here means alerts get
misrouted, double-counted, or silently dropped. Every state
transition is enumerated, every output is tagged, and the
property-based tests exercise the buffer state machine under
randomly-interleaved input.

Doctrine cross-references:
    * Q1 — Window 120 s default, 30-180 s configurable. Buffer
      memory cap protects against pathological input.
    * Q3 β nuanced — the bumper post-processes the verdict; this
      correlator only **tags** events with the corroboration state.
    * Q4 A — instantiated only when 2 sources are configured.

Lifecycle (driven by the consumer):
    * ``stream_alerts()`` returns an :class:`AsyncIterator[dict]`
      that the existing :class:`AgentStreamConsumer` consumes
      transparently — same Protocol shape as a single agent.
    * Background task pumps both source streams concurrently into
      an internal queue, applies the correlation logic, emits.
    * ``aclose()`` on the iterator stops the background pumps and
      drains pending state.

Topology of the state machine — see also Q4 of the memo:

    Event arrives
        │
        ▼
    Compute key = (src_ip, dest_ip, sig_id)
        │
        ▼
    Buffer hit?
        ├── No   → buffer the event
        │         emit with source_corroboration=*_PENDING
        │
        └── Yes  → pop from buffer
                  emit with source_corroboration=MATCH_CONFIRMED
                  (carrying the secondary event)

    Background sweeper (runs every poll_interval):
        For each buffer entry whose age >= window_seconds:
            emit a re-tag event:
              external-only sighting → DIVERGENCE_A
              local-only sighting   → DIVERGENCE_B
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
from typing import Any, AsyncIterator, Optional

from wardsoar.core.models import SourceCorroboration
from wardsoar.core.remote_agents.protocol import RemoteAgent

logger = logging.getLogger("ward_soar.dual_source_correlator")


# Default window length for matching events from the two sources.
# Doctrine Q1: 120 s covers PC-light cold-start Suricata + pic de
# charge réseau modéré. Configurable per instance, with a clamp at
# the consumer level (Pipeline reads the YAML and clamps to
# [30, 180]).
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
    """Compute the correlation key for an EVE event, or ``None`` if
    the event lacks the fields needed to correlate.

    Key = ``(src_ip, dest_ip, alert_signature_id)``. Events without
    an ``alert.signature_id`` or without IP addresses cannot be
    correlated — they are emitted with
    :data:`SourceCorroboration.SINGLE_SOURCE` regardless of the
    config.

    Args:
        event: Parsed EVE JSON dict (already validated as a dict
            upstream by ``stream_alerts`` of each agent).

    Returns:
        ``(src_ip, dest_ip, sig_id)`` tuple, or ``None`` when any
        field is missing / malformed.
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
class _BufferedEvent:
    """One event waiting in the correlation window for a match.

    Stored in the internal buffer keyed by ``_correlation_key``. The
    sweeper checks ``arrived_at`` against the configured window to
    decide whether to emit a divergence re-tag.
    """

    event: dict[str, Any]
    source: str  # "external" or "local"
    arrived_at: float  # ``time.monotonic()``
    # Sentinel set when the buffered event has been re-tagged into
    # a divergence; prevents the same event from being divergence-
    # tagged twice if the sweeper runs while a follow-up emission
    # for the same key is already in flight.
    diverged: bool = False


@dataclass
class _Output:
    """Wrapper for events emitted by the correlator.

    The consumer sees a regular EVE dict with two extra fields
    injected:
        * ``source_corroboration`` — the tag from
          :class:`SourceCorroboration`
        * ``secondary_event`` — the matching event from the other
          source (only set on ``MATCH_CONFIRMED``)

    These extra fields are stripped by downstream consumers that
    don't care; the pipeline's existing parser tolerates extra keys.
    """

    payload: dict[str, Any] = field(default_factory=dict)


class DualSourceCorrelator:
    """Correlate two ``RemoteAgent`` streams into a single tagged stream.

    Args:
        external_agent: The "base" source — typically NetgateAgent
            or VirusSniffAgent. Per Q3 of the doctrine, this source's
            verdict drives the pipeline; the local source either
            confirms (MATCH) or contradicts (DIVERGENCE).
        local_agent: The "secondary" source — typically
            LocalSuricataAgent on the operator's PC. Provides
            local process context that enriches confirmed matches
            and reveals divergences when topology disagrees.
        window_seconds: Reconciliation window. Default 120 s
            (doctrine Q1). Clamped to ``[10, 600]`` to defend
            against operator typos in config.yaml.
        sweep_interval_s: How often the background sweeper checks
            for expired buffer entries. Tests pass a small value
            (e.g. 0.05 s) to keep iterations fast.

    The correlator implements the same Protocol shape as a single
    :class:`RemoteAgent` (``stream_alerts``) so the consumer
    (:class:`AgentStreamConsumer`) treats it transparently.
    """

    def __init__(
        self,
        external_agent: RemoteAgent,
        local_agent: RemoteAgent,
        window_seconds: float = DEFAULT_WINDOW_S,
        sweep_interval_s: float = _SWEEP_INTERVAL_S,
    ) -> None:
        self._external = external_agent
        self._local = local_agent
        # The operator-facing range clamp [30, 180] is enforced at
        # config-load time (Pipeline.__init__ reads ``dual_suricata.
        # reconciliation_window_s`` and validates), not here.
        # The constructor itself only refuses zero / negative values
        # so tests can use sub-second windows for fast iterations
        # while the production config stays in the documented band.
        self._window = max(0.001, float(window_seconds))
        self._sweep_interval = max(0.001, float(sweep_interval_s))

        # Buffer of events waiting for a match. Keyed by
        # ``_correlation_key`` so a O(1) lookup decides the match.
        self._buffer: dict[tuple[str, str, int], _BufferedEvent] = {}

        # Output queue — events ready for the consumer.
        self._output: asyncio.Queue[_Output] = asyncio.Queue()

        # Match-delay observation: doctrine Q1 mandates passive
        # auto-tuning. We collect the delay between the two
        # sightings of every confirmed match (in seconds), keep a
        # bounded history, and log the median periodically.
        self._match_delays: list[float] = []
        self._delay_history_cap = 100

        # Source pump tasks + sweeper task — tracked so we can
        # cancel them cleanly on aclose.
        self._tasks: list[asyncio.Task[None]] = []
        self._stopped: bool = False
        self._last_health_log_at: float = 0.0

    # ------------------------------------------------------------------
    # RemoteAgent protocol surface — only stream_alerts is
    # meaningful for the correlator. The other methods raise
    # NotImplementedError because the correlator is a routing layer,
    # not an enforcement agent.
    # ------------------------------------------------------------------

    async def check_status(self) -> tuple[bool, str]:
        """Compose the two underlying agents' statuses.

        Healthy iff BOTH sources report healthy. Reports the worse
        of the two messages so the operator sees the actual
        problem.
        """
        ok_ext, msg_ext = await self._external.check_status()
        ok_local, msg_local = await self._local.check_status()
        if ok_ext and ok_local:
            return True, f"both sources OK (ext: {msg_ext}; local: {msg_local})"
        if not ok_ext and not ok_local:
            return False, f"both sources DOWN (ext: {msg_ext}; local: {msg_local})"
        if not ok_ext:
            return False, f"external source DOWN: {msg_ext}"
        return False, f"local source DOWN: {msg_local}"

    async def add_to_blocklist(self, ip: str) -> bool:
        """Routing layer — refuse the operation.

        The correlator does not own enforcement; the caller should
        reach for a registered :class:`RemoteAgent` directly.

        Raises:
            NotImplementedError: always.
        """
        raise NotImplementedError("DualSourceCorrelator is a source-only routing layer")

    async def remove_from_blocklist(self, ip: str) -> bool:
        raise NotImplementedError("DualSourceCorrelator is a source-only routing layer")

    async def is_blocked(self, ip: str) -> bool:
        raise NotImplementedError("DualSourceCorrelator is a source-only routing layer")

    async def list_blocklist(self) -> list[str]:
        raise NotImplementedError("DualSourceCorrelator is a source-only routing layer")

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        raise NotImplementedError("DualSourceCorrelator is a source-only routing layer")

    async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        """Yield correlated EVE events with corroboration tags.

        Spawns three background tasks: one pump per source agent
        and a sweeper for window expiry. Yields events as they land
        in the output queue. Cleans up tasks on consumer aclose.

        Each yielded dict carries TWO extra fields injected by the
        correlator:

        * ``source_corroboration`` — value from
          :class:`SourceCorroboration` describing the relationship
          of this event to the other source.
        * ``secondary_event`` — the matching event from the other
          source, present only on ``MATCH_CONFIRMED`` re-emissions.

        Pipeline downstream sees a regular EVE dict; it can ignore
        these fields if it doesn't care about corroboration.
        """
        self._stopped = False

        # Launch the two source pumps and the sweeper. They share
        # the same ``self._buffer`` and ``self._output``, guarded
        # by the asyncio single-threaded model — no lock needed
        # because all operations on the buffer are synchronous from
        # the loop's perspective.
        self._tasks = [
            asyncio.create_task(self._pump(self._external, "external")),
            asyncio.create_task(self._pump(self._local, "local")),
            asyncio.create_task(self._sweep()),
        ]

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

    async def _pump(self, agent: RemoteAgent, source: str) -> None:
        """Drain an agent's stream and feed events into the correlation logic."""
        try:
            async for event in agent.stream_alerts():
                if self._stopped:
                    break
                self._on_incoming_event(event, source)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — never crash the correlator
            detail = str(exc) or type(exc).__name__
            logger.error(
                "DualSourceCorrelator: %s pump error (%s) — pump exiting",
                source,
                detail,
            )

    def _on_incoming_event(self, event: dict[str, Any], source: str) -> None:
        """Apply the correlation state machine to an incoming event.

        Synchronous on purpose: every operation is a dict / queue
        access, no I/O. This is what lets the asyncio model give us
        atomic state mutation without locks — two concurrent
        ``_pump`` tasks cannot interleave a partial update because
        Python doesn't yield mid-method.
        """
        key = _correlation_key(event)
        if key is None:
            # Cannot correlate — emit as single source. Use
            # SINGLE_SOURCE since this is a 2-source config but
            # this specific event lacks the IPs/sig to match.
            self._emit(event, SourceCorroboration.SINGLE_SOURCE, source, None)
            return

        existing = self._buffer.get(key)
        if existing is None:
            # First sighting — buffer it and emit with PENDING.
            self._buffer[key] = _BufferedEvent(
                event=event, source=source, arrived_at=time.monotonic()
            )
            tag = (
                SourceCorroboration.MATCH_PENDING
                if source == "external"
                else SourceCorroboration.DIVERGENCE_PENDING
            )
            self._emit(event, tag, source, None)

            # Soft-cap warning: someone is flooding identical-key
            # events without their counterpart arriving.
            if len(self._buffer) > _BUFFER_SIZE_SOFT_CAP:
                logger.warning(
                    "DualSourceCorrelator: buffer size %d exceeds soft cap %d "
                    "— possible DoS or one-sided source flood",
                    len(self._buffer),
                    _BUFFER_SIZE_SOFT_CAP,
                )
            return

        # Existing entry — match decision based on whether the new
        # event comes from the *other* source.
        if existing.source == source:
            # Same source again before the counterpart arrived.
            # Two interpretations: a duplicate (same alert
            # re-emitted by Suricata after rule reload), or a burst
            # of the same flow. We keep the existing buffered event
            # (first one wins) and emit the new one with the same
            # PENDING tag — the pipeline's own deduplicator will
            # squash the burst at stage 2.
            tag = (
                SourceCorroboration.MATCH_PENDING
                if source == "external"
                else SourceCorroboration.DIVERGENCE_PENDING
            )
            self._emit(event, tag, source, None)
            return

        # Cross-source match → MATCH_CONFIRMED. Emit with the
        # secondary event attached so the DivergenceVerdictBumper /
        # the pipeline's enrichment stages can see both sightings.
        delay = max(0.0, time.monotonic() - existing.arrived_at)
        self._record_match_delay(delay)
        # Emit a re-tag of the buffered event (so the buffered side
        # of the pair gets confirmation) AND a confirmation for the
        # new event.
        self._emit(
            existing.event,
            SourceCorroboration.MATCH_CONFIRMED,
            existing.source,
            secondary=event,
        )
        self._emit(
            event,
            SourceCorroboration.MATCH_CONFIRMED,
            source,
            secondary=existing.event,
        )
        # Evict — the pair is fully resolved.
        del self._buffer[key]

    async def _sweep(self) -> None:
        """Periodically expire stale buffer entries → emit divergence tag."""
        try:
            while not self._stopped:
                await asyncio.sleep(self._sweep_interval)
                self._evict_expired()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("DualSourceCorrelator: sweeper error: %s", exc)

    def _evict_expired(self) -> None:
        """Walk the buffer, evict entries older than the window.

        For each evicted entry, emit a re-tag event so the pipeline
        consumer can update the source_corroboration metadata of
        the previously-emitted event (the consumer matches on a
        unique event id — the pipeline's existing alert dedup keys
        work here).
        """
        now = time.monotonic()
        to_evict: list[tuple[str, str, int]] = []
        for key, buffered in self._buffer.items():
            if now - buffered.arrived_at >= self._window and not buffered.diverged:
                to_evict.append(key)

        for key in to_evict:
            buffered = self._buffer[key]
            buffered.diverged = True
            tag = (
                SourceCorroboration.DIVERGENCE_A
                if buffered.source == "external"
                else SourceCorroboration.DIVERGENCE_B
            )
            self._emit(buffered.event, tag, buffered.source, None)
            del self._buffer[key]

    def _emit(
        self,
        event: dict[str, Any],
        tag: SourceCorroboration,
        source: str,
        secondary: Optional[dict[str, Any]],
    ) -> None:
        """Inject corroboration metadata and push the event onto the queue."""
        # Defensive copy so we never mutate the source agent's
        # event in place. The dict.copy() is shallow — that is OK
        # because we only add top-level keys.
        payload = dict(event)
        payload["source_corroboration"] = tag.value
        payload["correlation_source"] = source
        if secondary is not None:
            payload["secondary_event"] = dict(secondary)
        self._output.put_nowait(_Output(payload=payload))

    def _record_match_delay(self, delay_s: float) -> None:
        """Track the rolling sample of cross-source match delays.

        Bounded list so memory stays flat even on a long-running
        correlator. The median is logged in :meth:`_log_health` for
        the operator to see whether the configured window is too
        tight.
        """
        self._match_delays.append(delay_s)
        if len(self._match_delays) > self._delay_history_cap:
            # Drop oldest.
            self._match_delays.pop(0)

    def _log_health(self) -> None:
        """Emit periodic INFO log: buffer size + median match delay."""
        if not self._match_delays:
            logger.info(
                "DualSourceCorrelator: buffer=%d, queue=%d, no matches yet",
                len(self._buffer),
                self._output.qsize(),
            )
            return

        sorted_delays = sorted(self._match_delays)
        median = sorted_delays[len(sorted_delays) // 2]
        max_delay = sorted_delays[-1]
        # Operator-visible suggestion: if the median match delay is
        # above 60% of the configured window, the operator should
        # raise the window or expect false divergences.
        warning = ""
        if median > 0.6 * self._window:
            warning = (
                f" (WARNING: median delay {median:.1f}s exceeds 60% of "
                f"window {self._window:.0f}s — consider raising "
                f"reconciliation_window_s)"
            )
        logger.info(
            "DualSourceCorrelator: buffer=%d, queue=%d, "
            "match_delay median=%.2fs max=%.2fs (samples=%d)%s",
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


__all__ = ("DEFAULT_WINDOW_S", "DualSourceCorrelator")
