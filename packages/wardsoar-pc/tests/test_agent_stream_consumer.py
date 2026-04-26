"""Tests for :class:`AgentStreamConsumer` (Phase 3b.5).

The consumer is a thin Qt-aware wrapper that drives an agent's
``stream_alerts()`` async iterator and emits each yielded event as
a Qt signal. We test the asyncio-side (:meth:`_consume`) directly
without spinning up a QThread — Qt signals are still emitted
because the receiver is held by ``MagicMock`` slots, which works
for unit tests as long as a ``QApplication`` exists.

Three things matter and are exercised:

1. Each event yielded by ``stream_alerts`` reaches a connected slot
   via ``event_received(dict)``.
2. ``status_changed`` fires ``"Connected"`` exactly once on the
   first event so the dashboard banner is correct.
3. An exception out of ``stream_alerts`` is caught, logged, and
   surfaced via ``status_changed("Disconnected", detail)`` rather
   than propagating to the Qt thread.
"""

from __future__ import annotations

from typing import Any, AsyncIterator

import pytest
from PySide6.QtWidgets import QApplication

from wardsoar.pc.ui.agent_stream_consumer import AgentStreamConsumer


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a singleton QApplication so Qt signals can dispatch."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


class _StubAgent:
    """Minimal stand-in for :class:`RemoteAgent` that yields a scripted
    sequence of events (or raises after N).
    """

    def __init__(
        self,
        events: list[dict[str, Any]],
        raise_after: int | None = None,
        exception: Exception | None = None,
    ) -> None:
        self._events = events
        self._raise_after = raise_after
        self._exception = exception or RuntimeError("stub error")

    # The other Protocol methods aren't exercised here — the consumer
    # only calls ``stream_alerts``.
    async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        for index, event in enumerate(self._events):
            if self._raise_after is not None and index >= self._raise_after:
                raise self._exception
            yield event


class TestAgentStreamConsumerConsume:
    """Exercise the asyncio-side ``_consume`` coroutine directly."""

    @pytest.mark.asyncio
    async def test_each_event_emits_event_received_signal(self, qapp: QApplication) -> None:
        agent = _StubAgent(
            [
                {"event_type": "alert", "src_ip": "203.0.113.7"},
                {"event_type": "alert", "src_ip": "198.51.100.4"},
                {"event_type": "stats"},
            ]
        )
        consumer = AgentStreamConsumer(agent=agent)  # type: ignore[arg-type]
        consumer._running = True  # would normally be set in run()  # noqa: SLF001

        emitted: list[dict[str, Any]] = []
        consumer.event_received.connect(emitted.append)

        await consumer._consume()  # noqa: SLF001

        assert emitted == [
            {"event_type": "alert", "src_ip": "203.0.113.7"},
            {"event_type": "alert", "src_ip": "198.51.100.4"},
            {"event_type": "stats"},
        ]

    @pytest.mark.asyncio
    async def test_first_event_emits_connected_status(self, qapp: QApplication) -> None:
        agent = _StubAgent([{"event_type": "alert"}])
        consumer = AgentStreamConsumer(agent=agent)  # type: ignore[arg-type]
        consumer._running = True  # noqa: SLF001

        statuses: list[tuple[str, str]] = []
        consumer.status_changed.connect(lambda s, d: statuses.append((s, d)))

        await consumer._consume()  # noqa: SLF001

        # Exactly one Connected event, fired before the first event_received.
        assert statuses == [("Connected", "_StubAgent")]

    @pytest.mark.asyncio
    async def test_exception_in_stream_emits_disconnected_status(self, qapp: QApplication) -> None:
        agent = _StubAgent(
            [{"event_type": "alert", "id": 1}, {"event_type": "alert", "id": 2}],
            raise_after=1,
            exception=RuntimeError("transport fell off"),
        )
        consumer = AgentStreamConsumer(agent=agent)  # type: ignore[arg-type]
        consumer._running = True  # noqa: SLF001

        statuses: list[tuple[str, str]] = []
        consumer.status_changed.connect(lambda s, d: statuses.append((s, d)))
        emitted: list[dict[str, Any]] = []
        consumer.event_received.connect(emitted.append)

        # Must not raise — the consumer swallows the exception so the
        # UI thread keeps running and the dashboard sees a degraded
        # state instead.
        await consumer._consume()  # noqa: SLF001

        # First event delivered, then transport error → Disconnected.
        assert emitted == [{"event_type": "alert", "id": 1}]
        assert ("Disconnected", "transport fell off") in statuses

    @pytest.mark.asyncio
    async def test_stops_when_running_flag_cleared(self, qapp: QApplication) -> None:
        """Setting ``_running`` to False mid-stream causes the loop to
        break out — used by :meth:`stop` for graceful shutdown."""

        events_emitted: list[dict[str, Any]] = []

        class _StoppableAgent:
            def __init__(self, target: AgentStreamConsumer) -> None:
                self._target = target

            async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
                yield {"event_type": "alert", "id": 1}
                # Operator stop arrives between events.
                self._target._running = False  # noqa: SLF001
                yield {"event_type": "alert", "id": 2}
                yield {"event_type": "alert", "id": 3}

        consumer = AgentStreamConsumer(agent=_StoppableAgent(None))  # type: ignore[arg-type]
        consumer._agent = _StoppableAgent(consumer)  # rebind with self-reference  # noqa: SLF001
        consumer._running = True  # noqa: SLF001
        consumer.event_received.connect(events_emitted.append)

        await consumer._consume()  # noqa: SLF001

        # Only the first event made it; the running flag was cleared
        # before the second yield was processed.
        assert events_emitted == [{"event_type": "alert", "id": 1}]
