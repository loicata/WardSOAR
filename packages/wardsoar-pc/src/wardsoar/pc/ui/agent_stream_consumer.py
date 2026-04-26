"""Qt-aware consumer of a :class:`RemoteAgent`'s alert stream.

Replaces the legacy :class:`SshStreamer` (Phase 3b.5). The pipeline
no longer reaches into the SSH transport directly; instead it
consumes ``agent.stream_alerts()`` — an :class:`AsyncIterator` of
parsed EVE JSON events — from any agent that satisfies the
:class:`RemoteAgent` Protocol.

This keeps the live alert path uniform across:

* :class:`NetgateAgent` (today, SSH+``tail -f`` to pfSense)
* a future ``VsAgent`` (Virus Sniff RPi reading the local eve.json
  shipped over USB Gadget)
* a future co-resident ``WindowsFirewallBlocker`` once Suricata-on-
  Windows lands

The Qt surface stays exactly what :class:`SshStreamer` exposed —
``status_changed(str, str)`` for the dashboard banner — but the
``line_received(str)`` signal is replaced by ``event_received(dict)``
since the agent has already parsed the JSON. Downstream consumers
(``EngineWorker.on_alert_event`` → ``PipelineController.on_alert_event``)
no longer need a JSON-decode pass.

Reconnection is owned by the agent's ``stream_alerts``
implementation (see :meth:`PfSenseSSH.stream_alerts` for the SSH
case — exponential backoff up to 60s, infinite). The consumer just
iterates; if the iterator yields nothing forever (e.g. ``NoOpAgent``)
the thread is idle and that is fine.

Fail-safe: an unexpected exception out of ``stream_alerts`` is
logged and the thread exits cleanly. The dashboard receives a
``Disconnected`` status so the operator sees a degraded state
rather than silent stop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from PySide6.QtCore import QThread, Signal

from wardsoar.core.remote_agents import RemoteAgent

logger = logging.getLogger("ward_soar.agent_stream_consumer")


class AgentStreamConsumer(QThread):
    """Consume ``agent.stream_alerts()`` and emit each event as a Qt signal.

    Args:
        agent: A :class:`RemoteAgent` whose ``stream_alerts()`` yields
            parsed EVE events. Reconnection is the agent's
            responsibility — this class does not retry on its own.
        parent: Parent QObject (Qt ownership).

    Signals:
        event_received(dict): Emitted once per yielded EVE event.
        status_changed(str, str): ``(state, detail)`` updates for the
            dashboard banner. Emitted at startup, on the first event,
            and on graceful / failure shutdown.
    """

    event_received = Signal(dict)
    status_changed = Signal(str, str)

    def __init__(self, agent: RemoteAgent, parent: Optional[Any] = None) -> None:
        super().__init__(parent)
        self._agent = agent
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def run(self) -> None:
        """Thread entry — drive the asyncio loop that consumes the agent."""
        self._running = True

        agent_name = type(self._agent).__name__
        logger.info("AgentStreamConsumer starting (agent=%s)", agent_name)
        self.status_changed.emit("Connecting", agent_name)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._consume())
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

        self.status_changed.emit("Stopped", "stream consumer stopped")
        logger.info("AgentStreamConsumer stopped (agent=%s)", agent_name)

    async def _consume(self) -> None:
        """Iterate the agent's stream and emit events one by one."""
        agent_name = type(self._agent).__name__
        first_event = True
        try:
            async for event in self._agent.stream_alerts():
                if not self._running:
                    break
                if first_event:
                    self.status_changed.emit("Connected", agent_name)
                    first_event = False
                self.event_received.emit(event)
        except asyncio.CancelledError:
            # Operator-initiated stop.
            raise
        except Exception as exc:  # noqa: BLE001 — never crash the UI thread
            detail = str(exc) or type(exc).__name__
            logger.error("AgentStreamConsumer: stream error (%s) — exiting", detail)
            self.status_changed.emit("Disconnected", detail)

    def stop(self) -> None:
        """Stop the consumer — thread-safe, callable from the main thread.

        Sets the ``_running`` flag (so the next iteration breaks out) and
        asks the loop to stop. The ``finally`` block in :meth:`run`
        cancels any outstanding tasks (notably the agent's
        ``stream_alerts`` async generator, which propagates cancellation
        through ``aclose()`` to close any open SSH session cleanly).
        """
        self._running = False
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
