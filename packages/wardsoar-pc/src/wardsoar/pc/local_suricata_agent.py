"""``RemoteAgent`` implementation for a local Suricata install.

Used in standalone-PC mode (operator answered Netgate=No,
Suricata_local=Yes to the :class:`SourcesQuestionnaire`) and as
the *second* source in dual-Suricata configs (3 and 5 of the memo
``project_dual_suricata_sync.md``). The agent owns the local
Suricata process via :class:`wardsoar.pc.local_suricata.SuricataProcess`,
consumes the eve.json it writes, and delegates every enforcement-
related Protocol method to a composed
:class:`wardsoar.pc.windows_firewall.WindowsFirewallBlocker`.

Topology:

    LocalSuricataAgent
       │
       ├── SuricataProcess  (start / stop / monitor suricata.exe)
       │       └── writes eve.json to disk
       │
       ├── stream_alerts()  ←── reads eve.json (tail-follow)
       │
       └── enforcement methods → WindowsFirewallBlocker (composition)

Lifecycle:
    The agent **owns** the Suricata process. ``startup()`` spawns
    Suricata; ``shutdown()`` gracefully terminates it.
    :class:`Pipeline` calls these at boot / teardown. The eve.json
    file is shared state: read by :meth:`stream_alerts`, written
    by Suricata.

Doctrine cross-references:
    * ``project_local_suricata_plan.md`` — license rationale and
      install plan
    * ``project_dual_suricata_sync.md`` — stratégie de
      synchronisation 2 Suricata (configs 3 / 5)

Fail-safe:
    Every method catches local errors and returns the documented
    failure value rather than raising — same contract as the other
    agents. Streaming reconnects on file rotation and waits
    politely if the file does not yet exist (Suricata still
    booting, eve.json file rotated, etc.).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, AsyncIterator

from wardsoar.pc.local_suricata import SuricataProcess
from wardsoar.pc.windows_firewall import WindowsFirewallBlocker

logger = logging.getLogger("ward_soar.local_suricata_agent")


# How often we poll the eve.json file when nothing has changed.
# Suricata flushes EVE writes every 1-2s under load, so 1s polling
# keeps latency low without burning CPU.
_POLL_INTERVAL_S: float = 1.0

# Wait time when the eve.json file is missing entirely (Suricata
# still booting, wrong path, or service stopped). Logs a warning
# every Nth retry so the operator notices, but never raises.
_MISSING_FILE_RETRY_S: float = 5.0

# Cap on bytes read per poll so a Suricata burst can't blow memory.
_MAX_READ_PER_POLL_BYTES: int = 4 * 1024 * 1024  # 4 MiB

# Status freshness threshold. Beyond this, ``check_status`` reports
# the agent as degraded — usually means the Suricata process has
# died or hung.
_STATUS_FRESHNESS_THRESHOLD_S: float = 120.0


class LocalSuricataAgent:
    """``RemoteAgent`` that owns a local Suricata process.

    Composes :class:`SuricataProcess` for lifecycle and
    :class:`WindowsFirewallBlocker` for enforcement.

    Args:
        process: A :class:`SuricataProcess` instance configured with
            the operator's chosen interface and config path. The
            agent calls ``start()`` from :meth:`startup` and
            ``stop()`` from :meth:`shutdown`.
        blocker: A :class:`WindowsFirewallBlocker` instance that
            implements every enforcement-related Protocol method.
            Composition (not inheritance) keeps the two concerns
            independently testable and avoids a Liskov risk on
            ``WindowsFirewallBlocker``'s sink-only ``stream_alerts``.
        poll_interval_s: Override the eve.json poll cadence. Default
            1 s. Tests pass a smaller value to speed up iterations.
    """

    def __init__(
        self,
        process: SuricataProcess,
        blocker: WindowsFirewallBlocker,
        poll_interval_s: float = _POLL_INTERVAL_S,
    ) -> None:
        self._process = process
        self._blocker = blocker
        self._poll_interval = max(0.0, float(poll_interval_s))
        # Updated on each ``stream_alerts`` invocation: the byte offset
        # within eve.json from which we read forward. Set to current
        # file size on first connect so historical events are not
        # replayed into the pipeline.
        self._read_offset: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def startup(self) -> None:
        """Spawn the Suricata process. Idempotent."""
        await self._process.start()

    async def shutdown(self) -> None:
        """Gracefully terminate the Suricata process. Idempotent."""
        await self._process.stop()

    @property
    def eve_path(self) -> Path:
        """The eve.json path Suricata writes to (read by stream_alerts)."""
        return self._process.eve_path

    # ------------------------------------------------------------------
    # RemoteAgent protocol surface
    # ------------------------------------------------------------------

    async def check_status(self) -> tuple[bool, str]:
        """Probe whether the local Suricata install is producing events.

        Healthy means the Suricata process is running AND the
        eve.json file was updated within
        :data:`_STATUS_FRESHNESS_THRESHOLD_S` seconds. Stale or
        missing surfaces a clear message in the dashboard so the
        operator notices a stopped process.
        """
        if not self._process.is_running():
            return (False, "Suricata process is not running")

        try:
            stat = await asyncio.to_thread(self.eve_path.stat)
        except FileNotFoundError:
            return (
                False,
                f"eve.json not found at {self.eve_path} — Suricata may still be booting",
            )
        except OSError as exc:
            return False, f"cannot stat eve.json: {exc}"

        age = max(0.0, time.time() - stat.st_mtime)
        if age > _STATUS_FRESHNESS_THRESHOLD_S:
            return (
                False,
                f"eve.json is stale ({int(age)}s since last write) — Suricata stalled?",
            )
        return True, f"eve.json is fresh ({int(age)}s old)"

    async def add_to_blocklist(self, ip: str) -> bool:
        return await self._blocker.add_to_blocklist(ip)

    async def remove_from_blocklist(self, ip: str) -> bool:
        return await self._blocker.remove_from_blocklist(ip)

    async def is_blocked(self, ip: str) -> bool:
        return await self._blocker.is_blocked(ip)

    async def list_blocklist(self) -> list[str]:
        return await self._blocker.list_blocklist()

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        """Co-resident agent — delegate to the local firewall blocker.

        Both this agent and the Suricata process run on the same host
        as the suspect process, so killing it is meaningful (unlike
        ``NetgateAgent`` which is off-host and refuses).
        """
        return await self._blocker.kill_process_on_target(pid)

    async def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        """Tail-follow the local eve.json and yield each parsed event.

        Behaviour:

        * On first call the read offset is set to the **current file
          size** so historical events are NOT replayed into the
          pipeline — the operator only sees alerts emitted from this
          point forward (mirrors ``tail -n 0 -f``).
        * Each poll cycle reads new bytes from the last offset,
          splits on newlines, parses each line as JSON, and yields
          the resulting dict. Non-JSON lines are dropped silently
          (Suricata interleaves daemon notices like
          "Engine started", "Detection engine ready").
        * On a file shrink (Suricata rotated the log: file size now
          smaller than our offset) we reset the offset to 0 and
          read from the beginning of the rotated file.
        * On ``FileNotFoundError`` we sleep and retry — this lets
          the operator restart Suricata after WardSOAR without
          restarting WardSOAR.
        * On any other ``OSError`` we log + sleep + retry. Never
          raises a transport exception to the consumer.

        The async generator never terminates on its own. The
        consumer breaks the loop or calls ``aclose()`` (e.g. from
        :meth:`AgentStreamConsumer.stop`).
        """
        # Position the offset at end-of-file if it exists — we don't
        # want to replay history on startup.
        try:
            stat = await asyncio.to_thread(self.eve_path.stat)
            self._read_offset = stat.st_size
            logger.info(
                "LocalSuricataAgent: tailing %s (starting offset=%d)",
                self.eve_path,
                self._read_offset,
            )
        except FileNotFoundError:
            logger.warning(
                "LocalSuricataAgent: %s does not exist yet — waiting for Suricata",
                self.eve_path,
            )
            self._read_offset = 0
        except OSError as exc:
            logger.warning(
                "LocalSuricataAgent: cannot stat %s (%s) — starting at offset 0",
                self.eve_path,
                exc,
            )
            self._read_offset = 0

        consecutive_missing_logs = 0

        while True:
            try:
                stat = await asyncio.to_thread(self.eve_path.stat)
            except FileNotFoundError:
                # Periodic warn so the operator notices, but don't
                # spam the log on every poll.
                if consecutive_missing_logs % 12 == 0:
                    logger.warning("LocalSuricataAgent: %s still missing", self.eve_path)
                consecutive_missing_logs += 1
                await asyncio.sleep(_MISSING_FILE_RETRY_S)
                self._read_offset = 0
                continue
            except OSError as exc:
                logger.warning(
                    "LocalSuricataAgent: stat error on %s: %s — backing off",
                    self.eve_path,
                    exc,
                )
                await asyncio.sleep(_MISSING_FILE_RETRY_S)
                continue

            if consecutive_missing_logs:
                logger.info(
                    "LocalSuricataAgent: %s now present, resuming tail",
                    self.eve_path,
                )
                consecutive_missing_logs = 0

            current_size = stat.st_size

            # File rotation: size dropped below our offset → start
            # reading from the new beginning.
            if current_size < self._read_offset:
                logger.info(
                    "LocalSuricataAgent: %s shrank (rotated) — resetting offset",
                    self.eve_path,
                )
                self._read_offset = 0

            # No new bytes since last poll: sleep + retry.
            if current_size == self._read_offset:
                await asyncio.sleep(self._poll_interval)
                continue

            # Cap how many bytes we ingest per poll so a Suricata
            # burst can't blow our memory.
            to_read = min(current_size - self._read_offset, _MAX_READ_PER_POLL_BYTES)
            try:
                new_bytes = await asyncio.to_thread(self._read_chunk, self._read_offset, to_read)
            except OSError as exc:
                logger.warning(
                    "LocalSuricataAgent: read error on %s: %s — backing off",
                    self.eve_path,
                    exc,
                )
                await asyncio.sleep(_MISSING_FILE_RETRY_S)
                continue

            self._read_offset += len(new_bytes)

            # Split on newlines. The last fragment is incomplete if
            # Suricata is mid-write — we drop it. The next poll
            # picks up the missed bytes via the advanced offset, so
            # at most one event is lost per restart, acceptable for
            # an IDS event stream.
            for line in new_bytes.split(b"\n"):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    # Daemon notices, truncated writes — drop.
                    continue
                if isinstance(event, dict):
                    yield event

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_chunk(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes from ``self.eve_path`` starting at ``offset``.

        Synchronous helper, called from an executor thread by
        :meth:`stream_alerts` so the main event loop is never
        blocked on disk I/O.
        """
        with self.eve_path.open("rb") as f:
            f.seek(offset)
            return f.read(size)


__all__ = ("LocalSuricataAgent",)
