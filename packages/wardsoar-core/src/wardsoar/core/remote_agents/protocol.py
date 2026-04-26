"""Formal ``RemoteAgent`` protocol shared by every remote sensor/enforcer.

A *remote agent* is any external box (Netgate appliance, Virus Sniff
Raspberry Pi, third-party sensor) that the WardSOAR pipeline uses to
observe traffic OR to enforce blocking decisions. They differ in OS,
shell, and detection engine, but the operations exposed to the pipeline
are uniform: probe reachability, list/add/remove deny-list entries.

This module ships the structural contract only; concrete classes live
next to it (``pfsense_ssh.py`` for the Netgate, future ``virus_sniff.py``
for the Pi). Pipeline code consuming an agent depends on this Protocol,
not on the concrete type — so wiring a second agent later requires no
changes to ``responder``, ``rule_manager``, or the audit layer.

The protocol is ``runtime_checkable`` for ergonomic ``isinstance`` guards
at registration time; note that ``runtime_checkable`` only verifies that
the named methods exist, not their signatures, so ``mypy --strict``
remains the authoritative check.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Protocol, runtime_checkable


@runtime_checkable
class RemoteAgent(Protocol):
    """Minimal contract every concrete agent must satisfy.

    Methods are async because every known and planned implementation
    (SSH-over-asyncssh today, EVE socket streaming tomorrow) is I/O
    bound and the pipeline already runs under an event loop.

    All operations are fail-safe by contract: implementations must
    catch transport errors internally and translate them to the
    documented return shape (``False`` / empty list) — they MUST NOT
    raise to the caller. This mirrors the behaviour of ``PfSenseSSH``
    today and is what lets the responder degrade gracefully when the
    appliance is offline.
    """

    async def check_status(self) -> tuple[bool, str]:
        """Probe whether the agent is reachable and responsive.

        Returns:
            ``(reachable, human_readable_message)``. The message is
            surfaced in the UI / logs verbatim, so it should be short
            and operator-friendly (no stack traces).
        """
        ...

    async def add_to_blocklist(self, ip: str) -> bool:
        """Add ``ip`` to the agent's persistent deny list. Idempotent.

        Returns:
            ``True`` if the IP is now denied (whether it was just added
            or was already present). ``False`` on validation failure or
            on any transport / persistence error.
        """
        ...

    async def remove_from_blocklist(self, ip: str) -> bool:
        """Remove ``ip`` from the agent's persistent deny list. Idempotent.

        Returns:
            ``True`` if the IP is no longer denied (whether it was just
            removed or was already absent). ``False`` on error.
        """
        ...

    async def is_blocked(self, ip: str) -> bool:
        """Report whether ``ip`` is currently in the deny list.

        Returns:
            ``True`` only if the IP is reliably observed in the agent's
            authoritative store. On any error the implementation MUST
            return ``False`` — the responder treats a ``False`` here as
            "not blocked, please try to block it" which is the safe
            default for a defensive system.
        """
        ...

    async def list_blocklist(self) -> list[str]:
        """List every IP currently denied by the agent.

        Returns:
            All IP / CIDR strings present in the agent's deny list, or
            an empty list on error. Order is not guaranteed and the
            caller MUST treat the result as a set.
        """
        ...

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        """Terminate a process by PID on the host the agent runs on.

        Used by the responder when a confirmed-threat alert maps to a
        local process that should be killed in addition to the IP block.
        The semantics depend on the agent's topology relative to the
        target host:

        * **Co-resident agents** (the agent runs ON the same machine as
          the process to kill, e.g. ``WindowsFirewallBlocker`` on a
          standalone PC) implement the kill via ``psutil`` or equivalent
          and return ``(True, process_name)`` on success or
          ``(False, error_message)`` on local failure (NoSuchProcess,
          AccessDenied).
        * **Off-host agents** (the agent reaches the enforcement point
          over the network, e.g. ``NetgateAgent`` via SSH to pfSense, or
          a future ``VsAgent`` running on the Virus Sniff RPi appliance
          while the malicious process lives on a separate PC client)
          MUST raise :class:`NotImplementedError`. The responder catches
          this and skips the kill action — the IP block remains applied.

        Returns:
            ``(True, process_name)`` on successful termination.
            ``(False, error_message)`` on local error (process exited
            between lookup and kill, missing OS permission, etc.).

        Raises:
            NotImplementedError: When the agent does not co-reside with
                the target host. This design choice makes accidental
                cross-host kills architecturally impossible — a future
                Virus Sniff pipeline cannot kill a process on the RPi
                by mistake while believing it is killing a process on
                the connected PC.
        """
        ...

    def stream_alerts(self) -> AsyncIterator[dict[str, Any]]:
        """Yield Suricata EVE JSON events as they arrive on the agent's host.

        Each yielded item is a parsed JSON object — the canonical EVE
        event shape (``event_type``, ``alert``, ``flow_id``, ``src_ip``,
        ``dest_ip``, …). Implementations parse the line themselves so
        the pipeline never sees raw bytes; broken / non-JSON lines are
        dropped silently rather than yielded.

        Implementations come in two flavours:

        * **Source agents** (``NetgateAgent`` over SSH+``tail -f``,
          a future ``VsAgent`` reading the local eve.json on the RPi)
          open the live stream, yield every parsed event, and return
          when the consumer breaks out of the loop or calls ``aclose()``
          on the iterator. They MUST handle transient transport errors
          internally (reconnect, backoff) and SHOULD NOT raise to the
          consumer; raising is reserved for unrecoverable misconfiguration.
        * **Sink-only agents** (``NoOpAgent``, ``WindowsFirewallBlocker``
          today) yield nothing — the iterator is empty and terminates
          immediately. They are not a source of alerts; the operator's
          local Suricata, when wired in, will be a separate streamer.

        Note this is an *async generator function*: the protocol declares
        ``def`` (not ``async def``) returning ``AsyncIterator``, while
        concrete implementations use ``async def`` with ``yield`` inside.
        ``mypy --strict`` accepts this asymmetry.

        Returns:
            An async iterator of parsed EVE JSON events. The pipeline
            consumes it as ``async for event in agent.stream_alerts():``.

        Note:
            The current pipeline still consumes a Qt-based ``SshStreamer``
            in the UI layer — the migration of that call site to consume
            this Protocol method is tracked separately (Phase 3b.5).
        """
        ...
