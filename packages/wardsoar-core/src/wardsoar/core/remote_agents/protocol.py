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

from typing import Protocol, runtime_checkable


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
