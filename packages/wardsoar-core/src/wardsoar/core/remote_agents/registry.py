"""In-process registry of named ``RemoteAgent`` instances.

WardSOAR currently runs with at most one active agent at a time
(Netgate OR Virus Sniff — they cannot coexist at runtime, see the
2026-04-24 architecture decision on USB Gadget mode), but the wizard
already lets the operator declare both as *configured*. The registry
is the single place that knows which agents are configured and which
one — if any — is currently active.

The registry stays deliberately minimal: a small dict wrapper plus an
``isinstance(..., RemoteAgent)`` guard at registration. Multi-agent
dispatching (fan-out reads, fail-over) will land later, once the
Virus Sniff appliance actually exists; until then a richer interface
would just be speculative scaffolding.
"""

from __future__ import annotations

from wardsoar.core.remote_agents.protocol import RemoteAgent


class RemoteAgentRegistry:
    """Bookkeep ``RemoteAgent`` instances by short name.

    Names are operator-facing identifiers (``"netgate"``, ``"virus_sniff"``)
    so they appear in logs and config files; pick something stable.
    """

    def __init__(self) -> None:
        self._agents: dict[str, RemoteAgent] = {}

    def register(self, name: str, agent: RemoteAgent) -> None:
        """Register ``agent`` under ``name``.

        Re-registering an existing name replaces the previous entry; the
        operator-driven reconfiguration flow (Settings → Sources panel)
        relies on this to swap an agent's connection parameters without
        restarting the process.

        Raises:
            TypeError: If ``agent`` does not satisfy the ``RemoteAgent``
                protocol surface. This catches typos and forgotten
                methods at wire-up time rather than at the first
                production call.
            ValueError: If ``name`` is empty or whitespace-only.
        """
        if not name or not name.strip():
            raise ValueError("agent name must be a non-empty string")
        if not isinstance(agent, RemoteAgent):
            raise TypeError(
                f"agent for '{name}' does not implement RemoteAgent: {type(agent).__name__}"
            )
        self._agents[name] = agent

    def unregister(self, name: str) -> bool:
        """Drop the agent registered under ``name``.

        Returns:
            ``True`` if an entry existed and was removed, ``False`` if
            no entry was registered under that name.
        """
        return self._agents.pop(name, None) is not None

    def get(self, name: str) -> RemoteAgent | None:
        """Return the agent registered under ``name``, or ``None``."""
        return self._agents.get(name)

    def all_agents(self) -> dict[str, RemoteAgent]:
        """Return a copy of the registered agents map.

        The returned dict is a snapshot; mutating it does not affect the
        registry's internal state.
        """
        return dict(self._agents)

    def names(self) -> list[str]:
        """Return the list of registered agent names."""
        return list(self._agents.keys())

    def __len__(self) -> int:
        return len(self._agents)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._agents
