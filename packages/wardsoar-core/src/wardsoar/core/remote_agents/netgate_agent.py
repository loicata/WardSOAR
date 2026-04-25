"""Concrete ``RemoteAgent`` implementation for the Netgate / pfSense appliance.

Wraps the existing :class:`PfSenseSSH` transport via composition (not
inheritance) and exposes two surfaces:

  * the generic :class:`RemoteAgent` protocol (``check_status``,
    ``add_to_blocklist``, ``remove_from_blocklist``, ``is_blocked``,
    ``list_blocklist``) used by ``responder``, ``rule_manager`` and
    ``healthcheck``;
  * Netgate-specific operations (``run_read_only`` for audit/tamper
    diagnostics, ``apply_suricata_runmode`` and ``migrate_alias_to_urltable``
    for the Apply layer) that have no analogue on the future
    Virus Sniff appliance.

Why composition over inheritance: the future ``VirusSniffAgent`` cannot
sensibly inherit from ``PfSenseSSH`` (different OS, different transport
specifics).

The :class:`PfSenseSSH` transport stays public and importable for the
agent's own internal use, but every call site outside ``remote_agents/``
now consumes the agent (``NetgateAgent`` for Netgate-specific layers,
``RemoteAgent`` protocol for pipeline core). The short-lived ``ssh``
escape hatch from Phase 3b.2 was removed in Phase 3b.3.2.
"""

from __future__ import annotations

from wardsoar.core.remote_agents.pfsense_alias_migrate import (
    AliasMigrationResult,
    migrate_alias_to_urltable,
)
from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH
from wardsoar.core.remote_agents.pfsense_suricata_tune import (
    SuricataTuneResult,
    apply_suricata_runmode,
)


class NetgateAgent:
    """``RemoteAgent`` implementation backed by an SSH transport to pfSense.

    Args:
        ssh: An already-constructed :class:`PfSenseSSH`. Inject it
            directly when the test or caller wants to control the
            transport's lifecycle; otherwise prefer the
            :meth:`from_credentials` factory.
    """

    def __init__(self, ssh: PfSenseSSH) -> None:
        self._ssh = ssh

    @classmethod
    def from_credentials(
        cls,
        host: str,
        ssh_user: str,
        ssh_key_path: str,
        ssh_port: int = 22,
        blocklist_table: str = "blocklist",
    ) -> NetgateAgent:
        """Build the SSH transport and return a ready-to-use agent.

        This is the path most call sites should take; the explicit
        ``__init__`` form exists for tests that need to inject a mock
        transport.
        """
        return cls(
            PfSenseSSH(
                host=host,
                ssh_user=ssh_user,
                ssh_key_path=ssh_key_path,
                ssh_port=ssh_port,
                blocklist_table=blocklist_table,
            )
        )

    # ------------------------------------------------------------------
    # RemoteAgent protocol surface (delegates to PfSenseSSH)
    # ------------------------------------------------------------------

    async def check_status(self) -> tuple[bool, str]:
        return await self._ssh.check_status()

    async def add_to_blocklist(self, ip: str) -> bool:
        return await self._ssh.add_to_blocklist(ip)

    async def remove_from_blocklist(self, ip: str) -> bool:
        return await self._ssh.remove_from_blocklist(ip)

    async def is_blocked(self, ip: str) -> bool:
        return await self._ssh.is_blocked(ip)

    async def list_blocklist(self) -> list[str]:
        return await self._ssh.list_blocklist()

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        """Off-host agent — refuse the operation explicitly.

        ``NetgateAgent`` reaches pfSense via SSH from another host (the
        operator's PC running WardSOAR). It has no authority to kill a
        process on the WardSOAR host and zero relevance to processes on
        the pfSense appliance itself, which is a router, not a workstation.

        Raises:
            NotImplementedError: Always. The responder catches this and
                skips the kill action; the IP block remains applied.
        """
        raise NotImplementedError(
            "NetgateAgent does not co-reside with the target host — kill skipped"
        )

    # ------------------------------------------------------------------
    # Netgate-specific operations (no analogue on Virus Sniff)
    # ------------------------------------------------------------------

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        """Run a hard-coded read-only diagnostic command.

        Reserved for the audit and tamper layers. The ``cmd`` argument
        MUST be a literal — see :meth:`PfSenseSSH.run_read_only` for
        the rationale.
        """
        return await self._ssh.run_read_only(cmd, timeout=timeout)

    async def apply_suricata_runmode(self, target: str = "workers") -> SuricataTuneResult:
        """Flip the Suricata per-instance ``<runmode>`` (workers/autofp/single).

        Delegates to the existing free-function helper that performs
        the XML surgery and YAML regeneration via pfSense's canonical
        PHP path.
        """
        return await apply_suricata_runmode(self._ssh, target)

    async def migrate_alias_to_urltable(
        self, alias_name: str = "blocklist"
    ) -> AliasMigrationResult:
        """Migrate a host-type alias to ``urltable`` (one-shot, atomic).

        Delegates to the existing free-function helper. After the
        migration the alias survives every pfSense reload — the whole
        point of moving away from runtime ``config.xml`` mutations.
        """
        return await migrate_alias_to_urltable(self._ssh, alias_name)
