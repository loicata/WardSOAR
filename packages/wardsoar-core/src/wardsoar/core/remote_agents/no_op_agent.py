"""``RemoteAgent`` stub used when no remote enforcement agent is configured.

When the operator answered "No" to the Netgate question in the
:class:`SourcesQuestionnaire` (and Virus Sniff is not yet implemented),
the pipeline still needs *something* to plug into the responder /
rule_manager / healthcheck slots that expect a :class:`RemoteAgent`.
Rather than spreading ``Optional[RemoteAgent]`` plumbing through every
consumer (with the corresponding ``if agent is None`` branches in the
hot path) and risking a missed ``None`` check, we ship a stub that
satisfies the protocol structurally and reports honest "no remote
enforcement available" outcomes.

Behaviour summary:

  * ``check_status`` returns ``(False, "...")`` so the healthcheck
    surfaces a user-visible "no remote agent configured" status rather
    than a green tick that lies about reachability.
  * ``add_to_blocklist`` logs a WARNING (so the operator sees the
    block was attempted but skipped) and returns ``False``. The
    responder treats this as a failed block and logs it with the same
    diagnostic surface as a real SSH failure — operator ends up with
    one accurate trail of "I tried to block X but had nowhere to send
    the rule to" instead of a silent success that pretends a block
    happened.
  * ``remove_from_blocklist`` returns ``True`` — there is nothing to
    remove from a list that does not exist. Reporting success here
    keeps the cleanup loop quiet (rule_manager would log warnings on
    every periodic sweep otherwise).
  * ``is_blocked`` and ``list_blocklist`` return the empty answer
    (``False`` and ``[]``) so any caller that reasons about which
    IPs are denied gets the truthful answer.

A future Phase will replace this stub with a Windows Firewall blocker
once the local-blocking work lands; the responder will then have a
real local enforcement path even when no remote agent is plugged in.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("ward_soar.remote_agents.no_op")


class NoOpAgent:
    """``RemoteAgent`` protocol surface that performs no remote action.

    Used when the wizard's ``sources`` answers exclude every concrete
    agent. The pipeline keeps running and will still emit verdicts;
    only the remote enforcement step is skipped.
    """

    async def check_status(self) -> tuple[bool, str]:
        return (
            False,
            "no remote agent configured (sources.netgate=False)",
        )

    async def add_to_blocklist(self, ip: str) -> bool:
        logger.warning(
            "no_op_agent: refusing to block %s — no remote agent is configured "
            "(SourcesQuestionnaire answers exclude Netgate / Virus Sniff). "
            "Local Windows Firewall blocking is not yet implemented.",
            ip,
        )
        return False

    async def remove_from_blocklist(self, ip: str) -> bool:
        # Nothing to remove from a list that never existed; report
        # success so the periodic cleanup loop does not flood logs
        # with warnings on every sweep.
        return True

    async def is_blocked(self, ip: str) -> bool:
        return False

    async def list_blocklist(self) -> list[str]:
        return []

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        """Degenerate no-op agent — refuse the operation.

        Without any configured source there is no meaningful host on
        which to perform the kill. Behaves like an off-host agent and
        lets the responder skip the action gracefully.

        Raises:
            NotImplementedError: Always. The responder catches this
                and the IP block (also a no-op here) is the only
                visible action.
        """
        raise NotImplementedError("NoOpAgent has no target host — kill skipped")
