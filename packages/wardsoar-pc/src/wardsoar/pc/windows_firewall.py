"""``RemoteAgent`` implementation backed by Windows Firewall (netsh).

Used in standalone-PC mode (operator answered Netgate=No to the
SourcesQuestionnaire and Suricata=Yes for local detection): rather
than a no-op stub, the responder gets a real local enforcement path
via ``netsh advfirewall firewall add rule``.

Why netsh and not the Windows Firewall COM API:

  * netsh is bundled with every supported Windows version (no extra
    DLL, no pywin32 surface to test against);
  * the rules survive reboots without any additional persistence
    code (the Windows Firewall stores them itself);
  * the surface is small enough that a hand-rolled subprocess
    invocation is auditable line-by-line, which matters for a
    defensive tool.

Each blocked IP gets two rules — one inbound, one outbound — so the
agent matches the "block all traffic" semantics Netgate provides via
``pfctl -t blocklist``. Names follow ``WardSOAR_block_<ip>_<dir>``
so :meth:`list_blocklist` can scrape them out of
``netsh advfirewall firewall show rule name=all`` deterministically.

Fail-safe: every netsh invocation is wrapped in a try / catch on
:class:`subprocess.CalledProcessError`, :class:`OSError`, and the
generic ``Exception`` (the binary may be missing, the user may not
have admin rights). Errors are logged and the documented failure
return value (``False`` / empty list) is surfaced — the agent never
raises to the responder.

Permission requirements: ``netsh advfirewall firewall add rule``
requires admin rights. WardSOAR's MSI installs ``perMachine`` and
the app runs in the operator's user context — so add operations
will fail unless the operator launches WardSOAR elevated. The fail
mode is loud (every blocked IP triggers an ``ERROR`` log explaining
the missing privilege) but safe (no silent-success scenario).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess  # nosec B404 — netsh is the documented Windows surface
from typing import Optional

from wardsoar.pc import win_paths

logger = logging.getLogger("ward_soar.windows_firewall")


# Rule-name prefix WardSOAR uses to mark its own entries in the
# Windows Firewall rule store. Every rule we add starts with this so
# ``list_blocklist`` can scrape them back out without confusing them
# with rules the operator (or other software) created independently.
_RULE_PREFIX: str = "WardSOAR_block_"

# Per-direction suffix appended to ``_RULE_PREFIX + ip`` so each
# blocked IP gets one inbound rule and one outbound rule.
_DIR_SUFFIXES: tuple[str, str] = ("in", "out")

# Default timeout for netsh invocations. Empirically netsh on a
# healthy box returns under 200 ms; a 10-second cap gives plenty of
# headroom while still bounding the worst case (corrupt firewall
# service, etc.) so the responder hot path can never hang on a
# block.
_NETSH_TIMEOUT_S: float = 10.0


def _validate_ip(ip: str) -> bool:
    """Reject anything that isn't a parseable IP address.

    Defence-in-depth: the responder also validates upstream, but the
    blocker is the last layer between operator-supplied data and
    ``netsh.exe`` so we re-check here. An IP that fails parsing
    cannot be turned into a netsh argument that does anything
    interesting (Windows Firewall rejects the rule), but we refuse
    earlier so the error path is "log + return False" rather than
    "let netsh fail with a confusing message".
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class WindowsFirewallBlocker:
    """``RemoteAgent`` backed by ``netsh advfirewall firewall`` calls.

    Each blocked IP gets two rules (inbound + outbound). The agent
    is fail-safe: every netsh call is caught and translated into
    the documented :class:`RemoteAgent` return shape rather than
    raising to the responder.
    """

    def __init__(self, netsh_path: Optional[str] = None) -> None:
        """Build the blocker.

        Args:
            netsh_path: Override the path to netsh.exe — useful in
                tests that want to point at a fake binary. Defaults
                to the absolute path under ``%SystemRoot%\\System32``
                from :mod:`wardsoar.pc.win_paths`, which keeps the
                subprocess invocation safe against ``PATH`` shims.
        """
        self._netsh = netsh_path or win_paths.NETSH

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rule_names_for(self, ip: str) -> list[str]:
        """Return the per-direction rule names for ``ip``."""
        return [f"{_RULE_PREFIX}{ip}_{suffix}" for suffix in _DIR_SUFFIXES]

    async def _run_netsh(self, args: list[str]) -> tuple[bool, str]:
        """Invoke netsh in a worker thread and surface the outcome.

        Subprocess is synchronous on Windows; running it in
        :func:`asyncio.to_thread` keeps the event loop free for the
        rest of the pipeline.
        """

        def _invoke() -> tuple[bool, str]:
            try:
                completed = subprocess.run(  # nosec B603 — absolute path, hardcoded args, IP validated upstream
                    [self._netsh, *args],
                    capture_output=True,
                    text=True,
                    timeout=_NETSH_TIMEOUT_S,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except FileNotFoundError as exc:
                return False, f"netsh not found at {self._netsh}: {exc}"
            except subprocess.TimeoutExpired:
                return False, f"netsh timeout after {_NETSH_TIMEOUT_S}s"
            except OSError as exc:
                return False, f"OS error invoking netsh: {exc}"

            if completed.returncode == 0:
                return True, completed.stdout or ""
            # netsh writes its diagnostic to stdout, not stderr; combine
            # both so the caller sees whichever the binary actually used.
            message = (completed.stderr or "") + (completed.stdout or "")
            return False, message.strip() or f"netsh exit code {completed.returncode}"

        return await asyncio.to_thread(_invoke)

    # ------------------------------------------------------------------
    # RemoteAgent protocol surface
    # ------------------------------------------------------------------

    async def check_status(self) -> tuple[bool, str]:
        """Verify Windows Firewall is reachable via netsh.

        Runs ``netsh advfirewall show currentprofile`` — a read-only
        probe that confirms the firewall service is responsive
        without enumerating every rule.
        """
        ok, output = await self._run_netsh(["advfirewall", "show", "currentprofile"])
        if ok:
            return True, "Windows Firewall reachable"
        return False, f"Windows Firewall unreachable: {output}"

    async def add_to_blocklist(self, ip: str) -> bool:
        """Block ``ip`` inbound and outbound. Idempotent at the rule level.

        Adds two rules — one per direction. If a rule with the same
        name already exists netsh treats it as "duplicate" and
        returns success, so re-blocking the same IP is a no-op. Both
        rules must succeed for the overall operation to count as
        success — partial success would leave the IP blocked one
        direction only, which is worse than no block at all (false
        sense of safety).
        """
        if not _validate_ip(ip):
            logger.error("WindowsFirewallBlocker: invalid IP, refusing netsh call: %s", ip)
            return False

        all_ok = True
        for direction, rule_name in zip(_DIR_SUFFIXES, self._rule_names_for(ip)):
            ok, output = await self._run_netsh(
                [
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    f"dir={direction}",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ]
            )
            if not ok:
                logger.error(
                    "WindowsFirewallBlocker: failed to add %s rule for %s: %s",
                    direction,
                    ip,
                    output,
                )
                all_ok = False

        if all_ok:
            logger.info("WindowsFirewallBlocker: blocked %s (in + out)", ip)
        return all_ok

    async def remove_from_blocklist(self, ip: str) -> bool:
        """Remove both per-direction rules for ``ip``. Idempotent.

        Deleting a rule that does not exist returns a non-zero exit
        code from netsh; we treat that as success on the assumption
        that "the IP is no longer blocked" is the contract this
        method promises. The caller would otherwise see a spurious
        failure on every cleanup sweep.
        """
        if not _validate_ip(ip):
            logger.error("WindowsFirewallBlocker: invalid IP, refusing netsh call: %s", ip)
            return False

        for rule_name in self._rule_names_for(ip):
            ok, output = await self._run_netsh(
                ["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            )
            if not ok and "No rules match the specified criteria" not in output:
                logger.error(
                    "WindowsFirewallBlocker: failed to delete rule %s: %s",
                    rule_name,
                    output,
                )
                # Continue trying the other direction — better to
                # remove what we can than abort halfway.

        logger.info("WindowsFirewallBlocker: unblocked %s (in + out attempted)", ip)
        return True

    async def is_blocked(self, ip: str) -> bool:
        """Report whether ``ip`` has at least one of its rules in place.

        Treats "either direction is blocked" as blocked because the
        ``add_to_blocklist`` partial-failure path can leave one rule
        live; the responder needs to see ``True`` so its
        rate-limited "already blocked" path triggers instead of
        re-attempting the failing direction every alert.
        """
        if not _validate_ip(ip):
            return False

        for rule_name in self._rule_names_for(ip):
            ok, _ = await self._run_netsh(
                ["advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            )
            if ok:
                return True
        return False

    async def list_blocklist(self) -> list[str]:
        """List every IP currently blocked by a WardSOAR-prefixed rule.

        Walks every inbound rule with ``netsh ... show rule name=all
        dir=in``, picks out lines with our prefix, and returns the
        unique IP set. The outbound side mirrors the inbound side
        (we add both atomically), so scanning one direction is
        sufficient.
        """
        ok, output = await self._run_netsh(
            ["advfirewall", "firewall", "show", "rule", "name=all", "dir=in"]
        )
        if not ok:
            logger.error("WindowsFirewallBlocker: list_blocklist netsh failed: %s", output)
            return []

        ips: set[str] = set()
        for line in output.splitlines():
            stripped = line.strip()
            # netsh prints "Rule Name:                  WardSOAR_block_1.2.3.4_in"
            if _RULE_PREFIX not in stripped:
                continue
            try:
                tail = stripped.split(_RULE_PREFIX, 1)[1]
            except IndexError:  # pragma: no cover — split-with-maxsplit always returns >=1 element
                continue
            # Tail looks like ``1.2.3.4_in``; trim the trailing direction.
            for suffix in _DIR_SUFFIXES:
                marker = f"_{suffix}"
                if tail.endswith(marker):
                    candidate = tail[: -len(marker)]
                    if _validate_ip(candidate):
                        ips.add(candidate)
                    break
        return sorted(ips)
