"""SSH-based pfSense integration via pfctl commands.

Replaces the former REST API approach (removed in pfSense 25.x).
All blocking operations use the pf table mechanism via SSH+pfctl.

SAFETY CONSTRAINTS:
- IP addresses validated with ipaddress module before any pfctl call
- All SSH commands have explicit timeouts (10s default)
- Fail-safe: SSH errors are caught and logged, never crash the pipeline
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncssh

logger = logging.getLogger("ward_soar.pfsense_ssh")


# Transient SSH failures to pfSense (connection reset, DNS glitch,
# appliance mid-reload) were observed repeatedly on 176.126.240.84
# during the 2026-04 window — four failures on that single IP:
#     SSH command failed: Connection lost
#     SSH command failed: [WinError 10053] connection aborted
#     SSH command failed: Connection lost
#     SSH command timed out [10s]
# Each cost one lost block. A bounded retry with backoff rides these
# out without masking real pfSense outages: if three consecutive
# attempts fail, the caller still gets ``(False, …)`` and the
# responder falls back to its normal "pfctl add failed" handling.
_MAX_SSH_RETRIES: int = 2  # 3 attempts total (initial + 2 retries)
_SSH_RETRY_BASE_DELAY_S: float = 1.0  # 1s, 2s backoff


class PfSenseSSH:
    """Execute pfctl commands on pfSense via SSH.

    All methods are fail-safe: SSH errors are caught, logged,
    and returned as failure values. Never raises to callers.

    Args:
        host: pfSense IP address.
        ssh_user: SSH username (typically 'admin').
        ssh_key_path: Path to SSH private key file.
        ssh_port: SSH port (default 22).
        blocklist_table: pf table name for blocked IPs.
    """

    def __init__(
        self,
        host: str,
        ssh_user: str,
        ssh_key_path: str,
        ssh_port: int = 22,
        blocklist_table: str = "blocklist",
    ) -> None:
        self._host = host
        self._user = ssh_user
        self._key_path = ssh_key_path
        self._port = ssh_port
        self._table = blocklist_table
        # Serialises add/remove on the shared alias file. Two concurrent
        # writers racing on /var/db/aliastables/wardsoar_blocklist.txt.tmp
        # caused the 2026-04-23 22:40 incident where the second mv landed
        # on a .tmp that had already been renamed by the first writer,
        # failing with "No such file or directory" and leaving the target
        # IP unblocked. Serialising here also prevents the lost-update
        # race of read_entries/modify/write (T1 and T2 both read [],
        # T1's entry gets overwritten by T2).
        self._write_lock: asyncio.Lock = asyncio.Lock()

    @property
    def write_lock(self) -> asyncio.Lock:
        """Lock held while the blocklist file is being mutated."""
        return self._write_lock

    async def _run_cmd(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        """Run a command on pfSense via SSH, retrying transient failures.

        A bounded retry handles the flaky cases observed in production
        (``Connection lost``, ``[WinError 10053] connection aborted``,
        ``SSH timeout``). A *deterministic* failure — bad credentials,
        unknown host key — will also retry but we accept the small
        extra cost: distinguishing at the asyncssh level would add a
        fragile exception-class whitelist for marginal benefit.

        The operation stays fail-safe: if every retry also fails, we
        return ``(False, last_error)`` just like before.

        Args:
            cmd: Shell command to execute.
            timeout: Maximum seconds to wait per attempt.

        Returns:
            Tuple of (success, stdout_or_error_message).
        """
        last_error: str = "no attempt made"
        for attempt in range(_MAX_SSH_RETRIES + 1):
            try:
                async with asyncssh.connect(  # nosec B507 — local network appliance
                    host=self._host,
                    port=self._port,
                    username=self._user,
                    client_keys=[self._key_path],
                    known_hosts=None,
                ) as conn:
                    result = await asyncio.wait_for(
                        conn.run(cmd, check=False),
                        timeout=timeout,
                    )
                    if result.exit_status == 0:
                        return (True, str(result.stdout or ""))
                    # Non-zero exit is an authoritative "the command
                    # ran, pfctl disagreed" — do NOT retry, the caller
                    # will surface the stderr as a real error.
                    return (
                        False,
                        str(result.stderr or f"exit code {result.exit_status}"),
                    )
            except asyncio.TimeoutError:
                last_error = f"SSH timeout after {timeout}s"
            except Exception as exc:  # noqa: BLE001 — covers OSError + asyncssh.*
                # ``str(exc)`` is empty for some asyncssh exceptions
                # (e.g. bare ``ConnectionLost()``). Fall back to the
                # class name so the log always has something readable.
                last_error = str(exc) or type(exc).__name__

            if attempt >= _MAX_SSH_RETRIES:
                logger.error(
                    "SSH command failed after %d attempts [%s]: %s",
                    attempt + 1,
                    cmd,
                    last_error,
                )
                return (False, last_error)

            delay = _SSH_RETRY_BASE_DELAY_S * (2**attempt)
            logger.warning(
                "SSH attempt %d/%d failed (%s) — retrying in %.1fs",
                attempt + 1,
                _MAX_SSH_RETRIES + 1,
                last_error,
                delay,
            )
            await asyncio.sleep(delay)

        # Loop always returns from inside; this satisfies mypy on a
        # theoretical code path we never execute.
        return (False, last_error)

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP address to prevent command injection."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def add_to_blocklist(self, ip: str) -> bool:
        """Add an IP to the persistent blocklist. Idempotent.

        Writes the IP into
        ``/var/db/aliastables/wardsoar_blocklist.txt`` and reloads the
        pf table from that file. Once the ``blocklist`` alias has been
        migrated to ``urltable`` (see
        :class:`src.netgate_apply.NetgateApplier` handler
        ``pf.migrate_alias_to_urltable``), the entry survives every
        pfSense reload. Before migration, the file write still works
        and pfctl still reloads the table, but pfSense's own reload
        cycle will wipe it back to empty — which is exactly the bug
        the migration fixes and why the audit flags un-migrated aliases.

        Args:
            ip: IP address to block.

        Returns:
            True if the IP is now recorded in the blocklist (either
            already present or just added) AND the pf table is in sync.
        """
        if not self._validate_ip(ip):
            logger.error("Invalid IP address, refusing pfctl command: %s", ip)
            return False

        from wardsoar.core.remote_agents.pfsense_aliastable import PersistentBlocklist

        async with self._write_lock:
            result = await PersistentBlocklist(self, table_name=self._table).add(ip)
        if result.success:
            logger.info(
                "Added %s to pfSense blocklist (size %d → %d, file-backed)",
                ip,
                result.size_before,
                result.size_after,
            )
        else:
            logger.error("Failed to add %s to blocklist: %s", ip, result.error)
        return result.success

    async def remove_from_blocklist(self, ip: str) -> bool:
        """Remove an IP from the persistent blocklist. Idempotent.

        Like :meth:`add_to_blocklist`, this updates the alias file
        before reloading the pf table so the change survives every
        pfSense reload once the alias type is ``urltable``.

        Args:
            ip: IP address to unblock.

        Returns:
            True if the IP is no longer in the blocklist.
        """
        if not self._validate_ip(ip):
            logger.error("Invalid IP address, refusing pfctl command: %s", ip)
            return False

        from wardsoar.core.remote_agents.pfsense_aliastable import PersistentBlocklist

        async with self._write_lock:
            result = await PersistentBlocklist(self, table_name=self._table).remove(ip)
        if result.success:
            logger.info(
                "Removed %s from pfSense blocklist (size %d → %d, file-backed)",
                ip,
                result.size_before,
                result.size_after,
            )
        else:
            logger.error("Failed to remove %s from blocklist: %s", ip, result.error)
        return result.success

    async def is_blocked(self, ip: str) -> bool:
        """Check if an IP is in the blocklist (file + live pf table).

        Reads the alias file — the file is authoritative now that
        blocks are persistent. A ``pfctl -T test`` would only consult
        the live table and could disagree with the file during a
        pfSense reload window.

        Args:
            ip: IP address to check.

        Returns:
            True if the IP is currently listed in the blocklist file.
        """
        if not self._validate_ip(ip):
            return False

        from wardsoar.core.remote_agents.pfsense_aliastable import PersistentBlocklist

        entries = await PersistentBlocklist(self, table_name=self._table).read_entries()
        return ip in entries

    async def list_blocklist(self) -> list[str]:
        """List all IPs currently in the blocklist.

        Reads the alias file for the authoritative view. The live pf
        table is a mirror of this file (post-migration) or a
        best-effort in-memory snapshot (pre-migration); in both cases
        the file is what survives across reloads.

        Returns:
            List of IP / CIDR strings.
        """
        from wardsoar.core.remote_agents.pfsense_aliastable import PersistentBlocklist

        return await PersistentBlocklist(self, table_name=self._table).read_entries()

    async def check_status(self) -> tuple[bool, str]:
        """Check pfSense is reachable via SSH.

        Returns:
            Tuple of (reachable, message).
        """
        success, output = await self._run_cmd("pfctl -s info", timeout=5)
        if success:
            return (True, "pfSense SSH reachable")
        return (False, f"pfSense SSH unreachable: {output}")

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        """Run a read-only diagnostic command on pfSense.

        Thin public wrapper around :meth:`_run_cmd` reserved for the
        Netgate audit layer. The caller is responsible for passing a
        hard-coded, side-effect-free command — *no interpolation of
        user input is permitted here* because the wrapper performs no
        escaping and the SSH session runs as the admin user. Any
        operator-provided string must be rejected upstream.

        Args:
            cmd: The exact shell command to execute. Must not contain
                any value that originated from an untrusted source.
            timeout: Seconds to wait before reporting a timeout.

        Returns:
            Tuple of (success, stdout_or_error_message).
        """
        return await self._run_cmd(cmd, timeout=timeout)

    async def kill_process_on_target(self, pid: int) -> tuple[bool, str]:
        """Off-host transport — refuse the operation explicitly.

        ``PfSenseSSH`` is the SSH transport layer; pfSense itself is
        a router, not a workstation, and the SSH session has no
        authority over the WardSOAR host process table. Implemented
        here only so :class:`MagicMock(spec=PfSenseSSH)` test fixtures
        keep satisfying the :class:`RemoteAgent` Protocol after the
        method was added there.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "PfSenseSSH does not co-reside with the target host — kill skipped"
        )


class BlockTracker:
    """Track block timestamps locally since pf tables don't store metadata.

    Persists to a JSON file so state survives restarts.

    Args:
        persist_path: Path to the JSON persistence file.
    """

    def __init__(self, persist_path: Path) -> None:
        self._path = persist_path
        self._blocks: dict[str, str] = {}  # ip -> ISO timestamp
        self._load()

    def _load(self) -> None:
        """Load persisted block data from disk."""
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._blocks = data
                    logger.debug("Loaded %d block records from %s", len(data), self._path)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load block tracker: %s", exc)

    def _save(self) -> None:
        """Persist block data to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._blocks, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Failed to save block tracker: %s", exc)

    def record_block(self, ip: str) -> None:
        """Record that an IP was blocked now."""
        self._blocks[ip] = datetime.now(timezone.utc).isoformat()
        self._save()

    def remove_block(self, ip: str) -> None:
        """Remove an IP from tracking."""
        if ip in self._blocks:
            del self._blocks[ip]
            self._save()

    def get_block_time(self, ip: str) -> datetime | None:
        """Get when an IP was blocked.

        Returns:
            Datetime of block, or None if not tracked.
        """
        ts = self._blocks.get(ip)
        if ts:
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                return None
        return None

    def get_expired_ips(self, max_hours: int) -> list[str]:
        """Get IPs that have been blocked longer than max_hours.

        Args:
            max_hours: Maximum block duration in hours.

        Returns:
            List of expired IP addresses.
        """
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        for ip, ts_str in self._blocks.items():
            try:
                blocked_at = datetime.fromisoformat(ts_str)
                elapsed_hours = (now - blocked_at).total_seconds() / 3600
                if elapsed_hours > max_hours:
                    expired.append(ip)
            except ValueError:
                expired.append(ip)
        return expired

    def get_all_blocks(self) -> dict[str, Any]:
        """Get all tracked blocks with timestamps.

        Returns:
            Dict mapping IP to ISO timestamp string.
        """
        return dict(self._blocks)

    def clear_all(self) -> int:
        """Drop every tracked block and delete the backing file.

        Intended for the post-Netgate-reset cleanup: after a factory
        reset the pf ``blocklist`` table is empty, so the tracker's
        view of the box is definitely stale. Keeping the old records
        would confuse :meth:`reconcile` and mislead the operator.

        Returns:
            Number of tracked entries that were present before the purge.
        """
        count = len(self._blocks)
        self._blocks = {}
        try:
            self._path.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover — filesystem oddities
            logger.warning("block_tracker: failed to delete %s: %s", self._path, exc)
        if count:
            logger.info("block_tracker: purged %d entries (file deleted)", count)
        return count

    def reconcile(self, active_ips: list[str]) -> None:
        """Sync tracker with actual pf table contents.

        - IPs in tracker but not in table: remove from tracker
        - IPs in table but not in tracker: add with current time

        Args:
            active_ips: IPs currently in the pf blocklist table.
        """
        active_set = set(active_ips)
        tracked_set = set(self._blocks.keys())

        stale = tracked_set - active_set
        for ip in stale:
            logger.info("Reconcile: removing stale tracker entry for %s", ip)
            del self._blocks[ip]

        untracked = active_set - tracked_set
        now = datetime.now(timezone.utc).isoformat()
        for ip in untracked:
            logger.info("Reconcile: adding untracked IP %s with current time", ip)
            self._blocks[ip] = now

        if stale or untracked:
            self._save()
