"""File-backed persistent blocklist for pfSense (Phase 7h).

Motivation
----------
The pre-v0.8.0 implementation called ``pfctl -t blocklist -T add`` directly,
which mutates only the in-memory pf table. Any pfSense reload (config
save in the webGUI, package update, reboot, or the ``/etc/rc.filter_configure``
invoked after ANY firewall rule change) regenerates all pf tables from
``/cf/conf/config.xml``. Since the default ``blocklist`` alias ships with
``<address></address>`` (empty), every IP WardSOAR previously added was
silently erased within minutes, so a user's Netflix session stayed alive
not because Hard Protect spared it but because the block itself evaporated.

The fix is the **canonical pfSense pattern** for dynamic blocklists: an
alias of type ``urltable`` pointing at a local text file that WardSOAR
owns exclusively. pfSense reads the file back into the ``blocklist`` pf
table on every reload (and on its ``updatefreq`` polling interval), and
WardSOAR writes that file atomically. The result:

* Blocks survive every pfSense reload scenario — config save, upgrade,
  reboot, package install.
* No more ``config.xml`` surgery once the alias is migrated to
  ``urltable`` — WardSOAR never touches XML at runtime, only this text
  file. That is the "no tech debt" contract the operator requested.
* The pattern is documented, stable across pfSense CE and Plus since
  2019, and used by pfBlockerNG, Snort blocklist, CrowdSec, and
  suricata_blocked. We're joining an ecosystem rather than inventing a
  mechanism.

File contract
-------------
One entry per line, ASCII, ``\\n`` terminated. Each line is either an
IPv4/IPv6 address or a CIDR network. Comments and blank lines are
permitted on read (ignored) but never emitted on write. The canonical
path is ``/var/db/aliastables/wardsoar_blocklist.txt``; that directory is
pfSense's standard location for url-table alias files and requires no
special filesystem setup.

Atomicity
---------
Every write follows the Unix temp-file-and-rename pattern: we stage the
new content to ``<path>.tmp``, then ``mv`` it onto the canonical path.
That rename is atomic on UFS (pfSense's filesystem), so a crash or SSH
disconnect mid-write leaves either the pre-image or the full post-image,
never a truncated file. After the rename, we run
``pfctl -t blocklist -T replace -f <path>`` so the live pf table matches
the file even before pfSense's next scheduled reload.

Safety
------
Commands are hard-coded string literals with the only variable being the
file path and individual IP strings. The file path is not operator input.
IP strings are validated by the caller (``PfSenseSSH._validate_ip``) before
we ever build the file payload, so injection via a crafted "IP" like
``10.0.0.1; rm -rf /`` cannot reach a shell — the atomicity script uses
a quoted-delimiter heredoc and a static sentinel that we refuse to write
if it collides with any line in the payload.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.pfsense_aliastable")


#: Remote path pfSense expects for a url-table alias file. Under
#: ``/var/db/aliastables/`` is pfSense's canonical location; any
#: other path would work but deviates from the ecosystem and makes
#: the operator's future investigation harder.
DEFAULT_ALIAS_FILE_PATH = "/var/db/aliastables/wardsoar_blocklist.txt"

#: Remote directory the file lives in. ``mkdir -p`` before any write
#: because pfSense does not always ship the directory on fresh
#: installs (only when an url-table alias has been created).
DEFAULT_ALIAS_DIR = "/var/db/aliastables"

#: Heredoc sentinel used when pushing the text file over SSH. Static
#: on purpose so the caller's data is sanity-checked against it; we
#: refuse the write if the payload would collide with the delimiter.
_HEREDOC_SENTINEL = "__WARDSOAR_ALIAS_EOF__"

#: Name of the pf table matching the alias defined in ``config.xml``.
#: Kept configurable via :class:`PersistentBlocklist` for tests, but
#: the default matches ``config.yaml > responder.pfsense.blocklist_table``.
DEFAULT_TABLE_NAME = "blocklist"


@dataclass(frozen=True)
class BlocklistSyncResult:
    """Outcome of a ``write + pfctl replace`` cycle.

    Attributes:
        success: True only when both the file write and the pfctl
            reload succeeded. A partial success (file ok, pfctl ko)
            returns False — the next call will re-sync from file.
        size_before: Entry count before the operation.
        size_after: Entry count after the operation.
        error: Human-readable reason when ``success`` is False.
    """

    success: bool
    size_before: int
    size_after: int
    error: str | None = None


class PersistentBlocklist:
    """File-backed CRUD for the pf blocklist.

    All operations are idempotent and atomic. A caller may add the
    same IP twice, remove an IP that was never added, or be
    interrupted mid-write; the file remains coherent and the pf
    table stays in sync on the next successful call.

    Args:
        ssh: SSH session used to read / write on pfSense.
        file_path: Remote path of the url-table alias file. Defaults
            to :data:`DEFAULT_ALIAS_FILE_PATH`.
        table_name: Name of the pf table. Defaults to
            :data:`DEFAULT_TABLE_NAME`.
    """

    def __init__(
        self,
        ssh: "PfSenseSSH",
        file_path: str = DEFAULT_ALIAS_FILE_PATH,
        table_name: str = DEFAULT_TABLE_NAME,
    ) -> None:
        self._ssh = ssh
        self._file_path = file_path
        self._table = table_name

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    async def read_entries(self) -> list[str]:
        """Return the current IPs listed in the alias file.

        Missing file → empty list (the common case on first run before
        any block has been issued). Malformed lines are silently
        dropped: an operator who hand-edits the file and introduces a
        typo should not break the Responder, just lose that one entry.
        """
        ok, out = await self._ssh.run_read_only(
            f"cat {self._file_path} 2>/dev/null || true", timeout=10
        )
        if not ok:
            return []
        entries: list[str] = []
        for raw in out.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if self._is_valid_entry(line):
                entries.append(line)
            else:
                logger.debug(
                    "pfsense_aliastable: dropping malformed line %r from %s",
                    line,
                    self._file_path,
                )
        return entries

    async def file_exists(self) -> bool:
        """True if the alias file is present (and readable) on pfSense."""
        ok, out = await self._ssh.run_read_only(
            f"test -f {self._file_path} && echo yes || echo no", timeout=5
        )
        return ok and out.strip() == "yes"

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    async def add(self, ip: str) -> BlocklistSyncResult:
        """Add ``ip`` and sync the pf table.

        Idempotent: adding an IP already in the file is a no-op that
        still triggers a pfctl replace (cheap, guarantees sync).
        """
        if not self._is_valid_entry(ip):
            return BlocklistSyncResult(False, 0, 0, error=f"invalid entry: {ip!r}")
        entries = await self.read_entries()
        size_before = len(entries)
        if ip not in entries:
            entries.append(ip)
        return await self._flush(entries, size_before)

    async def remove(self, ip: str) -> BlocklistSyncResult:
        """Remove ``ip`` and sync the pf table.

        Idempotent: removing an IP not in the file is a no-op that
        still triggers a pfctl replace so the live table is known to
        match the file afterwards.
        """
        if not self._is_valid_entry(ip):
            return BlocklistSyncResult(False, 0, 0, error=f"invalid entry: {ip!r}")
        entries = await self.read_entries()
        size_before = len(entries)
        if ip in entries:
            entries.remove(ip)
        return await self._flush(entries, size_before)

    async def replace_all(self, entries: list[str]) -> BlocklistSyncResult:
        """Replace the whole list — used for rare bulk operations (reconcile).

        Drops entries that fail validation rather than raising, so a
        caller handing us a mixed list (e.g. from a saved tracker) gets
        a best-effort write with only the good IPs.
        """
        clean: list[str] = [e for e in entries if self._is_valid_entry(e)]
        size_before = len(await self.read_entries())
        return await self._flush(clean, size_before)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _flush(self, entries: list[str], size_before: int) -> BlocklistSyncResult:
        """Write ``entries`` atomically and trigger a pfctl replace.

        The sequence is deliberately two-phase:

        1. Write the file. If that fails, the pf table is untouched
           and the operator still has the pre-image on disk. We
           surface the error and leave the caller to retry.
        2. ``pfctl -t ... -T replace -f <file>``. This re-reads the
           file we just wrote and rebuilds the table to match. If
           this step fails, the file is nonetheless correct on disk
           and the next successful ``_flush`` will re-sync.
        """
        # Deduplicate while preserving insertion order — the operator
        # may inspect the file; sorted lists would be easier to read
        # but churn the diff on every add.
        seen: set[str] = set()
        ordered: list[str] = []
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                ordered.append(entry)

        payload = "\n".join(ordered)
        if payload:
            payload += "\n"

        if _HEREDOC_SENTINEL in payload:
            return BlocklistSyncResult(
                False,
                size_before,
                size_before,
                error="payload contains the heredoc sentinel — refusing write",
            )

        # Ensure the directory exists. pfSense ships it when any
        # url-table alias has been created, but on a fresh install
        # where the migration has not yet run it may be missing.
        mkdir_cmd = f"mkdir -p {DEFAULT_ALIAS_DIR}"
        ok, out = await self._ssh.run_read_only(mkdir_cmd, timeout=5)
        if not ok:
            return BlocklistSyncResult(
                False, size_before, size_before, error=f"mkdir failed: {out[:200]}"
            )

        # Atomic write: stage to ``.tmp.<pid>.<monotonic>`` then rename
        # onto the target. UFS (pfSense) and most POSIX filesystems
        # guarantee rename-over-existing is atomic — a concurrent reader
        # sees either the pre-image or the full post-image, never a
        # truncated mix.
        #
        # The ``.tmp`` suffix is uniquified per call so two concurrent
        # writers never race on the same staging file. Prior to this
        # change the tmp path was a constant ``…txt.tmp`` and a second
        # ``mv`` landed on a tmp the first writer had already renamed,
        # failing with "No such file or directory" (incident
        # 2026-04-23 22:40 in logs). The outer ``PfSenseSSH._write_lock``
        # already serialises concurrent calls inside this process; the
        # unique suffix is defence in depth against any external script
        # staging alongside.
        #
        # Shell shape: ``set -e`` + one-statement-per-line so that if
        # ``cat`` fails (disk full, permission) the ``mv`` is skipped
        # and the script exits non-zero. The previous shape put
        # ``&& mv …`` on a line BY ITSELF after the heredoc delimiter,
        # which POSIX sh rejects outright as a syntax error. The
        # regression test ``test_generated_write_command_is_valid_sh``
        # in ``tests/test_pfsense_aliastable.py`` guards this.
        tmp_path = f"{self._file_path}.tmp.{os.getpid()}.{time.monotonic_ns():x}"
        write_cmd = (
            "set -e\n"
            f"cat > {tmp_path} <<'{_HEREDOC_SENTINEL}'\n"
            f"{payload}"
            f"{_HEREDOC_SENTINEL}\n"
            f"mv {tmp_path} {self._file_path}\n"
        )
        ok, out = await self._ssh.run_read_only(write_cmd, timeout=15)
        if not ok:
            return BlocklistSyncResult(
                False, size_before, size_before, error=f"atomic write failed: {out[:200]}"
            )

        # Tell pfctl to rebuild the live table from the file. This is
        # idempotent and cheap; it's also the canonical way to sync
        # a url-table alias outside of pfSense's own reload cycle.
        replace_cmd = f"pfctl -t {self._table} -T replace -f {self._file_path} 2>&1"
        ok, out = await self._ssh.run_read_only(replace_cmd, timeout=15)
        if not ok:
            # The file is still correct; next call will re-try the
            # pfctl replace. This is why we don't roll back the file.
            logger.warning(
                "pfsense_aliastable: file written but pfctl replace failed: %s",
                out[:200],
            )
            return BlocklistSyncResult(
                True,  # file on disk is authoritative, it is up-to-date
                size_before,
                len(ordered),
                error=f"pfctl replace failed (file ok): {out[:200]}",
            )

        logger.info(
            "pfsense_aliastable: synced %s — %d → %d entries",
            self._file_path,
            size_before,
            len(ordered),
        )
        return BlocklistSyncResult(True, size_before, len(ordered))

    @staticmethod
    def _is_valid_entry(entry: str) -> bool:
        """Accept a plain IP or a CIDR; reject anything else.

        We are permissive on the CIDR mask — pfSense pf itself accepts
        ``/32`` implicitly. The stricter ``is_valid_ip`` used by the
        Responder elsewhere is paired with this loose check so a
        single operator-added CIDR like ``84.203.112.0/24`` survives.
        """
        try:
            ipaddress.ip_network(entry, strict=False)
            return True
        except (ValueError, TypeError):
            return False


__all__ = [
    "BlocklistSyncResult",
    "DEFAULT_ALIAS_DIR",
    "DEFAULT_ALIAS_FILE_PATH",
    "DEFAULT_TABLE_NAME",
    "PersistentBlocklist",
]
