"""Safe remediation of Netgate audit findings (Phase 7b).

Every mutating interaction with the Netgate goes through
:class:`NetgateApplier`, which wraps three guarantees around each
operator click on the "Apply" button:

1. **Pre-change backup** of ``/cf/conf/config.xml`` whenever the
   handler *might* patch it. The backup is taken on the WardSOAR
   host (never left on the Netgate, which is what got compromised in
   the scenarios we defend against). Backups rotate so older copies
   accumulate without bounding growth.
2. **Handler registry** — only fixes that have a registered async
   handler can be applied. Findings without a handler are visible in
   the audit UI but their checkbox stays disabled, so a future
   rename of a fix id cannot silently silently mutate the box.
3. **Post-apply verify** — after the handler returns, the applier
   calls the handler's ``verify_fn`` (typically a single-check read
   against the live pfSense state). If verification fails, the
   backup is restored and the apply returns a failure with a full
   trace. No half-fixed state is ever left on the Netgate without
   the operator knowing.

Tonight (v0.7.1) ships three handlers that are **strictly SSH-only**
— none of them patches ``/cf/conf/config.xml``. That keeps the
blast radius minimal while the persistent-patch handlers (attach to
WAN, enable ET Open, etc.) are validated in Phase 7b.2.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

if TYPE_CHECKING:
    from wardsoar.core.remote_agents.netgate_agent import NetgateAgent

logger = logging.getLogger("ward_soar.netgate_apply")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigBackupEntry:
    """Metadata for one persisted backup of ``/cf/conf/config.xml``."""

    path: Path
    created_at: str  # ISO 8601
    reason: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class SafeApplyResult:
    """Outcome of one :meth:`NetgateApplier.safe_apply` call."""

    fix_id: str
    success: bool
    backup_created: bool
    backup: Optional[ConfigBackupEntry]
    verify_passed: bool
    rollback_performed: bool
    messages: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fix_id": self.fix_id,
            "success": self.success,
            "backup_created": self.backup_created,
            "backup_path": str(self.backup.path) if self.backup else None,
            "verify_passed": self.verify_passed,
            "rollback_performed": self.rollback_performed,
            "messages": list(self.messages),
            "error": self.error,
        }


@dataclass(frozen=True)
class HandlerSpec:
    """Registry entry for one fix id.

    Attributes:
        apply_fn: Async callable ``(ssh) -> (ok: bool, message: str)``
            that performs the mutation. The callable must NEVER raise;
            errors are reported via the returned tuple.
        verify_fn: Async callable ``(ssh) -> (ok: bool, message: str)``
            that asserts the fix held. Identical contract to apply_fn.
        touches_config_xml: True when the handler may mutate
            ``/cf/conf/config.xml``. The applier will take a backup
            beforehand only in this case — SSH-only handlers skip
            the backup round-trip.
        description: One-line label shown in the UI.
    """

    apply_fn: Callable[["NetgateAgent"], Awaitable[tuple[bool, str]]]
    verify_fn: Callable[["NetgateAgent"], Awaitable[tuple[bool, str]]]
    touches_config_xml: bool
    description: str


# ---------------------------------------------------------------------------
# Handler library (SSH-only for v0.7.1)
# ---------------------------------------------------------------------------


# Commands are hard-coded literals; operator input is never
# interpolated into an SSH argument on this code path.
_CMD_RULE_UPDATE = (
    "test -x /usr/local/bin/suricata_updaterules.php "
    "&& /usr/local/bin/suricata_updaterules.php 2>&1 | tail -40 "
    "|| echo 'suricata_updaterules.php missing'"
)
_CMD_RULES_COUNT = (
    "find /usr/local/etc/suricata -maxdepth 3 -name '*.rules' "
    "-exec wc -l {} + 2>/dev/null | tail -1 || true"
)
_CMD_SURICATA_START = (
    "for inst in /usr/local/etc/suricata/suricata_*/; do "
    "  pfname=$(basename \"$inst\" | sed 's/suricata_//'); "
    '  echo "starting $pfname"; '
    "  /usr/local/etc/rc.d/suricata start >/dev/null 2>&1 || true; "
    "done; "
    "/usr/local/etc/rc.d/suricata start 2>&1 | tail -20 || true; "
    "sleep 2; "
    "pgrep -lf '^/usr/local/bin/suricata' 2>/dev/null || echo '(no suricata pid after start)'"
)
_CMD_SURICATA_PIDS_VERIFY = "pgrep -lf '^/usr/local/bin/suricata' 2>/dev/null || true"
_CMD_CREATE_BLOCKLIST = (
    "pfctl -t blocklist -T create 2>&1 " "|| pfctl -t blocklist -T add 0.0.0.0/32 2>&1"
)
_CMD_BLOCKLIST_VERIFY = "pfctl -s Tables 2>/dev/null | grep -w blocklist || true"

# Post-condition verifier for ``pf.migrate_alias_to_urltable``. Two
# hard requirements: (1) config.xml declares the alias as urltable,
# (2) the alias file physically exists on pfSense. Both must hold, so
# we test them separately and compose with exit codes rather than
# chaining ``&&`` -- a compound failure would otherwise report an
# ambiguous result.
_CMD_ALIAS_URLTABLE_VERIFY = (
    "grep -A 5 '<name>blocklist</name>' /cf/conf/config.xml 2>/dev/null "
    "| grep -q '<type>urltable</type>'; XML=$?; "
    "test -f /var/db/aliastables/wardsoar_blocklist.txt; FILE=$?; "
    'if [ "$XML" -eq 0 ] && [ "$FILE" -eq 0 ]; then '
    "  echo OK; "
    "else "
    '  echo "KO xml=$XML file=$FILE"; '
    "fi"
)


async def _run_with_trace(ssh: "NetgateAgent", cmd: str, timeout: int = 30) -> tuple[bool, str]:
    """Thin wrapper that surfaces both stdout and failure mode."""
    ok, out = await ssh.run_read_only(cmd, timeout=timeout)
    return ok, out


async def _apply_rule_update(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Trigger pfSense's Suricata rule-update script.

    This pulls ET Open / Snort Community rules from their configured
    sources and refreshes the rules directory on each Suricata
    instance. No ``/cf/conf/config.xml`` mutation — the updater uses
    already-persisted source definitions.
    """
    ok, out = await _run_with_trace(ssh, _CMD_RULE_UPDATE, timeout=180)
    return ok, out[-1800:] if out else ""


async def _verify_rules_loaded(ssh: "NetgateAgent") -> tuple[bool, str]:
    ok, out = await _run_with_trace(ssh, _CMD_RULES_COUNT, timeout=15)
    if not ok:
        return False, out
    # The tail line typically looks like "    48521 total".
    total_str = "".join(c for c in out.splitlines()[-1] if c.isdigit()) if out else ""
    try:
        total = int(total_str)
    except ValueError:
        return False, f"unparsed wc output: {out!r}"
    if total < 10_000:
        return False, f"only {total} rules loaded (expected >= 10 000)"
    return True, f"{total} rules loaded"


async def _apply_start_suricata(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Start the Suricata service on every configured interface.

    Uses pfSense's rc.d script entry point, which iterates instances
    internally. The command is idempotent — already-running instances
    are ignored with a non-fatal warning.
    """
    ok, out = await _run_with_trace(ssh, _CMD_SURICATA_START, timeout=60)
    return ok, out[-2000:] if out else ""


async def _verify_suricata_running(ssh: "NetgateAgent") -> tuple[bool, str]:
    ok, out = await _run_with_trace(ssh, _CMD_SURICATA_PIDS_VERIFY, timeout=15)
    if not ok:
        return False, out
    pids = [ln for ln in (out or "").splitlines() if "/usr/local/bin/suricata" in ln]
    if not pids:
        return False, "no suricata pid found after start"
    return True, f"{len(pids)} suricata PID(s) running"


async def _apply_create_blocklist(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Create the ``blocklist`` pf table if it does not exist.

    *Transient by design* — the table disappears on next ``pfctl -f
    /tmp/rules.debug`` reload unless pfSense's alias layer references
    it from ``config.xml``. This handler exists so blocking can at
    least start working immediately after an audit; persistence is
    Phase 7b.2 territory.
    """
    ok, out = await _run_with_trace(ssh, _CMD_CREATE_BLOCKLIST, timeout=15)
    return ok, out


async def _verify_blocklist_present(ssh: "NetgateAgent") -> tuple[bool, str]:
    ok, out = await _run_with_trace(ssh, _CMD_BLOCKLIST_VERIFY, timeout=15)
    if not ok:
        return False, out
    if "blocklist" not in out:
        return False, "table not present after create"
    return True, "table present in pfctl -s Tables"


async def _apply_migrate_alias_to_urltable(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Convert the ``blocklist`` alias from host to urltable (Phase 7h).

    A host-type alias stores its IPs inside ``config.xml``, which
    pfSense regenerates from the shipped empty default on every
    filter reload (rule change, package install, reboot, webGUI
    save). Every IP WardSOAR added via ``pfctl -T add`` therefore
    evaporated within minutes -- which is exactly why Netflix stayed
    reachable overnight despite a "blocked" log line. Flipping the
    alias to url-table, pointed at a file WardSOAR owns exclusively,
    is the canonical pfSense pattern (pfBlockerNG, Snort blocklist,
    CrowdSec all use it) and guarantees blocks survive every reload.

    This handler is idempotent: re-applying it when the alias is
    already urltable is a no-op that the underlying migration
    function reports as success. Pre-existing IPs in the legacy
    ``<address>`` element are preserved.

    :class:`NetgateApplier` takes a full ``config.xml`` backup before
    this runs (``touches_config_xml=True``), and will restore it if
    our post-verify fails.
    """
    try:
        result = await ssh.migrate_alias_to_urltable()
    except Exception as exc:  # noqa: BLE001 — fail-safe reporting
        logger.exception("migrate_alias_to_urltable raised")
        return False, repr(exc)
    return result.success, result.message


async def _verify_alias_persistent(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Confirm the blocklist alias is urltable AND the file is on disk."""
    ok, out = await _run_with_trace(ssh, _CMD_ALIAS_URLTABLE_VERIFY, timeout=15)
    if not ok:
        return False, out
    if "OK" not in (out or ""):
        return False, f"verification failed: {(out or '').strip()[:200]}"
    return True, "blocklist alias is urltable and seed file exists"


async def _apply_suricata_runmode_workers(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Flip every Suricata instance's runmode from autofp to workers.

    On a Netgate 4200 (4-core ARM) the ``workers`` runmode runs one
    independent Suricata inspection thread per CPU, instead of the
    ``autofp`` default that funnels all packets through a single
    flow-balancer thread. Real-world gain on pfSense 25.x: ~2-3x
    throughput and lower P99 packet latency.

    The operation is strictly XML-driven: we patch
    ``<runmode>`` in every ``<rule>`` record under
    ``<installedpackages><suricata>`` in ``config.xml``, then invoke
    pfSense's Suricata package helper to regenerate each instance's
    YAML and restart the service. Same "no tech debt" doctrine as
    Phase 7h — the change survives every GUI save, reboot and
    package upgrade.
    """
    try:
        result = await ssh.apply_suricata_runmode("workers")
    except Exception as exc:  # noqa: BLE001 — fail-safe reporting
        logger.exception("apply_suricata_runmode raised")
        return False, repr(exc)
    return result.success, result.message


async def _verify_suricata_runmode_workers(ssh: "NetgateAgent") -> tuple[bool, str]:
    """Confirm at least one regenerated YAML is now in workers mode."""
    ok, out = await _run_with_trace(
        ssh,
        "grep -E '^runmode:' /usr/local/etc/suricata/suricata_*/suricata.yaml "
        "2>/dev/null | head -5 || true",
        timeout=10,
    )
    if not ok:
        return False, out
    if "runmode: workers" not in (out or ""):
        return False, f"no YAML shows runmode: workers yet — {(out or '').strip()[:200]}"
    return True, "Suricata YAML reports runmode: workers"


#: The registry consumed by the applier and by the UI. Adding a new
#: handler is the only way to expose a new apply-capable audit finding
#: to the operator.
_HANDLERS: dict[str, HandlerSpec] = {
    "suricata.rules_loaded": HandlerSpec(
        apply_fn=_apply_rule_update,
        verify_fn=_verify_rules_loaded,
        touches_config_xml=False,
        description="Run pfSense's Suricata rule updater (ET Open + Snort Community)",
    ),
    "suricata.process_running": HandlerSpec(
        apply_fn=_apply_start_suricata,
        verify_fn=_verify_suricata_running,
        touches_config_xml=False,
        description="Start the Suricata service on configured interfaces",
    ),
    "pf.blocklist_table": HandlerSpec(
        apply_fn=_apply_create_blocklist,
        verify_fn=_verify_blocklist_present,
        touches_config_xml=False,
        description="Create the 'blocklist' pf table (ephemeral until config.xml persists it)",
    ),
    "pf.alias_persistent": HandlerSpec(
        apply_fn=_apply_migrate_alias_to_urltable,
        verify_fn=_verify_alias_persistent,
        touches_config_xml=True,
        description=("Migrate blocklist alias from host to urltable (enables persistent blocks)"),
    ),
    "suricata.runmode": HandlerSpec(
        apply_fn=_apply_suricata_runmode_workers,
        verify_fn=_verify_suricata_runmode_workers,
        touches_config_xml=True,
        description=(
            "Switch Suricata runmode to 'workers' (better throughput on multi-core pfSense)"
        ),
    ),
}


def applicable_fix_ids() -> set[str]:
    """Fix ids the UI is allowed to offer an Apply button for."""
    return set(_HANDLERS.keys())


# ---------------------------------------------------------------------------
# Applier
# ---------------------------------------------------------------------------


#: Cap on retained config.xml backups. Old backups are deleted in
#: insertion order. 20 is enough for several weeks of typical use.
_MAX_BACKUPS = 20


class NetgateApplier:
    """Orchestrate safe mutations on the Netgate.

    Args:
        ssh: Connected :class:`~src.pfsense_ssh.PfSenseSSH`.
        backup_dir: Directory on the WardSOAR host where snapshots of
            ``/cf/conf/config.xml`` are stored. Created on first use.
    """

    _BACKUP_CMD = "cat /cf/conf/config.xml 2>/dev/null || true"

    def __init__(self, ssh: "NetgateAgent", backup_dir: Path) -> None:
        self._ssh = ssh
        self._backup_dir = Path(backup_dir)
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Backup / rotation
    # ------------------------------------------------------------------

    async def _snapshot_config(self, reason: str) -> Optional[ConfigBackupEntry]:
        """Pull a fresh ``config.xml`` snapshot and persist it.

        Returns ``None`` when the remote read fails; callers treat
        that as a hard abort on anything config-mutating.
        """
        ok, content = await self._ssh.run_read_only(self._BACKUP_CMD, timeout=15)
        if not ok or not content.strip():
            logger.error("config backup failed: ssh ok=%s, size=%d", ok, len(content))
            return None
        now = datetime.now(timezone.utc)
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        safe_reason = "".join(c if c.isalnum() or c in "._-" else "_" for c in reason)[:48]
        fname = f"config_{stamp}_{safe_reason}.xml"
        path = self._backup_dir / fname
        path.write_text(content, encoding="utf-8")
        entry = ConfigBackupEntry(
            path=path,
            created_at=now.isoformat(),
            reason=reason,
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            size_bytes=len(content),
        )
        self._rotate_backups()
        logger.info(
            "config backup saved: %s (%d bytes, reason=%s)",
            path,
            entry.size_bytes,
            reason,
        )
        return entry

    def _rotate_backups(self) -> None:
        backups = sorted(
            (p for p in self._backup_dir.glob("config_*.xml") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
        )
        while len(backups) > _MAX_BACKUPS:
            oldest = backups.pop(0)
            try:
                oldest.unlink()
                logger.info("pruned old backup: %s", oldest)
            except OSError as exc:
                logger.warning("backup prune failed for %s: %s", oldest, exc)

    def list_backups(self) -> list[ConfigBackupEntry]:
        """All persisted backups, ordered oldest-first."""
        entries: list[ConfigBackupEntry] = []
        for path in sorted(self._backup_dir.glob("config_*.xml"), key=lambda p: p.stat().st_mtime):
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            entries.append(
                ConfigBackupEntry(
                    path=path,
                    created_at=datetime.fromtimestamp(
                        path.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    reason=path.stem,
                    sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    size_bytes=len(content),
                )
            )
        return entries

    # ------------------------------------------------------------------
    # Apply orchestration
    # ------------------------------------------------------------------

    async def safe_apply(self, fix_id: str) -> SafeApplyResult:
        """Apply the registered handler for ``fix_id`` with full safety.

        Returns a :class:`SafeApplyResult` describing every stage;
        even on success, ``messages`` contains the handler's raw
        output so the UI can show it to the operator.
        """
        messages: list[str] = [f"fix_id={fix_id}"]

        spec = _HANDLERS.get(fix_id)
        if spec is None:
            return SafeApplyResult(
                fix_id=fix_id,
                success=False,
                backup_created=False,
                backup=None,
                verify_passed=False,
                rollback_performed=False,
                messages=messages,
                error=f"No registered handler for fix_id={fix_id!r}",
            )

        # Step 1 — backup if the handler may touch config.xml.
        backup: Optional[ConfigBackupEntry] = None
        if spec.touches_config_xml:
            backup = await self._snapshot_config(f"pre-apply-{fix_id}")
            if backup is None:
                return SafeApplyResult(
                    fix_id=fix_id,
                    success=False,
                    backup_created=False,
                    backup=None,
                    verify_passed=False,
                    rollback_performed=False,
                    messages=messages,
                    error="Could not back up config.xml -- refusing to mutate.",
                )
            messages.append(f"backup: {backup.path.name} ({backup.size_bytes} bytes)")

        # Step 2 — run the apply handler.
        try:
            apply_ok, apply_msg = await spec.apply_fn(self._ssh)
        except Exception as exc:  # noqa: BLE001 - fail-safe reporting
            logger.exception("apply handler %s raised", fix_id)
            apply_ok = False
            apply_msg = repr(exc)
        messages.append(f"apply: ok={apply_ok} -- {apply_msg.strip()[:400]}")
        if not apply_ok:
            # Surface the handler's own reason in ``error`` so the UI
            # dialog does not collapse every distinct failure mode
            # (seed failed, push failed, verify step 7 KO, etc.) into
            # the useless generic "apply handler reported failure".
            # Keep the generic wrapper as a prefix so the label still
            # locates the failure in the apply phase.
            raw_reason = apply_msg.strip() or "no reason reported"
            return SafeApplyResult(
                fix_id=fix_id,
                success=False,
                backup_created=backup is not None,
                backup=backup,
                verify_passed=False,
                rollback_performed=False,
                messages=messages,
                error=f"apply failed: {raw_reason[:300]}",
            )

        # Step 3 — verify.
        try:
            verify_ok, verify_msg = await spec.verify_fn(self._ssh)
        except Exception as exc:  # noqa: BLE001 - fail-safe reporting
            logger.exception("verify handler %s raised", fix_id)
            verify_ok = False
            verify_msg = repr(exc)
        messages.append(f"verify: ok={verify_ok} -- {verify_msg.strip()[:400]}")

        if verify_ok:
            return SafeApplyResult(
                fix_id=fix_id,
                success=True,
                backup_created=backup is not None,
                backup=backup,
                verify_passed=True,
                rollback_performed=False,
                messages=messages,
            )

        # Step 4 — verify failed. Restore if we took a backup.
        rollback_done = False
        if backup is not None:
            # Shell-safe: backup.path.read_text() content is wrapped in
            # a quoted-delimiter heredoc, and the delimiter never
            # appears in a pfSense config.xml.
            try:
                payload = backup.path.read_text(encoding="utf-8")
                # Sentinel delimiter — matches the rules-deploy
                # approach in netgate_custom_rules.
                if "__WARDSOAR_CFG_EOF__" in payload:
                    messages.append("rollback: refused (sentinel collision in backup content)")
                else:
                    restore_cmd = (
                        "cat > /cf/conf/config.xml <<'__WARDSOAR_CFG_EOF__'\n"
                        f"{payload}"
                        "__WARDSOAR_CFG_EOF__\n"
                        "/etc/rc.conf_mount_rw >/dev/null 2>&1 || true"
                    )
                    rb_ok, rb_out = await self._ssh.run_read_only(restore_cmd, timeout=30)
                    rollback_done = rb_ok
                    messages.append(f"rollback: ok={rb_ok} -- {rb_out.strip()[:300]}")
            except OSError as exc:
                messages.append(f"rollback: could not read backup file -- {exc}")

        return SafeApplyResult(
            fix_id=fix_id,
            success=False,
            backup_created=backup is not None,
            backup=backup,
            verify_passed=False,
            rollback_performed=rollback_done,
            messages=messages,
            error="verify failed after apply",
        )

    async def safe_apply_many(self, fix_ids: list[str]) -> list[SafeApplyResult]:
        """Apply several fixes sequentially. Stops on first hard failure.

        *Sequential by design* — a half-finished first fix can change
        the evaluation of the next. Concurrent mutation of pfSense
        state is not a problem we want to debug on a home firewall.
        """
        results: list[SafeApplyResult] = []
        for fix_id in fix_ids:
            result = await self.safe_apply(fix_id)
            results.append(result)
            if not result.success and result.rollback_performed is False:
                # A failure without rollback may mean state was
                # partially mutated; refusing to chain protects the
                # operator from compounding issues.
                logger.warning(
                    "safe_apply_many aborting after %s: not rolling back further fixes",
                    fix_id,
                )
                break
        return results


__all__ = [
    "ConfigBackupEntry",
    "HandlerSpec",
    "NetgateApplier",
    "SafeApplyResult",
    "applicable_fix_ids",
]
