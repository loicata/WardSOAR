"""Post-reset cleanup of WardSOAR state tied to a specific Netgate.

When the operator factory-resets the Netgate, several WardSOAR files
become stale:

* ``netgate_baseline.json`` — fingerprints of surfaces that have all
  changed legitimately (host keys, config.xml, user accounts…), so a
  subsequent tamper check would cry wolf for every single surface.
* ``block_tracker.json`` — IPs recorded as actively blocked. After a
  reset the pf ``blocklist`` table is empty, so every tracked entry
  now points at nothing.
* ``trusted_temp.json`` — IPs quarantined by the rollback path. The
  pfSense side of the quarantine is a pf rule that no longer exists,
  so keeping the quarantine in WardSOAR only hides future alerts on
  those IPs without actually protecting the operator.

This module orchestrates the cleanup. It is intentionally pure Python
(no SSH, no UI); callers wire it via :class:`Pipeline.cleanup_netgate_state`
so the in-memory :class:`BlockTracker` and :class:`TrustedTempRegistry`
instances are purged in the same step as their backing files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from src.pfsense_ssh import BlockTracker
from src.trusted_temp import TrustedTempRegistry

logger = logging.getLogger("ward_soar.netgate_reset")


@dataclass(frozen=True)
class NetgateResetCleanupResult:
    """Summary of one post-reset cleanup invocation.

    Attributes:
        baseline_removed: ``True`` when the baseline file existed and
            was deleted; ``False`` when no file was on disk to begin
            with (already clean, non-fatal).
        block_entries_purged: Count of IPs removed from the block tracker.
        trusted_entries_purged: Count of IPs removed from the trusted-temp
            registry.
        errors: Human-readable errors (rare — file ops on the persistence
            layer only). Empty list means success.
    """

    baseline_removed: bool = False
    block_entries_purged: int = 0
    trusted_entries_purged: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True when every requested step completed without error."""
        return not self.errors


def cleanup_netgate_state(
    *,
    block_tracker: BlockTracker,
    trusted_temp: TrustedTempRegistry,
    baseline_path: Path,
) -> NetgateResetCleanupResult:
    """Purge every WardSOAR artefact whose meaning depends on the Netgate.

    Safe to call even when none of the files exist — each step is
    idempotent and surfaces errors individually rather than aborting
    the whole run.

    Args:
        block_tracker: The live :class:`BlockTracker`. Its backing file
            is deleted and its in-memory map is emptied atomically via
            :meth:`BlockTracker.clear_all`.
        trusted_temp: The live :class:`TrustedTempRegistry`. Same
            semantics as ``block_tracker``.
        baseline_path: Path to ``netgate_baseline.json``. Missing file
            is not an error.

    Returns:
        :class:`NetgateResetCleanupResult` describing what was purged.
    """
    errors: list[str] = []

    # --- 1. Block tracker -------------------------------------------------
    try:
        block_count = block_tracker.clear_all()
    except OSError as exc:
        logger.exception("cleanup_netgate_state: block_tracker.clear_all failed")
        errors.append(f"block_tracker: {exc}")
        block_count = 0

    # --- 2. Trusted-temp registry ----------------------------------------
    try:
        trusted_count = trusted_temp.clear_all()
    except OSError as exc:
        logger.exception("cleanup_netgate_state: trusted_temp.clear_all failed")
        errors.append(f"trusted_temp: {exc}")
        trusted_count = 0

    # --- 3. Netgate baseline ---------------------------------------------
    baseline_removed = _delete_file_if_present(baseline_path, errors)

    logger.warning(
        "netgate_reset: cleanup complete — baseline_removed=%s blocks_purged=%d "
        "trusted_purged=%d errors=%d",
        baseline_removed,
        block_count,
        trusted_count,
        len(errors),
    )

    return NetgateResetCleanupResult(
        baseline_removed=baseline_removed,
        block_entries_purged=block_count,
        trusted_entries_purged=trusted_count,
        errors=errors,
    )


def _delete_file_if_present(path: Path, errors: list[str]) -> bool:
    """Unlink ``path`` when it exists; append to ``errors`` on real failure.

    A missing file is not treated as an error — the cleanup is
    idempotent by design and the operator may legitimately click the
    button twice.
    """
    if not path.exists():
        logger.debug("netgate_reset: %s already absent — nothing to delete", path)
        return False
    try:
        path.unlink()
    except OSError as exc:
        logger.exception("netgate_reset: failed to delete %s", path)
        errors.append(f"{path.name}: {exc}")
        return False
    logger.info("netgate_reset: deleted %s", path)
    return True


# ---------------------------------------------------------------------------
# Used by the UI to build a human-readable summary of one cleanup run.
# ---------------------------------------------------------------------------


def format_result_for_display(result: NetgateResetCleanupResult) -> str:
    """Compose a short, operator-facing message for the result.

    The message is intentionally action-oriented: it starts with what
    *happened* and ends with the next step (re-establish baseline).
    Kept here rather than in the UI so terminal output and the tray
    toast can reuse the exact same wording.
    """
    parts: list[str] = []
    if result.baseline_removed:
        parts.append("baseline tamper removed")
    if result.block_entries_purged:
        parts.append(f"{result.block_entries_purged} block record(s) cleared")
    if result.trusted_entries_purged:
        parts.append(f"{result.trusted_entries_purged} quarantine entry/ies cleared")
    if not parts:
        parts.append("nothing to clean (state already fresh)")

    body = "; ".join(parts)
    if result.errors:
        return (
            f"Post-reset cleanup finished with errors: {body}. Errors: {'; '.join(result.errors)}"
        )

    return (
        f"Post-reset cleanup done — {body}. "
        "Finish Netgate + Suricata setup, then click « Establish baseline »."
    )


def default_baseline_path(data_dir: Path) -> Path:
    """Return the conventional baseline location under ``data_dir``.

    Kept here so callers (Pipeline, tests, future CLI) agree on the
    filename without duplicating the literal.
    """
    return data_dir / "netgate_baseline.json"
