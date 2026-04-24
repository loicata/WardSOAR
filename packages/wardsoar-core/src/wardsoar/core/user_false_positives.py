"""User-managed overlay of Suricata false-positive SIDs.

The bundled ``config/known_false_positives.yaml`` ships with the ~6
SIDs the maintainers have curated (STREAM noise, ipinfo.io, torproject
lookups, etc.). Operators often want to add their own without
modifying the shipped file — both because installs are read-only in
``Program Files`` and because upgrades would overwrite any edits.

This module provides a **user overlay**: a second YAML file that
lives under ``%APPDATA%\\WardSOAR\\config\\`` and is merged into the
filter at startup. SIDs added from the Alert Detail view append to
this overlay. The format matches the bundled file so an operator
can still hand-edit with a text editor.

Idempotence
-----------
:func:`append_sid` is idempotent: re-adding a SID that's already in
the overlay yields ``(True, path)`` without touching the file. The
UI button can be clicked multiple times without creating duplicate
entries.

Fail-safe
---------
YAML write errors are caught and returned as ``(False, error_msg)``;
the filter's existing loading logic already tolerates a missing
overlay (treats it as empty).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("ward_soar.user_false_positives")


def user_overlay_path() -> Path:
    """Return the canonical overlay path.

    Isolated from imports so that callers who monkey-patch
    ``get_data_dir`` in tests get the patched version.
    """
    from wardsoar.core.config import get_data_dir

    return get_data_dir() / "config" / "known_false_positives_user.yaml"


def _read_overlay(path: Path) -> dict[str, Any]:
    """Read the overlay YAML, tolerating missing / corrupt files.

    A missing file is treated as an empty overlay ({"suppressed_signatures": []}).
    A corrupt file is reset to empty and the previous content is
    NOT preserved — the overlay is an operator convenience, not a
    source of record.
    """
    if not path.is_file():
        return {"suppressed_signatures": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.warning("User FP overlay is corrupt, resetting: %s", exc)
        return {"suppressed_signatures": []}
    if not isinstance(raw, dict):
        return {"suppressed_signatures": []}
    raw.setdefault("suppressed_signatures", [])
    if not isinstance(raw["suppressed_signatures"], list):
        raw["suppressed_signatures"] = []
    return raw


def _write_overlay(path: Path, data: dict[str, Any]) -> None:
    """Write the overlay atomically (tempfile + rename).

    Ensures a parallel read by the filter never sees a truncated
    file. The rename is atomic on NTFS / ext4 / APFS.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    tmp.replace(path)


def append_sid(
    sid: int,
    *,
    signature: str = "",
    added_by: str = "Alert Detail UI",
) -> tuple[bool, str]:
    """Add a SID to the user false-positives overlay.

    Idempotent: if ``sid`` already appears, the call is a no-op and
    returns ``(True, "already present")``.

    Args:
        sid: Suricata signature ID to suppress.
        signature: Optional alert_signature string for the note
            field (helps the operator recognise the entry later when
            hand-editing).
        added_by: Free-form source tag stored in the note.

    Returns:
        ``(success, message_or_error)`` — the caller can surface
        the message verbatim in a toast.
    """
    if sid <= 0:
        return False, f"invalid SID: {sid!r}"

    path = user_overlay_path()
    try:
        overlay = _read_overlay(path)
    except OSError as exc:
        return False, f"could not read overlay: {exc}"

    existing_sids = {
        int(entry["signature_id"])
        for entry in overlay.get("suppressed_signatures", [])
        if isinstance(entry, dict) and "signature_id" in entry
    }
    if sid in existing_sids:
        return True, f"SID {sid} already in user overlay"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    note = f"Added via {added_by} at {now}"
    if signature:
        note += f" — {signature}"

    overlay["suppressed_signatures"].append(
        {
            "signature_id": sid,
            "note": note,
        }
    )

    try:
        _write_overlay(path, overlay)
    except OSError as exc:
        return False, f"could not write overlay: {exc}"

    logger.info("Added SID %d to user false-positives overlay at %s", sid, path)
    return True, f"SID {sid} added to user overlay (restart WardSOAR to activate)"


def list_sids() -> list[int]:
    """Return every SID currently in the user overlay.

    Useful for the filter reload path and for unit tests; the Alert
    Detail view doesn't consume this directly.
    """
    overlay = _read_overlay(user_overlay_path())
    result: list[int] = []
    for entry in overlay.get("suppressed_signatures", []):
        if isinstance(entry, dict) and "signature_id" in entry:
            try:
                result.append(int(entry["signature_id"]))
            except (ValueError, TypeError):
                continue
    return result


__all__ = ["append_sid", "list_sids", "user_overlay_path"]
