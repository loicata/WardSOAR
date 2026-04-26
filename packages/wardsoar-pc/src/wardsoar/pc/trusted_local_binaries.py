"""Operator-managed whitelist of trusted local binaries.

The :mod:`wardsoar.pc.process_risk` scorer is intentionally
suspicious of unsigned executables in user-writable locations —
that heuristic is correct for malware, but produces false
positives on legitimate hobby tools the operator built and
installed themselves (typical PyInstaller / Electron output:
unsigned, no version metadata, sitting under
``%LOCALAPPDATA%\\Programs\\``).

Rather than relax the scorer for every unsigned binary in that
class, we let the operator pin specific binaries by SHA-256
through this YAML file::

    %APPDATA%\\WardSOAR\\config\\trusted_local_binaries.yaml

When :func:`scan_process` finds the binary's hash in this list,
it short-circuits to :data:`VERDICT_BENIGN` with a clear
``signal`` indicating the operator opt-in — no Defender call,
no YARA scan, no VT cache lookup. The semantics are: *I, the
operator, have verified this binary's provenance and accept
responsibility for the verdict.*

File format::

    trusted:
      - sha256: "0b1c…"      # required, lowercase hex (64 chars)
        path_hint: "C:/…"    # optional, for human review only
        notes: "…"           # optional, reason / provenance
        added: "2026-04-26"  # optional, ISO date

The SHA-256 MUST be quoted: an unquoted purely numeric string
(``1111...1111``) is parsed by YAML as a large integer, which
the loader then drops with a warning rather than silently
converting to a wrong hex representation.

Anything outside ``trusted`` is ignored. The file is reloaded
when its mtime changes — no daemon restart needed after editing.
A missing or corrupted file collapses to an empty whitelist
without raising; the scorer keeps its conservative defaults.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from threading import Lock
from typing import Optional

import yaml

logger = logging.getLogger("ward_soar.trusted_local_binaries")

#: SHA-256 hex strings are exactly 64 lowercase hex chars. We
#: normalise on read so operator-typed uppercase still matches.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _Cache:
    """In-memory snapshot of the YAML, invalidated on mtime change.

    Thread-safe: ``scan_process`` runs from the asyncio worker thread
    while a future UI / CLI may read the file from another. The lock
    is deliberately fine-grained — we only protect the read of the
    cached set / mtime pair, not the YAML parse itself.
    """

    def __init__(self) -> None:
        self.path: Optional[Path] = None
        self.mtime: float = -1.0
        self.hashes: frozenset[str] = frozenset()
        self.lock = Lock()


_CACHE = _Cache()


def _resolve_default_path() -> Optional[Path]:
    """Return the canonical YAML path, or ``None`` if config dir absent.

    Lazy import of :func:`wardsoar.core.config.get_data_dir` so a unit
    test can still exercise the module without the core install
    rooted at ``%APPDATA%``.
    """
    try:
        from wardsoar.core.config import get_data_dir
    except Exception:  # noqa: BLE001 — module optional in stripped envs
        return None
    try:
        return get_data_dir() / "config" / "trusted_local_binaries.yaml"
    except Exception:  # noqa: BLE001 — get_data_dir may raise on locked-down hosts
        return None


def _parse_hashes(raw: object) -> frozenset[str]:
    """Extract a :class:`frozenset` of normalised SHA-256 hex strings.

    Accepts the documented schema (``{"trusted": [{"sha256": "…"}, …]}``)
    and silently drops malformed entries — a single bad row should never
    invalidate the whole list.
    """
    if not isinstance(raw, dict):
        return frozenset()
    entries = raw.get("trusted")
    if not isinstance(entries, list):
        return frozenset()

    out: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sha = entry.get("sha256")
        if isinstance(sha, int):
            # YAML parsed a 64-char numeric string (``1111...1111``) as
            # a bigint. Reverse-converting would give a wildly different
            # hex value than what the operator typed, so we drop it
            # with a clear warning instead of silently misclassifying.
            logger.warning(
                "trusted_local_binaries: sha256 entry was parsed as integer — "
                'wrap the value in quotes ("...") in the YAML so it stays a string'
            )
            continue
        if not isinstance(sha, str):
            continue
        normalised = sha.strip().lower()
        if _SHA256_RE.fullmatch(normalised):
            out.add(normalised)
        else:
            logger.debug("Ignoring malformed sha256 entry: %r", sha)
    return frozenset(out)


def load_trusted_hashes(path: Optional[Path] = None) -> frozenset[str]:
    """Return the set of operator-trusted SHA-256 hashes.

    The YAML is read at most once per mtime change — back-to-back
    calls during a Suricata burst share the cached snapshot.

    Args:
        path: Optional override for the YAML location. When ``None``
            (the default), :func:`_resolve_default_path` is consulted.
            Tests pass an explicit ``tmp_path`` to stay hermetic.

    Returns:
        Frozenset of lowercase hex SHA-256 strings. Empty when the
        file is missing, unreadable, or schema-invalid — never raises.
    """
    target = path or _resolve_default_path()
    if target is None or not target.is_file():
        # Reset cache so that creating the file later is picked up.
        with _CACHE.lock:
            if _CACHE.path != target or _CACHE.hashes:
                _CACHE.path = target
                _CACHE.mtime = -1.0
                _CACHE.hashes = frozenset()
        return frozenset()

    try:
        mtime = target.stat().st_mtime
    except OSError as exc:
        logger.debug("Cannot stat %s: %s", target, exc)
        return frozenset()

    with _CACHE.lock:
        if _CACHE.path == target and _CACHE.mtime == mtime:
            return _CACHE.hashes

    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        logger.debug("Cannot read %s: %s", target, exc)
        return frozenset()

    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        logger.warning("Trusted-local-binaries YAML invalid (%s): %s", target, exc)
        return frozenset()

    hashes = _parse_hashes(raw)

    with _CACHE.lock:
        _CACHE.path = target
        _CACHE.mtime = mtime
        _CACHE.hashes = hashes

    if hashes:
        logger.info(
            "trusted_local_binaries: %d hash(es) loaded from %s",
            len(hashes),
            target.name,
        )
    return hashes


def is_trusted(sha256_hex: str, *, path: Optional[Path] = None) -> bool:
    """Return ``True`` when ``sha256_hex`` matches an operator-trusted entry.

    Args:
        sha256_hex: Lowercase / uppercase hex SHA-256. Case-insensitive.
        path: Optional override for the YAML location (test hook).
    """
    if not sha256_hex:
        return False
    normalised = sha256_hex.strip().lower()
    if not _SHA256_RE.fullmatch(normalised):
        return False
    return normalised in load_trusted_hashes(path=path)


__all__ = ("is_trusted", "load_trusted_hashes")
