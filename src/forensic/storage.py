"""Protected evidence directory for forensic artefacts.

Creates a per-incident subdirectory (``evidence/{alert_id}/``) and
best-effort applies Windows ACLs via ``icacls`` so that non-admin user
code cannot tamper with the preserved files. Each written artefact is
immediately marked read-only.

If ``icacls`` is unavailable or denied (non-admin process), the code
logs a warning and continues — we'd rather have unprotected evidence
than no evidence at all.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess  # nosec B404 — needed to invoke icacls for ACL hardening
from pathlib import Path
from subprocess import (  # nosec B404 — exception class imports only
    CompletedProcess,
    TimeoutExpired,
)
from typing import Optional

from src import win_paths
from src.forensic.encryption import DpapiEncryptor, EncryptionUnavailable

logger = logging.getLogger("ward_soar.forensic.storage")


DEFAULT_ICACLS_TIMEOUT_SECONDS = 15


#: Extension appended to DPAPI-encrypted artefacts. The orchestrator uses
#: this to tell encrypted from plaintext blobs when listing a directory.
ENCRYPTED_EXTENSION = ".dpapi"


class ProtectedEvidenceStorage:
    """Filesystem helper for evidence directories.

    Args:
        root_dir: Base directory under which per-alert subdirectories are
                  created. Typically ``<data_dir>/evidence``.
        apply_acls: If True (default on Windows), run icacls to restrict
                    the evidence directory to SYSTEM + Administrators.
        encryptor: Optional DPAPI encryptor. When provided, every
                   ``write_and_seal`` call wraps the payload before
                   hitting disk and appends :data:`ENCRYPTED_EXTENSION`.
    """

    def __init__(
        self,
        root_dir: Path,
        apply_acls: bool = True,
        encryptor: Optional[DpapiEncryptor] = None,
    ) -> None:
        self._root = root_dir
        self._apply_acls = apply_acls and os.name == "nt"
        self._encryptor = encryptor
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def encryption_enabled(self) -> bool:
        """True if DPAPI encryption will wrap every write."""
        return self._encryptor is not None

    @property
    def root(self) -> Path:
        """Top-level evidence directory."""
        return self._root

    def create_incident_dir(self, alert_id: str, phase: str = "volatile") -> Path:
        """Create and return ``root/{alert_id}/{phase}/``.

        *No ACL hardening happens here* — the running WardSOAR user
        needs write access to populate the directory. Call
        :meth:`seal_directory` once all artefacts have been written
        to tighten the ACLs down to SYSTEM + Administrators.

        Prior to v0.7.5 this method applied ACL hardening inline,
        which reduced the caller's rights to read-only *before* any
        write had a chance to succeed, causing every
        :meth:`write_and_seal` call to fail with PermissionError
        (observed on 2026-04-20 22:59 after a Hard Protect block
        and multiple times earlier that afternoon).

        Args:
            alert_id: Identifier used as the per-incident subdirectory name.
                      Callers must sanitise this; we still strip slashes
                      defensively to avoid accidental path escape.
            phase: Subfolder for the acquisition stage (volatile / durable).

        Returns:
            The created Path, ready to receive artefacts.
        """
        safe_id = "".join(c for c in alert_id if c.isalnum() or c in "-_")
        safe_phase = "".join(c for c in phase if c.isalnum() or c in "-_")
        target = self._root / safe_id / safe_phase
        target.mkdir(parents=True, exist_ok=True)
        return target

    def seal_directory(self, directory: Path) -> None:
        """Tighten the evidence directory ACLs once all writes are done.

        Called by :class:`QuickAcquisitionManager` after
        ``MANIFEST.json`` lands on disk. At that point the directory
        no longer needs operator-level write access, and the ACL
        restriction protects the evidence from post-incident tampering
        by a non-admin user (or by malware that escalated to the
        operator but not yet to Administrators).

        Safe to call multiple times (icacls is idempotent for these
        grants) and safe to call with an empty directory. No-op on
        non-Windows or when ``apply_acls=False`` at construction.
        """
        if not self._apply_acls:
            return
        if not directory.is_dir():
            return
        self._harden_directory_acl(directory)

    def write_and_seal(self, path: Path, data: bytes) -> Path:
        """Write ``data`` to ``path`` (optionally DPAPI-encrypted) and seal it.

        If encryption is enabled, the payload is wrapped with DPAPI and
        the actual file written is ``path.dpapi``; the returned Path is
        the one that was actually created on disk.

        After the write, the file is chmoded read-only so accidental
        mutation is caught immediately.

        Args:
            path: Target file. Parent must already exist.
            data: Raw bytes to write.

        Returns:
            The path that was actually written (differs from ``path`` only
            when encryption is enabled, in which case ``.dpapi`` is appended).
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        actual_path = path
        payload = data

        if self._encryptor is not None:
            try:
                payload = self._encryptor.encrypt(data)
                actual_path = path.with_suffix(path.suffix + ENCRYPTED_EXTENSION)
            except EncryptionUnavailable:
                # Logged by the encryptor; fall back to plaintext rather
                # than losing the evidence.
                logger.warning("Falling back to plaintext for %s — DPAPI failed", path)

        actual_path.write_bytes(payload)
        try:
            os.chmod(actual_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            logger.debug("Failed to chmod readonly: %s", actual_path, exc_info=True)
        return actual_path

    def read_sealed(self, path: Path) -> bytes:
        """Read a sealed file, transparently decrypting if DPAPI was used.

        Accepts either the plaintext path or the ``.dpapi`` variant.
        """
        encrypted = path.with_suffix(path.suffix + ENCRYPTED_EXTENSION)
        if encrypted.is_file():
            blob = encrypted.read_bytes()
            if self._encryptor is None:
                raise RuntimeError(
                    f"Found encrypted evidence {encrypted} but no encryptor configured"
                )
            return self._encryptor.decrypt(blob)
        return path.read_bytes()

    def _harden_directory_acl(self, directory: Path) -> None:
        """Restrict the evidence directory to SYSTEM + Administrators.

        Best-effort: icacls errors are logged but do not raise so a
        non-admin user can still capture evidence (unprotected).
        """
        result = self._run_icacls(
            [
                str(directory),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "/grant:r",
                "Administrators:(OI)(CI)R",
            ]
        )
        if result is None:
            return
        if result.returncode != 0:
            logger.warning(
                "icacls returned %d while hardening %s — evidence may be writable by user",
                result.returncode,
                directory,
            )

    @staticmethod
    def _run_icacls(args: list[str]) -> CompletedProcess[str] | None:
        """Invoke icacls with a strict timeout. Returns None on failure."""
        try:
            return subprocess.run(  # nosec B603 — absolute path + hardcoded flags + caller-validated target
                [win_paths.ICACLS, *args],
                capture_output=True,
                text=True,
                timeout=DEFAULT_ICACLS_TIMEOUT_SECONDS,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
        except (FileNotFoundError, OSError, TimeoutExpired) as exc:
            logger.warning("icacls unavailable: %s", exc)
            return None
