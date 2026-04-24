"""DPAPI-backed encryption for forensic artefacts.

Windows DPAPI (Data Protection API) is the standard way to encrypt
blobs without managing a key: the OS derives a key from the current
user's credentials (or the machine account). Protected blobs:
    - Survive reboots.
    - Cannot be decrypted by another user on the same machine.
    - Cannot be decrypted on another machine, even by the same user.

For WardSOAR this is exactly what we want: evidence files are
unreadable by another account on the same PC (anti-insider threat)
and unreadable by anyone who copies them off the machine without
the matching credential material (anti-exfiltration).

Two scopes are available:
    CRYPTPROTECT_UI_FORBIDDEN = 0x1   → no interactive prompt
    CRYPTPROTECT_LOCAL_MACHINE = 0x4  → key bound to the machine, not user

We default to *user scope* (no flag) because WardSOAR normally runs as
the logged-in user. If the configuration sets ``scope: "machine"`` the
blob is decryptable by any process on the same host (useful when the
app runs as a service under SYSTEM).

Fail-safe:
    - Importing pywin32 fails on non-Windows → encryption disabled.
    - Encrypt/decrypt errors are logged and raised as
      EncryptionUnavailable so callers can fall back to plaintext
      storage rather than losing the evidence outright.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("ward_soar.forensic.encryption")


# Windows DPAPI flag.
CRYPTPROTECT_LOCAL_MACHINE = 0x4

# Optional "entropy" — a second secret that must match to decrypt.
# Hardcoded because it's not a cryptographic secret, just a domain
# separator: two apps using DPAPI with different entropy cannot read
# each other's blobs even under the same user.
_DEFAULT_ENTROPY = b"WardSOAR-evidence-v1"


class EncryptionUnavailable(RuntimeError):
    """Raised when DPAPI is not usable (non-Windows, import failure)."""


class DpapiEncryptor:
    """Thin wrapper around ``win32crypt.CryptProtectData``.

    Args:
        scope: ``"user"`` (default) or ``"machine"``. Machine scope lets
               any process on the host decrypt; user scope restricts to
               the running account.
        entropy: Per-app byte string mixed into the key. Protects against
                 cross-app blob reuse on the same machine.
    """

    def __init__(self, scope: str = "user", entropy: bytes = _DEFAULT_ENTROPY) -> None:
        self._scope = scope
        self._entropy = entropy
        self._flags = CRYPTPROTECT_LOCAL_MACHINE if scope == "machine" else 0
        self._win32crypt = self._load_win32crypt()

    @staticmethod
    def _load_win32crypt() -> object:
        """Import pywin32's crypt module once, or raise EncryptionUnavailable.

        Returns:
            The imported module (typed as object; typed access via getattr).

        Raises:
            EncryptionUnavailable: if pywin32 is missing or we're not on
            Windows.
        """
        try:
            import win32crypt
        except ImportError as exc:  # pragma: no cover — depends on platform
            raise EncryptionUnavailable(
                "pywin32 win32crypt is not available on this platform"
            ) from exc
        return win32crypt

    @property
    def available(self) -> bool:
        """True if DPAPI was importable — encrypt/decrypt will work."""
        return self._win32crypt is not None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` with DPAPI and return the opaque blob.

        Raises:
            EncryptionUnavailable: if the API call fails.
        """
        try:
            # CryptProtectData signature: (data, description, entropy, reserved,
            #                               prompt_struct, flags) → blob
            blob = self._win32crypt.CryptProtectData(  # type: ignore[attr-defined]
                plaintext,
                "WardSOAR evidence",
                self._entropy,
                None,
                None,
                self._flags,
            )
            return bytes(blob)
        except Exception as exc:  # pragma: no cover — pywin32 OSError
            logger.error("DPAPI encrypt failed: %s", exc)
            raise EncryptionUnavailable(str(exc)) from exc

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt a DPAPI blob produced by :meth:`encrypt`.

        Raises:
            EncryptionUnavailable: if the blob is corrupt, foreign, or
            the current credentials cannot unwrap it.
        """
        try:
            # CryptUnprotectData returns (description, data)
            _desc, plaintext = self._win32crypt.CryptUnprotectData(  # type: ignore[attr-defined]
                blob,
                self._entropy,
                None,
                None,
                self._flags,
            )
            return bytes(plaintext)
        except Exception as exc:  # pragma: no cover — pywin32 OSError
            logger.error("DPAPI decrypt failed: %s", exc)
            raise EncryptionUnavailable(str(exc)) from exc


def try_build_encryptor(scope: str = "user") -> Optional[DpapiEncryptor]:
    """Build an encryptor, returning None if DPAPI is unavailable.

    Convenience for callers that want to degrade gracefully rather
    than raise at startup.
    """
    try:
        return DpapiEncryptor(scope=scope)
    except EncryptionUnavailable as exc:
        logger.warning("Evidence encryption disabled: %s", exc)
        return None
