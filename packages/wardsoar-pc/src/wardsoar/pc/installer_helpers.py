"""Detection, download and install helpers for Npcap and Suricata on Windows.

WardSOAR ships **without** Npcap or Suricata embedded. The setup
wizard uses this module to detect what is already installed, fetch
the missing pieces from canonical sources, verify the publisher
signature on the downloaded installers, and launch them so the
operator can accept each upstream license interactively.

License compliance (decided 2026-04-24, formalised in
``docs/ARCHITECTURE.md`` §5.3):

* WardSOAR is licensed **GPL-3.0**.
* **Npcap** is licensed **NPSL** (Nmap Public Source License) — a
  modified GPL with proprietary restrictions, **not** GPL-compatible.
  Bundling Npcap in the WardSOAR MSI would create a license conflict
  and would require the paid Npcap OEM license to redistribute.
* **Suricata** is licensed **GPL-2.0+** (compatible with GPL-3.0)
  but follows the same download-at-setup flow for operational
  consistency.

Therefore: this module **never** bundles binaries. It downloads them
from the upstream's official URLs and runs the installers; the
operator's interaction with the Npcap installer (including its
license acceptance dialog) is what creates the install on their
machine — WardSOAR does not redistribute either piece of software.

Security model:

* HTTPS only, with TLS certificate validation enforced (httpx
  default).
* Authenticode signature verification of every downloaded installer
  **before** execution. Npcap installers are signed by
  "Insecure.Com LLC" (Nmap Project) and Suricata installers by the
  Open Information Security Foundation. An installer that is not
  signed by the expected publisher is refused.
* Installer launched in the user's session with UAC prompt — we do
  **not** silently install Npcap. The operator must see the NPSL
  license screen; that interaction is what makes the install
  legally clean.
* Network operations are async-friendly via :mod:`httpx` so the
  wizard UI never freezes on a slow CDN.

Fail-safe: every public function catches transport / OS errors and
returns the documented failure value (``False``, ``None``,
``InstallerError`` for explicit failures the wizard surfaces to the
operator). No public function raises ``Exception`` to the caller.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404 — used with absolute paths and validated signers
import winreg
from dataclasses import dataclass
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404
from typing import Awaitable, Callable, Optional

import httpx

from wardsoar.pc import win_paths

logger = logging.getLogger("ward_soar.installer_helpers")


# ---------------------------------------------------------------------------
# Canonical upstream URLs (override-able via environment variables)
# ---------------------------------------------------------------------------

#: Default Npcap installer URL. Pinning a specific version protects
#: us against a sudden upstream version bump that changes the
#: installer command-line surface or signing certificate. The
#: operator can override via ``WARDSOAR_NPCAP_URL`` if upstream
#: rotates the URL or we need to pin a different version.
DEFAULT_NPCAP_URL: str = "https://npcap.com/dist/npcap-1.79.exe"

#: Public NPSL license URL — surfaced in the wizard as a clickable
#: link before the operator confirms the download. The operator
#: actually accepts the license inside the Npcap installer window;
#: this URL exists so the wizard can present the legal context.
NPCAP_LICENSE_URL: str = "https://npcap.com/oem/license.html"

#: Substring expected in the Authenticode signer of the Npcap
#: installer. Match is case-insensitive and substring-based — the
#: full subject DN includes country / locality / org / OU which we
#: don't pin to.
NPCAP_EXPECTED_SIGNER: str = "Insecure.Com LLC"

#: Default Suricata Windows installer URL. Pinning the same way
#: as Npcap. Override via ``WARDSOAR_SURICATA_URL``.
DEFAULT_SURICATA_URL: str = (
    "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.7-1-64bit.msi"
)

#: Suricata source license URL.
SURICATA_LICENSE_URL: str = "https://github.com/OISF/suricata/blob/master/LICENSE"

#: Substring expected in the Authenticode signer of the Suricata
#: installer.
SURICATA_EXPECTED_SIGNER: str = "Open Information Security Foundation"

#: Maximum installer size we'll download — guards against a
#: redirected URL pointing at something silly (a 10 GB image, a
#: torrent of cat photos). Both Npcap and Suricata installers are
#: well under 100 MB.
_MAX_INSTALLER_BYTES: int = 200 * 1024 * 1024  # 200 MiB

#: HTTP timeouts. Downloads can be slow on bad connections; we'd
#: rather wait than abort.
_HTTP_CONNECT_TIMEOUT_S: float = 30.0
_HTTP_READ_TIMEOUT_S: float = 600.0  # 10 minutes total

#: Authenticode verification timeout. The PowerShell call typically
#: returns in <500 ms once the file is on disk.
_AUTHENTICODE_TIMEOUT_S: float = 10.0


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def is_npcap_installed() -> bool:
    """True when Npcap is present on the host.

    Probes the canonical Npcap registry key under
    ``HKLM\\SOFTWARE\\WOW6432Node\\Npcap`` (Npcap is a 32-bit-aware
    install on a 64-bit host, hence the WoW6432Node redirection).
    The mere presence of the key is sufficient — Npcap creates it
    only on a successful install.

    Falls back to ``False`` on any registry / permission error
    rather than raising; the wizard surfaces the result as
    "Npcap not detected — let's install it".
    """
    candidates = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
    )
    for hive, path in candidates:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ):
                return True
        except OSError:
            # Either the key doesn't exist or we can't read it. Keep
            # trying the other candidates; only return False at the
            # end if none matched.
            continue
    return False


def is_suricata_installed() -> tuple[bool, Optional[Path]]:
    """Locate ``suricata.exe`` on the host.

    Returns:
        ``(True, path)`` when the binary is found in PATH, in a
        canonical install location, or in a registry-recorded
        install location. ``(False, None)`` otherwise. Never raises.

    Lookup order:
        1. ``shutil.which("suricata")`` — fastest, covers PATH-installed
           Suricata.
        2. ``C:\\Program Files\\Suricata\\suricata.exe`` — the default
           installer location.
        3. ``HKLM\\SOFTWARE\\OISF\\Suricata`` (or WoW6432Node) —
           registry recorded install path, if any.
    """
    # 1. PATH lookup
    on_path = shutil.which("suricata.exe") or shutil.which("suricata")
    if on_path:
        candidate = Path(on_path)
        if candidate.is_file():
            return True, candidate

    # 2. Default install location
    default_path = (
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Suricata" / "suricata.exe"
    )
    if default_path.is_file():
        return True, default_path

    # 3. Registry probe — OISF historically records the install
    #    path under a few keys depending on installer version.
    registry_candidates = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OISF\Suricata"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\OISF\Suricata"),
    )
    for hive, key_path in registry_candidates:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                if isinstance(install_dir, str) and install_dir:
                    candidate = Path(install_dir) / "suricata.exe"
                    if candidate.is_file():
                        return True, candidate
        except OSError:
            continue
    return False, None


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallerError(Exception):
    """Operator-facing error from the installer flow.

    Subclasses :class:`Exception` only because the wizard's
    coroutines need a structured error to bubble up to a
    ``QMessageBox.critical()`` call. Public helpers in this module
    catch every other exception type and return ``False`` /
    ``None`` — :class:`InstallerError` is the only thing they
    deliberately let propagate, and only when the wizard called
    them with ``raise_on_error=True``.
    """

    message: str

    def __str__(self) -> str:
        return self.message


# Type for progress callbacks the wizard wires up.
ProgressCallback = Callable[[int, int], Awaitable[None]]
"""Callable invoked periodically with (bytes_downloaded, total_bytes).

``total_bytes`` is ``-1`` when the upstream did not send a
``Content-Length`` header. The wizard uses these to drive a
QProgressBar; tests use a list-appending shim to assert progress
fires.
"""


async def download_installer(
    url: str,
    dest: Path,
    progress_callback: Optional[ProgressCallback] = None,
) -> Path:
    """Download an installer from ``url`` to ``dest``.

    HTTPS is enforced (the URL must start with ``https://``) and TLS
    certificates are validated via httpx defaults. The download is
    streamed to disk to avoid loading large files in memory. A
    progress callback can be wired up by the wizard to drive a
    QProgressBar without freezing the UI.

    Args:
        url: HTTPS URL of the installer.
        dest: Local path the file is written to. Parent directory
            is created if missing. An existing file at ``dest`` is
            overwritten.
        progress_callback: Optional async callback ``(bytes_done,
            total_bytes)`` invoked roughly every 1 MiB. ``total_bytes``
            is ``-1`` when the server does not advertise a
            ``Content-Length`` header.

    Returns:
        The destination path after a successful download.

    Raises:
        InstallerError: with a clear message on transport failure,
            non-200 response, missing/invalid URL, or oversize
            download (>200 MiB).
    """
    if not url.lower().startswith("https://"):
        raise InstallerError(f"refusing to download from non-HTTPS URL: {url}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    timeout = httpx.Timeout(_HTTP_READ_TIMEOUT_S, connect=_HTTP_CONNECT_TIMEOUT_S)
    bytes_done = 0
    chunk_size = 64 * 1024  # 64 KiB

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    raise InstallerError(f"download failed: HTTP {resp.status_code} from {url}")
                total_bytes = int(resp.headers.get("Content-Length", "-1"))
                if total_bytes > _MAX_INSTALLER_BYTES:
                    raise InstallerError(
                        f"download refused: size {total_bytes} exceeds "
                        f"{_MAX_INSTALLER_BYTES} bytes cap"
                    )

                # Open destination only once we are sure we'll commit
                # to writing — avoids leaving an empty file on a
                # 4xx error.
                with dest.open("wb") as f:
                    async for chunk in resp.aiter_bytes(chunk_size):
                        f.write(chunk)
                        bytes_done += len(chunk)
                        if bytes_done > _MAX_INSTALLER_BYTES:
                            raise InstallerError(
                                f"download refused: streamed bytes "
                                f"exceeded {_MAX_INSTALLER_BYTES} cap"
                            )
                        if progress_callback is not None:
                            # Don't await on every 64 KiB chunk — that
                            # would saturate the event loop with UI
                            # updates. Once per ~1 MiB is plenty for
                            # a smooth progress bar.
                            if bytes_done % (1024 * 1024) < chunk_size:
                                await progress_callback(bytes_done, total_bytes)

        # Final progress tick so the bar reaches 100%.
        if progress_callback is not None:
            await progress_callback(bytes_done, bytes_done)

        return dest
    except httpx.HTTPError as exc:
        # Make sure a partially-written file does not get used by
        # mistake.
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        raise InstallerError(f"download failed ({type(exc).__name__}): {exc}") from exc


def sha256_of(path: Path) -> str:
    """Compute the SHA-256 of a file as a lowercase hex string.

    Used by the wizard to display the installer's hash next to the
    download progress so a paranoid operator can compare with
    fingerprints they get from a separate channel. Reads the file
    in 1 MiB chunks; safe on large installers.
    """
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


# ---------------------------------------------------------------------------
# Authenticode verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthenticodeResult:
    """Outcome of an Authenticode signature check.

    ``status`` is one of ``"valid"`` / ``"unsigned"`` /
    ``"hash_mismatch"`` / ``"invalid"`` / ``"unknown"`` (subprocess
    failure / PowerShell missing). ``signer`` is the short subject
    name extracted from the SignerCertificate.Subject — empty when
    the file is unsigned or the check failed.
    """

    status: str
    signer: str

    def is_trusted_for(self, expected_signer: str) -> bool:
        """Returns True when the signature is valid AND the expected
        signer substring is found in the actual signer.

        Helper for the two checks every installer flow does in
        sequence (status valid + signer match). Case-insensitive
        substring match — see :func:`verify_authenticode` for the
        rationale on not pinning the full subject DN.
        """
        return self.status == "valid" and expected_signer.lower() in self.signer.lower()


def verify_authenticode(path: Path, expected_signer_substring: str) -> AuthenticodeResult:
    """Run ``Get-AuthenticodeSignature`` on ``path``.

    Returns:
        :class:`AuthenticodeResult` describing the signature state.
        Never raises; PowerShell unavailable / timed out collapses
        to ``status="unknown"`` so the caller can decide whether to
        proceed (the wizard refuses; tests can override).

    The expected signer match is **substring + case-insensitive**.
    The full subject DN includes country / locality / org / OU
    which we don't pin to — only the publisher name. Caller MUST
    verify ``status == "valid"`` AND ``expected_signer_substring``
    is in the result's signer string before treating the file as
    trusted.

    Implementation note: we deliberately reuse the same approach as
    :func:`wardsoar.pc.process_risk._check_signature` — a
    ``Get-AuthenticodeSignature`` call wrapped in
    ``ConvertTo-Json``. Sharing the pattern keeps the code base's
    Authenticode handling uniform.
    """
    if not path.is_file():
        return AuthenticodeResult(status="unknown", signer="")

    ps_exe = getattr(win_paths, "POWERSHELL", None)
    if not ps_exe or not Path(str(ps_exe)).is_file():
        logger.warning("verify_authenticode: PowerShell not found, cannot verify %s", path)
        return AuthenticodeResult(status="unknown", signer="")

    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{path}';"
        "if($sig){"
        " $obj = @{"
        "  Status = $sig.Status.ToString();"
        "  Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }"
        " };"
        " $obj | ConvertTo-Json -Compress"
        '} else { \'{"Status":"Unknown","Subject":""}\' }'
    )

    try:
        result = subprocess.run(  # nosec B603 — absolute path + hardcoded args
            [str(ps_exe), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=_AUTHENTICODE_TIMEOUT_S,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (FileNotFoundError, OSError, TimeoutExpired) as exc:
        logger.debug("verify_authenticode: PowerShell call failed for %s: %s", path, exc)
        return AuthenticodeResult(status="unknown", signer="")

    if result.returncode != 0 or not result.stdout:
        return AuthenticodeResult(status="unknown", signer="")

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return AuthenticodeResult(status="unknown", signer="")

    raw_status = str(payload.get("Status") or "").lower()
    raw_subject = str(payload.get("Subject") or "")

    status_map = {
        "valid": "valid",
        "notsigned": "unsigned",
        "hashmismatch": "hash_mismatch",
        "notsupportedfiletype": "unknown",
        "incompatible": "unknown",
    }
    status = status_map.get(raw_status, "invalid" if raw_status else "unknown")
    signer = _extract_signer_short_name(raw_subject)
    return AuthenticodeResult(status=status, signer=signer)


def _extract_signer_short_name(subject: str) -> str:
    """Pull the ``CN=`` / ``O=`` short name from a certificate subject string.

    Subjects look like ``CN=Insecure.Com LLC, O=Insecure.Com LLC,
    L=City, S=State, C=US``. We return the first ``CN=`` value;
    falling back to ``O=`` or the trimmed raw subject when the
    regular parsing fails.
    """
    if not subject:
        return ""
    for key in ("CN=", "O="):
        for chunk in subject.split(","):
            chunk = chunk.strip()
            if chunk.startswith(key):
                return chunk[len(key) :].strip('"')
    return subject[:64]


# ---------------------------------------------------------------------------
# Installer launch
# ---------------------------------------------------------------------------


def launch_installer(path: Path, args: Optional[list[str]] = None) -> int:
    """Launch ``path`` with UAC elevation and wait for completion.

    Spawns the installer with ``runas`` so the operator gets the
    standard Windows UAC prompt. We deliberately do **not** silently
    install Npcap — the operator must see and accept the NPSL
    license inside the Npcap installer window. Suricata follows the
    same flow for consistency.

    Args:
        path: Absolute path of the installer (.exe or .msi).
        args: Optional command-line arguments. Empty by default —
            we want the interactive UI, not a silent install.

    Returns:
        Exit code of the installer process. 0 means success on most
        Windows installers; some MSI installers return 3010 to
        signal "install ok, reboot required" — the wizard treats
        that as success.

    Raises:
        InstallerError: only if the launch itself fails (file not
            found, ShellExecuteEx returns FALSE, etc.). A non-zero
            exit code from the installer is returned, NOT raised —
            the wizard decides what to do (most likely: show the
            error to the operator and let them retry).
    """
    if not path.is_file():
        raise InstallerError(f"installer not found: {path}")

    # We use the regular subprocess interface — the operator's session
    # is interactive, so the UAC prompt will surface naturally when
    # the binary requests elevation. For .msi we route through msiexec
    # so the install dialog appears (a bare ``subprocess.run([msi])``
    # would attempt to "execute" the .msi file directly).
    suffix = path.suffix.lower()
    if suffix == ".msi":
        msiexec = win_paths.MSIEXEC if hasattr(win_paths, "MSIEXEC") else "msiexec.exe"
        cmd: list[str] = [str(msiexec), "/i", str(path)]
        if args:
            cmd.extend(args)
    else:
        cmd = [str(path)]
        if args:
            cmd.extend(args)

    logger.info("launch_installer: %s", " ".join(cmd))
    try:
        result = subprocess.run(  # nosec B603 — caller-validated absolute path
            cmd,
            shell=False,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        raise InstallerError(f"installer failed to launch: {type(exc).__name__}: {exc}") from exc

    return result.returncode


# ---------------------------------------------------------------------------
# Public installer flows (orchestrators)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallOutcome:
    """Result of an end-to-end install flow."""

    success: bool
    detail: str
    installer_path: Optional[Path] = None
    sha256: str = ""


async def install_npcap(
    download_dir: Path,
    progress_callback: Optional[ProgressCallback] = None,
    url: Optional[str] = None,
) -> InstallOutcome:
    """End-to-end Npcap install: detect → download → verify → launch.

    Idempotent: if Npcap is already installed, returns
    ``InstallOutcome(success=True, detail="already_installed")``
    without downloading anything.

    Args:
        download_dir: Directory the installer is written to. Created
            if missing. The file is left in place after the install
            so a paranoid operator can re-verify the SHA-256 manually.
        progress_callback: Optional async callback for the wizard's
            progress bar.
        url: Override of the default Npcap URL. Falls back to
            ``WARDSOAR_NPCAP_URL`` env var, then
            :data:`DEFAULT_NPCAP_URL`.

    Returns:
        :class:`InstallOutcome` describing the outcome.
    """
    if is_npcap_installed():
        return InstallOutcome(success=True, detail="already_installed")

    final_url = url or os.environ.get("WARDSOAR_NPCAP_URL") or DEFAULT_NPCAP_URL
    dest = download_dir / Path(_filename_from_url(final_url, default="npcap.exe"))

    try:
        await download_installer(final_url, dest, progress_callback=progress_callback)
    except InstallerError as exc:
        return InstallOutcome(success=False, detail=str(exc))

    sig = verify_authenticode(dest, NPCAP_EXPECTED_SIGNER)
    if sig.status != "valid":
        return InstallOutcome(
            success=False,
            detail=f"signature check failed: status={sig.status} signer={sig.signer or '-'}",
            installer_path=dest,
            sha256=sha256_of(dest),
        )
    if NPCAP_EXPECTED_SIGNER.lower() not in sig.signer.lower():
        return InstallOutcome(
            success=False,
            detail=(
                f"unexpected signer: got {sig.signer!r}, "
                f"expected substring {NPCAP_EXPECTED_SIGNER!r}"
            ),
            installer_path=dest,
            sha256=sha256_of(dest),
        )

    sha = sha256_of(dest)
    try:
        exit_code = await asyncio.to_thread(launch_installer, dest)
    except InstallerError as exc:
        return InstallOutcome(success=False, detail=str(exc), installer_path=dest, sha256=sha)

    if exit_code != 0:
        return InstallOutcome(
            success=False,
            detail=f"installer exited with code {exit_code}",
            installer_path=dest,
            sha256=sha,
        )

    if not is_npcap_installed():
        # Installer reported success but the registry key is not
        # there — likely the operator clicked "Cancel" through UAC
        # or backed out of the install dialog. Surface this clearly.
        return InstallOutcome(
            success=False,
            detail="installer exited 0 but Npcap registry key not found — operator may have cancelled",
            installer_path=dest,
            sha256=sha,
        )

    return InstallOutcome(success=True, detail="installed", installer_path=dest, sha256=sha)


async def install_suricata(
    download_dir: Path,
    progress_callback: Optional[ProgressCallback] = None,
    url: Optional[str] = None,
) -> InstallOutcome:
    """End-to-end Suricata install: detect → download → verify → launch.

    Idempotent: if Suricata is already installed (binary findable),
    returns ``InstallOutcome(success=True, detail="already_installed")``
    without downloading.

    Args:
        download_dir: Where the installer is written.
        progress_callback: Optional async callback for the wizard.
        url: Override of the default Suricata URL.

    Returns:
        :class:`InstallOutcome`.
    """
    found, _path = is_suricata_installed()
    if found:
        return InstallOutcome(success=True, detail="already_installed")

    final_url = url or os.environ.get("WARDSOAR_SURICATA_URL") or DEFAULT_SURICATA_URL
    dest = download_dir / Path(_filename_from_url(final_url, default="suricata.msi"))

    try:
        await download_installer(final_url, dest, progress_callback=progress_callback)
    except InstallerError as exc:
        return InstallOutcome(success=False, detail=str(exc))

    sig = verify_authenticode(dest, SURICATA_EXPECTED_SIGNER)
    if sig.status != "valid":
        return InstallOutcome(
            success=False,
            detail=f"signature check failed: status={sig.status} signer={sig.signer or '-'}",
            installer_path=dest,
            sha256=sha256_of(dest),
        )
    if SURICATA_EXPECTED_SIGNER.lower() not in sig.signer.lower():
        return InstallOutcome(
            success=False,
            detail=(
                f"unexpected signer: got {sig.signer!r}, "
                f"expected substring {SURICATA_EXPECTED_SIGNER!r}"
            ),
            installer_path=dest,
            sha256=sha256_of(dest),
        )

    sha = sha256_of(dest)
    try:
        exit_code = await asyncio.to_thread(launch_installer, dest)
    except InstallerError as exc:
        return InstallOutcome(success=False, detail=str(exc), installer_path=dest, sha256=sha)

    # MSI exit code 3010 is "success, reboot required". Treat as
    # success.
    if exit_code not in (0, 3010):
        return InstallOutcome(
            success=False,
            detail=f"installer exited with code {exit_code}",
            installer_path=dest,
            sha256=sha,
        )

    found, _path = is_suricata_installed()
    if not found:
        return InstallOutcome(
            success=False,
            detail="installer exited 0 but suricata.exe not found — operator may have cancelled",
            installer_path=dest,
            sha256=sha,
        )

    return InstallOutcome(success=True, detail="installed", installer_path=dest, sha256=sha)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _filename_from_url(url: str, default: str) -> str:
    """Extract a sensible filename from a download URL.

    Strips query strings + URL-decodes nothing fancy, just the last
    path segment. Falls back to ``default`` when the URL doesn't
    have a meaningful path.
    """
    # Drop query / fragment
    cleaned = re.split(r"[?#]", url, maxsplit=1)[0]
    last_segment = cleaned.rsplit("/", 1)[-1]
    if not last_segment or last_segment.endswith("/"):
        return default
    return last_segment


# Mention asyncio directly so its presence is visible to type checkers
# and a future review doesn't ask why we imported it (used only in
# install_npcap / install_suricata via ``asyncio.to_thread``).
_ = asyncio


__all__ = (
    "AuthenticodeResult",
    "DEFAULT_NPCAP_URL",
    "DEFAULT_SURICATA_URL",
    "InstallerError",
    "InstallOutcome",
    "NPCAP_EXPECTED_SIGNER",
    "NPCAP_LICENSE_URL",
    "SURICATA_EXPECTED_SIGNER",
    "SURICATA_LICENSE_URL",
    "download_installer",
    "install_npcap",
    "install_suricata",
    "is_npcap_installed",
    "is_suricata_installed",
    "launch_installer",
    "sha256_of",
    "verify_authenticode",
)
