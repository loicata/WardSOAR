"""Elevated launcher for the bundled Sysmon install script.

UI glue: the "Install Sysmon" button in the Netgate tab calls
:func:`launch_install_script`, which spawns an unelevated
``powershell.exe`` that in turn runs ``Start-Process -Verb RunAs``
on :mod:`scripts.install-sysmon.ps1`. Windows displays the UAC
prompt, and on accept the elevated PowerShell downloads and
installs Sysmon. If the operator cancels UAC, the outer process
exits non-zero and we surface the refusal in the UI.

Design rationale:
    * We do **not** bundle the Sysmon binary itself — Microsoft's
      redistribution terms for Sysinternals are permissive but the
      signed binary is safer fetched live from download.sysinternals.com.
    * The script is bundled with WardSOAR so operators never run
      code we did not ship: the install is auditable in the MSI.
    * Launch is fire-and-forget from WardSOAR's POV. The UI
      refreshes its Sysmon banner by re-running
      :func:`sysmon_probe.probe_sysmon` after the child exits.
"""

from __future__ import annotations

import logging
import os
import subprocess  # nosec B404 — invoked with absolute paths, operator-triggered
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from wardsoar.pc import win_paths

logger = logging.getLogger("ward_soar.sysmon_installer")


@dataclass(frozen=True)
class InstallLaunchResult:
    """Outcome of a launch attempt.

    Attributes:
        started: True when we successfully spawned the parent
            PowerShell. False when we could not even start (missing
            PowerShell, script not found…).
        script_path: Absolute path of the install script we aimed
            to run. Useful for the UI error message.
        error: Human-readable failure detail, empty on success.
    """

    started: bool
    script_path: str
    error: str = ""


def find_install_script() -> Optional[Path]:
    """Locate ``install-sysmon.ps1`` in either the dev tree or the MSI bundle.

    Order of lookup matches :func:`ui.views.netgate.NetgateView._load_guide_markdown`:
        1. ``<repo_root>/scripts/install-sysmon.ps1`` for dev runs.
        2. ``get_bundle_dir()/scripts/install-sysmon.ps1`` for the frozen build.
    """
    candidates: list[Path] = []
    # ``get_data_dir()`` walks up to the monorepo root (the directory
    # that owns ``packages/``) or, failing that, the legacy layout
    # root — either way the repo's ``scripts/`` lives alongside it.
    # Before 2026-04-24 this used ``Path(__file__).parent.parent``
    # which pointed at ``src/`` in the old layout; the monorepo move
    # shifted the module to ``packages/wardsoar-pc/src/wardsoar/pc/``
    # so the old relative walk landed on ``.../wardsoar/`` and missed
    # the script.
    from wardsoar.core.config import get_bundle_dir, get_data_dir

    repo_script = get_data_dir() / "scripts" / "install-sysmon.ps1"
    candidates.append(repo_script)

    try:
        candidates.append(get_bundle_dir() / "scripts" / "install-sysmon.ps1")
    except Exception:  # noqa: BLE001 — bundle dir lookup is optional
        pass

    for path in candidates:
        if path.is_file():
            return path
    return None


def launch_install_script() -> InstallLaunchResult:
    """Spawn an elevated PowerShell that runs the Sysmon install script.

    The call flow is:
        WardSOAR (non-admin)
          → powershell.exe -Command "Start-Process powershell -Verb RunAs
              -ArgumentList ... install-sysmon.ps1"
          → UAC prompt
          → elevated powershell runs the script, console stays open
          → script completes, operator closes the window.

    This function returns as soon as the outer PowerShell is
    spawned — it does **not** wait for the UAC decision or for the
    install to finish. The UI is expected to poll
    :func:`src.sysmon_probe.probe_sysmon` to detect completion.

    Returns:
        :class:`InstallLaunchResult`.
    """
    ps_path = getattr(win_paths, "POWERSHELL", None)
    if not ps_path or not Path(str(ps_path)).is_file():
        return InstallLaunchResult(
            started=False,
            script_path="",
            error="PowerShell not found — cannot launch the Sysmon installer",
        )

    script_path = find_install_script()
    if script_path is None:
        return InstallLaunchResult(
            started=False,
            script_path="",
            error=(
                "install-sysmon.ps1 was not shipped with this WardSOAR install. "
                "Install Sysmon manually — see docs/bootstrap-netgate.md step 1."
            ),
        )

    # The inner script is passed to a fresh elevated PowerShell via
    # -Verb RunAs. The command composition is verbose because Windows
    # needs the file path escaped and quoted twice: once for the outer
    # shell and once for the ArgumentList that Start-Process forwards.
    inner_args = f"'-NoProfile -ExecutionPolicy Bypass -NoExit " f'-File ""{script_path}""\''
    outer_command = f"Start-Process -FilePath powershell -Verb RunAs -ArgumentList {inner_args}"

    try:
        subprocess.Popen(  # nosec B603 — absolute path + no operator input
            [
                str(ps_path),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                outer_command,
            ],
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            close_fds=False,
            # Detach stdout/stderr so WardSOAR does not hold a pipe
            # into the elevated window — the user will interact with
            # it directly.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.exception("Failed to launch install-sysmon.ps1")
        return InstallLaunchResult(
            started=False,
            script_path=str(script_path),
            error=f"Could not start the installer: {exc}",
        )

    logger.info("Sysmon installer launched — elevated window spawned via UAC")
    return InstallLaunchResult(started=True, script_path=str(script_path))


__all__ = (
    "InstallLaunchResult",
    "find_install_script",
    "launch_install_script",
)


# Re-export the install script location so the UI can show it in the
# error message / "view in Explorer" style action.
def describe_script_location() -> str:
    """Return a user-facing path to the install script (or a hint)."""
    path = find_install_script()
    if path is None:
        return "install-sysmon.ps1 not found in this WardSOAR build"
    # Normalise to the OS separator so the UI shows a clean Windows path.
    return str(path).replace("/", os.sep)
