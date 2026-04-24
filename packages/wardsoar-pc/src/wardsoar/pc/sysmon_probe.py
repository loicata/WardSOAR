"""Detect whether Microsoft Sysinternals Sysmon is running on this PC.

Sysmon is the difference between "we think Teams made that connection"
and "we know Teams made that connection": with Event ID 3 enabled, the
Windows Event Log stores the Image + PID + ProcessGuid of every new
TCP/UDP connection, and :mod:`src.forensics` replays those events to
attribute Suricata alerts to local processes even after the socket is
closed.

This module exposes a lightweight probe that the UI and the
Bootstrap checklist use to surface the installation status of Sysmon:

* :func:`probe_sysmon` — single snapshot call, returns a
  :class:`SysmonStatus`. Non-blocking; 5 s guard.
* :func:`recommended_install_snippet` — the two-liner PowerShell the
  operator can copy-paste to install Sysmon with a sensible config.

Fail-open: anything unexpected (missing ``sc.exe``, timeout, denied
access) degrades to ``installed=False`` rather than raising. The
health check never blocks the pipeline.
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 — invoked with absolute paths, hardcoded args
from dataclasses import dataclass
from pathlib import Path

from wardsoar.pc import win_paths

logger = logging.getLogger("ward_soar.sysmon_probe")


# Sysmon registers its service under one of two names depending on the
# installer bitness. ``Sysmon64`` is the modern default on Windows 10/11
# x64; ``Sysmon`` is kept for legacy x86 hosts. We probe both.
_SERVICE_NAMES: tuple[str, ...] = ("Sysmon64", "Sysmon")

# ``sc query`` output we care about. The line we look for is
# ``        STATE              : 4  RUNNING`` — any other state means
# installed-but-not-running, which is just as useless as "not installed".
_RUNNING_TOKEN = "RUNNING"

# How long we give ``sc query`` before we give up. The command is
# synchronous and a hung Service Control Manager would otherwise stall
# the WardSOAR startup health check.
_SC_QUERY_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class SysmonStatus:
    """Snapshot of Sysmon's availability at probe time.

    Attributes:
        installed: ``True`` when a Sysmon service is registered.
            This includes installed-but-stopped; check ``running``
            to distinguish.
        running: ``True`` when the service is in STATE=RUNNING.
            Only a running Sysmon actually writes Event ID 3.
        service_name: Which of the two registered names matched
            (``"Sysmon64"`` or ``"Sysmon"``), or ``""`` when nothing
            is installed.
        error: Human-readable message when the probe could not run
            at all (unexpected environment, not a diagnosis of
            Sysmon). Empty string on success.
    """

    installed: bool = False
    running: bool = False
    service_name: str = ""
    error: str = ""

    @property
    def healthy(self) -> bool:
        """True when forensic process attribution will work reliably."""
        return self.installed and self.running


def probe_sysmon() -> SysmonStatus:
    """Query the Service Control Manager for Sysmon's state.

    Runs ``sc query <name>`` for each candidate service name. The
    call is sandboxed with a 5 s timeout and ``CREATE_NO_WINDOW``
    so no console flashes on the desktop at startup.
    """
    sc_path = getattr(win_paths, "SC", None)
    if not sc_path or not Path(str(sc_path)).is_file():
        # Non-Windows host, or Sc.exe somehow missing. The probe
        # itself failed — report error=True, leave installed=False.
        return SysmonStatus(error="sc.exe not available on this host")

    for name in _SERVICE_NAMES:
        try:
            result = subprocess.run(  # nosec B603 — absolute path + hardcoded args
                [str(sc_path), "query", name],
                capture_output=True,
                text=True,
                timeout=_SC_QUERY_TIMEOUT_SECONDS,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            logger.debug("sc query %s failed: %s", name, exc)
            continue

        if result.returncode != 0:
            # Service not registered — try the next candidate.
            continue

        running = _RUNNING_TOKEN in (result.stdout or "").upper()
        return SysmonStatus(
            installed=True,
            running=running,
            service_name=name,
        )

    return SysmonStatus()


def recommended_install_snippet() -> str:
    """Copy-pasteable PowerShell snippet rendered in the UI tooltip."""
    return (
        "# Elevated PowerShell\n"
        "Invoke-WebRequest "
        "https://download.sysinternals.com/files/Sysmon.zip "
        "-OutFile Sysmon.zip\n"
        "Expand-Archive Sysmon.zip\n"
        "Invoke-WebRequest "
        "https://raw.githubusercontent.com/SwiftOnSecurity/"
        "sysmon-config/master/sysmonconfig-export.xml "
        "-OutFile sysmonconfig-export.xml\n"
        ".\\Sysmon\\Sysmon64.exe -accepteula "
        "-i .\\sysmonconfig-export.xml"
    )
