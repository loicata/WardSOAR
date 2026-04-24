"""Map a ``svchost.exe`` PID to the Windows services it hosts.

Sysmon + ``psutil.Process(pid).name()`` happily tell you the flow
belongs to ``svchost.exe`` — which is technically correct and
practically useless: one svchost instance routinely hosts BITS,
Dnscache, Schedule, WinHttpAutoProxySvc and more, each with its own
distinct network profile. This module squeezes the last bit of
specificity out by asking Windows itself which services live inside
a given svchost PID.

Two sources are tried, in order:

1. ``tasklist /svc /fi "PID eq <pid>" /fo csv`` — stable across
   Windows 10 / 11, no admin required, parses as plain CSV.
2. The process' command line (``svchost.exe -k <group> -s <service>``).
   The ``-s`` flag appeared in Windows 10 and pins a single service
   per process on Workstation SKUs; grabbing it is a very cheap
   fallback when ``tasklist`` is blocked or times out.

Both are bounded by a 5-second timeout so a hung SCM never stalls
the forensic step. Empty list on any failure — the caller already
knows the PID and name; service enrichment is pure bonus.
"""

from __future__ import annotations

import csv
import io
import logging
import subprocess  # nosec B404 — fixed absolute paths, no operator input
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404

import psutil
from psutil import AccessDenied, NoSuchProcess

from src import win_paths

logger = logging.getLogger("ward_soar.svchost_resolver")


#: Per-call budget. ``tasklist`` normally answers in <200 ms but under
#: load we keep a generous cap so the forensic coroutine moves on.
_TASKLIST_TIMEOUT_SECONDS = 5


def _tasklist_exe() -> "Path | None":
    """Return the absolute path to tasklist.exe if we can find one.

    ``tasklist.exe`` lives in ``%SystemRoot%\\System32``; use the
    ``win_paths`` helper to stay consistent with the rest of the
    module when it eventually adds a ``TASKLIST`` constant.
    """
    system_root = win_paths.__dict__.get("_SYSTEM_ROOT")
    if not system_root:
        return None
    candidate = Path(str(system_root)) / "System32" / "tasklist.exe"
    return candidate if candidate.is_file() else None


def resolve_services_for_pid(pid: int) -> list[str]:
    """Return the list of Windows service names hosted by ``pid``.

    The lookup is best-effort and never raises. Empty list on any
    failure (tasklist missing, process gone, CSV unparseable…).

    Args:
        pid: Process ID of a running ``svchost.exe``.

    Returns:
        List of service short names (e.g. ``["BITS", "Dnscache"]``).
        Sorted and deduplicated for stable output.
    """
    if pid <= 0:
        return []

    services: set[str] = set()

    # Primary source — tasklist /svc
    services.update(_services_from_tasklist(pid))

    # Secondary source — the ``-s`` flag on the svchost command line.
    # Contributes nothing when tasklist already returned everything,
    # but it saves the attribution for ``svchost.exe -s <svc>`` even
    # when tasklist is blocked by a restricted user token.
    services.update(_services_from_cmdline(pid))

    return sorted(services)


def _services_from_tasklist(pid: int) -> list[str]:
    """Parse ``tasklist /svc`` CSV output for a single PID."""
    exe = _tasklist_exe()
    if exe is None:
        return []

    try:
        result = subprocess.run(  # nosec B603 — absolute path + hardcoded flags
            [
                str(exe),
                "/svc",
                "/fi",
                f"PID eq {int(pid)}",
                "/fo",
                "csv",
                "/nh",
            ],
            capture_output=True,
            text=True,
            timeout=_TASKLIST_TIMEOUT_SECONDS,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (FileNotFoundError, OSError, TimeoutExpired) as exc:
        logger.debug("tasklist /svc failed for PID %d: %s", pid, exc)
        return []

    if result.returncode != 0 or not result.stdout:
        return []

    # CSV shape: "Image","PID","Services"
    try:
        row = next(csv.reader(io.StringIO(result.stdout)), None)
    except csv.Error as exc:
        logger.debug("tasklist CSV parse failed: %s", exc)
        return []
    if not row or len(row) < 3:
        return []

    # The service field is either "N/A" for a non-service host (plain
    # user process) or a comma-separated list. tasklist emits either
    # ``BITS,Dnscache`` or ``BITS, Dnscache`` depending on locale.
    raw = row[2].strip()
    if not raw or raw.upper() == "N/A":
        return []
    return [svc.strip() for svc in raw.split(",") if svc.strip()]


def _services_from_cmdline(pid: int) -> list[str]:
    """Extract the ``-s <service>`` argument from a svchost command line.

    Windows 10+ launches most service-hosted svchost instances with
    ``-s <ServiceName>`` which pins the service to the process. We
    grep the cmdline via psutil (already imported, no extra
    dependency). Gracefully returns an empty list when the process
    is gone, access is denied, or the argument is absent.
    """
    try:
        proc = psutil.Process(pid)
        cmdline = proc.cmdline()
    except (NoSuchProcess, AccessDenied, OSError):
        return []

    services: list[str] = []
    tokens = [token for token in cmdline if isinstance(token, str)]
    # Pattern: ["...svchost.exe", "-k", "group", "-s", "ServiceName", ...]
    # Iterate manually so we tolerate additional flags in-between.
    i = 0
    while i < len(tokens) - 1:
        if tokens[i].lower() == "-s" and tokens[i + 1]:
            services.append(tokens[i + 1])
            i += 2
            continue
        i += 1
    return services


__all__: tuple[str, ...] = ("resolve_services_for_pid",)
