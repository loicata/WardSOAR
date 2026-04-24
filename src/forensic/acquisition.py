"""Volatile evidence capture (RFC 3227 priority 1 & 2).

Each method returns JSON-serialisable data describing one category
of volatile state. The orchestrator is responsible for persisting the
data to disk via :class:`ProtectedEvidenceStorage`.

Collected artefacts:
    - ``capture_process_list``  → all processes with cmdline, cwd, exe.
    - ``capture_network_state`` → live connections via psutil.
    - ``capture_loaded_dlls``   → DLLs loaded by target PIDs.
    - ``capture_dns_cache``     → ``Get-DnsClientCache`` via PowerShell.
    - ``capture_arp_cache``     → ``arp -a``.
    - ``capture_routing_table`` → ``route print``.

Fail-safe: each method catches and logs per-entry errors so a missing
permission or dead process never aborts the full acquisition.
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 — required for PowerShell/arp/route queries; hardcoded args
from datetime import datetime, timezone
from subprocess import TimeoutExpired  # nosec B404 — exception class only
from typing import Any

import psutil
from psutil import AccessDenied, NoSuchProcess, ZombieProcess

from src import win_paths

logger = logging.getLogger("ward_soar.forensic.acquisition")


DEFAULT_SUBPROCESS_TIMEOUT = 15


def _utcnow_iso() -> str:
    """Return current UTC time in ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VolatileAcquirer:
    """Snapshot live system state as JSON-serialisable dicts.

    Holds no configuration — methods are independent so callers can
    skip any of them without side effects.
    """

    # ------------------------------------------------------------------
    # Process list
    # ------------------------------------------------------------------

    def capture_process_list(self) -> dict[str, Any]:
        """Full process table with metadata useful to an investigator.

        Returns:
            Dict with ``captured_at_utc`` + ``processes`` list. Each
            process entry has a stable set of keys; missing fields are
            represented as None rather than omitted.
        """
        items: list[dict[str, Any]] = []
        for proc in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "exe",
                "cmdline",
                "username",
                "status",
                "create_time",
                "num_threads",
                "cwd",
            ]
        ):
            try:
                info = proc.info
            except (NoSuchProcess, AccessDenied, ZombieProcess):
                continue
            # Flatten cmdline — easier to grep than a JSON array.
            cmdline = info.get("cmdline") or []
            info["cmdline"] = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            items.append(info)

        return {
            "captured_at_utc": _utcnow_iso(),
            "process_count": len(items),
            "processes": items,
        }

    # ------------------------------------------------------------------
    # Network state
    # ------------------------------------------------------------------

    def capture_network_state(self) -> dict[str, Any]:
        """Active connections (psutil.net_connections).

        Returns:
            Dict with ``connections`` list — each entry covers family,
            type, laddr, raddr, status, pid.
        """
        items: list[dict[str, Any]] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (PermissionError, OSError) as exc:
            logger.warning("net_connections failed: %s", exc)
            connections = []

        for conn in connections:
            laddr = (
                {"ip": conn.laddr.ip, "port": conn.laddr.port}
                if conn.laddr and hasattr(conn.laddr, "ip")
                else None
            )
            raddr = (
                {"ip": conn.raddr.ip, "port": conn.raddr.port}
                if conn.raddr and hasattr(conn.raddr, "ip")
                else None
            )
            items.append(
                {
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status,
                    "pid": conn.pid,
                }
            )
        return {
            "captured_at_utc": _utcnow_iso(),
            "connection_count": len(items),
            "connections": items,
        }

    # ------------------------------------------------------------------
    # Loaded DLLs per target PID
    # ------------------------------------------------------------------

    def capture_loaded_dlls(self, pids: list[int]) -> dict[str, Any]:
        """Module list for every provided PID.

        Args:
            pids: Target processes (usually those correlated with the alert).

        Returns:
            Dict with ``pid_modules`` — per-PID list of loaded module paths.
        """
        per_pid: dict[str, list[str]] = {}
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                modules = [m.path for m in proc.memory_maps(grouped=True)]
            except (NoSuchProcess, AccessDenied, ZombieProcess, OSError) as exc:
                logger.debug("memory_maps failed for PID %d: %s", pid, exc)
                modules = []
            per_pid[str(pid)] = modules
        return {
            "captured_at_utc": _utcnow_iso(),
            "pid_modules": per_pid,
        }

    # ------------------------------------------------------------------
    # Network utilities via subprocess
    # ------------------------------------------------------------------

    def capture_dns_cache(self) -> dict[str, Any]:
        """Windows resolver cache via PowerShell Get-DnsClientCache."""
        stdout = self._run_powershell("Get-DnsClientCache | Format-List")
        return {
            "captured_at_utc": _utcnow_iso(),
            "source": "powershell:Get-DnsClientCache",
            "raw": stdout,
        }

    def capture_arp_cache(self) -> dict[str, Any]:
        """ARP table via ``arp -a`` (absolute path, no PATH-injection)."""
        stdout = self._run_plain([win_paths.ARP, "-a"])
        return {
            "captured_at_utc": _utcnow_iso(),
            "source": "arp.exe",
            "raw": stdout,
        }

    def capture_routing_table(self) -> dict[str, Any]:
        """Routing table via ``route print``.

        ``route.exe`` lives in System32; we build the path from win_paths.
        """
        import os

        route_exe = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "route.exe"
        )
        stdout = self._run_plain([route_exe, "print"])
        return {
            "captured_at_utc": _utcnow_iso(),
            "source": "route.exe",
            "raw": stdout,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_powershell(command: str) -> str:
        """Run a PowerShell one-liner with an absolute path.

        Returns the captured stdout (empty string on failure).
        """
        try:
            result = subprocess.run(  # nosec B603 — absolute path, caller-controlled args
                [win_paths.POWERSHELL, "-Command", command],
                capture_output=True,
                text=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
        except (FileNotFoundError, OSError, TimeoutExpired) as exc:
            logger.warning("PowerShell command failed: %s", exc)
            return ""
        if result.returncode != 0:
            logger.debug(
                "PowerShell rc=%d stderr=%s",
                result.returncode,
                (result.stderr or "").strip()[:200],
            )
        return str(result.stdout or "")

    @staticmethod
    def _run_plain(argv: list[str]) -> str:
        """Run a command by absolute path with a strict timeout."""
        try:
            result = subprocess.run(  # nosec B603 — absolute path, hardcoded args
                argv,
                capture_output=True,
                text=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
        except (FileNotFoundError, OSError, TimeoutExpired) as exc:
            logger.warning("Subprocess failed (%s): %s", argv[0], exc)
            return ""
        return str(result.stdout or "")
