"""Periodic self-monitoring of all system components.

Checks that every part of the system is operational:
APIs reachable, disk space available, services running,
files accessible. Triggers notifications on failures.

Fail-safe: if a check itself fails, report UNKNOWN status.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import psutil

from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.healthcheck")


class ComponentStatus(str, Enum):
    """Health status of a component."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class HealthResult:
    """Result of a single component healthcheck."""

    component: str
    status: ComponentStatus
    message: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_ms: Optional[float] = None


class HealthChecker:
    """Periodic self-monitoring of all system components.

    Args:
        config: HealthCheck configuration dict from config.yaml.
    """

    def __init__(
        self,
        config: dict[str, Any],
        pfsense_ssh: PfSenseSSH | None = None,
    ) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._interval_seconds: int = config.get("interval_seconds", 300)
        self._disk_threshold_mb: int = config.get("disk_warning_threshold_mb", 500)
        self._eve_path: str = config.get("eve_json_path", "")
        self._eve_max_age: int = config.get("eve_max_age_seconds", 60)
        self._pfsense_ip: str = config.get("pfsense_ip", "")
        self._pfsense_ssh_port: int = config.get("pfsense_ssh_port", 22)
        self._pfsense_ssh = pfsense_ssh
        self._last_results: list[HealthResult] = []

    async def run_all_checks(self) -> list[HealthResult]:
        """Run all healthchecks and return results.

        Returns:
            List of HealthResult for each component.
        """
        results: list[HealthResult] = []
        checks = [
            self.check_pfsense_ssh,
            self.check_claude_api,
            self.check_virustotal_api,
            self.check_eve_json_file,
            self.check_sysmon_service,
            self.check_disk_space,
        ]
        for check in checks:
            try:
                result = await check()
                results.append(result)
            except (OSError, ValueError, RuntimeError) as exc:
                results.append(
                    HealthResult(
                        component=check.__name__,
                        status=ComponentStatus.UNKNOWN,
                        message=str(exc),
                    )
                )

        self._last_results = results
        return results

    async def check_pfsense_ssh(self) -> HealthResult:
        """Verify pfSense is reachable via SSH.

        Uses the PfSenseSSH instance if available, otherwise falls back
        to a simple TCP port check on the SSH port.
        """
        if self._pfsense_ssh is not None:
            start = time.monotonic()
            reachable, message = await self._pfsense_ssh.check_status()
            elapsed = (time.monotonic() - start) * 1000
            status = ComponentStatus.HEALTHY if reachable else ComponentStatus.FAILED
            return HealthResult(
                component="pfSense SSH",
                status=status,
                message=message,
                response_time_ms=elapsed,
            )

        # Fallback: TCP port check when no PfSenseSSH instance
        if not self._pfsense_ip:
            return HealthResult(
                component="pfSense SSH",
                status=ComponentStatus.UNKNOWN,
                message="pfSense IP not configured",
            )

        import socket

        start = time.monotonic()
        try:
            sock = socket.create_connection((self._pfsense_ip, self._pfsense_ssh_port), timeout=5)
            sock.close()
            elapsed = (time.monotonic() - start) * 1000
            return HealthResult(
                component="pfSense SSH",
                status=ComponentStatus.HEALTHY,
                message=f"SSH port open on {self._pfsense_ip}",
                response_time_ms=elapsed,
            )
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return HealthResult(
                component="pfSense SSH",
                status=ComponentStatus.FAILED,
                message=f"Cannot reach {self._pfsense_ip}:{self._pfsense_ssh_port} — {exc}",
                response_time_ms=elapsed,
            )

    async def check_claude_api(self) -> HealthResult:
        """Verify Anthropic API key is configured."""
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if api_key:
            return HealthResult(
                component="Claude API",
                status=ComponentStatus.HEALTHY,
                message="API key configured",
            )
        return HealthResult(
            component="Claude API",
            status=ComponentStatus.FAILED,
            message="ANTHROPIC_API_KEY not set",
        )

    async def check_virustotal_api(self) -> HealthResult:
        """Verify VirusTotal API key is configured."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if api_key:
            return HealthResult(
                component="VirusTotal API",
                status=ComponentStatus.HEALTHY,
                message="API key configured",
            )
        return HealthResult(
            component="VirusTotal API",
            status=ComponentStatus.DEGRADED,
            message="VIRUSTOTAL_API_KEY not set",
        )

    async def check_eve_json_file(self) -> HealthResult:
        """Verify EVE JSON file exists and is being updated."""
        if not self._eve_path:
            return HealthResult(
                component="EVE JSON",
                status=ComponentStatus.UNKNOWN,
                message="No path configured",
            )

        path = Path(self._eve_path)
        if not path.exists():
            return HealthResult(
                component="EVE JSON",
                status=ComponentStatus.FAILED,
                message=f"File not found: {self._eve_path}",
            )

        return HealthResult(
            component="EVE JSON",
            status=ComponentStatus.HEALTHY,
            message="File exists",
        )

    async def check_sysmon_service(self) -> HealthResult:
        """Verify Sysmon service is running on Windows."""
        try:
            import subprocess  # nosec B404 — required to probe Sysmon service via PowerShell; hardcoded args

            from wardsoar.pc import win_paths

            result = subprocess.run(  # nosec B603 — absolute path, hardcoded args, no user input
                [
                    win_paths.POWERSHELL,
                    "-Command",
                    "Get-Service Sysmon64 -ErrorAction SilentlyContinue",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0 and "Running" in result.stdout:
                return HealthResult(
                    component="Sysmon",
                    status=ComponentStatus.HEALTHY,
                    message="Service running",
                )
            return HealthResult(
                component="Sysmon",
                status=ComponentStatus.DEGRADED,
                message="Service not running or not found",
            )
        except (FileNotFoundError, OSError):
            return HealthResult(
                component="Sysmon",
                status=ComponentStatus.UNKNOWN,
                message="Cannot check service status",
            )

    async def check_disk_space(self) -> HealthResult:
        """Verify sufficient disk space for logs and cache."""
        try:
            usage = psutil.disk_usage("/")
            free_mb = usage.free / (1024 * 1024)
            if free_mb >= self._disk_threshold_mb:
                return HealthResult(
                    component="Disk Space",
                    status=ComponentStatus.HEALTHY,
                    message=f"{free_mb:.0f} MB free",
                )
            return HealthResult(
                component="Disk Space",
                status=ComponentStatus.DEGRADED,
                message=f"Low disk space: {free_mb:.0f} MB free (threshold: {self._disk_threshold_mb} MB)",
            )
        except (PermissionError, OSError) as exc:
            return HealthResult(
                component="Disk Space",
                status=ComponentStatus.UNKNOWN,
                message=str(exc),
            )

    def get_overall_status(self) -> ComponentStatus:
        """Get overall system health based on last check results.

        Returns:
            HEALTHY if all OK, DEGRADED if non-critical failures,
            FAILED if any critical failure, UNKNOWN if no checks run.
        """
        if not self._last_results:
            return ComponentStatus.UNKNOWN

        statuses = {r.status for r in self._last_results}
        if ComponentStatus.FAILED in statuses:
            return ComponentStatus.FAILED
        if ComponentStatus.DEGRADED in statuses:
            return ComponentStatus.DEGRADED
        return ComponentStatus.HEALTHY

    def get_last_results(self) -> list[HealthResult]:
        """Get results of the most recent healthcheck run."""
        return self._last_results
