"""Monitor Suricata EVE JSON file for new alerts.

Supports two modes:
- "file": tail-based polling of a local EVE JSON file (default)
- "ssh": SSH streaming from pfSense via asyncssh tail -f

New lines appended by Suricata are parsed and valid alerts
are forwarded via callback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from src.models import SuricataAlert, SuricataAlertSeverity

logger = logging.getLogger("ward_soar.watcher")


class EveJsonWatcher:
    """Watch a Suricata EVE JSON file and emit parsed alerts.

    Monitors the file for new lines (appended by Suricata),
    parses alert events, and calls the registered callback.

    Args:
        eve_path: Path to the EVE JSON file.
        callback: Function to call with each new SuricataAlert.
        min_severity: Minimum severity level to process (1=high, 3=low).
        poll_interval: Seconds between file checks.
    """

    def __init__(
        self,
        eve_path: str,
        callback: Callable[[SuricataAlert], None],
        min_severity: int = 3,
        poll_interval: float = 2.0,
    ) -> None:
        self._eve_path = Path(eve_path)
        self._callback = callback
        self._min_severity = min_severity
        self._poll_interval = poll_interval
        self._last_position: int = 0
        self._running: bool = False

    def start(self) -> None:
        """Start watching the EVE JSON file.

        Seeks to end of file on first start, then monitors for new lines.

        Raises:
            FileNotFoundError: If EVE JSON file does not exist.
        """
        if not self._eve_path.exists():
            raise FileNotFoundError(f"EVE JSON file not found: {self._eve_path}")

        # Seek to end of file (skip existing alerts on first start)
        self._last_position = self._eve_path.stat().st_size
        self._running = True

        logger.info("Watcher started, monitoring: %s", self._eve_path)

        while self._running:
            self._process_new_lines()
            time.sleep(self._poll_interval)

    def stop(self) -> None:
        """Stop watching the EVE JSON file."""
        self._running = False

    def _process_new_lines(self) -> None:
        """Read and process any new lines since last position.

        Fail-safe: malformed lines are skipped with a warning.
        """
        try:
            with open(self._eve_path, "r", encoding="utf-8") as f:
                f.seek(self._last_position)
                new_data = f.read()
                self._last_position = f.tell()
        except OSError:
            logger.warning("Failed to read EVE JSON file: %s", self._eve_path)
            return

        if not new_data:
            return

        for line in new_data.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            self._process_line(stripped)

    def _process_line(self, line: str) -> None:
        """Parse a single EVE JSON line and dispatch if valid alert.

        Args:
            line: A single line from the EVE JSON file.
        """
        try:
            raw_event: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON line in EVE file")
            return

        alert = self.parse_eve_alert(raw_event)
        if alert is None:
            return

        # Severity filter: lower number = higher severity
        if alert.alert_severity.value > self._min_severity:
            return

        self._callback(alert)

    @staticmethod
    def parse_eve_alert(raw_event: dict[str, Any]) -> Optional[SuricataAlert]:
        """Parse a raw EVE JSON event into a SuricataAlert.

        Args:
            raw_event: Parsed JSON dict from EVE log line.

        Returns:
            SuricataAlert if event is a valid alert, None otherwise.
        """
        if raw_event.get("event_type") != "alert":
            return None

        alert_data = raw_event.get("alert")
        if not isinstance(alert_data, dict):
            return None

        try:
            timestamp = datetime.fromisoformat(raw_event["timestamp"])
            severity_val = int(alert_data["severity"])
            severity = SuricataAlertSeverity(severity_val)

            return SuricataAlert(
                timestamp=timestamp,
                src_ip=raw_event["src_ip"],
                src_port=int(raw_event["src_port"]),
                dest_ip=raw_event["dest_ip"],
                dest_port=int(raw_event["dest_port"]),
                proto=raw_event["proto"],
                alert_signature=alert_data["signature"],
                alert_signature_id=int(alert_data["signature_id"]),
                alert_severity=severity,
                alert_category=alert_data.get("category", ""),
                alert_action=alert_data.get("action", "allowed"),
                flow_id=raw_event.get("flow_id"),
                raw_event=raw_event,
            )
        except (KeyError, ValueError, TypeError):
            logger.debug("Failed to parse EVE alert: missing or invalid fields")
            return None


# SSH reconnection backoff limits
_SSH_MIN_RETRY_DELAY = 2
_SSH_MAX_RETRY_DELAY = 60


class SshEveWatcher:
    """Stream EVE JSON alerts from pfSense via SSH tail -f.

    Connects to pfSense via asyncssh and streams new EVE JSON lines
    in real-time. Automatically reconnects with exponential backoff.

    Args:
        pfsense_ip: IP address of pfSense firewall.
        ssh_user: SSH username on pfSense.
        ssh_key_path: Path to SSH private key file.
        ssh_port: SSH port on pfSense.
        remote_eve_path: Path to EVE JSON file on pfSense.
        callback: Async function to call with each new SuricataAlert.
        min_severity: Minimum severity level to process (1=high, 3=low).
        local_addr: Local IP to bind to (bypasses VPN). Empty for auto.
    """

    def __init__(
        self,
        pfsense_ip: str,
        ssh_user: str,
        ssh_key_path: str,
        ssh_port: int,
        remote_eve_path: str,
        callback: Callable[[SuricataAlert], Any],
        min_severity: int = 3,
        local_addr: str = "",
    ) -> None:
        self._pfsense_ip = pfsense_ip
        self._ssh_user = ssh_user
        self._ssh_key_path = ssh_key_path
        self._ssh_port = ssh_port
        self._remote_eve_path = remote_eve_path
        self._callback = callback
        self._min_severity = min_severity
        self._local_addr = local_addr
        self._running = False
        self._retry_delay = _SSH_MIN_RETRY_DELAY

    async def start(self) -> None:
        """Start SSH streaming with auto-reconnect.

        Runs until stop() is called. Reconnects with exponential
        backoff on connection failures.
        """
        self._running = True
        self._retry_delay = _SSH_MIN_RETRY_DELAY

        logger.info(
            "SSH watcher starting: %s@%s:%d",
            self._ssh_user,
            self._pfsense_ip,
            self._ssh_port,
        )

        while self._running:
            try:
                await self._stream_loop()
            except Exception as exc:
                logger.error("SSH stream error: %s", exc)

            if not self._running:
                break

            logger.info("SSH reconnecting in %d seconds...", self._retry_delay)
            await asyncio.sleep(self._retry_delay)
            self._retry_delay = min(self._retry_delay * 2, _SSH_MAX_RETRY_DELAY)

        logger.info("SSH watcher stopped")

    async def _stream_loop(self) -> None:
        """Connect to pfSense and stream EVE JSON lines."""
        import asyncssh

        connect_kwargs: dict[str, Any] = {
            "host": self._pfsense_ip,
            "port": self._ssh_port,
            "username": self._ssh_user,
            "client_keys": [self._ssh_key_path],
            "known_hosts": None,
        }

        if self._local_addr:
            connect_kwargs["local_addr"] = (self._local_addr, 0)

        async with asyncssh.connect(**connect_kwargs) as conn:
            logger.info("SSH connected to %s", self._pfsense_ip)
            self._retry_delay = _SSH_MIN_RETRY_DELAY

            cmd = f"tail -n 0 -f {self._remote_eve_path}"
            async with conn.create_process(cmd) as process:
                if process.stdout is None:
                    logger.error("SSH process stdout is None")
                    return

                async for line in process.stdout:
                    if not self._running:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    self._process_line(stripped)

    def _process_line(self, line: str) -> None:
        """Parse a single EVE JSON line and dispatch if valid alert.

        Args:
            line: A single line from the EVE JSON stream.
        """
        try:
            raw_event: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON line from SSH stream")
            return

        alert = EveJsonWatcher.parse_eve_alert(raw_event)
        if alert is None:
            return

        if alert.alert_severity.value > self._min_severity:
            return

        self._callback(alert)

    def stop(self) -> None:
        """Stop the SSH watcher."""
        self._running = False


def create_watcher(
    config: dict[str, Any],
    callback: Callable[[SuricataAlert], Any],
) -> EveJsonWatcher | SshEveWatcher:
    """Factory function to create the appropriate watcher based on config.

    Args:
        config: Watcher configuration dict from config.yaml.
        callback: Function to call with each new SuricataAlert.

    Returns:
        EveJsonWatcher for file mode, SshEveWatcher for SSH mode.
    """
    mode = config.get("mode", "file")
    min_severity = config.get("min_severity", 3)

    if mode == "ssh":
        ssh_cfg = config.get("ssh", {})
        network_cfg = config.get("_network", {})
        responder_cfg = config.get("_responder", {})
        pfsense_cfg = responder_cfg.get("pfsense", {})

        return SshEveWatcher(
            pfsense_ip=network_cfg.get("pfsense_ip", "192.168.2.1"),
            ssh_user=pfsense_cfg.get("ssh_user", "admin"),
            ssh_key_path=pfsense_cfg.get("ssh_key_path", ""),
            ssh_port=int(pfsense_cfg.get("ssh_port", 22)),
            remote_eve_path=ssh_cfg.get("remote_eve_path", "/var/log/suricata/eve.json"),
            callback=callback,
            min_severity=min_severity,
            local_addr=network_cfg.get("pc_ip", ""),
        )

    return EveJsonWatcher(
        eve_path=config.get("eve_json_path", ""),
        callback=callback,
        min_severity=min_severity,
        poll_interval=float(config.get("poll_interval_seconds", 2.0)),
    )
