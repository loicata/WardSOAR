"""SSH-based EVE JSON streaming from pfSense.

Connects to pfSense via SSH and streams new EVE JSON lines
in real-time using tail -f. Binds to the LAN interface to
bypass VPN tunnels that would otherwise block local SSH traffic.

Uses ``loop.run_forever()`` with async tasks so the SSH stream,
reconnection backoff, and cleanup all run without blocking.

Fail-safe: on any SSH error, logs the error and retries with
exponential backoff. Never crashes the application.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from PySide6.QtCore import QThread, Signal

logger = logging.getLogger("ward_soar.ssh_streamer")

# Reconnection backoff limits
MIN_RETRY_DELAY = 2
MAX_RETRY_DELAY = 60


class SshStreamer(QThread):
    """Stream EVE JSON lines from pfSense via SSH tail -f.

    Emits each received line as a Qt signal for processing
    by the EngineWorker.

    Signals:
        line_received: Emitted with each EVE JSON line string.
        status_changed: Emitted with (status, details) tuple.
    """

    line_received = Signal(str)
    status_changed = Signal(str, str)

    def __init__(
        self,
        pfsense_ip: str,
        ssh_user: str,
        ssh_key_path: str,
        ssh_port: int,
        remote_eve_path: str,
        local_addr: str = "",
        parent: Optional[Any] = None,
    ) -> None:
        """Initialize the SSH streamer.

        Args:
            pfsense_ip: IP address of pfSense firewall.
            ssh_user: SSH username on pfSense.
            ssh_key_path: Path to SSH private key file.
            ssh_port: SSH port on pfSense.
            remote_eve_path: Path to EVE JSON file on pfSense.
            local_addr: Local IP to bind to (bypasses VPN). Empty for auto.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._pfsense_ip = pfsense_ip
        self._ssh_user = ssh_user
        self._ssh_key_path = ssh_key_path
        self._ssh_port = ssh_port
        self._remote_eve_path = remote_eve_path
        self._local_addr = local_addr
        self._running = False
        self._retry_delay = MIN_RETRY_DELAY
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def run(self) -> None:
        """Thread entry — start the async event loop with run_forever()."""
        self._running = True
        self._retry_delay = MIN_RETRY_DELAY

        logger.info(
            "SSH streamer starting: %s@%s:%d",
            self._ssh_user,
            self._pfsense_ip,
            self._ssh_port,
        )
        self.status_changed.emit("Connecting", f"SSH to {self._pfsense_ip}")

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self._loop.create_task(self._stream_with_reconnect())

        try:
            self._loop.run_forever()
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

        self.status_changed.emit("Stopped", "SSH streamer stopped")
        logger.info("SSH streamer stopped")

    async def _stream_with_reconnect(self) -> None:
        """Stream loop with auto-reconnect and exponential backoff."""
        while self._running:
            try:
                await self._stream_loop()
            except Exception as exc:
                logger.error("SSH stream error: %s", exc)
                self.status_changed.emit("Disconnected", str(exc))

            if not self._running:
                break

            # Exponential backoff retry — non-blocking
            logger.info("Reconnecting in %d seconds...", self._retry_delay)
            self.status_changed.emit("Reconnecting", f"in {self._retry_delay}s")
            await asyncio.sleep(self._retry_delay)
            self._retry_delay = min(self._retry_delay * 2, MAX_RETRY_DELAY)

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

        # Bind to LAN interface to bypass VPN
        if self._local_addr:
            connect_kwargs["local_addr"] = (self._local_addr, 0)

        async with asyncssh.connect(**connect_kwargs) as conn:
            logger.info("SSH connected to %s", self._pfsense_ip)
            self.status_changed.emit("Connected", f"SSH to {self._pfsense_ip}")
            self._retry_delay = MIN_RETRY_DELAY

            cmd = f"tail -n 0 -f {self._remote_eve_path}"
            async with conn.create_process(cmd) as process:
                if process.stdout is None:
                    logger.error("SSH process stdout is None")
                    return

                async for line in process.stdout:
                    if not self._running:
                        break
                    stripped = line.strip()
                    if stripped:
                        self.line_received.emit(stripped)

    def stop(self) -> None:
        """Stop the SSH streamer — thread-safe."""
        self._running = False
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
