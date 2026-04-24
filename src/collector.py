"""Collect network context and IP reputation data around an alert.

Gathers active connections, DNS cache, ARP cache, and queries
external reputation services to enrich the alert context.

Fail-safe: if any data source fails, return empty data for that
source and continue. Never crash the pipeline.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess  # nosec B404 — required for Windows system queries (DNS, ARP); args are hardcoded constants
from subprocess import TimeoutExpired  # nosec B404 — exception class import, not an execution risk
from typing import Any, Optional

import httpx
import psutil

from src import win_paths
from src.models import IPReputation, NetworkContext, SuricataAlert

logger = logging.getLogger("ward_soar.collector")


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT = 15
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
OTX_TIMEOUT = 15


class ContextCollector:
    """Gather network context for a Suricata alert.

    Args:
        config: Collector configuration dict from config.yaml.
        reputation_config: Reputation services configuration dict from config.yaml.
    """

    def __init__(
        self,
        config: dict[str, Any],
        reputation_config: Optional[dict[str, Any]] = None,
    ) -> None:
        self._config = config
        self._reputation_config = reputation_config or {}

    async def collect(self, alert: SuricataAlert) -> NetworkContext:
        """Collect all available network context for an alert.

        Args:
            alert: The triggering Suricata alert.

        Returns:
            NetworkContext with enriched data.
        """
        connections = await self.get_active_connections(filter_ip=alert.src_ip)
        dns_cache = await self.get_dns_cache()
        arp_cache = await self.get_arp_cache()
        ip_reputation = await self.get_ip_reputation(alert.src_ip)

        return NetworkContext(
            active_connections=connections,
            dns_cache=dns_cache,
            arp_cache=arp_cache,
            ip_reputation=ip_reputation,
        )

    async def get_active_connections(self, filter_ip: Optional[str] = None) -> list[dict[str, Any]]:
        """Get active network connections, optionally filtered by IP.

        Args:
            filter_ip: If set, only return connections involving this IP.

        Returns:
            List of connection dicts with local/remote addr, port, state, PID.
        """
        try:
            raw_connections = psutil.net_connections(kind="inet")
        except (PermissionError, OSError):
            logger.warning("Failed to retrieve network connections")
            return []

        connections: list[dict[str, Any]] = []
        for conn in raw_connections:
            if not conn.raddr or not conn.laddr:
                continue
            if not hasattr(conn.raddr, "ip") or not hasattr(conn.laddr, "ip"):
                continue

            local_ip: str = conn.laddr.ip
            local_port: int = conn.laddr.port
            remote_ip: str = conn.raddr.ip
            remote_port: int = conn.raddr.port

            if filter_ip is not None:
                if remote_ip != filter_ip and local_ip != filter_ip:
                    continue

            connections.append(
                {
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                    "pid": conn.pid,
                }
            )

        return connections

    async def get_dns_cache(self) -> list[dict[str, Any]]:
        """Get local DNS resolver cache entries.

        Returns:
            List of DNS cache entries as raw text lines.
        """
        try:
            result = subprocess.run(  # nosec B603 — absolute path, hardcoded args, no user input
                [win_paths.POWERSHELL, "-Command", "Get-DnsClientCache | Format-List"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                logger.warning("DNS cache query returned non-zero exit code")
                return []
            # Guard against stdout=None (observed when a child process
            # exits abnormally — would raise ``'NoneType' object has no
            # attribute 'strip'`` and propagate out of the pipeline).
            stdout = result.stdout or ""
            return [{"raw": line} for line in stdout.strip().splitlines() if line.strip()]
        except (FileNotFoundError, OSError, TimeoutExpired):
            logger.warning("Failed to retrieve DNS cache")
            return []

    async def get_arp_cache(self) -> list[dict[str, Any]]:
        """Get ARP cache entries.

        Returns:
            List of ARP entries as raw text lines.
        """
        try:
            result = subprocess.run(  # nosec B603 — absolute path, hardcoded args, no user input
                [win_paths.ARP, "-a"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                logger.warning("ARP cache query returned non-zero exit code")
                return []
            # Guard against stdout=None — same reasoning as get_dns_cache.
            stdout = result.stdout or ""
            return [{"raw": line} for line in stdout.strip().splitlines() if line.strip()]
        except (FileNotFoundError, OSError, TimeoutExpired):
            logger.warning("Failed to retrieve ARP cache")
            return []

    async def get_ip_reputation(self, ip: str) -> IPReputation:
        """Query external reputation services for an IP.

        Queries AbuseIPDB and AlienVault OTX when enabled and API keys
        are configured. Falls back gracefully if any service is unavailable.

        Args:
            ip: IP address to check.

        Returns:
            IPReputation with aggregated scores.
        """
        reputation = IPReputation(ip=ip)

        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                reputation.is_known_malicious = False
                return reputation
        except ValueError:
            logger.warning("Invalid IP address for reputation check: %s", ip)
            return reputation

        # Query enabled reputation services
        await self._query_abuseipdb(ip, reputation)
        await self._query_otx(ip, reputation)

        # Aggregate: mark as malicious if any source flags it
        if reputation.sources:
            reputation.is_known_malicious = True

        return reputation

    async def _query_abuseipdb(self, ip: str, reputation: IPReputation) -> None:
        """Query AbuseIPDB for IP reputation.

        Args:
            ip: IP address to check.
            reputation: IPReputation object to update in-place.
        """
        abuseipdb_cfg = self._reputation_config.get("abuseipdb", {})
        if not abuseipdb_cfg.get("enabled", False):
            return

        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not api_key:
            logger.debug("AbuseIPDB API key not configured, skipping")
            return

        confidence_threshold = abuseipdb_cfg.get("confidence_threshold", 50)

        try:
            async with httpx.AsyncClient(timeout=ABUSEIPDB_TIMEOUT) as client:
                response = await client.get(
                    ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers={
                        "Key": api_key,
                        "Accept": "application/json",
                    },
                )
                if response.status_code != 200:
                    logger.warning("AbuseIPDB returned status %d for %s", response.status_code, ip)
                    return

                data = response.json().get("data", {})
                score = int(data.get("abuseConfidenceScore", 0))
                reputation.abuseipdb_score = score

                if score >= confidence_threshold:
                    reputation.sources.append("abuseipdb")
                    logger.info("AbuseIPDB flagged %s with score %d", ip, score)

        except (httpx.TimeoutException, httpx.HTTPError, ValueError, KeyError) as exc:
            logger.warning("AbuseIPDB query failed for %s: %s", ip, exc)

    async def _query_otx(self, ip: str, reputation: IPReputation) -> None:
        """Query AlienVault OTX for IP reputation.

        Args:
            ip: IP address to check.
            reputation: IPReputation object to update in-place.
        """
        otx_cfg = self._reputation_config.get("otx", {})
        if not otx_cfg.get("enabled", False):
            return

        api_key = os.getenv("OTX_API_KEY", "")
        if not api_key:
            logger.debug("OTX API key not configured, skipping")
            return

        try:
            async with httpx.AsyncClient(timeout=OTX_TIMEOUT) as client:
                response = await client.get(
                    f"{OTX_URL}/{ip}/general",
                    headers={"X-OTX-API-KEY": api_key},
                )
                if response.status_code != 200:
                    logger.warning("OTX returned status %d for %s", response.status_code, ip)
                    return

                data = response.json()
                pulse_count = int(data.get("pulse_info", {}).get("count", 0))
                reputation.otx_pulse_count = pulse_count

                if pulse_count > 0:
                    reputation.sources.append("otx")
                    logger.info("OTX flagged %s with %d pulses", ip, pulse_count)

        except (httpx.TimeoutException, httpx.HTTPError, ValueError, KeyError) as exc:
            logger.warning("OTX query failed for %s: %s", ip, exc)
