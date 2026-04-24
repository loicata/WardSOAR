"""Manage pfSense blocklist lifecycle via SSH+pfctl.

Handles expiry of temporary IP blocks, coherence checks
between the block tracker and active pfSense table, and
emergency unblock operations.

Fail-safe: if pfSense SSH is unavailable, log the error
and continue. Never crash the pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from wardsoar.core.config import WhitelistConfig
from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker, PfSenseSSH

logger = logging.getLogger("ward_soar.rule_manager")


class RuleManager:
    """Manage pfSense blocklist lifecycle.

    Periodically checks for expired blocks, removes them,
    and verifies coherence between the block tracker and
    active blocklist entries on pfSense.

    Args:
        config: RuleManager configuration dict from config.yaml.
        whitelist: Whitelist configuration for safety checks.
        ssh: PfSenseSSH instance for firewall operations.
        tracker: BlockTracker instance for block timestamp tracking.
        block_duration_hours: Default block duration in hours.
    """

    def __init__(
        self,
        config: dict[str, Any],
        whitelist: WhitelistConfig,
        ssh: PfSenseSSH,
        tracker: BlockTracker,
        block_duration_hours: int = 24,
    ) -> None:
        self._config = config
        self._whitelist = whitelist
        self._ssh = ssh
        self._tracker = tracker
        self._block_duration_hours = block_duration_hours
        self._cleanup_interval: int = config.get("cleanup_interval_minutes", 15)

    async def cleanup_expired_rules(self) -> list[str]:
        """Remove expired IP blocks from pfSense.

        Returns:
            List of IP addresses that were unblocked.
        """
        expired_ips = self._tracker.get_expired_ips(self._block_duration_hours)
        removed: list[str] = []

        for ip in expired_ips:
            success = await self._ssh.remove_from_blocklist(ip)
            if success:
                self._tracker.remove_block(ip)
                removed.append(ip)
                logger.info("Cleaned up expired block: %s", ip)
            else:
                logger.warning("Failed to remove expired block: %s", ip)

        return removed

    async def verify_coherence(self) -> dict[str, list[str]]:
        """Verify coherence between active blocklist and whitelist.

        Detects:
        - Whitelisted IPs that somehow got blocked (critical error)

        Also reconciles the local tracker with the actual pf table.

        Returns:
            Dict with whitelist_violations list.
        """
        report: dict[str, list[str]] = {
            "whitelist_violations": [],
        }

        active_ips = await self._ssh.list_blocklist()
        self._tracker.reconcile(active_ips)

        for ip in active_ips:
            if self._whitelist.is_whitelisted(ip):
                logger.critical(
                    "WHITELIST VIOLATION: %s is whitelisted but is in the blocklist!", ip
                )
                report["whitelist_violations"].append(ip)

        return report

    async def emergency_unblock(self, ip: str) -> bool:
        """Emergency removal of an IP from the blocklist.

        Args:
            ip: IP address to unblock.

        Returns:
            True if the IP was removed from the blocklist.
        """
        success = await self._ssh.remove_from_blocklist(ip)
        if success:
            self._tracker.remove_block(ip)
            logger.info("Emergency unblock: removed %s from blocklist", ip)
            return True

        logger.warning("Emergency unblock: failed to remove %s", ip)
        return False
