"""Compare alert traffic against known normal network patterns.

Loads the network baseline configuration and provides context
about whether observed traffic matches expected patterns.
Anomalies increase the pre-score; matches decrease suspicion.

Fail-safe: if the baseline config is missing or corrupt,
skip baseline check and let the alert through.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from wardsoar.core.models import SuricataAlert

logger = logging.getLogger("ward_soar.baseline")


class BaselineVerdict:
    """Result of comparing an alert against the network baseline.

    Attributes:
        is_known_normal: Whether the traffic matches a known normal pattern.
        is_known_suspicious: Whether the traffic matches a known suspicious pattern.
        matching_rule: The baseline rule that matched, if any.
        anomaly_details: Description of why traffic is anomalous.
    """

    def __init__(
        self,
        is_known_normal: bool = False,
        is_known_suspicious: bool = False,
        matching_rule: Optional[str] = None,
        anomaly_details: Optional[str] = None,
    ) -> None:
        self.is_known_normal = is_known_normal
        self.is_known_suspicious = is_known_suspicious
        self.matching_rule = matching_rule
        self.anomaly_details = anomaly_details


class NetworkBaseline:
    """Compare traffic against known normal patterns.

    Args:
        config: Baseline configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._anomaly_score_bonus: int = config.get("anomaly_score_bonus", 15)
        self._internal_services: list[dict[str, Any]] = []
        self._expected_external: list[dict[str, Any]] = []
        self._expected_outbound_ports: set[int] = set()
        self._suspicious_outbound_ports: set[int] = set()

        if self._enabled:
            baseline_path = Path(config.get("config_file", "config/network_baseline.yaml"))
            if baseline_path.exists():
                self._load_baseline(baseline_path)

    def _load_baseline(self, path: Path) -> None:
        """Load baseline definitions from YAML file.

        Fail-safe: if the file is corrupt, log warning and skip.

        Args:
            path: Path to network_baseline.yaml.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.warning("Corrupt YAML in baseline file: %s", path)
            return

        if not isinstance(raw, dict):
            logger.warning("Unexpected format in baseline file: %s", path)
            return

        self._load_internal_services(raw)
        self._load_expected_external(raw)
        self._load_expected_ports(raw)
        self._load_suspicious_ports(raw)

        logger.info(
            "Loaded baseline: %d internal services, %d expected ports, %d suspicious ports",
            len(self._internal_services),
            len(self._expected_outbound_ports),
            len(self._suspicious_outbound_ports),
        )

    def _load_internal_services(self, raw: dict[str, Any]) -> None:
        """Load internal service definitions from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("internal_services", None) or []:
            if "ip" in entry:
                self._internal_services.append(entry)

    def _load_expected_external(self, raw: dict[str, Any]) -> None:
        """Load expected external destinations from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("expected_external_destinations", None) or []:
            self._expected_external.append(entry)

    def _load_expected_ports(self, raw: dict[str, Any]) -> None:
        """Load expected outbound ports from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("expected_outbound_ports", None) or []:
            if "port" in entry:
                self._expected_outbound_ports.add(int(entry["port"]))

    def _load_suspicious_ports(self, raw: dict[str, Any]) -> None:
        """Load suspicious outbound ports from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("suspicious_outbound_ports", None) or []:
            if "port" in entry:
                self._suspicious_outbound_ports.add(int(entry["port"]))

    def evaluate(self, alert: SuricataAlert) -> BaselineVerdict:
        """Evaluate an alert against the network baseline.

        Args:
            alert: The Suricata alert to evaluate.

        Returns:
            BaselineVerdict indicating whether traffic is normal, suspicious, or unknown.
        """
        if not self._enabled:
            return BaselineVerdict()

        # Check if destination is a known internal service on expected port
        for service in self._internal_services:
            if alert.dest_ip == service["ip"]:
                expected_ports = service.get("expected_ports", [])
                if alert.dest_port in expected_ports:
                    return BaselineVerdict(
                        is_known_normal=True,
                        matching_rule=f"internal_service:{service.get('name', 'unknown')}",
                    )

        # Check if destination port is suspicious
        if alert.dest_port in self._suspicious_outbound_ports:
            return BaselineVerdict(
                is_known_suspicious=True,
                matching_rule="suspicious_outbound_ports",
                anomaly_details=f"Port {alert.dest_port} is a known suspicious port",
            )

        return BaselineVerdict()

    def is_suspicious_port(self, port: int) -> bool:
        """Check if a port is in the suspicious outbound list.

        Args:
            port: The destination port to check.

        Returns:
            True if the port is considered suspicious.
        """
        return port in self._suspicious_outbound_ports
