"""Suspect-ASN registry: load YAML + classify ASNs + handle Tor exits.

The PreScorer asks :meth:`SuspectAsnRegistry.classify` for a weight to
apply given an :class:`AsnInfo` object. The weight is 0 for an unknown
ASN (no change) and up to 40 + priority-country bonus for a Tor exit.

Tor exit nodes are refreshed periodically from check.torproject.org so
a freshly-rotated exit node is caught without a WardSOAR restart.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml

from wardsoar.core.asn_enricher import AsnInfo

logger = logging.getLogger("ward_soar.suspect_asns")


# Official public Tor exit list. The endpoint returns one IP per line.
_TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_REFRESH_HOURS_DEFAULT = 1


@dataclass(frozen=True)
class AsnClassification:
    """Classification result for a given IP / ASN.

    Attributes:
        category: "tor_exit" | "vpn_provider" | "residential_proxy" |
                  "vps_uk_ie" | "datacenter_generic" | "unknown".
        weight: Points to add to the PreScorer. 0 means no bonus.
        priority_country_bonus: Extra points because the ASN is registered
                                in one of the operator's threat-priority
                                countries (UK/IE for Loïc's case).
        matched_asn: The ASN number that triggered the match, when any.
        matched_name: Registry name shown alongside the weight.
    """

    category: str
    weight: int
    priority_country_bonus: int = 0
    matched_asn: Optional[int] = None
    matched_name: Optional[str] = None

    @property
    def total_weight(self) -> int:
        """Sum of the category weight and the country bonus."""
        return self.weight + self.priority_country_bonus


class SuspectAsnRegistry:
    """Load ``suspect_asns.yaml`` and classify ASN lookups against it.

    Args:
        config_path: YAML file to load. If missing, the registry stays
            empty (every lookup returns ``("unknown", 0)``).
        tor_exits: Optional set of Tor exit IPs to bootstrap with. Left
            unset in normal operation — :class:`TorExitFetcher` feeds it
            on a background schedule.
    """

    def __init__(
        self,
        config_path: Path,
        tor_exits: Optional[set[str]] = None,
    ) -> None:
        self._path = config_path
        self._lock = threading.RLock()
        self._tor_exits: set[str] = set(tor_exits) if tor_exits else set()
        self._tor_weight: int = 40
        self._priority_countries: set[str] = set()
        self._priority_bonus: int = 0
        self._categories: dict[str, dict[str, Any]] = {}
        self._asn_lookup: dict[int, tuple[str, int, str]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.is_file():
            logger.info("suspect_asns: file missing at %s — registry empty", self._path)
            return
        try:
            raw = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("suspect_asns: failed to load %s: %s", self._path, exc)
            return

        if not isinstance(raw, dict):
            logger.warning("suspect_asns: unexpected YAML shape, ignoring")
            return

        self._priority_countries = {c.upper() for c in raw.get("priority_countries", [])}
        self._priority_bonus = int(raw.get("priority_country_bonus", 0))

        categories = raw.get("categories") or {}
        if not isinstance(categories, dict):
            return
        self._categories = categories

        asn_lookup: dict[int, tuple[str, int, str]] = {}
        for category_name, category in categories.items():
            weight = int(category.get("weight", 0))
            if category_name == "tor_exit":
                self._tor_weight = weight
            for entry in category.get("asns") or []:
                try:
                    asn = int(entry["asn"])
                except (KeyError, ValueError, TypeError):
                    continue
                name = str(entry.get("name", ""))
                asn_lookup[asn] = (category_name, weight, name)
        self._asn_lookup = asn_lookup
        logger.info(
            "suspect_asns: loaded %d ASN entries across %d categories",
            len(asn_lookup),
            len(categories),
        )

    def reload(self) -> None:
        """Re-read the YAML file. Useful after an operator edit."""
        with self._lock:
            self._load()

    # ------------------------------------------------------------------
    # Tor exits — fed by TorExitFetcher
    # ------------------------------------------------------------------

    def set_tor_exits(self, ips: set[str]) -> None:
        """Replace the Tor exit set (validates each address)."""
        valid: set[str] = set()
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid.add(ip)
            except ValueError:
                continue
        with self._lock:
            self._tor_exits = valid
        logger.info("suspect_asns: Tor exit list updated (%d IPs)", len(valid))

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(self, ip: str, info: Optional[AsnInfo]) -> AsnClassification:
        """Return the weight and category matching the IP/ASN combo.

        Args:
            ip: The address being scored (used for Tor-exit lookup).
            info: ASN info from :class:`AsnEnricher`. May be None when the
                enricher itself failed — we still catch Tor exits in that
                case because the Tor source is IP-based.

        Returns:
            An :class:`AsnClassification`. ``category="unknown"`` and
            ``weight=0`` when nothing matches.
        """
        with self._lock:
            # Tor exits are authoritative regardless of ASN lookup result.
            if ip in self._tor_exits:
                return AsnClassification(
                    category="tor_exit",
                    weight=self._tor_weight,
                    priority_country_bonus=0,
                    matched_asn=getattr(info, "asn", None) if info else None,
                    matched_name=getattr(info, "name", None) if info else None,
                )

            if info is None:
                return AsnClassification(category="unknown", weight=0)

            match = self._asn_lookup.get(info.asn)
            if match is None:
                return AsnClassification(category="unknown", weight=0)

            category, weight, name = match
            bonus = (
                self._priority_bonus
                if info.country and info.country.upper() in self._priority_countries
                else 0
            )
            return AsnClassification(
                category=category,
                weight=weight,
                priority_country_bonus=bonus,
                matched_asn=info.asn,
                matched_name=name or info.name,
            )


class TorExitFetcher:
    """Refresh the Tor exit node list periodically.

    Holds state only; a caller is responsible for scheduling :meth:`refresh`
    from an asyncio loop (e.g. a task in ``engine_bridge`` or a periodic
    heartbeat in the healthcheck module).

    Args:
        registry: :class:`SuspectAsnRegistry` that consumes the list.
        interval_hours: Minimum gap between successful refreshes. Default
                        1 hour — the list rotates moderately fast.
        url: Override the upstream endpoint (tests).
        timeout_seconds: HTTP timeout.
    """

    def __init__(
        self,
        registry: SuspectAsnRegistry,
        interval_hours: float = _TOR_REFRESH_HOURS_DEFAULT,
        url: str = _TOR_EXIT_URL,
        timeout_seconds: int = 10,
    ) -> None:
        self._registry = registry
        self._interval = max(0.25, float(interval_hours)) * 3600
        self._url = url
        self._timeout = timeout_seconds
        self._last_success: float = 0.0

    async def refresh(self, force: bool = False) -> int:
        """Fetch the list if it's due. Returns the number of IPs loaded.

        Args:
            force: Skip the interval check. Used for tests or first-boot.

        Returns:
            Number of IPs successfully loaded. 0 on failure.
        """
        now = time.monotonic()
        if not force and (now - self._last_success) < self._interval:
            return 0

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._url)
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Tor exit fetch failed: %s", exc)
            return 0

        if resp.status_code != 200:
            logger.debug("Tor exit endpoint returned %d", resp.status_code)
            return 0

        ips = {line.strip() for line in resp.text.splitlines() if line.strip()}
        self._registry.set_tor_exits(ips)
        self._last_success = now
        return len(ips)
