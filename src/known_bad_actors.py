"""Registry of known adversary IOCs with direct PreScorer scoring.

Some threat actors are not a guess — they've already been identified
through a forensic investigation, and the operator knows their
infrastructure (public IPs, CIDR blocks, domains). For those, the
pipeline should not wait for reputation databases or behavioural
signals: any contact with their known IOCs must be escalated
immediately.

This module loads ``config/known_bad_actors.yaml`` at startup and
answers two questions for the PreScorer:

1. Does this source IP belong to a listed adversary?
2. What weight should be added to the score if it does?

A single match is designed to push the alert past the threshold so
Opus is asked to adjudicate, and — if the Responder is in Protect mode
— a pfSense block plus a forensic quick acquisition follows the same
path as any other confirmed threat.

Scope and privacy note: the YAML stores only technical IOCs (IPs,
CIDRs, domains). Personal data from the operator's legal case (email
addresses, phone numbers, IBANs, postal addresses) is deliberately not
loaded here because WardSOAR cannot act on it on the wire and because
shipping it inside the product would leak case material.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("ward_soar.known_bad_actors")


@dataclass(frozen=True)
class ActorMatch:
    """Outcome of a lookup against the adversary registry.

    Attributes:
        actor_id: Opaque case reference (e.g. ``VINE-2025-001``).
        name: Human-readable adversary label used in logs / reports.
        weight: Score points added when this match wins. Chosen high
            enough to single-handedly cross the PreScorer threshold.
        reason: Short explanation for the audit log / deep report.
        matched_by: What specifically matched (``"ip"``, ``"cidr"``,
            ``"domain"``).
        matched_value: The exact IOC that fired (e.g. the CIDR string).
    """

    actor_id: str
    name: str
    weight: int
    reason: str
    matched_by: str
    matched_value: str


@dataclass
class _ActorEntry:
    """Internal structure — one parsed ``actors:`` entry."""

    actor_id: str
    name: str
    weight: int
    reason: str
    ips: set[str] = field(default_factory=set)
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)


class KnownActorsRegistry:
    """In-memory index over ``known_bad_actors.yaml``.

    Args:
        config_path: YAML file to load. A missing or malformed file
            leaves the registry empty (classify always returns None).
    """

    def __init__(self, config_path: Path) -> None:
        self._path = config_path
        self._lock = threading.RLock()
        self._actors: list[_ActorEntry] = []
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.is_file():
            logger.info("known_bad_actors: file missing at %s — registry empty", self._path)
            return

        try:
            raw = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("known_bad_actors: load failed (%s) — registry empty", exc)
            return

        if not isinstance(raw, dict):
            return

        entries: list[_ActorEntry] = []
        for item in raw.get("actors") or []:
            if not isinstance(item, dict):
                continue
            try:
                weight = int(item.get("weight", 0))
            except (ValueError, TypeError):
                weight = 0
            entry = _ActorEntry(
                actor_id=str(item.get("id", "")),
                name=str(item.get("name", "")),
                weight=weight,
                reason=str(item.get("reason", "")),
            )
            for ip in item.get("ips") or []:
                try:
                    ipaddress.ip_address(ip)
                    entry.ips.add(str(ip))
                except ValueError:
                    continue
            for cidr in item.get("cidrs") or []:
                try:
                    entry.cidrs.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            for domain in item.get("domains") or []:
                domain_str = str(domain).strip().lower()
                if domain_str:
                    entry.domains.add(domain_str)
            entries.append(entry)

        self._actors = entries
        total_ips = sum(len(e.ips) for e in entries)
        total_cidrs = sum(len(e.cidrs) for e in entries)
        total_domains = sum(len(e.domains) for e in entries)
        logger.info(
            "known_bad_actors: loaded %d actor(s) — %d IP(s), %d CIDR(s), %d domain(s)",
            len(entries),
            total_ips,
            total_cidrs,
            total_domains,
        )

    def reload(self) -> None:
        """Re-read the YAML (useful after an operator edit)."""
        with self._lock:
            self._load()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def classify_ip(self, ip: str) -> Optional[ActorMatch]:
        """Return the first :class:`ActorMatch` that claims ``ip``, or None.

        Matching order within an actor: exact IP first, then CIDR.
        Actors are matched in their YAML declaration order, so ordering
        the file from most-specific to least-specific yields predictable
        results when multiple entries overlap.
        """
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        with self._lock:
            for actor in self._actors:
                if ip in actor.ips:
                    return self._build_match(actor, "ip", ip)
                for cidr in actor.cidrs:
                    if addr.version != cidr.version:
                        continue
                    if addr in cidr:
                        return self._build_match(actor, "cidr", str(cidr))
        return None

    def classify_domain(self, domain: str) -> Optional[ActorMatch]:
        """Return the first :class:`ActorMatch` that lists ``domain``, or None.

        Matching is exact, case-insensitive. Subdomains are not implicit —
        add both ``example.com`` and ``foo.example.com`` if both should
        match.
        """
        if not domain:
            return None
        needle = domain.strip().lower().rstrip(".")
        with self._lock:
            for actor in self._actors:
                if needle in actor.domains:
                    return self._build_match(actor, "domain", needle)
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_match(actor: _ActorEntry, matched_by: str, matched_value: str) -> ActorMatch:
        return ActorMatch(
            actor_id=actor.actor_id,
            name=actor.name,
            weight=actor.weight,
            reason=actor.reason,
            matched_by=matched_by,
            matched_value=matched_value,
        )

    def snapshot(self) -> list[dict[str, str | int]]:
        """Summarise the registry for logging / UI purposes."""
        with self._lock:
            return [
                {
                    "id": actor.actor_id,
                    "name": actor.name,
                    "weight": actor.weight,
                    "ips": len(actor.ips),
                    "cidrs": len(actor.cidrs),
                    "domains": len(actor.domains),
                }
                for actor in self._actors
            ]
