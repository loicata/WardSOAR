"""CDN / major-SaaS ASN allowlist (Phase 7e).

Read :file:`config/cdn_allowlist.yaml` at startup and answer one
question for the Responder:

    "If the alert's source IP belongs to the ASN <N>, should
     Hard Protect step back to Protect semantics?"

Scope and non-goals
-------------------
* The allowlist is an **ASN-based** shortcut. It matches on the
  resolved origin of the IP, not on the IP itself — CDN edge IPs
  churn daily, the ASN does not.
* It is **not** a blanket "never block" list. When a listed ASN
  matches, the Responder falls back to Protect semantics: a
  CONFIRMED verdict with sufficient confidence still triggers a
  block. Opus remains the final judge.
* It is **not** a whitelist. The existing ``WhitelistConfig``
  (``ips`` + ``subnets``) always wins over the allowlist and
  guarantees full immunity for the operator's own infrastructure.
* It is **not** a replacement for :mod:`src.suspect_asns`. An ASN
  that appears in both files is treated as suspect (Tor / VPN /
  residential-proxy evidence trumps "common CDN"). The check order
  in the Responder enforces this.

Fail-safe behaviour
-------------------
A missing or malformed YAML makes the allowlist empty and
:meth:`classify_asn` returns ``None`` for every input. Hard Protect
then behaves exactly as in v0.7.5 — stricter, not looser, which is
the correct direction if the allowlist file is somehow lost.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("ward_soar.cdn_allowlist")


@dataclass(frozen=True)
class CdnMatch:
    """Outcome of a CDN-allowlist lookup.

    Attributes:
        asn: The matched ASN number.
        organisation: Human-readable label (e.g. ``"Cloudflare"``).
        category: Coarse grouping — ``"cdn"``, ``"streaming"``,
            ``"saas"`` or ``"platform"``. Used only for audit-log
            readability; the Responder does not branch on it.
    """

    asn: int
    organisation: str
    category: str


class CdnAllowlist:
    """In-memory index of CDN / SaaS ASNs we treat as low-risk.

    Args:
        config_path: YAML file to load. A missing or malformed file
            leaves the registry empty.
    """

    def __init__(self, config_path: Path) -> None:
        self._path = config_path
        self._lock = threading.RLock()
        self._by_asn: dict[int, CdnMatch] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.is_file():
            logger.info("cdn_allowlist: file missing at %s -- allowlist empty", self._path)
            return
        try:
            raw = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("cdn_allowlist: load failed (%s) -- allowlist empty", exc)
            return
        if not isinstance(raw, dict):
            logger.warning("cdn_allowlist: top level is not a mapping -- allowlist empty")
            return

        by_asn: dict[int, CdnMatch] = {}
        for item in raw.get("allowlisted") or []:
            if not isinstance(item, dict):
                continue
            asn_raw = item.get("asn")
            if asn_raw is None:
                continue
            try:
                asn = int(asn_raw)
            except (TypeError, ValueError):
                continue
            # Idempotent: first match wins (matches the YAML comment's
            # contract). A repeated ASN is silently dropped, which lets
            # us list the same number under different categories
            # without surprising the caller.
            if asn in by_asn:
                continue
            by_asn[asn] = CdnMatch(
                asn=asn,
                organisation=str(item.get("organisation", "") or f"AS{asn}"),
                category=str(item.get("category", "") or "saas"),
            )

        self._by_asn = by_asn
        logger.info("cdn_allowlist: loaded %d ASN entries from %s", len(by_asn), self._path)

    def reload(self) -> None:
        """Re-read the YAML from disk (operator edit without restart)."""
        with self._lock:
            self._load()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def classify_asn(self, asn: Optional[int]) -> Optional[CdnMatch]:
        """Return the :class:`CdnMatch` for ``asn`` or ``None``.

        ``None`` / malformed inputs are treated as misses rather than
        raised as errors — the Responder relies on a fail-closed
        return value (no match → keep current mode semantics).
        """
        if asn is None:
            return None
        try:
            asn_int = int(asn)
        except (TypeError, ValueError):
            return None
        with self._lock:
            return self._by_asn.get(asn_int)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_asn)

    def snapshot(self) -> list[dict[str, str | int]]:
        """Export the loaded entries for logging / UI consumption."""
        with self._lock:
            return [
                {
                    "asn": m.asn,
                    "organisation": m.organisation,
                    "category": m.category,
                }
                for m in self._by_asn.values()
            ]


__all__ = [
    "CdnAllowlist",
    "CdnMatch",
]
