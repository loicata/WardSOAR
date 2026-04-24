"""ASN (Autonomous System Number) enrichment for threat-actor-aware scoring.

An attacker who chooses fresh IPs from a VPN / proxy provider will
systematically evade IP-reputation lists (AbuseIPDB, OTX) because those
IPs are rotated fast enough that no report has had time to accumulate.
The network-block they all share, however — the AS number — is a stable,
publicly-known identifier: ``AS9009`` is ``M247 Ltd`` whether the current
exit IP is 45.159.241.4 or 185.176.43.2.

This module resolves an IP → ASN cheaply (cached, bounded fallbacks) so
the PreScorer can attach a weight proportional to how "anonymisation-
friendly" the source operator is. See ``config/suspect_asns.yaml``.

Design:
    - Primary source: ipinfo.io (generous free tier, same provider the
      UI already consults for the per-alert IP card).
    - Fallback: Team Cymru TCP whois (``whois.cymru.com:43``) — no key,
      no registration, rate-limit-friendly for the ~a-few-per-day
      lookups a SOHO WardSOAR instance actually makes.
    - Cache: SQLite, TTL 30 days (ASN assignments are stable over months).
    - Fail-safe: if every source errors out, return None. The PreScorer
      must not block on a missing ASN — "unknown" simply means no bonus.

Privacy note: resolving an IP to its ASN does not leak any information
about the local host to a third party beyond the IP itself. The same
IP is already queried by the UI's IP-reputation widget.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Optional

import httpx

logger = logging.getLogger("ward_soar.asn_enricher")


# Default TTL — ASN registrations don't move around often. A month lets
# us amortise the lookup cost without missing migrations.
_DEFAULT_TTL_SECONDS = 30 * 24 * 3600

# Per-source timeouts — keep them tight so a hung backend doesn't delay
# the whole pipeline. We have several fallbacks.
_IPINFO_TIMEOUT_SECONDS = 4
_CYMRU_TIMEOUT_SECONDS = 5

# Team Cymru bulk-whois port.
_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43


@dataclass(frozen=True)
class AsnInfo:
    """What we retain from an ASN lookup.

    Attributes:
        asn: AS number (e.g. 9009 for M247 Ltd).
        name: Short organisation name from the registry.
        country: ISO 3166-1 alpha-2 registration country (e.g. "GB", "IE").
        org: Free-text longer descriptor when available.
        source: "cache" | "ipinfo" | "cymru" — for debugging and audit.
    """

    asn: int
    name: str
    country: str
    org: str = ""
    source: str = "unknown"


class AsnEnricher:
    """IP → ASN resolver with SQLite cache + multi-source fallback.

    Args:
        cache_path: Path to the SQLite cache file. Parent dir is auto-created.
        ttl_seconds: Lifetime of cached entries before a re-query. Default 30 days.
        api_key: Optional ipinfo.io token. If unset, the free anonymous
            tier is used (50k/month is plenty for SOHO).
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS asn_cache (
        ip TEXT PRIMARY KEY,
        asn INTEGER NOT NULL,
        name TEXT NOT NULL,
        country TEXT NOT NULL,
        org TEXT NOT NULL,
        source TEXT NOT NULL,
        cached_at INTEGER NOT NULL
    );
    """

    def __init__(
        self,
        cache_path: Path,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        api_key: Optional[str] = None,
    ) -> None:
        self._cache_path = cache_path
        self._ttl = ttl_seconds
        self._api_key = api_key
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_lock = Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection with sane defaults."""
        conn = sqlite3.connect(self._cache_path, timeout=3.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(self._SCHEMA)
        except sqlite3.Error:
            logger.warning("ASN cache: schema init failed", exc_info=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def lookup(self, ip: str) -> Optional[AsnInfo]:
        """Return ASN info for ``ip`` or None if every backend fails.

        Cached entries are returned without any network call. A miss falls
        through to ipinfo.io, then Team Cymru whois. Each layer is best-
        effort; the caller must handle None as "don't apply any bonus".
        """
        if not ip:
            return None

        cached = self._cache_lookup(ip)
        if cached is not None:
            return cached

        info = await self._query_ipinfo(ip)
        if info is None:
            info = await self._query_cymru(ip)

        if info is not None:
            self._cache_store(ip, info)
        return info

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _cache_lookup(self, ip: str) -> Optional[AsnInfo]:
        now = int(time.time())
        try:
            with self._db_lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT asn, name, country, org, source, cached_at "
                    "FROM asn_cache WHERE ip = ?",
                    (ip,),
                ).fetchone()
        except sqlite3.Error:
            logger.debug("ASN cache lookup failed for %s", ip, exc_info=True)
            return None

        if row is None:
            return None
        asn, name, country, org, _src, cached_at = row
        if now - int(cached_at) > self._ttl:
            return None
        return AsnInfo(
            asn=int(asn),
            name=str(name),
            country=str(country),
            org=str(org),
            source="cache",
        )

    def _cache_store(self, ip: str, info: AsnInfo) -> None:
        now = int(time.time())
        try:
            with self._db_lock, self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO asn_cache "
                    "(ip, asn, name, country, org, source, cached_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ip, info.asn, info.name, info.country, info.org, info.source, now),
                )
        except sqlite3.Error:
            logger.warning("ASN cache: store failed for %s", ip, exc_info=True)

    # ------------------------------------------------------------------
    # ipinfo.io (primary source)
    # ------------------------------------------------------------------

    async def _query_ipinfo(self, ip: str) -> Optional[AsnInfo]:
        """Query ipinfo.io JSON endpoint. Fast, returns structured JSON."""
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            async with httpx.AsyncClient(timeout=_IPINFO_TIMEOUT_SECONDS) as client:
                response = await client.get(url, headers=headers)
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("ipinfo.io error for %s: %s", ip, exc)
            return None

        if response.status_code != 200:
            logger.debug("ipinfo.io returned %d for %s", response.status_code, ip)
            return None

        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError):
            return None

        # ipinfo's free tier exposes org as "ASNNNNN OrgName". A paid tier
        # has a nested "asn" object. Handle both.
        asn: Optional[int] = None
        name = ""
        org_raw = ""
        asn_obj = data.get("asn")
        if isinstance(asn_obj, dict):
            try:
                asn = int(str(asn_obj.get("asn", "AS0"))[2:])
            except ValueError:
                asn = None
            name = str(asn_obj.get("name", ""))
            org_raw = name
        else:
            org = str(data.get("org", ""))
            org_raw = org
            if org.startswith("AS"):
                try:
                    asn_token, _, rest = org.partition(" ")
                    asn = int(asn_token[2:])
                    name = rest.strip()
                except ValueError:
                    asn = None

        if asn is None:
            return None

        country = str(data.get("country", ""))
        return AsnInfo(
            asn=asn,
            name=name,
            country=country,
            org=org_raw,
            source="ipinfo",
        )

    # ------------------------------------------------------------------
    # Team Cymru fallback (no key, protocol is TCP-43 whois)
    # ------------------------------------------------------------------

    async def _query_cymru(self, ip: str) -> Optional[AsnInfo]:
        """Ask whois.cymru.com over TCP-43 using its bulk-verbose format.

        Protocol: send ``begin\\nverbose\\n<ip>\\nend\\n`` and read lines.
        Each response line is ``AS | IP | CIDR | CC | Registry | ASN Name``.
        """
        query = f"begin\nverbose\n{ip}\nend\n"
        loop = asyncio.get_running_loop()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(_CYMRU_HOST, _CYMRU_PORT),
                timeout=_CYMRU_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError, socket.gaierror) as exc:
            logger.debug("Team Cymru connect error: %s", exc)
            return None

        try:
            writer.write(query.encode("ascii"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(8192), timeout=_CYMRU_TIMEOUT_SECONDS)
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("Team Cymru read error: %s", exc)
            writer.close()
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            _ = loop  # keep the local reference mypy-happy

        return self._parse_cymru_response(raw.decode("ascii", errors="replace"))

    @staticmethod
    def _parse_cymru_response(text: str) -> Optional[AsnInfo]:
        """Parse a verbose Team Cymru response line."""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("bulk mode", "as ")):
                # Skip header lines.
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 6:
                continue
            try:
                asn = int(parts[0])
            except ValueError:
                continue
            cc = parts[3]
            name = parts[5]
            return AsnInfo(
                asn=asn,
                name=name,
                country=cc,
                org=name,
                source="cymru",
            )
        return None


# ---------------------------------------------------------------------------
# Convenience: an always-available empty enricher for tests / fail-safe wiring.
# ---------------------------------------------------------------------------


class NullAsnEnricher:
    """Drop-in replacement that returns None without any network call.

    Used when the configuration explicitly disables ASN enrichment or the
    cache backend could not be initialised. Keeps the PreScorer signature
    uniform.
    """

    async def lookup(self, ip: str) -> Optional[AsnInfo]:  # noqa: D401 — same name
        _ = ip
        return None


def dataclass_to_dict(info: Optional[AsnInfo]) -> dict[str, Any]:
    """Tiny helper used by tests and export tooling."""
    if info is None:
        return {}
    return {
        "asn": info.asn,
        "name": info.name,
        "country": info.country,
        "org": info.org,
        "source": info.source,
    }
