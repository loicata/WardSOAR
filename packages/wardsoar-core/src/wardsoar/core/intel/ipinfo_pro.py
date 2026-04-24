"""ipinfo.io pro tier client \u2014 privacy / VPN / proxy detection.

Unlike the other Phase 2 clients this one does not produce a
reputation row. Instead it enriches the ``Identity`` block of the
Alert Detail view by populating the ``is_vpn_or_proxy`` flag on
:class:`src.ip_enrichment.IpIdentity`. The operator sees one extra
line under ASN / Country / rDNS / Tor exit when the key is set.

Endpoint: ``GET https://ipinfo.io/{ip}/json?token={key}``
Authentication: query-string ``token`` or ``Authorization: Bearer``.

Free quota: 50 000 lookups / month (shared across anonymous and
pro tiers). The privacy fields (``privacy.vpn``, ``privacy.proxy``,
``privacy.tor``, ``privacy.hosting``) are only present when a key
is provided \u2014 that's exactly the upgrade we want to expose.

Response shape (relevant subset, pro tier):
    {
      "ip": "51.15.70.12",
      "hostname": "...",
      "city": "Amsterdam",
      "region": "North Holland",
      "country": "NL",
      "org": "AS12876 Scaleway S.a.s.",
      "privacy": {
        "vpn": false,
        "proxy": false,
        "tor": false,
        "relay": false,
        "hosting": true,
        "service": ""
      }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from wardsoar.core.intel.http_client_base import HttpReputationClient, ReputationVerdict

logger = logging.getLogger("ward_soar.intel.ipinfo_pro")


class IpinfoProClient(HttpReputationClient):
    """ipinfo.io pro-tier lookup for privacy detection.

    We still subclass :class:`HttpReputationClient` for the shared
    cache + env-var machinery, but the client exposes a second
    helper \u2014 :meth:`is_vpn_or_proxy` \u2014 that returns a plain bool
    for the Identity block. The standard :meth:`query_ip` is not
    used (ipinfo doesn't produce a reputation verdict).
    """

    name = "ipinfo_pro"
    display_name = "ipinfo.io (privacy tier)"
    env_var = "IPINFO_API_KEY"

    _URL = "https://ipinfo.io/{ip}/json"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        params = {"token": api_key}
        headers = {"accept": "application/json"}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL.format(ip=ip), params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return None
            return data

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        """Kept for compatibility with the base class.

        The real consumer of this client is
        :meth:`is_vpn_or_proxy`, which bypasses the standard
        query_ip() path and populates the Identity block directly.
        We still return a nominal verdict so the shared cache
        behaviour works if someone queries through the normal path.
        """
        privacy = raw.get("privacy") or {}
        flags = [name for name, active in privacy.items() if isinstance(active, bool) and active]
        if flags:
            return ReputationVerdict(
                level="info",
                verdict="\U0001f535 Privacy flags: " + ", ".join(flags),
                raw=raw,
            )
        return ReputationVerdict(
            level="clean",
            verdict="\U0001f7e2 No privacy flags (not VPN / proxy / hosting)",
            raw=raw,
        )

    async def is_vpn_or_proxy(self, ip: str) -> Optional[bool]:
        """Return ``True`` / ``False`` / ``None`` for the Identity row.

        * ``True``  \u2014 at least one of ``vpn`` / ``proxy`` / ``tor`` /
          ``relay`` / ``hosting`` is set.
        * ``False`` \u2014 privacy dict returned and all flags are false.
        * ``None``  \u2014 key not configured or lookup failed. The
          Identity row is omitted entirely in that case.
        """
        if not self.is_enabled():
            return None
        cached = self._cache.get(self.name, ip)
        if cached is not None:
            # Re-interpret the cached verdict to return a bool.
            return self._privacy_bool_from_raw(cached.raw or {})
        fresh: Optional[dict[str, Any]] = None
        try:
            key = self._current_api_key()
            fresh = await self._fetch_raw(ip, key)
        except httpx.HTTPError as exc:
            logger.warning("intel.ipinfo_pro: HTTP error on %s: %s", ip, exc)
            return None
        except Exception:  # noqa: BLE001 \u2014 defensive
            logger.exception("intel.ipinfo_pro: unexpected failure on %s", ip)
            return None
        if fresh is None:
            return None
        # Persist through the normal cache path for the /verdict row
        # as well (operator may inspect via query_ip later).
        try:
            verdict = self._verdict_from_raw(fresh)
            self._cache.put(self.name, ip, verdict)
        except Exception:  # noqa: BLE001
            logger.debug("ipinfo_pro: cache write failed", exc_info=True)
        return self._privacy_bool_from_raw(fresh)

    @staticmethod
    def _privacy_bool_from_raw(raw: dict[str, Any]) -> Optional[bool]:
        privacy = raw.get("privacy")
        if not isinstance(privacy, dict):
            return None
        for field in ("vpn", "proxy", "tor", "relay", "hosting"):
            if bool(privacy.get(field)):
                return True
        return False
