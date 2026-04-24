"""SecurityTrails passive-DNS client.

SecurityTrails' unique selling point for reputation work is the
**passive-DNS history**: every hostname that ever resolved to this
IP over time. A single IP serving a dozen phishing domains across
six months is a very strong signal \u2014 impossible to see from a
free-tier source.

Endpoint: ``GET https://api.securitytrails.com/v1/ips/{ip}/useragents``
(not relevant) \u2014 we use the ``/ips/{ip}`` reverse-DNS endpoint that
returns the domain history.

Actual working endpoint: ``GET https://api.securitytrails.com/v1/ips/nearby/{ip}``
returns blocks, which is not what we want. The passive-DNS data
lives at ``GET https://api.securitytrails.com/v1/history/{host}/dns/a``
\u2014 requires a hostname.

For an IP, the relevant query is:
``GET https://api.securitytrails.com/v1/ips/list``
with a POST body filter. To keep this client simple (GET + key)
we use ``GET /v1/ips/{ip}`` which returns the basic profile + a
``dns_records`` summary when the subscription tier allows it.

Authentication: ``APIKEY`` header.

Paid tier: $50/month includes 2 000 requests.

Response shape (subset):
    {
      "ip": "1.2.3.4",
      "hostnames": ["a.example.com", "b.example.com", ...],
      "ptr": "host.example.com",
      "first_seen": "2024-01-01",
      "last_seen": "2026-04-22",
      ...
    }
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from src.intel.http_client_base import HttpReputationClient, ReputationVerdict


class SecurityTrailsClient(HttpReputationClient):
    """SecurityTrails passive-DNS IP client."""

    name = "securitytrails"
    display_name = "SecurityTrails"
    env_var = "SECURITYTRAILS_API_KEY"

    _URL = "https://api.securitytrails.com/v1/ips/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        headers = {"APIKEY": api_key, "accept": "application/json"}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL.format(ip=ip), headers=headers)
            if response.status_code == 404:
                return {"_unknown": True}
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return None
            return data

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        if raw.get("_unknown"):
            return ReputationVerdict(
                level="clean",
                verdict="\U0001f7e2 No passive-DNS record",
            )
        hostnames = raw.get("hostnames") or raw.get("records") or []
        if isinstance(hostnames, dict):
            # Some responses wrap the list under ``records.a``.
            a_records = hostnames.get("a") or []
            host_list = (
                [str(r.get("host") or "") for r in a_records if isinstance(r, dict)]
                if isinstance(a_records, list)
                else []
            )
        elif isinstance(hostnames, list):
            host_list = [str(h) for h in hostnames]
        else:
            host_list = []

        host_list = [h for h in host_list if h]
        count = len(host_list)
        if count == 0:
            return ReputationVerdict(
                level="clean",
                verdict="\U0001f7e2 No passive-DNS history recorded",
                raw=raw,
            )
        # Quote the first 3 hostnames as context.
        sample = ", ".join(host_list[:3])
        if count > 3:
            sample += f", +{count - 3} more"
        return ReputationVerdict(
            level="info",
            verdict=f"\U0001f535 {count} historical hostname(s): {sample}",
            raw=raw,
        )
