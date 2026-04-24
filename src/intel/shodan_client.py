"""Shodan IP-host lookup client.

Shodan is the canonical "what is running on this IP" scanner. The
``/shodan/host/{ip}`` endpoint returns every exposed service the
scanner has observed for the IP, plus known CVEs and product /
version fingerprints.

Authentication: ``key`` query parameter (env var ``SHODAN_API_KEY``).

Tiers:
  * Academic: ~$49/year, lifetime (one-time Black-Friday deal).
  * API: $599/year for 1M queries/month.

Response shape (relevant subset):
    {
      "ip": 16909060,
      "ip_str": "1.2.3.4",
      "ports": [22, 80, 443],
      "hostnames": ["mail.example.com"],
      "country_code": "US",
      "city": "San Francisco",
      "org": "Some org",
      "tags": ["cloud"],
      "vulns": {
        "CVE-2023-1234": {"cvss": 9.8, "summary": "..."}
      },
      "data": [
        {"port": 22, "product": "OpenSSH", "version": "8.0p1"},
        {"port": 443, "product": "nginx", "version": "1.22"}
      ]
    }

HTTP 404: the IP has not been scanned by Shodan \u2014 we return a
``clean``-level row ("No exposed service indexed") rather than a
warning, because absence from Shodan is not in itself suspicious.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from src.intel.http_client_base import HttpReputationClient, ReputationVerdict


class ShodanClient(HttpReputationClient):
    """Shodan ``/shodan/host/{ip}`` client."""

    name = "shodan"
    display_name = "Shodan"
    env_var = "SHODAN_API_KEY"

    _URL = "https://api.shodan.io/shodan/host/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        params = {"key": api_key}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL.format(ip=ip), params=params)
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
                verdict="\U0001f7e2 No exposed service indexed",
            )
        ports = raw.get("ports") or []
        vulns = raw.get("vulns") or {}
        if isinstance(vulns, list):
            # Some responses return a list of CVE ids rather than a
            # dict. Normalise to a simple count.
            vuln_count = len(vulns)
        else:
            vuln_count = len(vulns)

        if vuln_count > 0:
            emoji = "\U0001f534"
            level = "bad"
            verdict = (
                f"{emoji} {vuln_count} known vulnerability(ies) "
                f"across {len(ports)} open port(s)"
            )
        elif ports:
            emoji = "\U0001f535"
            level = "info"
            # Show the first 4 ports for context.
            port_sample = ", ".join(str(p) for p in sorted(ports)[:4])
            if len(ports) > 4:
                port_sample += ", \u2026"
            verdict = f"{emoji} {len(ports)} open port(s): {port_sample}"
        else:
            emoji = "\U0001f7e2"
            level = "clean"
            verdict = f"{emoji} Indexed, no open ports observed"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
