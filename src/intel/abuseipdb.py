"""AbuseIPDB IP-reputation client.

Endpoint: ``GET https://api.abuseipdb.com/api/v2/check``
Authentication: ``Key`` header with the operator's API key
(env var ``ABUSEIPDB_API_KEY``).

Free tier: 1 000 checks per day. The shared SQLite cache (24h TTL)
keeps the quota unburdened even on chatty honeypot feeds.

Response shape (relevant subset):
    {
      "data": {
        "ipAddress": "...",
        "abuseConfidenceScore": 0,
        "countryCode": "FR",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "OVH SAS",
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": null
      }
    }

Scoring guide per AbuseIPDB documentation:
  *  0\u201325 → clean
  * 26\u201349 → suspicious
  * 50\u201374 → malicious
  * 75\u2013100 → highly malicious
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from src.intel.http_client_base import HttpReputationClient, ReputationVerdict


class AbuseIpDbClient(HttpReputationClient):
    """AbuseIPDB v2 IP-reputation client."""

    name = "abuseipdb"
    display_name = "AbuseIPDB"
    env_var = "ABUSEIPDB_API_KEY"

    _URL = "https://api.abuseipdb.com/api/v2/check"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        headers = {"Key": api_key, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return None
            return data

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        data = raw.get("data") or {}
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)
        if score >= 75:
            level = "bad"
            emoji = "\U0001f534"
        elif score >= 50:
            level = "bad"
            emoji = "\U0001f534"
        elif score >= 26:
            level = "warn"
            emoji = "\U0001f7e0"
        elif reports > 0:
            level = "info"
            emoji = "\U0001f535"
        else:
            level = "clean"
            emoji = "\U0001f7e2"
        verdict = f"{emoji} {score}/100 confidence \u2014 {reports} reports (last 90d)"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
