"""VirusTotal IP-reputation client.

Wraps the public ``/api/v3/ip_addresses/{ip}`` endpoint (v3 JSON
API). The endpoint returns an aggregated view computed from 92+
antivirus / threat-intel scanners, which is why a single VT key
is the highest-value reputation signal available on a free tier.

Authentication: ``x-apikey`` header with the operator's personal
API key (env var ``VIRUSTOTAL_API_KEY``).

Rate limit: free tier is 500 lookups per day + 4 per minute. The
shared SQLite cache (24h TTL) shields us from burning the daily
quota on repetitive scans of the same IP.

Response shape (relevant subset):
    {
      "data": {
        "attributes": {
          "last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "undetected": 72,
            "harmless": 20, "timeout": 0
          },
          "country": "US",
          "as_owner": "Fastly, Inc.",
          "reputation": 0,
          "total_votes": {"harmless": 0, "malicious": 0}
        }
      }
    }
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from wardsoar.core.intel.http_client_base import HttpReputationClient, ReputationVerdict


class VirusTotalClient(HttpReputationClient):
    """VirusTotal v3 IP-reputation client."""

    name = "virustotal"
    display_name = "VirusTotal"
    env_var = "VIRUSTOTAL_API_KEY"

    _URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(
                self._URL.format(ip=ip),
                headers={"x-apikey": api_key, "accept": "application/json"},
            )
            if response.status_code == 404:
                # IP is unknown to VT — no entry yet.
                return {"_unknown": True}
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return None
            return data

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        if raw.get("_unknown"):
            return ReputationVerdict(
                level="unknown",
                verdict="VirusTotal has no record for this IP yet",
            )
        attributes = (raw.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(stats.get(k, 0) or 0) for k in stats)
        if total == 0:
            return ReputationVerdict(
                level="unknown",
                verdict="VirusTotal returned an empty analysis",
                raw=raw,
            )
        if malicious > 0:
            verdict = f"🔴 {malicious}/{total} engines flag this IP as malicious"
            level = "bad"
        elif suspicious > 0:
            verdict = f"🟠 {suspicious}/{total} engines flag this IP as suspicious"
            level = "warn"
        else:
            verdict = f"🟢 0/{total} engines flagged as malicious"
            level = "clean"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
