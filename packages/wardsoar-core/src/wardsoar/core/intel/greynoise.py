"""GreyNoise Community API client.

Endpoint: ``GET https://api.greynoise.io/v3/community/{ip}``
Authentication: ``key`` header with the operator's Community
API key (env var ``GREYNOISE_API_KEY``).

Free tier: unlimited calls with per-minute rate limit (~ 50 rpm
observed). The shared SQLite cache (24h TTL) keeps us well within
the limit under realistic SOHO loads.

Response shape:
    {
      "ip": "...",
      "noise": true,
      "riot": false,
      "classification": "benign" | "malicious" | "unknown",
      "name": "Shodan" | "Censys" | ... | "",
      "link": "...",
      "last_seen": "2026-04-22",
      "message": "Success"
    }

HTTP 404: the IP is not in GreyNoise's database \u2014 we treat it as
a positive signal (no known internet-wide scanning activity).
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from wardsoar.core.intel.http_client_base import HttpReputationClient, ReputationVerdict


class GreyNoiseClient(HttpReputationClient):
    """GreyNoise Community tier client."""

    name = "greynoise"
    display_name = "GreyNoise"
    env_var = "GREYNOISE_API_KEY"

    _URL = "https://api.greynoise.io/v3/community/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        headers = {"key": api_key, "accept": "application/json"}
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
                verdict="\U0001f7e2 Not observed scanning the internet",
            )
        classification = str(raw.get("classification") or "unknown")
        name = str(raw.get("name") or "").strip()
        noise = bool(raw.get("noise"))
        riot = bool(raw.get("riot"))
        if classification == "malicious":
            return ReputationVerdict(
                level="bad",
                verdict=(
                    "\U0001f534 Malicious internet-wide scanner"
                    + (f" (\u201c{name}\u201d)" if name else "")
                ),
                raw=raw,
            )
        if classification == "benign":
            return ReputationVerdict(
                level="info",
                verdict=(
                    "\U0001f535 \u201cBenign scanner\u201d" + (f" \u2014 {name}" if name else "")
                ),
                raw=raw,
            )
        if riot:
            return ReputationVerdict(
                level="info",
                verdict=(
                    "\U0001f535 Common internet service"
                    + (f" (\u201c{name}\u201d)" if name else "")
                ),
                raw=raw,
            )
        if noise:
            return ReputationVerdict(
                level="info",
                verdict="\U0001f535 Internet background noise",
                raw=raw,
            )
        return ReputationVerdict(
            level="clean",
            verdict="\U0001f7e2 Not observed scanning the internet",
            raw=raw,
        )
