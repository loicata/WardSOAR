"""AlienVault OTX IP-reputation client.

Endpoint: ``GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general``
Authentication: ``X-OTX-API-KEY`` header with the operator's
API key (env var ``OTX_API_KEY``).

Free tier: unlimited, community-powered. Every registered user can
publish "pulses" (threat-intel packages) that tag indicators with
context. ``pulse_info.count`` \u2014 how many active pulses mention
this IP \u2014 is the primary signal.

Response shape (relevant subset):
    {
      "pulse_info": {
        "count": 3,
        "pulses": [
          {"name": "Emotet IOCs 2026-04", ...},
          ...
        ]
      },
      "reputation": 0,
      "country_name": "US",
      "asn": "AS54113 Fastly, Inc."
    }
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from wardsoar.core.intel.http_client_base import HttpReputationClient, ReputationVerdict


class AlienVaultOtxClient(HttpReputationClient):
    """AlienVault OTX (AT&T) IP-reputation client."""

    name = "alienvault_otx"
    display_name = "AlienVault OTX"
    env_var = "OTX_API_KEY"

    _URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        headers = {"X-OTX-API-KEY": api_key, "accept": "application/json"}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL.format(ip=ip), headers=headers)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return None
            return data

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        pulse_info = raw.get("pulse_info") or {}
        count = int(pulse_info.get("count", 0) or 0)
        pulses = pulse_info.get("pulses") or []
        if count == 0:
            return ReputationVerdict(
                level="clean",
                verdict="\U0001f7e2 0 active threat pulses",
                raw=raw,
            )
        # Quote the most recent pulse name when available.
        first_pulse_name: str = ""
        if isinstance(pulses, list) and pulses:
            first = pulses[0]
            if isinstance(first, dict):
                first_pulse_name = str(first.get("name") or "").strip()
        level = "bad" if count >= 3 else "warn"
        emoji = "\U0001f534" if level == "bad" else "\U0001f7e0"
        verdict = f"{emoji} {count} active threat pulse(s)"
        if first_pulse_name:
            # Trim to keep the UI row short.
            snippet = first_pulse_name[:60] + ("\u2026" if len(first_pulse_name) > 60 else "")
            verdict = f"{verdict} \u2014 \u201c{snippet}\u201d"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
