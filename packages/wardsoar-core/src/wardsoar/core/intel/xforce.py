"""IBM X-Force Exchange IP-reputation client.

Endpoint: ``GET https://api.xforce.ibmcloud.com/api/ipr/{ip}``
Authentication: HTTP Basic with ``api-key`` / ``api-password``
(env vars ``XFORCE_API_KEY`` + ``XFORCE_API_PASSWORD``).

Free tier: 5 000 API calls per month per account. The shared
SQLite cache keeps repeat queries off the wire.

Response shape (relevant subset):
    {
      "ip": "1.2.3.4",
      "score": 4.5,
      "reason": "Regional Internet Registry",
      "reasonDescription": "...",
      "cats": {"Spam": 50, "Botnet_C_and_C_Servers": 80},
      "geo": {"country": "US", "countrycode": "US"},
      "subnets": [...]
    }

Scoring guide per IBM X-Force docs:
  *   1   → safe / regional registry allocation
  *   2\u20133 → low risk (informational)
  *   4\u20135 → medium risk
  *   6\u201310 → high risk / confirmed malicious
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from wardsoar.core.intel.http_client_base import HttpReputationClient, ReputationVerdict


class XForceClient(HttpReputationClient):
    """IBM X-Force Exchange client."""

    name = "xforce"
    display_name = "IBM X-Force"
    env_var = "XFORCE_API_KEY"
    secondary_env_var = "XFORCE_API_PASSWORD"

    _URL = "https://api.xforce.ibmcloud.com/api/ipr/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        # HTTP Basic Auth: key = user, password = companion secret.
        auth = httpx.BasicAuth(username=api_key, password=self._current_api_secret())
        headers = {"accept": "application/json"}
        async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
            response = await client.get(self._URL.format(ip=ip), headers=headers, auth=auth)
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
                level="unknown",
                verdict="IBM X-Force has no record for this IP",
            )
        score = float(raw.get("score", 0) or 0)
        cats = raw.get("cats") or {}
        top_category = ""
        if isinstance(cats, dict) and cats:
            # Pick the highest-confidence category as the label.
            sorted_cats = sorted(
                cats.items(),
                key=lambda kv: float(kv[1] or 0),
                reverse=True,
            )
            top_category = str(sorted_cats[0][0]).replace("_", " ")

        if score >= 6:
            level = "bad"
            emoji = "\U0001f534"
        elif score >= 4:
            level = "warn"
            emoji = "\U0001f7e0"
        elif score >= 2:
            level = "info"
            emoji = "\U0001f535"
        else:
            level = "clean"
            emoji = "\U0001f7e2"
        verdict = f"{emoji} Risk score {score:.1f} / 10"
        if top_category:
            verdict = f"{verdict} \u2014 \u201c{top_category}\u201d"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
