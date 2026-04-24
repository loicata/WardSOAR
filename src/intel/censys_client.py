"""Censys hosts-lookup client.

Censys scans the entire internet continuously and indexes TLS
certificates, open services and device fingerprints. Its strength
vs Shodan is the emphasis on **certificate-chain patterns** that
frequently fingerprint malicious infrastructure (e.g. a self-signed
cert with a specific CN used across an attacker's fleet).

Endpoint: ``GET https://search.censys.io/api/v2/hosts/{ip}``
Authentication: HTTP Basic with API ID + Secret
(env vars ``CENSYS_API_ID`` + ``CENSYS_API_SECRET``).

Paid tier: $99/month base subscription.

Response shape (relevant subset):
    {
      "code": 200,
      "result": {
        "ip": "1.2.3.4",
        "services": [
          {"port": 443, "service_name": "HTTPS",
           "certificate": "sha256:..."},
          ...
        ],
        "location": {"country": "US", "city": "..."},
        "labels": ["cloud", "..."],
        "last_updated_at": "2026-04-22T00:00:00Z"
      }
    }
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from src.intel.http_client_base import HttpReputationClient, ReputationVerdict


class CensysClient(HttpReputationClient):
    """Censys v2 ``/hosts/{ip}`` client."""

    name = "censys"
    display_name = "Censys"
    env_var = "CENSYS_API_ID"
    secondary_env_var = "CENSYS_API_SECRET"

    _URL = "https://search.censys.io/api/v2/hosts/{ip}"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
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
                level="clean",
                verdict="\U0001f7e2 Not indexed by Censys",
            )
        result = raw.get("result") or {}
        services = result.get("services") or []
        labels = result.get("labels") or []
        if not isinstance(services, list):
            services = []
        service_count = len(services)
        cert_count = sum(1 for s in services if isinstance(s, dict) and s.get("certificate"))

        suspicious_labels = [
            label
            for label in labels
            if isinstance(label, str)
            and label.lower() in ("c2", "malware", "scanning", "tor", "botnet")
        ]
        if suspicious_labels:
            return ReputationVerdict(
                level="bad",
                verdict=("\U0001f534 Suspicious label: " + ", ".join(suspicious_labels)),
                raw=raw,
            )
        if service_count == 0:
            return ReputationVerdict(
                level="clean",
                verdict="\U0001f7e2 No services observed",
                raw=raw,
            )
        verdict = f"\U0001f535 {service_count} service(s) exposed" + (
            f" ({cert_count} with TLS cert)" if cert_count else ""
        )
        return ReputationVerdict(level="info", verdict=verdict, raw=raw)
