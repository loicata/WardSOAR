"""Project Honey Pot HTTP:BL (DNSBL) client.

Project Honey Pot exposes its reputation data through DNS queries
rather than a REST API. For an IP ``a.b.c.d``, the client queries:

    ``{access_key}.{d}.{c}.{b}.{a}.dnsbl.httpbl.org``

and interprets the A record that comes back:

    ``127.X.Y.Z``

Where:
  * ``X`` \u2014 days since the IP was last observed (0\u2013255).
  * ``Y`` \u2014 threat score (0\u2013255; higher = worse).
  * ``Z`` \u2014 visitor type bitmask:
      ``0`` = search engine, ``1`` = suspicious, ``2`` = harvester,
      ``4`` = comment spammer, ``1+2+4`` = combined.

NXDOMAIN means the IP is not listed \u2014 a positive signal.

Because Project Honey Pot is DNS-based, we do not use ``httpx``.
We perform the lookup through :func:`socket.gethostbyname` with a
short timeout so a slow resolver does not block the alert pipeline.

Signup: https://www.projecthoneypot.org/create_account.php (free).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Optional

from src.intel.http_client_base import HttpReputationClient, ReputationVerdict


def _reverse_ip(ip: str) -> Optional[str]:
    """Turn ``a.b.c.d`` into ``d.c.b.a`` for DNSBL lookup.

    Returns ``None`` for IPv6 or malformed input (DNSBL is v4 only).
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ValueError, ipaddress.AddressValueError):
        return None
    parts = str(addr).split(".")
    return ".".join(reversed(parts))


def _visitor_type_label(z: int) -> str:
    """Translate the bitmask ``Z`` byte into a short label."""
    if z == 0:
        return "search engine"
    parts = []
    if z & 1:
        parts.append("suspicious")
    if z & 2:
        parts.append("harvester")
    if z & 4:
        parts.append("comment spammer")
    return " + ".join(parts) if parts else f"type {z}"


class ProjectHoneyPotClient(HttpReputationClient):
    """Project Honey Pot HTTP:BL client over DNS."""

    name = "project_honey_pot"
    display_name = "Project Honey Pot"
    env_var = "HONEYPOT_API_KEY"

    _BL_SUFFIX = "dnsbl.httpbl.org"

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        reversed_ip = _reverse_ip(ip)
        if not reversed_ip:
            return {"_unsupported": True}

        # Project Honey Pot is DNSBL-only \u2014 httpx.AsyncClient is
        # unused. ``gethostbyname`` is synchronous; we keep the
        # timeout short so a slow resolver never stalls the alert.
        query = f"{api_key}.{reversed_ip}.{self._BL_SUFFIX}"
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(min(self._http_timeout_s, 5.0))
            resolved = socket.gethostbyname(query)
        except socket.gaierror:
            # NXDOMAIN = IP not listed. Safe IP.
            return {"_not_listed": True}
        except OSError:
            return None
        finally:
            socket.setdefaulttimeout(prev_timeout)

        # Parse the 127.X.Y.Z response.
        parts = resolved.split(".")
        if len(parts) != 4 or parts[0] != "127":
            return {"_invalid_response": resolved}
        try:
            days = int(parts[1])
            threat = int(parts[2])
            visitor_type = int(parts[3])
        except ValueError:
            return {"_invalid_response": resolved}
        return {
            "days": days,
            "threat": threat,
            "visitor_type": visitor_type,
            "raw_answer": resolved,
        }

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        if raw.get("_not_listed"):
            return ReputationVerdict(
                level="clean",
                verdict="\U0001f7e2 Not listed as spammer / harvester",
            )
        if raw.get("_unsupported"):
            return ReputationVerdict(
                level="unknown",
                verdict="Project Honey Pot only indexes IPv4",
            )
        if raw.get("_invalid_response"):
            return ReputationVerdict(
                level="unknown",
                verdict=f"Malformed DNSBL answer: {raw['_invalid_response']}",
            )
        threat = int(raw.get("threat", 0))
        days = int(raw.get("days", 0))
        visitor_type = int(raw.get("visitor_type", 0))
        label = _visitor_type_label(visitor_type)
        if threat >= 128:
            level = "bad"
            emoji = "\U0001f534"
        elif threat >= 32:
            level = "warn"
            emoji = "\U0001f7e0"
        elif threat > 0:
            level = "info"
            emoji = "\U0001f535"
        else:
            level = "info"
            emoji = "\U0001f535"
        verdict = f"{emoji} {label} (threat {threat}/255, last seen {days}d ago)"
        return ReputationVerdict(level=level, verdict=verdict, raw=raw)
