"""Common base for HTTP-based reputation API clients.

Every API client (VirusTotal, AbuseIPDB, GreyNoise, OTX, ...)
subclasses :class:`HttpReputationClient`. The base handles:

* **Environment-variable key lookup** — the client reads its API
  key from the env var declared in
  :mod:`src.api_keys_registry`. If the variable is empty the client
  disables itself silently: ``is_enabled()`` returns ``False`` and
  ``query_ip()`` returns ``None`` without any network I/O.
* **SQLite per-IP cache** — every successful lookup is persisted
  with a 24-hour TTL in a single shared DB under
  ``%APPDATA%\\WardSOAR\\intel_cache\\ip_reputation.db``. Subsequent
  queries for the same IP hit the cache instead of the remote
  service — essential for the free tiers (VT: 500/day, AbuseIPDB:
  1000/day, OTX/GreyNoise: rate-limited).
* **Timeout + graceful degradation** — every HTTP call has a hard
  per-request timeout; any failure (HTTP error, JSON parse error,
  auth error) returns ``None`` and is logged at WARNING level.
* **Consistent output shape** — subclasses return
  :class:`ReputationVerdict`, normalised so the aggregator can map
  it to an Alert-Detail reputation row directly.

Subclasses implement:
  * ``name`` / ``display_name`` / ``env_var`` class attrs.
  * ``async _fetch_raw(ip, api_key) -> dict`` — the HTTP call.
  * ``_verdict_from_raw(raw) -> ReputationVerdict`` — parse the
    response into a normalised verdict.

Design rules
------------
1. No HTTP on a cache hit. The SQLite cache is the first
   defence against free-tier exhaustion.
2. A missing API key is not an error. It's the operator's
   informed choice to keep a free tier unconfigured.
3. Failures never bubble out — the aggregator trusts every
   client to be silent on errors.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Optional

import httpx

logger = logging.getLogger("ward_soar.intel.http_client")


@dataclass(frozen=True)
class ReputationVerdict:
    """One client's verdict on an IP, ready for the UI row.

    Attributes:
        level: ``"clean"`` / ``"info"`` / ``"warn"`` / ``"bad"`` /
            ``"unknown"``. Drives the emoji and colour.
        verdict: Short human-readable summary (≤ 100 chars).
        raw: Full original response for forensic retention.
    """

    level: str
    verdict: str
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SQLite cache layer
# ---------------------------------------------------------------------------


class IpReputationCache:
    """Thin SQLite wrapper that stores one row per (client, ip) pair.

    The schema is single-table and client-keyed so every client
    shares the same DB file. Entries older than ``ttl_s`` are
    treated as missing; stale rows are overwritten on the next
    live fetch.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS ip_reputation (
        client_name TEXT NOT NULL,
        ip TEXT NOT NULL,
        queried_at INTEGER NOT NULL,
        result_json TEXT NOT NULL,
        PRIMARY KEY (client_name, ip)
    );
    """

    def __init__(self, db_path: Path, ttl_s: int = 24 * 3600) -> None:
        self._db_path = db_path
        self._ttl_s = ttl_s
        self._lock = Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # Initialize schema eagerly so the first query doesn't race.
        with sqlite3.connect(str(db_path)) as conn:
            conn.executescript(self._SCHEMA)
            conn.commit()

    def get(self, client_name: str, ip: str) -> Optional[ReputationVerdict]:
        """Return the cached verdict when it is still within TTL."""
        now = int(time.time())
        with self._lock, sqlite3.connect(str(self._db_path)) as conn:
            cur = conn.execute(
                "SELECT queried_at, result_json FROM ip_reputation "
                "WHERE client_name = ? AND ip = ?",
                (client_name, ip),
            )
            row = cur.fetchone()
            if row is None:
                return None
            queried_at, result_json = row
            if (now - queried_at) >= self._ttl_s:
                # ``>=`` so that ``ttl_s=0`` means "always expired"
                # (useful for tests that want to force a live fetch).
                return None
            try:
                payload = json.loads(result_json)
            except json.JSONDecodeError:
                return None
            return ReputationVerdict(
                level=str(payload.get("level", "unknown")),
                verdict=str(payload.get("verdict", "")),
                raw=dict(payload.get("raw", {})),
            )

    def put(self, client_name: str, ip: str, verdict: ReputationVerdict) -> None:
        """Persist a verdict."""
        now = int(time.time())
        payload = json.dumps(asdict(verdict))
        with self._lock, sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ip_reputation "
                "(client_name, ip, queried_at, result_json) "
                "VALUES (?, ?, ?, ?)",
                (client_name, ip, now, payload),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# Client base
# ---------------------------------------------------------------------------


class HttpReputationClient:
    """Base class for IP-reputation HTTP clients.

    Implements two protections against free-tier exhaustion
    (observed with GreyNoise on 2026-04-23 → 152 429 warnings/day):

    * **Negative cache** (per IP, in-memory): after one failure on an
      IP, skip live fetches for that IP for
      :data:`_NEGATIVE_CACHE_TTL_S` seconds. Prevents hammering the
      same dead IP every time a new alert mentions it.

    * **Circuit breaker** (per client, in-memory): after
      :data:`_CIRCUIT_BREAKER_THRESHOLD` consecutive failures,
      disable the client entirely for
      :data:`_CIRCUIT_BREAKER_COOLDOWN_S` seconds. Prevents burning
      through what's left of the daily quota once the API is
      refusing everything.

    Both states are deliberately process-local (not SQLite-backed):
    free-tier quotas typically reset on a clock boundary, so
    persisting the "disabled until" stamp across restarts would
    keep the client off even after the quota had rolled over.

    Args:
        cache: Shared :class:`IpReputationCache` (the IntelManager
            owns a single instance shared across every client).
        http_timeout_s: Per-request HTTP timeout.
    """

    #: Identifier used in the cache table. Override in each subclass.
    name: str = "unnamed_http_client"

    #: Shown in the Alert Detail row. Override in each subclass.
    display_name: str = "Unnamed HTTP client"

    #: Name of the environment variable holding the API key.
    #: Must match an entry in :data:`src.api_keys_registry.API_KEY_SPECS`.
    env_var: str = ""

    #: Optional secondary env var. Used for clients that need a
    #: key+password pair (IBM X-Force: API key + password) or
    #: an id+secret pair (Censys: API ID + secret). Leave empty
    #: for single-key clients. When set, :meth:`is_enabled`
    #: requires BOTH variables to be non-empty.
    secondary_env_var: str = ""

    #: Number of consecutive HTTP failures before the circuit opens.
    #: Override in subclasses with aggressive tiers (e.g. VirusTotal
    #: free at 4/min could justify a lower threshold).
    _CIRCUIT_BREAKER_THRESHOLD: int = 5

    #: How long the circuit stays open after it trips (seconds).
    #: 15 min matches the typical quota-reset granularity for
    #: minute- and hour-based limiters.
    _CIRCUIT_BREAKER_COOLDOWN_S: float = 15 * 60

    #: How long a per-IP failure suppresses retries (seconds). Short
    #: enough that a transient blip doesn't black-hole the IP for a
    #: whole day; long enough that a burst of alerts on one IP only
    #: causes a single 429.
    _NEGATIVE_CACHE_TTL_S: float = 15 * 60

    def __init__(self, cache: IpReputationCache, http_timeout_s: float = 10.0) -> None:
        self._cache = cache
        self._http_timeout_s = http_timeout_s
        # Circuit-breaker state (per-instance, volatile).
        self._consecutive_failures: int = 0
        self._circuit_open_until: float = 0.0  # monotonic seconds; 0 = closed
        # Per-IP negative cache: maps ip → monotonic-clock expiry.
        self._negative_cache: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Overridable hooks
    # ------------------------------------------------------------------

    async def _fetch_raw(self, ip: str, api_key: str) -> Optional[dict[str, Any]]:
        """Perform the actual HTTP call; return parsed JSON or ``None``."""
        raise NotImplementedError

    def _verdict_from_raw(self, raw: dict[str, Any]) -> ReputationVerdict:
        """Translate a raw API response into a normalised verdict."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        """Return ``True`` when the operator has configured the key.

        For two-secret clients (``secondary_env_var`` set), both
        variables must be non-empty.
        """
        if not self._current_api_key():
            return False
        if self.secondary_env_var and not self._current_api_secret():
            return False
        return True

    async def query_ip(self, ip: str) -> Optional[ReputationVerdict]:
        """Return the verdict for ``ip`` (cache-first, HTTP on miss).

        Returns ``None`` when:
          * The API key is not configured.
          * The circuit breaker is open (recent repeated failures).
          * The IP is in the negative cache (recent failure on it).
          * The HTTP call failed.
          * The parser failed.

        The aggregator treats ``None`` as "source unavailable" and
        omits the row.
        """
        key = self._current_api_key()
        if not key:
            return None

        cached = self._cache.get(self.name, ip)
        if cached is not None:
            return cached

        # Negative cache: a previous call for this IP already failed
        # recently. Skip the live fetch so we don't hammer the API on
        # every new alert that mentions the same address.
        if self._is_negatively_cached(ip):
            return None

        # Circuit breaker: too many consecutive failures. Skip without
        # hitting the network. No log here — the breaker already
        # logged once at the moment it opened.
        if self._is_circuit_open():
            return None

        try:
            raw = await self._fetch_raw(ip, key)
        except httpx.HTTPError as exc:
            # ``str(exc)`` is empty for some httpx exceptions (observed
            # on 2026-04-23 with ``intel.alienvault_otx: HTTP error on
            # X:`` — message truncated to nothing because
            # ``RemoteProtocolError()`` carries no args). Fall back to
            # the exception class name so the operator always learns
            # what went wrong rather than reading a dangling colon.
            detail = str(exc) or type(exc).__name__
            logger.warning("intel.%s: HTTP error on %s: %s", self.name, ip, detail)
            self._record_failure(ip)
            return None
        except Exception:  # noqa: BLE001 — defensive
            logger.exception("intel.%s: unexpected failure on %s", self.name, ip)
            self._record_failure(ip)
            return None

        if raw is None:
            return None

        try:
            verdict = self._verdict_from_raw(raw)
        except Exception:  # noqa: BLE001
            logger.exception("intel.%s: failed to parse response for %s", self.name, ip)
            return None

        self._cache.put(self.name, ip, verdict)
        self._record_success()
        return verdict

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _current_api_key(self) -> str:
        """Read the API key from the environment right before use.

        Re-read at every call so key changes made in the Keys tab
        take effect immediately on the next alert without requiring
        a client restart (the app still restarts on Save — but
        in-process tests can mutate ``os.environ``).
        """
        return (os.environ.get(self.env_var) or "").strip()

    def _current_api_secret(self) -> str:
        """Read the paired secret / password from the environment.

        Returns ``""`` when :attr:`secondary_env_var` is not set
        (single-secret clients).
        """
        if not self.secondary_env_var:
            return ""
        return (os.environ.get(self.secondary_env_var) or "").strip()

    # ------------------------------------------------------------------
    # Circuit breaker + negative cache
    # ------------------------------------------------------------------

    def _is_circuit_open(self) -> bool:
        """True while the client is in the breaker's cooldown window."""
        return time.monotonic() < self._circuit_open_until

    def _is_negatively_cached(self, ip: str) -> bool:
        """True when a recent failure for ``ip`` should suppress retry.

        Expired entries are pruned opportunistically on read so the
        dict cannot grow unbounded even if the breaker never opens.
        """
        expires = self._negative_cache.get(ip)
        if expires is None:
            return False
        if time.monotonic() >= expires:
            # Stale — drop and let the caller retry.
            del self._negative_cache[ip]
            return False
        return True

    def _record_failure(self, ip: str) -> None:
        """Register one failure: touch negative cache + maybe trip breaker.

        The breaker trips *exactly once* when the threshold is reached;
        subsequent failures extend nothing — the cooldown is absolute.
        This avoids permanent lockout: the operator's next manual
        retry, or the next alert after the cooldown, gets a fair try.
        """
        self._negative_cache[ip] = time.monotonic() + self._NEGATIVE_CACHE_TTL_S
        self._consecutive_failures += 1
        if self._consecutive_failures == self._CIRCUIT_BREAKER_THRESHOLD:
            self._circuit_open_until = time.monotonic() + self._CIRCUIT_BREAKER_COOLDOWN_S
            logger.warning(
                "intel.%s: circuit breaker opened after %d consecutive failures — "
                "suppressing calls for %.0fs",
                self.name,
                self._consecutive_failures,
                self._CIRCUIT_BREAKER_COOLDOWN_S,
            )

    def _record_success(self) -> None:
        """Reset breaker state after a successful fetch.

        One good response is enough to close the circuit — we trust
        the API again. The negative cache is *not* cleared here
        because each entry is per-IP and may still be legitimately
        dead (e.g. a single IP that returns 404) even if the client
        as a whole is healthy.
        """
        if self._consecutive_failures > 0 or self._circuit_open_until > 0:
            logger.info("intel.%s: circuit breaker reset after successful call", self.name)
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0


__all__ = [
    "HttpReputationClient",
    "IpReputationCache",
    "ReputationVerdict",
]
