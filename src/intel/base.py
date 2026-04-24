"""Common base for intelligence feed downloaders.

Every feed in :mod:`src.intel` subclasses :class:`FeedRegistry`.
The base handles the boring plumbing:

* **On-disk cache** — downloaded feeds are persisted as a JSON
  snapshot under ``%APPDATA%\\WardSOAR\\intel_feeds\\<name>.json``
  so WardSOAR re-uses the last known good data across restarts and
  never starts from an empty set.
* **Staleness check** — each feed has a refresh interval (``1h``
  for abuse.ch, ``30min`` for Blocklist.de, ``24h`` for Spamhaus).
  ``refresh_if_stale()`` triggers a download only when the cache
  is older than the interval.
* **In-memory index** — the parsed indicators are held in a ``set``
  (for IPs / hashes / URLs) with optional per-entry metadata in a
  ``dict``. ``lookup_ip(ip)`` is therefore O(1).
* **Graceful degradation** — every HTTP failure, timeout, or parse
  error is caught and logged. The registry keeps serving the last
  snapshot; the aggregator shows "unknown" or "offline" rather than
  crashing.

Subclasses only need to declare:
  * ``name``: the registry's short identifier.
  * ``display_name``: what the UI row shows.
  * ``url``: where to fetch the feed.
  * ``refresh_interval_s``: staleness threshold.
  * ``_parse(raw_text)``: turn the raw HTTP body into
    ``(indicators: set[str], meta: dict[str, FeedEntry])``.

Design rules
------------
1. Never block the Qt main thread. All network I/O goes through
   ``httpx.AsyncClient`` and is awaited from the asyncio loop owned
   by :class:`EngineWorker`. The alert-time lookup is synchronous
   and touches only the in-memory set.
2. Every feed has a hard per-download timeout (default 15s). A slow
   or offline feed must not delay the refresh cycle of the others.
3. Disk cache is written atomically (``.tmp`` + ``os.replace``) so
   a crash during download never corrupts the cached snapshot.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger("ward_soar.intel.base")


@dataclass(frozen=True)
class FeedEntry:
    """One enriched indicator in a feed (when metadata is available).

    Not every feed has per-entry metadata (Blocklist.de is just a
    bare IP list, for example). When present, the registry exposes
    it so the reputation-row verdict can quote the source's own
    classification (``"Malware: Emotet"``, ``"Bulletproof hoster:
    PonyNet"``).

    Attributes:
        indicator: The raw IP / URL / hash string.
        kind: ``"ip"``, ``"url"`` or ``"hash"``.
        category: Source-specific tag (``"botnet_cc"``, ``"malware_url"``,
            ``"brute_force"``, ...). Free-form.
        first_seen: ISO-8601 timestamp from the feed when available.
        description: Human text (malware family, campaign, ...).
        raw: Full original row for forensic retention.
    """

    indicator: str
    kind: str
    category: str = ""
    first_seen: str = ""
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class FeedRegistry:
    """Base class for all intelligence feeds.

    Args:
        cache_dir: Writable directory for the on-disk snapshot.
        http_timeout_s: Per-request HTTP timeout.
    """

    #: Short identifier for the registry. Used for the cache
    #: filename and log messages. Override in each subclass.
    name: str = "unnamed_feed"

    #: What the UI row displays. Override in each subclass.
    display_name: str = "Unnamed feed"

    #: Feed URL. Override in each subclass.
    url: str = ""

    #: Staleness threshold in seconds. ``refresh_if_stale`` triggers
    #: a download only when the last refresh is older than this.
    refresh_interval_s: int = 3600  # 1h default

    def __init__(self, cache_dir: Path, http_timeout_s: float = 15.0) -> None:
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = cache_dir / f"{self.name}.json"
        self._http_timeout_s = http_timeout_s
        self._indicators: set[str] = set()
        self._meta: dict[str, FeedEntry] = {}
        self._last_refresh_ts: Optional[float] = None
        self._last_error: Optional[str] = None
        # On-disk snapshot is loaded eagerly — the registry serves
        # stale data from boot 1 instead of an empty set while the
        # first refresh runs in the background.
        self._load_from_disk()

    # ------------------------------------------------------------------
    # Overridable hooks
    # ------------------------------------------------------------------

    def _parse(self, raw_text: str) -> tuple[set[str], dict[str, FeedEntry]]:
        """Parse the feed's raw HTTP body.

        Returns:
            A 2-tuple ``(indicators, meta)``. ``indicators`` is the
            set of raw IP / URL / hash strings used for O(1) lookup.
            ``meta`` maps each indicator to its :class:`FeedEntry`
            when per-entry metadata is available; otherwise the
            dict is empty.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def is_stale(self) -> bool:
        """Return ``True`` when the last refresh is older than the interval."""
        if self._last_refresh_ts is None:
            return True
        now = datetime.now(timezone.utc).timestamp()
        return (now - self._last_refresh_ts) >= self.refresh_interval_s

    def indicator_count(self) -> int:
        """Return the number of indicators in the in-memory index."""
        return len(self._indicators)

    def last_refresh_iso(self) -> Optional[str]:
        """Return the last-refresh timestamp as an ISO-8601 string."""
        if self._last_refresh_ts is None:
            return None
        return datetime.fromtimestamp(self._last_refresh_ts, tz=timezone.utc).isoformat(
            timespec="seconds"
        )

    def last_error(self) -> Optional[str]:
        """Return the last refresh error (if any)."""
        return self._last_error

    def lookup_ip(self, ip: str) -> Optional[FeedEntry]:
        """Look up an IP against the in-memory index.

        Returns the :class:`FeedEntry` when the IP is in the feed
        AND per-entry metadata is available; returns a synthesised
        entry (with empty metadata) when the IP is in the feed but
        the source does not expose metadata; returns ``None`` when
        the IP is absent.
        """
        if ip not in self._indicators:
            return None
        entry = self._meta.get(ip)
        if entry is not None:
            return entry
        return FeedEntry(indicator=ip, kind="ip")

    async def refresh_if_stale(self) -> bool:
        """Download + parse the feed if the cache is stale.

        Returns:
            ``True`` when a refresh ran (regardless of success),
            ``False`` when the cache is still fresh.
        """
        if not self.is_stale():
            return False
        await self.refresh()
        return True

    async def refresh(self) -> None:
        """Unconditionally download + parse the feed."""
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout_s) as client:
                logger.info("intel.%s: downloading %s", self.name, self.url)
                response = await client.get(self.url, follow_redirects=True)
                response.raise_for_status()
                indicators, meta = self._parse(response.text)
        except httpx.HTTPError as exc:
            self._last_error = f"HTTP error: {exc}"
            logger.warning("intel.%s: refresh failed: %s", self.name, exc)
            return
        except Exception as exc:  # noqa: BLE001 — defensive
            self._last_error = f"Parse error: {exc}"
            logger.exception("intel.%s: refresh failed", self.name)
            return

        self._indicators = indicators
        self._meta = meta
        self._last_refresh_ts = datetime.now(timezone.utc).timestamp()
        self._last_error = None
        self._persist_to_disk()
        logger.info(
            "intel.%s: refreshed %d indicators",
            self.name,
            len(indicators),
        )

    # ------------------------------------------------------------------
    # Disk cache
    # ------------------------------------------------------------------

    def _persist_to_disk(self) -> None:
        """Write the in-memory index to the cache file atomically."""
        payload = {
            "name": self.name,
            "url": self.url,
            "last_refresh_ts": self._last_refresh_ts,
            "indicators": sorted(self._indicators),
            "meta": {k: asdict(v) for k, v in self._meta.items()},
        }
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".tmp", dir=str(self._cache_dir))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, self._cache_file)
        except OSError:
            logger.warning(
                "intel.%s: could not persist cache to %s",
                self.name,
                self._cache_file,
                exc_info=True,
            )

    def _load_from_disk(self) -> None:
        """Populate the in-memory index from the on-disk snapshot."""
        if not self._cache_file.exists():
            return
        try:
            payload = json.loads(self._cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning(
                "intel.%s: could not read cache %s",
                self.name,
                self._cache_file,
                exc_info=True,
            )
            return
        self._indicators = set(payload.get("indicators", []))
        meta_dict = payload.get("meta", {}) or {}
        self._meta = {
            key: FeedEntry(
                indicator=data.get("indicator", key),
                kind=data.get("kind", "ip"),
                category=data.get("category", ""),
                first_seen=data.get("first_seen", ""),
                description=data.get("description", ""),
                raw=data.get("raw", {}),
            )
            for key, data in meta_dict.items()
        }
        self._last_refresh_ts = payload.get("last_refresh_ts")
        logger.debug(
            "intel.%s: loaded %d indicators from disk cache",
            self.name,
            len(self._indicators),
        )
