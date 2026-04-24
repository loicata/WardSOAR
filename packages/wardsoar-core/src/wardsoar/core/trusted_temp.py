"""Short-lived trust registry for IPs just released by user rollback.

Prevents the pipeline from re-blocking an IP that the operator has
just unblocked. Without this, a rollback would flap: the same alerts
keep arriving, the pipeline keeps blocking, the user keeps rolling
back — useless churn and noise.

Each entry has its own TTL (default 30 min). Entries expire lazily on
lookup; an explicit `cleanup_expired` is also available for housekeeping.

Persisted to JSON so a WardSOAR restart does not forget user intent.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from threading import Lock

logger = logging.getLogger("ward_soar.trusted_temp")


DEFAULT_TTL_SECONDS = 30 * 60  # 30 min — matches architecture doc §4.3


class TrustedTempRegistry:
    """Persistent IP → expiry (unix seconds) map.

    Args:
        persist_path: JSON file backing the registry.
    """

    def __init__(self, persist_path: Path) -> None:
        self._path = persist_path
        self._entries: dict[str, int] = {}
        self._lock = Lock()
        self._load()

    def _load(self) -> None:
        """Read persisted entries from disk. Silent on missing or corrupt file."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._entries = {str(k): int(v) for k, v in raw.items()}
                logger.debug("Loaded %d trusted_temp entries", len(self._entries))
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning("trusted_temp: failed to load %s: %s", self._path, exc)

    def _save(self) -> None:
        """Flush to disk. Called under self._lock."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._entries, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("trusted_temp: failed to save %s: %s", self._path, exc)

    def add(self, ip: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        """Register an IP as trusted for ``ttl_seconds`` from now.

        Args:
            ip: IPv4/IPv6 address to trust temporarily.
            ttl_seconds: Lifetime in seconds.
        """
        expiry = int(time.time()) + int(ttl_seconds)
        with self._lock:
            self._entries[ip] = expiry
            self._save()
        logger.info("trusted_temp: %s trusted for %ds", ip, ttl_seconds)

    def is_trusted(self, ip: str) -> bool:
        """Return True if the IP has an unexpired entry.

        Expired entries are purged opportunistically.
        """
        now = int(time.time())
        with self._lock:
            expiry = self._entries.get(ip)
            if expiry is None:
                return False
            if expiry <= now:
                del self._entries[ip]
                self._save()
                return False
            return True

    def remove(self, ip: str) -> None:
        """Explicitly drop an IP from the registry."""
        with self._lock:
            if ip in self._entries:
                del self._entries[ip]
                self._save()

    def cleanup_expired(self) -> int:
        """Prune all expired entries. Returns the number removed."""
        now = int(time.time())
        with self._lock:
            expired = [ip for ip, exp in self._entries.items() if exp <= now]
            for ip in expired:
                del self._entries[ip]
            if expired:
                self._save()
        return len(expired)

    def snapshot(self) -> dict[str, int]:
        """Return a shallow copy of the current registry (ip → expiry)."""
        with self._lock:
            return dict(self._entries)

    def clear_all(self) -> int:
        """Drop every entry and delete the backing file.

        Intended for the post-Netgate-reset cleanup: after a factory
        reset the quarantined IPs no longer correspond to any rule on
        the Netgate, so keeping them would give the operator a false
        sense of protection.

        Returns:
            Number of entries that were present before the purge.
        """
        with self._lock:
            count = len(self._entries)
            self._entries = {}
            try:
                self._path.unlink(missing_ok=True)
            except OSError as exc:  # pragma: no cover — filesystem oddities
                logger.warning("trusted_temp: failed to delete %s: %s", self._path, exc)
        if count:
            logger.info("trusted_temp: purged %d entries (file deleted)", count)
        return count
