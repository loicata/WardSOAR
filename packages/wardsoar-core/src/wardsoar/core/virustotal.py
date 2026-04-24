"""VirusTotal API integration for hash lookup and file submission.

Uses the free tier API (500 requests/day, 4 requests/minute).
Always performs hash lookup first to avoid unnecessary uploads.
WARNING: Files uploaded to VirusTotal become publicly accessible.

Fail-safe: if the API is unavailable, return None and continue.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Optional

import httpx
from httpx import HTTPError

from wardsoar.core.models import VirusTotalResult
from wardsoar.core.vt_cache import VTCache

logger = logging.getLogger("ward_soar.virustotal")

# Free tier rate limits
VT_MAX_REQUESTS_PER_MINUTE = 4
VT_MAX_REQUESTS_PER_DAY = 500
VT_MAX_FILE_SIZE = 33_554_432  # 32 MB
VT_API_BASE = "https://www.virustotal.com/api/v3"

# Detection threshold: above this ratio, file is considered malicious
MALICIOUS_THRESHOLD = 0.1


class VirusTotalClient:
    """Client for VirusTotal API v3 (free tier).

    Args:
        config: VirusTotal configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any], cache: Optional[VTCache] = None) -> None:
        self._config = config
        self._api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._enabled: bool = config.get("enabled", True)
        self._submit_unknown: bool = config.get("submit_unknown_files", False)
        self._max_file_size: int = config.get("max_file_size", VT_MAX_FILE_SIZE)
        self._excluded_paths: list[str] = config.get("excluded_paths", [])

        if self._enabled and not self._api_key:
            logger.warning("VirusTotal API key not set — module disabled")
            self._enabled = False

        # Cache + rate limiter. Injected by the Pipeline so tests can swap
        # in a temp-path instance. If None, caching is disabled (each lookup
        # hits the API — only suitable for ephemeral tests).
        self._cache: Optional[VTCache] = cache

    async def lookup_hash(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Look up a file hash on VirusTotal, using the local cache when possible.

        Flow:
            1. Cache hit → return cached verdict (no API call, no hash leak).
            2. Cache miss → check rate limit; if exceeded, return None (fail-safe).
            3. Call VT API → cache the result on success.

        Args:
            file_hash: SHA256 hash of the file.

        Returns:
            VirusTotalResult if found (cache or live), None otherwise.
        """
        if not self._enabled:
            return None

        # Step 1 — cache lookup
        if self._cache is not None:
            cached = self._cache.lookup(file_hash)
            if cached is not None:
                logger.debug("VT cache hit for %s", file_hash[:16])
                return cached

        # Step 2 — rate limit check
        if self._cache is not None and not await self._cache.can_call_api():
            logger.info("VT API call skipped (rate limit) for %s", file_hash[:16])
            return None

        # Step 3 — live API call
        url = f"{VT_API_BASE}/files/{file_hash}"
        headers = {"x-apikey": self._api_key}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=30)
            if self._cache is not None:
                await self._cache.record_call()

            if response.status_code == 404:
                logger.info("Hash not found in VirusTotal: %s", file_hash[:16])
                return None

            if response.status_code != 200:
                logger.warning(
                    "VirusTotal API error: status %d for hash %s",
                    response.status_code,
                    file_hash[:16],
                )
                return None

            result = self._parse_lookup_response(file_hash, response.json())
        except (HTTPError, OSError, ValueError):
            logger.warning("VirusTotal lookup failed for hash %s", file_hash[:16])
            return None

        # Cache the verdict for future queries
        if self._cache is not None:
            self._cache.store(result)
        return result

    def _parse_lookup_response(self, file_hash: str, data: dict[str, Any]) -> VirusTotalResult:
        """Parse a VirusTotal API lookup response.

        Args:
            file_hash: The queried hash.
            data: Parsed JSON response from the API.

        Returns:
            VirusTotalResult with parsed detection data.
        """
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + undetected

        detection_ratio = malicious / total if total > 0 else 0.0

        threat_labels: list[str] = []
        classification = attrs.get("popular_threat_classification", {})
        label = classification.get("suggested_threat_label")
        if label:
            threat_labels.append(str(label))

        return VirusTotalResult(
            file_hash=file_hash,
            detection_count=malicious,
            total_engines=total,
            detection_ratio=detection_ratio,
            is_malicious=detection_ratio >= MALICIOUS_THRESHOLD,
            threat_labels=threat_labels,
            lookup_type="hash",
        )

    async def check_file(self, file_path: str) -> Optional[VirusTotalResult]:
        """Check a file: hash lookup first, then optional submission.

        Args:
            file_path: Path to the file to check.

        Returns:
            VirusTotalResult if available, None otherwise.
        """
        if not self._enabled:
            return None

        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found for VT check: %s", file_path)
            return None

        # Check excluded paths
        for excluded in self._excluded_paths:
            if str(path).startswith(excluded):
                logger.info("File in excluded path, skipping VT check: %s", file_path)
                return None

        # Check file size
        file_size = path.stat().st_size
        if file_size > self._max_file_size:
            logger.info(
                "File too large for VT check (%d bytes > %d max): %s",
                file_size,
                self._max_file_size,
                file_path,
            )
            return None

        # Compute hash and lookup
        file_hash = self.compute_sha256(file_path)
        return await self.lookup_hash(file_hash)

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        """Compute SHA256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hex-encoded SHA256 hash string.

        Raises:
            FileNotFoundError: If file does not exist.
            PermissionError: If file cannot be read.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
