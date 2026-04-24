"""Tests for WardSOAR VirusTotal integration.

VirusTotal is HIGH (85% coverage). All API calls are mocked.
"""

import os
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.core.models import VirusTotalResult
from wardsoar.core.virustotal import VirusTotalClient

# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestVirusTotalClientInit:
    """Tests for VirusTotalClient initialization."""

    def test_disabled_when_no_api_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            client = VirusTotalClient({"enabled": True})
            assert client._enabled is False

    def test_enabled_with_api_key(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})
            assert client._enabled is True

    def test_explicitly_disabled(self) -> None:
        client = VirusTotalClient({"enabled": False})
        assert client._enabled is False

    def test_default_config(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({})
            assert client._submit_unknown is False
            assert client._max_file_size == 33_554_432


# ---------------------------------------------------------------------------
# compute_sha256 tests
# ---------------------------------------------------------------------------


class TestComputeSha256:
    """Tests for VirusTotalClient.compute_sha256."""

    def test_computes_hash(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world", encoding="utf-8")
        result = VirusTotalClient.compute_sha256(str(test_file))
        # Known SHA256 of "hello world"
        assert len(result) == 64
        assert result.isalnum()

    def test_consistent_hash(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("deterministic content", encoding="utf-8")
        hash1 = VirusTotalClient.compute_sha256(str(test_file))
        hash2 = VirusTotalClient.compute_sha256(str(test_file))
        assert hash1 == hash2

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            VirusTotalClient.compute_sha256("/nonexistent/file.txt")

    def test_empty_file_has_hash(self, tmp_path: Path) -> None:
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")
        result = VirusTotalClient.compute_sha256(str(test_file))
        assert len(result) == 64


# ---------------------------------------------------------------------------
# lookup_hash tests
# ---------------------------------------------------------------------------


class TestLookupHash:
    """Tests for VirusTotalClient.lookup_hash."""

    @pytest.mark.asyncio
    async def test_disabled_returns_none(self) -> None:
        client = VirusTotalClient({"enabled": False})
        result = await client.lookup_hash("abc123")
        assert result is None

    @pytest.mark.asyncio
    async def test_successful_lookup(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 15,
                            "undetected": 55,
                        },
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.generic",
                        },
                    }
                }
            }
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await client.lookup_hash("abc123" * 11)
            assert result is not None
            assert result.detection_count == 15
            assert result.is_malicious is True

    @pytest.mark.asyncio
    async def test_hash_not_found(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await client.lookup_hash("unknown_hash")
            assert result is None

    @pytest.mark.asyncio
    async def test_api_error_returns_none(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(side_effect=OSError("Connection failed"))
            mock_httpx.AsyncClient.return_value = mock_client

            result = await client.lookup_hash("abc123")
            assert result is None


# ---------------------------------------------------------------------------
# check_file tests
# ---------------------------------------------------------------------------


class TestCheckFile:
    """Tests for VirusTotalClient.check_file."""

    @pytest.mark.asyncio
    async def test_disabled_returns_none(self) -> None:
        client = VirusTotalClient({"enabled": False})
        result = await client.check_file("/some/file.exe")
        assert result is None

    @pytest.mark.asyncio
    async def test_file_not_found_returns_none(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})
        result = await client.check_file("/nonexistent/file.exe")
        assert result is None

    @pytest.mark.asyncio
    async def test_calls_lookup_hash(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True})

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test content")

        expected_result = VirusTotalResult(file_hash="abc", detection_count=0, is_malicious=False)
        client.lookup_hash = AsyncMock(return_value=expected_result)  # type: ignore[method-assign]

        result = await client.check_file(str(test_file))
        assert result is not None
        client.lookup_hash.assert_called_once()

    @pytest.mark.asyncio
    async def test_excluded_path_returns_none(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient(
                {
                    "enabled": True,
                    "excluded_paths": [str(tmp_path)],
                }
            )

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"content")

        result = await client.check_file(str(test_file))
        assert result is None

    @pytest.mark.asyncio
    async def test_file_too_large_returns_none(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient(
                {
                    "enabled": True,
                    "max_file_size": 10,
                }
            )

        test_file = tmp_path / "large.exe"
        test_file.write_bytes(b"x" * 100)

        result = await client.check_file(str(test_file))
        assert result is None


# ---------------------------------------------------------------------------
# Cache integration — hit / miss / rate limit
# ---------------------------------------------------------------------------


class TestCacheIntegration:
    """Verify VirusTotalClient properly delegates to VTCache.

    Uses a stub cache so tests never touch SQLite or the real API.
    """

    class _StubCache:
        """Minimal VTCache lookalike — tracks calls for assertions."""

        def __init__(self) -> None:
            self.stored: list[VirusTotalResult] = []
            self.calls_recorded: int = 0
            self.allow_calls: bool = True
            self.canned_lookup: Optional[VirusTotalResult] = None

        def lookup(self, file_hash: str) -> Optional[VirusTotalResult]:
            return self.canned_lookup

        def store(self, result: VirusTotalResult) -> None:
            self.stored.append(result)

        async def can_call_api(self) -> bool:
            return self.allow_calls

        async def record_call(self) -> None:
            self.calls_recorded += 1

    @pytest.mark.asyncio
    async def test_cache_hit_skips_api(self) -> None:
        """A cache hit must bypass httpx entirely."""
        stub = TestCacheIntegration._StubCache()
        stub.canned_lookup = VirusTotalResult(
            file_hash="h" * 64,
            detection_count=10,
            total_engines=70,
            detection_ratio=10 / 70,
            is_malicious=True,
            threat_labels=["cached"],
            lookup_type="hash",
        )

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True}, cache=stub)  # type: ignore[arg-type]

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            result = await client.lookup_hash("h" * 64)

        assert result is not None
        assert result.threat_labels == ["cached"]
        mock_httpx.AsyncClient.assert_not_called()
        assert stub.calls_recorded == 0

    @pytest.mark.asyncio
    async def test_rate_limited_skips_api(self) -> None:
        """If VTCache refuses a call (rate limit), API must not be hit."""
        stub = TestCacheIntegration._StubCache()
        stub.allow_calls = False

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True}, cache=stub)  # type: ignore[arg-type]

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            result = await client.lookup_hash("z" * 64)

        assert result is None
        mock_httpx.AsyncClient.assert_not_called()

    @pytest.mark.asyncio
    async def test_api_result_is_cached(self) -> None:
        """After a live API call, the verdict must be stored in the cache."""
        stub = TestCacheIntegration._StubCache()

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            client = VirusTotalClient({"enabled": True}, cache=stub)  # type: ignore[arg-type]

        with patch("wardsoar.core.virustotal.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "undetected": 60},
                        "popular_threat_classification": {
                            "suggested_threat_label": "adware",
                        },
                    }
                }
            }
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await client.lookup_hash("a" * 64)

        assert result is not None
        assert len(stub.stored) == 1
        assert stub.stored[0].file_hash == "a" * 64
        assert stub.calls_recorded == 1
