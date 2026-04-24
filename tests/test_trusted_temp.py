"""Tests for the short-lived trust registry.

A failure here lets the pipeline re-block an IP the user just released,
causing flap cycles. Tests cover TTL expiry, persistence across reopens,
and explicit removal.
"""

from __future__ import annotations

import time
from pathlib import Path

from src.trusted_temp import DEFAULT_TTL_SECONDS, TrustedTempRegistry


class TestTrustedTempRegistry:
    """Tests for add/is_trusted round-trips."""

    def test_empty_registry(self, tmp_path: Path) -> None:
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        assert registry.is_trusted("1.2.3.4") is False

    def test_add_then_trusted(self, tmp_path: Path) -> None:
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        registry.add("1.2.3.4", ttl_seconds=60)
        assert registry.is_trusted("1.2.3.4") is True

    def test_unknown_ip_not_trusted(self, tmp_path: Path) -> None:
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        registry.add("1.2.3.4", ttl_seconds=60)
        assert registry.is_trusted("5.6.7.8") is False

    def test_default_ttl_matches_architecture(self) -> None:
        # docs/architecture.md §4.3 mandates 30 min.
        assert DEFAULT_TTL_SECONDS == 30 * 60


class TestExpiry:
    """Tests for TTL-based expiration."""

    def test_expired_entry_returns_false(self, tmp_path: Path) -> None:
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        registry.add("1.2.3.4", ttl_seconds=0)

        # Sleep just long enough for `expiry <= now` to be true.
        time.sleep(1.1)
        assert registry.is_trusted("1.2.3.4") is False

    def test_expired_entry_is_purged(self, tmp_path: Path) -> None:
        """is_trusted() must also remove the entry after expiry."""
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        registry.add("1.2.3.4", ttl_seconds=0)
        time.sleep(1.1)

        registry.is_trusted("1.2.3.4")
        assert "1.2.3.4" not in registry.snapshot()

    def test_cleanup_expired_bulk(self, tmp_path: Path) -> None:
        registry = TrustedTempRegistry(persist_path=tmp_path / "trusted.json")
        registry.add("1.1.1.1", ttl_seconds=0)
        registry.add("2.2.2.2", ttl_seconds=0)
        registry.add("3.3.3.3", ttl_seconds=3600)
        time.sleep(1.1)

        removed = registry.cleanup_expired()
        assert removed == 2
        assert registry.is_trusted("3.3.3.3") is True


class TestPersistence:
    """Tests that the registry survives restarts."""

    def test_entries_persist_across_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "trusted.json"
        reg1 = TrustedTempRegistry(persist_path=path)
        reg1.add("10.0.0.1", ttl_seconds=3600)

        reg2 = TrustedTempRegistry(persist_path=path)
        assert reg2.is_trusted("10.0.0.1") is True

    def test_remove_is_persisted(self, tmp_path: Path) -> None:
        path = tmp_path / "trusted.json"
        reg1 = TrustedTempRegistry(persist_path=path)
        reg1.add("10.0.0.1", ttl_seconds=3600)
        reg1.remove("10.0.0.1")

        reg2 = TrustedTempRegistry(persist_path=path)
        assert reg2.is_trusted("10.0.0.1") is False

    def test_corrupt_file_does_not_raise(self, tmp_path: Path) -> None:
        """Bad JSON must not crash the constructor."""
        path = tmp_path / "trusted.json"
        path.write_text("not valid json", encoding="utf-8")

        registry = TrustedTempRegistry(persist_path=path)
        assert registry.snapshot() == {}
