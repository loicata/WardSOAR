"""Tests for the post-Netgate-reset cleanup helpers.

Covers the pure orchestrator in :mod:`src.netgate_reset` plus the
``clear_all`` methods it relies on in :class:`BlockTracker` and
:class:`TrustedTempRegistry`. The Pipeline + UI glue is exercised by
the existing Netgate tab tests and the integration smoke tests.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.netgate_reset import (
    NetgateResetCleanupResult,
    cleanup_netgate_state,
    default_baseline_path,
    format_result_for_display,
)
from src.pfsense_ssh import BlockTracker
from src.trusted_temp import TrustedTempRegistry

# ---------------------------------------------------------------------------
# clear_all() on the two registries
# ---------------------------------------------------------------------------


class TestBlockTrackerClearAll:
    def test_clear_all_purges_memory_and_file(self, tmp_path: Path) -> None:
        path = tmp_path / "block_tracker.json"
        tracker = BlockTracker(persist_path=path)
        tracker.record_block("203.0.113.1")
        tracker.record_block("203.0.113.2")
        assert path.is_file()

        removed = tracker.clear_all()

        assert removed == 2
        assert tracker.get_all_blocks() == {}
        assert not path.exists()

    def test_clear_all_is_idempotent_on_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "block_tracker.json"
        tracker = BlockTracker(persist_path=path)

        removed = tracker.clear_all()

        assert removed == 0
        assert tracker.get_all_blocks() == {}
        assert not path.exists()


class TestTrustedTempClearAll:
    def test_clear_all_purges_memory_and_file(self, tmp_path: Path) -> None:
        path = tmp_path / "trusted_temp.json"
        registry = TrustedTempRegistry(persist_path=path)
        registry.add("203.0.113.1", ttl_seconds=3600)
        registry.add("203.0.113.2", ttl_seconds=3600)
        assert path.is_file()

        removed = registry.clear_all()

        assert removed == 2
        assert registry.snapshot() == {}
        assert not path.exists()

    def test_clear_all_is_idempotent_on_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "trusted_temp.json"
        registry = TrustedTempRegistry(persist_path=path)

        removed = registry.clear_all()

        assert removed == 0
        assert registry.snapshot() == {}


# ---------------------------------------------------------------------------
# cleanup_netgate_state() — the orchestrator
# ---------------------------------------------------------------------------


class TestCleanupNetgateState:
    def test_cleans_everything_when_all_three_files_exist(self, tmp_path: Path) -> None:
        block_path = tmp_path / "block_tracker.json"
        trusted_path = tmp_path / "trusted_temp.json"
        baseline_path = default_baseline_path(tmp_path)

        # Populate the two registries so there is real state to purge.
        tracker = BlockTracker(persist_path=block_path)
        tracker.record_block("203.0.113.1")
        tracker.record_block("203.0.113.2")

        registry = TrustedTempRegistry(persist_path=trusted_path)
        registry.add("198.51.100.5", ttl_seconds=1800)

        # Fake baseline JSON — shape is not inspected by the cleanup.
        baseline_path.write_text(json.dumps({"entries": []}), encoding="utf-8")

        result = cleanup_netgate_state(
            block_tracker=tracker,
            trusted_temp=registry,
            baseline_path=baseline_path,
        )

        assert isinstance(result, NetgateResetCleanupResult)
        assert result.success is True
        assert result.errors == []
        assert result.baseline_removed is True
        assert result.block_entries_purged == 2
        assert result.trusted_entries_purged == 1

        # All three files are gone on disk.
        assert not baseline_path.exists()
        assert not block_path.exists()
        assert not trusted_path.exists()
        # And the in-memory state matches.
        assert tracker.get_all_blocks() == {}
        assert registry.snapshot() == {}

    def test_is_idempotent_when_called_twice(self, tmp_path: Path) -> None:
        """Second call must not error — just reports zero counters."""
        block_path = tmp_path / "block_tracker.json"
        trusted_path = tmp_path / "trusted_temp.json"
        baseline_path = default_baseline_path(tmp_path)

        tracker = BlockTracker(persist_path=block_path)
        tracker.record_block("203.0.113.1")
        registry = TrustedTempRegistry(persist_path=trusted_path)
        baseline_path.write_text("{}", encoding="utf-8")

        cleanup_netgate_state(
            block_tracker=tracker,
            trusted_temp=registry,
            baseline_path=baseline_path,
        )
        second = cleanup_netgate_state(
            block_tracker=tracker,
            trusted_temp=registry,
            baseline_path=baseline_path,
        )

        assert second.success is True
        assert second.baseline_removed is False  # already gone
        assert second.block_entries_purged == 0
        assert second.trusted_entries_purged == 0
        assert second.errors == []

    def test_missing_files_are_not_an_error(self, tmp_path: Path) -> None:
        """Calling cleanup on a pristine install returns success."""
        block_path = tmp_path / "block_tracker.json"
        trusted_path = tmp_path / "trusted_temp.json"
        baseline_path = default_baseline_path(tmp_path)

        tracker = BlockTracker(persist_path=block_path)
        registry = TrustedTempRegistry(persist_path=trusted_path)

        result = cleanup_netgate_state(
            block_tracker=tracker,
            trusted_temp=registry,
            baseline_path=baseline_path,
        )

        assert result.success is True
        assert result.errors == []
        assert result.baseline_removed is False
        assert result.block_entries_purged == 0
        assert result.trusted_entries_purged == 0


class TestFormatResultForDisplay:
    def test_success_message_ends_with_next_step(self) -> None:
        result = NetgateResetCleanupResult(
            baseline_removed=True,
            block_entries_purged=3,
            trusted_entries_purged=1,
        )
        msg = format_result_for_display(result)

        assert "baseline tamper removed" in msg
        assert "3 block record" in msg
        assert "1 quarantine" in msg
        assert "Establish baseline" in msg

    def test_empty_run_has_friendly_wording(self) -> None:
        """A cleanup that found nothing must not read as a failure."""
        msg = format_result_for_display(NetgateResetCleanupResult())

        assert "nothing to clean" in msg
        assert "Establish baseline" in msg

    def test_errors_are_surfaced(self) -> None:
        result = NetgateResetCleanupResult(
            errors=["block_tracker: disk full"],
        )
        msg = format_result_for_display(result)

        assert "with errors" in msg
        assert "disk full" in msg
