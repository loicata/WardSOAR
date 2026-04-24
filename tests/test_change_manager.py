"""Tests for WardSOAR configuration versioning and rollback.

ChangeManager is CRITICAL (95% coverage) — it protects configuration
integrity and enables safe rollback of any configuration change.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.change_manager import MANAGED_FILES, ChangeManager, ConfigSnapshot

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def project_root(tmp_path: Path) -> Path:
    """Create a temporary project structure with managed config files."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    prompts_dir = config_dir / "prompts"
    prompts_dir.mkdir()

    # Create all managed files with known content
    files_content = {
        "config/config.yaml": "network:\n  pfsense_ip: '192.168.1.1'\n",
        "config/whitelist.yaml": "infrastructure:\n  - ip: '192.168.1.1'\n",
        "config/known_false_positives.yaml": "suppressed_signatures: []\n",
        "config/network_baseline.yaml": "internal_services: []\n",
        "config/prompts/analyzer_system.txt": "You are a security analyst.\n",
    }
    for rel_path, content in files_content.items():
        (tmp_path / rel_path).write_text(content, encoding="utf-8")

    return tmp_path


@pytest.fixture()
def manager(project_root: Path) -> ChangeManager:
    """Create a ChangeManager with default config."""
    return ChangeManager(config={"max_snapshots": 50}, project_root=project_root)


# ---------------------------------------------------------------------------
# ConfigSnapshot tests
# ---------------------------------------------------------------------------


class TestConfigSnapshot:
    """Tests for ConfigSnapshot data structure."""

    def test_construction(self) -> None:
        now = datetime.now(timezone.utc)
        snap = ConfigSnapshot(
            snapshot_id="20260315-103000",
            created_at=now,
            description="Initial snapshot",
            files={"config.yaml": "content"},
        )
        assert snap.snapshot_id == "20260315-103000"
        assert snap.description == "Initial snapshot"
        assert "config.yaml" in snap.files


# ---------------------------------------------------------------------------
# ChangeManager.__init__ tests
# ---------------------------------------------------------------------------


class TestChangeManagerInit:
    """Tests for ChangeManager initialization."""

    def test_creates_snapshot_directory(self, tmp_path: Path) -> None:
        snapshot_dir = tmp_path / "snapshots"
        assert not snapshot_dir.exists()
        ChangeManager(config={}, project_root=tmp_path)
        assert snapshot_dir.exists()

    def test_default_max_snapshots(self, project_root: Path) -> None:
        mgr = ChangeManager(config={}, project_root=project_root)
        assert mgr._max_snapshots == 50

    def test_custom_max_snapshots(self, project_root: Path) -> None:
        mgr = ChangeManager(config={"max_snapshots": 10}, project_root=project_root)
        assert mgr._max_snapshots == 10


# ---------------------------------------------------------------------------
# create_snapshot tests
# ---------------------------------------------------------------------------


class TestCreateSnapshot:
    """Tests for ChangeManager.create_snapshot."""

    def test_creates_snapshot_with_all_files(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("Test snapshot")
        assert snap.description == "Test snapshot"
        assert len(snap.files) == len(MANAGED_FILES)
        for managed_file in MANAGED_FILES:
            assert managed_file in snap.files

    def test_snapshot_contains_correct_content(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        snap = manager.create_snapshot("Content check")
        expected = (project_root / "config/config.yaml").read_text(encoding="utf-8")
        assert snap.files["config/config.yaml"] == expected

    def test_snapshot_id_is_timestamp_based(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("ID check")
        # ID should be parseable as a timestamp-like string
        assert len(snap.snapshot_id) > 0
        assert snap.snapshot_id.replace("-", "").replace("_", "").isalnum()

    def test_snapshot_stored_on_disk(self, manager: ChangeManager, project_root: Path) -> None:
        snap = manager.create_snapshot("Disk check")
        snapshot_dir = project_root / "snapshots" / snap.snapshot_id
        assert snapshot_dir.exists()

    def test_snapshot_metadata_on_disk(self, manager: ChangeManager, project_root: Path) -> None:
        snap = manager.create_snapshot("Metadata check")
        metadata_file = project_root / "snapshots" / snap.snapshot_id / "metadata.json"
        assert metadata_file.exists()
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
        assert metadata["description"] == "Metadata check"
        assert metadata["snapshot_id"] == snap.snapshot_id

    def test_max_snapshots_enforced(self, project_root: Path) -> None:
        mgr = ChangeManager(config={"max_snapshots": 3}, project_root=project_root)
        ids = []
        for i in range(5):
            snap = mgr.create_snapshot(f"Snapshot {i}")
            ids.append(snap.snapshot_id)

        snapshots = mgr.list_snapshots()
        assert len(snapshots) <= 3
        # Most recent should be kept
        snapshot_ids = [s.snapshot_id for s in snapshots]
        assert ids[-1] in snapshot_ids

    def test_snapshot_with_missing_managed_file(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        """If a managed file is missing, snapshot should still succeed."""
        (project_root / "config/network_baseline.yaml").unlink()
        snap = manager.create_snapshot("Missing file test")
        # The missing file should not be in the snapshot
        assert "config/network_baseline.yaml" not in snap.files
        # Other files should still be captured
        assert "config/config.yaml" in snap.files


# ---------------------------------------------------------------------------
# list_snapshots tests
# ---------------------------------------------------------------------------


class TestListSnapshots:
    """Tests for ChangeManager.list_snapshots."""

    def test_empty_list(self, manager: ChangeManager) -> None:
        snapshots = manager.list_snapshots()
        assert snapshots == []

    def test_returns_snapshots_newest_first(self, manager: ChangeManager) -> None:
        manager.create_snapshot("First")
        manager.create_snapshot("Second")
        manager.create_snapshot("Third")
        snapshots = manager.list_snapshots()
        assert len(snapshots) == 3
        assert snapshots[0].description == "Third"
        assert snapshots[2].description == "First"


# ---------------------------------------------------------------------------
# get_snapshot tests
# ---------------------------------------------------------------------------


class TestGetSnapshot:
    """Tests for ChangeManager.get_snapshot."""

    def test_get_existing_snapshot(self, manager: ChangeManager) -> None:
        created = manager.create_snapshot("Get test")
        retrieved = manager.get_snapshot(created.snapshot_id)
        assert retrieved is not None
        assert retrieved.snapshot_id == created.snapshot_id
        assert retrieved.files == created.files

    def test_get_nonexistent_returns_none(self, manager: ChangeManager) -> None:
        result = manager.get_snapshot("nonexistent-id")
        assert result is None


# ---------------------------------------------------------------------------
# rollback tests
# ---------------------------------------------------------------------------


class TestRollback:
    """Tests for ChangeManager.rollback."""

    def test_rollback_restores_files(self, manager: ChangeManager, project_root: Path) -> None:
        # Take snapshot of original state
        snap = manager.create_snapshot("Before change")

        # Modify a config file
        config_file = project_root / "config/config.yaml"
        config_file.write_text("network:\n  pfsense_ip: '10.0.0.1'\n", encoding="utf-8")

        # Rollback
        result = manager.rollback(snap.snapshot_id)
        assert result is True

        # Verify file was restored
        restored = config_file.read_text(encoding="utf-8")
        assert "192.168.1.1" in restored

    def test_rollback_creates_pre_rollback_snapshot(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("Before rollback")
        manager.rollback(snap.snapshot_id)

        # Should have 2 snapshots: original + pre-rollback
        snapshots = manager.list_snapshots()
        assert len(snapshots) >= 2
        descriptions = [s.description for s in snapshots]
        assert any("rollback" in d.lower() for d in descriptions)

    def test_rollback_nonexistent_raises(self, manager: ChangeManager) -> None:
        with pytest.raises(FileNotFoundError):
            manager.rollback("nonexistent-id")


# ---------------------------------------------------------------------------
# diff tests
# ---------------------------------------------------------------------------


class TestDiff:
    """Tests for ChangeManager.diff and diff_current."""

    def test_diff_identical_snapshots(self, manager: ChangeManager) -> None:
        snap_a = manager.create_snapshot("A")
        snap_b = manager.create_snapshot("B")
        diffs = manager.diff(snap_a.snapshot_id, snap_b.snapshot_id)
        # All files should be identical, so diffs should be empty strings
        for diff_content in diffs.values():
            assert diff_content == ""

    def test_diff_detects_changes(self, manager: ChangeManager, project_root: Path) -> None:
        snap_a = manager.create_snapshot("Before")
        # Modify a file
        config_file = project_root / "config/config.yaml"
        config_file.write_text("network:\n  pfsense_ip: '10.0.0.1'\n", encoding="utf-8")
        snap_b = manager.create_snapshot("After")

        diffs = manager.diff(snap_a.snapshot_id, snap_b.snapshot_id)
        assert "config/config.yaml" in diffs
        assert diffs["config/config.yaml"] != ""
        assert "192.168.1.1" in diffs["config/config.yaml"]
        assert "10.0.0.1" in diffs["config/config.yaml"]

    def test_diff_current(self, manager: ChangeManager, project_root: Path) -> None:
        snap = manager.create_snapshot("Baseline")
        # Modify a file
        config_file = project_root / "config/config.yaml"
        config_file.write_text("network:\n  pfsense_ip: '10.0.0.1'\n", encoding="utf-8")

        diffs = manager.diff_current(snap.snapshot_id)
        assert "config/config.yaml" in diffs
        assert diffs["config/config.yaml"] != ""

    def test_diff_current_no_changes(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("No changes")
        diffs = manager.diff_current(snap.snapshot_id)
        for diff_content in diffs.values():
            assert diff_content == ""

    def test_diff_nonexistent_snapshot_a_raises(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("Exists")
        with pytest.raises(FileNotFoundError):
            manager.diff("nonexistent", snap.snapshot_id)

    def test_diff_nonexistent_snapshot_b_raises(self, manager: ChangeManager) -> None:
        snap = manager.create_snapshot("Exists")
        with pytest.raises(FileNotFoundError):
            manager.diff(snap.snapshot_id, "nonexistent")

    def test_diff_current_nonexistent_raises(self, manager: ChangeManager) -> None:
        with pytest.raises(FileNotFoundError):
            manager.diff_current("nonexistent")


# ---------------------------------------------------------------------------
# Edge case / error path tests
# ---------------------------------------------------------------------------


class TestChangeManagerEdgeCases:
    """Tests for error paths and edge cases."""

    def test_corrupt_metadata_skipped_in_list(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        """Snapshot with corrupt metadata.json should be skipped."""
        # Create a valid snapshot first
        manager.create_snapshot("Valid")

        # Create a corrupt snapshot directory
        corrupt_dir = project_root / "snapshots" / "corrupt-snapshot"
        corrupt_dir.mkdir()
        (corrupt_dir / "metadata.json").write_text("not valid json{{{", encoding="utf-8")

        snapshots = manager.list_snapshots()
        # Only the valid snapshot should be listed
        assert len(snapshots) == 1

    def test_missing_metadata_skipped_in_list(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        """Snapshot directory without metadata.json should be skipped."""
        manager.create_snapshot("Valid")

        # Create directory without metadata
        no_meta_dir = project_root / "snapshots" / "no-metadata"
        no_meta_dir.mkdir()

        snapshots = manager.list_snapshots()
        assert len(snapshots) == 1

    def test_non_directory_in_snapshots_ignored(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        """Files in the snapshots directory should be ignored."""
        manager.create_snapshot("Valid")

        # Create a stray file in snapshots/
        (project_root / "snapshots" / "stray_file.txt").write_text("junk", encoding="utf-8")

        snapshots = manager.list_snapshots()
        assert len(snapshots) == 1

    def test_get_snapshot_with_corrupt_metadata(
        self, manager: ChangeManager, project_root: Path
    ) -> None:
        """get_snapshot should return None if metadata is corrupt."""
        corrupt_dir = project_root / "snapshots" / "corrupt-id"
        corrupt_dir.mkdir()
        (corrupt_dir / "metadata.json").write_text("{bad json", encoding="utf-8")

        result = manager.get_snapshot("corrupt-id")
        assert result is None

    def test_snapshot_dir_does_not_exist(self, tmp_path: Path) -> None:
        """list_snapshots should handle missing snapshot directory."""
        mgr = ChangeManager(config={}, project_root=tmp_path)
        # Delete the snapshot dir that __init__ created
        import shutil

        shutil.rmtree(tmp_path / "snapshots")
        assert mgr.list_snapshots() == []
