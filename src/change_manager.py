"""Configuration versioning, snapshots, and undo/rollback.

Every configuration change is versioned. The user can view the history
of changes, diff any two versions, and rollback to any previous state.
This includes all YAML config files and external prompt files.

Snapshots are stored as timestamped copies in the snapshots/ directory.
"""

from __future__ import annotations

import difflib
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("ward_soar.change_manager")

MANAGED_FILES = [
    "config/config.yaml",
    "config/whitelist.yaml",
    "config/known_false_positives.yaml",
    "config/network_baseline.yaml",
    "config/prompts/analyzer_system.txt",
]

METADATA_FILENAME = "metadata.json"


class ConfigSnapshot:
    """A versioned snapshot of all configuration files.

    Attributes:
        snapshot_id: Unique identifier (timestamp-based).
        created_at: When the snapshot was taken.
        description: Human-readable reason for the change.
        files: Dict of filename -> content at snapshot time.
    """

    def __init__(
        self,
        snapshot_id: str,
        created_at: datetime,
        description: str,
        files: dict[str, str],
    ) -> None:
        self.snapshot_id = snapshot_id
        self.created_at = created_at
        self.description = description
        self.files = files


class ChangeManager:
    """Manage configuration versioning and rollback.

    Args:
        config: ChangeManager configuration dict.
        project_root: Path to the project root directory.
    """

    def __init__(self, config: dict[str, Any], project_root: Path) -> None:
        self._project_root = project_root
        self._snapshot_dir = project_root / "snapshots"
        self._max_snapshots: int = config.get("max_snapshots", 50)
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)

    def _generate_snapshot_id(self) -> str:
        """Generate a unique timestamp-based snapshot ID.

        Returns:
            String in format YYYYMMDD-HHMMSS-ffffff.
        """
        now = datetime.now(timezone.utc)
        return now.strftime("%Y%m%d-%H%M%S-%f")

    def _read_managed_files(self) -> dict[str, str]:
        """Read all managed configuration files that exist.

        Returns:
            Dict of relative path -> file content. Missing files are skipped.
        """
        files: dict[str, str] = {}
        for rel_path in MANAGED_FILES:
            full_path = self._project_root / rel_path
            if full_path.exists():
                files[rel_path] = full_path.read_text(encoding="utf-8")
            else:
                logger.warning("Managed file not found, skipping: %s", rel_path)
        return files

    def _write_snapshot_to_disk(self, snapshot: ConfigSnapshot) -> None:
        """Persist a snapshot to the snapshots directory.

        Args:
            snapshot: The snapshot to write.
        """
        snap_dir = self._snapshot_dir / snapshot.snapshot_id
        snap_dir.mkdir(parents=True, exist_ok=True)

        # Write each managed file
        for rel_path, content in snapshot.files.items():
            target = snap_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        # Write metadata
        metadata = {
            "snapshot_id": snapshot.snapshot_id,
            "created_at": snapshot.created_at.isoformat(),
            "description": snapshot.description,
            "files": list(snapshot.files.keys()),
        }
        metadata_path = snap_dir / METADATA_FILENAME
        metadata_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _enforce_max_snapshots(self) -> None:
        """Delete oldest snapshots if count exceeds max_snapshots."""
        snapshots = self.list_snapshots()
        if len(snapshots) <= self._max_snapshots:
            return

        # snapshots are sorted newest first, so trim from the end
        to_delete = snapshots[self._max_snapshots :]
        for snap in to_delete:
            snap_dir = self._snapshot_dir / snap.snapshot_id
            if snap_dir.exists():
                shutil.rmtree(snap_dir)
                logger.info("Deleted old snapshot: %s", snap.snapshot_id)

    def _load_metadata(self, snap_dir: Path) -> Optional[dict[str, Any]]:
        """Load snapshot metadata from a directory.

        Args:
            snap_dir: Path to the snapshot directory.

        Returns:
            Parsed metadata dict, or None if file is missing/corrupt.
        """
        metadata_path = snap_dir / METADATA_FILENAME
        if not metadata_path.exists():
            return None
        try:
            return json.loads(metadata_path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError):
            logger.warning("Corrupt metadata in snapshot: %s", snap_dir.name)
            return None

    def create_snapshot(self, description: str) -> ConfigSnapshot:
        """Create a snapshot of all managed configuration files.

        MUST be called BEFORE any configuration modification.

        Args:
            description: Human-readable reason for the change.

        Returns:
            The created ConfigSnapshot.
        """
        snapshot_id = self._generate_snapshot_id()
        created_at = datetime.now(timezone.utc)
        files = self._read_managed_files()

        snapshot = ConfigSnapshot(
            snapshot_id=snapshot_id,
            created_at=created_at,
            description=description,
            files=files,
        )

        self._write_snapshot_to_disk(snapshot)
        self._enforce_max_snapshots()

        logger.info(
            "Created snapshot %s: %s (%d files)",
            snapshot_id,
            description,
            len(files),
        )
        return snapshot

    def list_snapshots(self) -> list[ConfigSnapshot]:
        """List all available snapshots, newest first.

        Returns:
            List of ConfigSnapshot metadata (without file contents).
        """
        snapshots: list[ConfigSnapshot] = []

        if not self._snapshot_dir.exists():
            return snapshots

        for snap_dir in self._snapshot_dir.iterdir():
            if not snap_dir.is_dir():
                continue

            metadata = self._load_metadata(snap_dir)
            if metadata is None:
                continue

            snapshots.append(
                ConfigSnapshot(
                    snapshot_id=metadata["snapshot_id"],
                    created_at=datetime.fromisoformat(metadata["created_at"]),
                    description=metadata["description"],
                    files={},  # Metadata only, no file contents
                )
            )

        # Sort newest first
        snapshots.sort(key=lambda s: s.created_at, reverse=True)
        return snapshots

    def get_snapshot(self, snapshot_id: str) -> Optional[ConfigSnapshot]:
        """Load a specific snapshot by ID.

        Args:
            snapshot_id: The snapshot identifier.

        Returns:
            Full ConfigSnapshot with file contents, or None if not found.
        """
        snap_dir = self._snapshot_dir / snapshot_id
        if not snap_dir.exists():
            return None

        metadata = self._load_metadata(snap_dir)
        if metadata is None:
            return None

        # Read file contents
        files: dict[str, str] = {}
        for rel_path in metadata.get("files", []):
            file_path = snap_dir / rel_path
            if file_path.exists():
                files[rel_path] = file_path.read_text(encoding="utf-8")

        return ConfigSnapshot(
            snapshot_id=metadata["snapshot_id"],
            created_at=datetime.fromisoformat(metadata["created_at"]),
            description=metadata["description"],
            files=files,
        )

    def rollback(self, snapshot_id: str) -> bool:
        """Rollback all configuration to a previous snapshot.

        Creates a new snapshot of the CURRENT state before rolling back,
        so the rollback itself is reversible.

        Args:
            snapshot_id: The snapshot to restore.

        Returns:
            True if rollback succeeded.

        Raises:
            FileNotFoundError: If snapshot_id does not exist.
        """
        target = self.get_snapshot(snapshot_id)
        if target is None:
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")

        # Create a safety snapshot before rollback
        self.create_snapshot(f"Pre-rollback backup (restoring {snapshot_id})")

        # Restore each file from the target snapshot
        for rel_path, content in target.files.items():
            full_path = self._project_root / rel_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")

        logger.info("Rolled back to snapshot %s: %s", snapshot_id, target.description)
        return True

    def _compute_file_diff(self, content_a: str, content_b: str, filename: str) -> str:
        """Compute unified diff between two file contents.

        Args:
            content_a: Content of file version A.
            content_b: Content of file version B.
            filename: Name of the file (for diff header).

        Returns:
            Unified diff string, or empty string if identical.
        """
        lines_a = content_a.splitlines(keepends=True)
        lines_b = content_b.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )
        return "".join(diff_lines)

    def diff(self, snapshot_id_a: str, snapshot_id_b: str) -> dict[str, str]:
        """Compute diff between two snapshots.

        Args:
            snapshot_id_a: First snapshot ID.
            snapshot_id_b: Second snapshot ID.

        Returns:
            Dict of filename -> unified diff string.

        Raises:
            FileNotFoundError: If either snapshot does not exist.
        """
        snap_a = self.get_snapshot(snapshot_id_a)
        snap_b = self.get_snapshot(snapshot_id_b)
        if snap_a is None:
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id_a}")
        if snap_b is None:
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id_b}")

        all_files = set(snap_a.files.keys()) | set(snap_b.files.keys())
        diffs: dict[str, str] = {}
        for filename in sorted(all_files):
            content_a = snap_a.files.get(filename, "")
            content_b = snap_b.files.get(filename, "")
            diffs[filename] = self._compute_file_diff(content_a, content_b, filename)

        return diffs

    def diff_current(self, snapshot_id: str) -> dict[str, str]:
        """Compute diff between a snapshot and the current configuration.

        Args:
            snapshot_id: Snapshot to compare against current state.

        Returns:
            Dict of filename -> unified diff string.

        Raises:
            FileNotFoundError: If snapshot does not exist.
        """
        snap = self.get_snapshot(snapshot_id)
        if snap is None:
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")

        current_files = self._read_managed_files()
        all_files = set(snap.files.keys()) | set(current_files.keys())
        diffs: dict[str, str] = {}
        for filename in sorted(all_files):
            content_snap = snap.files.get(filename, "")
            content_current = current_files.get(filename, "")
            diffs[filename] = self._compute_file_diff(content_snap, content_current, filename)

        return diffs
