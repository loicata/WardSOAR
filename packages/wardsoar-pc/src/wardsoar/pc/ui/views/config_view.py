"""Configuration tab — edit config, view snapshots, rollback.

Provides YAML editor, snapshot history, diff viewer,
and rollback functionality via ChangeManager.

Uses PyQt-Fluent-Widgets for Windows 11 Fluent Design.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QListWidgetItem,
    QMessageBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    Dialog,
    ListWidget,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SimpleCardWidget,
    SubtitleLabel,
)

import yaml as _yaml

from wardsoar.core.change_manager import ChangeManager
from wardsoar.core.config import get_data_dir

logger = logging.getLogger("ward_soar.ui.config_view")

# Config files available for editing
CONFIG_FILES = [
    "config/config.yaml",
    "config/whitelist.yaml",
    "config/known_false_positives.yaml",
    "config/network_baseline.yaml",
    "config/prompts/analyzer_system.txt",
]


class DiffDialog(Dialog):  # type: ignore[misc]
    """Side-by-side diff viewer for comparing config versions.

    Args:
        before: Content of the previous version.
        after: Content of the current version.
        parent: Parent widget.
    """

    def __init__(self, before: str, after: str, parent: Optional[QWidget] = None) -> None:
        super().__init__("Configuration Diff", "", parent)
        self.setFixedSize(1200, 700)

        # Add two text editors side by side
        content = QWidget()
        layout = QHBoxLayout(content)

        before_section = QVBoxLayout()
        before_section.addWidget(SubtitleLabel("Before"))
        before_editor = PlainTextEdit()
        before_editor.setReadOnly(True)
        before_editor.setPlainText(before)
        before_editor.setFont(QFont("Consolas", 10))
        before_section.addWidget(before_editor)
        layout.addLayout(before_section)

        after_section = QVBoxLayout()
        after_section.addWidget(SubtitleLabel("After"))
        after_editor = PlainTextEdit()
        after_editor.setReadOnly(True)
        after_editor.setPlainText(after)
        after_editor.setFont(QFont("Consolas", 10))
        after_section.addWidget(after_editor)
        layout.addLayout(after_section)

        self.textLayout.addWidget(content)


class ConfigView(QWidget):
    """Configuration editor with snapshot history and rollback.

    Also exposes two quick-access spinboxes for the Responder decision
    thresholds — the numbers operators realistically want to tune in
    the field — so they do not have to hand-edit YAML for a routine
    calibration.

    Signals:
        threshold_changed: ``(mode_name, value)`` — emitted when the
            user edits one of the quick-access spinboxes. ``mode_name``
            is ``"protect"`` or ``"hard_protect"``. Connected by the
            application to the live Responder so changes take effect
            without a restart.

    Args:
        parent: Parent widget.
    """

    threshold_changed = Signal(str, float)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._is_modified = False
        # Suppressed during programmatic population of the spinboxes at
        # load time, otherwise every ``setValue`` would flash a fake
        # "threshold changed" event to the live pipeline.
        self._suppress_threshold_signals = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # --- Quick thresholds card (top) -------------------------------
        # The two numbers the operator most often retunes in the field.
        # Exposing them as spinboxes (rather than requiring a YAML
        # edit) keeps the calibration loop short: observe FP rate →
        # tweak → observe again.
        thresh_card = SimpleCardWidget()
        thresh_layout = QGridLayout(thresh_card)
        thresh_layout.setContentsMargins(16, 12, 16, 12)
        thresh_layout.setHorizontalSpacing(12)
        thresh_layout.setVerticalSpacing(6)

        thresh_layout.addWidget(SubtitleLabel("Response thresholds"), 0, 0, 1, 2)

        # --- Protect mode: "prouve qu'il faut bloquer" -----------------
        thresh_layout.addWidget(
            BodyLabel("Protect mode — minimum confidence to trigger a block"), 1, 0
        )
        self._protect_spin = QDoubleSpinBox()
        self._protect_spin.setRange(0.50, 0.99)
        self._protect_spin.setDecimals(2)
        self._protect_spin.setSingleStep(0.01)
        self._protect_spin.setValue(0.70)
        self._protect_spin.setFixedWidth(96)
        self._protect_spin.valueChanged.connect(self._on_protect_threshold_changed)
        thresh_layout.addWidget(self._protect_spin, 1, 1)
        thresh_layout.addWidget(
            CaptionLabel(
                "Blocks when the verdict is CONFIRMED and confidence ≥ this threshold. "
                "Higher = fewer blocks."
            ),
            2,
            0,
            1,
            2,
        )

        # --- Hard Protect mode: "prouve qu'il ne faut pas bloquer" ------
        thresh_layout.addWidget(
            BodyLabel("Hard Protect mode — minimum BENIGN confidence to spare a block"),
            3,
            0,
        )
        self._hp_spin = QDoubleSpinBox()
        self._hp_spin.setRange(0.80, 0.99)
        self._hp_spin.setDecimals(2)
        self._hp_spin.setSingleStep(0.01)
        self._hp_spin.setValue(0.99)
        self._hp_spin.setFixedWidth(96)
        self._hp_spin.valueChanged.connect(self._on_hard_protect_threshold_changed)
        thresh_layout.addWidget(self._hp_spin, 3, 1)
        thresh_layout.addWidget(
            CaptionLabel(
                "Skips the block when the verdict is BENIGN and confidence ≥ this "
                "threshold. Higher = more blocks (stricter)."
            ),
            4,
            0,
            1,
            2,
        )

        layout.addWidget(thresh_card)

        # File selector
        file_row = QHBoxLayout()
        file_row.addWidget(BodyLabel("File:"))
        self._file_selector = ComboBox()
        self._file_selector.addItems(CONFIG_FILES)
        self._file_selector.currentTextChanged.connect(self._on_file_changed)
        file_row.addWidget(self._file_selector, stretch=1)
        layout.addLayout(file_row)

        # Splitter: editor + history
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Editor
        self._editor = PlainTextEdit()
        self._editor.setFont(QFont("Consolas", 11))
        self._editor.textChanged.connect(self._on_text_changed)
        splitter.addWidget(self._editor)

        # History card
        history_card = SimpleCardWidget()
        history_layout = QVBoxLayout(history_card)
        history_layout.setContentsMargins(16, 12, 16, 12)
        history_layout.addWidget(SubtitleLabel("Snapshot History"))

        self._snapshot_list = ListWidget()
        history_layout.addWidget(self._snapshot_list)

        btn_row = QHBoxLayout()
        self._diff_btn = PushButton("View Diff")
        self._diff_btn.clicked.connect(self._on_view_diff)
        self._restore_btn = PushButton("Restore")
        self._restore_btn.clicked.connect(self._on_restore)
        btn_row.addWidget(self._diff_btn)
        btn_row.addWidget(self._restore_btn)
        history_layout.addLayout(btn_row)

        splitter.addWidget(history_card)
        splitter.setSizes([700, 300])
        layout.addWidget(splitter, stretch=1)

        # Save bar
        save_row = QHBoxLayout()
        self._save_btn = PrimaryPushButton("Save")
        self._save_btn.clicked.connect(self._on_save)
        save_row.addWidget(self._save_btn)
        self._modified_label = BodyLabel("")
        save_row.addWidget(self._modified_label)
        save_row.addStretch()
        layout.addLayout(save_row)

        # Initialize change manager
        self._change_manager = ChangeManager(
            {"max_snapshots": 50, "snapshot_dir": str(get_data_dir() / "snapshots")},
            project_root=get_data_dir(),
        )

        # Load initial file
        self._load_file(CONFIG_FILES[0])
        self._load_snapshots()
        # Populate thresholds from the current config.yaml so the UI
        # reflects what the engine is actually using on boot.
        self._load_threshold_values()

    # ----------------------------------------------------------------
    # Threshold handling — quick-access Responder calibration knobs.
    # ----------------------------------------------------------------

    def _load_threshold_values(self) -> None:
        """Read the two thresholds from ``config.yaml`` and populate the spinboxes.

        Silent-fail: if the config is missing or malformed, leave the
        default values (0.70 / 0.99) in place.
        """
        config_path = get_data_dir() / "config" / "config.yaml"
        if not config_path.exists():
            return
        try:
            from wardsoar.core.responder import (
                DEFAULT_HARD_PROTECT_BENIGN_THRESHOLD,
                DEFAULT_PROTECT_CONFIDENCE_THRESHOLD,
            )

            with open(config_path, "r", encoding="utf-8") as fh:
                raw = _yaml.safe_load(fh) or {}
            analyzer = raw.get("analyzer", {}) if isinstance(raw, dict) else {}
            protect_val = float(
                analyzer.get(
                    "confidence_threshold",
                    DEFAULT_PROTECT_CONFIDENCE_THRESHOLD,
                )
            )
            hp_val = float(
                analyzer.get(
                    "hard_protect_benign_threshold",
                    DEFAULT_HARD_PROTECT_BENIGN_THRESHOLD,
                )
            )
        except (OSError, _yaml.YAMLError, ValueError, TypeError):
            logger.debug("Could not preload threshold values from config.yaml", exc_info=True)
            return

        self._suppress_threshold_signals = True
        try:
            self._protect_spin.setValue(protect_val)
            self._hp_spin.setValue(hp_val)
        finally:
            self._suppress_threshold_signals = False

    def _persist_threshold(self, key: str, value: float) -> None:
        """Write one threshold back to ``analyzer.<key>`` in ``config.yaml``.

        Creates the analyzer section if missing. Any I/O or YAML error
        is logged and swallowed — the live setter on the Responder has
        already accepted the value, so worst case the change survives
        only the current session.
        """
        config_path = get_data_dir() / "config" / "config.yaml"
        if not config_path.exists():
            return
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                raw = _yaml.safe_load(fh) or {}
            if not isinstance(raw, dict):
                return
            analyzer = raw.setdefault("analyzer", {})
            analyzer[key] = value
            with open(config_path, "w", encoding="utf-8") as fh:
                _yaml.dump(raw, fh, default_flow_style=False, sort_keys=False)
        except (OSError, _yaml.YAMLError) as exc:
            logger.warning("Failed to persist %s to config.yaml: %s", key, exc)

    def _on_protect_threshold_changed(self, value: float) -> None:
        if self._suppress_threshold_signals:
            return
        self._persist_threshold("confidence_threshold", float(value))
        self.threshold_changed.emit("protect", float(value))

    def _on_hard_protect_threshold_changed(self, value: float) -> None:
        if self._suppress_threshold_signals:
            return
        self._persist_threshold("hard_protect_benign_threshold", float(value))
        self.threshold_changed.emit("hard_protect", float(value))

    def _load_file(self, filename: str) -> None:
        """Load a config file into the editor."""
        path = get_data_dir() / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")
            self._editor.blockSignals(True)
            self._editor.setPlainText(content)
            self._editor.blockSignals(False)
            self._is_modified = False
            self._modified_label.setText("")
        else:
            self._editor.setPlainText(f"# File not found: {filename}")

    def _load_snapshots(self) -> None:
        """Load snapshot history into the list."""
        self._snapshot_list.clear()
        snapshots = self._change_manager.list_snapshots()
        for snap in snapshots:
            label = f"{snap.created_at.strftime('%Y-%m-%d %H:%M')} — {snap.description}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, snap.snapshot_id)
            self._snapshot_list.addItem(item)

    def _on_file_changed(self, filename: str) -> None:
        """Handle file selector change."""
        if self._is_modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Discard unsaved changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self._load_file(filename)

    def _on_text_changed(self) -> None:
        """Handle editor text changes."""
        self._is_modified = True
        self._modified_label.setText("Modified")

    def _on_save(self) -> None:
        """Save the editor content to disk."""
        filename = self._file_selector.currentText()
        path = get_data_dir() / filename

        # Create snapshot before saving
        desc, ok = QInputDialog.getText(self, "Snapshot", "Description for this change:")
        if not ok:
            return

        self._change_manager.create_snapshot(desc or "Manual edit")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._editor.toPlainText(), encoding="utf-8")
        self._is_modified = False
        self._modified_label.setText("Saved")
        self._load_snapshots()

    def _on_view_diff(self) -> None:
        """Show diff between selected snapshot and current file."""
        item = self._snapshot_list.currentItem()
        if not item:
            return
        snapshot_id = item.data(Qt.ItemDataRole.UserRole)
        if not snapshot_id:
            return

        diffs = self._change_manager.diff_current(snapshot_id)
        diff_text = "\n\n".join(f"--- {f} ---\n{d}" for f, d in diffs.items())
        current_content = self._editor.toPlainText()

        dialog = DiffDialog(diff_text or "(no differences)", current_content, self)
        dialog.exec()

    def _on_restore(self) -> None:
        """Restore the selected snapshot."""
        item = self._snapshot_list.currentItem()
        if not item:
            return

        reply = QMessageBox.question(
            self,
            "Restore Snapshot",
            "This will overwrite current config. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        snapshot_id = item.data(Qt.ItemDataRole.UserRole)
        self._change_manager.rollback(snapshot_id)
        self._load_file(self._file_selector.currentText())
        self._load_snapshots()
