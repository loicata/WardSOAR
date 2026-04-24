"""Netgate / pfSense configuration audit tab (Phase 7a).

Lets the operator run an on-demand, read-only audit of their Netgate
box and read back a tiered checklist of findings. Phase 7b will wire
the "Apply selected" button to actually remediate divergences; for
now the button is disabled and its tooltip says so.

Design notes
------------

* The list is a :class:`QTreeWidget` with three top-level sections
  (Critical / Recommended / Advanced). Critical expands by default
  because those items block the mode-escalation gate — the operator
  needs to see them immediately.
* Each child row is a single finding, rendered as
  ``<status icon>  <title>  <risk badge>  <current → expected>``.
  The fix description lives in the item's tool tip so the UI stays
  compact; the full detail is in the JSON export.
* Every finding carries the audit's stable ``id`` in
  :data:`Qt.UserRole`, so a future Apply pipeline can map checkboxes
  back to remediation handlers without re-parsing the text.
* "Select all" / "Select none" cascade to every finding regardless of
  its current check state — cheap and predictable. Checked-by-default
  rules:

    * Critical in KO — checked
    * Recommended in KO — unchecked (operator opts in)
    * Advanced — unchecked
    * OK items — unchecked and disabled (nothing to do)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    PrimaryPushButton,
    PushButton,
    SimpleCardWidget,
    SubtitleLabel,
)

from wardsoar.core.bootstrap_checklist import (
    BOOTSTRAP_STEPS,
    KIND_WARDSOAR,
    BootstrapChecklistState,
    ChecklistStep,
)

logger = logging.getLogger("ward_soar.ui.netgate_view")


# Light-on-dark palette reused across views (alert_detail.py, keys_view.py).
# BodyLabel and QCheckBox fall back to the system text colour on Windows 11,
# which renders as near-black on the dark Fluent theme — illegible on the
# cards we build here. Explicit colours keep the text readable.
_TEXT_PRIMARY = "color: #F0F0F0;"
_TEXT_SECONDARY = "color: #CFCFCF;"


# QTreeWidget picks up Qt's default (white) palette instead of Fluent's
# dark theme, which made the audit + tamper result lists render as a
# white block in the middle of the otherwise-dark Netgate tab. The
# stylesheet below forces the dark surface + light text, keeps the
# status colours (green/amber/red) readable, and tones down the
# selection highlight so it sits flush with the card it belongs to.
_TREE_STYLE = """
    QTreeWidget {
        background-color: #1F1F1F;
        color: #F0F0F0;
        border: 1px solid #2D2D2D;
        border-radius: 4px;
        outline: 0;
    }
    QTreeWidget::item {
        padding: 3px 2px;
        border: 0;
    }
    QTreeWidget::item:hover {
        background-color: #2A2A2A;
    }
    QTreeWidget::item:selected {
        background-color: #094771;
        color: #FFFFFF;
    }
    QTreeWidget::branch {
        background-color: transparent;
    }
"""


# --- Presentation helpers ---------------------------------------------------


_TIERS: tuple[tuple[str, str, bool], ...] = (
    # (tier_id, human label, expanded by default)
    ("critical", "Critical", True),
    ("recommended", "Recommended", True),
    ("advanced", "Advanced", False),
)

_STATUS_ICONS: dict[str, str] = {
    "ok": "✅",
    "warning": "⚠️",
    "critical": "❌",
    "unknown": "❔",
}

_RISK_ICONS: dict[str, str] = {
    "green": "🟢",
    "amber": "🟡",
    "red": "🔴",
}

_STATUS_COLOURS: dict[str, QColor] = {
    "ok": QColor(76, 175, 80),
    "warning": QColor(255, 152, 0),
    "critical": QColor(244, 67, 54),
    "unknown": QColor(158, 158, 158),
}


def _finding_line(finding: dict[str, Any]) -> str:
    """Single-line representation used in the tree widget."""
    icon = _STATUS_ICONS.get(finding.get("status", "unknown"), "❔")
    risk = _RISK_ICONS.get(finding.get("risk_badge", "green"), "🟢")
    title = finding.get("title") or finding.get("id") or "?"
    current = finding.get("current_value") or "?"
    expected = finding.get("expected_value") or ""
    trail = f"    {current} → {expected}" if expected else f"    {current}"
    return f"{icon}  {title}   {risk}{trail}"


def _default_checked(finding: dict[str, Any]) -> bool:
    """Which findings arrive pre-checked on the Select-none baseline.

    Only ``critical`` tier findings in a non-OK state are pre-checked
    — the ones that block WardSOAR from doing its job.
    """
    return finding.get("tier") == "critical" and finding.get("status") not in (None, "", "ok")


# --- View -------------------------------------------------------------------


class NetgateView(QWidget):
    """Netgate tab — audit + integrity (tamper detection).

    Two concerns share the tab, each with its own card:

    * **Integrity** (Phase 7g) — detects whether the Netgate has been
      tampered with since the operator last blessed it. Offers
      *Establish baseline*, *Check for tampering*, and *Re-bless*.
    * **Audit** (Phase 7a) — read-only sanity check on Suricata, pf,
      EVE output, etc.

    Signals:
        run_check_requested: emitted when the operator clicks
            "Run Check". Connected to
            :meth:`~src.ui.engine_bridge.EngineWorker.request_netgate_audit`.
        establish_baseline_requested: emitted when the operator
            clicks *Establish* or *Re-bless*.
        tamper_check_requested: emitted when the operator clicks
            *Check for tampering*.
    """

    run_check_requested = Signal()
    establish_baseline_requested = Signal()
    tamper_check_requested = Signal()
    deploy_custom_rules_requested = Signal()
    apply_fixes_requested = Signal(list)  # list[str] fix_ids
    # Bootstrap track for a just-reset Netgate. The operator confirms
    # via a dialog; the signal then triggers the pipeline-side cleanup
    # (baseline + block_tracker + trusted_temp).
    netgate_reset_cleanup_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self._findings: list[dict[str, Any]] = []
        self._last_result: Optional[dict[str, Any]] = None

        # Bootstrap checklist state — loads (or creates) the per-user
        # JSON under %APPDATA%\WardSOAR. We keep the view coupled to
        # get_data_dir() rather than injecting the state from the app
        # shell because the checklist is a pure client-side concern:
        # no worker thread, no pipeline dependency.
        from wardsoar.core.config import get_data_dir
        from wardsoar.core.bootstrap_checklist import default_persist_path

        self._checklist_state = BootstrapChecklistState(
            persist_path=default_persist_path(get_data_dir())
        )
        self._checklist_checkboxes: dict[str, QCheckBox] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(12)

        # ---- Header --------------------------------------------------
        header = QHBoxLayout()
        header.addWidget(SubtitleLabel("Netgate audit"))
        header.addStretch()
        self._last_label = CaptionLabel("No audit yet")
        header.addWidget(self._last_label)
        root.addLayout(header)

        # ---- Bootstrap checklist card (first-setup walkthrough) -----
        # Placed first because a new appliance needs to see it before
        # anything else. Experienced operators can ignore it once every
        # row is ticked.
        self._build_checklist_card(root)

        # ---- Description card ---------------------------------------
        intro_card = SimpleCardWidget()
        intro_layout = QVBoxLayout(intro_card)
        intro_layout.setContentsMargins(16, 10, 16, 10)
        intro_layout.addWidget(
            BodyLabel(
                "Reads the Netgate 4200's current configuration: Suricata, "
                "pf rules, EVE JSON output, NTP, disk space, version. "
                "The audit never mutates the Netgate. The « Apply » button "
                "will be enabled in v0.7."
            )
        )
        root.addWidget(intro_card)

        # ---- Integrity (Phase 7g) card ------------------------------
        # Tamper detection sits *above* the audit because an
        # integrity breach invalidates every config check that
        # follows. If the operator realises the box has been
        # touched, they almost always want to reset it physically,
        # not tune Suricata.
        integrity_card = SimpleCardWidget()
        integrity_layout = QVBoxLayout(integrity_card)
        integrity_layout.setContentsMargins(16, 10, 16, 10)
        integrity_layout.setSpacing(6)

        integrity_header = QHBoxLayout()
        integrity_header.addWidget(SubtitleLabel("Integrity (tamper detection)"))
        integrity_header.addStretch()
        self._tamper_status_label = CaptionLabel("No baseline yet")
        integrity_header.addWidget(self._tamper_status_label)
        integrity_layout.addLayout(integrity_header)

        integrity_layout.addWidget(
            BodyLabel(
                "Captures a fingerprint of the sensitive surfaces (SSH keys, "
                "user accounts, config.xml, pf rules, cron, host keys, "
                "packages, kernel modules). Re-run periodically to detect "
                "any modification since you last blessed the Netgate state. "
                "Sensitive content is hashed — only summaries ever leave "
                "the Netgate."
            )
        )

        integrity_buttons = QHBoxLayout()
        self._establish_baseline_btn = PushButton("Establish baseline")
        self._establish_baseline_btn.setToolTip(
            "Capture the current Netgate state as the trusted baseline."
        )
        self._establish_baseline_btn.clicked.connect(self._on_establish_clicked)
        integrity_buttons.addWidget(self._establish_baseline_btn)

        self._tamper_check_btn = PushButton("Check for tampering")
        self._tamper_check_btn.setToolTip(
            "Compare the current state against the baseline and list any deviations."
        )
        self._tamper_check_btn.clicked.connect(self._on_tamper_check_clicked)
        self._tamper_check_btn.setEnabled(False)
        integrity_buttons.addWidget(self._tamper_check_btn)

        integrity_buttons.addStretch()
        integrity_layout.addLayout(integrity_buttons)

        self._tamper_result_label = BodyLabel("")
        self._tamper_result_label.setWordWrap(True)
        self._tamper_result_label.setVisible(False)
        integrity_layout.addWidget(self._tamper_result_label)

        self._tamper_tree = QTreeWidget()
        self._tamper_tree.setColumnCount(1)
        self._tamper_tree.setHeaderHidden(True)
        self._tamper_tree.setRootIsDecorated(True)
        self._tamper_tree.setMaximumHeight(220)
        self._tamper_tree.setVisible(False)
        self._tamper_tree.setStyleSheet(_TREE_STYLE)
        integrity_layout.addWidget(self._tamper_tree)

        root.addWidget(integrity_card)

        # ---- Post-reset cleanup card --------------------------------
        # Narrow-purpose button dedicated to the "I just factory-reset
        # the Netgate" workflow. Lives next to Integrity because the
        # baseline invalidation is the dominant reason the button
        # exists — a just-reset box would otherwise ring every tamper
        # surface on the first check.
        reset_card = SimpleCardWidget()
        reset_layout = QVBoxLayout(reset_card)
        reset_layout.setContentsMargins(16, 10, 16, 10)
        reset_layout.setSpacing(6)

        reset_header = QHBoxLayout()
        reset_header.addWidget(SubtitleLabel("Post-reset cleanup"))
        reset_header.addStretch()
        self._reset_status_label = CaptionLabel("")
        reset_header.addWidget(self._reset_status_label)
        reset_layout.addLayout(reset_header)

        reset_layout.addWidget(
            BodyLabel(
                "Use after a factory reset of the Netgate. Clears the local "
                "tamper baseline (every surface changed legitimately), the "
                "block tracker (pf blocklist is empty) and the trusted-temp "
                "registry (quarantine rules are gone). No effect on the "
                "Netgate itself — only WardSOAR state."
            )
        )

        reset_buttons = QHBoxLayout()
        self._reset_cleanup_btn = PushButton("Clean WardSOAR state after Netgate reset")
        self._reset_cleanup_btn.setToolTip(
            "Deletes netgate_baseline.json, block_tracker.json and "
            "trusted_temp.json; asks for confirmation first."
        )
        self._reset_cleanup_btn.clicked.connect(self._on_reset_cleanup_clicked)
        reset_buttons.addWidget(self._reset_cleanup_btn)
        reset_buttons.addStretch()
        reset_layout.addLayout(reset_buttons)

        self._reset_result_label = BodyLabel("")
        self._reset_result_label.setWordWrap(True)
        self._reset_result_label.setVisible(False)
        reset_layout.addWidget(self._reset_result_label)

        root.addWidget(reset_card)

        # ---- Custom rules (Phase 7c) card ---------------------------
        rules_card = SimpleCardWidget()
        rules_layout = QVBoxLayout(rules_card)
        rules_layout.setContentsMargins(16, 10, 16, 10)
        rules_layout.setSpacing(6)

        rules_header = QHBoxLayout()
        rules_header.addWidget(SubtitleLabel("Custom Suricata rules (Ben-model + KBA)"))
        rules_header.addStretch()
        self._rules_status_label = CaptionLabel("Not yet deployed")
        rules_header.addWidget(self._rules_status_label)
        rules_layout.addLayout(rules_header)

        rules_layout.addWidget(
            BodyLabel(
                "Generates and deploys a Suricata rules file tailored to "
                "your threat model: one rule per IOC in known_bad_actors.yaml "
                "(priority 1, fires on any traffic to/from the IP, CIDR or "
                "domain) + 3 hand-written signatures (SSH brute-force, "
                "inbound RST flood, NXDOMAIN burst). After deploy, enable "
                "the file in the pfSense GUI: Services → Suricata → WAN → "
                "Categories → Custom rules files."
            )
        )

        rules_buttons = QHBoxLayout()
        self._preview_rules_btn = PushButton("Preview rules")
        self._preview_rules_btn.setToolTip(
            "Opens the rendered file in a dialog — does not touch the Netgate."
        )
        self._preview_rules_btn.clicked.connect(self._on_preview_rules_clicked)
        rules_buttons.addWidget(self._preview_rules_btn)

        self._deploy_rules_btn = PushButton("Deploy to Netgate")
        self._deploy_rules_btn.setToolTip(
            "Writes /usr/local/etc/suricata/rules/wardsoar_custom.rules via SSH."
        )
        self._deploy_rules_btn.clicked.connect(self._on_deploy_rules_clicked)
        rules_buttons.addWidget(self._deploy_rules_btn)

        rules_buttons.addStretch()
        rules_layout.addLayout(rules_buttons)

        self._rules_result_label = BodyLabel("")
        self._rules_result_label.setWordWrap(True)
        self._rules_result_label.setVisible(False)
        rules_layout.addWidget(self._rules_result_label)

        root.addWidget(rules_card)
        # Store the preview-bundle provider (wired by the app shell).
        self._rules_provider: Optional[Any] = None

        # ---- Action bar ---------------------------------------------
        action_row = QHBoxLayout()
        self._run_btn = PrimaryPushButton("▶ Run Check")
        self._run_btn.clicked.connect(self._on_run_clicked)
        action_row.addWidget(self._run_btn)

        self._select_all_btn = PushButton("Select all")
        self._select_all_btn.clicked.connect(lambda: self._set_all_checked(True))
        self._select_all_btn.setEnabled(False)
        action_row.addWidget(self._select_all_btn)

        self._select_none_btn = PushButton("Select none")
        self._select_none_btn.clicked.connect(lambda: self._set_all_checked(False))
        self._select_none_btn.setEnabled(False)
        action_row.addWidget(self._select_none_btn)

        action_row.addStretch()

        self._apply_btn = PushButton("Apply selected")
        self._apply_btn.setEnabled(False)
        self._apply_btn.setToolTip(
            "Apply the checked fixes to the Netgate. Only a limited set "
            "of SSH-only fixes is supported in v0.7.1; config.xml patches "
            "arrive in v0.7.2."
        )
        self._apply_btn.clicked.connect(self._on_apply_clicked)
        action_row.addWidget(self._apply_btn)

        # Set of fix ids whose handler is registered server-side. The
        # UI uses this to decide which checkboxes are enabled and to
        # gate the Apply button. Populated by ``set_applicable_fix_ids``.
        self._applicable_fix_ids: set[str] = set()

        self._export_btn = PushButton("Export JSON")
        self._export_btn.clicked.connect(self._on_export_clicked)
        self._export_btn.setEnabled(False)
        action_row.addWidget(self._export_btn)

        root.addLayout(action_row)

        # ---- Results tree -------------------------------------------
        self._tree = QTreeWidget()
        self._tree.setColumnCount(1)
        self._tree.setHeaderHidden(True)
        self._tree.setRootIsDecorated(True)
        self._tree.setStyleSheet(_TREE_STYLE)
        # Keep the Apply button's enabled state in lock-step with the
        # checked rows. Without this wiring the button only updated on
        # a full audit re-render, so ticking a single box after the
        # audit finished left "Apply selected" greyed out even though
        # a valid fix was selected. ``itemChanged`` fires for every
        # checkbox toggle, for programmatic changes (Select all / Select
        # none) AND for user clicks, so one connection covers both paths.
        self._tree.itemChanged.connect(self._on_tree_item_changed)
        root.addWidget(self._tree, stretch=1)

        # ---- Placeholder -------------------------------------------
        self._placeholder = BodyLabel(
            "Click « Run Check » to run an audit. " "Nothing is mutated on the Netgate — read-only."
        )
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._placeholder)

    # ------------------------------------------------------------------
    # Public API — called by the application shell.
    # ------------------------------------------------------------------

    def display_audit_result(self, payload: dict[str, Any]) -> None:
        """Render a result returned by EngineWorker.netgate_audit_completed.

        Payload shape follows :meth:`src.netgate_audit.AuditResult.to_dict`.
        """
        self._last_result = payload
        self._run_btn.setEnabled(True)
        self._run_btn.setText("▶ Run Check")

        error = payload.get("error")
        ssh_reachable = payload.get("ssh_reachable", True)

        self._tree.clear()
        self._findings = list(payload.get("findings") or [])

        if error or not ssh_reachable:
            err_item = QTreeWidgetItem(
                [f"❌  Cannot reach Netgate via SSH: {error or payload.get('ssh_error', '?')}"]
            )
            err_item.setForeground(0, QBrush(_STATUS_COLOURS["critical"]))
            self._tree.addTopLevelItem(err_item)
            self._placeholder.setVisible(False)
            self._last_label.setText(datetime.now(timezone.utc).strftime("last: %H:%M:%S — KO"))
            self._select_all_btn.setEnabled(False)
            self._select_none_btn.setEnabled(False)
            self._export_btn.setEnabled(True)
            return

        self._placeholder.setVisible(False)
        self._select_all_btn.setEnabled(True)
        self._select_none_btn.setEnabled(True)
        self._export_btn.setEnabled(True)

        # Build a tier → findings map, preserving original ordering.
        per_tier: dict[str, list[dict[str, Any]]] = {tier: [] for tier, _lab, _exp in _TIERS}
        for finding in self._findings:
            per_tier.setdefault(finding.get("tier") or "advanced", []).append(finding)

        total_ko = 0
        for tier_id, label, expanded in _TIERS:
            tier_findings = per_tier.get(tier_id, [])
            ko_count = sum(1 for f in tier_findings if f.get("status") not in (None, "", "ok"))
            if ko_count > 0:
                total_ko += ko_count
            header_text = (
                f"{label}  ({len(tier_findings)} check(s), {ko_count} KO)"
                if tier_findings
                else f"{label}  (0 check)"
            )
            tier_item = QTreeWidgetItem([header_text])
            tier_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self._tree.addTopLevelItem(tier_item)
            tier_item.setExpanded(expanded and bool(tier_findings))

            for finding in tier_findings:
                child = QTreeWidgetItem([_finding_line(finding)])
                fix_id = finding.get("id") or ""
                child.setData(0, Qt.ItemDataRole.UserRole, fix_id)
                child.setToolTip(0, self._tooltip_for(finding))
                is_ok = finding.get("status") == "ok"
                is_applicable = fix_id in self._applicable_fix_ids
                # Rows become checkable only when BOTH conditions hold:
                # status is not OK (something to fix) AND the backend
                # has a registered safe-apply handler for this fix id.
                # Without the second check, the operator could tick a
                # finding whose Apply handler does not exist, producing
                # a confusing silent no-op.
                flags = Qt.ItemFlag.ItemIsEnabled
                if not is_ok and is_applicable:
                    flags |= Qt.ItemFlag.ItemIsUserCheckable
                child.setFlags(flags)
                if not is_ok and is_applicable:
                    child.setCheckState(
                        0,
                        (
                            Qt.CheckState.Checked
                            if _default_checked(finding)
                            else Qt.CheckState.Unchecked
                        ),
                    )
                colour = _STATUS_COLOURS.get(finding.get("status") or "unknown")
                if colour is not None:
                    child.setForeground(0, QBrush(colour))
                if not is_ok and not is_applicable:
                    # Visually hint why the box is not tickable.
                    child.setToolTip(
                        0,
                        self._tooltip_for(finding)
                        + "\n\n(No auto-apply handler yet — this fix is a manual operator step.)",
                    )
                tier_item.addChild(child)

        self._apply_btn.setEnabled(self._any_checkbox_checked())

        started = payload.get("started_at", "")
        duration = payload.get("duration_seconds", 0.0)
        try:
            duration_ms = int(float(duration) * 1000)
        except (ValueError, TypeError):
            duration_ms = 0
        short_time = started[11:19] if started else ""
        self._last_label.setText(
            f"last: {short_time} — {len(self._findings)} checks, "
            f"{total_ko} KO, {duration_ms} ms"
        )
        logger.info("netgate_audit UI: rendered %d findings (%d KO)", len(self._findings), total_ko)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _on_run_clicked(self) -> None:
        self._run_btn.setEnabled(False)
        self._run_btn.setText("⏳ Running…")
        self._tree.clear()
        self._placeholder.setText("Running audit — usually 5 to 15 seconds on a healthy Netgate…")
        self._placeholder.setVisible(True)
        self.run_check_requested.emit()

    # ------------------------------------------------------------------
    # Safe-apply (Phase 7b) — wire the Apply selected button.
    # ------------------------------------------------------------------

    def set_applicable_fix_ids(self, fix_ids: set[str]) -> None:
        """Tell the view which fix ids have a server-side Apply handler.

        Called once at engine start from :class:`WardSOARApp` so the
        UI stays in sync with whatever handlers the Applier registry
        ships. The set is consulted on every re-render of the audit
        tree; there is no need to re-run an audit to pick up a change.
        """
        self._applicable_fix_ids = set(fix_ids)

    def _any_checkbox_checked(self) -> bool:
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            tier_item = root.child(i)
            for j in range(tier_item.childCount()):
                child = tier_item.child(j)
                if bool(child.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                    if child.checkState(0) == Qt.CheckState.Checked:
                        return True
        return False

    def _on_tree_item_changed(self, _item: QTreeWidgetItem, _column: int) -> None:
        """Refresh the Apply button whenever any checkbox toggles.

        Qt fires ``itemChanged`` for every kind of mutation on the
        item (text edit, check-state flip, flag change). We only care
        about checkbox flips here, but calling ``_any_checkbox_checked``
        unconditionally is cheap (linear scan of ~20 rows with early
        exit) and avoids having to track which exact change fired the
        signal. The signal is also emitted during tree construction as
        each row has its initial check-state applied — that's fine, the
        helper returns the same boolean whether it runs once or twenty
        times in a row.
        """
        self._apply_btn.setEnabled(self._any_checkbox_checked())

    def _checked_fix_ids(self) -> list[str]:
        """Extract the fix ids for every ticked row in display order."""
        ticked: list[str] = []
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            tier_item = root.child(i)
            for j in range(tier_item.childCount()):
                child = tier_item.child(j)
                if child.checkState(0) == Qt.CheckState.Checked:
                    fix_id = child.data(0, Qt.ItemDataRole.UserRole)
                    if isinstance(fix_id, str) and fix_id in self._applicable_fix_ids:
                        ticked.append(fix_id)
        return ticked

    def _on_apply_clicked(self) -> None:
        from qfluentwidgets import MessageBox

        fix_ids = self._checked_fix_ids()
        if not fix_ids:
            return
        msg = MessageBox(
            f"Apply {len(fix_ids)} fix(es) to the Netgate?",
            "WardSOAR will run the selected remediations one by one. "
            "Each fix is verified immediately after apply — if "
            "verification fails, the backup (if any) is restored. "
            "Continue?",
            self,
        )
        msg.yesButton.setText("Apply")
        msg.cancelButton.setText("Cancel")
        if not msg.exec():
            return
        self._apply_btn.setEnabled(False)
        self._apply_btn.setText("⏳ Applying…")
        self.apply_fixes_requested.emit(fix_ids)

    def display_apply_results(self, results: list[dict[str, Any]]) -> None:
        """Render the outcome of an Apply run — one dialog, all rows.

        Also triggers a fresh audit after the dialog closes when any
        fix succeeded. Without this, the tree keeps showing the
        pre-apply state (still WARNING on the migrated alias, etc.)
        and the operator has to click Run Check manually to see the
        green check-mark — which defeats the whole point of the fix.
        """
        from qfluentwidgets import MessageBox

        self._apply_btn.setEnabled(True)
        self._apply_btn.setText("Apply selected")
        if not results:
            return
        lines = []
        for res in results:
            flag = "✅" if res.get("success") else "❌"
            line = f"{flag}  {res.get('fix_id', '?')}"
            error = res.get("error")
            if error:
                line += f"  — {error}"
            if res.get("rollback_performed"):
                line += "  [backup restored]"
            lines.append(line)
        body = "\n".join(lines)

        any_success = any(r.get("success") for r in results)
        if any_success:
            # Nudge the operator: the dialog mentions the upcoming
            # auto-refresh so closing it does not look like a freeze.
            body += "\n\nRe-running the audit now to show the new state…"

        dialog = MessageBox(
            f"Apply completed ({sum(1 for r in results if r.get('success'))}/{len(results)} OK)",
            body,
            self,
        )
        dialog.yesButton.setText("Close")
        dialog.cancelButton.hide()
        dialog.exec()

        if any_success:
            # Re-run the audit so the tree reflects reality. Uses the
            # same code path as the Run Check button — the EngineWorker
            # handles it asynchronously and streams back the new
            # findings to ``display_audit_result``.
            self._on_run_clicked()

    def _on_export_clicked(self) -> None:
        if self._last_result is None:
            return
        default_name = "wardsoar_netgate_audit_{:%Y%m%d_%H%M%S}.json".format(
            datetime.now(timezone.utc)
        )
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Export audit report",
            default_name,
            "JSON (*.json)",
        )
        if not path_str:
            return
        try:
            Path(path_str).write_text(
                json.dumps(self._last_result, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Failed to export Netgate audit: %s", exc)

    def _set_all_checked(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            tier_item = root.child(i)
            for j in range(tier_item.childCount()):
                child = tier_item.child(j)
                # Only cascade to rows that actually carry a checkbox
                # (OK items are created non-checkable by design).
                if bool(child.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                    child.setCheckState(0, state)

    # ------------------------------------------------------------------
    # Tamper detection — public API + button handlers.
    # ------------------------------------------------------------------

    def set_baseline_status(self, captured_at: Optional[str]) -> None:
        """Called by the app on startup once it knows the baseline state.

        ``captured_at`` is the ISO timestamp of the current baseline,
        or ``None`` when no baseline exists on disk.
        """
        if captured_at:
            self._tamper_status_label.setText(f"Baseline: {captured_at[:19]}")
            self._establish_baseline_btn.setText("Re-bless baseline")
            self._establish_baseline_btn.setToolTip(
                "Capture a new snapshot — re-bless after any intentional "
                "change (package, new user account, firewall rule)."
            )
            self._tamper_check_btn.setEnabled(True)
        else:
            self._tamper_status_label.setText("No baseline yet")
            self._establish_baseline_btn.setText("Establish baseline")
            self._tamper_check_btn.setEnabled(False)

    def display_baseline_established(self, payload: dict[str, Any]) -> None:
        """Called after :class:`EngineWorker` emits
        :attr:`~src.ui.engine_bridge.EngineWorker.baseline_established`.

        Payload fields: ``captured_at`` (ISO), ``host``, ``entries`` (int count),
        ``error`` (optional).
        """
        self._establish_baseline_btn.setEnabled(True)
        err = payload.get("error")
        if err:
            self._tamper_result_label.setText(f"❌  Baseline capture failed: {err}")
            self._tamper_result_label.setVisible(True)
            return
        captured_at = str(payload.get("captured_at") or "")
        count = int(payload.get("entries") or 0)
        self.set_baseline_status(captured_at)
        self._tamper_result_label.setText(
            f"✅  Baseline captured — {count} surfaces fingerprinted at " f"{captured_at[:19]}."
        )
        self._tamper_result_label.setVisible(True)
        self._tamper_tree.setVisible(False)

    def display_tamper_check(self, payload: dict[str, Any]) -> None:
        """Render the outcome of a tamper-diff run."""
        self._tamper_check_btn.setEnabled(True)
        self._tamper_check_btn.setText("Check for tampering")
        self._tamper_tree.clear()

        if payload.get("error"):
            self._tamper_result_label.setText(f"❌  SSH error: {payload.get('error')}")
            self._tamper_result_label.setVisible(True)
            self._tamper_tree.setVisible(False)
            return

        if not payload.get("baseline_present"):
            self._tamper_result_label.setText(
                "ℹ️  No baseline on disk — click « Establish baseline » first."
            )
            self._tamper_result_label.setVisible(True)
            self._tamper_tree.setVisible(False)
            return

        findings = list(payload.get("findings") or [])
        if not findings:
            self._tamper_result_label.setText(
                "✅  No deviation detected — the Netgate matches the baseline."
            )
            self._tamper_result_label.setVisible(True)
            self._tamper_tree.setVisible(False)
            return

        self._tamper_result_label.setText(
            f"⚠️  {len(findings)} deviation(s) detected since baseline. "
            "If these changes were not made by you, treat the Netgate as "
            "compromised and reset it."
        )
        self._tamper_result_label.setVisible(True)

        severity_rank = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: severity_rank.get(f.get("severity", "low"), 3))
        for finding in findings:
            sev = finding.get("severity", "medium")
            icon = "❌" if sev == "high" else "⚠️" if sev == "medium" else "ℹ️"
            title = finding.get("title") or finding.get("id")
            header = QTreeWidgetItem([f"{icon}  {title}   [{sev}]"])
            header.setForeground(
                0,
                QBrush(
                    _STATUS_COLOURS["critical"]
                    if sev == "high"
                    else (
                        _STATUS_COLOURS["warning"]
                        if sev == "medium"
                        else _STATUS_COLOURS["unknown"]
                    )
                ),
            )
            header.setData(0, Qt.ItemDataRole.UserRole, finding.get("id"))
            base_summary = QTreeWidgetItem(
                [f"    baseline: {finding.get('baseline_summary') or '?'}"]
            )
            cur_summary = QTreeWidgetItem(
                [f"    current:  {finding.get('current_summary') or '?'}"]
            )
            captured_at = finding.get("baseline_captured_at") or ""
            if captured_at:
                cur_summary.setToolTip(0, f"Baseline captured at: {captured_at}")
            header.addChild(base_summary)
            header.addChild(cur_summary)
            self._tamper_tree.addTopLevelItem(header)
            header.setExpanded(sev == "high")
        self._tamper_tree.setVisible(True)

    # ------------------------------------------------------------------
    # Post-reset cleanup (bootstrap track)
    # ------------------------------------------------------------------

    def _on_reset_cleanup_clicked(self) -> None:
        """Ask for confirmation, then emit the cleanup request.

        The dialog is deliberately blunt: the operator has to type
        nothing, but they must click the affirmative button — losing
        the tamper baseline and the list of currently-blocked IPs is
        irreversible. A stray click on a skimmed-over button is a
        reason not to lose data.
        """
        from PySide6.QtWidgets import QMessageBox

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Post-reset cleanup")
        box.setText("Clean WardSOAR state for a just-reset Netgate?")
        box.setInformativeText(
            "This will delete:\n"
            "  • the tamper baseline (netgate_baseline.json)\n"
            "  • the block tracker (block_tracker.json)\n"
            "  • the trusted-temp registry (trusted_temp.json)\n"
            "  • the bootstrap checklist ticks\n\n"
            "No effect on the Netgate itself. Only run this right after "
            "a factory reset; otherwise you will lose legitimate state."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        self._reset_cleanup_btn.setEnabled(False)
        self._reset_result_label.setText("⏳  Cleaning WardSOAR state…")
        self._reset_result_label.setVisible(True)
        self._reset_status_label.setText("In progress…")
        self.netgate_reset_cleanup_requested.emit()

    def display_netgate_reset_cleanup(self, payload: dict[str, Any]) -> None:
        """Render the outcome of a cleanup run.

        Payload shape matches the one emitted by
        :attr:`~src.ui.engine_bridge.EngineWorker.netgate_reset_cleanup_completed`.
        """
        self._reset_cleanup_btn.setEnabled(True)
        errors = payload.get("errors") or []
        message = payload.get("message") or "Cleanup complete."

        if errors:
            self._reset_result_label.setText(f"❌  {message}")
            self._reset_status_label.setText("Errors — see log")
        else:
            self._reset_result_label.setText(f"✅  {message}")
            parts: list[str] = []
            if payload.get("baseline_removed"):
                parts.append("baseline removed")
            if payload.get("block_entries_purged"):
                parts.append(f"{payload['block_entries_purged']} blocks")
            if payload.get("trusted_entries_purged"):
                parts.append(f"{payload['trusted_entries_purged']} quarantined")
            self._reset_status_label.setText(", ".join(parts) if parts else "Nothing to clean")

        # The integrity card's status drifts now that the baseline is
        # gone — reflect it immediately so the operator sees the next
        # step (click Establish baseline) without having to reopen the
        # tab.
        if payload.get("baseline_removed"):
            self._tamper_status_label.setText("No baseline yet")
            self._establish_baseline_btn.setText("Establish baseline")
            self._establish_baseline_btn.setEnabled(True)
            self._tamper_check_btn.setEnabled(False)
            self._tamper_result_label.setVisible(False)
            self._tamper_tree.setVisible(False)
            # Factory reset starts a fresh bootstrap — drop the ticks
            # so the checklist reflects the new reality.
            self._checklist_state.reset_all()
            for checkbox in self._checklist_checkboxes.values():
                checkbox.blockSignals(True)
                checkbox.setChecked(False)
                checkbox.blockSignals(False)
            self._refresh_checklist_progress()

    # ------------------------------------------------------------------
    # Bootstrap checklist (first-setup walkthrough)
    # ------------------------------------------------------------------

    def _build_checklist_card(self, root: QVBoxLayout) -> None:
        """Create the bootstrap checklist card and append it to ``root``.

        One row per :data:`~src.bootstrap_checklist.BOOTSTRAP_STEPS`
        entry: ``[checkbox] <icon> <number>. <title>`` with the step's
        ``description`` as tooltip. A caption in the header shows the
        running progress (``3 / 11 done``).
        """
        card = SimpleCardWidget()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(6)

        header = QHBoxLayout()
        header.addWidget(SubtitleLabel("Bootstrap checklist"))
        header.addStretch()
        self._checklist_progress_label = CaptionLabel("")
        header.addWidget(self._checklist_progress_label)
        layout.addLayout(header)

        description = BodyLabel(
            "Step-by-step walkthrough for a brand-new or factory-reset "
            "Netgate 4200. Four rows require a click in the pfSense webGUI "
            "(🖱️ icon); the rest is driven from WardSOAR (⚙️ icon). "
            "Your progress is saved — closing WardSOAR does not reset the ticks."
        )
        description.setWordWrap(True)
        description.setStyleSheet(_TEXT_SECONDARY)
        layout.addWidget(description)

        # Sysmon banner — surfaced here (rather than on the Dashboard)
        # because step #1 of the checklist is "install Sysmon". If the
        # probe says it is missing or stopped, the banner tells the
        # operator exactly what they lose (process attribution) so the
        # checkbox is not perceived as purely ceremonial.
        self._sysmon_banner = BodyLabel("")
        self._sysmon_banner.setWordWrap(True)
        self._sysmon_banner.setVisible(False)
        layout.addWidget(self._sysmon_banner)

        # Action button shown only when Sysmon is fully absent. Runs
        # scripts/install-sysmon.ps1 under UAC elevation. A stopped
        # service is different (operator already installed Sysmon, we
        # just need ``Start-Service``) and does not need a button.
        sysmon_btn_row = QHBoxLayout()
        sysmon_btn_row.setContentsMargins(0, 0, 0, 0)
        self._sysmon_install_btn = PushButton("Install Sysmon")
        self._sysmon_install_btn.setToolTip(
            "Download + install Microsoft Sysmon with the SwiftOnSecurity "
            "network-logging config. Windows will prompt for admin rights."
        )
        self._sysmon_install_btn.clicked.connect(self._on_install_sysmon_clicked)
        self._sysmon_install_btn.setVisible(False)
        sysmon_btn_row.addWidget(self._sysmon_install_btn)
        sysmon_btn_row.addStretch()
        layout.addLayout(sysmon_btn_row)

        self._refresh_sysmon_banner()

        # Checkboxes, one per step.
        for step in BOOTSTRAP_STEPS:
            self._add_checklist_row(layout, step)

        # Footer: view-guide button.
        footer = QHBoxLayout()
        footer.addStretch()
        self._view_guide_btn = PushButton("View full guide")
        self._view_guide_btn.setToolTip("Open the step-by-step Markdown guide in a dialog.")
        self._view_guide_btn.clicked.connect(self._on_view_guide_clicked)
        footer.addWidget(self._view_guide_btn)
        layout.addLayout(footer)

        root.addWidget(card)
        self._refresh_checklist_progress()

    def _refresh_sysmon_banner(self) -> None:
        """Probe Sysmon and update the banner visibility / text.

        Shown when Sysmon is missing or stopped — hidden otherwise so
        an OK state does not clutter the card. Called at construction
        and could be re-called on demand if we ever add a refresh
        action.
        """
        from wardsoar.pc.sysmon_probe import probe_sysmon

        status = probe_sysmon()
        if status.healthy:
            self._sysmon_banner.setVisible(False)
            if getattr(self, "_sysmon_install_btn", None) is not None:
                self._sysmon_install_btn.setVisible(False)
            return

        if status.error:
            message = (
                "⚠️  Sysmon probe failed: " + status.error + ". "
                "Process attribution will degrade to psutil only "
                "(see step 1 above)."
            )
            show_install_button = False
        elif status.installed and not status.running:
            message = (
                f"⚠️  Sysmon ({status.service_name}) is installed but not running. "
                "Start it from an elevated PowerShell with "
                f"« Start-Service {status.service_name} » for reliable "
                "process attribution on every alert."
            )
            show_install_button = False
        else:
            message = (
                "⚠️  Sysmon is not installed on this PC. WardSOAR can still "
                "correlate Suricata alerts to a local process via psutil, but "
                "only while the socket is still open — UDP bursts and closed "
                "TCP flows will have no process attached. Click « Install Sysmon » "
                "below to download + install it automatically (UAC prompt)."
            )
            show_install_button = True

        # Amber text on the dark card — same convention as other
        # warning strings in the app (see alert_detail.py).
        self._sysmon_banner.setText(message)
        self._sysmon_banner.setStyleSheet("color: #FFB74D;")  # Material Amber-300
        self._sysmon_banner.setVisible(True)
        if getattr(self, "_sysmon_install_btn", None) is not None:
            self._sysmon_install_btn.setVisible(show_install_button)
            self._sysmon_install_btn.setEnabled(show_install_button)

    def _on_install_sysmon_clicked(self) -> None:
        """Launch the elevated Sysmon installer and schedule a re-probe.

        The click hands off to a child PowerShell that asks Windows
        for elevation and runs ``scripts/install-sysmon.ps1``. We
        cannot wait synchronously for the UAC decision + install (it
        can take tens of seconds), so we just fire the launcher and
        re-probe the Sysmon service a few seconds later to refresh
        the banner. If the operator cancels UAC the banner stays as
        it was, which is the right behaviour.
        """
        from PySide6.QtCore import QTimer

        from wardsoar.pc.sysmon_installer import launch_install_script

        self._sysmon_install_btn.setEnabled(False)
        self._sysmon_install_btn.setText("⏳ UAC prompt — check your desktop…")

        result = launch_install_script()
        if not result.started:
            self._sysmon_install_btn.setEnabled(True)
            self._sysmon_install_btn.setText("Install Sysmon")
            self._sysmon_banner.setText(f"⚠️  {result.error}")
            return

        # Poll the probe every 5 s for up to 2 minutes. Sysmon install
        # is typically under 20 s but we allow for slow download / AV
        # scanning without leaving the banner stale.
        self._sysmon_poll_count = 0

        def _poll() -> None:
            self._sysmon_poll_count += 1
            self._refresh_sysmon_banner()
            # Stop polling once the banner cleared (probe reports
            # healthy) or after 24 polls (~2 min).
            from wardsoar.pc.sysmon_probe import probe_sysmon

            if probe_sysmon().healthy or self._sysmon_poll_count >= 24:
                self._sysmon_poll_timer.stop()
                if (
                    getattr(self, "_sysmon_install_btn", None) is not None
                    and self._sysmon_install_btn.isVisible()
                ):
                    self._sysmon_install_btn.setEnabled(True)
                    self._sysmon_install_btn.setText("Install Sysmon")

        self._sysmon_poll_timer = QTimer(self)
        self._sysmon_poll_timer.setInterval(5000)
        self._sysmon_poll_timer.timeout.connect(_poll)
        self._sysmon_poll_timer.start()

    def _add_checklist_row(self, layout: QVBoxLayout, step: ChecklistStep) -> None:
        """Create one checkbox row for ``step`` and wire its toggle signal."""
        # 🖱️ for anything the operator clicks through a GUI (pfSense
        # webGUI or the Windows host); ⚙️ for actions triggered from
        # another WardSOAR card. Same visual rule as the guide.
        icon = "⚙️" if step.kind == KIND_WARDSOAR else "🖱️"
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        checkbox = QCheckBox(f"{icon}  {step.number}. {step.title}")
        # Force a light text colour — the default Qt palette paints the
        # checkbox label in near-black, which is unreadable on the dark
        # Fluent card background. We only touch the label colour; leave
        # the indicator styling to the system so it still looks native.
        checkbox.setStyleSheet("QCheckBox { color: #F0F0F0; }")
        checkbox.setToolTip(step.description)
        checkbox.setChecked(self._checklist_state.is_checked(step.id))
        # Bind the step id via a default arg so each lambda captures its
        # own value rather than the final loop variable.
        checkbox.toggled.connect(
            lambda checked, sid=step.id: self._on_checklist_toggled(sid, checked)
        )
        row.addWidget(checkbox, stretch=1)
        layout.addLayout(row)
        self._checklist_checkboxes[step.id] = checkbox

    def _on_checklist_toggled(self, step_id: str, checked: bool) -> None:
        """Persist the new tick state and refresh the progress label."""
        self._checklist_state.set_checked(step_id, checked)
        self._refresh_checklist_progress()

    def _refresh_checklist_progress(self) -> None:
        """Update the ``X / N done`` caption in the card header."""
        done, total = self._checklist_state.progress()
        if done == 0:
            self._checklist_progress_label.setText(f"{total} steps — nothing done yet")
        elif done == total:
            self._checklist_progress_label.setText(
                f"✅  {done} / {total} done — bootstrap complete"
            )
        else:
            self._checklist_progress_label.setText(f"{done} / {total} done")

    def _on_view_guide_clicked(self) -> None:
        """Open the full Markdown guide in a read-only dialog.

        The source lives under ``docs/bootstrap-netgate.md``. When the
        file cannot be resolved (e.g. the frozen build ships it under
        a different prefix) we fall back to a short in-memory snippet
        so the button never looks broken.
        """
        text = self._load_guide_markdown()
        dialog = QDialog(self)
        dialog.setWindowTitle("Netgate bootstrap — full guide")
        dialog.resize(900, 700)
        viewer = QTextBrowser(dialog)
        viewer.setOpenExternalLinks(True)
        viewer.setMarkdown(text)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(viewer)
        close_btn = PushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dialog.exec()

    def _load_guide_markdown(self) -> str:
        """Resolve the guide path across dev and frozen installs.

        Order:
        1. ``<repo_root>/docs/bootstrap-netgate.md`` — dev / test run.
        2. ``get_bundle_dir()/docs/bootstrap-netgate.md`` — PyInstaller.
        3. Hard-coded fallback — one-liner pointing to the GitHub doc.
        """
        candidates: list[Path] = []

        repo_doc = Path(__file__).resolve().parents[3] / "docs" / "bootstrap-netgate.md"
        candidates.append(repo_doc)

        try:
            from wardsoar.core.config import get_bundle_dir

            candidates.append(get_bundle_dir() / "docs" / "bootstrap-netgate.md")
        except Exception:  # noqa: BLE001 — optional path resolution
            pass

        for path in candidates:
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8")
            except OSError:
                continue

        logger.warning("bootstrap-netgate.md not found in %s", candidates)
        return (
            "# Netgate bootstrap — guide\n\n"
            "The detailed Markdown guide was not shipped with this "
            "WardSOAR install. The checklist above still captures the "
            "11 steps. For a full walk-through, consult "
            "`docs/bootstrap-netgate.md` in the WardSOAR source tree."
        )

    def _on_establish_clicked(self) -> None:
        self._establish_baseline_btn.setEnabled(False)
        self._tamper_result_label.setText("⏳  Capturing baseline over SSH…")
        self._tamper_result_label.setVisible(True)
        self._tamper_tree.setVisible(False)
        self.establish_baseline_requested.emit()

    def _on_tamper_check_clicked(self) -> None:
        self._tamper_check_btn.setEnabled(False)
        self._tamper_check_btn.setText("⏳ Checking…")
        self._tamper_result_label.setText("⏳  Re-capturing and diffing against baseline…")
        self._tamper_result_label.setVisible(True)
        self._tamper_tree.setVisible(False)
        self.tamper_check_requested.emit()

    # ------------------------------------------------------------------
    # Phase 7c — custom rules
    # ------------------------------------------------------------------

    def set_rules_provider(self, provider: Any) -> None:
        """Connect a callable ``() → RulesBundle`` for in-process previews.

        Typically set to ``EngineWorker.preview_custom_rules`` by the
        application shell. Keeping the provider as a plain callable
        makes the view trivially testable with a fake.
        """
        self._rules_provider = provider

    def display_custom_rules_deployed(self, payload: dict[str, Any]) -> None:
        """Render the outcome of a deploy attempt."""
        self._deploy_rules_btn.setEnabled(True)
        self._deploy_rules_btn.setText("Deploy to Netgate")
        success = bool(payload.get("success"))
        rule_count = int(payload.get("rule_count") or 0)
        err = payload.get("error")
        if success:
            self._rules_status_label.setText(
                f"Deployed — {rule_count} rules, " f"{int(payload.get('bytes_written') or 0)} bytes"
            )
            self._rules_result_label.setText(
                f"✅  Wrote {rule_count} rules to {payload.get('remote_path')}. "
                "Enable them in pfSense: Services → Suricata → WAN → "
                "Categories → Custom rules files → check "
                "« wardsoar_custom.rules » → Save → Restart Suricata."
            )
        else:
            self._rules_result_label.setText(f"❌  Deploy failed: {err or 'unknown error'}")
        self._rules_result_label.setVisible(True)

    def _on_preview_rules_clicked(self) -> None:
        if self._rules_provider is None:
            self._rules_result_label.setText(
                "Preview unavailable — the engine has not started yet."
            )
            self._rules_result_label.setVisible(True)
            return
        try:
            bundle = self._rules_provider()
        except Exception as exc:  # noqa: BLE001 — surface any error
            self._rules_result_label.setText(f"Preview failed: {exc}")
            self._rules_result_label.setVisible(True)
            return

        from qfluentwidgets import MessageBox

        content = bundle.render()
        # MessageBox from qfluentwidgets wraps a body label that
        # doesn't scroll nicely on very long inputs. Show a truncated
        # view with an explicit "see file" note if the payload is too
        # large; the same content is what will be deployed.
        preview_body = (
            content
            if len(content) < 4000
            else (
                content[:3800]
                + "\n\n… (truncated for preview — "
                + f"{len(bundle.rules)} rules total)\n"
            )
        )
        dialog = MessageBox(
            f"Custom Suricata rules preview ({len(bundle.rules)} rules)",
            preview_body,
            self,
        )
        dialog.yesButton.setText("Close")
        dialog.cancelButton.hide()
        dialog.exec()

    def _on_deploy_rules_clicked(self) -> None:
        # Require an explicit confirmation — writing files on the
        # firewall is a mutating action, Phase 7c's doctrine says
        # *always confirm*.
        from qfluentwidgets import MessageBox

        dialog = MessageBox(
            "Deploy custom Suricata rules to Netgate?",
            "WardSOAR will write /usr/local/etc/suricata/rules/"
            "wardsoar_custom.rules via SSH. The file contains one rule "
            "per IOC in known_bad_actors.yaml plus the Ben-pattern "
            "signatures. It does NOT activate them — you must enable "
            "the file in pfSense Suricata GUI afterwards.",
            self,
        )
        dialog.yesButton.setText("Deploy")
        dialog.cancelButton.setText("Cancel")
        if not dialog.exec():
            return
        self._deploy_rules_btn.setEnabled(False)
        self._deploy_rules_btn.setText("⏳ Deploying…")
        self._rules_result_label.setText("⏳  Uploading rules over SSH…")
        self._rules_result_label.setVisible(True)
        self.deploy_custom_rules_requested.emit()

    @staticmethod
    def _tooltip_for(finding: dict[str, Any]) -> str:
        lines = [
            f"ID: {finding.get('id', '')}",
            f"Category: {finding.get('category', '')}",
            f"Current: {finding.get('current_value', '')}",
            f"Expected: {finding.get('expected_value', '')}",
            f"Fix: {finding.get('fix_description', '')}",
        ]
        details = finding.get("details")
        if details:
            lines.append(f"Details: {details}")
        return "\n".join(lines)
