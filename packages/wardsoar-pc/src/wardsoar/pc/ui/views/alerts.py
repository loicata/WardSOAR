"""Alerts tab — full-page alerts list + per-alert detail view (v0.9.0).

The tab owns a :class:`QStackedWidget` with two pages:

* Index 0 — the alerts list: filters, search, full-width table.
* Index 1 — :class:`~src.ui.views.alert_detail.AlertDetailView`: the
  forensic-report-style view of one alert. Clicking a row navigates
  here. Clicking the "← Back" button returns to the list.

Before v0.9.0 this tab used a split view (table + side detail panel +
IP reputation card). All of that is superseded by the dedicated
detail page — the side panel couldn't surface every field captured
by the 13-step pipeline, and the forced narrow width made long
Opus reasoning illegible. Ripped out entirely here; the relevant
logic (``rollback_requested``, ``on_rollback_completed``) is
re-exposed at this class level so the outer shell's wiring in
``app.py`` did not need to change.
"""

from __future__ import annotations

import logging
from typing import Any, Optional


from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    Action,
    BodyLabel,
    CaptionLabel,
    ComboBox,
    PushButton,
    RoundMenu,
    SearchLineEdit,
    StrongBodyLabel,
    SubtitleLabel,
    TableWidget,
    TextEdit,
)

from wardsoar.pc.ui.views.alert_detail import AlertDetailView

logger = logging.getLogger("ward_soar.ui.alerts")


# ---------------------------------------------------------------------------
# ManualReviewDialog \u2014 v0.16.0 full implementation.
#
# The Alert Detail view's "Manual Review" button emits
# ``manual_review_requested(record)`` which the shell wires to this
# dialog. The operator can then override the verdict (Confirmed /
# Suspicious / Benign / Inconclusive / Filtered, or "keep original"
# to only add a note). The override is persisted to a dedicated
# append-only file so ``alerts_history.jsonl`` stays immutable.
# ---------------------------------------------------------------------------


#: Verdicts that the operator can pick in the override dropdown.
#: Order matches the UI: keep-original first, then the 5 real
#: verdicts from most-to-least severe so the most common case on a
#: manual review (operator bumps BENIGN \u2192 CONFIRMED after spotting
#: something the AI missed) is high in the list.
_MANUAL_VERDICT_CHOICES: tuple[tuple[str, str], ...] = (
    ("", "\u2014 Keep original verdict, only add a note"),
    ("confirmed", "Confirmed \u2014 operator overrides to confirmed threat"),
    ("suspicious", "Suspicious \u2014 operator keeps an eye on it"),
    ("benign", "Benign \u2014 operator clears it as false positive"),
    ("inconclusive", "Inconclusive \u2014 operator cannot decide"),
    ("filtered", "Filtered \u2014 operator marks as background noise"),
)


class ManualReviewDialog(QDialog):
    """Dialog for manual verdict override + operator notes.

    Emits :attr:`review_submitted` with the raw form values when
    the operator clicks Save. The shell persists the review via
    :mod:`src.manual_reviews`.
    """

    #: Signal payload: ``(alert_ts, original_verdict, operator_verdict, notes)``.
    review_submitted = Signal(str, str, str, str)

    def __init__(self, record: dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._record = record
        self.setWindowTitle("Manual Review")
        self.setMinimumSize(560, 460)
        # Align on Fluent dark canvas (same fix as keys_view / detail view).
        self.setStyleSheet("background-color: #1E1E1E; color: #F0F0F0;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # --- Header summary --------------------------------------------
        layout.addWidget(SubtitleLabel("Manual review"))

        src = str(record.get("src_ip") or "?")
        dst = str(record.get("dest_ip") or "?")
        sig = str(record.get("signature") or "?")
        sid = str(record.get("signature_id") or "")
        summary_text = f"{src} \u2192 {dst}  \u2022  {sig}"
        if sid:
            summary_text += f"  (SID {sid})"
        summary = BodyLabel(summary_text)
        summary.setWordWrap(True)
        summary.setStyleSheet("color: #CFCFCF;")
        layout.addWidget(summary)

        original = str(record.get("verdict") or "unknown").lower()
        orig_line = CaptionLabel(f"Pipeline verdict: {original.upper()}")
        orig_line.setStyleSheet("color: #A0A0A0;")
        layout.addWidget(orig_line)

        # --- Verdict override ------------------------------------------
        layout.addWidget(StrongBodyLabel("Override verdict"))
        self._verdict_combo = ComboBox()
        for _code, label in _MANUAL_VERDICT_CHOICES:
            self._verdict_combo.addItem(label)
        self._verdict_combo.setCurrentIndex(0)
        layout.addWidget(self._verdict_combo)

        # --- Notes -----------------------------------------------------
        layout.addWidget(StrongBodyLabel("Notes / justification"))
        self._notes_edit = TextEdit()
        self._notes_edit.setPlaceholderText(
            "Why are you overriding this verdict? Document what you saw that "
            "the pipeline missed \u2014 the note is kept verbatim in your "
            "history."
        )
        self._notes_edit.setMinimumHeight(160)
        layout.addWidget(self._notes_edit)

        # --- Footer buttons --------------------------------------------
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(self._on_save_clicked)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _on_save_clicked(self) -> None:
        """Validate + emit the review then close the dialog."""
        index = self._verdict_combo.currentIndex()
        if index < 0 or index >= len(_MANUAL_VERDICT_CHOICES):
            operator_verdict = ""
        else:
            operator_verdict = _MANUAL_VERDICT_CHOICES[index][0]

        notes = self._notes_edit.toPlainText().strip()
        if not operator_verdict and not notes:
            # Nothing to save \u2014 tell the user by disabling the save and
            # leaving the dialog open. We use a simple hint instead of a
            # popup to keep the flow linear.
            self._notes_edit.setPlaceholderText(
                "Please pick an override verdict OR write a note before saving."
            )
            return

        alert_ts = str(self._record.get("_ts") or "")
        original = str(self._record.get("verdict") or "").lower()
        self.review_submitted.emit(alert_ts, original, operator_verdict, notes)
        self.accept()


# ---------------------------------------------------------------------------
# Row colours — kept local so the list stays consistent without hard
# dependency on the detail view's colour map.
# ---------------------------------------------------------------------------


def _format_time_cell(alert: dict[str, Any]) -> str:
    """Render the Time column as ``YYYY-MM-DD HH:MM:SS`` whenever possible.

    Historical alerts persisted before v0.22.3 stored only ``HH:MM:SS``
    in the ``time`` field. To display a full date+time in the table
    without migrating the history file, fall back to the ISO ``_ts``
    attached to every persisted entry by
    ``HistoryController.persist_alert``.
    Live alerts built by v0.22.3+ already carry the full format in
    ``time``, so the extra derivation is a no-op for them.
    """
    raw = str(alert.get("time") or "")
    # v0.22.3+ format already has the date → return as-is.
    if len(raw) >= 16 and raw[4] == "-":
        return raw
    ts = str(alert.get("_ts") or "")
    # Expected ISO-8601: "YYYY-MM-DDTHH:MM:SS[.ffffff][+00:00]"
    if len(ts) >= 19 and ts[4] == "-" and (ts[10] in ("T", " ")):
        return f"{ts[:10]} {ts[11:19]}"
    return raw


_MONTH_NAMES: tuple[str, ...] = (
    "",  # padding so index matches the 1-based month number
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)


def _format_month_label(month_iso: str) -> str:
    """Render ``"2026-04"`` as ``"April 2026"``.

    Falls back to the raw ISO string if the input is malformed so
    the menu never shows an empty entry.
    """
    try:
        year_s, month_s = month_iso.split("-", 1)
        month_idx = int(month_s)
        if 1 <= month_idx <= 12:
            return f"{_MONTH_NAMES[month_idx]} {year_s}"
    except (ValueError, IndexError):
        pass
    return month_iso


_VERDICT_COLOURS: dict[str, QColor] = {
    "confirmed": QColor(244, 67, 54),
    "suspicious": QColor(255, 152, 0),
    "benign": QColor(76, 175, 80),
    "inconclusive": QColor(158, 158, 158),
    "filtered": QColor(100, 149, 237),
}


class AlertsView(QWidget):
    """Alerts tab: list page + detail page switched via a QStackedWidget.

    Signals:
        rollback_requested: emitted with (ip, sid_or_None) when the
            operator clicks "Unblock IP" in the detail view. The shell
            forwards to the engine worker for actual pfSense rollback.
        add_sid_filter_requested: emitted with (sid, signature) when
            the operator clicks "Add SID to filter" in the detail
            view. The shell calls the user-overlay helper.
        manual_review_requested: emitted with the alert record dict
            when the operator clicks "Manual Review" in the detail
            view. The shell opens the :class:`ManualReviewDialog`.
        forensic_report_requested: emitted with the alert record dict
            when the operator clicks "Forensic Report" in the detail
            view. The shell opens the zip location in Explorer.
    """

    rollback_requested = Signal(str, object)
    add_sid_filter_requested = Signal(int, str)
    manual_review_requested = Signal(dict)
    forensic_report_requested = Signal(dict)
    #: v0.22.1 — emitted when the operator clicks "Load 200 older".
    #: Payload is how many entries of the current month are already
    #: loaded (the offset cursor). The shell answers via
    #: :meth:`append_older_alerts`.
    load_older_requested = Signal(int)
    #: Emitted when the operator picks an archive in the Archives
    #: menu. Payload is the absolute archive path as returned by
    #: ``engine.list_history_archives``.
    load_archive_requested = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self._alert_data: list[dict[str, Any]] = []
        #: Count of current-month entries already loaded (via the
        #: initial reload + subsequent "Load older" pages). Drives
        #: the offset cursor. Live alerts pushed by the engine do
        #: NOT increment it — only historical reads do, because
        #: ``older_than_count`` is anchored at the end of the file.
        self._active_file_loaded = 0
        #: Archive paths already merged into the view — used to grey
        #: out menu entries the operator has already loaded so they
        #: cannot double-load the same archive by mistake.
        self._loaded_archive_paths: set[str] = set()

        # v0.14.1 UX fix \u2014 inherit the Fluent dark canvas, same as
        # the other full-page tabs. Without this, the detail page
        # (AlertDetailView) renders on Qt's default white background.
        self.setStyleSheet("background-color: transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- Stack: list page (0) and detail page (1) ---
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background-color: transparent;")

        self._list_page = self._build_list_page()
        self._detail_view = AlertDetailView()
        # Re-emit signals from the detail view to this view's
        # signals so the outer shell only needs to connect to
        # AlertsView and stays agnostic of the detail widget.
        self._detail_view.back_requested.connect(self._show_list)
        self._detail_view.rollback_requested.connect(self.rollback_requested.emit)
        self._detail_view.add_sid_filter_requested.connect(self.add_sid_filter_requested.emit)
        self._detail_view.manual_review_requested.connect(self.manual_review_requested.emit)
        self._detail_view.forensic_report_requested.connect(self.forensic_report_requested.emit)

        self._stack.addWidget(self._list_page)
        self._stack.addWidget(self._detail_view)
        self._stack.setCurrentIndex(0)

        root.addWidget(self._stack, stretch=1)

    # ------------------------------------------------------------------
    # List page construction
    # ------------------------------------------------------------------

    def _build_list_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # Filter + search bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(BodyLabel("Verdict:"))
        self._verdict_filter = ComboBox()
        self._verdict_filter.addItems(
            ["All", "confirmed", "suspicious", "benign", "inconclusive", "filtered"]
        )
        self._verdict_filter.currentTextChanged.connect(self._on_filters_changed)
        filter_layout.addWidget(self._verdict_filter)
        self._search_input = SearchLineEdit()
        self._search_input.setPlaceholderText("Search alerts…")
        self._search_input.textChanged.connect(self._on_filters_changed)
        filter_layout.addWidget(self._search_input)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Full-page alerts table
        self._alert_table = TableWidget()
        self._alert_table.setColumnCount(6)
        self._alert_table.setHorizontalHeaderLabels(
            ["Time", "Src IP", "Dest IP", "Signature", "Verdict", "Severity"]
        )
        header = self._alert_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(60)
        self._alert_table.setColumnWidth(0, 180)  # Time (YYYY-MM-DD HH:MM:SS, 19 chars)
        self._alert_table.setColumnWidth(1, 160)  # Src IP
        self._alert_table.setColumnWidth(2, 160)  # Dest IP
        # Signature (col 3) stretches to fill remaining width
        self._alert_table.setColumnWidth(4, 120)  # Verdict
        self._alert_table.setColumnWidth(5, 90)  # Severity
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._alert_table.verticalHeader().setVisible(False)
        self._alert_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._alert_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self._alert_table.setRowCount(0)
        # Click (row select) opens the detail view. The old behaviour
        # was to just update a side panel — we now navigate.
        self._alert_table.cellActivated.connect(self._on_row_activated)
        self._alert_table.cellClicked.connect(self._on_row_activated)
        layout.addWidget(self._alert_table, stretch=1)

        # v0.22.1 — history footer. Caption on the left reports
        # how many rows are shown; "Load 200 older" pages backward
        # through the current month (the active file is bounded
        # to it by the rotator); "Archives ▾" lets the operator
        # pull any past month on demand as a full batch.
        history_bar = QHBoxLayout()
        self._history_status = CaptionLabel("")
        history_bar.addWidget(self._history_status)
        history_bar.addStretch()
        self._load_older_btn = PushButton("Load 200 older")
        self._load_older_btn.clicked.connect(self._on_load_older_clicked)
        history_bar.addWidget(self._load_older_btn)
        # Plain PushButton + an explicit click handler that rebuilds
        # and popups the RoundMenu. Earlier attempts (QMenu +
        # PushButton.setMenu, then DropDownPushButton + RoundMenu)
        # both failed on the operator's box: the first because
        # DropDownPushButton's ``_showMenu`` expects a RoundMenu
        # ``.view`` attr, the second because ``aboutToShow`` was
        # not emitted in the drop-down flow. Owning the flow
        # manually removes both traps.
        self._archives_btn = PushButton("Archives \u25be")
        self._archives_btn.clicked.connect(self._on_archives_btn_clicked)
        self._archives_menu = RoundMenu(parent=self._archives_btn)
        history_bar.addWidget(self._archives_btn)
        layout.addLayout(history_bar)

        return page

    # ------------------------------------------------------------------
    # Public API — consumed by the shell (``app.py``)
    # ------------------------------------------------------------------

    def add_alert_row(self, alert: dict[str, Any]) -> None:
        """Add a new alert row at the top (newest-first, v0.8.5 convention)."""
        row = 0
        self._alert_table.insertRow(row)

        item_map = {
            0: _format_time_cell(alert),
            1: alert.get("src_ip", ""),
            2: alert.get("dest_ip", ""),
            3: alert.get("signature", ""),
            4: alert.get("verdict", ""),
            5: alert.get("severity", ""),
        }
        for col, value in item_map.items():
            item = QTableWidgetItem(str(value))
            if col == 4:
                fg = _VERDICT_COLOURS.get(str(alert.get("verdict", "")).lower())
                if fg:
                    item.setForeground(fg)
            self._alert_table.setItem(row, col, item)

        self._alert_data.insert(0, alert)
        self._alert_table.scrollToTop()
        self._refresh_history_status()

    def mark_history_loaded(self, count_from_active_file: int) -> None:
        """Declare how many active-file entries the shell fed in.

        Called by :class:`WardApp` right after the initial reload so
        the Load older cursor is aligned with the table. Separate
        from ``add_alert_row`` because live incoming alerts must NOT
        advance the cursor (they sit at the top, not at the tail).
        """
        self._active_file_loaded = count_from_active_file
        self._refresh_history_status()

    def append_older_alerts(self, alerts: list[dict[str, Any]]) -> None:
        """Append a page of older current-month entries at the bottom.

        Empty batch = the current month is exhausted: the Load
        older button greys out and the operator is expected to use
        the Archives menu for past months.

        After appending, the table scrolls so the first newly-loaded
        row sits at the top of the viewport. Otherwise the new
        rows hide below the scrollbar and the click feels like a
        no-op (reported on 0.22.1).
        """
        if not alerts:
            self._load_older_btn.setEnabled(False)
            self._refresh_history_status(exhausted_active=True)
            return
        # Index where the first new row lands. Captured BEFORE
        # the inserts so the scroll target is accurate.
        first_new_row = self._alert_table.rowCount()
        # Entries returned by ``load_history_page`` are in file order
        # (oldest first within the page). Iterate in reverse so the
        # first appended row is the newest of the page, landing right
        # below what is currently on screen and preserving the
        # newest-on-top chronology.
        for alert in reversed(alerts):
            self._append_row_at_end(alert)
        self._active_file_loaded += len(alerts)
        self._refresh_history_status()
        target = self._alert_table.item(first_new_row, 0)
        if target is not None:
            self._alert_table.scrollToItem(target, QAbstractItemView.ScrollHint.PositionAtTop)

    def append_archive_alerts(self, archive_path: str, alerts: list[dict[str, Any]]) -> None:
        """Append an archive's alerts at the bottom of the table.

        The same archive can only be loaded once per session —
        menu entries for already-loaded archives are disabled.

        Like "Load older", we scroll to the first newly-added row
        so the operator sees the archive's content appear without
        having to hunt for it below the viewport fold.
        """
        self._loaded_archive_paths.add(archive_path)
        if not alerts:
            self._refresh_history_status()
            return
        first_new_row = self._alert_table.rowCount()
        # Entries returned by ``load_archive`` are in file order
        # (oldest first). Iterate in reverse so the newest of the
        # month lands right below what the table currently shows.
        for alert in reversed(alerts):
            self._append_row_at_end(alert)
        self._refresh_history_status()
        target = self._alert_table.item(first_new_row, 0)
        if target is not None:
            self._alert_table.scrollToItem(target, QAbstractItemView.ScrollHint.PositionAtTop)

    def _append_row_at_end(self, alert: dict[str, Any]) -> None:
        """Shared tail-insert for archive loads."""
        row = self._alert_table.rowCount()
        self._alert_table.insertRow(row)
        item_map = {
            0: _format_time_cell(alert),
            1: alert.get("src_ip", ""),
            2: alert.get("dest_ip", ""),
            3: alert.get("signature", ""),
            4: alert.get("verdict", ""),
            5: alert.get("severity", ""),
        }
        for col, value in item_map.items():
            item = QTableWidgetItem(str(value))
            if col == 4:
                fg = _VERDICT_COLOURS.get(str(alert.get("verdict", "")).lower())
                if fg:
                    item.setForeground(fg)
            self._alert_table.setItem(row, col, item)
        # Keep ``_alert_data`` aligned with the table: the row index
        # must match the list index so ``_on_row_activated`` resolves
        # the correct record for the detail view.
        self._alert_data.append(alert)

    def _refresh_history_status(self, *, exhausted_active: bool = False) -> None:
        """Update the caption that reports how much is loaded."""
        parts = [f"{self._alert_table.rowCount()} loaded"]
        if exhausted_active:
            parts.append("(current month exhausted \u2014 use Archives)")
        self._history_status.setText("  \u00b7  ".join(parts))

    def clear_alerts(self) -> None:
        """Clear all alerts from the table."""
        self._alert_table.setRowCount(0)
        self._alert_data.clear()
        self._active_file_loaded = 0
        self._loaded_archive_paths.clear()
        self._load_older_btn.setEnabled(True)
        self._refresh_history_status()
        # Also reset the detail view if it was showing something.
        self._detail_view.set_record({})
        self._show_list()

    def on_rollback_completed(self, payload: dict[str, Any]) -> None:
        """Called by the shell after the engine finishes a rollback.

        Re-enables the ``Unblock IP`` button regardless of outcome
        so the operator can retry a failed rollback. The success /
        failure message is surfaced via a tray toast elsewhere.
        """
        # The detail view owns the button state. Refresh the visibility
        # using the current record so the new state (no active block)
        # propagates.
        ip = payload.get("ip", "")
        current_src = self._detail_view._current_record.get("src_ip") or ""  # noqa: SLF001
        if ip and current_src == ip and payload.get("success"):
            # Successful rollback → remove the block action from the
            # record so the button stops offering to unblock.
            record = dict(self._detail_view._current_record)  # noqa: SLF001
            record["actions"] = [
                a for a in record.get("actions") or [] if a not in ("ip_block", "ip_port_block")
            ]
            self._detail_view.set_record(record)
        else:
            # Failure: re-enable so user can retry.
            self._detail_view._unblock_btn.setEnabled(True)  # noqa: SLF001

    def on_sid_filtered(self, sid: int, success: bool, message: str) -> None:
        """Called by the shell after the Add-SID-to-filter completes.

        Re-enables the Add-SID button. On success, hides it because
        the SID is now filtered — it won't recur on this alert's
        verdict pane.
        """
        btn = self._detail_view._addfp_btn  # noqa: SLF001
        btn.setEnabled(True)
        if success:
            btn.setVisible(False)

    # ------------------------------------------------------------------
    # Lazy history loading (v0.22.1)
    # ------------------------------------------------------------------

    def set_archive_provider(self, provider: Any) -> None:
        """Inject the callable the Archives menu uses to list archives.

        The shell passes ``engine.list_history_archives`` here. We
        keep it behind a provider so the view has no direct handle
        on the engine worker (consistent with how custom rules /
        audit buttons are wired).
        """
        self._archive_provider = provider

    def _on_archives_btn_clicked(self) -> None:
        """Rebuild the Archives menu and pop it up below the button.

        Owning the flow explicitly avoids the two earlier failure
        modes (QMenu incompatible with DropDownPushButton, and
        ``aboutToShow`` not emitted by DropDownPushButton's path).
        """
        self._rebuild_archives_menu()
        # Anchor the menu just below the button so it behaves like
        # a normal drop-down from the operator's point of view.
        from PySide6.QtCore import QPoint

        pos = self._archives_btn.mapToGlobal(QPoint(0, self._archives_btn.height()))
        self._archives_menu.exec(pos)

    def _on_load_older_clicked(self) -> None:
        """Emit the pagination request; shell fills in the result."""
        self.load_older_requested.emit(self._active_file_loaded)

    def _rebuild_archives_menu(self) -> None:
        """Rebuild the Archives dropdown from the injected provider."""
        self._archives_menu.clear()
        provider = getattr(self, "_archive_provider", None)
        if provider is None:
            action = Action("No archive provider wired", self._archives_menu)
            action.setEnabled(False)
            self._archives_menu.addAction(action)
            return
        try:
            archives = list(provider())
        except Exception:  # noqa: BLE001 — defensive; an empty menu is acceptable
            logger.warning("Failed to list history archives", exc_info=True)
            archives = []
        self._archives_cache = archives
        if not archives:
            action = Action("No archives yet", self._archives_menu)
            action.setEnabled(False)
            self._archives_menu.addAction(action)
            return
        for info in archives:
            path = str(info.get("path", ""))
            month = str(info.get("month", "?"))  # "2026-04"
            size = int(info.get("size_bytes", 0) or 0)
            size_kb = max(1, size // 1024)
            label = f"{_format_month_label(month)}  \u2014  {size_kb} kB"
            action = Action(label, self._archives_menu)
            if path in self._loaded_archive_paths:
                action.setEnabled(False)
                action.setText(f"{label}  (already loaded)")
            else:
                action.triggered.connect(
                    lambda _=False, p=path: self.load_archive_requested.emit(p)
                )
            self._archives_menu.addAction(action)

    # ------------------------------------------------------------------
    # Navigation helpers
    # ------------------------------------------------------------------

    def _show_list(self) -> None:
        self._stack.setCurrentIndex(0)

    def _show_detail(self, record: dict[str, Any]) -> None:
        self._detail_view.set_record(record)
        self._stack.setCurrentIndex(1)

    def _on_row_activated(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._alert_data):
            self._show_detail(self._alert_data[row])

    # ------------------------------------------------------------------
    # Filter + search
    # ------------------------------------------------------------------

    def _on_filters_changed(self) -> None:
        """Re-apply the verdict filter + search text to every row."""
        verdict_filter = self._verdict_filter.currentText().lower()
        search_text = self._search_input.text().strip().lower()
        for i, alert in enumerate(self._alert_data):
            matches_verdict = (
                verdict_filter == "all" or str(alert.get("verdict", "")).lower() == verdict_filter
            )
            matches_search = not search_text or any(
                search_text in str(alert.get(f, "")).lower()
                for f in ("src_ip", "dest_ip", "signature", "signature_id")
            )
            self._alert_table.setRowHidden(i, not (matches_verdict and matches_search))


__all__ = ["AlertsView", "ManualReviewDialog"]
