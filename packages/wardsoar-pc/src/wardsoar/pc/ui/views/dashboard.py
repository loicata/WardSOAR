"""Dashboard tab — system status, metrics, health, and time-scaled charts.

Displays system status, key metrics (Alerts/Blocked), healthcheck grid,
and four charts (Alerts, Verdicts, Blocked IPs, Top Source IPs) with
selectable time scale: Minute, Hour, Day, Week, Month, Year.

Uses PyQt-Fluent-Widgets + PySide6 QtCharts.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QStackedBarSeries,
    QValueAxis,
)
from PySide6.QtCore import QMargins, Qt, Signal
from PySide6.QtGui import QColor, QCursor, QPainter
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    CaptionLabel,
    MessageBox,
    PushButton,
    SimpleCardWidget,
    SubtitleLabel,
    TableWidget,
    TitleLabel,
)

logger = logging.getLogger("ward_soar.ui.dashboard")

# Chart colors
COLOR_BG = QColor(30, 30, 30)
COLOR_TEXT = QColor(180, 180, 180)
COLOR_BLUE = QColor(0, 120, 212)
COLOR_RED = QColor(244, 67, 54)
COLOR_ORANGE = QColor(255, 152, 0)
COLOR_GREEN = QColor(76, 175, 80)
COLOR_GREY = QColor(158, 158, 158)

# Time scale definitions: (label, key, title_suffix)
SCALES: list[tuple[str, str, str]] = [
    ("1 min", "minute", "1 min"),
    ("1 h", "hour", "1 h"),
    ("1 j", "day", "24 h"),
    ("1 sem", "week", "7 j"),
    ("1 mois", "month", "30 j"),
    ("1 an", "year", "12 mois"),
]

# Button styles
_BTN_ACTIVE = (
    "QPushButton { color: #ffffff; background-color: #0078d4; "
    "border: none; border-radius: 4px; padding: 4px 10px; font-size: 12px; }"
)
_BTN_INACTIVE = (
    "QPushButton { color: #b4b4b4; background-color: transparent; "
    "border: 1px solid #555555; border-radius: 4px; padding: 4px 10px; font-size: 12px; }"
    "QPushButton:hover { border-color: #0078d4; color: #0078d4; }"
)


def _create_dark_chart(title: str) -> QChart:
    """Create a chart with dark theme styling."""
    chart = QChart()
    chart.setTitle(title)
    chart.setTitleBrush(COLOR_TEXT)
    chart.setBackgroundBrush(COLOR_BG)
    chart.legend().setLabelColor(COLOR_TEXT)
    chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
    chart.setMargins(QMargins(4, 4, 4, 4))
    return chart


def _time_labels(scale: str) -> list[str]:
    """Generate time-axis labels for the given scale.

    v0.9.7 — returns at most 12 labels per time-based scale so every
    label fits without Qt collision-hiding. Each label matches the
    bucket key produced by :func:`_bucket_key` for a timestamp that
    falls inside it.
    """
    now = datetime.now(timezone.utc)
    if scale == "minute":
        # 12 buckets of 5 seconds. Oldest bucket at now - 55s.
        labels: list[str] = []
        base = now.replace(second=(now.second // 5) * 5, microsecond=0)
        for i in range(12):
            lbl = (base - timedelta(seconds=(11 - i) * 5)).strftime("%M:%S")
            labels.append(lbl)
        return labels
    if scale == "hour":
        # 12 buckets of 5 minutes. Oldest at now - 55 min.
        labels = []
        base = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
        for i in range(12):
            lbl = (base - timedelta(minutes=(11 - i) * 5)).strftime("%H:%M")
            labels.append(lbl)
        return labels
    if scale == "day":
        # 12 buckets of 2 hours. Oldest at now - 22 h.
        labels = []
        base = now.replace(hour=(now.hour // 2) * 2, minute=0, second=0, microsecond=0)
        for i in range(12):
            lbl = (base - timedelta(hours=(11 - i) * 2)).strftime("%Hh")
            labels.append(lbl)
        return labels
    if scale == "week":
        # Last 7 days, 1 bar per day.
        return [(now - timedelta(days=6 - i)).strftime("%a") for i in range(7)]
    if scale == "month":
        # 10 buckets of 3 days. Oldest at now - 27 days.
        labels = []
        # Floor today's day to the 3-day grid (1, 4, 7, ..., 28)
        today_floor_day = ((now.day - 1) // 3) * 3 + 1
        base = now.replace(day=today_floor_day, hour=0, minute=0, second=0, microsecond=0)
        for i in range(10):
            dt = base - timedelta(days=(9 - i) * 3)
            labels.append(f"{dt.day:02d}/{dt.month:02d}")
        return labels
    # year: last 12 months, 1 bar per month
    labels = []
    for i in range(12):
        dt = now - timedelta(days=(11 - i) * 30)
        labels.append(dt.strftime("%b"))
    return labels


#: Keep every Nth label for a given scale and replace the rest with
#: empty strings. Qt Charts has no "show every Nth tick" API on a
#: ``QBarCategoryAxis`` — each category is a tick, and if you give it
#: 60 categories it tries to render all 60 labels side-by-side and
#: collapses them to "..." when they don't fit. Thinning the label
#: list at source is the simplest workaround and matches the v0.9.0
#: decision not to introduce a datetime axis (~200 lines of refactor).
_SCALE_LABEL_STEP: dict[str, int] = {
    # v0.9.7 — every bucket now carries its own label (step=1 on all
    # scales). Previously we packed 60 bars per minute/hour view with
    # thinned labels, but Qt silently dropped overlapping labels when
    # the "HH:MM:SS" / "MM:SS" format was too wide, producing visible
    # gaps. The bucket coarsening in :func:`_bucket_key` ensures every
    # scale has at most 12 bars, so step=1 is always safe.
    "minute": 1,
    "hour": 1,
    "day": 1,
    "week": 1,
    "month": 1,
    "year": 1,
}


def _nice_y_ticks(raw_max: int) -> tuple[int, int]:
    """Choose a Y-axis max + tick count that produces INTEGER labels.

    Alert counts are always integers (0, 1, 2, 3 …), but Qt's default
    ``QValueAxis`` with ``setRange(0, max_val + 2)`` and the default
    5-tick layout produces fractional labels like
    ``0.0, 1.3, 2.5, 3.8, 5.0`` — unreadable for a counts-axis.

    This helper picks a "nice" step (power-of-ten × {1, 2, 5}) so that
    every tick lands on a clean integer:

    * ``raw_max = 0``  →  ``(5, 6)``   →  0, 1, 2, 3, 4, 5
    * ``raw_max = 3``  →  ``(5, 6)``   →  0, 1, 2, 3, 4, 5
    * ``raw_max = 10`` →  ``(12, 7)``  →  0, 2, 4, 6, 8, 10, 12
    * ``raw_max = 34`` →  ``(40, 5)``  →  0, 10, 20, 30, 40
    * ``raw_max = 100``→  ``(120, 7)`` →  0, 20, 40, 60, 80, 100, 120

    Pads the raw max by ~20 % so the tallest bar never touches the
    frame, rounds UP to the nearest step multiple, then returns the
    tick count that keeps intervals between 5 and 8 for readability.
    """
    if raw_max <= 0:
        return (5, 6)
    padded = max(5, raw_max + max(1, raw_max // 5))
    for step in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10_000):
        y_max = ((padded + step - 1) // step) * step
        tick_count = y_max // step + 1
        if 5 <= tick_count <= 8:
            return (y_max, tick_count)
    # Fallback — shouldn't happen for any realistic alert volume.
    return (padded, 6)


def _display_labels(full_labels: list[str], scale: str) -> list[str]:
    """Blank-out non-keep labels to avoid X-axis overlap.

    The chart keeps all N bars (one per timestamp), but only every
    ``step`` labels are rendered; the rest are returned as ``""`` so
    Qt just draws the tick without any text. Without this, 1-hour and
    1-minute scales showed "..." on every label slot.

    v0.9.5: use forward-aligned indices ``{0, step, 2*step, ...}``
    so every visible label sits at a clean ``step``-sized interval.
    The previous ``{0, n-1, ...}`` approach forced index 0 AND index
    ``n-1``, which on scales where ``(n-1) % step != 0`` (minute 60/10,
    hour 60/10, day 24/3, month 30/5) produced an irregular first gap:
    e.g. minute showed labels at indices {0, 9, 19, 29, 39, 49, 59},
    with the 0→9 gap visually narrower than the uniform 10-wide gaps
    that followed. We now drop the last label on dense scales — the
    most-recent bar is still drawn, just unlabelled — in exchange for
    perfectly regular spacing across the whole axis.
    """
    step = _SCALE_LABEL_STEP.get(scale, 1)
    if step <= 1:
        return list(full_labels)
    n = len(full_labels)
    keep_indices = set(range(0, n, step))
    return [lbl if i in keep_indices else "" for i, lbl in enumerate(full_labels)]


def _bucket_key(dt: datetime, scale: str) -> str:
    """Map a datetime to its bucket label for the given scale.

    v0.9.7 — dense scales now use FIXED-SIZE buckets that coarsen to
    ≤12 bars per chart, so every bar carries its own label without
    Qt collision-hiding. The previous design emitted 60 bars per
    minute/hour view with step=5 label thinning, but Qt silently
    dropped every other label when the chosen format ("HH:MM:SS" or
    even "MM:SS") was too wide for the per-bar slot — producing the
    reported "2nd column has no value" gap.

    * ``minute``  — 12 buckets of 5 seconds  → label ``MM:SS``
    * ``hour``    — 12 buckets of 5 minutes  → label ``HH:MM``
    * ``day``     — 12 buckets of 2 hours    → label ``HHh``
    * ``week``    — 7 buckets of 1 day        → label day-abbrev
    * ``month``   — 10 buckets of 3 days      → label ``DD/MM``
    * ``year``    — 12 buckets of 1 month     → label month-abbrev

    The ``dt`` argument is floored to the bucket boundary so two
    timestamps one second apart land in the same bar on the minute
    view.
    """
    if scale == "minute":
        floored = dt.replace(second=(dt.second // 5) * 5, microsecond=0)
        return floored.strftime("%M:%S")
    if scale == "hour":
        floored = dt.replace(minute=(dt.minute // 5) * 5, second=0, microsecond=0)
        return floored.strftime("%H:%M")
    if scale == "day":
        floored = dt.replace(hour=(dt.hour // 2) * 2, minute=0, second=0, microsecond=0)
        return floored.strftime("%Hh")
    if scale == "week":
        return dt.strftime("%a")
    if scale == "month":
        # Day-of-month floored to a 3-day window starting at day 1
        # (so days 1-3 -> "01/MM", 4-6 -> "04/MM", …, 28-30 -> "28/MM").
        day_floor = ((dt.day - 1) // 3) * 3 + 1
        return f"{day_floor:02d}/{dt.month:02d}"
    # year
    return dt.strftime("%b")


def _time_window(scale: str) -> timedelta:
    """Return the lookback window for the given scale."""
    if scale == "minute":
        return timedelta(seconds=60)
    if scale == "hour":
        return timedelta(minutes=60)
    if scale == "day":
        return timedelta(hours=24)
    if scale == "week":
        return timedelta(days=7)
    if scale == "month":
        return timedelta(days=30)
    # year
    return timedelta(days=365)


_MODE_CYCLE = ("monitor", "protect", "hard_protect")

_MODE_LABELS = {
    "monitor": "Monitor",
    "protect": "Protect",
    "hard_protect": "Hard Protect",
}

# Per-transition modal copy — one entry per (from, to) pair so the
# operator reads a prompt tailored to the escalation they are about
# to confirm. Order follows _MODE_CYCLE: Monitor → Protect → Hard
# Protect → Monitor.
_MODE_TRANSITION_PROMPTS: dict[tuple[str, str], tuple[str, str]] = {
    ("monitor", "protect"): (
        "Enable Protect mode?",
        "WardSOAR will automatically block confirmed threat IPs on "
        "pfSense (verdict CONFIRMED with confidence above the configured "
        "threshold).",
    ),
    ("protect", "hard_protect"): (
        "Enable Hard Protect mode?",
        "This inverts the block policy: alerts are blocked UNLESS Opus "
        "returns BENIGN with very high confidence (≥ 0.99 by default). "
        "False positives are expected — use the 1-click rollback from "
        "the alert detail panel to recover any legitimate flow.",
    ),
    ("hard_protect", "monitor"): (
        "Return to Monitor mode?",
        "WardSOAR will continue analyzing traffic but will no longer "
        "block any IP. Choose this to safely pause enforcement.",
    ),
}


class DashboardView(QWidget):
    """Dashboard tab with metrics, health, and time-scaled charts.

    Signals:
        mode_changed: Emitted with the new :class:`~src.models.WardMode`
            value ("monitor", "protect", or "hard_protect").
    """

    mode_changed = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # --- Status banner ---
        self._status_card = SimpleCardWidget()
        status_layout = QHBoxLayout(self._status_card)
        status_layout.setContentsMargins(20, 12, 20, 12)

        self._status_label = SubtitleLabel("Operational")
        self._status_label.setStyleSheet("color: #5cb85c;")
        status_layout.addWidget(self._status_label)
        status_layout.addStretch()

        self._ward_mode: str = "monitor"
        self._mode_btn = PushButton("Mode: Monitor")
        self._mode_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._mode_btn.clicked.connect(self._on_mode_clicked)
        self._update_mode_button()
        status_layout.addWidget(self._mode_btn)
        layout.addWidget(self._status_card)

        # --- Main area: Left column + Charts ---
        main_area = QHBoxLayout()
        main_area.setSpacing(12)

        # Left column: Alerts Today + Blocked Today + System Health
        left_col = QVBoxLayout()
        left_col.setSpacing(12)

        # Alerts Today card
        self._alerts_card = SimpleCardWidget()
        self._alerts_card.setFixedWidth(220)
        alerts_layout = QVBoxLayout(self._alerts_card)
        alerts_layout.setContentsMargins(16, 12, 16, 12)
        self._alerts_value = TitleLabel("0")
        self._alerts_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        alerts_layout.addWidget(self._alerts_value)
        alerts_layout.addWidget(
            CaptionLabel("Alerts Today"), alignment=Qt.AlignmentFlag.AlignCenter
        )
        left_col.addWidget(self._alerts_card)

        # Blocked Today card
        self._blocked_card = SimpleCardWidget()
        self._blocked_card.setFixedWidth(220)
        blocked_layout = QVBoxLayout(self._blocked_card)
        blocked_layout.setContentsMargins(16, 12, 16, 12)
        self._blocked_value = TitleLabel("0")
        self._blocked_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        blocked_layout.addWidget(self._blocked_value)
        blocked_layout.addWidget(
            CaptionLabel("Blocked Today"), alignment=Qt.AlignmentFlag.AlignCenter
        )
        left_col.addWidget(self._blocked_card)

        # Unexplained Divergences (24 h) card — Step 11 of
        # project_dual_suricata_sync.md. Visible only when the
        # dual-Suricata configuration is active; in single-source
        # mode the card stays at zero (which is the correct
        # answer — no divergence is even possible without two
        # sources). Hidden by default until the first divergence
        # to keep the dashboard clean for single-source operators.
        self._divergence_card = SimpleCardWidget()
        self._divergence_card.setFixedWidth(220)
        divergence_layout = QVBoxLayout(self._divergence_card)
        divergence_layout.setContentsMargins(16, 12, 16, 12)
        self._divergence_value = TitleLabel("0")
        self._divergence_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        divergence_layout.addWidget(self._divergence_value)
        divergence_layout.addWidget(
            CaptionLabel("Divergences 24 h"),
            alignment=Qt.AlignmentFlag.AlignCenter,
        )
        self._divergence_card.setVisible(False)
        left_col.addWidget(self._divergence_card)

        # System Health card
        health_card = SimpleCardWidget()
        health_card.setFixedWidth(220)
        health_layout = QVBoxLayout(health_card)
        health_layout.setContentsMargins(12, 8, 12, 8)
        health_layout.addWidget(CaptionLabel("System Health"))
        self._health_table = TableWidget()
        self._health_table.setColumnCount(2)
        self._health_table.setHorizontalHeaderLabels(["Component", "Status"])
        self._health_table.horizontalHeader().setStretchLastSection(True)
        self._health_table.verticalHeader().setVisible(False)
        self._health_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._health_table.setShowGrid(False)
        components = [
            "pfSense SSH",
            "Claude API",
            "VirusTotal API",
            "EVE JSON",
            "Sysmon",
            "Disk Space",
        ]
        self._health_table.setRowCount(len(components))
        for i, comp in enumerate(components):
            self._health_table.setItem(i, 0, QTableWidgetItem(comp))
            self._health_table.setItem(i, 1, QTableWidgetItem("Unknown"))
        health_layout.addWidget(self._health_table)
        left_col.addWidget(health_card, stretch=1)

        main_area.addLayout(left_col)

        # --- Right side: scale buttons + charts ---
        right_side = QVBoxLayout()
        right_side.setSpacing(8)

        # Time scale selector bar
        scale_bar = QHBoxLayout()
        scale_bar.setSpacing(6)
        scale_bar.addStretch()

        self._current_scale = "week"
        self._scale_buttons: dict[str, PushButton] = {}

        for label, key, _suffix in SCALES:
            btn = PushButton(label)
            btn.setFixedHeight(28)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(lambda checked=False, k=key: self._on_scale_changed(k))
            self._scale_buttons[key] = btn
            scale_bar.addWidget(btn)

        self._update_scale_buttons()
        right_side.addLayout(scale_bar)

        # Charts grid (2x2)
        charts_widget = QWidget()
        charts_grid = QGridLayout(charts_widget)
        charts_grid.setSpacing(12)
        charts_grid.setContentsMargins(0, 0, 0, 0)

        # Alert data: list of (timestamp, src_ip, verdict, blocked)
        self._alert_records: list[tuple[datetime, str, str, bool]] = []
        self._ip_counts: dict[str, int] = defaultdict(int)

        # Divergence rolling 24 h window (Step 11 of
        # project_dual_suricata_sync.md). Each entry:
        # (timestamp, explanation, is_unexplained). The card displays
        # the count of entries with is_unexplained=True. Pruning
        # happens on every record_divergence call rather than on a
        # timer — same complexity, no extra timer plumbing.
        self._divergence_records: deque[tuple[datetime, str, bool]] = deque()

        # Chart 1: Alerts
        self._alerts_chart = _create_dark_chart("Alerts (7 j)")
        self._alerts_chart.legend().setVisible(False)
        self._alerts_view = QChartView(self._alerts_chart)
        self._alerts_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._build_alerts_chart()
        charts_grid.addWidget(self._alerts_view, 0, 0)

        # Chart 2: Verdicts (stacked)
        self._verdicts_chart = _create_dark_chart("Verdicts (7 j)")
        self._verdicts_view = QChartView(self._verdicts_chart)
        self._verdicts_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._build_verdicts_chart()
        charts_grid.addWidget(self._verdicts_view, 0, 1)

        # Chart 3: Blocked IPs
        self._blocked_chart = _create_dark_chart("Blocked IPs (7 j)")
        self._blocked_chart.legend().setVisible(False)
        self._blocked_view = QChartView(self._blocked_chart)
        self._blocked_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._build_blocked_chart()
        charts_grid.addWidget(self._blocked_view, 1, 0)

        # Chart 4: Top Source IPs
        self._top_ips_chart = _create_dark_chart("Top Source IPs (7 j)")
        self._top_ips_chart.legend().setVisible(False)
        self._top_ips_view = QChartView(self._top_ips_chart)
        self._top_ips_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        charts_grid.addWidget(self._top_ips_view, 1, 1)

        right_side.addWidget(charts_widget, stretch=1)
        main_area.addLayout(right_side, stretch=1)
        layout.addLayout(main_area, stretch=1)

        # Activity callback for forwarding to Activity tab
        self._activity_callback: Optional[Any] = None

    # ----------------------------------------------------------------
    # Time scale
    # ----------------------------------------------------------------

    def _on_scale_changed(self, scale: str) -> None:
        """Handle time scale button click."""
        if scale == self._current_scale:
            return
        self._current_scale = scale
        self._update_scale_buttons()
        self._rebuild_all_charts()

    def _update_scale_buttons(self) -> None:
        """Update button styles to highlight the active scale."""
        for key, btn in self._scale_buttons.items():
            btn.setStyleSheet(_BTN_ACTIVE if key == self._current_scale else _BTN_INACTIVE)

    def _scale_suffix(self) -> str:
        """Return the title suffix for the current scale."""
        for _label, key, suffix in SCALES:
            if key == self._current_scale:
                return suffix
        return ""

    # ----------------------------------------------------------------
    # Data aggregation
    # ----------------------------------------------------------------

    def _filtered_records(self) -> list[tuple[datetime, str, str, bool]]:
        """Return alert records within the current time window."""
        cutoff = datetime.now(timezone.utc) - _time_window(self._current_scale)
        return [(ts, ip, v, b) for ts, ip, v, b in self._alert_records if ts >= cutoff]

    def _aggregate_counts(
        self, labels: list[str], records: list[tuple[datetime, str, str, bool]]
    ) -> dict[str, int]:
        """Aggregate total alert counts per bucket."""
        counts: dict[str, int] = {lbl: 0 for lbl in labels}
        for ts, _ip, _v, _b in records:
            key = _bucket_key(ts, self._current_scale)
            if key in counts:
                counts[key] += 1
        return counts

    def _aggregate_blocked(
        self, labels: list[str], records: list[tuple[datetime, str, str, bool]]
    ) -> dict[str, int]:
        """Aggregate blocked counts per bucket."""
        counts: dict[str, int] = {lbl: 0 for lbl in labels}
        for ts, _ip, _v, blocked in records:
            if blocked:
                key = _bucket_key(ts, self._current_scale)
                if key in counts:
                    counts[key] += 1
        return counts

    def _aggregate_verdicts(
        self, labels: list[str], records: list[tuple[datetime, str, str, bool]]
    ) -> dict[str, dict[str, int]]:
        """Aggregate verdict counts per bucket."""
        verdicts: dict[str, dict[str, int]] = {
            lbl: {
                "confirmed": 0,
                "suspicious": 0,
                "benign": 0,
                "inconclusive": 0,
                "filtered": 0,
            }
            for lbl in labels
        }
        for ts, _ip, verdict, _b in records:
            key = _bucket_key(ts, self._current_scale)
            if key in verdicts and verdict in verdicts[key]:
                verdicts[key][verdict] += 1
        return verdicts

    def _aggregate_ips(self, records: list[tuple[datetime, str, str, bool]]) -> dict[str, int]:
        """Aggregate IP counts within the current window."""
        counts: dict[str, int] = defaultdict(int)
        for _ts, ip, _v, _b in records:
            counts[ip] += 1
        return dict(counts)

    # ----------------------------------------------------------------
    # Chart builders
    # ----------------------------------------------------------------

    def _rebuild_all_charts(self) -> None:
        """Rebuild all 4 charts with current scale."""
        self._build_alerts_chart()
        self._build_verdicts_chart()
        self._build_blocked_chart()
        self._build_top_ips_chart()

    def _build_alerts_chart(self) -> None:
        """Build the alerts bar chart for the current scale."""
        self._alerts_chart.removeAllSeries()
        for axis in self._alerts_chart.axes():
            self._alerts_chart.removeAxis(axis)

        suffix = self._scale_suffix()
        self._alerts_chart.setTitle(f"Alerts ({suffix})")

        labels = _time_labels(self._current_scale)
        records = self._filtered_records()
        counts = self._aggregate_counts(labels, records)

        series = QBarSeries()
        barset = QBarSet("Alerts")
        barset.setColor(COLOR_BLUE)
        for lbl in labels:
            barset.append(counts.get(lbl, 0))
        series.append(barset)
        self._alerts_chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        # v0.9.2 — thin out labels on dense scales (1h = 60 ticks,
        # 1min = 60 ticks, 1month = 30 ticks) so they stop rendering
        # as "..." and become legible. See ``_display_labels``.
        axis_x.append(_display_labels(labels, self._current_scale))
        axis_x.setLabelsColor(COLOR_TEXT)
        self._alerts_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        max_val = max(counts.values(), default=0)
        y_max, tick_count = _nice_y_ticks(max_val)
        axis_y.setRange(0, y_max)
        axis_y.setTickCount(tick_count)
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(COLOR_TEXT)
        self._alerts_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    def _build_verdicts_chart(self) -> None:
        """Build the verdicts stacked bar chart for the current scale."""
        self._verdicts_chart.removeAllSeries()
        for axis in self._verdicts_chart.axes():
            self._verdicts_chart.removeAxis(axis)

        suffix = self._scale_suffix()
        self._verdicts_chart.setTitle(f"Verdicts ({suffix})")

        labels = _time_labels(self._current_scale)
        records = self._filtered_records()
        verdicts = self._aggregate_verdicts(labels, records)

        confirmed = QBarSet("Confirmed")
        confirmed.setColor(COLOR_RED)
        suspicious = QBarSet("Suspicious")
        suspicious.setColor(COLOR_ORANGE)
        benign = QBarSet("Benign")
        benign.setColor(COLOR_GREEN)
        inconclusive = QBarSet("Inconclusive")
        inconclusive.setColor(COLOR_GREY)
        filtered = QBarSet("Filtered")
        filtered.setColor(COLOR_BLUE)

        for lbl in labels:
            v = verdicts.get(lbl, {})
            confirmed.append(v.get("confirmed", 0))
            suspicious.append(v.get("suspicious", 0))
            benign.append(v.get("benign", 0))
            inconclusive.append(v.get("inconclusive", 0))
            filtered.append(v.get("filtered", 0))

        series = QStackedBarSeries()
        series.append(confirmed)
        series.append(suspicious)
        series.append(benign)
        series.append(inconclusive)
        series.append(filtered)
        self._verdicts_chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        # v0.9.2 — thin out labels on dense scales (1h = 60 ticks,
        # 1min = 60 ticks, 1month = 30 ticks) so they stop rendering
        # as "..." and become legible. See ``_display_labels``.
        axis_x.append(_display_labels(labels, self._current_scale))
        axis_x.setLabelsColor(COLOR_TEXT)
        self._verdicts_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        max_val = max(
            (sum(verdicts.get(lbl, {}).values()) for lbl in labels),
            default=0,
        )
        y_max, tick_count = _nice_y_ticks(max_val)
        axis_y.setRange(0, y_max)
        axis_y.setTickCount(tick_count)
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(COLOR_TEXT)
        self._verdicts_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    def _build_blocked_chart(self) -> None:
        """Build the blocked IPs bar chart for the current scale."""
        self._blocked_chart.removeAllSeries()
        for axis in self._blocked_chart.axes():
            self._blocked_chart.removeAxis(axis)

        suffix = self._scale_suffix()
        self._blocked_chart.setTitle(f"Blocked IPs ({suffix})")

        labels = _time_labels(self._current_scale)
        records = self._filtered_records()
        counts = self._aggregate_blocked(labels, records)

        series = QBarSeries()
        barset = QBarSet("Blocked")
        barset.setColor(COLOR_RED)
        for lbl in labels:
            barset.append(counts.get(lbl, 0))
        series.append(barset)
        self._blocked_chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        # v0.9.2 — thin out labels on dense scales (1h = 60 ticks,
        # 1min = 60 ticks, 1month = 30 ticks) so they stop rendering
        # as "..." and become legible. See ``_display_labels``.
        axis_x.append(_display_labels(labels, self._current_scale))
        axis_x.setLabelsColor(COLOR_TEXT)
        self._blocked_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        max_val = max(counts.values(), default=0)
        y_max, tick_count = _nice_y_ticks(max_val)
        axis_y.setRange(0, y_max)
        axis_y.setTickCount(tick_count)
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(COLOR_TEXT)
        self._blocked_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    def _build_top_ips_chart(self) -> None:
        """Build the top 5 source IPs bar chart for the current window."""
        self._top_ips_chart.removeAllSeries()
        for axis in self._top_ips_chart.axes():
            self._top_ips_chart.removeAxis(axis)

        suffix = self._scale_suffix()
        self._top_ips_chart.setTitle(f"Top Source IPs ({suffix})")

        records = self._filtered_records()
        ip_counts = self._aggregate_ips(records)
        top_5 = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if not top_5:
            return

        series = QBarSeries()
        barset = QBarSet("Alerts")
        barset.setColor(COLOR_ORANGE)
        labels: list[str] = []
        for ip, count in reversed(top_5):
            barset.append(count)
            labels.append(ip)

        series.append(barset)
        self._top_ips_chart.addSeries(series)

        # Top Source IPs uses IP strings as labels, NOT time ticks — so
        # no thinning needed (always 5 bars). Pass labels verbatim.
        axis_x = QBarCategoryAxis()
        axis_x.append(labels)
        axis_x.setLabelsColor(COLOR_TEXT)
        self._top_ips_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        max_val = max(c for _, c in top_5)
        y_max, tick_count = _nice_y_ticks(max_val)
        axis_y.setRange(0, y_max)
        axis_y.setTickCount(tick_count)
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(COLOR_TEXT)
        self._top_ips_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    # ----------------------------------------------------------------
    # Public update methods
    # ----------------------------------------------------------------

    def record_alert(
        self,
        src_ip: str,
        verdict: str,
        blocked: bool = False,
        ts: Optional[datetime] = None,
    ) -> None:
        """Record an alert and refresh all charts.

        v0.9.4: ``ts`` is now optional — when supplied (e.g. during
        the startup replay of ``alerts_history.jsonl``) we use the
        alert's actual detection timestamp instead of wall-clock now.
        Previously every historical alert was timestamped at boot
        time, which stacked the entire history into whatever bucket
        the user booted in — a full-height bar at the current hour
        and empty bars everywhere else, which looked like "there are
        no values below the first column".
        """
        bucket_ts = ts if ts is not None else datetime.now(timezone.utc)
        self._alert_records.append((bucket_ts, src_ip, verdict, blocked))
        self._ip_counts[src_ip] += 1
        self._rebuild_all_charts()

    def record_divergence(
        self,
        explanation: str,
        is_unexplained: bool,
        ts: Optional[datetime] = None,
    ) -> None:
        """Record one divergence event for the 24 h rolling counter.

        Step 11 of ``project_dual_suricata_sync.md``: the dashboard
        surface the count of *unexplained* divergences over the
        last 24 hours. Benign-explained divergences (loopback / VPN /
        LAN-only) are recorded too — only unexplained + suricata-dead
        events drive the visible counter — but the deque holds them
        all so a future audit panel can show the full breakdown.

        Args:
            explanation: One of ``"unexplained"``,
                ``"suricata_local_dead"``, ``"loopback_traffic"``,
                ``"vpn_traffic"``, ``"lan_only_traffic"``. Any other
                value is accepted and stored verbatim — the dashboard
                does not gatekeep new explanation tokens.
            is_unexplained: ``True`` when the divergence drives a
                verdict bump. The card counter increments by 1 for
                every such entry. Per Q3 doctrine, this is True for
                ``unexplained`` *and* ``suricata_local_dead``.
            ts: Optional timestamp. Defaults to ``datetime.now`` (UTC).
        """
        now = ts if ts is not None else datetime.now(timezone.utc)
        self._divergence_records.append((now, explanation, is_unexplained))

        # Prune entries older than 24 h. The deque is kept in
        # insertion order — pop from the front while too old.
        cutoff = now - timedelta(hours=24)
        while self._divergence_records and self._divergence_records[0][0] < cutoff:
            self._divergence_records.popleft()

        # Refresh the card. Counter shows ONLY unexplained-class
        # entries — benign-explained divergences are noise to the
        # operator and are excluded from the headline number.
        unexplained_count = sum(
            1 for (_, _expl, unexplained) in self._divergence_records if unexplained
        )
        self._divergence_value.setText(str(unexplained_count))

        # First divergence of the run reveals the card. We test
        # the explicit-hide bit (``isHidden``) rather than the
        # parent-chain visibility (``isVisible``) so the reveal
        # logic also works under unit tests that don't show the
        # window.
        if self._divergence_card.isHidden():
            self._divergence_card.setVisible(True)

    def update_metrics(self, metrics: dict[str, Any]) -> None:
        """Update metric cards from engine data."""
        self._alerts_value.setText(str(metrics.get("alerts_today", 0)))
        self._blocked_value.setText(str(metrics.get("blocked_today", 0)))

    def update_health(self, component: str, status: str) -> None:
        """Update a single component health status."""
        for row in range(self._health_table.rowCount()):
            item = self._health_table.item(row, 0)
            if item and item.text() == component:
                status_item = QTableWidgetItem(status)
                color_map = {
                    "healthy": COLOR_GREEN,
                    "degraded": COLOR_ORANGE,
                    "failed": COLOR_RED,
                }
                fg = color_map.get(status.lower())
                if fg:
                    status_item.setForeground(fg)
                self._health_table.setItem(row, 1, status_item)
                break

    def set_status(self, status: str, mode: str) -> None:
        """Update the status banner and mode button.

        Accepts either a display label (``"Monitor"`` / ``"Protect"`` /
        ``"Hard Protect"``) emitted by the engine's ``status_changed``
        signal, or a canonical WardMode string. Legacy ``"Active"`` is
        treated as ``"Protect"`` for backward compatibility.
        """
        self._status_label.setText(status)
        color_map = {"Operational": "#5cb85c", "Degraded": "#ff9800", "Failed": "#f44336"}
        self._status_label.setStyleSheet(f"color: {color_map.get(status, '#9a9a9a')};")
        self._ward_mode = self._coerce_mode(mode)
        self._update_mode_button()

    @staticmethod
    def _coerce_mode(raw: str) -> str:
        normalised = raw.strip().lower().replace("-", "_").replace(" ", "_")
        if normalised in _MODE_CYCLE:
            return normalised
        if normalised in ("active",):  # legacy pre-0.5.5 label
            return "protect"
        return "monitor"

    def add_activity(self, time: str, event: str, details: str) -> None:
        """Forward activity to the Activity tab via callback."""
        if self._activity_callback:
            self._activity_callback(time, event, details)

    # ----------------------------------------------------------------
    # Mode toggle
    # ----------------------------------------------------------------

    def _on_mode_clicked(self) -> None:
        """Cycle through the three ward modes with a per-transition modal.

        Click once → Monitor → Protect. Click again → Protect → Hard
        Protect. Click again → Hard Protect → Monitor. The operator
        confirms each step, so no escalation can happen accidentally.
        """
        current = self._ward_mode
        try:
            idx = _MODE_CYCLE.index(current)
        except ValueError:
            idx = 0  # fail-safe: treat unknown current as Monitor
        next_mode = _MODE_CYCLE[(idx + 1) % len(_MODE_CYCLE)]

        title, body = _MODE_TRANSITION_PROMPTS[(current, next_mode)]
        msg = MessageBox(title, body, self)
        msg.yesButton.setText("Confirm")
        msg.cancelButton.setText("Cancel")
        if not msg.exec():
            return

        self._ward_mode = next_mode
        self._update_mode_button()
        self.mode_changed.emit(next_mode)
        self.add_activity(
            datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "MODE",
            f"Switched to {_MODE_LABELS[next_mode]}",
        )

    def _update_mode_button(self) -> None:
        """Update mode button text and style — three styles, one per mode.

        Colour progression mirrors the escalation: neutral blue for
        Monitor (informational), amber for Protect (action), red for
        Hard Protect (very aggressive).
        """
        label = _MODE_LABELS.get(self._ward_mode, "Monitor")
        self._mode_btn.setText(f"Mode: {label}")
        if self._ward_mode == "monitor":
            self._mode_btn.setStyleSheet(
                "QPushButton { color: #0078d4; border: 1px solid #0078d4; "
                "border-radius: 6px; padding: 4px 16px; }"
                "QPushButton:hover { background-color: #0078d4; color: white; }"
            )
        elif self._ward_mode == "protect":
            self._mode_btn.setStyleSheet(
                "QPushButton { color: #ffffff; background-color: #d48318; "
                "border: none; border-radius: 6px; padding: 4px 16px; }"
                "QPushButton:hover { background-color: #b06f14; }"
            )
        else:  # hard_protect
            self._mode_btn.setStyleSheet(
                "QPushButton { color: #ffffff; background-color: #d41830; "
                "border: none; border-radius: 6px; padding: 4px 16px; }"
                "QPushButton:hover { background-color: #b01428; }"
            )

    def add_ssh_status(self, status: str, details: str) -> None:
        """Forward SSH status to activity tab."""
        self.add_activity(
            datetime.now(timezone.utc).strftime("%H:%M:%S"),
            f"SSH: {status}",
            details,
        )
