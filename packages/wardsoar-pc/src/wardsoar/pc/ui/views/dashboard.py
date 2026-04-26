"""Dashboard tab — status banner + compact Alerts chart + Sources/Destinations tables.

Top banner shows the current operational status and the Ward mode
toggle. Below it sits a compact stacked-bar chart of alert verdicts
over a selectable time scale (Minute, Hour, Day, Week, Month, Year),
followed by two stacked tables — Sources and Destinations — that
aggregate the alerts by ``src_ip`` and ``dest_ip`` respectively,
enriched with ASN owner / country / CDN-or-SaaS tag from the
``AsnEnricher`` and ``CdnAllowlist`` modules.

The pre-v0.25 layout had four charts (Alerts count, Verdicts,
Blocked IPs, Top Source IPs); three were retired because:

* Alerts (count) duplicated Verdicts which already shows the breakdown.
* Blocked IPs always reads zero in ``dry_run=True`` and is otherwise
  redundant with the red bar of the Verdicts chart.
* Top Source IPs was self-referential — the operator's own PC
  dominated the ranking 90 % of the time. The Sources table below
  surfaces the same data but enriched with Owner/Country/Tag, which
  changes the lecture (e.g. ``192.168.2.100`` is now visibly tagged
  ``[lan]``, the operator-self-reference is one tag away).

Uses PyQt-Fluent-Widgets + PySide6 QtCharts + QTableWidget.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QChart,
    QChartView,
    QStackedBarSeries,
    QBarSet,
    QValueAxis,
)
from PySide6.QtCore import QMargins, Qt, Signal
from PySide6.QtGui import QColor, QCursor, QPainter
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
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

        # --- Charts area: scale buttons + charts ---
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

        # Alert data: list of (timestamp, src_ip, dest_ip, verdict, blocked).
        # ``dest_ip`` was added in v0.25 so the Destinations table can
        # group the same record set by destination — the previous tuple
        # only carried ``src_ip`` because the four charts at the time
        # ranked sources only.
        self._alert_records: list[tuple[datetime, str, str, str, bool]] = []
        self._src_counts: dict[str, int] = defaultdict(int)
        self._dest_counts: dict[str, int] = defaultdict(int)

        # --- Compact Alerts chart (verdicts stacked, ~140 px tall) ---
        # Title is "Alerts (...)" — the underlying series is the same
        # verdict-stacked bars as before, but the historical
        # ``Alerts (count-only)`` chart has been retired since the
        # stacked one already carries the total via the bar height.
        self._alerts_chart = _create_dark_chart("Alerts (7 j)")
        self._alerts_view = QChartView(self._alerts_chart)
        self._alerts_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._alerts_view.setFixedHeight(180)
        self._build_alerts_chart()
        right_side.addWidget(self._alerts_view)

        # --- Sources table (full width, stretch=1) ---
        self._sources_table = self._build_ip_table(("IP", "Alerts", "Owner", "Country", "Tag"))
        self._sources_caption_label = CaptionLabel("Sources (7 j)")
        sources_card = SimpleCardWidget()
        sources_layout = QVBoxLayout(sources_card)
        sources_layout.setContentsMargins(16, 12, 16, 12)
        sources_layout.addWidget(self._sources_caption_label)
        sources_layout.addWidget(self._sources_table)
        right_side.addWidget(sources_card, stretch=1)

        # --- Destinations table (full width, stretch=1) ---
        self._destinations_table = self._build_ip_table(("IP", "Alerts", "Owner", "Country", "Tag"))
        self._destinations_caption_label = CaptionLabel("Destinations (7 j)")
        destinations_card = SimpleCardWidget()
        destinations_layout = QVBoxLayout(destinations_card)
        destinations_layout.setContentsMargins(16, 12, 16, 12)
        destinations_layout.addWidget(self._destinations_caption_label)
        destinations_layout.addWidget(self._destinations_table)
        right_side.addWidget(destinations_card, stretch=1)

        layout.addLayout(right_side, stretch=1)

        # ASN enricher — initialised lazily because it touches the
        # SQLite cache file that lives in the user's data directory.
        # Lookups are cache-only (sync, fast) — uncached IPs render
        # as "—" so the UI stays responsive. The pipeline's
        # ``alert_enrichment`` populates the cache for every alert
        # that passes through, so by the time an alert reaches the
        # Dashboard its IPs are warm.
        self._asn_enricher: Optional[Any] = None
        self._cdn_allowlist: Optional[Any] = None
        try:
            from wardsoar.core.asn_enricher import AsnEnricher
            from wardsoar.core.cdn_allowlist import CdnAllowlist
            from wardsoar.core.config import get_data_dir, get_bundle_dir

            self._asn_enricher = AsnEnricher(cache_path=get_data_dir() / "data" / "asn_cache.db")
            cdn_path = get_bundle_dir() / "config" / "cdn_allowlist.yaml"
            if cdn_path.exists():
                self._cdn_allowlist = CdnAllowlist(cdn_path)
        except Exception as exc:  # noqa: BLE001 — UI must never crash on enrichment init
            logger.debug("Dashboard enrichment init failed: %s", exc)

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

    def _filtered_records(self) -> list[tuple[datetime, str, str, str, bool]]:
        """Return alert records within the current time window."""
        cutoff = datetime.now(timezone.utc) - _time_window(self._current_scale)
        return [(ts, src, dst, v, b) for ts, src, dst, v, b in self._alert_records if ts >= cutoff]

    def _aggregate_verdicts(
        self,
        labels: list[str],
        records: list[tuple[datetime, str, str, str, bool]],
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
        for ts, _src, _dst, verdict, _b in records:
            key = _bucket_key(ts, self._current_scale)
            if key in verdicts and verdict in verdicts[key]:
                verdicts[key][verdict] += 1
        return verdicts

    def _aggregate_by_ip(
        self,
        records: list[tuple[datetime, str, str, str, bool]],
        field: str,
    ) -> dict[str, int]:
        """Aggregate alert counts by ``src`` or ``dest`` IP.

        Args:
            records: Filtered records (already in the time window).
            field: ``"src"`` or ``"dest"``.
        """
        counts: dict[str, int] = defaultdict(int)
        if field == "src":
            for _ts, src, _dst, _v, _b in records:
                counts[src] += 1
        elif field == "dest":
            for _ts, _src, dst, _v, _b in records:
                counts[dst] += 1
        return dict(counts)

    # ----------------------------------------------------------------
    # Chart builders
    # ----------------------------------------------------------------

    def _rebuild_all_charts(self) -> None:
        """Rebuild the alerts chart and the two IP tables for the current scale."""
        self._build_alerts_chart()
        self._rebuild_ip_tables()

    def _build_alerts_chart(self) -> None:
        """Build the stacked-verdict bar chart for the current scale.

        Carries the same data the pre-v0.25 ``Verdicts`` chart did —
        five colour-coded sets (Confirmed / Suspicious / Benign /
        Inconclusive / Filtered) — but is now the *only* time-series
        chart on the Dashboard. The simple count chart was a
        duplicate (same total carried by the bar height here) and the
        Blocked-IPs chart always read zero in dry-run mode.
        """
        self._alerts_chart.removeAllSeries()
        for axis in self._alerts_chart.axes():
            self._alerts_chart.removeAxis(axis)

        suffix = self._scale_suffix()
        self._alerts_chart.setTitle(f"Alerts ({suffix})")

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
        self._alerts_chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        axis_x.append(_display_labels(labels, self._current_scale))
        axis_x.setLabelsColor(COLOR_TEXT)
        self._alerts_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
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
        self._alerts_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    # ----------------------------------------------------------------
    # IP tables (Sources + Destinations)
    # ----------------------------------------------------------------

    def _build_ip_table(self, headers: tuple[str, ...]) -> TableWidget:
        """Common builder for Sources and Destinations tables.

        Both tables share the same column structure; the difference
        is the data source (``src_ip`` vs ``dest_ip``) handled in
        :meth:`_rebuild_ip_tables`.
        """
        table = TableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(list(headers))
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setSortingEnabled(False)
        # IP and Owner stretch; Alerts/Country/Tag fit content.
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        return table

    def _rebuild_ip_tables(self, top_n: int = 20) -> None:
        """Refresh both Sources and Destinations tables for the current scale.

        Aggregates the filtered records by ``src_ip`` and ``dest_ip``,
        sorts by alert count desc, and resolves Owner / Country / Tag
        from the cached ASN lookup. Cache-only (sync) — uncached IPs
        render as ``—`` so the UI stays responsive. The pipeline's
        ``alert_enrichment`` warms the cache for every alert that
        passes through.
        """
        records = self._filtered_records()
        suffix = self._scale_suffix()
        if hasattr(self, "_sources_caption_label"):
            self._sources_caption_label.setText(f"Sources ({suffix})")
        if hasattr(self, "_destinations_caption_label"):
            self._destinations_caption_label.setText(f"Destinations ({suffix})")

        src_counts = self._aggregate_by_ip(records, "src")
        dst_counts = self._aggregate_by_ip(records, "dest")
        self._populate_ip_table(self._sources_table, src_counts, top_n)
        self._populate_ip_table(self._destinations_table, dst_counts, top_n)

    def _populate_ip_table(
        self,
        table: TableWidget,
        ip_counts: dict[str, int],
        top_n: int,
    ) -> None:
        """Fill one table with the top-N IPs by alert count."""
        rows = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        table.setRowCount(len(rows))
        for row_idx, (ip, count) in enumerate(rows):
            owner, country, tag = self._resolve_ip_metadata(ip)
            table.setItem(row_idx, 0, QTableWidgetItem(ip))
            count_item = QTableWidgetItem(f"{count}")
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            table.setItem(row_idx, 1, count_item)
            table.setItem(row_idx, 2, QTableWidgetItem(owner))
            table.setItem(row_idx, 3, QTableWidgetItem(country))
            table.setItem(row_idx, 4, QTableWidgetItem(tag))

    def _resolve_ip_metadata(self, ip: str) -> tuple[str, str, str]:
        """Return ``(owner, country, tag)`` for an IP — cache-only.

        For RFC1918 / loopback / link-local addresses the ASN cache
        will never carry an answer; we synthesise a ``[lan]`` tag and
        skip the network lookup. For external IPs we read the cache
        directly via the private ``_cache_lookup`` so the UI thread
        never blocks on a network call.
        """
        if not ip:
            return ("—", "—", "—")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ("—", "—", "—")
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ("(local network)", "—", "[lan]")

        if self._asn_enricher is None:
            return ("—", "—", "—")
        try:
            info = self._asn_enricher._cache_lookup(ip)  # noqa: SLF001 — sync fast path
        except Exception:  # noqa: BLE001 — never break the UI on a cache hiccup
            return ("—", "—", "—")
        if info is None:
            return ("—", "—", "—")

        owner = info.org or info.name or "—"
        country = info.country or "—"

        tag = ""
        if self._cdn_allowlist is not None and info.asn:
            try:
                match = self._cdn_allowlist.classify_asn(info.asn)
            except Exception:  # noqa: BLE001
                match = None
            if match is not None:
                tag = f"[{match.category}] {match.organisation}"
        return (owner, country, tag)

    # ----------------------------------------------------------------
    # Public update methods
    # ----------------------------------------------------------------

    def record_alert(
        self,
        src_ip: str,
        verdict: str,
        blocked: bool = False,
        ts: Optional[datetime] = None,
        dest_ip: str = "",
    ) -> None:
        """Record an alert and refresh the chart + IP tables.

        v0.9.4: ``ts`` is now optional — when supplied (e.g. during
        the startup replay of ``alerts_history.jsonl``) we use the
        alert's actual detection timestamp instead of wall-clock now.

        v0.25 — added ``dest_ip`` so the new Destinations table can
        group records by destination. Defaults to ``""`` for callers
        (legacy / tests) that haven't been updated; those records
        contribute to Sources only.
        """
        bucket_ts = ts if ts is not None else datetime.now(timezone.utc)
        self._alert_records.append((bucket_ts, src_ip, dest_ip, verdict, blocked))
        if src_ip:
            self._src_counts[src_ip] += 1
        if dest_ip:
            self._dest_counts[dest_ip] += 1
        self._rebuild_all_charts()

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
