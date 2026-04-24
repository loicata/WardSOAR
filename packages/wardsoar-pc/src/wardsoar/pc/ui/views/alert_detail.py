"""Full-page per-alert detail view (v0.9.0 Phase 7j).

Replaces the v0.8.x split-view ``AlertDetailPanel`` + ``IP Lookup``
side cards with a scrollable, forensic-report-style page that surfaces
every field the pipeline captured for a single alert:

* Hero card — verdict, confidence, action, timing.
* Identification — category, severity, mode at detection.
* Pipeline trace — all 13 stages with outcome + short detail.
* Evidence — network context, forensic findings, threat intel.
* AI reasoning — Claude Opus's verdict in full, zero truncation.
* Actions taken — blocks, notifications, forensic bundles.
* Raw eve.json — collapsed by default, expand for the operator
  who needs the complete upstream payload.

A sticky footer carries three context-dependent action buttons
(``Manual Review``, ``Forensic Report``, ``Unblock IP``, ``Add SID
to filter``). Each button's visibility depends on the alert's
verdict and current block state — see :meth:`_refresh_actions`.

Signals
-------
* ``back_requested`` — user clicked ← Back to alerts list.
* ``rollback_requested(ip, sid_or_None)`` — user clicked Unblock IP.
* ``add_sid_filter_requested(sid, signature)`` — user clicked "Add
  SID to filter". The engine writes the overlay + updates the live
  filter; this view just asks.
* ``manual_review_requested(record)`` — user clicked Manual Review.
  The outer shell opens the existing review dialog.
* ``forensic_report_requested(record)`` — user clicked Forensic
  Report. The outer shell opens the existing zip in explorer.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    HyperlinkButton,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SimpleCardWidget,
    TitleLabel,
)

logger = logging.getLogger("ward_soar.ui.alert_detail")


def _escape_html(text: str) -> str:
    """Escape HTML special chars for safe use in a Qt rich-text label.

    Keeps the display-layer templating free of XSS-like issues when
    the caller stuffs an arbitrary string (e.g. a pipeline stage
    detail) into an HTML-rendered ``BodyLabel``. We only need the
    four characters Qt interprets as markup.
    """
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Visual palette — v0.15.1 fix: align on the Fluent Dark theme.
#
# The v0.9.1 palette assumed a LIGHT-GREY panel and used dark text.
# After v0.14.1 wrapped everything in a transparent QScrollArea the
# background is now the Fluent Dark canvas (~#1E1E1E), so the dark
# text became invisible. We now use LIGHT text on dark and
# Material-400 swatches for verdict / outcome colours so they stay
# distinguishable against the dark canvas.
# ---------------------------------------------------------------------------

_TEXT_PRIMARY = "color: #F0F0F0;"
_TEXT_SECONDARY = "color: #CFCFCF;"
_TEXT_MUTED = "color: #A0A0A0;"
_TEXT_NA = "color: #9A9A9A; font-style: italic;"

# PlainTextEdit (Opus reasoning + raw eve.json) needs its own stylesheet
# because the QTextEdit-family widgets don't pick up QLabel-scoped
# styles. Dark background + light text to match the Fluent Dark canvas.
_PLAINTEXT_BLOCK_STYLE = (
    "QPlainTextEdit { color: #F0F0F0; background-color: #1E1E1E; "
    "border: 1px solid #444444; border-radius: 4px; "
    "padding: 6px; font-family: 'Consolas', 'Courier New', monospace; "
    "font-size: 12px; }"
)

_VERDICT_COLORS: dict[str, QColor] = {
    "confirmed": QColor(239, 83, 80),  # red-400 — bright on dark bg
    "suspicious": QColor(255, 167, 38),  # orange-400
    "benign": QColor(102, 187, 106),  # green-400
    "inconclusive": QColor(189, 189, 189),  # grey-400
    "filtered": QColor(66, 165, 245),  # blue-400
}

_VERDICT_ICONS: dict[str, str] = {
    "confirmed": "🔴",
    "suspicious": "🟠",
    "benign": "🟢",
    "inconclusive": "⚫",
    "filtered": "🔵",
}

_OUTCOME_ICONS: dict[str, str] = {
    "passed": "✓",
    "skipped": "─",
    "failed": "✗",
    "filtered": "⊘",
}

_OUTCOME_COLORS: dict[str, QColor] = {
    "passed": QColor(102, 187, 106),  # green-400
    "skipped": QColor(189, 189, 189),  # grey-400
    "failed": QColor(239, 83, 80),  # red-400
    "filtered": QColor(66, 165, 245),  # blue-400
}


# ---------------------------------------------------------------------------
# Section building blocks
# ---------------------------------------------------------------------------


class _CollapsibleSection(QWidget):
    """A section with a ▼ / ▸ toggle and a scrollable content area.

    Click the header to expand/collapse. Default state is expanded.
    Keeps the rendering dumb — the caller stuffs whatever layout it
    wants into :attr:`content_layout`.
    """

    def __init__(self, title: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._expanded = True
        self._title = title

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 6, 0, 6)
        outer.setSpacing(4)

        self._header_btn = PushButton(f"▼  {title.upper()}")
        # Dark text on the light-grey Fluent panel — the v0.9.0
        # default button colour rendered almost as invisible.
        self._header_btn.setStyleSheet(
            "QPushButton { text-align: left; border: none; "
            "color: #F0F0F0; font-weight: bold; padding: 4px 0; }"
            "QPushButton:hover { background-color: rgba(255, 255, 255, 20); }"
        )
        self._header_btn.clicked.connect(self._toggle)
        outer.addWidget(self._header_btn)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(16, 0, 0, 6)
        self._content_layout.setSpacing(4)
        outer.addWidget(self._content)

    @property
    def content_layout(self) -> QVBoxLayout:
        return self._content_layout

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._content.setVisible(self._expanded)
        self._header_btn.setText(f"{'▼' if self._expanded else '▸'}  {self._title.upper()}")


# ---------------------------------------------------------------------------
# Main view
# ---------------------------------------------------------------------------


class AlertDetailView(QWidget):
    """Full-page detail view for one alert.

    Args:
        parent: Parent widget.
    """

    back_requested = Signal()
    rollback_requested = Signal(str, object)  # ip, sid_or_None
    add_sid_filter_requested = Signal(int, str)  # sid, signature
    manual_review_requested = Signal(dict)
    forensic_report_requested = Signal(dict)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._current_record: dict[str, Any] = {}

        # v0.14.1 UX fix \u2014 inherit the Fluent dark canvas. Without
        # this, the AlertDetailView renders on the Qt default white
        # background because the full-page layout doesn't pick up
        # the theme.
        self.setStyleSheet("background-color: transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- Top bar: ← Back + alert id ---
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(16, 12, 16, 6)
        self._back_btn = PushButton("← Back to alerts list")
        self._back_btn.clicked.connect(self.back_requested.emit)
        top_bar.addWidget(self._back_btn)
        top_bar.addStretch()
        self._alert_id_label = CaptionLabel("")
        self._alert_id_label.setStyleSheet(_TEXT_MUTED)
        self._alert_id_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self._alert_id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        top_bar.addWidget(self._alert_id_label)
        root.addLayout(top_bar)

        # --- Scrollable body ---
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        # v0.14.1 UX fix — force the QScrollArea viewport and its
        # inner container to inherit the Fluent canvas (transparent
        # background) instead of the default Qt white panel. Same
        # fix as keys_view.py: the scroll area creates a viewport
        # widget that does not pick up QSS from the parent.
        self._scroll.setStyleSheet(
            "QScrollArea { background-color: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background-color: transparent; }"
        )
        body = QWidget()
        body.setStyleSheet("background-color: transparent;")
        self._body_layout = QVBoxLayout(body)
        self._body_layout.setContentsMargins(24, 8, 24, 24)
        self._body_layout.setSpacing(12)
        self._scroll.setWidget(body)
        root.addWidget(self._scroll, stretch=1)

        # Hero card — set up once, repopulated on each record.
        self._hero_card = SimpleCardWidget()
        hero_layout = QVBoxLayout(self._hero_card)
        hero_layout.setContentsMargins(16, 14, 16, 14)
        self._hero_verdict_label = TitleLabel("…")
        self._hero_meta_label = BodyLabel("")
        self._hero_flow_label = BodyLabel("")
        self._hero_sig_label = BodyLabel("")
        self._hero_time_label = CaptionLabel("")
        # v0.9.1 — force high-contrast text on the hero card so the
        # flow/sig/timestamp don't fade into the dark background. The
        # verdict label keeps its own per-verdict colour (set in
        # _populate_hero).
        for lbl in (self._hero_flow_label, self._hero_sig_label):
            lbl.setStyleSheet(_TEXT_PRIMARY + " font-size: 14px;")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._hero_time_label.setStyleSheet(_TEXT_MUTED)
        self._hero_meta_label.setStyleSheet(_TEXT_SECONDARY)
        hero_layout.addWidget(self._hero_verdict_label)
        hero_layout.addWidget(self._hero_meta_label)
        hero_layout.addWidget(self._hero_flow_label)
        hero_layout.addWidget(self._hero_sig_label)
        hero_layout.addWidget(self._hero_time_label)
        self._body_layout.addWidget(self._hero_card)

        # Sections — created once, each gets its own _CollapsibleSection.
        self._sec_identification = _CollapsibleSection("Identification")
        # v0.10.0 — IP ownership & reputation section. Placed right
        # after IDENTIFICATION so the operator sees who owns the IP
        # before scrolling through the pipeline trace. Works for
        # filtered alerts too (the pipeline Evidence sections are
        # N/A for them).
        self._sec_ip_ownership = _CollapsibleSection("IP ownership & reputation")
        self._sec_pipeline = _CollapsibleSection("Pipeline trace")
        self._sec_network = _CollapsibleSection("Evidence — Network")
        self._sec_forensic = _CollapsibleSection("Evidence — Forensic")
        self._sec_threat = _CollapsibleSection("Evidence — Threat intel")
        self._sec_reasoning = _CollapsibleSection("AI reasoning")
        self._sec_actions = _CollapsibleSection("Actions taken")
        # v0.16.0 — surfaces the operator's manual verdict override
        # when present. Hidden entirely when the alert has no
        # review; the section header only appears once a review is
        # attached.
        self._sec_manual_review = _CollapsibleSection("Manual review")
        self._sec_raw = _CollapsibleSection("Raw eve.json")
        # Raw section starts collapsed — it's the longest and least
        # commonly consulted.
        self._sec_raw._toggle()  # pylint: disable=protected-access

        for sec in (
            self._sec_identification,
            self._sec_ip_ownership,
            self._sec_pipeline,
            self._sec_network,
            self._sec_forensic,
            self._sec_threat,
            self._sec_reasoning,
            self._sec_actions,
            self._sec_manual_review,
            self._sec_raw,
        ):
            self._body_layout.addWidget(sec)
        self._body_layout.addStretch(1)

        # --- Sticky footer with action buttons ---
        footer = QHBoxLayout()
        footer.setContentsMargins(16, 10, 16, 10)
        footer.setSpacing(10)
        self._review_btn = PushButton("✎ Manual Review")
        self._review_btn.clicked.connect(
            lambda: self.manual_review_requested.emit(self._current_record)
        )
        self._forensic_btn = PushButton("📄 Forensic Report")
        self._forensic_btn.clicked.connect(
            lambda: self.forensic_report_requested.emit(self._current_record)
        )
        self._unblock_btn = PrimaryPushButton("⛔ Unblock IP")
        self._unblock_btn.clicked.connect(self._on_unblock_clicked)
        self._addfp_btn = PushButton("➕ Filter SID")
        self._addfp_btn.clicked.connect(self._on_addfp_clicked)
        footer.addWidget(self._review_btn)
        footer.addWidget(self._forensic_btn)
        footer.addWidget(self._unblock_btn)
        footer.addWidget(self._addfp_btn)
        footer.addStretch()
        footer_widget = QFrame()
        footer_widget.setLayout(footer)
        footer_widget.setStyleSheet("QFrame { border-top: 1px solid rgba(128, 128, 128, 60); }")
        root.addWidget(footer_widget)

    # ------------------------------------------------------------------
    # Public API — the shell calls this to (re)populate the view.
    # ------------------------------------------------------------------

    def set_record(self, record: dict[str, Any]) -> None:
        """Re-render every section for the given alert record."""
        self._current_record = dict(record)

        full = record.get("_full") or {}
        self._populate_hero(record)
        self._populate_identification(record, full)
        self._populate_ip_ownership(record, full)
        self._populate_pipeline(full)
        self._populate_network(full)
        self._populate_forensic(full)
        self._populate_threat_intel(full)
        self._populate_reasoning(record, full)
        self._populate_actions(record, full)
        self._populate_manual_review(record)
        self._populate_raw(full)
        self._refresh_actions(record)

    # ------------------------------------------------------------------
    # Section populators
    # ------------------------------------------------------------------

    def _populate_hero(self, record: dict[str, Any]) -> None:
        verdict = str(record.get("verdict", "inconclusive")).lower()
        icon = _VERDICT_ICONS.get(verdict, "⚫")
        confidence = record.get("confidence", "—")
        actions = record.get("actions") or []
        if actions and any(a != "none" for a in actions):
            action_label = "[ " + ", ".join(a for a in actions if a != "none") + " ]"
        else:
            action_label = "[ no action taken ]"
        try:
            pipeline_ms = int(record.get("pipeline_ms", "0"))
            timing = f"{pipeline_ms:,} ms".replace(",", " ")
        except (TypeError, ValueError):
            timing = "—"

        self._hero_verdict_label.setText(
            f"{icon}  {verdict.upper()}    {confidence} confidence    "
            f"{action_label}    {timing}"
        )
        color = _VERDICT_COLORS.get(verdict)
        if color is not None:
            self._hero_verdict_label.setStyleSheet(f"color: {color.name()};")

        src = record.get("src_ip", "?")
        sport = record.get("src_port", "?")
        dst = record.get("dest_ip", "?")
        dport = record.get("dest_port", "?")
        proto = record.get("proto", "?")
        self._hero_flow_label.setText(f"{src}:{sport}  →  {dst}:{dport}    ({proto})")

        sig = record.get("signature", "—")
        sid = record.get("signature_id", "—")
        sev = record.get("severity", "—")
        self._hero_sig_label.setText(f"{sig}    SID {sid}    severity {sev}")

        time_str = record.get("time", "")
        ts = record.get("_ts", "")
        self._hero_time_label.setText(f"Detected: {ts or time_str} UTC")

        full = record.get("_full") or {}
        alert_id = full.get("record_id", "")
        self._alert_id_label.setText(f"Alert id: {alert_id}" if alert_id else "")

        # v0.9.1 — surface the reason that led to the verdict right in
        # the hero card. For filtered alerts, the Filter stage's own
        # reason string (e.g. "known false positive (SID 2210050)") is
        # shown verbatim. For benign / confirmed / etc., we show the
        # first sentence of the AI reasoning as a one-line teaser.
        meta_text = ""
        if verdict == "filtered":
            filter_reason = full.get("filter_reason", "")
            if filter_reason:
                meta_text = f"Reason: {filter_reason}"
        else:
            reasoning = full.get("analysis", {}).get("reasoning") or record.get("reasoning", "")
            if reasoning:
                first_sentence = reasoning.split(". ", 1)[0].strip()
                if len(first_sentence) > 160:
                    first_sentence = first_sentence[:157] + "…"
                meta_text = f"Reason: {first_sentence}"
        self._hero_meta_label.setText(meta_text)

    def _populate_identification(self, record: dict[str, Any], full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_identification.content_layout)
        raw_alert = full.get("alert", {})
        self._add_kv(self._sec_identification, "Category", record.get("category", "—"))
        self._add_kv(
            self._sec_identification,
            "Severity",
            f"{record.get('severity', '—')} "
            f"({ {'1': 'high', '2': 'medium', '3': 'low'}.get(str(record.get('severity')), '?')})",
        )
        self._add_kv(self._sec_identification, "Protocol", record.get("proto", "—"))
        self._add_kv(
            self._sec_identification,
            "Suricata action",
            raw_alert.get("alert_action", "allowed"),
        )
        flow_id = raw_alert.get("flow_id")
        if flow_id:
            self._add_kv(self._sec_identification, "Flow ID", str(flow_id))

    def _populate_ip_ownership(self, record: dict[str, Any], full: dict[str, Any]) -> None:
        """Render the v0.15.0 "IP Ownership & Reputation" section.

        Structure:
          ━━━ SOURCE IP ━━━
            Identity (ASN, country, rDNS, Tor, VPN)
            External reputation (17 possible rows)
            Manual external checks (collapsible, 7 links)
            WardSOAR history
            WardSOAR classification

          ━━━ DESTINATION IP ━━━  (v0.15.0)
            [same 5 sub-blocks]

        Reads ``ip_enrichment`` (source) and ``dest_ip_enrichment``
        (destination, v0.15.0+) from the ``_full`` payload. When
        ``dest_ip_enrichment`` is absent (pre-0.15 records or a
        single-endpoint alert), only the source block is rendered
        \u2014 the layout gracefully collapses.
        """
        self._clear_layout(self._sec_ip_ownership.content_layout)

        src_enrichment = full.get("ip_enrichment") or {}
        dst_enrichment = full.get("dest_ip_enrichment") or {}

        src_ip = (
            record.get("src_ip")
            or src_enrichment.get("ip")
            or full.get("alert", {}).get("src_ip")
            or ""
        )
        dst_ip = (
            record.get("dest_ip")
            or dst_enrichment.get("ip")
            or full.get("alert", {}).get("dest_ip")
            or ""
        )

        self._render_ip_block(src_enrichment, src_ip, "SOURCE IP")
        if dst_enrichment or dst_ip:
            # Visual spacer between the two blocks.
            spacer = BodyLabel(" ")
            self._sec_ip_ownership.content_layout.addWidget(spacer)
            self._render_ip_block(dst_enrichment, dst_ip, "DESTINATION IP")

    def _render_ip_block(self, enrichment: dict[str, Any], ip: str, label: str) -> None:
        """Render one complete IP block (5 sub-blocks) into the
        shared ``_sec_ip_ownership`` section.

        Called twice by :meth:`_populate_ip_ownership` \u2014 once for
        the source IP, once for the destination IP.
        """
        from wardsoar.core.api_keys_registry import MANUAL_CHECKS
        from wardsoar.core.ip_enrichment import iso_to_human_delta

        layout = self._sec_ip_ownership.content_layout

        # -- Section header (big divider) --------------------------------
        header = BodyLabel(f"<b>\u2501\u2501\u2501 {label} \u2501\u2501\u2501</b>")
        header.setTextFormat(Qt.TextFormat.RichText)
        header.setStyleSheet(_TEXT_PRIMARY + " padding-top: 6px;")
        layout.addWidget(header)

        # -- Identity ----------------------------------------------------
        identity_title = BodyLabel(f"<b>Identity</b> \u2014 {_escape_html(ip)}")
        identity_title.setTextFormat(Qt.TextFormat.RichText)
        identity_title.setStyleSheet(_TEXT_PRIMARY)
        layout.addWidget(identity_title)

        ident = enrichment.get("identity") or {}
        asn = ident.get("asn")
        asn_name = ident.get("asn_name")
        if asn:
            asn_text = f"AS{asn} {asn_name or ''}".strip()
        elif asn_name:
            asn_text = asn_name
        else:
            asn_text = "\u2014 (no ASN data cached)"
        self._add_kv(self._sec_ip_ownership, "ASN", asn_text)

        country = ident.get("country")
        self._add_kv(self._sec_ip_ownership, "Country", country or "\u2014")

        rdns = ident.get("rdns")
        self._add_kv(
            self._sec_ip_ownership,
            "Reverse DNS",
            rdns if rdns else "(no reverse DNS record)",
        )

        if ident.get("is_private"):
            self._add_na(
                self._sec_ip_ownership,
                "Private / loopback / reserved range \u2014 external lookups are skipped.",
            )
        else:
            tor_text = "\u274c Not a Tor exit node"
            if ident.get("is_tor_exit"):
                tor_text = "\U0001f7e0 Known Tor exit node"
            self._add_kv(self._sec_ip_ownership, "Tor exit", tor_text)
            vpn = ident.get("is_vpn_or_proxy")
            if vpn is True:
                self._add_kv(
                    self._sec_ip_ownership,
                    "VPN / Proxy",
                    "\U0001f7e0 Anonymized (via ipinfo pro tier)",
                )
            elif vpn is False:
                self._add_kv(
                    self._sec_ip_ownership,
                    "VPN / Proxy",
                    "\u274c Not anonymized (via ipinfo pro tier)",
                )
            # When vpn is None, the "privacy detection" feature is
            # disabled (no ipinfo pro key). We omit the row rather
            # than display a confusing "unknown".

        layout.addWidget(BodyLabel(" "))

        # -- External reputation -----------------------------------------
        rep_title = BodyLabel("<b>External reputation</b>")
        rep_title.setTextFormat(Qt.TextFormat.RichText)
        rep_title.setStyleSheet(_TEXT_PRIMARY)
        layout.addWidget(rep_title)

        rows = enrichment.get("reputation") or []
        if not rows:
            self._add_na(
                self._sec_ip_ownership,
                "No reputation data available for this IP.",
            )
        else:
            for row in rows:
                self._add_reputation_row(row)

        # -- Manual external checks (collapsible sub-block) --------------
        self._add_manual_checks_subblock(ip, MANUAL_CHECKS)

        layout.addWidget(BodyLabel(" "))

        # -- WardSOAR history --------------------------------------------
        hist_title = BodyLabel("<b>Your WardSOAR history</b>")
        hist_title.setTextFormat(Qt.TextFormat.RichText)
        hist_title.setStyleSheet(_TEXT_PRIMARY)
        layout.addWidget(hist_title)

        history = enrichment.get("history") or {}
        total_alerts = int(history.get("total_alerts", 0) or 0)
        if total_alerts == 0:
            self._add_na(
                self._sec_ip_ownership,
                "This IP has not been seen before in your WardSOAR history.",
            )
        else:
            first_human = iso_to_human_delta(history.get("first_seen"))
            last_human = iso_to_human_delta(history.get("last_seen"))
            if first_human:
                self._add_kv(self._sec_ip_ownership, "First seen", first_human)
            if last_human:
                self._add_kv(self._sec_ip_ownership, "Last seen", last_human)
            self._add_kv(
                self._sec_ip_ownership,
                "Total alerts",
                f"{total_alerts} on this IP",
            )
            breakdown = history.get("breakdown") or {}
            if breakdown:
                parts = [f"{n} {verdict}" for verdict, n in breakdown.items()]
                self._add_kv(
                    self._sec_ip_ownership,
                    "Breakdown",
                    " \u00b7 ".join(parts),
                )
            ever = history.get("ever_blocked")
            self._add_kv(
                self._sec_ip_ownership,
                "Ever blocked",
                "Yes" if ever else "Never",
            )

        layout.addWidget(BodyLabel(" "))

        # -- WardSOAR classification -------------------------------------
        cls_title = BodyLabel("<b>WardSOAR classification</b>")
        cls_title.setTextFormat(Qt.TextFormat.RichText)
        cls_title.setStyleSheet(_TEXT_PRIMARY)
        layout.addWidget(cls_title)

        cls = enrichment.get("classification") or {}
        cdn = cls.get("cdn_match")
        self._add_kv(
            self._sec_ip_ownership,
            "CDN allowlist",
            f"\u2705 MATCHED \u2014 {cdn}" if cdn else "\u274c Not listed",
        )
        suspect = cls.get("suspect_asn")
        self._add_kv(
            self._sec_ip_ownership,
            "Suspect ASNs list",
            f"\U0001f7e0 {suspect}" if suspect else "\u274c Not listed",
        )
        bad = cls.get("bad_actor_match")
        self._add_kv(
            self._sec_ip_ownership,
            "Known bad actors",
            f"\U0001f534 MATCHED \u2014 {bad}" if bad else "\u274c Not listed",
        )

        final_tier = cls.get("final_tier") or "unknown"
        tier_reason = cls.get("final_tier_reason") or ""
        tier_emoji = {
            "legit_cdn": "\U0001f7e2",
            "confirmed_bad": "\U0001f534",
            "suspect": "\U0001f7e0",
            "private_local": "\U0001f3e0",
            "unknown": "\u26ab",
        }.get(final_tier, "\u26ab")
        tier_text = f"{tier_emoji} {final_tier.replace('_', ' ').upper()}"
        if tier_reason:
            tier_text = f"{tier_text} \u2014 {tier_reason}"
        self._add_kv(self._sec_ip_ownership, "Final tier", tier_text)

    def _add_reputation_row(self, row: dict[str, Any]) -> None:
        """Render a single per-source reputation row.

        Layout:
           [emoji]  Source name        Verdict text
        """
        level_emoji = {
            "clean": "🟢",
            "info": "🔵",
            "warn": "🟠",
            "bad": "🔴",
            "unknown": "⚪",
        }.get(row.get("level", "unknown"), "⚪")

        source_name = row.get("source_name", "?")
        verdict = row.get("verdict", "")

        line = BodyLabel(
            f"<span style='font-family: monospace;'>{level_emoji}  "
            f"<b>{_escape_html(source_name):<22}</b></span>  "
            f"{_escape_html(verdict)}"
        )
        line.setTextFormat(Qt.TextFormat.RichText)
        line.setWordWrap(True)
        line.setStyleSheet(_TEXT_SECONDARY)
        self._sec_ip_ownership.content_layout.addWidget(line)

    def _add_manual_checks_subblock(self, src_ip: str, manual_checks: tuple[Any, ...]) -> None:
        """Render the collapsible "Manual external checks" sub-block.

        Header toggles a container holding one clickable row per
        manual check. Descriptions are shown inline so the operator
        understands what each link contributes before clicking.
        Sorted by relevance (HIGH first, then MEDIUM).
        """
        # Header (click-to-expand).
        header = PushButton(f"▸ Manual external checks ({len(manual_checks)} browser lookups)")
        header.setFlat(True)
        header.setStyleSheet(
            "QPushButton { text-align: left; color: #F0F0F0; "
            "font-style: italic; padding: 4px 0; }"
            "QPushButton:hover { background-color: rgba(255, 255, 255, 15); }"
        )
        self._sec_ip_ownership.content_layout.addWidget(header)

        # Content container — hidden by default.
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(16, 4, 8, 4)
        container_layout.setSpacing(6)

        last_relevance: str = ""
        for mc in manual_checks:
            if getattr(mc, "relevance", "medium") != last_relevance:
                last_relevance = getattr(mc, "relevance", "medium")
                heading_emoji = "🟢" if last_relevance == "high" else "🟡"
                heading_text = (
                    "HIGH relevance for IP alerts"
                    if last_relevance == "high"
                    else "MEDIUM relevance"
                )
                hd = BodyLabel(f"<b>{heading_emoji} {_escape_html(heading_text)}</b>")
                hd.setTextFormat(Qt.TextFormat.RichText)
                hd.setStyleSheet(_TEXT_PRIMARY + " padding-top: 4px;")
                container_layout.addWidget(hd)

            row_layout = QHBoxLayout()
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(8)
            name_label = BodyLabel(f"<b>{_escape_html(mc.name)}</b>")
            name_label.setTextFormat(Qt.TextFormat.RichText)
            name_label.setStyleSheet(_TEXT_PRIMARY)
            row_layout.addWidget(name_label, stretch=1)
            url = mc.url_template.format(ip=src_ip) if src_ip else mc.url_template
            hyperlink = HyperlinkButton(url, "🔍 Check →")
            row_layout.addWidget(hyperlink, alignment=Qt.AlignmentFlag.AlignRight)
            container_layout.addLayout(row_layout)

            desc = BodyLabel(mc.description)
            desc.setStyleSheet(_TEXT_SECONDARY)
            desc.setWordWrap(True)
            container_layout.addWidget(desc)

        container.setVisible(False)
        self._sec_ip_ownership.content_layout.addWidget(container)

        def _toggle() -> None:
            expanded = not container.isVisible()
            container.setVisible(expanded)
            arrow = "▼" if expanded else "▸"
            header.setText(f"{arrow} Manual external checks ({len(manual_checks)} browser lookups)")

        header.clicked.connect(_toggle)

    def _populate_pipeline(self, full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_pipeline.content_layout)
        trace = full.get("pipeline_trace") or []
        if not trace:
            self._add_na(self._sec_pipeline, "Trace not available for this alert.")
            return
        # Header
        hdr = BodyLabel(
            f"{len(trace)} steps — "
            f"{full.get('pipeline_duration_ms', 0):,} ms total. "
            "Click any step to see WHY it gave this result.".replace(",", " ")
        )
        hdr.setStyleSheet(_TEXT_PRIMARY)
        hdr.setFont(QFont("", -1, QFont.Weight.Bold))
        hdr.setWordWrap(True)
        self._sec_pipeline.content_layout.addWidget(hdr)

        # Rows — stage name + icon coloured by outcome, a one-line
        # detail, and a click-to-expand explanation block below.
        for stage in trace:
            self._sec_pipeline.content_layout.addWidget(self._build_pipeline_row(stage))

    def _build_pipeline_row(self, stage: dict[str, Any]) -> QWidget:
        """Build a single click-to-expand row for the pipeline trace.

        Layout:
            [▸]  ✓ Stage Name    short outcome summary
                 └─ (hidden until clicked) pedagogical explanation.

        Clicking the header toggles the explanation. Multiple rows can
        be expanded at once; each is independent.
        """
        wrap = QWidget()
        vbox = QVBoxLayout(wrap)
        vbox.setContentsMargins(0, 0, 0, 4)
        vbox.setSpacing(2)

        outcome = stage.get("outcome", "skipped")
        icon = _OUTCOME_ICONS.get(outcome, "·")
        colour = _OUTCOME_COLORS.get(outcome, QColor(200, 200, 200))
        detail = stage.get("detail", "")
        explanation = stage.get("explanation", "")
        # v0.9.5 — per-alert specific paragraph. Empty when the
        # persisted record predates v0.9.5 or the stage has no
        # relevant data; the UI falls back to
        # "(no specific details available)" so the divider always
        # renders at the same position.
        specific = stage.get("specific_details", "")

        # --- Click-to-expand header as a borderless button --------
        arrow = "▸"
        header_text = (
            f"{arrow}  {icon}  <b>{stage.get('name', '?'):<14}</b>  "
            f"<span style='color: #F0F0F0;'>{_escape_html(detail)}</span>"
        )
        header = PushButton()
        header.setText("")  # We use a sibling label for rich text.
        header.setFlat(True)
        header.setStyleSheet(
            "QPushButton { text-align: left; border: none; padding: 2px 4px; }"
            "QPushButton:hover { background-color: rgba(255, 255, 255, 20); }"
        )
        # Overlay a QLabel inside the button so we can use rich HTML
        # (bold stage name, coloured outcome icon) without fighting
        # Qt's plain-text button rendering.
        header_label = BodyLabel()
        header_label.setTextFormat(Qt.TextFormat.RichText)
        header_label.setStyleSheet(
            f"color: {colour.name()}; font-family: monospace; " "font-weight: bold;"
        )
        header_label.setText(header_text)
        header_label.setWordWrap(True)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(4, 2, 4, 2)
        header_layout.addWidget(header_label, stretch=1)

        vbox.addWidget(header)

        # --- Hidden explanation block -----------------------------
        # Structure when expanded:
        #   [generic pedagogical explanation of the stage]
        #   ───── About this specific alert ─────
        #   [alert-specific paragraph — quotes SID, YAML reason,
        #    Opus reasoning, pfSense rule id, etc.]
        expl_widget: QWidget = QWidget()
        expl_layout = QVBoxLayout(expl_widget)
        expl_layout.setContentsMargins(44, 2, 12, 8)
        expl_layout.setSpacing(6)

        expl_label = BodyLabel(explanation or "(no explanation recorded for this step)")
        expl_label.setStyleSheet(
            _TEXT_SECONDARY + " background-color: rgba(255, 255, 255, 15); "
            "padding: 8px; border-radius: 4px;"
        )
        expl_label.setWordWrap(True)
        expl_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        expl_layout.addWidget(expl_label)

        # --- Divider + specific-details block ---------------------
        divider = BodyLabel("─ About this specific alert ─")
        divider.setStyleSheet(
            "color: #F0F0F0; font-weight: bold; font-style: italic; " "padding-top: 4px;"
        )
        expl_layout.addWidget(divider)

        specific_text = specific if specific else "(no specific details available)"
        spec_label = BodyLabel(specific_text)
        spec_label.setStyleSheet(
            "color: #F0F0F0; background-color: rgba(30, 144, 255, 45); "
            "padding: 8px; border-radius: 4px;"
        )
        spec_label.setWordWrap(True)
        spec_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        expl_layout.addWidget(spec_label)

        expl_widget.setVisible(False)
        vbox.addWidget(expl_widget)

        # --- Click wiring -----------------------------------------
        def _toggle() -> None:
            expanded = not expl_widget.isVisible()
            expl_widget.setVisible(expanded)
            new_arrow = "▼" if expanded else "▸"
            header_label.setText(
                header_text.replace("▸", new_arrow, 1)
                if not expanded
                else header_text.replace("▸", new_arrow, 1)
            )

        header.clicked.connect(_toggle)
        return wrap

    def _populate_network(self, full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_network.content_layout)
        nc = full.get("network_context")
        if not nc:
            self._add_na(
                self._sec_network,
                "N/A — pipeline short-circuited before the Collector ran.",
            )
            return

        # Destination IP + ASN + reputation summary
        rep = nc.get("ip_reputation") or {}
        self._add_kv(
            self._sec_network,
            "Destination IP",
            rep.get("ip", full.get("alert", {}).get("dest_ip", "—")),
        )
        if rep.get("sources"):
            self._add_kv(self._sec_network, "Reputation sources", ", ".join(rep["sources"]))

        # Active connections + DNS
        conns = nc.get("active_connections") or []
        if conns:
            self._add_kv(self._sec_network, "Active connections", str(len(conns)))
        dns = nc.get("dns_cache") or []
        if dns:
            self._add_kv(self._sec_network, "DNS cache entries", str(len(dns)))
            for entry in dns[:3]:
                self._add_leaf(
                    self._sec_network,
                    f"   {entry.get('name', '?')}  →  {entry.get('ip', '?')}",
                )
            if len(dns) > 3:
                self._add_leaf(self._sec_network, f"   [ {len(dns) - 3} more in raw JSON ]")

        related = nc.get("related_alerts") or []
        if related:
            self._add_kv(self._sec_network, "Related alerts", str(len(related)))

    def _populate_forensic(self, full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_forensic.content_layout)
        fr = full.get("forensic_result")
        if not fr:
            self._add_na(self._sec_forensic, "N/A — no forensic enrichment for this alert.")
            return
        suspect = fr.get("suspect_processes") or []
        self._add_kv(
            self._sec_forensic,
            "Suspect processes",
            f"{len(suspect)} flagged" if suspect else "none flagged",
        )
        # One row per attributed process. The risk verdict is surfaced
        # inline (🟢 / ⚪ / 🟡 / 🔴) with a tooltip listing the signals
        # that drove the score — cheap and useful when triaging.
        for proc in suspect:
            self._add_suspect_process_row(proc)
        sysmon = fr.get("sysmon_events") or []
        if sysmon:
            self._add_kv(
                self._sec_forensic,
                "Sysmon events",
                f"{len(sysmon)} collected (see raw JSON for full list)",
            )
        procs = fr.get("process_tree") or []
        if procs:
            self._add_kv(self._sec_forensic, "Process tree", f"{len(procs)} nodes (see raw JSON)")

    def _add_suspect_process_row(self, proc: dict[str, Any]) -> None:
        """Render one process entry with a risk badge + services + tooltip.

        Called by :meth:`_populate_forensic` for every process in
        ``suspect_processes``. The badge colour tracks the verdict
        returned by :mod:`src.process_risk`; the tooltip exposes the
        concrete signals so the operator can audit why a process was
        flagged.
        """
        pid = proc.get("pid")
        name = proc.get("name") or "?"
        risk = proc.get("risk") or {}
        verdict = str(risk.get("verdict") or "unknown").lower()
        score = risk.get("score")
        services = proc.get("services") or []

        badge_by_verdict = {
            "benign": "🟢",
            "unknown": "⚪",
            "suspicious": "🟡",
            "malicious": "🔴",
        }
        badge = badge_by_verdict.get(verdict, "⚪")

        label = f"{badge}  {name} (PID {pid})"
        if services:
            label += f" — {', '.join(services)}"

        # Right-hand value summarises the score + verdict band; the
        # tooltip carries the full signal list.
        value = verdict.upper()
        if isinstance(score, int):
            value = f"{verdict.upper()}  ({score}/100)"

        signals: list[str] = risk.get("signals") or []
        tooltip_lines = [f"Score: {score}/100", f"Verdict: {verdict}"]
        sig_status = risk.get("signature_status")
        sig_signer = risk.get("signature_signer")
        if sig_status:
            sig_line = f"Signature: {sig_status}"
            if sig_signer:
                sig_line += f" — {sig_signer}"
            tooltip_lines.append(sig_line)
        parent = risk.get("parent_name")
        if parent:
            tooltip_lines.append(f"Parent: {parent}")
        if signals:
            tooltip_lines.append("")
            tooltip_lines.extend(f"• {s}" for s in signals)
        tooltip = "\n".join(tooltip_lines)

        kv = self._add_kv(self._sec_forensic, label, value)
        if kv is not None:
            kv.setToolTip(tooltip)

    def _populate_threat_intel(self, full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_threat.content_layout)
        nc = full.get("network_context") or {}
        rep = nc.get("ip_reputation") or {}
        vt_results = full.get("virustotal_results") or []

        if not rep and not vt_results:
            self._add_na(self._sec_threat, "N/A — no external intel lookups for this alert.")
            return

        if rep:
            self._add_kv(
                self._sec_threat,
                "AbuseIPDB",
                (
                    f"{rep.get('abuseipdb_score', '—')}/100 confidence score"
                    if rep.get("abuseipdb_score") is not None
                    else "—"
                ),
            )
            self._add_kv(
                self._sec_threat,
                "VirusTotal (IP)",
                (
                    f"{rep.get('virustotal_detections', '—')} engine(s) flagged"
                    if rep.get("virustotal_detections") is not None
                    else "—"
                ),
            )
            self._add_kv(
                self._sec_threat,
                "OTX pulses",
                (
                    str(rep.get("otx_pulse_count", "—"))
                    if rep.get("otx_pulse_count") is not None
                    else "—"
                ),
            )
            if rep.get("is_known_malicious"):
                self._add_leaf(
                    self._sec_threat,
                    "   🔴 Known-malicious marker set by at least one source.",
                )

        if vt_results:
            self._add_kv(self._sec_threat, "VirusTotal hash lookups", str(len(vt_results)))
            for vt in vt_results[:3]:
                label = vt.get("file_hash", "?")[:12]
                self._add_leaf(
                    self._sec_threat,
                    f"   {label}  {vt.get('detection_count', 0)}/{vt.get('total_engines', 0)} "
                    f"engines  "
                    f"{', '.join(vt.get('threat_labels', [])) or 'no labels'}",
                )

    def _populate_reasoning(self, record: dict[str, Any], full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_reasoning.content_layout)
        verdict = str(record.get("verdict", "")).lower()
        if verdict == "filtered":
            self._add_na(
                self._sec_reasoning,
                "N/A — filtered alerts do not reach the Claude Opus analyzer. "
                "The Filter stage uses deterministic YAML-based SID matching (~0.5 ms) "
                "instead of an Opus call (~10 s, $0.03).",
            )
            return
        analysis = full.get("analysis") or {}
        reasoning = analysis.get("reasoning") or record.get("reasoning", "")
        if not reasoning:
            self._add_na(self._sec_reasoning, "No reasoning available for this alert.")
            return
        confidence = analysis.get("confidence")
        confidence_pct = (
            f"{int(float(confidence) * 100)}%"
            if confidence is not None
            else record.get("confidence", "—")
        )
        header = BodyLabel(
            f"Verdict: {analysis.get('verdict', record.get('verdict', '?'))}  "
            f"·  Confidence: {confidence_pct}"
        )
        header.setFont(QFont("", -1, QFont.Weight.Bold))
        header.setStyleSheet(_TEXT_PRIMARY)
        self._sec_reasoning.content_layout.addWidget(header)
        # Full reasoning in a scrollable, selectable text block.
        reasoning_box = PlainTextEdit()
        reasoning_box.setReadOnly(True)
        reasoning_box.setPlainText(reasoning)
        reasoning_box.setMinimumHeight(120)
        reasoning_box.setMaximumHeight(360)
        reasoning_box.setStyleSheet(_PLAINTEXT_BLOCK_STYLE)
        self._sec_reasoning.content_layout.addWidget(reasoning_box)
        recommended = analysis.get("recommended_actions") or []
        if recommended:
            self._add_kv(self._sec_reasoning, "Recommended actions", ", ".join(recommended))

    def _populate_actions(self, record: dict[str, Any], full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_actions.content_layout)
        actions = full.get("actions_taken") or []
        if not actions:
            verdict = str(record.get("verdict", "")).lower()
            if verdict == "filtered":
                self._add_leaf(
                    self._sec_actions,
                    "No action — alert suppressed by the stage-1 filter.",
                )
            else:
                self._add_leaf(
                    self._sec_actions,
                    "No action taken — verdict did not meet the current mode's blocking threshold.",
                )
            return
        for a in actions:
            line = (
                f"{'✓' if a.get('success') else '✗'}  "
                f"{a.get('action_type', '?')}  "
                f"target={a.get('target_ip', '—')}"
            )
            if a.get("pfsense_rule_id"):
                line += f"  rule={a['pfsense_rule_id']}"
            if a.get("block_duration_hours"):
                line += f"  duration={a['block_duration_hours']}h"
            if not a.get("success") and a.get("error_message"):
                line += f"  error={a['error_message']}"
            self._add_leaf(self._sec_actions, line)

    def _populate_manual_review(self, record: dict[str, Any]) -> None:
        """Render the operator's manual verdict override when present.

        v0.16.0 \u2014 the Alert Detail view shows a new "Manual review"
        section the moment the operator submits an override via the
        Manual Review dialog. The section stays hidden (content
        layout empty) when no review is attached to the alert.
        """
        self._clear_layout(self._sec_manual_review.content_layout)
        review = record.get("manual_review") or {}
        if not review:
            # Hide the whole section when there is no review. Setting
            # the widget invisible prevents an empty collapsible
            # header from polluting the page.
            self._sec_manual_review.setVisible(False)
            return
        self._sec_manual_review.setVisible(True)

        operator = str(review.get("operator_verdict") or "").lower()
        original = str(review.get("original_verdict") or "").lower()
        reviewed_at = str(review.get("reviewed_at") or "")
        notes = str(review.get("notes") or "").strip()

        if operator and operator != original:
            self._add_kv(
                self._sec_manual_review,
                "Verdict override",
                f"{original.upper() or '\u2014'} \u2192 {operator.upper()}",
            )
        elif operator:
            self._add_kv(
                self._sec_manual_review,
                "Verdict",
                f"{operator.upper()} (operator confirmed)",
            )
        else:
            self._add_kv(
                self._sec_manual_review,
                "Verdict",
                "Kept as "
                + (original.upper() or "(original)")
                + " \u2014 operator added a note only",
            )
        if reviewed_at:
            self._add_kv(self._sec_manual_review, "Reviewed at", reviewed_at)
        if notes:
            self._add_kv(self._sec_manual_review, "Notes", notes)
        else:
            self._add_na(self._sec_manual_review, "No notes attached.")

    def _populate_raw(self, full: dict[str, Any]) -> None:
        self._clear_layout(self._sec_raw.content_layout)
        raw = full.get("alert", {}).get("raw_event") or full.get("alert") or full
        if not raw:
            self._add_na(self._sec_raw, "No raw event captured.")
            return
        box = PlainTextEdit()
        box.setReadOnly(True)
        box.setPlainText(json.dumps(raw, indent=2, default=str))
        box.setMinimumHeight(200)
        box.setMaximumHeight(500)
        box.setStyleSheet(_PLAINTEXT_BLOCK_STYLE)
        self._sec_raw.content_layout.addWidget(box)

    # ------------------------------------------------------------------
    # Footer action logic
    # ------------------------------------------------------------------

    def _refresh_actions(self, record: dict[str, Any]) -> None:
        verdict = str(record.get("verdict", "")).lower()
        actions = record.get("actions") or []
        has_block = "ip_block" in actions or "ip_port_block" in actions

        # Manual Review is always available.
        self._review_btn.setVisible(True)
        # Forensic Report only when we actually captured evidence.
        self._forensic_btn.setVisible(verdict == "confirmed" and has_block)
        # Unblock IP only when there's an active block.
        self._unblock_btn.setVisible(has_block)
        self._unblock_btn.setEnabled(has_block)
        # Add-to-filter makes sense for benign / inconclusive (alerts
        # we don't want to keep re-analyzing). Explicitly NOT for
        # confirmed / suspicious / already-filtered.
        self._addfp_btn.setVisible(verdict in {"benign", "inconclusive"})
        sid_str = str(record.get("signature_id", ""))
        if sid_str and self._addfp_btn.isVisible():
            self._addfp_btn.setText(f"➕ Filter SID {sid_str}")
        else:
            self._addfp_btn.setText("➕ Filter SID")

    def _on_unblock_clicked(self) -> None:
        ip = self._current_record.get("src_ip", "")
        sid_raw = self._current_record.get("signature_id")
        sid: Optional[int]
        if sid_raw in (None, ""):
            sid = None
        else:
            try:
                sid = int(str(sid_raw))
            except (ValueError, TypeError):
                sid = None
        if ip:
            self._unblock_btn.setEnabled(False)
            self.rollback_requested.emit(ip, sid)

    def _on_addfp_clicked(self) -> None:
        sid_raw = self._current_record.get("signature_id")
        if sid_raw in (None, ""):
            return
        try:
            sid = int(str(sid_raw))
        except (ValueError, TypeError):
            return
        sig = self._current_record.get("signature", "")
        self._addfp_btn.setEnabled(False)
        self.add_sid_filter_requested.emit(sid, sig)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        """Remove every widget from ``layout`` before re-populating."""
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                continue
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _add_kv(self, section: _CollapsibleSection, key: str, value: str) -> QWidget:
        """Add a key/value row. Key = SECONDARY, value = PRIMARY.

        Returns the wrapper widget so callers can attach a tooltip
        (used by :meth:`_add_suspect_process_row` for the risk signal
        breakdown).
        """
        row = QHBoxLayout()
        k = BodyLabel(f"{key}:")
        k.setFixedWidth(180)
        k.setStyleSheet(_TEXT_SECONDARY)
        v = BodyLabel(str(value))
        v.setStyleSheet(_TEXT_PRIMARY)
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(k)
        row.addWidget(v, stretch=1)
        wrap = QWidget()
        wrap.setLayout(row)
        section.content_layout.addWidget(wrap)
        return wrap

    def _add_leaf(self, section: _CollapsibleSection, text: str) -> None:
        """Add a standalone line — always PRIMARY contrast."""
        lbl = BodyLabel(text)
        lbl.setStyleSheet(_TEXT_PRIMARY)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lbl.setWordWrap(True)
        section.content_layout.addWidget(lbl)

    def _add_na(self, section: _CollapsibleSection, text: str) -> None:
        """Add the "N/A — …" placeholder. Italic but still readable
        (v0.9.1 contrast pass raised the opacity)."""
        lbl = CaptionLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(_TEXT_NA)
        section.content_layout.addWidget(lbl)


__all__ = ["AlertDetailView"]
