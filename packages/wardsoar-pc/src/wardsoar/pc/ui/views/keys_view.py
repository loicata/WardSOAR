"""Keys tab — manage all API keys and secrets.

Renders every credential WardSOAR consumes, grouped in six visible
blocks that match :mod:`src.api_keys_registry`:

1. **Auto-enabled** — informational. 11 intelligence feeds that
   run without any user action. Zero fields — just the list.
2. **Required** — one password field. The Anthropic key.
3. **Essentials** — four free, high-signal keys.
4. **Useful for specific cases** — three free, narrower-use keys.
5. **Paid** — three commercial sources with per-tier pricing.
6. **Notifications** — SMTP + Telegram credentials.

Every key is **optional** except Anthropic. Missing keys cause a
graceful degradation at the aggregator level — the matching rows
are simply omitted from the Alert Detail view.

Keys are persisted to ``%APPDATA%\\WardSOAR\\.env`` — never in the
config YAML, never in snapshots, never in git. On Save the app
restarts so HTTP clients can re-read ``os.environ``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
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
    PasswordLineEdit,
    PrimaryPushButton,
    SimpleCardWidget,
    StrongBodyLabel,
    SubtitleLabel,
)

from wardsoar.core.api_keys_registry import (
    API_KEY_SPECS,
    AUTO_ENABLED_SOURCES,
    Tier,
)
from wardsoar.core.config import get_data_dir

logger = logging.getLogger("ward_soar.ui.keys_view")


_TIER_HEADINGS: dict[Tier, tuple[str, str]] = {
    "required": (
        "Required",
        "Without this key WardSOAR cannot analyse alerts that reach the AI stage.",
    ),
    "essential": (
        "Essentials \u2014 recommended (free)",
        "High-signal, free-tier keys. Most operators create all four.",
    ),
    "useful": (
        "Useful for specific cases (free)",
        "Free-tier keys that unlock narrower-use signals.",
    ),
    "paid": (
        "Paid sources",
        "Commercial tiers. Enable only the ones you are prepared to pay for.",
    ),
    "notification": (
        "Notifications (optional)",
        "Outbound channels for block alerts. Leave blank to disable.",
    ),
}


def _build_auto_enabled_card() -> SimpleCardWidget:
    """Build the top informational card listing the 11 auto-enabled feeds."""
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(20, 16, 20, 16)
    layout.setSpacing(8)

    title = StrongBodyLabel("\U0001f7e2  Active by default \u2014 no action needed")
    layout.addWidget(title)
    layout.addWidget(
        CaptionLabel(
            f"These {len(AUTO_ENABLED_SOURCES)} intelligence sources run automatically "
            "in the background. Zero setup required \u2014 they are already working "
            "behind the scenes."
        )
    )

    for source in AUTO_ENABLED_SOURCES:
        row = QVBoxLayout()
        row.setSpacing(0)

        name_row = QHBoxLayout()
        name_row.setContentsMargins(0, 0, 0, 0)
        name_row.addWidget(BodyLabel(f"\u2705  {source.name}"), stretch=1)
        cadence = CaptionLabel(source.refresh_cadence)
        cadence.setStyleSheet("color: #e4e4e4;")
        name_row.addWidget(cadence)
        row.addLayout(name_row)

        desc = CaptionLabel(f"    {source.description}")
        desc.setStyleSheet("color: #e4e4e4;")
        desc.setWordWrap(True)
        row.addWidget(desc)

        layout.addLayout(row)
    return card


def _build_tier_card(
    tier: Tier,
    fields: dict[str, PasswordLineEdit],
) -> SimpleCardWidget:
    """Build one keyed-tier card (required / essential / useful / paid / notif).

    Each spec rendered as:
      Label          Pricing caption
      Description (two lines max)
      [ Sign up \u2192 ] button (when signup_url is set)
      [ password field ................................ ]
    """
    specs = tuple(spec for spec in API_KEY_SPECS if spec.tier == tier)
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(20, 16, 20, 16)
    layout.setSpacing(12)

    heading, subheading = _TIER_HEADINGS.get(tier, ("", ""))
    if heading:
        layout.addWidget(StrongBodyLabel(heading))
    if subheading:
        layout.addWidget(CaptionLabel(subheading))

    for spec in specs:
        entry = QVBoxLayout()
        entry.setSpacing(4)

        # Header row: label + right-aligned pricing.
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        label_text = spec.display_label
        if spec.required:
            label_text = f"{label_text}  \u2014  REQUIRED"
        header.addWidget(BodyLabel(label_text), stretch=1)
        if spec.pricing:
            pricing = CaptionLabel(spec.pricing)
            pricing.setStyleSheet("color: #e4e4e4;")
            pricing.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            header.addWidget(pricing)
        entry.addLayout(header)

        # Description.
        desc = CaptionLabel(spec.description)
        desc.setStyleSheet("color: #e4e4e4;")
        desc.setWordWrap(True)
        entry.addWidget(desc)

        # Sign-up button (only when we have a URL).
        if spec.signup_url:
            signup = HyperlinkButton(spec.signup_url, f"Sign up at {spec.signup_url} \u2192")
            entry.addWidget(signup, alignment=Qt.AlignmentFlag.AlignLeft)

        # Password field.
        field = PasswordLineEdit()
        field.setPlaceholderText(spec.placeholder)
        entry.addWidget(field)
        fields[spec.env_var] = field

        layout.addLayout(entry)

    return card


class KeysView(QWidget):
    """Keys management tab \u2014 edit all API keys stored in .env.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        # v0.11.1 UX fix \u2014 the full Keys page (auto-enabled list +
        # five tier cards) grew past the typical viewport height and
        # the plain QVBoxLayout was vertically compressing the cards
        # into each other. Wrap the content in a QScrollArea so a
        # proper scrollbar appears on the right when the cards don't
        # fit.
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        # v0.11.2 \u2014 force the scroll area to inherit the Fluent
        # dark-theme background. Without this the QScrollArea
        # viewport defaults to white, which makes the whole Keys
        # page render on a white panel instead of the app's dark
        # canvas. The inner QWidget set below also needs the
        # override because QScrollArea creates a viewport widget
        # that does not inherit the QSS.
        scroll.setStyleSheet(
            "QScrollArea { background-color: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background-color: transparent; }"
        )

        container = QWidget()
        # Ensure the inner container is transparent too so the
        # outer Fluent canvas shows through the scrollable area.
        container.setStyleSheet("background-color: transparent;")
        outer = QVBoxLayout(container)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        # Header
        outer.addWidget(SubtitleLabel("API Keys & Secrets"))
        outer.addWidget(
            CaptionLabel(
                "Stored in .env \u2014 never included in snapshots, config history, "
                "or version control. Every key is optional except the Anthropic one."
            )
        )

        # Block 1 \u2014 auto-enabled informational card.
        outer.addWidget(_build_auto_enabled_card())

        # Blocks 2-6 - one card per tier. Order matters.
        self._fields: dict[str, PasswordLineEdit] = {}
        tiers: tuple[Tier, ...] = ("required", "essential", "useful", "paid", "notification")
        for tier in tiers:
            outer.addWidget(_build_tier_card(tier, self._fields))

        # Save row.
        btn_row = QHBoxLayout()
        self._save_btn = PrimaryPushButton("Save All Keys and Restart")
        self._save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(self._save_btn)
        self._status_label = CaptionLabel("")
        btn_row.addWidget(self._status_label)
        btn_row.addStretch()
        outer.addLayout(btn_row)

        outer.addStretch()

        scroll.setWidget(container)
        page_layout.addWidget(scroll)

        # Populate fields from existing .env if any.
        self._load_keys()

    # ------------------------------------------------------------------
    # .env persistence
    # ------------------------------------------------------------------

    def _env_path(self) -> Path:
        return get_data_dir() / ".env"

    def _load_keys(self) -> None:
        """Pre-fill fields from the existing ``.env``."""
        path = self._env_path()
        if not path.exists():
            return
        values: dict[str, str] = {}
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        except OSError:
            logger.warning("Could not read %s", path, exc_info=True)
            return
        for env_var, field in self._fields.items():
            if values.get(env_var):
                field.setText(values[env_var])

    def _on_save(self) -> None:
        """Write every non-empty field to ``.env`` and restart the app."""
        path = self._env_path()

        # Read existing values so we preserve unknown keys (written by
        # hand or by older versions of WardSOAR).
        existing: dict[str, str] = {}
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    existing[key.strip()] = value.strip()
            except OSError:
                logger.warning("Could not read %s for merge", path, exc_info=True)

        # Overwrite with field values.
        for env_var, field in self._fields.items():
            value = field.text().strip()
            if value:
                existing[env_var] = value
                os.environ[env_var] = value

        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"{k}={v}" for k, v in existing.items()]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        logger.info("API keys saved to %s \u2014 restarting app", path)

        # Restart so that freshly-loaded env vars take effect in the
        # pipeline worker threads.
        import sys

        from PySide6.QtCore import QProcess
        from PySide6.QtWidgets import QApplication

        QProcess.startDetached(sys.executable, sys.argv)
        app = QApplication.instance()
        if app is not None:
            app.quit()

    # Convenience used by tests ---------------------------------------------

    def open_signup_url(self, url: str) -> None:
        """Open a signup URL in the default browser.

        Kept as a method rather than an anonymous lambda so tests
        can monkey-patch it without touching Qt globals.
        """
        QDesktopServices.openUrl(QUrl(url))
