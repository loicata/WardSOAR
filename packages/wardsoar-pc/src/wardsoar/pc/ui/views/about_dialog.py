"""About dialog — shows version, copyright, license and a link home.

Opened from the sidebar "About" entry (bottom of the navigation).
Deliberately spare: operators need the version number at a glance
when filing a bug report, plus the license and copyright for
redistribution compliance. Everything else belongs in the README.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from wardsoar.pc import __version__

# The homepage link surfaced as a clickable label. Kept as a constant
# so future renames (branding change, custom domain move) land in one
# place.
_HOMEPAGE_URL = "https://loicata.com"

# Copyright + license match pyproject.toml. Update both if the
# project changes its license.
_COPYRIGHT = "Copyright (c) 2026 Loic Ader"
_LICENSE = "GNU General Public License v3.0"


class AboutDialog(QDialog):
    """Version / copyright / license popup.

    Styled to match the Fluent dark theme: light-on-dark text, hover
    accent on the homepage link, close-on-escape. Non-blocking wise,
    a modal ``QDialog`` is fine here — the operator does not need the
    main window while reading four lines.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About WardSOAR")
        self.setModal(True)
        self.setMinimumWidth(360)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(10)

        # --- Header: app name + version ----------------------------------
        title = QLabel(f"WardSOAR v{__version__}")
        title.setStyleSheet("color: #F0F0F0; font-size: 20px; font-weight: 600;")
        root.addWidget(title)

        # A short blank line visually separates the header from the
        # metadata block, the same way the Backup Manager sample does.
        spacer = QLabel("")
        spacer.setFixedHeight(4)
        root.addWidget(spacer)

        # --- Copyright ---------------------------------------------------
        copyright_label = QLabel(_COPYRIGHT)
        copyright_label.setStyleSheet("color: #CFCFCF;")
        root.addWidget(copyright_label)

        # --- Homepage (clickable) ---------------------------------------
        # Using a plain QLabel with Qt's RichText link handling keeps the
        # dialog free of extra widgets. The cursor + underline hint at
        # clickability; the actual click goes through the system
        # browser so the app never embeds a webview just for this.
        link = QLabel(
            f'<a href="{_HOMEPAGE_URL}" '
            f'style="color: #4FC3F7; text-decoration: none;">'
            f"{_HOMEPAGE_URL.removeprefix('https://')}</a>"
        )
        link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        link.setOpenExternalLinks(False)
        link.linkActivated.connect(self._open_homepage)
        link.setCursor(Qt.CursorShape.PointingHandCursor)
        root.addWidget(link)

        # --- License -----------------------------------------------------
        license_label = QLabel(_LICENSE)
        license_label.setStyleSheet("color: #CFCFCF;")
        root.addWidget(license_label)

        # Keep the dialog background consistent with the Fluent dark
        # surface — the default Qt palette would show a near-white
        # background here, which clashes with the rest of the app.
        self.setStyleSheet("QDialog { background-color: #1F1F1F; }")

        # Close on Esc without adding a visible button. The system
        # window chrome still provides the X in the top-right.
        self.setSizeGripEnabled(False)

    @staticmethod
    def _open_homepage(url: str) -> None:
        """Hand the click off to the system browser.

        Extracted so a test can patch it without spawning a browser.
        """
        from PySide6.QtCore import QUrl

        QDesktopServices.openUrl(QUrl(url))


def show_about_dialog(parent: Optional[QWidget] = None) -> None:
    """Convenience helper for the sidebar ``addItem`` callback.

    The navigation item expects a zero-argument callable; wrapping
    the ``QDialog.exec()`` here keeps the app shell terse.
    """
    AboutDialog(parent).exec()


# ``QPixmap`` is imported at the top for a future shield icon we may
# embed (matches the Backup Manager sample). Silencing the unused
# import now avoids a ruff nit while leaving the wiring for later.
_ = QPixmap
