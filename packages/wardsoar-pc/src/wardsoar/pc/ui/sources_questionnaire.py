"""Upstream questionnaire that runs before the detailed setup wizard.

The full :class:`SetupWizard` collects everything WardSOAR needs to
boot the pipeline (API keys, network config, forensic toggles, etc.)
across eleven pages. Most of that is independent of *which sources*
the operator has plugged in, but a handful of pages — pfSense SSH
credentials, EVE remote path — only make sense when a Netgate is
present. Asking the operator a flat list of questions where half are
contextually irrelevant is friction; instead we open with three
binary questions whose answers gate the rest of the wizard.

Decision (2026-04-24 architecture session): the wizard pattern is

  1. ``Do you have a Netgate pfSense on this LAN?``
  2. ``Do you have a Virus Sniff (Raspberry Pi) appliance?``
  3. ``Install Suricata locally on this PC?``

…with a rule that *at least one* alert source must be reachable. The
recap screen calls out coverage holes (e.g. "loopback / VPN traffic
not covered if no local Suricata"). This module ships those four
screens; the detailed :class:`SetupWizard` keeps running afterwards,
gated on the choices captured here.

Persistence happens in ``config.yaml`` under a new ``sources:`` key
and feeds the in-process ``RemoteAgentRegistry`` at runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QHBoxLayout,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    PrimaryPushButton,
    PushButton,
    RadioButton,
    StrongBodyLabel,
    TextEdit,
    TitleLabel,
)

logger = logging.getLogger("ward_soar.ui.sources_questionnaire")


# Page indices for the four-screen flow.
PAGE_NETGATE = 0
PAGE_VIRUS_SNIFF = 1
PAGE_SURICATA_LOCAL = 2
PAGE_RECAP = 3
TOTAL_PAGES = 4


@dataclass(frozen=True)
class SourceChoices:
    """The three boolean answers collected by the questionnaire.

    The instance is what the rest of the application — the detailed
    :class:`SetupWizard`, the ``RemoteAgentRegistry`` wire-up,
    ``config.yaml`` generation — consumes.
    """

    netgate: bool
    virus_sniff: bool
    suricata_local: bool

    def at_least_one_source(self) -> bool:
        """Invariant: the operator must have at least one alert source.

        WardSOAR cannot run without an alert stream, so we refuse to
        accept "no Netgate, no Virus Sniff, no local Suricata".
        """
        return self.netgate or self.virus_sniff or self.suricata_local

    def coverage_warnings(self) -> list[str]:
        """Plain-English warnings about gaps the operator is signing up for.

        Surfaced on the recap screen so the operator can flip a choice
        before committing rather than discovering the gap weeks later
        when something slips through.
        """
        warnings: list[str] = []
        if self.netgate and not self.suricata_local:
            warnings.append(
                "Loopback and VPN-tunnelled traffic on this PC will not be "
                "monitored — the Netgate only sees traffic that crosses it. "
                "Enable local Suricata if you want full coverage."
            )
        if self.netgate and self.virus_sniff:
            warnings.append(
                "Netgate and Virus Sniff cannot both be active at the same "
                "time (the Pi's USB Gadget mode replaces the LAN's WAN path). "
                "Only one will run at runtime; the other stays configured "
                "and can be activated by physically plugging the Pi in."
            )
        if not self.netgate and not self.virus_sniff and self.suricata_local:
            warnings.append(
                "Standalone PC mode — alerts come exclusively from local "
                "Suricata. Threats targeting other devices on the LAN will "
                "not be visible to WardSOAR."
            )
        return warnings


class SourcesQuestionnaire(QDialog):
    """Pre-wizard questionnaire — three Yes/No questions plus a recap.

    Modal dialog. Returns ``QDialog.Accepted`` once the operator has
    picked a valid combination (at least one source) and confirmed
    the recap. The selections are then exposed on :attr:`choices`.
    """

    # Default-No on Netgate / Virus Sniff because we have no way to
    # auto-detect either; the operator confirms what they own. Default
    # True on the Suricata fallback only when both other answers are
    # No (the "PC seul" topology).
    _DEFAULT_NETGATE: bool = False
    _DEFAULT_VIRUS_SNIFF: bool = False

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("WardSOAR — alert sources")
        self.setMinimumSize(640, 480)
        # Disable the title-bar close button: an operator who quits
        # mid-questionnaire ends up with WardSOAR thinking it has no
        # source configured. Cancel via the explicit button instead,
        # which exits the app the same way the legacy wizard does.
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint)

        self._netgate_choice: bool = self._DEFAULT_NETGATE
        self._virus_sniff_choice: bool = self._DEFAULT_VIRUS_SNIFF
        self._suricata_choice: bool = False
        self._current_page: int = PAGE_NETGATE

        self._stack = QStackedWidget(self)
        self._stack.addWidget(self._build_netgate_page())
        self._stack.addWidget(self._build_virus_sniff_page())
        self._stack.addWidget(self._build_suricata_page())
        self._stack.addWidget(self._build_recap_page())

        self._back_button = PushButton("Back")
        self._next_button = PrimaryPushButton("Next")
        self._cancel_button = PushButton("Cancel")
        self._back_button.clicked.connect(self._go_back)
        self._next_button.clicked.connect(self._go_next)
        self._cancel_button.clicked.connect(self.reject)

        nav = QHBoxLayout()
        nav.addWidget(self._cancel_button)
        nav.addStretch(1)
        nav.addWidget(self._back_button)
        nav.addWidget(self._next_button)

        layout = QVBoxLayout(self)
        layout.addWidget(self._stack)
        layout.addLayout(nav)

        self._refresh_navigation()

    # ------------------------------------------------------------------
    # Public surface — exposed to the SetupWizard caller
    # ------------------------------------------------------------------

    @property
    def choices(self) -> SourceChoices:
        """The three answers, computed from the current widget state."""
        return SourceChoices(
            netgate=self._netgate_choice,
            virus_sniff=self._virus_sniff_choice,
            suricata_local=self._suricata_choice,
        )

    # ------------------------------------------------------------------
    # Page builders
    # ------------------------------------------------------------------

    def _build_netgate_page(self) -> QWidget:
        page, layout = self._page_skeleton()
        layout.addWidget(TitleLabel("1 of 3 — Netgate pfSense"))
        layout.addWidget(
            BodyLabel(
                "Do you have a Netgate pfSense (or any pfSense-based) "
                "appliance on this LAN running Suricata?"
            )
        )
        layout.addWidget(
            BodyLabel(
                "WardSOAR will read its EVE-JSON alert stream over SSH and "
                "use the same channel to install firewall blocks via pfctl."
            )
        )

        self._netgate_yes = RadioButton("Yes — connect to a Netgate / pfSense")
        self._netgate_no = RadioButton("No — I do not have a Netgate / pfSense appliance")
        self._netgate_yes.setChecked(self._DEFAULT_NETGATE)
        self._netgate_no.setChecked(not self._DEFAULT_NETGATE)

        group = QButtonGroup(page)
        group.addButton(self._netgate_yes)
        group.addButton(self._netgate_no)
        self._netgate_yes.toggled.connect(self._on_netgate_changed)

        layout.addSpacing(16)
        layout.addWidget(self._netgate_yes)
        layout.addWidget(self._netgate_no)
        layout.addStretch(1)
        return page

    def _build_virus_sniff_page(self) -> QWidget:
        page, layout = self._page_skeleton()
        layout.addWidget(TitleLabel("2 of 3 — Virus Sniff appliance"))
        layout.addWidget(
            BodyLabel(
                "Do you have a Virus Sniff Raspberry-Pi diagnostic appliance "
                "you plan to plug into this PC over USB?"
            )
        )
        layout.addWidget(
            BodyLabel(
                "Virus Sniff is a portable single-PC sensor — Pi 5 + USB "
                "gadget mode. Useful for laptops away from your LAN, or for "
                "containment of a suspect PC. You can have one configured "
                "alongside a Netgate, but only one runs at a time."
            )
        )

        self._virus_sniff_yes = RadioButton("Yes — I have (or plan to have) a Virus Sniff")
        self._virus_sniff_no = RadioButton("No — I do not have a Virus Sniff")
        self._virus_sniff_yes.setChecked(self._DEFAULT_VIRUS_SNIFF)
        self._virus_sniff_no.setChecked(not self._DEFAULT_VIRUS_SNIFF)

        group = QButtonGroup(page)
        group.addButton(self._virus_sniff_yes)
        group.addButton(self._virus_sniff_no)
        self._virus_sniff_yes.toggled.connect(self._on_virus_sniff_changed)

        layout.addSpacing(16)
        layout.addWidget(self._virus_sniff_yes)
        layout.addWidget(self._virus_sniff_no)
        layout.addStretch(1)
        return page

    def _build_suricata_page(self) -> QWidget:
        page, layout = self._page_skeleton()
        layout.addWidget(TitleLabel("3 of 3 — Local Suricata"))
        self._suricata_intro = BodyLabel("")
        layout.addWidget(self._suricata_intro)

        layout.addWidget(
            BodyLabel(
                "Local Suricata covers loopback traffic and any VPN tunnel "
                "the PC terminates — the Netgate cannot see those flows. It "
                "needs Npcap (downloaded at first launch from npcap.com) and "
                "uses Windows Firewall for blocking."
            )
        )

        self._suricata_yes = RadioButton("Yes — install Suricata on this PC")
        self._suricata_no = RadioButton("No — do not install Suricata locally")

        group = QButtonGroup(page)
        group.addButton(self._suricata_yes)
        group.addButton(self._suricata_no)
        self._suricata_yes.toggled.connect(self._on_suricata_changed)

        layout.addSpacing(16)
        layout.addWidget(self._suricata_yes)
        layout.addWidget(self._suricata_no)
        layout.addStretch(1)
        return page

    def _build_recap_page(self) -> QWidget:
        page, layout = self._page_skeleton()
        layout.addWidget(TitleLabel("Recap"))
        layout.addWidget(
            BodyLabel(
                "Review your choices below. Going Back lets you change "
                "any answer; clicking Finish proceeds to the detailed "
                "setup wizard."
            )
        )

        layout.addSpacing(8)
        self._recap_text = TextEdit()
        self._recap_text.setReadOnly(True)
        self._recap_text.setMinimumHeight(180)
        layout.addWidget(self._recap_text)

        layout.addWidget(StrongBodyLabel("Coverage notes:"))
        self._warnings_text = TextEdit()
        self._warnings_text.setReadOnly(True)
        self._warnings_text.setMinimumHeight(100)
        layout.addWidget(self._warnings_text)

        layout.addStretch(1)
        return page

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _page_skeleton() -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(12)
        return page, layout

    def _on_netgate_changed(self, checked: bool) -> None:
        self._netgate_choice = checked
        self._refresh_suricata_page()

    def _on_virus_sniff_changed(self, checked: bool) -> None:
        self._virus_sniff_choice = checked
        self._refresh_suricata_page()

    def _on_suricata_changed(self, checked: bool) -> None:
        self._suricata_choice = checked

    def _refresh_suricata_page(self) -> None:
        """Update the Suricata page text and forced-Yes rule.

        Rule from the 2026-04-24 architecture decision: at least one
        source is mandatory. If the operator just said No to both
        Netgate and Virus Sniff, local Suricata becomes the only
        possible source — we force Yes and lock the radio so the
        invariant cannot be violated by clicking Next.
        """
        only_local_possible = not self._netgate_choice and not self._virus_sniff_choice
        if only_local_possible:
            self._suricata_intro.setText(
                "You answered No to both Netgate and Virus Sniff. Local "
                "Suricata is the only remaining alert source, so it is "
                "required for WardSOAR to start."
            )
            self._suricata_yes.setChecked(True)
            self._suricata_yes.setEnabled(False)
            self._suricata_no.setEnabled(False)
            self._suricata_choice = True
        else:
            self._suricata_intro.setText(
                "Local Suricata is recommended for laptops that move between "
                "networks, or for full visibility into loopback and VPN "
                "traffic. Skip it if your Netgate or Virus Sniff already "
                "covers everything you care about."
            )
            self._suricata_yes.setEnabled(True)
            self._suricata_no.setEnabled(True)

    def _refresh_recap(self) -> None:
        """Render the recap text from the current choices."""
        c = self.choices
        lines = [
            f"  Netgate pfSense:    {'YES' if c.netgate else 'no'}",
            f"  Virus Sniff (Pi):   {'YES' if c.virus_sniff else 'no'}",
            f"  Local Suricata:     {'YES' if c.suricata_local else 'no'}",
        ]
        self._recap_text.setPlainText("\n".join(lines))

        warnings = c.coverage_warnings()
        if warnings:
            self._warnings_text.setPlainText("\n\n".join(f"- {w}" for w in warnings))
        else:
            self._warnings_text.setPlainText(
                "No coverage gaps detected for the chosen combination."
            )

    def _refresh_navigation(self) -> None:
        """Update Back/Next button labels and enabled state."""
        self._back_button.setEnabled(self._current_page > PAGE_NETGATE)
        if self._current_page == PAGE_RECAP:
            self._next_button.setText("Finish")
        else:
            self._next_button.setText("Next")

    def _go_back(self) -> None:
        if self._current_page == PAGE_NETGATE:
            return
        self._current_page -= 1
        self._stack.setCurrentIndex(self._current_page)
        self._refresh_navigation()

    def _go_next(self) -> None:
        if self._current_page == PAGE_RECAP:
            self._on_finish()
            return
        # Refresh derived state when leaving each question page.
        if self._current_page == PAGE_VIRUS_SNIFF:
            self._refresh_suricata_page()
        self._current_page += 1
        if self._current_page == PAGE_RECAP:
            self._refresh_recap()
        self._stack.setCurrentIndex(self._current_page)
        self._refresh_navigation()

    def _on_finish(self) -> None:
        """Validate the invariant one last time and accept the dialog."""
        if not self.choices.at_least_one_source():
            # Belt-and-braces: the Suricata page already forces Yes
            # in the only-local topology, so this branch should be
            # unreachable. Refusing to accept here is the safe default
            # if a future regression slips past the page-level guard.
            logger.error("sources_questionnaire: refusing to accept — no source selected")
            return
        self.accept()
