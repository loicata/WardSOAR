"""First-run setup wizard for WardSOAR.

Launches automatically when config.yaml does not exist.
Collects all configuration from the user via a multi-page wizard,
then generates config.yaml and .env in the writable data directory.

Uses PyQt-Fluent-Widgets for Windows 11 Fluent Design.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CheckBox,
    ComboBox,
    DoubleSpinBox,
    HyperlinkButton,
    LineEdit,
    PasswordLineEdit,
    PrimaryPushButton,
    PushButton,
    SimpleCardWidget,
    SpinBox,
    StrongBodyLabel,
    SubtitleLabel,
    TextEdit,
    TitleLabel,
    isDarkTheme,
)

from wardsoar.core.api_keys_registry import (
    API_KEY_SPECS,
    AUTO_ENABLED_SOURCES,
    Tier,
)
from wardsoar.pc.ui.sources_questionnaire import SourceChoices

# Legacy field-name aliases kept so existing wizard code (summary
# page, validation step, _generate_env) can keep referencing the
# short names while the new v0.10.0 fields are keyed by env_var.
_LEGACY_WIZARD_ALIASES: dict[str, str] = {
    "anthropic_key": "ANTHROPIC_API_KEY",
    "vt_key": "VIRUSTOTAL_API_KEY",
    "abuseipdb_key": "ABUSEIPDB_API_KEY",
    "otx_key": "OTX_API_KEY",
}

logger = logging.getLogger("ward_soar.ui.setup_wizard")

# Page indices
PAGE_WELCOME = 0
PAGE_SYSMON = 1
PAGE_API_KEYS = 2
PAGE_NETWORK = 3
PAGE_PFSENSE_SSH = 4
# Step 12 of project_dual_suricata_sync.md: two extra pages collect
# the local-Suricata setup. They are inserted between the Netgate
# block and the analyzer block so source-related questions stay
# contiguous, and they are skipped when ``sources.suricata_local``
# is False (single-Netgate operators see no extra steps).
PAGE_SURICATA_INSTALL = 5
PAGE_SURICATA_CONFIG = 6
PAGE_ANALYSIS = 7
PAGE_NOTIFICATIONS = 8
PAGE_PIPELINE = 9
PAGE_FORENSICS = 10
PAGE_LOGGING = 11
PAGE_SUMMARY = 12
TOTAL_PAGES = 13


def _section_label(text: str) -> SubtitleLabel:
    """Create a styled section header label."""
    label = SubtitleLabel(text)
    label.setStyleSheet("color: #0078d4; padding: 8px 0 4px 0;")
    return label


def _field_label(text: str, optional: bool = False) -> BodyLabel:
    """Create a field label, marking optional fields."""
    suffix = "  (Optional)" if optional else ""
    label = BodyLabel(f"{text}{suffix}")
    if optional:
        label.setStyleSheet("color: #9a9a9a;")
    return label


class SetupWizard(QDialog):
    """Multi-page setup wizard for first-run configuration.

    Args:
        data_dir: Writable data directory for config output.
        sources: Optional answers from the upstream
            :class:`SourcesQuestionnaire`. When supplied, pages whose
            inputs only matter for an unselected source are skipped
            (e.g. the pfSense SSH key page is hidden when the operator
            said they have no Netgate). When ``None``, the wizard
            behaves exactly like before — every page is shown — which
            keeps existing tests and the legacy "edit config" entry
            point working unchanged.
        parent: Parent widget.
    """

    def __init__(
        self,
        data_dir: Path,
        sources: Optional[SourceChoices] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._data_dir = data_dir
        self._sources = sources
        self.setWindowTitle("WardSOAR — Setup Wizard")
        self.setMinimumSize(800, 700)
        self.resize(900, 750)
        self._current_page = 0
        self._fields: dict[str, Any] = {}
        self._setup_ui()
        self._apply_theme()

    def _is_page_relevant(self, page_index: int) -> bool:
        """Whether the given page should be shown given the source answers.

        The pfSense SSH page (and its credentials) is meaningless if the
        operator said they have no Netgate; skip it. The two Suricata-
        local pages (install + config) are meaningless if the operator
        said they don't want a local Suricata; skip them. Every other
        page is always shown — they collect data WardSOAR needs
        regardless of which alert source feeds the pipeline.
        """
        if self._sources is None:
            return True
        if page_index == PAGE_PFSENSE_SSH and not self._sources.netgate:
            return False
        if (
            page_index in (PAGE_SURICATA_INSTALL, PAGE_SURICATA_CONFIG)
            and not self._sources.suricata_local
        ):
            return False
        return True

    def _setup_ui(self) -> None:
        """Build the wizard layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet("background-color: #0f3460; padding: 16px;")
        header_layout = QVBoxLayout(header)
        title = TitleLabel("WardSOAR Setup")
        title.setStyleSheet("color: #ffffff;")
        header_layout.addWidget(title)
        self._page_indicator = CaptionLabel("Step 1 of 10")
        self._page_indicator.setStyleSheet("color: #80b0e0;")
        header_layout.addWidget(self._page_indicator)
        layout.addWidget(header)

        # Pages stack
        self._stack = QStackedWidget()
        self._build_welcome_page()
        self._build_sysmon_page()
        self._build_api_keys_page()
        self._build_network_page()
        self._build_pfsense_page()
        self._build_suricata_install_page()
        self._build_suricata_config_page()
        self._build_analysis_page()
        self._build_notifications_page()
        self._build_pipeline_page()
        self._build_forensics_page()
        self._build_logging_page()
        self._build_summary_page()
        layout.addWidget(self._stack, stretch=1)

        # Navigation buttons
        nav = QFrame()
        nav_bg = "#252525" if isDarkTheme() else "#f0f0f0"
        nav.setStyleSheet(f"background-color: {nav_bg}; padding: 12px;")
        nav_layout = QHBoxLayout(nav)
        self._back_btn = PushButton("Back")
        self._back_btn.clicked.connect(self._go_back)
        self._next_btn = PrimaryPushButton("Next")
        self._next_btn.clicked.connect(self._go_next)
        self._cancel_btn = PushButton("Cancel")
        self._cancel_btn.clicked.connect(self.reject)
        nav_layout.addWidget(self._cancel_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self._back_btn)
        nav_layout.addWidget(self._next_btn)
        layout.addWidget(nav)

        self._update_nav()

    def _apply_theme(self) -> None:
        """Apply dark theme styling to the wizard dialog."""
        if isDarkTheme():
            self.setStyleSheet(
                "QDialog { background-color: #1e1e1e; }"
                "QScrollArea { background-color: #1e1e1e; border: none; }"
                "QScrollArea > QWidget > QWidget { background-color: #1e1e1e; }"
                "QWidget { background-color: #1e1e1e; color: #e4e4e4; }"
            )

    def _scrollable_page(self) -> tuple[QWidget, QVBoxLayout]:
        """Create a scrollable page with a content layout."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(32, 24, 32, 24)
        content_layout.setSpacing(8)
        scroll.setWidget(content)
        self._stack.addWidget(scroll)
        return content, content_layout

    # ----------------------------------------------------------------
    # Page builders
    # ----------------------------------------------------------------

    def _build_welcome_page(self) -> None:
        """Page 0: Welcome."""
        page, layout = self._scrollable_page()
        layout.addSpacing(40)
        logo = TitleLabel("\U0001f6e1")
        logo.setFont(QFont("Segoe UI", 48))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)
        title = TitleLabel("Welcome to WardSOAR")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(16)
        desc = BodyLabel(
            "This wizard will configure WardSOAR for your environment.\n\n"
            "All fields show their default values. Modify only what you need.\n"
            "Fields marked (Optional) can be left empty or at their defaults."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)
        layout.addStretch()

    def _build_sysmon_page(self) -> None:
        """Page 1: Install Sysmon (critical prerequisite).

        Sysmon is the difference between ~75% and ~99% process
        attribution on Suricata alerts (see docs/bootstrap-netgate.md
        step 1). We front-load the install here so operators see the
        dependency before they dive into API keys and pipeline
        tuning — with an explicit "skip" escape hatch because the
        pfSense side is still operational without it.
        """
        from PySide6.QtCore import QTimer

        from wardsoar.pc.sysmon_installer import launch_install_script
        from wardsoar.pc.sysmon_probe import probe_sysmon

        page, layout = self._scrollable_page()
        layout.addSpacing(20)

        title = TitleLabel("Install Sysmon (recommended)")
        layout.addWidget(title)
        layout.addSpacing(8)

        subtitle = StrongBodyLabel("Required for reliable process attribution on alerts.")
        layout.addWidget(subtitle)
        layout.addSpacing(12)

        desc = BodyLabel(
            "Sysmon is a free Microsoft Sysinternals tool that logs every "
            "network connection with the Windows process that opened it. "
            "WardSOAR uses those logs to tell you which program on this PC "
            "generated each Suricata alert — rather than just the remote IP.\n\n"
            "Without Sysmon, WardSOAR can only attribute a process while the "
            "socket is still open (roughly 75% of flows). With Sysmon, we reach "
            "~99% attribution even for short-lived and UDP bursts.\n\n"
            "Clicking the button below will:\n"
            "  • download Sysmon from Microsoft (download.sysinternals.com)\n"
            "  • verify the Authenticode signature is Microsoft's\n"
            "  • install the SwiftOnSecurity sysmon-config network ruleset\n"
            "  • start the Sysmon64 Windows service\n\n"
            "Windows will prompt for administrator rights (UAC) — that is "
            "required to register a Windows service."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        layout.addSpacing(16)

        self._sysmon_wizard_status = StrongBodyLabel("")
        layout.addWidget(self._sysmon_wizard_status)

        btn_row = QHBoxLayout()
        self._sysmon_wizard_btn = PrimaryPushButton("Install Sysmon now")
        btn_row.addWidget(self._sysmon_wizard_btn)
        btn_row.addStretch()
        skip_hint = CaptionLabel(
            "You can skip this page and install Sysmon later "
            "from the Netgate tab. The Next button is always enabled."
        )
        skip_hint.setWordWrap(True)
        layout.addLayout(btn_row)
        layout.addSpacing(6)
        layout.addWidget(skip_hint)
        layout.addStretch()

        # Wizard state.
        self._sysmon_wizard_poll_timer: Optional[QTimer] = None
        self._sysmon_wizard_poll_count = 0

        def _refresh_status() -> None:
            status = probe_sysmon()
            if status.healthy:
                self._sysmon_wizard_status.setText("✅  Sysmon detected and running.")
                self._sysmon_wizard_status.setStyleSheet("color: #66BB6A;")  # green-400
                self._sysmon_wizard_btn.setEnabled(False)
                self._sysmon_wizard_btn.setText("Sysmon installed")
                if self._sysmon_wizard_poll_timer is not None:
                    self._sysmon_wizard_poll_timer.stop()
                return
            if status.installed and not status.running:
                self._sysmon_wizard_status.setText(
                    "⚠️  Sysmon installed but service stopped — "
                    "run « Start-Service Sysmon64 » as admin."
                )
                self._sysmon_wizard_status.setStyleSheet("color: #FFB74D;")
                self._sysmon_wizard_btn.setEnabled(False)
                return
            self._sysmon_wizard_status.setText("⚠️  Sysmon not detected on this PC.")
            self._sysmon_wizard_status.setStyleSheet("color: #FFB74D;")
            self._sysmon_wizard_btn.setEnabled(True)
            self._sysmon_wizard_btn.setText("Install Sysmon now")

        def _on_install_clicked() -> None:
            self._sysmon_wizard_btn.setEnabled(False)
            self._sysmon_wizard_btn.setText("⏳ UAC prompt — check your desktop…")
            self._sysmon_wizard_status.setText(
                "Waiting for Windows elevation prompt. Accept it to start the install."
            )
            result = launch_install_script()
            if not result.started:
                self._sysmon_wizard_status.setText(f"❌  {result.error}")
                self._sysmon_wizard_status.setStyleSheet("color: #EF5350;")
                self._sysmon_wizard_btn.setEnabled(True)
                self._sysmon_wizard_btn.setText("Install Sysmon now")
                return

            self._sysmon_wizard_poll_count = 0

            def _poll() -> None:
                self._sysmon_wizard_poll_count += 1
                _refresh_status()
                if probe_sysmon().healthy or self._sysmon_wizard_poll_count >= 24:  # ~2 min
                    if self._sysmon_wizard_poll_timer is not None:
                        self._sysmon_wizard_poll_timer.stop()

            self._sysmon_wizard_poll_timer = QTimer(self)
            self._sysmon_wizard_poll_timer.setInterval(5000)
            self._sysmon_wizard_poll_timer.timeout.connect(_poll)
            self._sysmon_wizard_poll_timer.start()

        self._sysmon_wizard_btn.clicked.connect(_on_install_clicked)
        _refresh_status()

    def _build_api_keys_page(self) -> None:
        """Page 2: API Keys.

        v0.10.0 rewrite. Renders the same six-block layout as the
        "API Keys & Secrets" settings tab:
          1. Auto-enabled intelligence feeds (informational only).
          2. Required (Anthropic).
          3. Essentials (free, high-signal: VT / AbuseIPDB / GreyNoise / OTX).
          4. Useful for specific cases (free: X-Force / Honey Pot / ipinfo pro).
          5. Paid (Shodan / SecurityTrails / Censys).
          6. Notifications block — kept separate on the notifications page
             so this page stays focused on reputation sources.

        Fields are keyed by the spec's ``env_var`` (canonical). Legacy
        short names (``anthropic_key`` etc.) are registered as aliases
        so the summary / validation / env-generation code that
        predates this rewrite keeps working unchanged.
        """
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("API Keys & Secrets"))

        # Block 1 --- auto-enabled informational card.
        auto_card = SimpleCardWidget()
        auto_layout = QVBoxLayout(auto_card)
        auto_layout.setContentsMargins(16, 12, 16, 12)
        auto_layout.setSpacing(6)
        auto_layout.addWidget(
            StrongBodyLabel("\U0001f7e2  Active by default \u2014 no action needed")
        )
        auto_layout.addWidget(
            CaptionLabel(
                f"{len(AUTO_ENABLED_SOURCES)} intelligence sources run automatically "
                "in the background once WardSOAR starts. Listed here so you know "
                "what is already feeding the Alert Detail view."
            )
        )
        for source in AUTO_ENABLED_SOURCES:
            row = QVBoxLayout()
            row.setSpacing(0)
            header = QHBoxLayout()
            header.setContentsMargins(0, 0, 0, 0)
            header.addWidget(BodyLabel(f"\u2705  {source.name}"), stretch=1)
            cadence = CaptionLabel(source.refresh_cadence)
            cadence.setStyleSheet("color: #7a7a7a;")
            header.addWidget(cadence)
            row.addLayout(header)
            desc = CaptionLabel(f"    {source.description}")
            desc.setStyleSheet("color: #5a5a5a;")
            desc.setWordWrap(True)
            row.addWidget(desc)
            auto_layout.addLayout(row)
        layout.addWidget(auto_card)

        # Blocks 2..5 --- keyed tier cards (reputation sources only).
        # The notifications block (SMTP / Telegram) stays on the
        # dedicated notifications page of the wizard.
        layout.addSpacing(12)
        self._add_tier_card(layout, "required", "Required")
        layout.addSpacing(12)
        self._add_tier_card(layout, "essential", "Essentials \u2014 recommended (free)")
        layout.addSpacing(12)
        self._add_tier_card(layout, "useful", "Useful for specific cases (free)")
        layout.addSpacing(12)
        self._add_tier_card(layout, "paid", "Paid sources")
        layout.addStretch()

    def _add_tier_card(self, parent_layout: QVBoxLayout, tier: Tier, heading: str) -> None:
        """Render one tier's card inside the API keys page.

        Each ``ApiKeySpec`` becomes:
           label           pricing caption
           description
           [ Sign up \u2192 ]
           [ password field ................................ ]
        """
        specs = tuple(spec for spec in API_KEY_SPECS if spec.tier == tier)
        if not specs:
            return
        card = SimpleCardWidget()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(12)
        card_layout.addWidget(StrongBodyLabel(heading))
        for spec in specs:
            entry = QVBoxLayout()
            entry.setSpacing(4)

            header = QHBoxLayout()
            header.setContentsMargins(0, 0, 0, 0)
            label_text = spec.display_label
            if spec.required:
                label_text = f"{label_text}  \u2014  REQUIRED"
            header.addWidget(BodyLabel(label_text), stretch=1)
            if spec.pricing:
                pricing = CaptionLabel(spec.pricing)
                pricing.setStyleSheet("color: #7a7a7a;")
                pricing.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                header.addWidget(pricing)
            entry.addLayout(header)

            desc = CaptionLabel(spec.description)
            desc.setStyleSheet("color: #5a5a5a;")
            desc.setWordWrap(True)
            entry.addWidget(desc)

            if spec.signup_url:
                signup = HyperlinkButton(spec.signup_url, f"Sign up at {spec.signup_url} \u2192")
                entry.addWidget(signup, alignment=Qt.AlignmentFlag.AlignLeft)

            field = PasswordLineEdit()
            field.setPlaceholderText(spec.placeholder)
            self._fields[spec.env_var] = field
            # Register legacy short aliases so the rest of the wizard
            # (summary page, validation, env generation) keeps working.
            for alias, env_var in _LEGACY_WIZARD_ALIASES.items():
                if env_var == spec.env_var:
                    self._fields[alias] = field
            entry.addWidget(field)
            card_layout.addLayout(entry)
        parent_layout.addWidget(card)

    def _build_network_page(self) -> None:
        """Page 2: Network configuration."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Network Configuration"))

        for key, label, default in [
            ("pfsense_ip", "pfSense / Gateway IP", "192.168.2.1"),
            ("pc_ip", "This PC IP", "192.168.2.100"),
            ("dns1", "Primary DNS", "1.1.1.1"),
            ("dns2", "Secondary DNS", "8.8.8.8"),
        ]:
            layout.addWidget(_field_label(label))
            self._fields[key] = LineEdit()
            self._fields[key].setText(default)
            layout.addWidget(self._fields[key])
        layout.addStretch()

    def _build_pfsense_page(self) -> None:
        """Page 3: pfSense SSH."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("pfSense SSH Configuration"))

        layout.addWidget(_field_label("SSH Username"))
        self._fields["ssh_user"] = LineEdit()
        self._fields["ssh_user"].setText("admin")
        layout.addWidget(self._fields["ssh_user"])

        layout.addWidget(_field_label("SSH Private Key Path"))
        key_layout = QHBoxLayout()
        default_key = str(Path.home() / ".ssh" / "ward_key")
        self._fields["ssh_key"] = LineEdit()
        self._fields["ssh_key"].setText(default_key)
        browse_btn = PushButton("Browse...")
        browse_btn.clicked.connect(self._browse_ssh_key)
        key_layout.addWidget(self._fields["ssh_key"], stretch=1)
        key_layout.addWidget(browse_btn)
        layout.addLayout(key_layout)

        layout.addWidget(_field_label("SSH Port"))
        self._fields["ssh_port"] = SpinBox()
        self._fields["ssh_port"].setRange(1, 65535)
        self._fields["ssh_port"].setValue(22)
        layout.addWidget(self._fields["ssh_port"])

        layout.addWidget(_field_label("Remote EVE JSON Path"))
        self._fields["remote_eve"] = LineEdit()
        self._fields["remote_eve"].setText("/var/log/suricata/suricata_igc252678/eve.json")
        layout.addWidget(self._fields["remote_eve"])

        layout.addWidget(_field_label("Blocklist Table Name"))
        self._fields["blocklist_table"] = LineEdit()
        self._fields["blocklist_table"].setText("blocklist")
        layout.addWidget(self._fields["blocklist_table"])
        layout.addStretch()

    def _build_suricata_install_page(self) -> None:
        """Page: Local Suricata installation status + install entry points.

        Step 12 of project_dual_suricata_sync.md. Skipped when
        ``sources.suricata_local`` is False (see ``_is_page_relevant``).

        Shows the current install status of the two Windows
        prerequisites (Suricata + Npcap) read live from
        :mod:`installer_helpers`. The two install actions launch
        the official installers — they always run with the operator's
        consent (UAC prompt) and we explicitly DO NOT silently
        accept the Npcap NPSL: Npcap's licence requires an explicit
        end-user click, both for compliance and for the operator
        to see what they are agreeing to. The Suricata installer
        is GPLv2 / freely redistributable, but we still surface
        the click for symmetry.

        The page does not block the wizard — the operator can
        proceed without installing immediately, in which case the
        runtime falls back to a Netgate-only stream and surfaces a
        WARNING log inviting them to come back to the wizard.
        """
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Local Suricata — Install"))

        layout.addWidget(
            BodyLabel(
                "WardSOAR's dual-source mode requires a local Suricata IDS "
                "and the Npcap packet-capture driver. Both are downloaded "
                "from their official sources at install time — they are "
                "never bundled with WardSOAR (license boundary)."
            )
        )

        # Status read live so the page reflects the actual state on
        # the operator's machine. Imported lazily so test environments
        # without the Windows registry / WMI surface still build the
        # wizard for unit tests.
        from wardsoar.pc.installer_helpers import (
            is_npcap_installed,
            is_suricata_installed,
        )

        try:
            suricata_present, suricata_path = is_suricata_installed()
        except Exception:  # noqa: BLE001 — installer probe must not crash the wizard
            suricata_present, suricata_path = False, None
        try:
            npcap_present = is_npcap_installed()
        except Exception:  # noqa: BLE001
            npcap_present = False

        layout.addSpacing(8)
        layout.addWidget(_field_label("Suricata status"))
        suricata_status = StrongBodyLabel(
            f"Installed at {suricata_path}" if suricata_present else "Not installed"
        )
        suricata_status.setStyleSheet("color: #4caf50;" if suricata_present else "color: #f44336;")
        layout.addWidget(suricata_status)
        # Field stored so the summary page can surface the state.
        self._fields["suricata_install_status"] = suricata_status

        suricata_btn = PushButton("Install / re-install Suricata...")
        suricata_btn.setEnabled(True)
        suricata_btn.clicked.connect(self._on_install_suricata_clicked)
        layout.addWidget(suricata_btn)
        self._fields["suricata_install_btn"] = suricata_btn

        layout.addSpacing(8)
        layout.addWidget(_field_label("Npcap status"))
        npcap_status = StrongBodyLabel("Installed" if npcap_present else "Not installed")
        npcap_status.setStyleSheet("color: #4caf50;" if npcap_present else "color: #f44336;")
        layout.addWidget(npcap_status)
        self._fields["npcap_install_status"] = npcap_status

        npcap_btn = PushButton("Install Npcap...")
        npcap_btn.clicked.connect(self._on_install_npcap_clicked)
        layout.addWidget(npcap_btn)
        self._fields["npcap_install_btn"] = npcap_btn

        layout.addSpacing(12)
        layout.addWidget(_section_label("Licenses"))
        layout.addWidget(
            BodyLabel(
                "Suricata is downloaded from openinfosecfoundation.org under "
                "the GPLv2. Npcap is downloaded from npcap.com under the "
                "Npcap Public Source Licence (NPSL); the operator must accept "
                "the NPSL in the Npcap installer for it to proceed."
            )
        )
        layout.addStretch()

    def _build_suricata_config_page(self) -> None:
        """Page: Local Suricata runtime configuration.

        Step 12 of project_dual_suricata_sync.md. Skipped when
        ``sources.suricata_local`` is False.

        Collects the three operator-supplied parameters that
        ``LocalSuricataAgent`` needs at runtime:

        * **Interface** — Windows network adapter Suricata should
          listen on, picked from the live psutil enumeration
          (loopback / disabled adapters filtered out by
          :func:`list_network_interfaces`).
        * **Reconciliation window** — Q1 doctrine, default 120 s,
          band [30, 180]. Only meaningful in dual-source mode
          (Netgate + local) but stored unconditionally so the
          field is ready when the operator later turns on the
          external Netgate.
        * **Local subnets** — RFC1918 ranges or extras that count
          as "LAN-only" for the divergence investigator's
          ``lan_only`` check. One CIDR per line; defaults to
          empty (the investigator falls back to RFC1918 ranges).
        """
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Local Suricata — Configuration"))

        # Interface picker — populated from the live psutil
        # enumeration.
        from wardsoar.pc.local_suricata import list_network_interfaces

        try:
            interfaces = list_network_interfaces()
        except Exception:  # noqa: BLE001 — psutil failure must not crash the wizard
            interfaces = []
            logger.exception("list_network_interfaces failed during wizard build")

        layout.addWidget(_field_label("Listen interface"))
        self._fields["suricata_interface"] = ComboBox()
        if interfaces:
            for iface_name, iface_descr in interfaces:
                # Display: "<name> — <description>" so the operator
                # can pick the right adapter even when names are
                # cryptic (e.g. {GUID}).
                self._fields["suricata_interface"].addItem(f"{iface_name} — {iface_descr}")
        else:
            self._fields["suricata_interface"].addItem("(no interface detected)")
            self._fields["suricata_interface"].setEnabled(False)
        layout.addWidget(self._fields["suricata_interface"])

        layout.addSpacing(8)
        layout.addWidget(_field_label("Reconciliation window (seconds)"))
        layout.addWidget(
            CaptionLabel(
                "How long the dual-source correlator waits for the second "
                "Suricata to confirm a flow before flagging a divergence. "
                "Only meaningful when Netgate is also enabled. Q1 doctrine: "
                "120 s default, allowed band [30, 180]."
            )
        )
        self._fields["suricata_window_s"] = DoubleSpinBox()
        self._fields["suricata_window_s"].setRange(30.0, 180.0)
        self._fields["suricata_window_s"].setSingleStep(10.0)
        self._fields["suricata_window_s"].setValue(120.0)
        layout.addWidget(self._fields["suricata_window_s"])

        layout.addSpacing(8)
        layout.addWidget(_field_label("Local subnets — extra CIDRs", optional=True))
        layout.addWidget(
            CaptionLabel(
                "RFC1918 (10/8, 172.16/12, 192.168/16) is always treated "
                "as LAN. Add operator-specific ranges here, one CIDR per "
                "line, e.g. ``100.64.0.0/10`` for CGNAT or ``10.13.0.0/16`` "
                "for a routed lab subnet."
            )
        )
        self._fields["suricata_local_subnets"] = TextEdit()
        self._fields["suricata_local_subnets"].setFixedHeight(80)
        layout.addWidget(self._fields["suricata_local_subnets"])

        layout.addStretch()

    def _on_install_suricata_clicked(self) -> None:
        """Launch the Suricata installer in the background.

        Best-effort wrapper around ``installer_helpers.install_suricata``.
        Failures are logged and surfaced via the existing status
        label rather than raised, so the operator sees the failure
        without losing wizard state.

        The downloaded installer is written to
        ``<data_dir>/installers`` so a paranoid operator can
        re-verify the SHA-256 manually after the wizard closes.
        """
        from wardsoar.pc.installer_helpers import install_suricata

        download_dir = self._data_dir / "installers"
        download_dir.mkdir(parents=True, exist_ok=True)

        async def _run() -> None:
            outcome = await install_suricata(download_dir=download_dir)
            logger.info("install_suricata outcome: %s", outcome)
            # Update the status label on completion.
            try:
                from wardsoar.pc.installer_helpers import is_suricata_installed

                installed, path = is_suricata_installed()
                status_widget = self._fields.get("suricata_install_status")
                if status_widget is not None:
                    status_widget.setText(
                        f"Installed at {path}" if installed else "Install cancelled or failed"
                    )
                    status_widget.setStyleSheet(
                        "color: #4caf50;" if installed else "color: #f44336;"
                    )
            except Exception:  # noqa: BLE001
                logger.debug("post-install Suricata status refresh failed", exc_info=True)

        # The wizard runs on the main thread; spin a one-shot
        # asyncio runner. The installer launches an external EXE
        # asynchronously, so this returns quickly.
        import asyncio

        try:
            asyncio.run(_run())
        except Exception:  # noqa: BLE001 — installer must never crash the wizard
            logger.exception("Suricata installer failed")

    def _on_install_npcap_clicked(self) -> None:
        """Launch the Npcap installer in the background.

        See :meth:`_on_install_suricata_clicked` for the rationale —
        Npcap requires the operator to accept the NPSL in the
        installer dialog, so we never silent-install.
        """
        from wardsoar.pc.installer_helpers import install_npcap

        download_dir = self._data_dir / "installers"
        download_dir.mkdir(parents=True, exist_ok=True)

        async def _run() -> None:
            outcome = await install_npcap(download_dir=download_dir)
            logger.info("install_npcap outcome: %s", outcome)
            try:
                from wardsoar.pc.installer_helpers import is_npcap_installed

                installed = is_npcap_installed()
                status_widget = self._fields.get("npcap_install_status")
                if status_widget is not None:
                    status_widget.setText(
                        "Installed" if installed else "Install cancelled or failed"
                    )
                    status_widget.setStyleSheet(
                        "color: #4caf50;" if installed else "color: #f44336;"
                    )
            except Exception:  # noqa: BLE001
                logger.debug("post-install Npcap status refresh failed", exc_info=True)

        import asyncio

        try:
            asyncio.run(_run())
        except Exception:  # noqa: BLE001
            logger.exception("Npcap installer failed")

    def _build_analysis_page(self) -> None:
        """Page 4: Analysis & Response."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Analysis & Response"))

        layout.addWidget(_field_label("Claude Model"))
        self._fields["model"] = ComboBox()
        # v0.5 uses Opus exclusively. Older model IDs are kept for users who
        # want to downgrade while the new pipeline beds in.
        self._fields["model"].addItems(
            [
                "claude-opus-4-7",
                "claude-opus-4-20250514",
            ]
        )
        layout.addWidget(self._fields["model"])

        layout.addWidget(_field_label("Max Tokens"))
        self._fields["max_tokens"] = SpinBox()
        self._fields["max_tokens"].setRange(512, 16384)
        self._fields["max_tokens"].setValue(4096)
        layout.addWidget(self._fields["max_tokens"])

        layout.addWidget(_field_label("Confidence Threshold (0.0 - 1.0)"))
        self._fields["confidence"] = DoubleSpinBox()
        self._fields["confidence"].setRange(0.5, 1.0)
        self._fields["confidence"].setSingleStep(0.05)
        self._fields["confidence"].setValue(0.7)
        layout.addWidget(self._fields["confidence"])

        layout.addSpacing(8)
        layout.addWidget(_section_label("Response"))

        self._fields["dry_run"] = CheckBox("Dry-run mode (log only, no blocking)")
        self._fields["dry_run"].setChecked(True)
        layout.addWidget(self._fields["dry_run"])

        layout.addWidget(_field_label("Block duration (hours)"))
        self._fields["block_hours"] = SpinBox()
        self._fields["block_hours"].setRange(1, 720)
        self._fields["block_hours"].setValue(24)
        layout.addWidget(self._fields["block_hours"])

        layout.addWidget(_field_label("Max blocks per hour"))
        self._fields["max_blocks"] = SpinBox()
        self._fields["max_blocks"].setRange(1, 100)
        self._fields["max_blocks"].setValue(20)
        layout.addWidget(self._fields["max_blocks"])

        self._fields["kill_process"] = CheckBox("Kill suspicious local process")
        self._fields["kill_process"].setChecked(True)
        layout.addWidget(self._fields["kill_process"])

        layout.addSpacing(8)
        layout.addWidget(_field_label("PreScorer mode"))
        self._fields["prescorer_mode"] = ComboBox()
        self._fields["prescorer_mode"].addItems(["learning", "active"])
        layout.addWidget(self._fields["prescorer_mode"])
        layout.addStretch()

    def _build_notifications_page(self) -> None:
        """Page 5: Notifications."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Email Notifications (Optional)"))

        self._fields["email_enabled"] = CheckBox("Enable email notifications")
        layout.addWidget(self._fields["email_enabled"])

        for key, label, default in [
            ("smtp_host", "SMTP Host", "smtp.gmail.com"),
            ("smtp_port", "SMTP Port", None),
            ("smtp_user", "SMTP Username", ""),
            ("smtp_password", "SMTP Password", ""),
            ("email_from", "From Address", ""),
            ("email_to", "To Address", ""),
        ]:
            layout.addWidget(_field_label(label, optional=True))
            if key == "smtp_port":
                self._fields[key] = SpinBox()
                self._fields[key].setRange(1, 65535)
                self._fields[key].setValue(587)
            elif key == "smtp_password":
                self._fields[key] = PasswordLineEdit()
            else:
                self._fields[key] = LineEdit()
                if default:
                    self._fields[key].setText(default)
            layout.addWidget(self._fields[key])

        self._fields["smtp_tls"] = CheckBox("Use TLS")
        self._fields["smtp_tls"].setChecked(True)
        layout.addWidget(self._fields["smtp_tls"])

        layout.addSpacing(16)
        layout.addWidget(_section_label("Telegram Notifications (Optional)"))

        self._fields["telegram_enabled"] = CheckBox("Enable Telegram notifications")
        layout.addWidget(self._fields["telegram_enabled"])

        layout.addWidget(_field_label("Bot Token", optional=True))
        self._fields["telegram_token"] = PasswordLineEdit()
        layout.addWidget(self._fields["telegram_token"])

        layout.addWidget(_field_label("Chat ID", optional=True))
        self._fields["telegram_chat_id"] = LineEdit()
        layout.addWidget(self._fields["telegram_chat_id"])
        layout.addStretch()

    def _build_pipeline_page(self) -> None:
        """Page 6: Anti-False-Positive Pipeline."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Filter (Optional)"))
        self._fields["filter_enabled"] = CheckBox("Enable false positive filter")
        self._fields["filter_enabled"].setChecked(True)
        layout.addWidget(self._fields["filter_enabled"])
        self._fields["filter_log"] = CheckBox("Log suppressed alerts")
        self._fields["filter_log"].setChecked(True)
        layout.addWidget(self._fields["filter_log"])

        layout.addSpacing(8)
        layout.addWidget(_section_label("Deduplicator (Optional)"))
        self._fields["dedup_enabled"] = CheckBox("Enable alert deduplication")
        self._fields["dedup_enabled"].setChecked(True)
        layout.addWidget(self._fields["dedup_enabled"])

        layout.addWidget(_field_label("Grouping window (seconds)", optional=True))
        self._fields["dedup_window"] = SpinBox()
        self._fields["dedup_window"].setRange(5, 600)
        self._fields["dedup_window"].setValue(60)
        layout.addWidget(self._fields["dedup_window"])

        layout.addWidget(_field_label("Max group size", optional=True))
        self._fields["dedup_max"] = SpinBox()
        self._fields["dedup_max"].setRange(5, 500)
        self._fields["dedup_max"].setValue(50)
        layout.addWidget(self._fields["dedup_max"])

        layout.addSpacing(8)
        layout.addWidget(_section_label("Decision Cache (Optional)"))
        self._fields["cache_enabled"] = CheckBox("Enable decision cache")
        self._fields["cache_enabled"].setChecked(True)
        layout.addWidget(self._fields["cache_enabled"])

        for key, label, val in [
            ("cache_benign", "Benign TTL (seconds)", 3600),
            ("cache_confirmed", "Confirmed TTL (seconds)", 86400),
            ("cache_inconclusive", "Inconclusive TTL (seconds)", 600),
            ("cache_max", "Max entries", 10000),
        ]:
            layout.addWidget(_field_label(label, optional=True))
            self._fields[key] = SpinBox()
            self._fields[key].setRange(10, 1000000)
            self._fields[key].setValue(val)
            layout.addWidget(self._fields[key])

        layout.addStretch()

    def _build_forensics_page(self) -> None:
        """Page 7: Forensics & VirusTotal."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Forensics (Optional)"))

        layout.addWidget(_field_label("Sysmon event log channel", optional=True))
        self._fields["sysmon_channel"] = LineEdit()
        self._fields["sysmon_channel"].setText("Microsoft-Windows-Sysmon/Operational")
        layout.addWidget(self._fields["sysmon_channel"])

        layout.addWidget(_field_label("Correlation window (seconds)", optional=True))
        self._fields["forensic_window"] = SpinBox()
        self._fields["forensic_window"].setRange(30, 3600)
        self._fields["forensic_window"].setValue(300)
        layout.addWidget(self._fields["forensic_window"])

        layout.addWidget(_field_label("Max events per query", optional=True))
        self._fields["forensic_max_events"] = SpinBox()
        self._fields["forensic_max_events"].setRange(50, 5000)
        self._fields["forensic_max_events"].setValue(500)
        layout.addWidget(self._fields["forensic_max_events"])

        layout.addWidget(_field_label("Forensic checks:"))
        for key, label in [
            ("chk_processes", "Check running processes"),
            ("chk_network", "Check network connections"),
            ("chk_dns", "Check DNS cache"),
            ("chk_arp", "Check ARP cache"),
            ("chk_sysmon", "Check Sysmon events"),
            ("chk_eventlog", "Check Windows event logs"),
            ("chk_registry", "Check registry persistence"),
            ("chk_files", "Check recent files"),
        ]:
            self._fields[key] = CheckBox(label)
            self._fields[key].setChecked(True)
            layout.addWidget(self._fields[key])

        layout.addSpacing(12)
        layout.addWidget(_section_label("VirusTotal (Optional)"))
        self._fields["vt_enabled"] = CheckBox("Enable VirusTotal lookups")
        self._fields["vt_enabled"].setChecked(True)
        layout.addWidget(self._fields["vt_enabled"])

        self._fields["vt_hash_first"] = CheckBox("Check hash before submitting")
        self._fields["vt_hash_first"].setChecked(True)
        layout.addWidget(self._fields["vt_hash_first"])

        self._fields["vt_submit"] = CheckBox("Submit unknown files (files become public on VT)")
        self._fields["vt_submit"].setChecked(False)
        layout.addWidget(self._fields["vt_submit"])

        layout.addWidget(_field_label("Max file size (MB)", optional=True))
        self._fields["vt_max_size"] = SpinBox()
        self._fields["vt_max_size"].setRange(1, 256)
        self._fields["vt_max_size"].setValue(32)
        layout.addWidget(self._fields["vt_max_size"])
        layout.addStretch()

    def _build_logging_page(self) -> None:
        """Page 8: Logging & Monitoring."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Logging (Optional)"))

        layout.addWidget(_field_label("Log level", optional=True))
        self._fields["log_level"] = ComboBox()
        self._fields["log_level"].addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self._fields["log_level"].setCurrentIndex(1)  # INFO
        layout.addWidget(self._fields["log_level"])

        layout.addWidget(_field_label("Max log file size (MB)", optional=True))
        self._fields["log_max_size"] = SpinBox()
        self._fields["log_max_size"].setRange(1, 100)
        self._fields["log_max_size"].setValue(10)
        layout.addWidget(self._fields["log_max_size"])

        layout.addWidget(_field_label("Log backup count", optional=True))
        self._fields["log_backups"] = SpinBox()
        self._fields["log_backups"].setRange(1, 20)
        self._fields["log_backups"].setValue(5)
        layout.addWidget(self._fields["log_backups"])

        layout.addSpacing(12)
        layout.addWidget(_section_label("Health Check (Optional)"))

        self._fields["health_enabled"] = CheckBox("Enable periodic health checks")
        self._fields["health_enabled"].setChecked(True)
        layout.addWidget(self._fields["health_enabled"])

        for key, label, lo, hi, val in [
            ("health_interval", "Check interval (seconds)", 30, 3600, 300),
            ("health_disk", "Disk warning threshold (MB)", 100, 10000, 500),
            ("health_eve_age", "EVE max age (seconds)", 10, 600, 60),
        ]:
            layout.addWidget(_field_label(label, optional=True))
            self._fields[key] = SpinBox()
            self._fields[key].setRange(lo, hi)
            self._fields[key].setValue(val)
            layout.addWidget(self._fields[key])

        self._fields["health_notify"] = CheckBox("Notify on failure")
        self._fields["health_notify"].setChecked(True)
        layout.addWidget(self._fields["health_notify"])

        layout.addSpacing(12)
        layout.addWidget(_section_label("Metrics (Optional)"))

        self._fields["metrics_enabled"] = CheckBox("Enable metrics collection")
        self._fields["metrics_enabled"].setChecked(True)
        layout.addWidget(self._fields["metrics_enabled"])

        layout.addWidget(_field_label("Flush interval (seconds)", optional=True))
        self._fields["metrics_interval"] = SpinBox()
        self._fields["metrics_interval"].setRange(10, 600)
        self._fields["metrics_interval"].setValue(60)
        layout.addWidget(self._fields["metrics_interval"])
        layout.addStretch()

    def _build_summary_page(self) -> None:
        """Page 9: Summary."""
        page, layout = self._scrollable_page()
        layout.addWidget(_section_label("Configuration Summary"))
        desc = BodyLabel(
            "Review your configuration below. Click Finish to save and start WardSOAR."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        self._summary_text = TextEdit()
        self._summary_text.setReadOnly(True)
        self._summary_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self._summary_text, stretch=1)

    # ----------------------------------------------------------------
    # Navigation
    # ----------------------------------------------------------------

    def _update_nav(self) -> None:
        """Update navigation button states and page indicator."""
        self._back_btn.setEnabled(self._current_page > 0)
        is_last = self._current_page == TOTAL_PAGES - 1
        self._next_btn.setText("Finish" if is_last else "Next")
        self._page_indicator.setText(f"Step {self._current_page + 1} of {TOTAL_PAGES}")

    def _go_next(self) -> None:
        """Advance to the next page or finish."""
        if self._current_page == TOTAL_PAGES - 1:
            self._finish()
            return

        error = self._validate_page(self._current_page)
        if error:
            return

        # Walk forward over any pages that are not relevant under the
        # current source choices (e.g. pfSense SSH when Netgate=No).
        next_page = self._current_page + 1
        while next_page < TOTAL_PAGES - 1 and not self._is_page_relevant(next_page):
            next_page += 1
        self._current_page = next_page
        self._stack.setCurrentIndex(self._current_page)

        if self._current_page == PAGE_SUMMARY:
            self._update_summary()

        self._update_nav()

    def _go_back(self) -> None:
        """Go back to the previous page (skipping irrelevant pages)."""
        prev_page = self._current_page - 1
        while prev_page > 0 and not self._is_page_relevant(prev_page):
            prev_page -= 1
        if prev_page >= 0 and self._current_page > 0:
            self._current_page = prev_page
            self._stack.setCurrentIndex(self._current_page)
            self._update_nav()

    def _validate_page(self, page: int) -> Optional[str]:
        """Validate the current page fields. Returns error message or None."""
        if page == PAGE_API_KEYS:
            key = self._fields["anthropic_key"].text().strip()
            if not key:
                self._fields["anthropic_key"].setFocus()
                return "Anthropic API Key is required"
        if page == PAGE_NETWORK:
            for field_key in ("pfsense_ip", "pc_ip"):
                if not self._fields[field_key].text().strip():
                    self._fields[field_key].setFocus()
                    return f"{field_key} is required"
        return None

    def _browse_ssh_key(self) -> None:
        """Open file dialog for SSH key selection."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select SSH Private Key", str(Path.home() / ".ssh"), "All Files (*)"
        )
        if path:
            self._fields["ssh_key"].setText(path)

    # ----------------------------------------------------------------
    # Summary & Finish
    # ----------------------------------------------------------------

    def _update_summary(self) -> None:
        """Generate a text summary of all configured values."""
        lines = []
        lines.append("=== Network ===")
        lines.append(f"  pfSense IP:    {self._fields['pfsense_ip'].text()}")
        lines.append(f"  PC IP:         {self._fields['pc_ip'].text()}")
        lines.append(
            f"  DNS:           {self._fields['dns1'].text()}, {self._fields['dns2'].text()}"
        )
        lines.append("")
        lines.append("=== pfSense SSH ===")
        lines.append(f"  User:          {self._fields['ssh_user'].text()}")
        lines.append(f"  Key:           {self._fields['ssh_key'].text()}")
        lines.append(f"  Port:          {self._fields['ssh_port'].value()}")
        lines.append(f"  Remote EVE:    {self._fields['remote_eve'].text()}")
        lines.append("")
        lines.append("=== Analysis ===")
        lines.append(f"  Model:         {self._fields['model'].currentText()}")
        lines.append(f"  Max tokens:    {self._fields['max_tokens'].value()}")
        lines.append(f"  Threshold:     {self._fields['confidence'].value()}")
        lines.append(f"  Dry-run:       {self._fields['dry_run'].isChecked()}")
        lines.append(f"  Block hours:   {self._fields['block_hours'].value()}")
        lines.append(f"  Max blocks/h:  {self._fields['max_blocks'].value()}")
        lines.append(f"  PreScorer:     {self._fields['prescorer_mode'].currentText()}")
        lines.append("")
        lines.append("=== API Keys ===")
        lines.append(
            f"  Anthropic:     {'***configured***' if self._fields['anthropic_key'].text() else 'NOT SET'}"
        )
        lines.append(
            f"  VirusTotal:    {'***configured***' if self._fields['vt_key'].text() else 'not set'}"
        )
        lines.append(
            f"  AbuseIPDB:     {'***configured***' if self._fields['abuseipdb_key'].text() else 'not set'}"
        )
        lines.append(
            f"  AlienVault OTX:{'***configured***' if self._fields['otx_key'].text() else 'not set'}"
        )
        lines.append("")
        lines.append("=== Notifications ===")
        lines.append(
            f"  Email:         {'enabled' if self._fields['email_enabled'].isChecked() else 'disabled'}"
        )
        lines.append(
            f"  Telegram:      {'enabled' if self._fields['telegram_enabled'].isChecked() else 'disabled'}"
        )
        lines.append("")
        lines.append("=== Pipeline ===")
        lines.append(
            f"  Filter:        {'enabled' if self._fields['filter_enabled'].isChecked() else 'disabled'}"
        )
        lines.append(
            f"  Deduplicator:  {'enabled' if self._fields['dedup_enabled'].isChecked() else 'disabled'}"
        )
        lines.append(
            f"  Cache:         {'enabled' if self._fields['cache_enabled'].isChecked() else 'disabled'}"
        )
        lines.append("")
        lines.append("=== Logging ===")
        lines.append(f"  Level:         {self._fields['log_level'].currentText()}")
        lines.append(
            f"  Health check:  {'enabled' if self._fields['health_enabled'].isChecked() else 'disabled'}"
        )
        lines.append(
            f"  Metrics:       {'enabled' if self._fields['metrics_enabled'].isChecked() else 'disabled'}"
        )
        self._summary_text.setPlainText("\n".join(lines))

    def _finish(self) -> None:
        """Generate config.yaml and .env, then accept the dialog."""
        self._generate_config()
        self._generate_env()
        self.accept()

    def _generate_config(self) -> None:
        """Write config.yaml from wizard fields."""
        data_dir = self._data_dir
        log_dir = str(data_dir / "data" / "logs")
        eve_path = str(data_dir / "data" / "eve.json")
        decision_log = str(data_dir / "data" / "logs" / "decisions.jsonl")

        config = {
            "network": {
                "pfsense_ip": self._fields["pfsense_ip"].text(),
                "pc_ip": self._fields["pc_ip"].text(),
                "lan_subnet": self._fields["pc_ip"].text().rsplit(".", 1)[0] + ".0/24",
                "dns_servers": [self._fields["dns1"].text(), self._fields["dns2"].text()],
            },
            "watcher": {
                "mode": "ssh",
                "eve_json_path": eve_path,
                "poll_interval_seconds": 2,
                "min_severity": 3,
                "ssh": {"remote_eve_path": self._fields["remote_eve"].text()},
            },
            "filter": {
                "enabled": self._fields["filter_enabled"].isChecked(),
                "config_file": "config/known_false_positives.yaml",
                "log_suppressed": self._fields["filter_log"].isChecked(),
            },
            "deduplicator": {
                "enabled": self._fields["dedup_enabled"].isChecked(),
                "grouping_window_seconds": self._fields["dedup_window"].value(),
                "max_group_size": self._fields["dedup_max"].value(),
            },
            "prescorer": {
                "enabled": True,
                "mode": self._fields["prescorer_mode"].currentText(),
                "min_score_for_analysis": 15,
            },
            "decision_cache": {
                "enabled": self._fields["cache_enabled"].isChecked(),
                "ttl_benign_seconds": self._fields["cache_benign"].value(),
                "ttl_confirmed_seconds": self._fields["cache_confirmed"].value(),
                "ttl_inconclusive_seconds": self._fields["cache_inconclusive"].value(),
                "max_entries": self._fields["cache_max"].value(),
            },
            "forensics": {
                "sysmon_channel": self._fields["sysmon_channel"].text(),
                "correlation_window": self._fields["forensic_window"].value(),
                "max_events": self._fields["forensic_max_events"].value(),
                "checks": {
                    "processes": self._fields["chk_processes"].isChecked(),
                    "network_connections": self._fields["chk_network"].isChecked(),
                    "dns_cache": self._fields["chk_dns"].isChecked(),
                    "arp_cache": self._fields["chk_arp"].isChecked(),
                    "sysmon_events": self._fields["chk_sysmon"].isChecked(),
                    "windows_event_logs": self._fields["chk_eventlog"].isChecked(),
                    "registry_persistence": self._fields["chk_registry"].isChecked(),
                    "recent_files": self._fields["chk_files"].isChecked(),
                },
            },
            "virustotal": {
                "enabled": self._fields["vt_enabled"].isChecked(),
                "hash_first": self._fields["vt_hash_first"].isChecked(),
                "submit_unknown_files": self._fields["vt_submit"].isChecked(),
                "max_file_size": self._fields["vt_max_size"].value() * 1024 * 1024,
            },
            "analyzer": {
                "model": self._fields["model"].currentText(),
                "max_tokens": self._fields["max_tokens"].value(),
                "confidence_threshold": self._fields["confidence"].value(),
                "full_context": True,
            },
            "responder": {
                "dry_run": self._fields["dry_run"].isChecked(),
                "block_duration_hours": self._fields["block_hours"].value(),
                "max_blocks_per_hour": self._fields["max_blocks"].value(),
                "kill_local_process": self._fields["kill_process"].isChecked(),
                "block_type": "ip",
                "pfsense": {
                    "method": "ssh",
                    "ssh_user": self._fields["ssh_user"].text(),
                    "ssh_key_path": self._fields["ssh_key"].text(),
                    "ssh_port": self._fields["ssh_port"].value(),
                    "blocklist_table": self._fields["blocklist_table"].text(),
                },
            },
            "logging": {
                "level": self._fields["log_level"].currentText(),
                "log_dir": log_dir,
                "decision_log": "decisions.jsonl",
                "max_file_size": self._fields["log_max_size"].value() * 1024 * 1024,
                "backup_count": self._fields["log_backups"].value(),
            },
            "notifier": {
                "enabled": True,
                "rate_limit_per_minute": 10,
                "email": {
                    "enabled": self._fields["email_enabled"].isChecked(),
                    "smtp_host": self._fields["smtp_host"].text(),
                    "smtp_port": self._fields["smtp_port"].value(),
                    "smtp_use_tls": self._fields["smtp_tls"].isChecked(),
                    "from": self._fields["email_from"].text(),
                    "to": self._fields["email_to"].text(),
                },
                "telegram": {
                    "enabled": self._fields["telegram_enabled"].isChecked(),
                    "chat_id": self._fields["telegram_chat_id"].text(),
                },
            },
            "healthcheck": {
                "enabled": self._fields["health_enabled"].isChecked(),
                "interval_seconds": self._fields["health_interval"].value(),
                "disk_warning_threshold_mb": self._fields["health_disk"].value(),
                "eve_max_age_seconds": self._fields["health_eve_age"].value(),
                "notify_on_failure": self._fields["health_notify"].isChecked(),
            },
            "metrics": {
                "enabled": self._fields["metrics_enabled"].isChecked(),
                "flush_interval_seconds": self._fields["metrics_interval"].value(),
            },
            "app": {"minimize_to_tray": True, "single_instance": True, "save_window_state": True},
            "replay": {"enabled": True, "decision_log_path": decision_log},
        }

        # Persist the source-topology answers from the upstream
        # SourcesQuestionnaire under a top-level ``sources`` key, so
        # the runtime RemoteAgentRegistry knows which agents to
        # instantiate. Skipped when no questionnaire ran (legacy /
        # test paths) — the runtime defaults to "Netgate enabled" in
        # that case for backward compatibility with pre-v0.22.20 configs.
        if self._sources is not None:
            config["sources"] = {
                "netgate": self._sources.netgate,
                "virus_sniff": self._sources.virus_sniff,
                "suricata_local": self._sources.suricata_local,
            }

        # Local-Suricata runtime configuration (Step 12 of
        # project_dual_suricata_sync.md). Written unconditionally —
        # the runtime ignores the section when ``sources.suricata_local``
        # is False, but persisting it keeps the operator's choices
        # ready for a later toggle of the source flag.
        if "suricata_interface" in self._fields:
            interface_text = self._fields["suricata_interface"].currentText()
            # Strip the " — <description>" suffix the picker added
            # for clarity; the runtime only needs the raw adapter
            # name.
            interface_name = interface_text.split(" — ", 1)[0].strip()
            window_value = self._fields["suricata_window_s"].value()
            subnets_raw = self._fields["suricata_local_subnets"].toPlainText()
            subnets_list = [
                line.strip()
                for line in subnets_raw.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            config["suricata_local"] = {
                "interface": interface_name if interface_name != "(no interface detected)" else "",
                "reconciliation_window_s": window_value,
                "local_subnets_cidr": subnets_list,
            }

        config_dir = data_dir / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "config.yaml"
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        for subdir in ("config/prompts", "data", "data/logs", "snapshots"):
            (data_dir / subdir).mkdir(parents=True, exist_ok=True)

        eve_file = data_dir / "data" / "eve.json"
        if not eve_file.exists():
            eve_file.touch()

        logger.info("Configuration saved to %s", config_path)

    def _generate_env(self) -> None:
        """Write .env file with all API keys from the registry.

        v0.10.0: iterates over every :class:`ApiKeySpec` in
        :data:`API_KEY_SPECS` and writes the value of the matching
        field when non-empty. Notifications (SMTP / Telegram) keep
        their opt-in checkbox behaviour so users don't get surprise
        credentials in their ``.env``.
        """
        env_path = self._data_dir / ".env"
        lines: list[str] = []

        for spec in API_KEY_SPECS:
            if spec.tier == "notification":
                # Notifications are gated by their page checkboxes.
                continue
            field = self._fields.get(spec.env_var)
            if field is None:
                continue
            value = field.text().strip()
            # Required keys are always written (even empty, so the
            # operator can correct them later). Optional keys are
            # skipped when empty.
            if spec.required or value:
                lines.append(f"{spec.env_var}={value}")

        if self._fields["email_enabled"].isChecked():
            lines.append(f"SMTP_USER={self._fields['smtp_user'].text()}")
            lines.append(f"SMTP_PASSWORD={self._fields['smtp_password'].text()}")

        if self._fields["telegram_enabled"].isChecked():
            lines.append(f"TELEGRAM_BOT_TOKEN={self._fields['telegram_token'].text()}")

        with open(env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        try:
            import subprocess  # nosec B404 — required to restrict .env ACL via icacls; hardcoded args

            from wardsoar.pc import win_paths

            subprocess.run(  # nosec B603 — absolute path, os.getlogin() is the current process owner
                [
                    win_paths.ICACLS,
                    str(env_path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{os.getlogin()}:F",
                ],
                check=False,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except OSError:
            logger.warning("Could not restrict .env file permissions")

        logger.info("Environment file saved to %s", env_path)
