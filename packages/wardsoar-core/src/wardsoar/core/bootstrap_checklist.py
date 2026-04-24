"""Netgate bootstrap checklist — progress tracking for the 11-step setup.

Walking a fresh or factory-reset Netgate 4200 through a working
WardSOAR deployment takes ten to fifteen minutes and involves four
irreducible clicks in the pfSense webGUI (package install, Suricata
interface attach, EVE JSON activation, Pass/Suppress lists) plus
several actions on the WardSOAR side (Audit, Apply, Deploy custom
rules, Establish baseline).

The checklist in this module is the source of truth for both the
operator-facing UI card (in the Netgate tab) and the detailed guide
(``docs/bootstrap-netgate.md``). The :class:`BootstrapChecklistState`
persists the operator's progress under
``%APPDATA%\\WardSOAR\\bootstrap_checklist.json`` so stepping away
from the machine — or rebooting WardSOAR mid-setup — never loses the
trail.

The steps themselves are frozen dataclasses; their ``id`` values are
the persistence keys and must never change without a migration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

logger = logging.getLogger("ward_soar.bootstrap_checklist")


# Step categories — shown as an icon in the UI. "pfsense_ui" means
# "open the pfSense webGUI and click"; "wardsoar" means "trigger the
# action via another card in the Netgate tab and come back to tick
# this box"; "windows" means "run something on the Windows host that
# is not part of WardSOAR itself" (e.g. install Sysmon).
KIND_PFSENSE_UI = "pfsense_ui"
KIND_WARDSOAR = "wardsoar"
KIND_WINDOWS = "windows"


@dataclass(frozen=True)
class ChecklistStep:
    """One row in the bootstrap checklist.

    Attributes:
        id: Stable identifier used as the persistence key. Never
            rename — the value is written to disk and a rename would
            silently reset the operator's progress.
        number: 1-based display number (matches the markdown guide).
        title: Short one-line label shown next to the checkbox.
        kind: Either :data:`KIND_PFSENSE_UI` or :data:`KIND_WARDSOAR`.
        description: Tooltip detail. For pfSense steps this is the
            exact menu path so the operator doesn't hunt around.
    """

    id: str
    number: int
    title: str
    kind: str
    description: str


#: The 11 bootstrap steps, in display order. This tuple is imported by
#: the UI card and by the tests — it is the single source of truth.
#: Adding a new step:
#:   * Append to the tuple so existing ``id`` offsets stay stable.
#:   * Bump the ``number`` field contiguously.
#:   * Update ``docs/bootstrap-netgate.md`` in the same change.
BOOTSTRAP_STEPS: tuple[ChecklistStep, ...] = (
    ChecklistStep(
        id="sysmon_install",
        number=1,
        title="Install Sysmon with network logging (PC)",
        kind=KIND_WINDOWS,
        description=(
            "Install Microsoft Sysinternals Sysmon on this PC so WardSOAR can "
            "correlate every Suricata alert to the Windows process that generated "
            "the flow (Event ID 3: NetworkConnect). Without Sysmon, process "
            "attribution only works while the socket is still open (UDP bursts, "
            "closed TCP flows are lost). Steps:\n"
            "  1. Download Sysmon from learn.microsoft.com/sysinternals/downloads/sysmon\n"
            "  2. Download the config from github.com/SwiftOnSecurity/sysmon-config "
            "(sysmonconfig-export.xml)\n"
            "  3. Open an elevated PowerShell and run: "
            "Sysmon64.exe -accepteula -i sysmonconfig-export.xml"
        ),
    ),
    ChecklistStep(
        id="netgate_wizard",
        number=2,
        title="Finish the Netgate wizard (firmware, Plus license, LAN/WAN)",
        kind=KIND_PFSENSE_UI,
        description=(
            "Boot the appliance, connect to its default LAN IP, run the factory "
            "wizard. Upgrade to the latest firmware when prompted; sign in with "
            "your Netgate account to activate the pfSense Plus license."
        ),
    ),
    ChecklistStep(
        id="ssh_enable",
        number=3,
        title="Enable SSH and install ward_key.pub",
        kind=KIND_PFSENSE_UI,
        description=(
            "System → Advanced → Admin Access → Secure Shell. Tick « Enable Secure "
            "Shell », set Authentication Method to « Public Key Only », paste the "
            "content of ward_key.pub into admin's Authorized Keys, Save."
        ),
    ),
    ChecklistStep(
        id="pkg_suricata",
        number=4,
        title="Install the Suricata package",
        kind=KIND_PFSENSE_UI,
        description=(
            "System → Package Manager → Available Packages → search « suricata » "
            "→ Install. Wait for the install to finish (~2 minutes on a 4200)."
        ),
    ),
    ChecklistStep(
        id="attach_interface",
        number=5,
        title="Attach Suricata to the PORT2LAN interface",
        kind=KIND_PFSENSE_UI,
        description=(
            "Services → Suricata → Interfaces → Add. Select « PORT2LAN » (igc2), "
            "enable « Send Alerts to System Log », tick the ET Open, Snort GPLv2 "
            "Community, Feodo Tracker C2 and Abuse.ch SSL rule categories, Save."
        ),
    ),
    ChecklistStep(
        id="eve_json",
        number=6,
        title="Enable EVE JSON output",
        kind=KIND_PFSENSE_UI,
        description=(
            "Services → Suricata → PORT2LAN (edit) → Logs Mgmt → enable EVE JSON "
            "Log. Tick Alerts, HTTP, DNS, TLS, DHCP, SMTP, SSH, Files, Flow, Drop. "
            "Enable TLS logging and PCAP on alerts only. Save + Restart Suricata."
        ),
    ),
    ChecklistStep(
        id="pass_suppress",
        number=7,
        title="Create WardSOAR_LAN_protect and WardSOAR_noise_filter lists",
        kind=KIND_PFSENSE_UI,
        description=(
            "Services → Suricata → Pass Lists → add « WardSOAR_LAN_protect » "
            "covering your LAN / gateway / DNS / VPN subnets. Suppress Lists → "
            "add « WardSOAR_noise_filter » with SID 2031071, 2013504, 2062715. "
            "Bind both to PORT2LAN in Interface Settings."
        ),
    ),
    ChecklistStep(
        id="audit",
        number=8,
        title="Run the WardSOAR Audit",
        kind=KIND_WARDSOAR,
        description=(
            "Click « Run Check » in the Netgate audit card below. Lists anything "
            "Suricata / pf / blocklist-related that still needs attention."
        ),
    ),
    ChecklistStep(
        id="apply_fixes",
        number=9,
        title="Apply the 5 SSH-only fixes (rules, process, blocklist, urltable, workers)",
        kind=KIND_WARDSOAR,
        description=(
            "In the audit results, tick the critical findings and click « Apply "
            "selected ». The 5 registered handlers back up config.xml, apply, and "
            "verify each fix."
        ),
    ),
    ChecklistStep(
        id="deploy_rules",
        number=10,
        title="Deploy wardsoar_custom.rules",
        kind=KIND_WARDSOAR,
        description=(
            "Custom rules card → « Deploy to Netgate ». Writes the Ben-model + "
            "known bad actors rules to /usr/local/etc/suricata/rules/ via SSH."
        ),
    ),
    ChecklistStep(
        id="activate_custom_rules",
        number=11,
        title="Activate wardsoar_custom.rules in pfSense Categories",
        kind=KIND_PFSENSE_UI,
        description=(
            "Services → Suricata → PORT2LAN → Categories → Custom rules files → "
            "tick « wardsoar_custom.rules » → Save → Restart Suricata."
        ),
    ),
    ChecklistStep(
        id="establish_baseline",
        number=12,
        title="Establish the tamper baseline",
        kind=KIND_WARDSOAR,
        description=(
            "Integrity card → « Establish baseline ». Snapshots the legitimate "
            "Netgate state so any future drift is detected."
        ),
    ),
)


class BootstrapChecklistState:
    """Persistent map of ``step_id -> bool`` tracking operator progress.

    Thread-safe. The JSON file sits next to every other WardSOAR state
    file (block_tracker, trusted_temp, netgate_baseline) under the
    data directory.

    Args:
        persist_path: Full path to the JSON file. Callers resolve this
            via :func:`default_persist_path` so every entry point
            agrees on the filename.
    """

    def __init__(self, persist_path: Path) -> None:
        self._path = persist_path
        self._state: dict[str, bool] = {}
        self._lock = Lock()
        self._load()

    def _load(self) -> None:
        """Read the persisted state from disk. Silent on missing/corrupt file."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._state = {str(k): bool(v) for k, v in raw.items()}
                logger.debug(
                    "bootstrap_checklist: loaded %d entries from %s",
                    len(self._state),
                    self._path,
                )
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning(
                "bootstrap_checklist: failed to load %s (%s) — starting fresh",
                self._path,
                exc,
            )

    def _save(self) -> None:
        """Flush to disk. Must be called under :attr:`_lock`."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._state, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("bootstrap_checklist: failed to save %s: %s", self._path, exc)

    def is_checked(self, step_id: str) -> bool:
        """Return ``True`` if ``step_id`` has been ticked by the operator."""
        with self._lock:
            return bool(self._state.get(step_id, False))

    def set_checked(self, step_id: str, checked: bool) -> None:
        """Record the new checkbox state and persist immediately."""
        with self._lock:
            self._state[step_id] = bool(checked)
            self._save()

    def snapshot(self) -> dict[str, bool]:
        """Return a shallow copy of the full state (step_id → bool)."""
        with self._lock:
            return dict(self._state)

    def reset_all(self) -> None:
        """Drop every tick and delete the backing file.

        Useful when reusing a WardSOAR install for a new Netgate, or
        after a factory reset where the bootstrap starts from scratch.
        """
        with self._lock:
            self._state = {}
            try:
                self._path.unlink(missing_ok=True)
            except OSError as exc:  # pragma: no cover — filesystem oddities
                logger.warning(
                    "bootstrap_checklist: failed to delete %s: %s",
                    self._path,
                    exc,
                )

    def progress(self) -> tuple[int, int]:
        """Return ``(checked, total)`` computed against :data:`BOOTSTRAP_STEPS`.

        Unknown ids in the state file (left over from a renamed step,
        for instance) do not count toward the tally.
        """
        total = len(BOOTSTRAP_STEPS)
        with self._lock:
            checked = sum(1 for step in BOOTSTRAP_STEPS if self._state.get(step.id, False))
        return checked, total


def default_persist_path(data_dir: Path) -> Path:
    """Return the conventional JSON location under ``data_dir``."""
    return data_dir / "bootstrap_checklist.json"


def step_by_id(step_id: str) -> ChecklistStep | None:
    """Return the matching :class:`ChecklistStep`, or ``None`` if absent.

    Linear scan — the tuple has 11 entries, nothing to optimise.
    """
    for step in BOOTSTRAP_STEPS:
        if step.id == step_id:
            return step
    return None
