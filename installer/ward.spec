# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for WardSOAR.

Builds a one-folder distribution with PySide6 GUI.
Run with: pyinstaller installer/ward.spec --noconfirm

After the 2026-04-24 monorepo refactor, the application lives under
``packages/wardsoar-pc/`` and shares ``packages/wardsoar-core/`` with
the planned Virus Sniff appliance. The spec targets the canonical
module path ``wardsoar.pc.main:main`` directly; the legacy shim
``src/main.py`` is no longer referenced.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None

PROJECT_ROOT = Path(SPECPATH).parent
CORE_SRC = PROJECT_ROOT / "packages" / "wardsoar-core" / "src"
PC_SRC = PROJECT_ROOT / "packages" / "wardsoar-pc" / "src"
PC_MAIN = PC_SRC / "wardsoar" / "pc" / "main.py"
PC_UI_ASSETS = PC_SRC / "wardsoar" / "pc" / "ui" / "assets"

# ``collect_all`` walks the package and returns every submodule, every
# bundled data file (reportlab ships TTF fonts + CSS/PDF templates in
# its package dir) and every binary. Listing the top-level module alone
# in ``hiddenimports`` gave PyInstaller only the compiled bytecode of
# the root ``__init__.py``; downstream imports like ``reportlab.lib.
# enums`` then failed at runtime. Extracted as a reusable helper so the
# same pattern applies to any future package with dynamic imports.
_rl_datas, _rl_binaries, _rl_hiddenimports = collect_all("reportlab")

a = Analysis(
    [str(PC_MAIN)],
    # pathex must include both package src roots so PyInstaller's
    # module resolver can import ``wardsoar.core.*`` and
    # ``wardsoar.pc.*`` during analysis. Without them the monorepo
    # editable installs would be invisible at build time.
    pathex=[
        str(PROJECT_ROOT),
        str(CORE_SRC),
        str(PC_SRC),
    ],
    binaries=list(_rl_binaries),
    datas=[
        *_rl_datas,
        # Claude API prompt files
        (str(PROJECT_ROOT / "config" / "prompts"), "config/prompts"),
        # Default config files
        (str(PROJECT_ROOT / "config" / "known_false_positives.yaml"), "config"),
        (str(PROJECT_ROOT / "config" / "network_baseline.yaml"), "config"),
        # Suspect ASN registry (Phase 4.5 — threat-actor-aware scoring)
        (str(PROJECT_ROOT / "config" / "suspect_asns.yaml"), "config"),
        # Known bad actors registry (Phase 4.6 — direct IOC scoring)
        (str(PROJECT_ROOT / "config" / "known_bad_actors.yaml"), "config"),
        # CDN / major-SaaS allowlist (Phase 7e — Hard Protect bypass)
        (str(PROJECT_ROOT / "config" / "cdn_allowlist.yaml"), "config"),
        # YARA rules directory (Phase 3)
        (str(PROJECT_ROOT / "config" / "yara_rules"), "config/yara_rules"),
        # UI assets (moved into wardsoar-pc during the monorepo refactor).
        # Inside the bundle we still expose them at ``src/ui/assets`` so
        # legacy shims reading asset paths with that prefix keep working.
        (str(PC_UI_ASSETS), "src/ui/assets"),
        # EVE streaming script
        (str(PROJECT_ROOT / "scripts" / "sync_eve.ps1"), "scripts"),
        # Sysmon installer script — fetched live in the UI when the
        # operator clicks "Install Sysmon" from the Netgate tab
        # bootstrap checklist banner.
        (str(PROJECT_ROOT / "scripts" / "install-sysmon.ps1"), "scripts"),
        # Operator-facing docs rendered in-app (Netgate bootstrap guide
        # opened from the Bootstrap checklist card). Shipping the file
        # under the bundle dir lets the "View full guide" button find
        # it in frozen installs; the dev run falls back to the repo
        # copy automatically.
        (str(PROJECT_ROOT / "docs" / "bootstrap-netgate.md"), "docs"),
    ],
    hiddenimports=[
        # Windows-specific modules (COM/WMI)
        "wmi",
        "win32api",
        "win32con",
        "win32evtlog",
        "win32security",
        "win32event",
        "win32service",
        "win32serviceutil",
        "pywintypes",
        "pythoncom",
        "win32timezone",
        # --------------------------------------------------------------
        # wardsoar-core (cross-platform) — same modules as before the
        # refactor but reachable through the new canonical paths.
        # --------------------------------------------------------------
        "wardsoar",
        "wardsoar.core",
        "wardsoar.core.config",
        "wardsoar.core.models",
        "wardsoar.core.logger",
        "wardsoar.core.watcher",
        "wardsoar.core.alert_queue",
        "wardsoar.core.filter",
        "wardsoar.core.deduplicator",
        "wardsoar.core.prescorer",
        "wardsoar.core.virustotal",
        "wardsoar.core.baseline",
        "wardsoar.core.analyzer",
        "wardsoar.core.decision_cache",
        "wardsoar.core.responder",
        "wardsoar.core.rollback",
        "wardsoar.core.rule_manager",
        "wardsoar.core.forensic_report",
        "wardsoar.core.notifier",
        "wardsoar.core.metrics",
        "wardsoar.core.change_manager",
        "wardsoar.core.replay",
        "wardsoar.core.trusted_temp",
        "wardsoar.core.prescorer_feedback",
        "wardsoar.core.vt_cache",
        "wardsoar.core.asn_enricher",
        "wardsoar.core.suspect_asns",
        "wardsoar.core.known_bad_actors",
        "wardsoar.core.cdn_allowlist",
        "wardsoar.core.netgate_audit",
        "wardsoar.core.netgate_tamper",
        "wardsoar.core.netgate_custom_rules",
        "wardsoar.core.netgate_apply",
        "wardsoar.core.alert_enrichment",
        "wardsoar.core.user_false_positives",
        "wardsoar.core.ip_enrichment",
        "wardsoar.core.api_keys_registry",
        "wardsoar.core.alerts_stats",
        "wardsoar.core.bootstrap_checklist",
        "wardsoar.core.history_rotator",
        "wardsoar.core.manual_reviews",
        "wardsoar.core.netgate_reset",
        "wardsoar.pc.single_instance",
        # intel clients
        "wardsoar.core.intel",
        "wardsoar.core.intel.abuseipdb",
        "wardsoar.core.intel.alienvault_otx",
        "wardsoar.core.intel.base",
        "wardsoar.core.intel.blocklist_de",
        "wardsoar.core.intel.censys_client",
        "wardsoar.core.intel.feodo_tracker",
        "wardsoar.core.intel.firehol",
        "wardsoar.core.intel.greynoise",
        "wardsoar.core.intel.honeypot",
        "wardsoar.core.intel.http_client_base",
        "wardsoar.core.intel.ipinfo_pro",
        "wardsoar.core.intel.manager",
        "wardsoar.core.intel.securitytrails",
        "wardsoar.core.intel.shodan_client",
        "wardsoar.core.intel.spamhaus_drop",
        "wardsoar.core.intel.threatfox",
        "wardsoar.core.intel.urlhaus",
        "wardsoar.core.intel.virustotal_client",
        "wardsoar.core.intel.xforce",
        # remote agents (pfSense over SSH, future Virus Sniff agent)
        "wardsoar.core.remote_agents",
        "wardsoar.core.remote_agents.pfsense_ssh",
        "wardsoar.core.remote_agents.pfsense_aliastable",
        "wardsoar.core.remote_agents.pfsense_alias_migrate",
        "wardsoar.core.remote_agents.pfsense_suricata_tune",
        # --------------------------------------------------------------
        # wardsoar-pc (Windows-only desktop stack)
        # --------------------------------------------------------------
        "wardsoar.pc",
        "wardsoar.pc.main",
        "wardsoar.pc.collector",
        "wardsoar.pc.forensics",
        "wardsoar.pc.healthcheck",
        "wardsoar.pc.process_risk",
        "wardsoar.pc.process_risk_cache",
        "wardsoar.pc.process_snapshot_buffer",
        "wardsoar.pc.svchost_resolver",
        "wardsoar.pc.sysmon_events",
        "wardsoar.pc.sysmon_installer",
        "wardsoar.pc.sysmon_probe",
        "wardsoar.pc.win_paths",
        # Phase 3 — local AV cascade
        "wardsoar.pc.local_av",
        "wardsoar.pc.local_av.defender",
        "wardsoar.pc.local_av.orchestrator",
        "wardsoar.pc.local_av.yara_scanner",
        # Phases 5 + 6 — forensic acquisition and deep analysis
        "wardsoar.pc.forensic",
        "wardsoar.pc.forensic.acquisition",
        "wardsoar.pc.forensic.attack_mapper",
        "wardsoar.pc.forensic.deep_orchestrator",
        "wardsoar.pc.forensic.encryption",
        "wardsoar.pc.forensic.export",
        "wardsoar.pc.forensic.ioc_extractor",
        "wardsoar.pc.forensic.manifest",
        "wardsoar.pc.forensic.memory",
        "wardsoar.pc.forensic.orchestrator",
        "wardsoar.pc.forensic.report_pdf",
        "wardsoar.pc.forensic.storage",
        "wardsoar.pc.forensic.timeline",
        # UI (PySide6 + qfluentwidgets)
        "wardsoar.pc.ui",
        "wardsoar.pc.ui.agent_stream_consumer",
        "wardsoar.pc.ui.app",
        "wardsoar.pc.ui.engine_bridge",
        "wardsoar.pc.ui.setup_wizard",
        "wardsoar.pc.ui.views",
        "wardsoar.pc.ui.views.about_dialog",
        "wardsoar.pc.ui.views.activity_view",
        "wardsoar.pc.ui.views.alert_detail",
        "wardsoar.pc.ui.views.alerts",
        "wardsoar.pc.ui.views.config_view",
        "wardsoar.pc.ui.views.dashboard",
        "wardsoar.pc.ui.views.keys_view",
        "wardsoar.pc.ui.views.netgate",
        "wardsoar.pc.ui.views.replay_view",
        # --------------------------------------------------------------
        # Third-party with dynamic imports
        # --------------------------------------------------------------
        "anthropic",
        "asyncssh",
        "httpx",
        "httpx._transports",
        "httpx._transports.default",
        "vt",
        "yara",
        # reportlab submodules are collected exhaustively via
        # ``collect_all("reportlab")`` above — that handles the dynamic
        # imports inside platypus / pdfgen that previously crashed the
        # frozen app with ``ModuleNotFoundError: reportlab``.
        *_rl_hiddenimports,
        # pywin32 for DPAPI encryption
        "win32crypt",
        # PyQt-Fluent-Widgets (Windows 11 Fluent Design)
        "qfluentwidgets",
        "qfluentwidgets.common",
        "qfluentwidgets.components",
        "qfluentwidgets.window",
        "qfluentwidgets._rc",
        "qframelesswindow",
        "colorthief",
        "scipy.ndimage",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Unused standard library
        "tkinter",
        "unittest",
        "test",
        # Unused PySide6 modules (saves ~150 MB)
        "PySide6.QtWebEngine",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebChannel",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.Qt3DInput",
        "PySide6.Qt3DLogic",
        "PySide6.Qt3DAnimation",
        "PySide6.Qt3DExtras",
        "PySide6.QtQuick",
        "PySide6.QtQuickWidgets",
        "PySide6.QtQml",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtDesigner",
        "PySide6.QtHelp",
        "PySide6.QtBluetooth",
        "PySide6.QtNfc",
        "PySide6.QtPositioning",
        "PySide6.QtSensors",
        "PySide6.QtSerialPort",
        "PySide6.QtRemoteObjects",
        # Unused large libraries. NOTE: PIL stays in because reportlab
        # pulls it in transitively via reportlab.lib.utils.
        "matplotlib",
        "pandas",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WardSOAR",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT_ROOT / "installer" / "assets" / "ward.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="WardSOAR",
)
