# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for WardSOAR.

Builds a one-folder distribution with PySide6 GUI.
Run with: pyinstaller installer/ward.spec --noconfirm
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None

PROJECT_ROOT = Path(SPECPATH).parent

# ``collect_all`` walks the package and returns every submodule, every
# bundled data file (reportlab ships TTF fonts + CSS/PDF templates in
# its package dir) and every binary. Listing the top-level module alone
# in ``hiddenimports`` gave PyInstaller only the compiled bytecode of
# the root ``__init__.py``; downstream imports like ``reportlab.lib.
# enums`` then failed at runtime. Extracted as a reusable helper so the
# same pattern applies to any future package with dynamic imports.
_rl_datas, _rl_binaries, _rl_hiddenimports = collect_all("reportlab")

a = Analysis(
    [str(PROJECT_ROOT / "src" / "main.py")],
    pathex=[str(PROJECT_ROOT)],
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
        # UI assets
        (str(PROJECT_ROOT / "src" / "ui" / "assets"), "src/ui/assets"),
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
        # src modules (ensure all are included)
        "src",
        "src.config",
        "src.models",
        "src.logger",
        "src.main",
        "src.watcher",
        "src.alert_queue",
        "src.filter",
        "src.deduplicator",
        "src.prescorer",
        "src.collector",
        "src.forensics",
        "src.virustotal",
        "src.baseline",
        "src.analyzer",
        "src.decision_cache",
        "src.responder",
        "src.rollback",
        "src.rule_manager",
        "src.forensic_report",
        "src.notifier",
        "src.metrics",
        "src.healthcheck",
        "src.change_manager",
        "src.replay",
        "src.trusted_temp",
        "src.prescorer_feedback",
        "src.vt_cache",
        "src.win_paths",
        "src.asn_enricher",
        "src.suspect_asns",
        "src.known_bad_actors",
        "src.cdn_allowlist",
        "src.netgate_audit",
        "src.netgate_tamper",
        "src.netgate_custom_rules",
        "src.netgate_apply",
        # Phase 7h — persistent url-table blocklist
        "src.pfsense_aliastable",
        "src.pfsense_alias_migrate",
        # Phase 7b.2 — Suricata runmode tuning via config.xml
        "src.pfsense_suricata_tune",
        # Phase 7j (v0.9.0) — full-page alert detail + user FP overlay
        "src.alert_enrichment",
        "src.user_false_positives",
        "src.ui.views.alert_detail",
        # Phase 3 — local AV cascade
        "src.local_av",
        "src.local_av.defender",
        "src.local_av.yara_scanner",
        "src.local_av.orchestrator",
        # Phases 5 + 6 — forensic acquisition and deep analysis
        "src.forensic",
        "src.forensic.acquisition",
        "src.forensic.attack_mapper",
        "src.forensic.deep_orchestrator",
        "src.forensic.encryption",
        "src.forensic.export",
        "src.forensic.ioc_extractor",
        "src.forensic.manifest",
        "src.forensic.memory",
        "src.forensic.orchestrator",
        "src.forensic.report_pdf",
        "src.forensic.storage",
        "src.forensic.timeline",
        "src.ui",
        "src.ui.app",
        "src.ui.engine_bridge",
        "src.ui.views",
        "src.ui.views.dashboard",
        "src.ui.views.alerts",
        "src.ui.views.activity_view",
        "src.ui.views.config_view",
        "src.ui.views.keys_view",
        "src.ui.views.replay_view",
        "src.ui.views.netgate",
        "src.ssh_streamer",
        # Third-party with dynamic imports
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
