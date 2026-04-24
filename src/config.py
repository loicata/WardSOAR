"""Configuration loading and validation for WardSOAR."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


def get_app_dir() -> Path:
    """Return application root directory (read-only install location).

    Handles both normal execution (from source) and PyInstaller frozen mode.
    In frozen mode, this is the directory containing WardSOAR.exe — useful
    for launcher/shortcut logic but NOT for bundled data files, which live
    under ``_internal/`` (see :func:`get_bundle_dir`).

    Returns:
        Path to the application root directory.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def get_bundle_dir() -> Path:
    """Return the directory containing PyInstaller-bundled data files.

    PyInstaller's one-folder mode puts every datas entry (yara rules,
    config templates, UI assets…) under ``_internal/`` beside the EXE,
    exposing its location through ``sys._MEIPASS``. Use this function
    whenever you need to read a file that was added to ``ward.spec``'s
    ``datas=``: resolving against ``get_app_dir()`` skips the
    ``_internal/`` prefix and fails silently at runtime.

    In development (non-frozen) the bundle is the project root, so the
    same relative path works in both modes.

    Returns:
        Absolute path to the data-bundle root.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return get_app_dir()


def get_data_dir() -> Path:
    """Return writable data directory for config, logs, and snapshots.

    In frozen mode (installed exe), uses %APPDATA%/WardSOAR to avoid
    permission issues with Program Files. In development mode, uses the
    project root directory.

    Returns:
        Path to the writable data directory.
    """
    if getattr(sys, "frozen", False):
        import os

        appdata = os.environ.get("APPDATA", "")
        if appdata:
            data_dir = Path(appdata) / "WardSOAR"
            data_dir.mkdir(parents=True, exist_ok=True)
            return data_dir
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


# Default paths (resolved relative to writable data dir)
DEFAULT_CONFIG_PATH = get_data_dir() / "config" / "config.yaml"
DEFAULT_WHITELIST_PATH = get_data_dir() / "config" / "whitelist.yaml"


class AppConfig(BaseModel):
    """Application configuration loaded from config.yaml."""

    # Loaded at runtime from YAML — typed sub-models will be added per phase
    network: dict[str, Any] = Field(default_factory=dict)
    watcher: dict[str, Any] = Field(default_factory=dict)
    filter: dict[str, Any] = Field(default_factory=dict)
    deduplicator: dict[str, Any] = Field(default_factory=dict)
    prescorer: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)
    decision_cache: dict[str, Any] = Field(default_factory=dict)
    forensics: dict[str, Any] = Field(default_factory=dict)
    forensic: dict[str, Any] = Field(default_factory=dict)
    virustotal: dict[str, Any] = Field(default_factory=dict)
    local_av: dict[str, Any] = Field(default_factory=dict)
    analyzer: dict[str, Any] = Field(default_factory=dict)
    responder: dict[str, Any] = Field(default_factory=dict)
    logging: dict[str, Any] = Field(default_factory=dict)
    reputation: dict[str, Any] = Field(default_factory=dict)
    alert_queue: dict[str, Any] = Field(default_factory=dict)
    rule_manager: dict[str, Any] = Field(default_factory=dict)
    forensic_report: dict[str, Any] = Field(default_factory=dict)
    prompts: dict[str, Any] = Field(default_factory=dict)
    notifier: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    healthcheck: dict[str, Any] = Field(default_factory=dict)
    change_manager: dict[str, Any] = Field(default_factory=dict)
    replay: dict[str, Any] = Field(default_factory=dict)
    app: dict[str, Any] = Field(default_factory=dict)


class WhitelistConfig(BaseModel):
    """Whitelist of IPs that must never be blocked."""

    ips: set[str] = Field(default_factory=set)
    subnets: list[str] = Field(default_factory=list)

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted (exact match or subnet membership)."""
        if ip in self.ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(
                addr in ipaddress.ip_network(subnet, strict=False) for subnet in self.subnets
            )
        except ValueError:
            return False


def _create_default_config(path: Path) -> None:
    """Create a default config.yaml and required directories on first launch.

    Args:
        path: Target path for config.yaml.
    """
    data_dir = get_data_dir()

    # Create required directories in writable location
    for subdir in ("config", "config/prompts", "data", "data/logs", "snapshots"):
        (data_dir / subdir).mkdir(parents=True, exist_ok=True)

    # Default eve path in writable data directory
    eve_path = str(data_dir / "data" / "eve.json").replace("\\", "\\\\")
    log_dir = str(data_dir / "data" / "logs").replace("\\", "\\\\")
    decision_log = str(data_dir / "data" / "logs" / "decisions.jsonl").replace("\\", "\\\\")

    default_config = {
        "network": {
            "pfsense_ip": "192.168.2.1",
            "pc_ip": "192.168.2.100",
            "lan_subnet": "192.168.2.0/24",
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
        },
        "watcher": {
            "mode": "file",
            "eve_json_path": eve_path,
            "poll_interval_seconds": 2,
            "min_severity": 3,
            "ssh": {
                "remote_eve_path": "/var/log/suricata/suricata_igc252678/eve.json",
            },
        },
        "filter": {
            "enabled": True,
            "config_file": "config/known_false_positives.yaml",
            "log_suppressed": True,
        },
        "deduplicator": {"enabled": True, "grouping_window_seconds": 60, "max_group_size": 50},
        "prescorer": {"enabled": True, "mode": "active", "min_score_for_analysis": 30},
        "analyzer": {
            "model": "claude-opus-4-7",
            "max_tokens": 4096,
            # Protect mode — min confidence on a CONFIRMED verdict to
            # trigger a block. Default 0.70 = moderate.
            "confidence_threshold": 0.7,
            # Hard Protect mode — min confidence on a BENIGN verdict to
            # SKIP a block. Any lower value in BENIGN, or any non-BENIGN
            # verdict, blocks. Default 0.99 = very restrictive (the
            # operator accepts FPs in exchange for near-zero FNs and
            # relies on the 1-click rollback to recover).
            "hard_protect_benign_threshold": 0.99,
        },
        "responder": {
            # New in v0.5.5 — replaces the legacy ``dry_run`` bool.
            # Valid values: "monitor" (no block ever), "protect"
            # (today's behaviour), "hard_protect" (deny-by-default).
            # Legacy configs with ``dry_run`` are migrated on load.
            "mode": "monitor",
            "block_duration_hours": 24,
            "max_blocks_per_hour": 20,
        },
        "logging": {"level": "INFO", "log_dir": log_dir, "decision_log": "decisions.jsonl"},
        "notifier": {"enabled": True, "rate_limit_per_minute": 10},
        "app": {"minimize_to_tray": True, "single_instance": True, "save_window_state": True},
        "replay": {"enabled": True, "decision_log_path": decision_log},
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

    # Create empty eve.json if not exists
    eve_file = data_dir / "data" / "eve.json"
    if not eve_file.exists():
        eve_file.touch()


def _migrate_config_if_needed(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    """Apply v0.4 → v0.5 migrations to a freshly-loaded config dict.

    v0.5 changed a handful of defaults that an operator coming from v0.4.x
    will otherwise miss because their existing config.yaml overrides the
    new defaults baked into the source code:

    - ``prescorer.mode`` should be ``active`` (was ``learning``).
    - ``prescorer.min_score_for_analysis`` should be ``30`` (was ``15``).
    - ``analyzer.model`` should be ``claude-opus-4-7`` (Sonnet retired).
    - ``confirmer:`` section is obsolete (module removed) — dropped.

    Migrations are applied in-memory AND persisted back to disk so the
    next boot shows a clean banner. Each applied migration is logged.

    Args:
        raw: Parsed YAML dict from disk.
        path: Source path, used when we write the migrated version back.

    Returns:
        The (possibly modified) dict.
    """
    import logging

    logger = logging.getLogger("ward_soar.config")
    migrations: list[str] = []

    prescorer = raw.setdefault("prescorer", {})
    if prescorer.get("mode") == "learning":
        prescorer["mode"] = "active"
        migrations.append("prescorer.mode: learning → active")
    if prescorer.get("min_score_for_analysis", 15) == 15:
        prescorer["min_score_for_analysis"] = 30
        migrations.append("prescorer.min_score_for_analysis: 15 → 30")

    analyzer = raw.setdefault("analyzer", {})
    model = str(analyzer.get("model", ""))
    if model.startswith("claude-sonnet-") or model == "claude-opus-4-20250514":
        analyzer["model"] = "claude-opus-4-7"
        migrations.append(f"analyzer.model: {model} → claude-opus-4-7")

    if "confirmer" in raw:
        del raw["confirmer"]
        migrations.append("confirmer: section removed (module deleted in v0.5)")

    # v0.5.4 → v0.5.5 — responder.dry_run replaced by responder.mode.
    # True → "monitor" (never block), False → "protect" (block on
    # CONFIRMED + confidence). "hard_protect" is opt-in, never set by
    # migration. We keep the dry_run key readable for one release so an
    # operator downgrading to 0.5.4 still has a coherent config.
    responder = raw.setdefault("responder", {})
    if "mode" not in responder:
        legacy_dry_run = responder.get("dry_run")
        if legacy_dry_run is True:
            responder["mode"] = "monitor"
            migrations.append("responder.dry_run=True → responder.mode=monitor")
        elif legacy_dry_run is False:
            responder["mode"] = "protect"
            migrations.append("responder.dry_run=False → responder.mode=protect")

    # Seed the Hard Protect threshold if the operator upgraded without
    # seeing the new key. Default matches _create_default_config.
    analyzer_section = raw.setdefault("analyzer", {})
    if "hard_protect_benign_threshold" not in analyzer_section:
        analyzer_section["hard_protect_benign_threshold"] = 0.99
        migrations.append("analyzer.hard_protect_benign_threshold: added default 0.99")

    if migrations:
        logger.warning(
            "Config migration v0.4 → v0.5 applied at %s:\n  - %s",
            path,
            "\n  - ".join(migrations),
        )
        try:
            with open(path, "w", encoding="utf-8") as fh:
                yaml.dump(raw, fh, default_flow_style=False, sort_keys=False)
        except OSError as exc:
            logger.error("Config migration could not be persisted: %s", exc)

    return raw


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load application configuration from YAML file.

    Args:
        config_path: Path to config.yaml. Defaults to config/config.yaml.

    Returns:
        Validated AppConfig instance.

    Raises:
        FileNotFoundError: If config file does not exist.
        yaml.YAMLError: If config file is invalid YAML.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        # First launch — create default config and required directories
        _create_default_config(path)

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw = _migrate_config_if_needed(raw, path)

    return AppConfig(**raw)


def _create_default_whitelist(path: Path, network_cfg: Optional[dict[str, Any]] = None) -> None:
    """Seed ``whitelist.yaml`` on first launch if it is missing.

    Prior to v0.6.4 the whitelist file was silently left absent when
    the operator never opened it, which meant *every* mode (including
    Hard Protect) treated the operator's own machine as
    blockable. That bug took the box offline once and is the whole
    motivation for this helper. We now ALWAYS ship a populated
    whitelist on first launch, seeded from the network settings in
    ``config.yaml``: the host's own IP, the pfSense LAN gateway, the
    DNS resolvers, the LAN subnet, and the RFC 1918 ranges as a
    belt-and-braces layer. The Responder adds an unconditional
    refusal on top (see ``_is_rfc1918_or_local``), so even a wiped
    whitelist cannot turn the box into a self-blocking tool.

    Args:
        path: Target path for ``whitelist.yaml`` — typically
            :data:`DEFAULT_WHITELIST_PATH`.
        network_cfg: Optional ``network`` section from ``config.yaml``
            used to personalise the seed (``pc_ip``, ``pfsense_ip``,
            ``lan_subnet``, ``dns_servers``). When ``None`` we fall
            back to the defaults used by ``_create_default_config``.
    """
    if network_cfg is None:
        network_cfg = {}
    pc_ip = str(network_cfg.get("pc_ip") or "192.168.2.100")
    pfsense_ip = str(network_cfg.get("pfsense_ip") or "192.168.2.1")
    lan_subnet = str(network_cfg.get("lan_subnet") or "192.168.2.0/24")
    dns_servers = list(network_cfg.get("dns_servers") or ["1.1.1.1", "8.8.8.8"])

    # Deduplicate while preserving insertion order.
    seen: set[str] = set()
    ordered_ips: list[str] = []
    for candidate in [pc_ip, pfsense_ip, *dns_servers]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered_ips.append(candidate)

    seen_subnets: set[str] = set()
    ordered_subnets: list[str] = []
    for subnet in [lan_subnet, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        if subnet and subnet not in seen_subnets:
            seen_subnets.add(subnet)
            ordered_subnets.append(subnet)

    default_whitelist = {"ips": ordered_ips, "subnets": ordered_subnets}
    header = (
        "# WardSOAR whitelist -- IPs and subnets that MUST NEVER be blocked.\n"
        "#\n"
        "# Generated on first launch from the network settings in config.yaml.\n"
        "# Edit freely and restart WardSOAR to apply.\n"
        "#\n"
        "# Note: even an empty whitelist cannot cause WardSOAR to block\n"
        "# RFC 1918 / loopback / link-local traffic -- the Responder has a\n"
        "# hard-coded unconditional refusal for those. This file exists to\n"
        "# cover additional trusted IPs outside RFC 1918 (mobile hotspots,\n"
        "# VPN endpoints, friends' residential IPs, CDNs you rely on).\n"
        "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.dump(default_whitelist, f, default_flow_style=False, sort_keys=False)


def load_whitelist(whitelist_path: Optional[Path] = None) -> WhitelistConfig:
    """Load whitelist configuration from YAML file.

    If the file is missing, :func:`_create_default_whitelist` seeds
    it from the operator's ``config.yaml`` network section before
    returning the parsed result. This guarantees that an operator who
    never opens the Configuration tab still gets a safe whitelist on
    first boot.

    Args:
        whitelist_path: Path to whitelist.yaml. Defaults to config/whitelist.yaml.

    Returns:
        Validated WhitelistConfig instance.
    """
    path = whitelist_path or DEFAULT_WHITELIST_PATH
    if not path.exists():
        # Seed from the companion config.yaml if it exists; fall back
        # to the built-in defaults otherwise.
        network_cfg: Optional[dict[str, Any]] = None
        cfg_path = DEFAULT_CONFIG_PATH
        if cfg_path.exists():
            try:
                with open(cfg_path, "r", encoding="utf-8") as cfg_fh:
                    raw_cfg = yaml.safe_load(cfg_fh) or {}
                if isinstance(raw_cfg, dict):
                    network_cfg = raw_cfg.get("network")
            except (OSError, yaml.YAMLError):
                network_cfg = None
        _create_default_whitelist(path, network_cfg)

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    ips: set[str] = set()
    subnets: list[str] = []

    for section in ("infrastructure", "dns", "trusted"):
        for entry in raw.get(section, None) or []:
            if "ip" in entry:
                ips.add(entry["ip"])

    for entry in raw.get("subnets", None) or []:
        if "cidr" in entry:
            subnets.append(entry["cidr"])

    return WhitelistConfig(ips=ips, subnets=subnets)


def load_env() -> None:
    """Load environment variables from .env file.

    Searches in both the writable data directory (AppData in frozen mode)
    and the app directory (project root in dev mode). Data dir takes priority.
    """
    # Load from app dir first (dev mode fallback)
    load_dotenv(get_app_dir() / ".env", override=True)
    # Then from data dir (overrides — this is where the wizard/UI writes keys)
    data_env = get_data_dir() / ".env"
    if data_env.exists():
        load_dotenv(data_env, override=True)
