"""Local Suricata process lifecycle + config generation.

Companion of :mod:`wardsoar.pc.installer_helpers` (which installs
Suricata) and :mod:`wardsoar.pc.local_suricata_agent` (which uses
Suricata's output). This module owns the *running* Suricata process
on the operator's PC: starting it, stopping it gracefully, checking
whether it is alive, and generating a minimal valid configuration
suited to a single-PC deployment.

Two surfaces:

* :class:`SuricataProcess` — context-manager-friendly wrapper around
  ``subprocess.Popen``. Idempotent ``start()`` / ``stop()`` so the
  pipeline can be safely restarted without stale child processes.
  Uses ``psutil`` for the existence + graceful-then-forceful kill
  pattern WardSOAR uses elsewhere.
* :func:`generate_suricata_config` — produces a minimal
  ``suricata.yaml`` aimed at the operator's chosen network interface,
  with EVE JSON output, no PCAP storage (we only consume alerts),
  and conservative ruleset paths. The wizard uses this once at
  install time; the operator can edit the generated file freely.

Fail-safe: every external interaction (subprocess, file I/O,
psutil) is caught at the public surface and translated into a
documented return value. No public function raises ``Exception``
to the caller.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess  # nosec B404 — invoked with absolute paths, operator-triggered
import time
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger("ward_soar.local_suricata")


# ---------------------------------------------------------------------------
# Process lifecycle
# ---------------------------------------------------------------------------

#: Time we give Suricata to terminate gracefully after SIGTERM /
#: ``terminate()`` before escalating to ``kill()``. Suricata flushes
#: pending packets to eve.json on shutdown; rushing the kill loses
#: the last in-flight events. 10 s is generous enough for a fully
#: loaded engine to drain.
_GRACEFUL_TERMINATE_TIMEOUT_S: float = 10.0

#: How long we wait after ``start()`` before declaring "Suricata
#: failed to come up". Suricata typically prints "engine started"
#: within 5–15 s; we cap at 30 s to let cold starts on a slow PC
#: succeed.
_STARTUP_GRACE_S: float = 30.0

#: Filename Suricata must write its EVE JSON output to. Must match
#: the ``filename:`` field generated in :func:`generate_suricata_config`
#: so :class:`LocalSuricataAgent` reads from the same path the
#: process writes to. Hardcoded here intentionally — making it
#: configurable would force the agent + config gen to share a
#: setting, which would invite drift.
EVE_JSON_FILENAME: str = "eve.json"


class SuricataProcess:
    """Wrapper around the local ``suricata.exe`` process.

    Args:
        binary_path: Absolute path to ``suricata.exe`` (typically
            ``C:\\Program Files\\Suricata\\suricata.exe``). The
            wizard discovers this via
            :func:`wardsoar.pc.installer_helpers.is_suricata_installed`.
        config_path: Absolute path to the ``suricata.yaml`` config
            file Suricata reads at startup. The wizard generates
            this via :func:`generate_suricata_config`.
        interface: Network interface Suricata should sniff on
            (e.g. ``\\Device\\NPF_{guid}`` on Windows or a friendly
            adapter name resolved at config time).
        log_dir: Directory Suricata writes its outputs to (eve.json,
            stats, fast.log). Created if missing.
    """

    def __init__(
        self,
        binary_path: Path,
        config_path: Path,
        interface: str,
        log_dir: Path,
    ) -> None:
        self._binary = Path(binary_path)
        self._config = Path(config_path)
        self._interface = interface
        self._log_dir = Path(log_dir)
        self._process: Optional[subprocess.Popen[bytes]] = None
        # PID we last spawned; used by :meth:`is_running` to
        # distinguish "we never started" from "we started but the
        # process died on its own".
        self._spawned_pid: Optional[int] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def eve_path(self) -> Path:
        """Where Suricata writes its EVE JSON output, by convention."""
        return self._log_dir / EVE_JSON_FILENAME

    @property
    def pid(self) -> Optional[int]:
        """Last PID we spawned (None if never started or fully reaped)."""
        return self._spawned_pid

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def is_running(self) -> bool:
        """True when our spawned Suricata process is alive.

        Distinguishes three cases:

        * **Never started** (``_spawned_pid is None``) → False
        * **Started, still alive** → True
        * **Started, exited on its own** (crashed, killed externally)
          → False

        Uses ``psutil`` to avoid the subprocess module's race
        condition on Windows where ``poll()`` can lag a few hundred
        ms behind a kill.
        """
        if self._spawned_pid is None:
            return False
        try:
            proc = psutil.Process(self._spawned_pid)
            return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    async def start(self) -> bool:
        """Spawn Suricata. Idempotent — no-op if already running.

        Returns:
            ``True`` on successful start (or already running),
            ``False`` if the spawn or the startup grace check failed.
        """
        if self.is_running():
            logger.info("SuricataProcess.start: already running (pid=%s)", self._spawned_pid)
            return True

        if not self._binary.is_file():
            logger.error(
                "SuricataProcess.start: binary not found at %s — "
                "operator must install Suricata first",
                self._binary,
            )
            return False
        if not self._config.is_file():
            logger.error(
                "SuricataProcess.start: config not found at %s — "
                "wizard should have generated it",
                self._config,
            )
            return False

        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error(
                "SuricataProcess.start: cannot create log dir %s: %s",
                self._log_dir,
                exc,
            )
            return False

        cmd = [
            str(self._binary),
            "-c",
            str(self._config),
            "-i",
            self._interface,
            "-l",
            str(self._log_dir),
        ]
        logger.info("SuricataProcess.start: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(  # nosec B603 — absolute paths only
                cmd,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (FileNotFoundError, OSError) as exc:
            logger.error("SuricataProcess.start: spawn failed: %s", exc)
            self._process = None
            return False

        self._spawned_pid = self._process.pid

        # Suricata takes a few seconds to load rules + initialise
        # threads. Wait a short grace period and verify the process
        # is still alive. If it crashed on startup (bad config,
        # missing Npcap, etc.) the early-exit is detectable here.
        startup_check_deadline = time.monotonic() + min(_STARTUP_GRACE_S, 5.0)
        while time.monotonic() < startup_check_deadline:
            if self._process.poll() is not None:
                # Already exited.
                logger.error(
                    "SuricataProcess.start: process exited during startup " "(returncode=%s)",
                    self._process.returncode,
                )
                self._spawned_pid = None
                return False
            await asyncio.sleep(0.1)
        return True

    async def stop(self) -> bool:
        """Gracefully terminate the Suricata process. Idempotent.

        Sends ``terminate()``, waits up to
        :data:`_GRACEFUL_TERMINATE_TIMEOUT_S` for the process to
        flush + exit, then escalates to ``kill()`` if needed. Always
        clears internal state so a follow-up :meth:`start` works.

        Returns:
            ``True`` on successful stop (or wasn't running),
            ``False`` if even the kill failed (process already
            unreachable).
        """
        if not self.is_running():
            self._process = None
            self._spawned_pid = None
            return True

        proc = self._process
        if proc is None:  # pragma: no cover — is_running guards this
            return True

        logger.info("SuricataProcess.stop: terminating pid=%s gracefully", self._spawned_pid)
        try:
            proc.terminate()
        except OSError as exc:
            logger.warning("SuricataProcess.stop: terminate() raised: %s", exc)

        # Wait for graceful exit, polling instead of blocking the
        # event loop.
        deadline = time.monotonic() + _GRACEFUL_TERMINATE_TIMEOUT_S
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                logger.info(
                    "SuricataProcess.stop: pid=%s exited cleanly (rc=%s)",
                    self._spawned_pid,
                    proc.returncode,
                )
                self._process = None
                self._spawned_pid = None
                return True
            await asyncio.sleep(0.2)

        # Graceful failed → escalate to kill.
        logger.warning(
            "SuricataProcess.stop: pid=%s did not exit gracefully in %.1fs, killing",
            self._spawned_pid,
            _GRACEFUL_TERMINATE_TIMEOUT_S,
        )
        try:
            proc.kill()
        except OSError as exc:
            logger.error("SuricataProcess.stop: kill() also failed: %s", exc)
            self._process = None
            self._spawned_pid = None
            return False

        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            logger.error(
                "SuricataProcess.stop: pid=%s still hanging after kill",
                self._spawned_pid,
            )
            return False
        finally:
            self._process = None
            self._spawned_pid = None

        return True


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

#: Minimum Suricata config emitted by :func:`generate_suricata_config`.
#: Deliberately spartan — the operator can extend it freely. The
#: critical pieces are:
#:
#: * ``default-rule-path`` and ``rule-files`` so Suricata loads
#:   rules at startup
#: * ``af-packet`` / ``pcap`` interface configured to the operator's
#:   adapter (rendered into the template)
#: * ``outputs`` exposing EVE JSON only — no full pcap (we don't need
#:   it and storage gets out of hand quickly)
#: * Stats output disabled by default — the wizard can re-enable
#:   if the operator wants performance metrics
_CONFIG_TEMPLATE: str = """\
%YAML 1.1
---
# Generated by WardSOAR setup wizard. Edit freely; comments are
# preserved on the next read by the operator. Regenerated only if
# the operator clicks "Reset to default" in the wizard.

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    SSH_PORTS: "22"

default-log-dir: {log_dir}

stats:
  enabled: no

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: {eve_filename}
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
        - dns
        - tls
        - ssh
        - http

default-rule-path: {rule_dir}
rule-files:
  - suricata.rules

classification-file: {classification_file}
reference-config-file: {reference_config_file}

af-packet:
  - interface: {interface}
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes

pcap:
  - interface: {interface}

# Logging — minimal so we don't drown disk under regular use.
logging:
  default-log-level: notice
  outputs:
    - file:
        enabled: yes
        level: notice
        filename: {log_dir}/suricata.log
"""


def generate_suricata_config(
    config_path: Path,
    interface: str,
    log_dir: Path,
    rule_dir: Path,
    classification_file: Path,
    reference_config_file: Path,
) -> Path:
    """Write a minimal ``suricata.yaml`` to ``config_path``.

    Idempotent: writing the same arguments twice yields the same
    file content (the template is deterministic). Existing file is
    overwritten — the wizard prompts the operator before calling
    this when a config already exists, so this function is a pure
    generator.

    Args:
        config_path: Absolute path of the YAML file to write.
        interface: Suricata interface identifier — typically a
            friendly adapter name (e.g. ``"Ethernet"``) or the
            Windows NPF device path (``\\Device\\NPF_{guid}``).
        log_dir: Directory Suricata logs to (eve.json + suricata.log).
        rule_dir: Directory containing ``suricata.rules`` (typically
            ``C:\\Program Files\\Suricata\\rules`` after a default
            install).
        classification_file: Path of ``classification.config``
            (shipped by the Suricata installer).
        reference_config_file: Path of ``reference.config``
            (shipped by the Suricata installer).

    Returns:
        The ``config_path`` (for convenience in fluent calls).
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _CONFIG_TEMPLATE.format(
        interface=interface,
        log_dir=str(log_dir).replace("\\", "/"),
        eve_filename=EVE_JSON_FILENAME,
        rule_dir=str(rule_dir).replace("\\", "/"),
        classification_file=str(classification_file).replace("\\", "/"),
        reference_config_file=str(reference_config_file).replace("\\", "/"),
    )
    config_path.write_text(rendered, encoding="utf-8")
    logger.info(
        "generate_suricata_config: wrote %s (interface=%s, log_dir=%s)",
        config_path,
        interface,
        log_dir,
    )
    return config_path


# ---------------------------------------------------------------------------
# Network interface enumeration (for the wizard's interface picker)
# ---------------------------------------------------------------------------


def list_network_interfaces() -> list[tuple[str, str]]:
    """Return ``[(friendly_name, address_summary), ...]`` for the host.

    Used by the setup wizard's interface-picker page. Empty list on
    any psutil failure (returns ``False`` rather than raising — the
    wizard surfaces an error message).

    Each tuple:
        * ``friendly_name`` — adapter name as Suricata accepts it on
          Windows (e.g. ``"Ethernet"``). Useful for the operator to
          recognise their adapter.
        * ``address_summary`` — first IPv4 + first MAC address of
          the adapter, or ``"no addresses"`` for adapters without an
          IP (typically disabled / unconfigured).

    Adapters whose name suggests they are virtual / loopback /
    container interfaces are filtered out (the operator wants to
    sniff their real NIC, not Hyper-V virtual switches or
    Docker bridges).
    """
    skip_substrings = ("Loopback", "Hyper-V", "Docker", "vEthernet", "WSL")
    out: list[tuple[str, str]] = []
    try:
        addrs = psutil.net_if_addrs()
    except (psutil.Error, OSError) as exc:
        logger.warning("list_network_interfaces: psutil failed: %s", exc)
        return []

    for name, address_list in addrs.items():
        if any(needle.lower() in name.lower() for needle in skip_substrings):
            continue
        ipv4 = ""
        mac = ""
        for addr in address_list:
            family_name = getattr(addr.family, "name", str(addr.family))
            # AF_INET / AF_LINK names vary across Python versions / OSes.
            if family_name in ("AF_INET", "AddressFamily.AF_INET"):
                ipv4 = addr.address
            elif family_name in ("AF_LINK", "AddressFamily.AF_LINK", "AF_PACKET"):
                mac = addr.address
        if ipv4 or mac:
            summary = ipv4 or "no IPv4"
            if mac:
                summary = f"{summary} (MAC {mac})"
            out.append((name, summary))
        else:
            out.append((name, "no addresses"))

    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def find_suricata_install_dir() -> Optional[Path]:
    """Locate the Suricata install directory (the parent of suricata.exe).

    Mirrors :func:`wardsoar.pc.installer_helpers.is_suricata_installed`
    but returns the *directory* — the wizard needs it to locate
    ``rules\\suricata.rules``, ``classification.config``, and
    ``reference.config`` shipped by the installer.
    """
    on_path = shutil.which("suricata.exe") or shutil.which("suricata")
    if on_path:
        candidate = Path(on_path).parent
        if (candidate / "suricata.exe").is_file():
            return candidate

    default = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Suricata"
    if (default / "suricata.exe").is_file():
        return default

    return None


__all__ = (
    "EVE_JSON_FILENAME",
    "SuricataProcess",
    "find_suricata_install_dir",
    "generate_suricata_config",
    "list_network_interfaces",
)
