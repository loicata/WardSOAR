"""Local forensic analysis of the Windows PC.

Interrogates Sysmon logs, running processes, Windows Event Logs,
registry persistence keys, and recent file activity to correlate
with Suricata alerts.

Fail-safe: if any forensic check fails, return empty results
for that check and continue. Never crash the pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess  # nosec B404 — required for Sysmon/Event Log queries via PowerShell; args are hardcoded
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404 — exception class import, not an execution risk
from typing import Any, Optional

import psutil
from psutil import AccessDenied, NoSuchProcess, ZombieProcess

from wardsoar.pc import win_paths
from wardsoar.core.models import ForensicResult, SuricataAlert, SysmonEvent

logger = logging.getLogger("ward_soar.forensics")

# Sysmon Event IDs of interest
SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11
SYSMON_REGISTRY_EVENT = 13
SYSMON_DNS_QUERY = 22
SYSMON_PROCESS_TAMPERING = 25

# Windows Security Event IDs of interest
WIN_LOGON_SUCCESS = 4624
WIN_LOGON_FAILED = 4625
WIN_PRIVILEGE_ESCALATION = 4672
WIN_PROCESS_CREATION = 4688

# Registry persistence locations to check
REGISTRY_PERSISTENCE_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
]

# Common file drop locations
SUSPICIOUS_DIRECTORIES = [
    "{TEMP}",
    "{USERPROFILE}\\Downloads",
    "{APPDATA}",
    "{LOCALAPPDATA}\\Temp",
]

# Extensions considered executable / suspect (case-insensitive match on Path.suffix)
SUSPICIOUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Windows binaries
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".pif",
        ".sys",
        # PowerShell
        ".ps1",
        ".psm1",
        ".psd1",
        # Batch / command
        ".bat",
        ".cmd",
        # Scripts
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        # Web / installers
        ".hta",
        ".msi",
        ".msp",
        ".mst",
        # Archives used for delivery
        ".jar",
        # Shortcuts — frequently weaponized
        ".lnk",
    }
)

# Path substrings that identify legitimate installed apps (case-insensitive).
# Files under these paths are skipped to reduce forensic noise and VT fuite.
APP_EXCLUSIONS: tuple[str, ...] = (
    # Browsers
    r"\google\chrome",
    r"\mozilla\firefox",
    r"\bravesoftware",
    r"\microsoft\edge",
    r"\opera software",
    r"\vivaldi",
    # Communication
    r"\discord",
    r"\slack",
    r"\microsoft\teams",
    r"\zoom",
    r"\spotify",
    r"\telegram desktop",
    r"\signal",
    r"\whatsapp",
    # Developer tools
    r"\microsoft vs code",
    r"\code\cache",
    r"\jetbrains",
    r"\npm-cache",
    r"\pip\cache",
    r"\yarn\cache",
    r"\.cache\pip",
    r"\.cache\yarn",
    r"\nuget\packagesource",
    # Gaming
    r"\steam",
    r"\epic games",
    r"\origin",
    r"\battle.net",
    # System utilities
    r"\microsoft\windows\wer",
    r"\microsoft\windows\inetcache",
    r"\microsoft\windows\explorer",
    r"\packages\microsoft",
    r"\microsoftedge\user data",
    # Common legit AppData cache dirs
    r"\cache\cache_data",
    r"\code cache",
)

# Size bounds for suspicious files (bytes)
DEFAULT_FILE_MIN_SIZE = 1024  # 1 KB — filter out empty/flag files
DEFAULT_FILE_MAX_SIZE = 33_554_432  # 32 MB — matches VirusTotal free tier limit

# Default freshness window (seconds before the alert timestamp).
# Files modified strictly outside [alert - freshness_before, alert + freshness_after]
# are considered unrelated and skipped.
DEFAULT_FRESHNESS_BEFORE_SECONDS = 300  # 5 min — typical drop-to-alert delay
DEFAULT_FRESHNESS_AFTER_SECONDS = 60  # 1 min — files written right after alert


# Explicit list of "on our LAN" ranges. ``ipaddress.IPv4Address.is_private``
# would also cover TEST-NET-1/2/3 (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), CGNAT and a handful of IANA reserved blocks. Those
# *are* rare on real traffic but they show up in Suricata fixtures, and
# treating them as "our LAN" flips the flow direction to the wrong
# side. Keep the list strict.
_LOCAL_V4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)
_LOCAL_V6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)


def _is_local_ip(ip: str) -> bool:
    """True when ``ip`` is on our LAN (RFC1918, loopback, link-local).

    Defensive on unparseable strings: returns False so the caller
    still gets a best-effort IP to feed into psutil rather than an
    exception. Scoped to the explicit networks above to exclude
    reserved ranges like TEST-NET that Python's ``is_private`` marks
    True but that we do not treat as "our own" traffic.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _LOCAL_V4_NETWORKS)
    return any(addr in net for net in _LOCAL_V6_NETWORKS)


def _select_external_ip(alert: SuricataAlert) -> str:
    """Pick the external end of an alert's flow for psutil correlation.

    Suricata's ``src_ip`` / ``dest_ip`` depend on which direction
    triggered the rule. For process attribution we need the IP of the
    remote peer as seen from the PC — :func:`psutil.net_connections`
    populates ``conn.raddr`` with that address, never with the local
    LAN IP.

    Rules:
        * ``src_ip`` is local and ``dest_ip`` is external (PC initiates
          the flow, e.g. STUN, TLS handshake, STREAM retrans) → return
          ``dest_ip``.
        * ``src_ip`` is external and ``dest_ip`` is local (attacker
          parle au PC) → return ``src_ip``.
        * Both local (LAN-to-LAN scan) or both external (unusual) →
          fall back to ``src_ip`` so behaviour matches the pre-fix
          code.
    """
    src_local = _is_local_ip(alert.src_ip)
    dst_local = _is_local_ip(alert.dest_ip)
    if src_local and not dst_local:
        return alert.dest_ip
    return alert.src_ip


@dataclass(frozen=True)
class FlowKey:
    """5-tuple describing a Suricata-observed flow from the PC's POV.

    Attributes:
        local_ip: The PC-side IP of the flow. Empty if both ends of
            the alert are outside the RFC1918 ranges (unusual).
        local_port: The PC-side port.
        remote_ip: The peer's IP.
        remote_port: The peer's port.
        proto: Upper-case protocol (TCP / UDP / ...). Used to refine
            the match against :attr:`psutil._common.sconn.type`.
        pc_is_initiator: True when the alert ``src`` side maps to the
            PC (outbound flow), False when the alert ``dest`` side
            maps to the PC (inbound flow). Used by the matcher to
            decide whether a listener-only entry counts as a hit.
    """

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    proto: str
    pc_is_initiator: bool


def build_flow_key(alert: SuricataAlert) -> FlowKey:
    """Convert a :class:`SuricataAlert` into a direction-aware 5-tuple.

    Mapping rules:
        * ``src`` of the alert is on our LAN → PC is the initiator;
          ``local_*`` takes ``src_*``, ``remote_*`` takes ``dest_*``.
        * ``dest`` of the alert is on our LAN → PC is the receiver;
          ``local_*`` takes ``dest_*``, ``remote_*`` takes ``src_*``.
        * Neither side is local → we still pick ``src`` as "local"
          with ``pc_is_initiator=False`` so downstream code keeps
          today's behaviour (fallback to a remote-IP search).

    The flow key is the single authoritative object the matching
    helpers consume; it isolates the direction-handling logic from
    the psutil plumbing.
    """
    src_local = _is_local_ip(alert.src_ip)
    dst_local = _is_local_ip(alert.dest_ip)

    if src_local and not dst_local:
        return FlowKey(
            local_ip=alert.src_ip,
            local_port=int(alert.src_port),
            remote_ip=alert.dest_ip,
            remote_port=int(alert.dest_port),
            proto=(alert.proto or "").upper(),
            pc_is_initiator=True,
        )
    if dst_local and not src_local:
        return FlowKey(
            local_ip=alert.dest_ip,
            local_port=int(alert.dest_port),
            remote_ip=alert.src_ip,
            remote_port=int(alert.src_port),
            proto=(alert.proto or "").upper(),
            pc_is_initiator=False,
        )
    # Both local (LAN→LAN) or both public — keep the pre-fix defaults
    # so no legacy test relying on ``src_ip`` gets broken.
    return FlowKey(
        local_ip=alert.src_ip,
        local_port=int(alert.src_port),
        remote_ip=alert.dest_ip,
        remote_port=int(alert.dest_port),
        proto=(alert.proto or "").upper(),
        pc_is_initiator=False,
    )


def _conn_matches_flow(
    conn: Any,
    flow: FlowKey,
) -> bool:
    """True when ``conn`` is the live socket for ``flow``.

    The match is strict on the 5-tuple when both ends of the socket
    are known (``ESTABLISHED``/``SYN_*``/``FIN_*``). For ``LISTEN``
    entries we match on the local port alone so an inbound alert
    attributes to the listener even after the accepted socket has
    closed. UDP sockets often report no ``raddr`` even during an
    active exchange; we treat them the same as listeners then.
    """
    laddr = getattr(conn, "laddr", None)
    raddr = getattr(conn, "raddr", None)

    if laddr is None or not hasattr(laddr, "port"):
        return False

    if int(laddr.port) != flow.local_port:
        return False

    # Inbound alert + no remote info on the socket → match the
    # listener (common on TCP LISTEN and connectionless UDP).
    if not raddr or not hasattr(raddr, "ip"):
        return not flow.pc_is_initiator

    return str(raddr.ip) == flow.remote_ip and int(raddr.port) == flow.remote_port


class ForensicAnalyzer:
    """Perform local forensic analysis on the Windows PC.

    Args:
        config: Forensics configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._correlation_window: int = config.get("correlation_window", 300)
        self._sysmon_channel: str = config.get(
            "sysmon_channel", "Microsoft-Windows-Sysmon/Operational"
        )

        # find_suspicious_files filters (drastically narrow the scope to keep VT
        # cost and forensic noise manageable). All overridable via config.yaml
        # section forensics.suspicious_files.
        sf_cfg: dict[str, Any] = config.get("suspicious_files", {})
        allowed_ext = sf_cfg.get("allowed_extensions")
        self._sf_extensions: frozenset[str] = (
            frozenset(ext.lower() for ext in allowed_ext) if allowed_ext else SUSPICIOUS_EXTENSIONS
        )
        extra_exclusions = sf_cfg.get("excluded_path_fragments", [])
        self._sf_exclusions: tuple[str, ...] = tuple(
            p.lower() for p in (*APP_EXCLUSIONS, *extra_exclusions)
        )
        self._sf_min_size: int = int(sf_cfg.get("min_size_bytes", DEFAULT_FILE_MIN_SIZE))
        self._sf_max_size: int = int(sf_cfg.get("max_size_bytes", DEFAULT_FILE_MAX_SIZE))
        self._sf_freshness_before: int = int(
            sf_cfg.get("freshness_before_seconds", DEFAULT_FRESHNESS_BEFORE_SECONDS)
        )
        self._sf_freshness_after: int = int(
            sf_cfg.get("freshness_after_seconds", DEFAULT_FRESHNESS_AFTER_SECONDS)
        )

    async def analyze(self, alert: SuricataAlert) -> ForensicResult:
        """Run full forensic analysis correlated with a Suricata alert.

        Each check is wrapped in its own error handler. If one check
        fails, the others still run.

        Args:
            alert: The triggering Suricata alert.

        Returns:
            ForensicResult with all findings.
        """
        # Correlate against the *external* side of the flow using a
        # direction-aware 5-tuple match (see :func:`build_flow_key`).
        # The 5-tuple eliminates the "same remote IP with several
        # concurrent flows" ambiguity of the old raddr-only match, and
        # naturally handles both directions (PC initiator / PC
        # receiver) via :attr:`FlowKey.pc_is_initiator`. When the
        # 5-tuple yields no hit we fall back on the legacy remote-IP
        # lookup so an alert on a flow whose local port has already
        # been recycled still attributes to something.
        flow = build_flow_key(alert)
        suspect_processes = await self._safe_call(self.get_processes_by_flow, flow)

        # Level 3: Sysmon Event 3 — only when layers 1 + 2 came up
        # empty. Sysmon persists NetworkConnect events long after the
        # socket is gone, so this layer catches the short-lived flows
        # the live / buffered lookups necessarily miss. Adds ~200 ms
        # per alert in the worst case so we gate on the empty result
        # rather than running it unconditionally.
        if not suspect_processes:
            sysmon_pids = await self._sysmon_flow_pids(flow, alert.timestamp)
            if sysmon_pids:
                suspect_processes = self._describe_pids(sysmon_pids)

        # Final fallback: legacy remote-IP-only search. Catches the
        # edge case where the 5-tuple has shifted but the same process
        # has another socket to the same peer.
        if not suspect_processes:
            suspect_processes = await self._safe_call(
                self.get_processes_by_remote_ip, flow.remote_ip
            )
        sysmon_events = await self._safe_call(self.query_sysmon_events, alert)
        windows_events = await self._safe_call(self.query_windows_events, alert)
        registry_anomalies = await self._safe_call(self.check_registry_persistence)
        suspicious_files = await self._safe_call(self.find_suspicious_files, alert)

        # Build process trees for each suspect process
        process_tree: list[dict[str, Any]] = []
        for proc in suspect_processes:
            pid = proc.get("pid")
            if pid is not None:
                tree = await self._safe_call(self.build_process_tree, pid)
                process_tree.extend(tree)

        return ForensicResult(
            suspect_processes=suspect_processes,
            sysmon_events=sysmon_events,
            suspicious_files=suspicious_files,
            registry_anomalies=registry_anomalies,
            windows_events=windows_events,
            process_tree=process_tree,
        )

    async def _safe_call(self, func: Any, *args: Any) -> list[Any]:
        """Call a forensic function with error handling.

        Args:
            func: The async function to call.
            *args: Arguments to pass.

        Returns:
            Function result, or empty list on error.
        """
        try:
            return await func(*args)  # type: ignore[no-any-return]
        except (OSError, PermissionError, RuntimeError, ValueError):
            logger.warning("Forensic check failed: %s", func.__name__, exc_info=True)
            return []

    def get_pids_for_flow(self, flow: FlowKey) -> set[int]:
        """Lightweight PID discovery — live snapshot + rolling buffer only.

        Runs the layer-1 and layer-2 matchers from
        :meth:`get_processes_by_flow` but stops short of inflating the
        PIDs into ``{name, exe, cmdline}`` dicts and does not query
        Sysmon Event 3. Designed to be called *early* in
        :meth:`Pipeline.process_alert`, before the filter decision,
        where we only need the PIDs to feed into the risk scorer.

        Returns an empty set rather than raising on psutil denial.
        """
        target_pids: set[int] = set()

        try:
            connections = psutil.net_connections(kind="inet")
        except (PermissionError, OSError):
            logger.debug("psutil.net_connections denied in get_pids_for_flow")
            connections = []

        for conn in connections:
            if conn.pid is None:
                continue
            if _conn_matches_flow(conn, flow):
                target_pids.add(int(conn.pid))

        buffer = getattr(self, "_conn_buffer", None)
        if buffer is not None:
            try:
                target_pids.update(buffer.pids_matching(flow))
            except Exception:  # noqa: BLE001 — buffer must not break the pipeline
                logger.debug("buffer.pids_matching raised in get_pids_for_flow", exc_info=True)

        return target_pids

    async def get_processes_by_flow(self, flow: FlowKey) -> list[dict[str, Any]]:
        """Find the process(es) bound to the exact 5-tuple of ``flow``.

        Two-layer lookup:

        1. **Live snapshot** of ``psutil.net_connections()``. Catches
           flows whose socket is still open at the moment of the
           alert — the common case for long-lived TCP and for any
           listener on the inbound side.
        2. **Rolling buffer** (level 2, if wired). Catches flows that
           closed between Suricata's wire capture and the pipeline
           reaching this function (typically 100 ms – 60 s).

        Match order covers both directions:

        * **PC initiates the flow** (``flow.pc_is_initiator`` True):
          the ephemeral local port uniquely identifies the caller,
          even if several concurrent flows target the same remote
          server.
        * **PC receives the flow**: the listener on
          ``flow.local_port`` catches the attribution even when the
          accepted socket has already gone back to ``TIME_WAIT`` or
          disappeared.

        Returns an empty list rather than raising when psutil denies
        access (normal on non-admin Windows for some sockets).
        """
        target_pids: set[int] = set()

        # --- Layer 1: live snapshot -------------------------------------
        try:
            connections = psutil.net_connections(kind="inet")
        except (PermissionError, OSError):
            logger.warning("Failed to get network connections for flow matching")
            connections = []

        for conn in connections:
            if conn.pid is None:
                continue
            if _conn_matches_flow(conn, flow):
                target_pids.add(int(conn.pid))

        # --- Layer 2: rolling history buffer ---------------------------
        buffer = getattr(self, "_conn_buffer", None)
        if buffer is not None:
            try:
                target_pids.update(buffer.pids_matching(flow))
            except Exception:  # noqa: BLE001 — buffer must never break forensics
                logger.debug("buffer.pids_matching raised", exc_info=True)

        return self._describe_pids(target_pids)

    async def _sysmon_flow_pids(self, flow: FlowKey, alert_time: datetime) -> "set[int]":
        """Query Sysmon Event 3 and return matching PIDs.

        Wrapped in a ``try/except`` so a Sysmon outage never breaks
        the forensic flow — empty set falls through to the next layer.
        """
        try:
            from src.sysmon_events import find_pids_for_flow

            hits = await find_pids_for_flow(flow, alert_time)
            return {hit.pid for hit in hits}
        except Exception:  # noqa: BLE001 — fail-safe, never abort forensics
            logger.debug("Sysmon Event 3 query raised", exc_info=True)
            return set()

    def _describe_pids(self, pids: "set[int]") -> list[dict[str, Any]]:
        """Inflate a set of PIDs to ``{pid, name, exe, cmdline[, services, risk]}`` rows.

        For ``svchost.exe`` PIDs we additionally resolve the Windows
        service names hosted inside via
        :func:`svchost_resolver.resolve_services_for_pid`. This lifts
        the attribution from the generic *"svchost.exe PID 1234"* to
        the actual service (``BITS``, ``Dnscache``, ``Schedule``…) —
        which is the difference between a useful datapoint and a
        shrug for the investigator.

        Every entry also carries a ``risk`` block from
        :func:`src.process_risk.scan_process` — a 0-100 score +
        verdict + signals. The UI surfaces it as a coloured badge;
        the decision analyzer can eventually weigh it into the
        overall verdict. Scoring is strictly local (no VT, no
        network) so it is cheap enough to run on every PID.
        """
        from src.process_risk import scan_process
        from src.svchost_resolver import resolve_services_for_pid

        processes: list[dict[str, Any]] = []
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                entry: dict[str, Any] = {
                    "pid": pid,
                    "name": name,
                    "exe": proc.exe(),
                    "cmdline": proc.cmdline(),
                }
                if name.lower() == "svchost.exe":
                    services = resolve_services_for_pid(pid)
                    if services:
                        entry["services"] = services
                try:
                    entry["risk"] = scan_process(pid).to_dict()
                except Exception:  # noqa: BLE001 — scoring is best-effort
                    logger.debug("process_risk.scan_process raised for PID %d", pid)
                processes.append(entry)
            except (NoSuchProcess, AccessDenied):
                logger.debug("Cannot access process %d", pid)
        return processes

    async def get_processes_by_remote_ip(self, ip: str) -> list[dict[str, Any]]:
        """Find processes with active connections to a remote IP.

        Args:
            ip: Remote IP to search for.

        Returns:
            List of process dicts with PID, name, path, command_line.
        """
        try:
            connections = psutil.net_connections(kind="inet")
        except (PermissionError, OSError):
            logger.warning("Failed to get network connections for forensics")
            return []

        target_pids: set[int] = set()
        for conn in connections:
            if conn.raddr and hasattr(conn.raddr, "ip") and conn.raddr.ip == ip:
                if conn.pid is not None:
                    target_pids.add(conn.pid)

        processes: list[dict[str, Any]] = []
        for pid in target_pids:
            try:
                proc = psutil.Process(pid)
                processes.append(
                    {
                        "pid": pid,
                        "name": proc.name(),
                        "exe": proc.exe(),
                        "cmdline": proc.cmdline(),
                    }
                )
            except (NoSuchProcess, AccessDenied):
                logger.debug("Cannot access process %d", pid)

        return processes

    async def build_process_tree(self, pid: int) -> list[dict[str, Any]]:
        """Build the parent-child process tree for a given PID.

        Args:
            pid: Process ID to trace.

        Returns:
            List of process dicts from target to root.
        """
        tree: list[dict[str, Any]] = []
        try:
            proc = psutil.Process(pid)
            tree.append(
                {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                }
            )
            for parent in proc.parents():
                tree.append(
                    {
                        "pid": parent.pid,
                        "name": parent.name(),
                        "exe": parent.exe(),
                    }
                )
        except (NoSuchProcess, AccessDenied, ZombieProcess):
            logger.debug("Cannot build process tree for PID %d", pid)

        return tree

    async def query_sysmon_events(
        self, alert: SuricataAlert, event_ids: Optional[list[int]] = None
    ) -> list[SysmonEvent]:
        """Query Sysmon event log for events correlated with an alert.

        Args:
            alert: The triggering alert for time/IP correlation.
            event_ids: Specific Sysmon event IDs to query. Defaults to all.

        Returns:
            List of parsed SysmonEvent objects.
        """
        if event_ids is None:
            event_ids = [
                SYSMON_PROCESS_CREATE,
                SYSMON_NETWORK_CONNECT,
                SYSMON_FILE_CREATE,
                SYSMON_DNS_QUERY,
            ]

        start_time = alert.timestamp - timedelta(seconds=self._correlation_window)

        # Use FilterHashtable — more reliable than XPath for time filtering
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        ids_filter = ",".join(str(eid) for eid in event_ids)
        ps_command = (
            f"Get-WinEvent -FilterHashtable @{{"
            f"LogName='{self._sysmon_channel}';"
            f"Id={ids_filter};"
            f"StartTime='{start_str}'"
            f"}} -MaxEvents 100 -ErrorAction SilentlyContinue "
            f"| Select-Object Id, TimeCreated, Message "
            f"| ConvertTo-Json -Compress"
        )

        try:
            result = (
                subprocess.run(  # nosec B603 — absolute path, server-controlled args, no user input
                    [win_paths.POWERSHELL, "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            )
            # Guard against ``result.stdout is None``. subprocess.run
            # with ``text=True, capture_output=True`` normally returns
            # an empty string, but a crashed PowerShell child (observed
            # 2026-04-20 15:12 at SID 2017926 / 2054168, two alerts
            # raising ``AttributeError: 'NoneType' object has no
            # attribute 'strip'``) can deliver ``stdout=None``. Falling
            # back to an empty string keeps the fail-safe semantics the
            # rest of this function expects.
            stdout = result.stdout or ""
            if result.returncode != 0 or not stdout.strip():
                return []

            return self._parse_sysmon_json(stdout)
        except (FileNotFoundError, OSError, TimeoutExpired):
            logger.warning("Failed to query Sysmon events")
            return []

    def _parse_sysmon_json(self, raw_json: str) -> list[SysmonEvent]:
        """Parse PowerShell JSON output into SysmonEvent objects.

        Args:
            raw_json: JSON string from PowerShell.

        Returns:
            List of parsed SysmonEvent objects.
        """
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Sysmon JSON output")
            return []

        if isinstance(data, dict):
            data = [data]

        events: list[SysmonEvent] = []
        for entry in data:
            try:
                events.append(
                    SysmonEvent(
                        event_id=int(entry.get("Id", 0)),
                        timestamp=alert_timestamp_from_string(entry.get("TimeCreated", "")),
                        description=str(entry.get("Message", "")),
                        raw_event=entry,
                    )
                )
            except (ValueError, TypeError):
                continue

        return events

    async def query_windows_events(self, alert: SuricataAlert) -> list[dict[str, Any]]:
        """Query Windows Security event log for suspicious activity.

        Args:
            alert: The triggering alert for time correlation.

        Returns:
            List of relevant Windows event dicts.
        """
        start_time = alert.timestamp - timedelta(seconds=self._correlation_window)
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")

        ps_command = (
            f"Get-WinEvent -FilterHashtable @{{"
            f"LogName='Security';"
            f"Id={WIN_LOGON_SUCCESS},{WIN_LOGON_FAILED},{WIN_PRIVILEGE_ESCALATION},{WIN_PROCESS_CREATION};"
            f"StartTime='{start_str}'"
            f"}} -MaxEvents 50 -ErrorAction SilentlyContinue "
            f"| Select-Object Id, TimeCreated, Message "
            f"| ConvertTo-Json -Compress"
        )

        try:
            result = (
                subprocess.run(  # nosec B603 — absolute path, server-controlled args, no user input
                    [win_paths.POWERSHELL, "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            )
            # Same NoneType guard as query_sysmon_events (see there).
            stdout = result.stdout or ""
            if result.returncode != 0 or not stdout.strip():
                return []

            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]
            return data  # type: ignore[no-any-return]
        except (FileNotFoundError, OSError, TimeoutExpired, json.JSONDecodeError):
            logger.warning("Failed to query Windows Security events")
            return []

    async def check_registry_persistence(self) -> list[dict[str, Any]]:
        """Check common registry persistence locations for anomalies.

        Returns:
            List of suspicious registry entries.
        """
        entries: list[dict[str, Any]] = []

        for key in REGISTRY_PERSISTENCE_KEYS:
            ps_command = (
                f"Get-ItemProperty -Path 'Registry::{key}' -ErrorAction SilentlyContinue "
                f"| ConvertTo-Json -Compress"
            )
            try:
                result = subprocess.run(  # nosec B603 — absolute path, server-controlled args, no user input
                    [win_paths.POWERSHELL, "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                # Same NoneType guard as query_sysmon_events (see there).
                stdout = (result.stdout or "").strip()
                if result.returncode == 0 and stdout:
                    entries.append({"key": key, "raw": stdout})
            except (FileNotFoundError, OSError, TimeoutExpired):
                logger.debug("Failed to query registry key: %s", key)

        return entries

    async def find_suspicious_files(self, alert: SuricataAlert) -> list[dict[str, Any]]:
        """Find recently created or modified files likely related to the alert.

        Applies four filters (freshness, size, extension, app-exclusions) to
        reduce the candidate set from thousands of benign files to a small
        handful worth VirusTotal/Defender scanning. Each filter rejects the
        file early without further I/O.

        Args:
            alert: The triggering alert for time correlation.

        Returns:
            List of file dicts with path, size, modified time.
        """
        files: list[dict[str, Any]] = []

        alert_ts = alert.timestamp.timestamp()
        time_min = alert_ts - self._sf_freshness_before
        time_max = alert_ts + self._sf_freshness_after

        for dir_template in SUSPICIOUS_DIRECTORIES:
            try:
                expanded = dir_template.format(
                    TEMP=os.environ.get("TEMP", ""),
                    USERPROFILE=os.environ.get("USERPROFILE", ""),
                    APPDATA=os.environ.get("APPDATA", ""),
                    LOCALAPPDATA=os.environ.get("LOCALAPPDATA", ""),
                )
                dir_path = Path(expanded)
                if not dir_path.exists():
                    continue

                for file_path in dir_path.iterdir():
                    if not file_path.is_file():
                        continue

                    # Filter 1 — extension whitelist
                    if file_path.suffix.lower() not in self._sf_extensions:
                        continue

                    # Filter 2 — app-installer exclusions (drops Chrome cache, Discord, etc.)
                    path_lower = str(file_path).lower()
                    if any(frag in path_lower for frag in self._sf_exclusions):
                        continue

                    try:
                        stat = file_path.stat()
                    except (PermissionError, OSError):
                        continue

                    # Filter 3 — size bounds (skip empty flag files and oversized dumps)
                    if stat.st_size < self._sf_min_size or stat.st_size > self._sf_max_size:
                        continue

                    # Filter 4 — freshness (must be within correlation window)
                    if stat.st_mtime < time_min or stat.st_mtime > time_max:
                        continue

                    files.append(
                        {
                            "path": str(file_path),
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                        }
                    )

            except (KeyError, OSError, ValueError):
                continue

        return files


def alert_timestamp_from_string(ts_str: str) -> datetime:
    """Parse a timestamp string from PowerShell output.

    Args:
        ts_str: Timestamp string to parse.

    Returns:
        Parsed datetime object.
    """
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
