"""Level 3 process attribution — Sysmon Event ID 3 (NetworkConnect).

When layers 1 (live ``psutil.net_connections``) and 2 (rolling
snapshot buffer) both come up empty, the socket was likely torn down
before any of them ran. Microsoft Sysinternals Sysmon — if installed
and running (see ``src/sysmon_probe.py``) — writes a Windows Event
Log entry per new TCP/UDP connection, with the full 5-tuple and
the originating Image / PID / ProcessGuid. Those events persist for
the lifetime of the Event Log rotation, so we can re-discover the
process that generated the alert hours after the socket is gone.

Design:
    * :func:`find_pids_for_flow` is the single entry point. It
      fans out a PowerShell ``Get-WinEvent`` call with a
      FilterHashtable that narrows the search to Event ID 3 within
      a short time window around the alert, parses the JSON
      response, and filters by the flow's 5-tuple.
    * The PowerShell call is synchronous internally but wrapped in
      ``asyncio.to_thread`` so it does not block the forensic
      coroutine.
    * Missing Sysmon / query failure → empty list (fail-safe).

The separation from ``forensics.query_sysmon_events`` is
deliberate: that function returns generic ``SysmonEvent`` records
for the enrichment prompt, while this module returns only the
process attribution that matched ``flow``, with enough context for
the UI to distinguish "attributed via Sysmon Event 3" from a live
psutil match.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess  # nosec B404 — invoked with absolute paths and hardcoded args
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404
from typing import Any

from src import win_paths
from src.forensics import FlowKey

logger = logging.getLogger("ward_soar.sysmon_events")


#: How far around ``alert_time`` to look. A short TCP connection
#: typically shows up in Event 3 within ~200 ms of the socket open,
#: but clock skew between the Netgate and the PC can add a second or
#: two. Thirty seconds is generous without flooding the event query.
_DEFAULT_WINDOW_SECONDS = 30

#: Per-query timeout. PowerShell + Event Log can be slow under load;
#: forensic calls should never stall the pipeline on a hung SCM.
_QUERY_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class SysmonFlowHit:
    """One Event 3 record that matched the incoming flow.

    Attributes:
        pid: The process that opened the socket.
        image: Full image path (e.g. ``C:\\Program Files\\...\\svchost.exe``).
        process_guid: Sysmon's stable per-process identifier. Useful
            to disambiguate PID reuse — two different processes can
            share a PID over time.
        local_port: Port on the PC side.
        remote_ip: The peer's IP.
        remote_port: The peer's port.
        initiated: True when the PC started the flow (Sysmon's
            ``Initiated`` field). Should align with
            :attr:`FlowKey.pc_is_initiator`.
        event_time: UTC timestamp pulled from the Event record.
    """

    pid: int
    image: str
    process_guid: str
    local_port: int
    remote_ip: str
    remote_port: int
    initiated: bool
    event_time: str


async def find_pids_for_flow(
    flow: FlowKey,
    alert_time: datetime,
    window_seconds: int = _DEFAULT_WINDOW_SECONDS,
) -> list[SysmonFlowHit]:
    """Return every Event 3 entry whose 5-tuple matches ``flow``.

    Args:
        flow: The 5-tuple we want to attribute.
        alert_time: Suricata alert timestamp. Used to bound the
            Event Log query window; a naive datetime is assumed UTC.
        window_seconds: Half-width of the query window. Default 30 s.

    Returns:
        List of :class:`SysmonFlowHit`. Empty when Sysmon is absent,
        the query times out, or no event matches.
    """
    events = await asyncio.to_thread(
        _run_sysmon_event3_query,
        alert_time,
        window_seconds,
    )
    hits = [hit for hit in (_try_match(ev, flow) for ev in events) if hit is not None]
    return hits


def _run_sysmon_event3_query(alert_time: datetime, window_seconds: int) -> list[dict[str, Any]]:
    """Invoke ``Get-WinEvent`` and return the parsed list of events."""
    ps_path = getattr(win_paths, "POWERSHELL", None)
    if not ps_path or not Path(str(ps_path)).is_file():
        logger.debug("PowerShell not available — skipping Sysmon Event 3 query")
        return []

    # Format the start/end times for the FilterHashtable. The
    # PowerShell FileTime / DateTime conversion accepts ISO 8601 with
    # the 'Z' suffix; we force UTC on a naive timestamp to match the
    # pipeline's convention.
    aware = alert_time if alert_time.tzinfo else alert_time.replace(tzinfo=timezone.utc)
    start = (aware - timedelta(seconds=window_seconds)).astimezone(timezone.utc)
    end = (aware + timedelta(seconds=window_seconds)).astimezone(timezone.utc)

    # Use a here-string PowerShell script so we can interpolate the
    # time bounds safely (integers, no operator input) without
    # worrying about cmd.exe escaping. ConvertTo-Json -Depth 5 keeps
    # nested Event/EventData structures intact.
    ps_script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$start=[datetime]::Parse('" + start.isoformat() + "');"
        "$end=[datetime]::Parse('" + end.isoformat() + "');"
        "$filter=@{LogName='Microsoft-Windows-Sysmon/Operational';Id=3;"
        "StartTime=$start;EndTime=$end};"
        "$events=Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 |"
        " ForEach-Object { $e=@{}; $e.TimeCreated=$_.TimeCreated.ToString('o');"
        " $_.Properties | ForEach-Object { } ;"
        " $xml=[xml]$_.ToXml();"
        " $xml.Event.EventData.Data | ForEach-Object { $e[$_.Name]=$_.'#text' };"
        " New-Object PSObject -Property $e };"
        "if($events){ $events | ConvertTo-Json -Depth 5 -Compress } else { '[]' }"
    )

    try:
        result = subprocess.run(  # nosec B603 — absolute path + no operator input
            [
                str(ps_path),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_script,
            ],
            capture_output=True,
            text=True,
            timeout=_QUERY_TIMEOUT_SECONDS,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (FileNotFoundError, OSError, TimeoutExpired) as exc:
        logger.debug("Sysmon Event 3 query failed: %s", exc)
        return []

    if result.returncode != 0 or not result.stdout:
        return []

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Sysmon Event 3 output is not JSON")
        return []

    # Get-WinEvent returns a single object if only one event matches.
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    return []


def _try_match(raw_event: dict[str, Any], flow: FlowKey) -> "SysmonFlowHit | None":
    """Project an Event 3 dict onto :class:`SysmonFlowHit` if 5-tuple matches.

    Sysmon normalises fields under these names:
        * ``ProcessId`` / ``Image`` / ``ProcessGuid``
        * ``SourceIp`` / ``SourcePort`` / ``DestinationIp`` /
          ``DestinationPort``
        * ``Initiated`` — "true"/"false"; when True the PC is the
          flow initiator so ``Source*`` is local and ``Destination*``
          is remote, and vice versa.

    Returns None when a field is missing or the 5-tuple does not
    match ``flow``. Match is strict (local_port + remote_ip +
    remote_port) so a Sysmon entry for an unrelated concurrent flow
    does not mis-attribute.
    """
    try:
        pid = int(raw_event.get("ProcessId") or 0)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None

    initiated_str = str(raw_event.get("Initiated") or "").strip().lower()
    initiated = initiated_str == "true"

    if initiated:
        local_port_s = raw_event.get("SourcePort") or "0"
        remote_ip = str(raw_event.get("DestinationIp") or "")
        remote_port_s = raw_event.get("DestinationPort") or "0"
    else:
        local_port_s = raw_event.get("DestinationPort") or "0"
        remote_ip = str(raw_event.get("SourceIp") or "")
        remote_port_s = raw_event.get("SourcePort") or "0"

    try:
        local_port = int(local_port_s)
        remote_port = int(remote_port_s)
    except (TypeError, ValueError):
        return None

    if local_port != flow.local_port:
        return None
    if remote_ip and remote_ip != flow.remote_ip:
        return None
    if remote_port and remote_port != flow.remote_port:
        return None

    return SysmonFlowHit(
        pid=pid,
        image=str(raw_event.get("Image") or ""),
        process_guid=str(raw_event.get("ProcessGuid") or ""),
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        initiated=initiated,
        event_time=str(raw_event.get("TimeCreated") or ""),
    )


__all__: tuple[str, ...] = (
    "SysmonFlowHit",
    "find_pids_for_flow",
)
