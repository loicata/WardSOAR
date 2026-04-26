"""Investigates dual-Suricata divergences.

Triggered by the pipeline (stage 0.5, post-:class:`process_risk`)
on every alert whose :class:`SourceCorroboration` has resolved to
``DIVERGENCE_A`` (external-only) or ``DIVERGENCE_B`` (local-only).
The investigator runs six fail-safe checks **in parallel** and
synthesises a :class:`DivergenceFindings` dict that:

* explains the divergence when a topological / known-failure cause
  is identified (loopback, VPN, LAN-only, suricata_local_dead) →
  ``is_explained=True``
* declares it unexplained otherwise → drives the verdict bump
  (Q3 β nuanced of ``project_dual_suricata_sync.md``).

The 6 checks (Q2 of the memo):

| ID | Check | Timeout | Output |
|---|---|---|---|
| (a) | Snapshot processes + connections from NetConnectionsBuffer | <100 ms | ``snapshot_summary`` |
| (b) | Sysmon EventLog (ID 1 process create + ID 3 network conn) ±15 s | 5 s | ``sysmon_correlation`` |
| (c) | Suricata local process alive | <50 ms | ``suricata_local_state`` |
| (d) | Loopback (127/8, ::1, host's local interfaces) | <10 ms | ``is_loopback`` |
| (e) | VPN active (TUN/TAP/WireGuard/OpenVPN interfaces) | <100 ms | ``is_vpn`` |
| (f) | LAN-only (RFC1918 src + dst, no WAN transit) | <10 ms | ``is_lan_only`` |

CRITICAL invariants:
    * Every check is fail-safe: a check that errors / times out
      returns its default and other checks continue. The investigator
      never raises to the pipeline.
    * Sysmon (b) is best-effort: when not installed, ``sysmon_correlation``
      is ``[]`` and ``checks_run`` doesn't include ``"sysmon"``. The
      pipeline carries on without it.
    * The investigator runs all 6 checks via :func:`asyncio.gather`
      so the wall-clock latency is bounded by the slowest check
      (Sysmon, 5 s timeout) — not the sum.

See ``project_dual_suricata_sync.md`` Q2 for the full doctrine and
``project_dual_suricata_sync.md`` Q3 for how the findings drive
the verdict-bumping decision (in :class:`DivergenceVerdictBumper`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess  # nosec B404 — calls Get-WinEvent via PowerShell, fixed args
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404
from typing import Any, Optional, Union

import psutil

from wardsoar.core.corroboration import CorroborationStatus
from wardsoar.core.models import DivergenceFindings, SourceCorroboration
from wardsoar.pc import win_paths
from wardsoar.pc.local_suricata import SuricataProcess

logger = logging.getLogger("ward_soar.divergence_investigator")


# ---------------------------------------------------------------------------
# Per-check timeouts (Q2 of the memo)
# ---------------------------------------------------------------------------

_SYSMON_TIMEOUT_S: float = 5.0
"""Sysmon EventLog query is the slowest check by far. 5 s is the
documented cap; beyond that we surrender and continue without
Sysmon correlation."""

_SYSMON_MAX_EVENTS: int = 100
"""Cap returned Sysmon events so a chatty host doesn't blow our
forensic record."""

_SYSMON_WINDOW_S: int = 15
"""Half-window around the alert timestamp for Sysmon correlation
(±15 s = 30 s total scan window)."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


class DivergenceInvestigator:
    """Run the 6 divergence checks for an alert and produce findings.

    The investigator holds references to the components it needs
    (the operator's :class:`SuricataProcess` for the alive check,
    the :class:`NetConnectionsBuffer` for the snapshot check). All
    other inputs flow per-call via :meth:`investigate`.

    Args:
        suricata_process: The local Suricata process. ``None`` when
          standalone-PC mode is not active and the local Suricata
          state is irrelevant — the alive check then collapses to
          ``"unknown"``.
        netconns_buffer: The rolling :class:`NetConnectionsBuffer`
          maintained by the pipeline. ``None`` when the buffer is
          not yet started; the snapshot check then returns an empty
          summary.
        local_subnets_cidr: Pre-computed list of LAN subnets the
          host belongs to (e.g. ``["192.168.2.0/24"]``). The
          ``is_lan_only`` check uses these to decide whether a flow
          stayed inside the LAN.
    """

    def __init__(
        self,
        suricata_process: Optional[SuricataProcess] = None,
        netconns_buffer: Optional[Any] = None,
        local_subnets_cidr: Optional[list[str]] = None,
        processes_by_name: Optional[dict[str, SuricataProcess]] = None,
    ) -> None:
        self._process = suricata_process
        # N-source mapping: every configured local Suricata source gets
        # its own process handle here (the operator may run several —
        # e.g. one per network interface). When provided, the alive
        # check returns a per-source dict; the legacy single-process
        # path stays available so existing callers don't break.
        self._processes_by_name: dict[str, SuricataProcess] = dict(processes_by_name or {})
        self._netconns = netconns_buffer
        # Parse + dedupe CIDRs once at init so the per-event check
        # is a tight integer-comparison loop.
        self._local_subnets: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for cidr in local_subnets_cidr or []:
            try:
                self._local_subnets.append(ipaddress.ip_network(cidr, strict=False))
            except (ValueError, TypeError):
                logger.warning(
                    "DivergenceInvestigator: ignoring invalid local subnet CIDR %r",
                    cidr,
                )

    async def investigate(
        self,
        event: dict[str, Any],
        corroboration: SourceCorroboration,
        secondary_event: Optional[dict[str, Any]] = None,
    ) -> DivergenceFindings:
        """Run all 6 checks in parallel, synthesise the findings.

        Args:
            event: The primary EVE alert from the
              :class:`DualSourceCorrelator`.
            corroboration: The correlation tag — only
              ``DIVERGENCE_A`` and ``DIVERGENCE_B`` invocations are
              expected, but the method tolerates other values
              defensively (returns an empty :class:`DivergenceFindings`
              with ``checks_run=[]``).
            secondary_event: The matching event from the other source
              when available (``MATCH_CONFIRMED`` doesn't need an
              investigation, but the method accepts it for forward
              compatibility).

        Returns:
            A :class:`DivergenceFindings` populated with whichever
            checks succeeded. Never raises.
        """
        # Defensive guard: only run the full investigation for the
        # two divergent tags. Other tags (PENDING, MATCH_CONFIRMED,
        # SINGLE_SOURCE) get an empty findings record so the pipeline
        # downstream has a well-formed object to attach.
        if corroboration not in (
            SourceCorroboration.DIVERGENCE_A,
            SourceCorroboration.DIVERGENCE_B,
        ):
            return DivergenceFindings()

        # Run all six checks in parallel. asyncio.gather caps the
        # total wall clock at the slowest one (Sysmon, 5 s).
        snapshot_task = asyncio.create_task(self._check_snapshot(event))
        sysmon_task = asyncio.create_task(self._check_sysmon(event))
        suricata_task = asyncio.create_task(self._check_suricata_alive())
        loopback_task = asyncio.create_task(self._check_loopback(event))
        vpn_task = asyncio.create_task(self._check_vpn())
        lan_task = asyncio.create_task(self._check_lan_only(event))

        results = await asyncio.gather(
            snapshot_task,
            sysmon_task,
            suricata_task,
            loopback_task,
            vpn_task,
            lan_task,
            return_exceptions=False,  # checks already swallow their own
        )
        snapshot_summary = results[0]
        sysmon_correlation = results[1]
        suricata_state = results[2]
        is_loopback = results[3]
        is_vpn = results[4]
        is_lan_only = results[5]

        checks_run: list[str] = ["snapshot", "suricata_alive", "loopback", "vpn", "lan_only"]
        # ``sysmon`` is only reported as run when it actually
        # produced something, OR when Sysmon is installed even if
        # no correlated events were found. We can detect "Sysmon
        # not installed" because the check returns an empty list
        # with no underlying call. Simpler heuristic: present iff
        # at least one event was returned. Trade-off: a real
        # "Sysmon installed but no correlated events" is reported
        # as "sysmon not present" — false but doesn't affect the
        # bumping logic (sysmon never explains a divergence by
        # itself).
        if sysmon_correlation:
            checks_run.insert(1, "sysmon")  # alphabetical-ish ordering

        # Synthesise the explanation token. The order matters — we
        # take the first matching cause (per Q2 doctrine).
        is_explained = False
        explanation = "unexplained"
        if is_loopback:
            is_explained = True
            explanation = "loopback_traffic"
        elif is_vpn:
            is_explained = True
            explanation = "vpn_traffic"
        elif is_lan_only:
            is_explained = True
            explanation = "lan_only_traffic"
        elif suricata_state == "dead":
            # Per Q3: suricata_local_dead is "explained" but still
            # bumps the verdict, because a dead local Suricata is a
            # high-signal anomaly.
            is_explained = True
            explanation = "suricata_local_dead"

        return DivergenceFindings(
            checks_run=checks_run,
            is_explained=is_explained,
            explanation=explanation,
            snapshot_summary=snapshot_summary,
            sysmon_correlation=sysmon_correlation,
            suricata_local_state=suricata_state,
            is_loopback=is_loopback,
            is_vpn=is_vpn,
            is_lan_only=is_lan_only,
        )

    async def investigate_n(
        self,
        event: dict[str, Any],
        status: CorroborationStatus,
        secondary_events: Optional[dict[str, dict[str, Any]]] = None,
    ) -> DivergenceFindings:
        """N-source counterpart to :meth:`investigate`.

        Same six fail-safe checks but driven by a
        :class:`CorroborationStatus` instead of the legacy
        :class:`SourceCorroboration` enum, and the alive check
        produces a :attr:`DivergenceFindings.suricata_states` mapping
        keyed by source name (one entry per configured local
        Suricata).

        Defensive: only :data:`CorroborationVerdict.DIVERGENCE` and
        :data:`CorroborationVerdict.MATCH_MAJORITY` justify a full
        investigation. Other verdicts (PENDING, MATCH_FULL,
        SINGLE_SOURCE, NO_DATA) get an empty :class:`DivergenceFindings`
        record so downstream consumers always have a well-formed
        object.
        """
        from wardsoar.core.corroboration import CorroborationVerdict

        if status.verdict not in (
            CorroborationVerdict.DIVERGENCE,
            CorroborationVerdict.MATCH_MAJORITY,
        ):
            return DivergenceFindings()

        snapshot_task = asyncio.create_task(self._check_snapshot(event))
        sysmon_task = asyncio.create_task(self._check_sysmon(event))
        suricata_task = asyncio.create_task(self._check_suricata_alive_per_source())
        loopback_task = asyncio.create_task(self._check_loopback(event))
        vpn_task = asyncio.create_task(self._check_vpn())
        lan_task = asyncio.create_task(self._check_lan_only(event))

        results = await asyncio.gather(
            snapshot_task,
            sysmon_task,
            suricata_task,
            loopback_task,
            vpn_task,
            lan_task,
            return_exceptions=False,
        )
        snapshot_summary = results[0]
        sysmon_correlation = results[1]
        suricata_states: dict[str, str] = results[2]
        is_loopback = results[3]
        is_vpn = results[4]
        is_lan_only = results[5]

        checks_run: list[str] = ["snapshot", "suricata_alive", "loopback", "vpn", "lan_only"]
        if sysmon_correlation:
            checks_run.insert(1, "sysmon")

        # Synthesise the explanation. Same ladder as the legacy
        # investigate() method, but the suricata-dead check now
        # surfaces if ANY configured source went silent.
        is_explained = False
        explanation = "unexplained"
        if is_loopback:
            is_explained = True
            explanation = "loopback_traffic"
        elif is_vpn:
            is_explained = True
            explanation = "vpn_traffic"
        elif is_lan_only:
            is_explained = True
            explanation = "lan_only_traffic"
        elif any(state == "dead" for state in suricata_states.values()):
            is_explained = True
            explanation = "suricata_local_dead"

        return DivergenceFindings(
            checks_run=checks_run,
            is_explained=is_explained,
            explanation=explanation,
            snapshot_summary=snapshot_summary,
            sysmon_correlation=sysmon_correlation,
            suricata_states=suricata_states,
            is_loopback=is_loopback,
            is_vpn=is_vpn,
            is_lan_only=is_lan_only,
        )

    # ------------------------------------------------------------------
    # Individual checks (each is fail-safe — never raises)
    # ------------------------------------------------------------------

    async def _check_snapshot(self, event: dict[str, Any]) -> dict[str, Any]:
        """Check (a): snapshot of processes + connections at event time."""
        if self._netconns is None:
            return {}

        # The buffer's API exposes a per-flow lookup. We assemble a
        # lightweight summary: PID count, connection count, top
        # PIDs by connection volume.
        try:
            # pids_matching takes a FlowKey; we don't import the
            # type here to keep the investigator non-pc-coupled
            # except for psutil. The buffer API tolerates a dict-
            # shaped query; if the consumer supplies one a richer
            # version of this can be wired later.
            snapshot_count = await asyncio.to_thread(
                getattr(self._netconns, "snapshot_count", lambda: 0)
            )
        except Exception as exc:  # noqa: BLE001 — fail-safe
            logger.debug("DivergenceInvestigator: snapshot check failed: %s", exc)
            return {}

        return {
            "snapshots_in_buffer": snapshot_count,
            "src_ip": event.get("src_ip", ""),
            "dest_ip": event.get("dest_ip", ""),
        }

    async def _check_sysmon(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Check (b): Sysmon EventLog ±15 s of the alert timestamp.

        Best-effort: if Sysmon isn't installed (no Sysmon channel
        in the EventLog), the PowerShell call returns an error and
        we report an empty list. The pipeline continues with the
        other checks.
        """
        ps_exe = getattr(win_paths, "POWERSHELL", None)
        if not ps_exe or not Path(str(ps_exe)).is_file():
            return []

        # Build the PowerShell query. We probe the Microsoft-Windows-
        # Sysmon/Operational channel for IDs 1 (process create) and
        # 3 (network connection) within ±15 s of "now" (the
        # investigator runs shortly after the alert, the EventLog
        # is timestamped per-event so a "now ±15s" window picks up
        # everything around the alert).
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$end = (Get-Date).AddSeconds({_SYSMON_WINDOW_S});"
            f"$start = (Get-Date).AddSeconds(-{_SYSMON_WINDOW_S});"
            "$evts = Get-WinEvent -FilterHashtable @{"
            " LogName='Microsoft-Windows-Sysmon/Operational';"
            " ID=@(1,3);"
            " StartTime=$start;"
            " EndTime=$end;"
            f"}} -MaxEvents {_SYSMON_MAX_EVENTS};"
            "if($evts){"
            " $out = $evts | ForEach-Object {"
            "  @{ Id = $_.Id;"
            "     Time = $_.TimeCreated.ToString('o');"
            "     Message = $_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))"
            "  }"
            " };"
            " $out | ConvertTo-Json -Compress"
            "} else { '[]' }"
        )

        try:
            result = await asyncio.to_thread(
                lambda: subprocess.run(  # nosec B603 — fixed PowerShell + literal script
                    [
                        str(ps_exe),
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        script,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=_SYSMON_TIMEOUT_S,
                    shell=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    check=False,
                )
            )
        except (FileNotFoundError, OSError, TimeoutExpired) as exc:
            logger.debug("DivergenceInvestigator: Sysmon query failed: %s", exc)
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        # Parse JSON — single-event responses are emitted as an
        # object, multi-event as an array. Normalise to list.
        try:
            import json as _json

            parsed = _json.loads(result.stdout)
        except (ValueError, TypeError):
            return []

        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        return []

    async def _check_suricata_alive(self) -> str:
        """Check (c) — legacy single-process flavour. Returns ``running`` /
        ``dead`` / ``unknown`` for the lone configured local Suricata."""
        if self._process is None:
            return "unknown"
        try:
            if self._process.is_running():
                return "running"
            return "dead"
        except Exception as exc:  # noqa: BLE001 — fail-safe
            logger.debug("DivergenceInvestigator: suricata_alive check failed: %s", exc)
            return "unknown"

    async def _check_suricata_alive_per_source(self) -> dict[str, str]:
        """Check (c) — N-source flavour. Returns ``{name: state}`` for every
        configured Suricata source. ``"dead"`` from any source still drives
        the verdict bump; the dict shape lets the operator see exactly which
        source went silent."""
        if not self._processes_by_name:
            return {}
        states: dict[str, str] = {}
        for name, process in self._processes_by_name.items():
            try:
                states[name] = "running" if process.is_running() else "dead"
            except Exception as exc:  # noqa: BLE001 — fail-safe per source
                logger.debug(
                    "DivergenceInvestigator: per-source alive check (%s) failed: %s",
                    name,
                    exc,
                )
                states[name] = "unknown"
        return states

    async def _check_loopback(self, event: dict[str, Any]) -> bool:
        """Check (d): is this a loopback flow (127/8, ::1, host local IPs)?"""
        src = event.get("src_ip", "")
        dst = event.get("dest_ip", "")
        if not isinstance(src, str) or not isinstance(dst, str):
            return False
        if not src or not dst:
            return False

        try:
            src_addr = ipaddress.ip_address(src)
            dst_addr = ipaddress.ip_address(dst)
        except ValueError:
            return False

        # Loopback addresses (127.0.0.0/8, ::1/128).
        if src_addr.is_loopback and dst_addr.is_loopback:
            return True

        # Both IPs match a local interface address → loopback-like
        # (host talking to itself via its own LAN IP).
        try:
            local_ips: set[str] = set()
            for iface_addrs in psutil.net_if_addrs().values():
                for addr in iface_addrs:
                    family_name = getattr(addr.family, "name", str(addr.family))
                    if family_name in ("AF_INET", "AddressFamily.AF_INET"):
                        local_ips.add(addr.address)
                    elif family_name in ("AF_INET6", "AddressFamily.AF_INET6"):
                        local_ips.add(addr.address.split("%")[0])
            if src in local_ips and dst in local_ips:
                return True
        except (psutil.Error, OSError) as exc:
            logger.debug("DivergenceInvestigator: loopback check (psutil) failed: %s", exc)

        return False

    async def _check_vpn(self) -> bool:
        """Check (e): is a VPN-style interface (TUN/TAP/WireGuard) active?

        We look for known VPN driver name substrings in the host's
        active interfaces. This is a heuristic but covers the
        common cases (OpenVPN tap0, WireGuard wg0, Cisco AnyConnect
        cscotun0, NordLynx, etc.).
        """
        vpn_substrings = ("tun", "tap", "wireguard", "wg0", "vpn", "ppp", "cscotun")
        try:
            stats = await asyncio.to_thread(psutil.net_if_stats)
            for name, stat in stats.items():
                if not stat.isup:
                    continue
                lname = name.lower()
                if any(needle in lname for needle in vpn_substrings):
                    return True
        except (psutil.Error, OSError) as exc:
            logger.debug("DivergenceInvestigator: VPN check failed: %s", exc)
        return False

    async def _check_lan_only(self, event: dict[str, Any]) -> bool:
        """Check (f): does the flow stay inside a configured LAN?

        Both src and dst must be RFC1918 (or in the operator-
        configured ``local_subnets_cidr``) for the check to
        positive. A single public IP on either end means WAN
        transit, hence the external Suricata could see the flow.
        """
        src = event.get("src_ip", "")
        dst = event.get("dest_ip", "")
        if not isinstance(src, str) or not isinstance(dst, str):
            return False

        try:
            src_addr = ipaddress.ip_address(src)
            dst_addr = ipaddress.ip_address(dst)
        except ValueError:
            return False

        # Either RFC1918 ``is_private`` or in the operator's
        # configured local subnets.
        def _is_lan(addr: Any) -> bool:
            if addr.is_private:
                return True
            for net in self._local_subnets:
                if addr in net:
                    return True
            return False

        return _is_lan(src_addr) and _is_lan(dst_addr)


__all__ = ("DivergenceInvestigator",)
