"""Super timeline builder for the deep forensic report.

Merges all timestamped evidence into a single chronological view so
the investigator can see the alert in context:
    - Suricata alert (the trigger).
    - Suspicious process start times (``psutil.create_time``).
    - Sysmon events (process create / network connect / file create).
    - Windows Security events (logon, privilege escalation).
    - Files captured by ``find_suspicious_files`` (mtime).
    - Rollback + block actions, if the record carries them.

Output is a list of :class:`TimelineEntry`, sorted ascending by UTC
timestamp. Each entry has a short human-readable ``description`` and
a ``source`` tag so downstream tools (and humans) can filter.

Serialisation helpers:
    - ``to_plaso_csv``  → Plaso/log2timeline compatible CSV.
    - ``to_json_list``  → JSON array useful in the technical report.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from src.models import DecisionRecord, ResponseAction, SuricataAlert

# CSV header matching the Plaso format; external tools (Timesketch,
# Excel) understand it without any extra config.
_PLASO_HEADER = "datetime,timestamp_desc,source,source_long,message,parser,tag"


def _parse_create_time(value: Any) -> Optional[datetime]:
    """psutil returns create_time as epoch seconds; tolerate strings too."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            return datetime.fromisoformat(value)
    except (ValueError, OSError, OverflowError):
        return None
    return None


def _parse_mtime(value: Any) -> Optional[datetime]:
    """File mtime from stat is also epoch seconds."""
    return _parse_create_time(value)


@dataclass
class TimelineEntry:
    """A single event on the super timeline.

    Attributes:
        timestamp_utc: Event time in UTC, ISO 8601.
        source: Short tag (``alert``, ``process``, ``sysmon``…).
        description: Human-readable one-line summary.
        details: Arbitrary key/value context for the technical report.
    """

    timestamp_utc: str
    source: str
    description: str
    details: dict[str, Any]


class TimelineBuilder:
    """Turn a DecisionRecord into a :class:`TimelineEntry` list.

    The builder is pure (no I/O) and deterministic for a given record:
    two successive calls on the same input produce byte-identical output.
    """

    def build(
        self,
        record: DecisionRecord,
        rollback_events: Optional[list[dict[str, Any]]] = None,
    ) -> list[TimelineEntry]:
        """Merge every timestamped source into a single sorted list.

        Args:
            record: The DecisionRecord produced by the main pipeline.
            rollback_events: Optional rollback log entries to splice in
                             (format: dicts with ``unblocked_at``, ``ip``).

        Returns:
            Entries sorted by timestamp_utc ascending. Ties broken by source.
        """
        entries: list[TimelineEntry] = []
        entries.extend(self._alert_entry(record.alert))
        entries.extend(self._process_entries(record))
        entries.extend(self._sysmon_entries(record))
        entries.extend(self._windows_event_entries(record))
        entries.extend(self._file_entries(record))
        entries.extend(self._action_entries(record))
        if rollback_events:
            entries.extend(self._rollback_entries(rollback_events))

        entries.sort(key=lambda e: (e.timestamp_utc, e.source))
        return entries

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def _alert_entry(self, alert: SuricataAlert) -> list[TimelineEntry]:
        return [
            TimelineEntry(
                timestamp_utc=alert.timestamp.astimezone(timezone.utc).isoformat(),
                source="alert",
                description=(
                    f"Suricata alert SID={alert.alert_signature_id} "
                    f"{alert.src_ip}:{alert.src_port} -> "
                    f"{alert.dest_ip}:{alert.dest_port} "
                    f"({alert.alert_signature})"
                ),
                details={
                    "signature": alert.alert_signature,
                    "signature_id": alert.alert_signature_id,
                    "severity": alert.alert_severity.value,
                    "src_ip": alert.src_ip,
                    "dest_ip": alert.dest_ip,
                    "src_port": alert.src_port,
                    "dest_port": alert.dest_port,
                    "proto": alert.proto,
                },
            )
        ]

    def _process_entries(self, record: DecisionRecord) -> list[TimelineEntry]:
        fr = record.forensic_result
        if fr is None:
            return []
        out: list[TimelineEntry] = []
        for proc in getattr(fr, "suspect_processes", []) or []:
            if not isinstance(proc, dict):
                continue
            # psutil does not expose create_time via process_iter info by
            # default, so this is often absent. We still emit an entry
            # pegged to the alert time so the process shows up.
            ts = _parse_create_time(proc.get("create_time")) or record.alert.timestamp
            out.append(
                TimelineEntry(
                    timestamp_utc=ts.astimezone(timezone.utc).isoformat(),
                    source="process",
                    description=(
                        f"Suspect process PID={proc.get('pid')} "
                        f"{proc.get('name', '')} cmd={proc.get('cmdline', '')}"
                    ),
                    details={k: v for k, v in proc.items() if k != "raw_event"},
                )
            )
        return out

    def _sysmon_entries(self, record: DecisionRecord) -> list[TimelineEntry]:
        fr = record.forensic_result
        if fr is None:
            return []
        out: list[TimelineEntry] = []
        for ev in getattr(fr, "sysmon_events", []) or []:
            ts = getattr(ev, "timestamp", None) or record.alert.timestamp
            if isinstance(ts, datetime):
                ts_iso = ts.astimezone(timezone.utc).isoformat()
            else:
                ts_iso = str(ts)
            out.append(
                TimelineEntry(
                    timestamp_utc=ts_iso,
                    source="sysmon",
                    description=f"Sysmon event {getattr(ev, 'event_id', '?')}",
                    details={
                        "event_id": getattr(ev, "event_id", None),
                        "description": getattr(ev, "description", ""),
                    },
                )
            )
        return out

    def _windows_event_entries(self, record: DecisionRecord) -> list[TimelineEntry]:
        fr = record.forensic_result
        if fr is None:
            return []
        out: list[TimelineEntry] = []
        for ev in getattr(fr, "windows_events", []) or []:
            if not isinstance(ev, dict):
                continue
            ts_raw = ev.get("TimeCreated") or ev.get("timestamp")
            try:
                ts = datetime.fromisoformat(str(ts_raw)) if ts_raw else record.alert.timestamp
            except ValueError:
                ts = record.alert.timestamp
            out.append(
                TimelineEntry(
                    timestamp_utc=ts.astimezone(timezone.utc).isoformat(),
                    source="windows_event",
                    description=f"Windows Event {ev.get('Id')}: {ev.get('Message', '')[:120]}",
                    details=ev,
                )
            )
        return out

    def _file_entries(self, record: DecisionRecord) -> list[TimelineEntry]:
        fr = record.forensic_result
        if fr is None:
            return []
        out: list[TimelineEntry] = []
        for sf in getattr(fr, "suspicious_files", []) or []:
            if not isinstance(sf, dict):
                continue
            ts = _parse_mtime(sf.get("modified")) or record.alert.timestamp
            out.append(
                TimelineEntry(
                    timestamp_utc=ts.astimezone(timezone.utc).isoformat(),
                    source="file",
                    description=f"Suspicious file {sf.get('path', '')} ({sf.get('size', 0)} B)",
                    details=sf,
                )
            )
        return out

    def _action_entries(self, record: DecisionRecord) -> list[TimelineEntry]:
        actions = record.actions_taken or []
        out: list[TimelineEntry] = []
        for action in actions:
            if not isinstance(action, ResponseAction):
                continue
            ts = action.executed_at or record.alert.timestamp
            out.append(
                TimelineEntry(
                    timestamp_utc=ts.astimezone(timezone.utc).isoformat(),
                    source="responder",
                    description=(
                        f"Action {action.action_type.value} "
                        f"target={action.target_ip or action.target_process_id} "
                        f"success={action.success}"
                    ),
                    details={
                        "action_type": action.action_type.value,
                        "target_ip": action.target_ip,
                        "target_process_id": action.target_process_id,
                        "block_duration_hours": action.block_duration_hours,
                        "success": action.success,
                        "error_message": action.error_message,
                    },
                )
            )
        return out

    def _rollback_entries(self, events: list[dict[str, Any]]) -> list[TimelineEntry]:
        out: list[TimelineEntry] = []
        for ev in events:
            ts_raw = ev.get("unblocked_at") or ev.get("timestamp")
            try:
                ts = datetime.fromisoformat(str(ts_raw)) if ts_raw else None
            except ValueError:
                ts = None
            if ts is None:
                continue
            out.append(
                TimelineEntry(
                    timestamp_utc=ts.astimezone(timezone.utc).isoformat(),
                    source="rollback",
                    description=f"User rollback: {ev.get('ip', '?')}",
                    details=ev,
                )
            )
        return out


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def to_plaso_csv(entries: list[TimelineEntry]) -> str:
    """Plaso-compatible CSV (Timesketch loads this directly)."""
    lines = [_PLASO_HEADER]
    for entry in entries:
        # Escape any embedded quotes in the description.
        msg = entry.description.replace('"', "'")
        lines.append(
            f"{entry.timestamp_utc},Event,{entry.source},{entry.source}," f'"{msg}",wardsoar,'
        )
    return "\n".join(lines) + "\n"


def to_json_list(entries: list[TimelineEntry]) -> list[dict[str, Any]]:
    """Plain JSON representation for technical report embedding."""
    return [asdict(e) for e in entries]
