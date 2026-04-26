"""Data models for WardSOAR pipeline.

All data structures used across modules are defined here
as Pydantic models for validation and serialization.

Note on ``dict[str, Any]`` usage:
    Several fields store heterogeneous data from external sources
    (Sysmon events, netstat output, registry entries, raw EVE JSON).
    Typed sub-models will be introduced when schemas stabilise.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SuricataAlertSeverity(int, Enum):
    """Suricata alert severity levels."""

    HIGH = 1
    MEDIUM = 2
    LOW = 3


class ThreatVerdict(str, Enum):
    """Final threat assessment verdict."""

    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class BlockAction(str, Enum):
    """Type of blocking action taken."""

    IP_BLOCK = "ip_block"
    IP_PORT_BLOCK = "ip_port_block"
    PROCESS_KILL = "process_kill"
    NONE = "none"


class WardMode(str, Enum):
    """Operating mode of the WardSOAR responder.

    The three modes span a spectrum of aggressiveness by *inverting
    the burden of proof* between each step:

    - ``MONITOR``: never blocks. Pipeline runs end-to-end, verdicts are
      logged, but no firewall action is taken. Used during initial
      rollout to observe the system without risking connectivity.

    - ``PROTECT``: burden of proof is on the *threat*. The Responder
      blocks only when Opus returns a CONFIRMED verdict with
      confidence at or above ``confidence_threshold`` (default 0.70).
      Any other verdict — BENIGN, SUSPICIOUS, INCONCLUSIVE, or a
      CONFIRMED below the threshold — is let through.

    - ``HARD_PROTECT``: burden of proof is on the *benignity*. The
      Responder blocks *unless* Opus returns BENIGN with confidence
      at or above ``hard_protect_benign_threshold`` (default 0.99).
      Anything else — including CONFIRMED, SUSPICIOUS, INCONCLUSIVE,
      a low-confidence BENIGN, or an Opus API failure — triggers a
      block. Designed for a threat landscape where the operator
      accepts a steady trickle of false positives in exchange for
      near-zero false negatives, and relies on the 1-click rollback
      to recover connectivity when a legitimate flow is caught.

    The safety guardrails (whitelist, trusted-temp flap prevention,
    rate limiter) apply to all three modes identically — HARD_PROTECT
    can never override a whitelist decision.
    """

    MONITOR = "monitor"
    PROTECT = "protect"
    HARD_PROTECT = "hard_protect"

    @classmethod
    def parse(cls, value: Any) -> "WardMode":
        """Coerce a config value (string, bool, or enum) into a WardMode.

        Accepts legacy ``dry_run: bool`` fields written by v<=0.5.4
        configs so the migration is transparent:

        * ``dry_run=True``  → :attr:`MONITOR`
        * ``dry_run=False`` → :attr:`PROTECT`
        * any recognised mode string (case-insensitive, with or
          without underscores/dashes) → the matching enum member
        * anything else → :attr:`MONITOR` (fail-safe: never block
          when the config is unparseable).
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return cls.MONITOR if value else cls.PROTECT
        if isinstance(value, str):
            normalised = value.strip().lower().replace("-", "_").replace(" ", "_")
            for member in cls:
                if member.value == normalised:
                    return member
        return cls.MONITOR


class SuricataAlert(BaseModel):
    """Parsed Suricata EVE JSON alert."""

    timestamp: datetime
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    alert_signature: str
    alert_signature_id: int
    alert_severity: SuricataAlertSeverity
    alert_category: str = ""
    alert_action: str = "allowed"
    payload: Optional[str] = None
    flow_id: Optional[int] = None
    raw_event: dict[str, Any] = Field(default_factory=dict)


class NetworkContext(BaseModel):
    """Network context gathered around an alert."""

    active_connections: list[dict[str, Any]] = Field(default_factory=list)
    dns_cache: list[dict[str, Any]] = Field(default_factory=list)
    arp_cache: list[dict[str, Any]] = Field(default_factory=list)
    related_alerts: list[SuricataAlert] = Field(default_factory=list)
    ip_reputation: Optional[IPReputation] = None


class IPReputation(BaseModel):
    """IP reputation data from external sources."""

    ip: str
    abuseipdb_score: Optional[int] = None
    virustotal_detections: Optional[int] = None
    otx_pulse_count: Optional[int] = None
    is_known_malicious: bool = False
    sources: list[str] = Field(default_factory=list)


class SysmonEvent(BaseModel):
    """Parsed Sysmon event."""

    event_id: int
    timestamp: datetime
    description: str
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    file_hash: Optional[str] = None
    raw_event: dict[str, Any] = Field(default_factory=dict)


class ForensicResult(BaseModel):
    """Results of local forensic analysis."""

    suspect_processes: list[dict[str, Any]] = Field(default_factory=list)
    sysmon_events: list[SysmonEvent] = Field(default_factory=list)
    suspicious_files: list[dict[str, Any]] = Field(default_factory=list)
    registry_anomalies: list[dict[str, Any]] = Field(default_factory=list)
    windows_events: list[dict[str, Any]] = Field(default_factory=list)
    process_tree: list[dict[str, Any]] = Field(default_factory=list)


class VirusTotalResult(BaseModel):
    """VirusTotal analysis result."""

    file_hash: str
    file_name: Optional[str] = None
    detection_count: int = 0
    total_engines: int = 0
    detection_ratio: float = 0.0
    is_malicious: bool = False
    threat_labels: list[str] = Field(default_factory=list)
    lookup_type: str = "hash"  # "hash" or "file_upload"


class ThreatAnalysis(BaseModel):
    """Claude API threat analysis result."""

    verdict: ThreatVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_actions: list[str] = Field(default_factory=list)
    ioc_summary: str = ""
    false_positive_indicators: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """Action taken in response to a confirmed threat."""

    action_type: BlockAction
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    target_process_id: Optional[int] = None
    pfsense_rule_id: Optional[str] = None
    block_duration_hours: int = 24
    success: bool = False
    error_message: Optional[str] = None
    executed_at: Optional[datetime] = None
    # True when the action was a no-op because the target was already
    # in the desired state (e.g. IP already on the pfSense blocklist).
    # The audit trail records a successful outcome but no state change
    # happened — the rate limiter is NOT charged, the block tracker is
    # NOT updated, and no duplicate log line is emitted. Aligns with
    # CLAUDE.md §3 (idempotence flag).
    idempotent: bool = False


class DecisionRecord(BaseModel):
    """Complete audit record for a single alert processing cycle."""

    record_id: str
    timestamp: datetime
    alert: SuricataAlert
    network_context: Optional[NetworkContext] = None
    forensic_result: Optional[ForensicResult] = None
    virustotal_results: list[VirusTotalResult] = Field(default_factory=list)
    analysis: Optional[ThreatAnalysis] = None
    actions_taken: list[ResponseAction] = Field(default_factory=list)
    pipeline_duration_ms: int = 0
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Dual-Suricata source corroboration (configs 3 and 5)
# ---------------------------------------------------------------------------


class SourceCorroboration(str, Enum):
    """Status of an alert relative to dual-Suricata source comparison.

    Tagged on every alert by the :class:`DualSourceCorrelator` (see
    ``project_dual_suricata_sync.md`` memo for the doctrine). Mono-source
    configurations stay on :data:`SINGLE_SOURCE`; dual-source configs
    transition the tag through pending → confirmed/diverged states as
    the reconciliation window closes.

    Lifecycle:
        ``MATCH_PENDING``      → ``MATCH_CONFIRMED``  (both sources saw it)
                              \\→ ``DIVERGENCE_A``    (window expired, only external)
        ``DIVERGENCE_PENDING`` → ``MATCH_CONFIRMED``  (other source caught up)
                              \\→ ``DIVERGENCE_B``    (window expired, only local)

    The pipeline emits a verdict on the first sighting (with the
    ``_PENDING`` tag); the tag is overwritten when the window closes.
    Downstream consumers must therefore tolerate alerts whose tag
    changes out-of-band.
    """

    SINGLE_SOURCE = "single_source"
    """Only one Suricata source is configured. No corroboration possible."""

    MATCH_PENDING = "match_pending"
    """External source saw it; we're within the reconciliation window
    waiting for the local source to confirm."""

    DIVERGENCE_PENDING = "divergence_pending"
    """Local source saw it; we're within the reconciliation window
    waiting for the external source to confirm."""

    MATCH_CONFIRMED = "match_confirmed"
    """Both sources observed the same flow within the reconciliation
    window. Local process context (PID, Sysmon) enriches the verdict."""

    DIVERGENCE_A = "divergence_a"
    """Reconciliation window expired and only the external source
    saw the flow. May indicate LAN-only traffic, a stopped local
    Suricata, or — alarmingly — traffic the local Suricata cannot see
    (rootkit cloaking). Triggers :class:`DivergenceFindings` analysis."""

    DIVERGENCE_B = "divergence_b"
    """Reconciliation window expired and only the local source saw
    the flow. Often legitimate (loopback, VPN-terminated-on-PC,
    LAN-internal traffic) but warrants investigation to confirm the
    external Suricata is not silently dropping events."""


class DivergenceFindings(BaseModel):
    """Output of the ``DivergenceInvestigator`` for a divergent alert.

    Attached to alerts whose :class:`SourceCorroboration` resolved to
    :data:`SourceCorroboration.DIVERGENCE_A` or
    :data:`SourceCorroboration.DIVERGENCE_B`. Captures the result of
    six fail-safe checks run in parallel, plus a synthesised
    ``explanation`` string that drives the verdict-bumping logic
    (Q3 doctrine: bump verdict only when ``is_explained=False`` or
    ``explanation="suricata_local_dead"``).

    All checks are best-effort: a failed check returns its default
    (``False`` / ``"unknown"`` / ``[]``) and the others continue.
    The investigator never raises to the pipeline.

    See ``project_dual_suricata_sync.md`` Q2 for the precise check
    semantics and ``project_dual_suricata_sync.md`` Q3 for how the
    fields drive the verdict bumping decision.
    """

    checks_run: list[str] = Field(default_factory=list)
    """Names of checks that were attempted: ``snapshot``, ``sysmon``,
    ``suricata_alive``, ``loopback``, ``vpn``, ``lan_only``. A check
    that errored or skipped (e.g. Sysmon not installed) is *not*
    listed here — the field reports successful runs only."""

    is_explained: bool = False
    """True when at least one check found a topological reason that
    explains the divergence (loopback, VPN, LAN-only) or a known
    failure mode (suricata_local_dead). False means the divergence
    is unexplained — drives the verdict bump."""

    explanation: str = "unexplained"
    """Short token describing the explanation. Possible values:
    ``loopback_traffic``, ``vpn_traffic``, ``lan_only_traffic``,
    ``suricata_local_dead``, ``unexplained``. Only the first
    matching cause is recorded — the investigator stops scoring
    once it has a positive answer."""

    snapshot_summary: dict[str, Any] = Field(default_factory=dict)
    """Output of check (a). Holds the PIDs and connections seen in
    the ``NetConnectionsBuffer`` at the time of the event. Empty
    dict when the snapshot was unavailable (process exited, buffer
    not yet primed)."""

    sysmon_correlation: list[dict[str, Any]] = Field(default_factory=list)
    """Output of check (b). Up to 100 Sysmon events (Process Create
    + Network Connection) within ±15 s of the alert timestamp.
    Empty list when Sysmon is not installed, the query timed out,
    or no correlated events were found."""

    suricata_local_state: str = "unknown"
    """Output of check (c). One of ``running``, ``dead``, ``unknown``.
    ``dead`` means the Suricata process is not running — a
    high-signal divergence cause that bumps the verdict."""

    is_loopback: bool = False
    """Output of check (d). True when both ``src_ip`` and ``dest_ip``
    resolve to a loopback address (``127.0.0.1``, ``::1``) or to
    a local interface IP."""

    is_vpn: bool = False
    """Output of check (e). True when the host has at least one
    active VPN-style interface (TUN/TAP/WireGuard/OpenVPN)."""

    is_lan_only: bool = False
    """Output of check (f). True when both ``src_ip`` and ``dest_ip``
    are within RFC1918 LAN ranges and the WAN is on a different
    subnet (no transit through the WAN, hence the external Suricata
    on the WAN side never sees the flow)."""


# Fix forward reference for NetworkContext
NetworkContext.model_rebuild()
