"""N-source corroboration — replacement for the dual-source ``SourceCorroboration`` enum.

The pre-v0.24 ``SourceCorroboration`` enum captured the cross-check
between exactly **two** Suricata sources (external = Netgate, local =
Windows Suricata) with hard-coded transitions (``MATCH_PENDING`` →
``MATCH_CONFIRMED`` / ``DIVERGENCE_A`` / ``DIVERGENCE_B``). That
shape ran out of room as soon as we wanted three sources.

This module replaces the enum with a richer model that scales to any
number of sources:

* :class:`CorroborationVerdict` — coarse verdict (PENDING /
  SINGLE_SOURCE / NO_DATA / MATCH_FULL / MATCH_MAJORITY / DIVERGENCE).
* :class:`CorroborationStatus` — per-source breakdown (which sources
  agreed, which dissented, which stayed silent) plus the consensus
  verdict string and the threshold ratio used to compute it.

Two corroboration modes are supported (Q2 of the N-source refactor
memo):

* **Strict (β, default)** — ``threshold_ratio=1.0``. Every observing
  source must agree, otherwise the verdict is :data:`DIVERGENCE` and
  the worst-case verdict applies downstream.
* **Configurable threshold (γ)** — ``threshold_ratio<1.0``. The
  operator sets a K/N ratio (e.g. ``2/3``) below which dissent is
  tolerated. Useful for production setups where one noisy source
  must not drive the verdict alone.

The dataclass is **frozen** (immutable). Status updates create new
instances — keeps the audit trail clean and avoids race conditions
between the correlator producer and downstream consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class CorroborationVerdict(str, Enum):
    """Coarse verdict produced by the N-source correlator.

    The verdict is computed when the reconciliation window closes
    (or when the correlator decides a flow is settled, e.g. all
    configured sources have reported). Downstream the verdict drives
    the divergence investigator + verdict bumper.
    """

    PENDING = "pending"
    """The reconciliation window is still open. At least one source
    has reported but we are waiting for the others. Surfaced briefly
    on the alert; downstream consumers must tolerate the tag changing
    out-of-band when the window closes."""

    SINGLE_SOURCE = "single_source"
    """Only one Suricata source is configured. No corroboration
    possible by definition; the verdict mirrors that source's verdict
    verbatim."""

    NO_DATA = "no_data"
    """The window closed without any source reporting on this flow.
    Should not normally happen — a flow that no source saw is not an
    alert at all — but the value exists so the type is total."""

    MATCH_FULL = "match_full"
    """Every source that saw the flow agreed on the verdict, AND no
    source stayed silent. Highest possible confidence."""

    MATCH_MAJORITY = "match_majority"
    """The threshold ratio was met (K observing sources out of N
    agreed) but at least one source dissented or stayed silent. The
    consensus verdict applies; the dissenters are recorded for
    audit."""

    DIVERGENCE = "divergence"
    """The threshold was NOT met — no clear consensus. The
    divergence investigator runs to find a topological explanation
    (loopback, VPN, LAN-only, dead source). Worst-case verdict
    applies pending the investigation."""


@dataclass(frozen=True)
class CorroborationStatus:
    """Per-source breakdown of how N Suricata sources observed a flow.

    Replaces the ``SourceCorroboration`` enum. Carries the full
    per-source picture so the operator (and future audits) can see
    exactly which sources agreed, dissented, or stayed silent — not
    just the headline verdict.

    The dataclass is frozen — mutations during the reconciliation
    window create new instances via :meth:`with_observation` or
    :meth:`finalised`. This keeps the audit trail clean and makes
    the type safe to share across async boundaries.

    Attributes:
        verdict: Coarse :class:`CorroborationVerdict` derived from
            the per-source observations and the threshold ratio.
        matching_sources: Names of sources that saw the flow and
            agreed on the consensus verdict.
        dissenting_sources: Names of sources that saw the flow but
            emitted a different verdict from the consensus.
        silent_sources: Names of sources that did NOT see the flow
            within the reconciliation window.
        consensus_verdict: The verdict string the matching sources
            agreed on (e.g. ``"alert"``, ``"match"``). ``None`` when
            the verdict is :data:`PENDING`, :data:`NO_DATA`, or
            :data:`DIVERGENCE`.
        threshold_ratio: K/N ratio used to compute the verdict.
            ``1.0`` (default) means strict — every observing source
            must agree. ``0.5`` would mean simple majority.
        window_opened_at: Timestamp when the first source reported.
            Used by the correlator to know when to close the window.
            ``None`` when the status is the initial empty state.
        window_closed_at: Timestamp when the window expired (or all
            configured sources had reported). ``None`` while the
            verdict is :data:`PENDING`.
    """

    verdict: CorroborationVerdict
    matching_sources: tuple[str, ...] = field(default_factory=tuple)
    dissenting_sources: tuple[str, ...] = field(default_factory=tuple)
    silent_sources: tuple[str, ...] = field(default_factory=tuple)
    consensus_verdict: Optional[str] = None
    threshold_ratio: float = 1.0
    window_opened_at: Optional[datetime] = None
    window_closed_at: Optional[datetime] = None

    @property
    def observing_sources(self) -> tuple[str, ...]:
        """Sources that actually saw the flow (matching ∪ dissenting)."""
        return self.matching_sources + self.dissenting_sources

    @property
    def total_sources(self) -> int:
        """Total number of sources tracking this flow (observing + silent)."""
        return len(self.matching_sources) + len(self.dissenting_sources) + len(self.silent_sources)

    @property
    def is_unanimous(self) -> bool:
        """True when every configured source saw the flow and agreed."""
        return self.verdict == CorroborationVerdict.MATCH_FULL

    @property
    def has_dissent(self) -> bool:
        """True when at least one observing source disagreed with the consensus."""
        return len(self.dissenting_sources) > 0

    @property
    def has_silence(self) -> bool:
        """True when at least one configured source did not report."""
        return len(self.silent_sources) > 0

    @property
    def is_divergent(self) -> bool:
        """True when the verdict requires the divergence investigator to run."""
        return self.verdict == CorroborationVerdict.DIVERGENCE

    @property
    def is_terminal(self) -> bool:
        """True when the verdict is settled (window closed, no more updates expected).

        Pending statuses are not terminal — the correlator may still
        receive late observations within the reconciliation window.
        """
        return self.verdict not in (CorroborationVerdict.PENDING,)


def derive_verdict(
    matching: int,
    dissenting: int,
    silent: int,
    threshold_ratio: float,
) -> CorroborationVerdict:
    """Derive the coarse verdict from per-bucket counts and the threshold.

    Pure function — no side effects, no datetime, no I/O. Pulled out
    of :class:`CorroborationStatus` so it is trivially testable in
    isolation and so the correlator can call it from its hot path
    without constructing a status instance just to peek at the
    result.

    Ratio semantics: the ratio is computed as ``matching / total``
    (NOT ``matching / observing``). A silent source counts as a
    failed corroboration just like a dissenting one — both fail to
    confirm. In strict mode (``threshold_ratio=1.0``) every
    configured source must therefore both observe AND agree;
    anything less yields :data:`DIVERGENCE`. Lax thresholds
    (``< 1.0``) trade strictness for noise tolerance.

    Edge cases (kept explicit so the table is auditable):

    * ``matching + dissenting + silent == 0`` → :data:`NO_DATA` —
      no source reported and no source is configured.
    * ``observing == 0`` AND ``silent > 0`` → :data:`NO_DATA` —
      every configured source stayed silent; the alert nobody saw
      cannot be corroborated.
    * ``total == 1`` AND ``silent == 0`` → :data:`SINGLE_SOURCE` —
      only one source is configured; corroboration impossible by
      definition.
    * ``dissenting == 0`` AND ``silent == 0`` AND ``matching >= 1``
      → :data:`MATCH_FULL` — every configured source agreed.
    * ``matching / total >= threshold_ratio`` (with at least one
      silent or dissenting) → :data:`MATCH_MAJORITY`.
    * Otherwise → :data:`DIVERGENCE` — threshold not met.

    Args:
        matching: Number of sources that agreed on the consensus verdict.
        dissenting: Number of sources that disagreed.
        silent: Number of configured sources that did not report.
        threshold_ratio: K/N ratio required for MATCH_MAJORITY,
            computed as ``matching / total``. ``1.0`` (strict) means
            every configured source must observe and agree.

    Returns:
        The :class:`CorroborationVerdict` matching the inputs.
    """
    if matching < 0 or dissenting < 0 or silent < 0:
        raise ValueError("counts must be non-negative")
    if not 0.0 < threshold_ratio <= 1.0:
        raise ValueError("threshold_ratio must be in (0.0, 1.0]")

    total = matching + dissenting + silent
    if total == 0:
        return CorroborationVerdict.NO_DATA

    observing = matching + dissenting
    if observing == 0:
        return CorroborationVerdict.NO_DATA

    if total == 1 and silent == 0:
        return CorroborationVerdict.SINGLE_SOURCE

    if dissenting == 0 and silent == 0:
        return CorroborationVerdict.MATCH_FULL

    ratio = matching / total
    if ratio >= threshold_ratio:
        return CorroborationVerdict.MATCH_MAJORITY

    return CorroborationVerdict.DIVERGENCE
