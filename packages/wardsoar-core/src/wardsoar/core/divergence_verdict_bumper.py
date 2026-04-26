"""Stateless verdict-bumping helper for divergent dual-Suricata alerts.

When a flow is observed by only one of two Suricata instances and the
:class:`~wardsoar.core.models.DivergenceFindings` produced by the
``DivergenceInvestigator`` cannot pin a benign topological reason on
the divergence (loopback, VPN-terminated-on-PC, LAN-only traffic), the
verdict produced by the Analyzer is escalated by one notch on the
``BENIGN -> SUSPICIOUS -> CONFIRMED`` ladder. The same escalation
applies when the local Suricata was found dead during the event window
— a high-signal failure mode that often masks real attacks (operator
disabled the IDS, IDS crashed, or — most concerning — an attacker
killed it).

The escalation is intentionally **one notch only**. Q3 doctrine
(``project_dual_suricata_sync.md``) treats divergence as a
*confidence-tilting* signal, not a verdict in itself: the Analyzer's
verdict remains the source of truth, the bump merely shifts the
risk-tolerance threshold.

This module is a **pure helper**: no I/O, no state, no side effects,
no logging beyond DEBUG/INFO. The Pipeline calls
:func:`bump_verdict` after the Analyzer (stage 9) and before the
Responder (stage 10) — see ``main.py`` ``Pipeline._process_alert``.

See ``project_dual_suricata_sync.md`` Q3 for the full doctrine.
"""

from __future__ import annotations

import logging
from typing import Optional

from wardsoar.core.models import DivergenceFindings, ThreatVerdict

_LOGGER = logging.getLogger(__name__)


# Q3 ladder: the verdict on the left is bumped to the verdict on the
# right when a divergence-bump is warranted.
#
# CONFIRMED is intentionally absent — it is already the maximum, no
# bump applies. INCONCLUSIVE is also absent: escalating "we don't
# know" to "we're sure it's a threat" is not defensible from a
# fail-safe standpoint, so an INCONCLUSIVE verdict on a divergent
# alert remains INCONCLUSIVE (the operator review queue picks it up).
_BUMP_LADDER: dict[ThreatVerdict, ThreatVerdict] = {
    ThreatVerdict.BENIGN: ThreatVerdict.SUSPICIOUS,
    ThreatVerdict.SUSPICIOUS: ThreatVerdict.CONFIRMED,
}

# Explanations that warrant a verdict bump.
#
# - ``unexplained``: no benign reason was found for the divergence.
#   The local Suricata is silent for an unknown cause — could be a
#   blind spot, a partial crash, or — worst-case — an attacker
#   evading detection on the local agent.
# - ``suricata_local_dead``: the local Suricata process is not
#   running. The external source caught a flow the local agent
#   could not have seen — but the operator should know the local
#   IDS was down, and the verdict is escalated to ensure the
#   incident is reviewed.
#
# Any other explanation (``loopback_traffic``, ``vpn_traffic``,
# ``lan_only_traffic``) captures a benign topological reason and
# does not trigger the bump.
_BUMP_TRIGGER_EXPLANATIONS: frozenset[str] = frozenset({"unexplained", "suricata_local_dead"})


def should_bump(findings: Optional[DivergenceFindings]) -> bool:
    """Return True when ``findings`` warrant a verdict bump.

    Q3 rule:
      - unexplained divergence       -> bump
      - local Suricata dead          -> bump
      - loopback / VPN / LAN-only    -> no bump
      - non-divergent corroboration  -> no bump
      - findings is None             -> no bump

    The "non-divergent corroboration" case is detected by an empty
    ``checks_run`` list: when the corroboration is SINGLE_SOURCE or
    MATCH_CONFIRMED the ``DivergenceInvestigator`` short-circuits
    and returns a default :class:`DivergenceFindings()` with
    ``checks_run=[]``. The defaults happen to look like "unexplained"
    (``is_explained=False``, ``explanation='unexplained'``), so this
    guard is essential to avoid spurious bumps on alerts that were
    never actually investigated.
    """
    if findings is None:
        return False
    # Empty checks_run = no investigation ran; defaults must not
    # be interpreted as "unexplained divergence".
    if not findings.checks_run:
        return False
    return findings.explanation in _BUMP_TRIGGER_EXPLANATIONS


def bump_verdict(
    verdict: ThreatVerdict,
    findings: Optional[DivergenceFindings],
) -> ThreatVerdict:
    """Apply the Q3 divergence-bump to a verdict.

    Pure function. Returns the bumped verdict when the findings
    warrant a bump *and* the input verdict has a logical successor;
    otherwise returns the input verdict unchanged.

    Examples (when findings warrant a bump):

    - ``bump_verdict(BENIGN, findings)``       -> ``SUSPICIOUS``
    - ``bump_verdict(SUSPICIOUS, findings)``   -> ``CONFIRMED``
    - ``bump_verdict(CONFIRMED, findings)``    -> ``CONFIRMED``  (already max)
    - ``bump_verdict(INCONCLUSIVE, findings)`` -> ``INCONCLUSIVE``  (no logical step)

    When the findings do not warrant a bump (None, empty checks_run,
    benign explanation), the verdict is returned unchanged regardless
    of its level.

    The function emits a single INFO log line on every actual bump,
    and a DEBUG line when the verdict has no logical successor.
    Callers must not call this for non-divergent corroborations —
    the empty-findings guard makes that safe, but the explicit
    contract keeps Activity-tab annotations accurate.
    """
    if not should_bump(findings):
        return verdict
    bumped = _BUMP_LADDER.get(verdict)
    if bumped is None:
        # CONFIRMED (already at the top) or INCONCLUSIVE (no logical
        # step above) — return the input unchanged.
        _LOGGER.debug(
            "divergence_bumper: verdict %s has no logical bump; leaving unchanged",
            verdict.value,
        )
        return verdict
    # findings is non-None here (should_bump returned True). Pull
    # the explanation for the log line.
    explanation = findings.explanation if findings is not None else "none"
    _LOGGER.info(
        "divergence_bumper: bumping verdict %s -> %s (explanation=%s)",
        verdict.value,
        bumped.value,
        explanation,
    )
    return bumped


__all__ = [
    "bump_verdict",
    "should_bump",
]
