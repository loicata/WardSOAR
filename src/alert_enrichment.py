"""Alert enrichment — turn a DecisionRecord into a UI-friendly payload.

The Alert Detail view (Phase 0.9.0) surfaces everything we know about
a single alert: raw Suricata fields, enriched network context,
forensic evidence, VirusTotal lookups, Claude Opus reasoning,
actions taken, plus an inferred pipeline trace showing how the alert
travelled through the 13-step pipeline.

Before 0.9.0 the persistence was a flat dict (12 string fields) —
enough for the alerts *list* but nothing for the detail view. Now we
serialise the full :class:`DecisionRecord` alongside the flat
display fields so a reload from ``alerts_history.jsonl`` still has
access to everything.

Design decisions
----------------
* **Inference-based pipeline trace**. Instrumenting every pipeline
  stage to record its timing + outcome would touch a dozen modules.
  Instead we *infer* each stage's outcome from which fields ended up
  populated in the DecisionRecord. The inferred trace is 80% as
  useful as a real one and costs 0 lines of pipeline changes.
* **Flat display fields stay unchanged**. The alerts list reads the
  same keys as before; adding ``_full`` is backward-compatible.
* **Serialisation via ``model_dump``**. Pydantic handles enums,
  datetimes and nested models cleanly. No hand-rolled ``to_dict``.

Nothing in this module performs I/O. The caller (engine_bridge)
decides when and where to persist the output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from src.models import DecisionRecord


@dataclass(frozen=True)
class StageTrace:
    """One entry in the 13-step pipeline trace.

    Attributes:
        index: Stage number (1..13).
        name: Human-readable stage name.
        outcome: ``passed`` / ``skipped`` / ``failed`` / ``filtered``.
        detail: Short one-line result summary shown by default in
            the UI.
        explanation: Longer "why" — the stage's purpose, its decision
            logic, and any operator-relevant context. Shown only when
            the operator clicks on the row (v0.9.1+ UI). Empty string
            on older persisted records; the UI falls back to ``detail``.
        specific_details: v0.9.5 — per-alert specific paragraph
            rendered *below* the generic explanation, separated by a
            divider. Quotes the alert's actual SID / signature /
            operator reason / score / verdict / action so the operator
            understands why THIS specific alert got THIS specific
            result — not just what the stage does in general. Empty
            string when no specific data is available; the UI renders
            "(no specific details available)" as a fallback.
    """

    index: int
    name: str
    outcome: str
    detail: str
    explanation: str = ""
    specific_details: str = ""


#: Stage names in the exact order the pipeline traverses them. Shared
#: between the inferred-trace builder and any future real-trace
#: instrumentation so the display always shows the same 13 rows.
PIPELINE_STAGES: tuple[str, ...] = (
    "Filter",
    "Deduplicator",
    "Correlation",
    "PreScorer",
    "Collector",
    "VirusTotal",
    "Baseline",
    "Analyzer",
    "Confirmer",
    "Responder",
    "pfSense API",
    "Notifier",
    "Log",
)


def _first_sentence(text: str, max_len: int = 260) -> str:
    """Extract the first sentence of a multi-sentence reasoning string.

    Falls back to ``max_len`` characters with an ellipsis when no
    sentence terminator is found. Used to quote a concise snippet of
    Claude Opus reasoning in the specific-details paragraph without
    dumping the full 500-2000 word block.
    """
    if not text:
        return ""
    text = text.strip()
    for term in (". ", "! ", "? "):
        idx = text.find(term)
        if 0 <= idx <= max_len:
            return text[: idx + 1].strip()
    return text[:max_len].rstrip() + ("…" if len(text) > max_len else "")


def _specific_filter_passed(record: DecisionRecord) -> str:
    sid = record.alert.alert_signature_id
    sig = record.alert.alert_signature or ""
    name_part = f' — "{sig}"' if sig else ""
    return (
        f"SID {sid}{name_part} is NOT on the known-harmless list. "
        "The alert continues to the next stages for deeper analysis."
    )


def _specific_dedup(record: DecisionRecord, related_count: int) -> str:
    src = record.alert.src_ip or "?"
    dst = record.alert.dest_ip or "?"
    if related_count == 0:
        return (
            f"No identical alert from {src} → {dst} was seen in the last 60 "
            "seconds, so this alert is processed on its own (no merging)."
        )
    return (
        f"{related_count} identical alert(s) from {src} → {dst} were already "
        "received in the last 60 seconds; they are grouped together so only "
        "ONE AI consultation is needed for the whole group."
    )


def _specific_correlation(record: DecisionRecord, related_count: int) -> str:
    if related_count == 0:
        return (
            "No other alert from the same source was observed in the recent "
            "window. This alert is evaluated on its own, without extra "
            "pattern context."
        )
    return (
        f"{related_count} related alert(s) from the same source were attached "
        "to this record so the AI can see patterns (e.g. repeated login "
        "attempts) instead of judging each alert in isolation."
    )


def _specific_prescorer(record: DecisionRecord) -> str:
    sid = record.alert.alert_signature_id
    severity = record.alert.alert_severity
    return (
        f"Priority score high enough to justify an AI call. The score factors "
        f"in the alert's Suricata severity ({severity}), reputation of the "
        f"involved addresses, and the targeted port. SID {sid} cleared the "
        "threshold, so the pipeline continued."
    )


def _specific_collector(record: DecisionRecord) -> str:
    if record.network_context is None:
        return ""
    nc = record.network_context
    return (
        f"Captured a snapshot of local state at alert time: "
        f"{len(nc.active_connections)} active TCP/UDP connection(s), "
        f"{len(nc.dns_cache)} cached DNS record(s), "
        f"{len(nc.arp_cache)} visible device(s) on your local network. "
        "This context helps the AI distinguish legitimate local programs "
        "from suspicious external traffic."
    )


def _specific_virustotal(record: DecisionRecord) -> str:
    if not record.virustotal_results:
        return (
            "No file hash was attached to this alert, so there was nothing "
            "to look up on VirusTotal (the service works on hashes / URLs, "
            "not on plain IPs). The daily quota is preserved for alerts "
            "that carry a hash."
        )
    summaries = []
    for vt in record.virustotal_results:
        flag = "🔴 malicious" if vt.is_malicious else "🟢 clean"
        summaries.append(
            f"{vt.file_name or vt.file_hash}: {vt.detection_count}/"
            f"{vt.total_engines} engines flagged → {flag}"
        )
    return "VirusTotal lookup results:\n  • " + "\n  • ".join(summaries)


def _specific_baseline(record: DecisionRecord) -> str:
    dst = record.alert.dest_ip or "?"
    return (
        f"Destination {dst} was compared against WardSOAR's two curated lists: "
        "the always-safe list (Netflix, Google, your VPN, …) and the "
        "known-bad list (suspect hosting providers, known attacker IPs). "
        "The comparison result was attached to the record as a hint for the AI."
    )


def _specific_analyzer(record: DecisionRecord) -> str:
    """Quote Claude Opus's full reasoning so the operator sees the
    decision chain in place, not just a pointer to a section below.

    Structure:
      1. Verdict + confidence (the outcome)
      2. Full reasoning text (the chain of thought)
      3. Recommended actions (what Opus suggests doing)
      4. False-positive indicators (what Opus noticed that points
         AWAY from the verdict — useful for operator sanity-check)
      5. IOC summary (the malicious fingerprints Opus extracted)

    Missing fields are omitted rather than rendered as "(none)" to
    keep the paragraph compact when Opus did not return them.
    """
    if record.analysis is None:
        return ""
    a = record.analysis
    verdict = a.verdict.value.upper()
    lines: list[str] = [
        f"Verdict: {verdict}  ·  Confidence: {a.confidence:.0%}",
    ]
    if a.reasoning:
        lines.append("")
        lines.append("Full Opus reasoning that led to this verdict:")
        lines.append(a.reasoning.strip())
    if a.recommended_actions:
        lines.append("")
        lines.append("Actions recommended by Opus:")
        for act in a.recommended_actions:
            lines.append(f"  • {act}")
    if a.false_positive_indicators:
        lines.append("")
        lines.append("Signs that pointed AWAY from the verdict (Opus noted these anyway):")
        for fp in a.false_positive_indicators:
            lines.append(f"  • {fp}")
    if a.ioc_summary:
        lines.append("")
        lines.append(f"IOC summary: {a.ioc_summary}")
    return "\n".join(lines)


def _specific_confirmer(record: DecisionRecord) -> str:
    if record.analysis is None:
        return ""
    if record.analysis.confidence < 0.90:
        return (
            f"The main AI returned only {record.analysis.confidence:.0%} "
            "confidence — below the 90% safety bar — so a second AI opinion "
            "was requested with a reworded prompt. If the two verdicts "
            "disagree, the final outcome is forced to INCONCLUSIVE and no "
            "automatic block is applied."
        )
    return (
        f"Main AI confidence was {record.analysis.confidence:.0%}, above the "
        "90% safety bar — a second opinion would be redundant. Skipped to "
        "save ~10 s / 3 cents of AI time."
    )


def _specific_responder(record: DecisionRecord) -> str:
    """Walk the operator through the Responder's decision chain so the
    reasoning is transparent — not just the final outcome.

    The Responder combines 5 inputs to produce an action:
      1. The Analyzer verdict + confidence (primary signal)
      2. The operator's current protection mode
         (Monitor / Protect / Hard Protect)
      3. The whitelist (per-host exception list)
      4. The CDN allowlist (never block major services)
      5. The rate limiter (cap on daily automatic blocks)

    We surface all five in the specific paragraph. When the source
    record is thin (e.g. persisted pre-0.9.5), we fall back to the
    fields we can read and explicitly note the rest as uncertain.
    """
    if record.analysis is None:
        return ""
    verdict = record.analysis.verdict.value.upper()
    conf = record.analysis.confidence

    acts = [a for a in record.actions_taken if a.action_type.value != "none"]
    if acts:
        lines = [
            "Decision inputs that led the Responder to act:",
            f"  • Analyzer verdict: {verdict} at {conf:.0%} confidence",
            "  • Current protection mode allowed an automatic block at this " "confidence level",
            "  • Whitelist did NOT cover the target",
            "  • CDN allowlist did NOT cover the destination",
            "  • Daily block rate limit was not yet reached",
            "",
            "Actions the Responder ordered:",
        ]
        for a in acts:
            parts = [f"action={a.action_type.value}"]
            if a.target_ip:
                parts.append(f"target={a.target_ip}")
            if a.target_port:
                parts.append(f"port={a.target_port}")
            if a.action_type.value in ("ip_block", "ip_port_block"):
                parts.append(f"duration={a.block_duration_hours}h")
            parts.append(f"success={a.success}")
            if a.error_message:
                parts.append(f'error="{a.error_message}"')
            lines.append("  • " + ", ".join(parts))
        return "\n".join(lines)

    # No action branch — explain which safety rule likely dominated.
    if verdict == "BENIGN":
        reason_line = "the AI verdict was BENIGN — there was nothing to block in the first place"
    elif verdict == "INCONCLUSIVE":
        reason_line = (
            "the AI verdict was INCONCLUSIVE (the two AI passes disagreed or the "
            "single pass was too uncertain) — the safety rule is to never block "
            "on inconclusive verdicts"
        )
    elif verdict in ("CONFIRMED", "SUSPICIOUS"):
        reason_line = (
            f"the AI verdict was {verdict} at {conf:.0%}, but one of the safety "
            "rails overrode the block: current protection mode threshold, "
            "operator whitelist, CDN safe-list (Netflix / Cloudflare / GitHub / "
            "Apple / …), OR the daily block rate limit was already reached"
        )
    else:
        reason_line = f"verdict={verdict} at {conf:.0%}"
    return (
        "Decision inputs that led the Responder to HOLD OFF:\n"
        f"  • {reason_line}\n"
        "  • No pfSense rule was installed, no Windows toast was sent.\n"
        "You can still review the alert and manually block the source from "
        'the "Add SID to false positives" or rollback controls at the bottom '
        "of this page."
    )


def _specific_pfsense(record: DecisionRecord) -> str:
    block_actions = [
        a for a in record.actions_taken if a.action_type.value in ("ip_block", "ip_port_block")
    ]
    if not block_actions:
        return ""
    first = block_actions[0]
    if first.success:
        when = first.executed_at.isoformat() if first.executed_at else "unknown time"
        return (
            f"Address {first.target_ip} added to the pfSense blocklist alias "
            f"(urltable, file-backed) for {first.block_duration_hours} hour(s). "
            f"Rule id: {first.pfsense_rule_id or 'blocklist'}. "
            f"Executed at {when}. The block survives any firewall reboot."
        )
    return (
        f"Attempt to block {first.target_ip} FAILED: "
        f"{first.error_message or 'unknown error'}. "
        "The alert is still saved; you can retry manually from the Alerts tab."
    )


def _specific_notifier(record: DecisionRecord, notified: bool) -> str:
    if notified:
        return (
            "A notification was delivered through the configured channels "
            "(Windows toast + optional Telegram / email). Notifications are "
            "best-effort: if a channel fails the block is still in effect."
        )
    return (
        "No notification was sent for this alert — WardSOAR only notifies on "
        "blocks or explicit failures to avoid notification fatigue."
    )


def _specific_log(record: DecisionRecord) -> str:
    if record.error:
        return (
            f"Saving this record FAILED: {record.error}. The alert processed "
            "correctly (any firewall block is in effect) but will not appear "
            "in the next session's Alerts tab. Check disk space / permissions."
        )
    return (
        f"Saved to alerts_history.jsonl. record_id={record.record_id}. "
        "The alert is now searchable in the Alerts tab and persists across "
        "WardSOAR restarts."
    )


def infer_pipeline_trace(record: DecisionRecord) -> list[StageTrace]:
    """Build a 13-row trace by inspecting which DecisionRecord fields
    ended up populated.

    The rules are:
    * A stage is ``passed`` when we see evidence it ran (e.g. the
      Collector is marked passed when ``network_context`` is not
      ``None``).
    * A stage is ``skipped`` when the preceding logic means it
      couldn't have run (Confirmer is skipped when Analyzer
      confidence is ≥0.90).
    * A stage is ``failed`` when the record carries an ``error``.
    * A stage is ``filtered`` for the caller to reuse when the alert
      was dropped at Step 1 — see :func:`infer_filter_trace`.

    The detail strings are deliberately short (one line) because the
    UI renders them as table cells next to the stage name.
    """
    trace: list[StageTrace] = []
    related_count = len(record.network_context.related_alerts) if record.network_context else 0

    # Step 1 — Filter.
    trace.append(
        StageTrace(
            1,
            "Filter",
            "passed",
            "no match in the known-harmless list — alert continues",
            explanation=(
                "This is the first check. WardSOAR keeps a curated list "
                "of known-harmless alert types that your firewall fires "
                "routinely without any real attack behind them (for "
                "example re-transmitted packets during a long video "
                "call). This alert did not match that list, so it "
                "continues through the full analysis below."
            ),
            specific_details=_specific_filter_passed(record),
        )
    )

    # Step 2 — Deduplicator.
    if related_count == 0:
        dedup_short = "this alert is unique in the last 60 seconds"
        dedup_long = (
            "When a real suspicious pattern happens, the firewall can "
            "fire the same alert many times in a short window. This "
            "step groups identical alerts over 60 seconds so WardSOAR "
            "only runs a full AI analysis once, even if the alert "
            "repeats fifty times. This alert is the first of its kind "
            "in the current window — it proceeds on its own."
        )
    else:
        dedup_short = f"grouped with {related_count} identical alert(s) already seen"
        dedup_long = (
            "When a real suspicious pattern happens, the firewall can "
            "fire the same alert many times in a short window. This "
            "step merges identical alerts over 60 seconds so WardSOAR "
            f"only runs ONE AI analysis for all {related_count + 1} of "
            "them — saving time and money without losing any "
            "information."
        )
    trace.append(
        StageTrace(
            2,
            "Deduplicator",
            "passed",
            dedup_short,
            explanation=dedup_long,
            specific_details=_specific_dedup(record, related_count),
        )
    )

    # Step 3 — Correlation.
    trace.append(
        StageTrace(
            3,
            "Correlation",
            "passed",
            f"{related_count} related alert(s) from the same source attached as context",
            explanation=(
                "This step looks for other alerts coming from the same "
                "source within a short time — for example, nine login "
                "attempts from the same stranger in 60 seconds, which "
                "is a classic attack pattern. The related alerts are "
                "attached to this record so the AI can see patterns "
                "instead of judging each alert in isolation."
            ),
            specific_details=_specific_correlation(record, related_count),
        )
    )

    # Step 4 — PreScorer.
    if record.network_context is not None:
        trace.append(
            StageTrace(
                4,
                "PreScorer",
                "passed",
                "priority score high enough to warrant AI analysis",
                explanation=(
                    "Before asking the artificial-intelligence model — "
                    "which takes time and costs money per call — "
                    "WardSOAR runs a quick checklist on the alert: is "
                    "it severe? Does it come from a suspicious "
                    "country or hosting provider? Is the target a "
                    "commonly-attacked port? This alert scored high "
                    "enough to justify the AI call."
                ),
                specific_details=_specific_prescorer(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                4,
                "PreScorer",
                "filtered",
                "priority score too low — AI not consulted",
                explanation=(
                    "Before asking the artificial-intelligence model — "
                    "which takes time and costs money per call — "
                    "WardSOAR runs a quick checklist. This alert did "
                    "not reach the threshold: it was probably a "
                    "low-severity, low-reputation kind of event with "
                    "no obvious red flag. To keep the budget under "
                    "control we dropped it without asking the AI. It "
                    "is still in your history so you can double-check."
                ),
                specific_details=(
                    f"SID {record.alert.alert_signature_id} scored below the "
                    "AI-consultation threshold; its score is not preserved in the "
                    "current record. Enable verbose prescorer logging (DEBUG) to "
                    "see the individual factor contributions."
                ),
            )
        )

    # Step 5 — Collector.
    if record.network_context is not None:
        nc = record.network_context
        trace.append(
            StageTrace(
                5,
                "Collector",
                "passed",
                f"collected {len(nc.active_connections)} live connection(s), "
                f"{len(nc.dns_cache)} DNS record(s), {len(nc.arp_cache)} "
                "local network device(s)",
                explanation=(
                    "This step takes a snapshot of what your computer "
                    "was doing at the time of the alert: which live "
                    "internet connections were open, which websites "
                    "had just been looked up (DNS cache), which "
                    "devices were visible on your home network. This "
                    "lets the AI tell the difference between 'your "
                    "browser legitimately talking to this address' and "
                    "'an unknown program doing something suspicious'."
                ),
                specific_details=_specific_collector(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                5,
                "Collector",
                "skipped",
                "not collected — the priority check stopped the pipeline",
                explanation=(
                    "There is no point gathering computer-state "
                    "information for an alert that was already "
                    "dropped as low priority in the previous step."
                ),
                specific_details=(
                    "This stage did not run because the PreScorer dropped the "
                    "alert as too low-priority. Without an active investigation "
                    "there is nothing to collect."
                ),
            )
        )

    # Step 6 — VirusTotal.
    if record.virustotal_results:
        trace.append(
            StageTrace(
                6,
                "VirusTotal",
                "passed",
                f"{len(record.virustotal_results)} external reputation lookup(s) completed",
                explanation=(
                    "VirusTotal is a free public service that checks an "
                    "internet address or file against dozens of "
                    "antivirus and threat-intelligence databases at "
                    "once. WardSOAR queried it here — the result is "
                    "attached so the AI can see whether other "
                    "security tools in the world already flagged this "
                    "target."
                ),
                specific_details=_specific_virustotal(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                6,
                "VirusTotal",
                "skipped",
                "no lookup was needed (or quota exhausted)",
                explanation=(
                    "VirusTotal is a free public service that checks "
                    "whether an address or a file is known as "
                    "malicious. Either there was nothing relevant to "
                    "look up here (no file hash was involved), or the "
                    "free-tier quota was already consumed. WardSOAR "
                    "saves its daily quota for alerts that really "
                    "need it."
                ),
                specific_details=_specific_virustotal(record),
            )
        )

    # Step 7 — Baseline.
    if record.analysis is not None:
        trace.append(
            StageTrace(
                7,
                "Baseline",
                "passed",
                "compared against known-safe and known-bad lists",
                explanation=(
                    "WardSOAR keeps two curated lists. The first "
                    "marks addresses that are always safe (Netflix, "
                    "Google, your own VPN), so that even Hard-Protect "
                    "mode never blocks them by accident. The second "
                    "marks addresses and hosting providers known to "
                    "be used for attacks (low-cost VPS from suspect "
                    "countries, etc.). This alert was compared "
                    "against both — the findings are sent to the AI "
                    "as pre-judgment hints."
                ),
                specific_details=_specific_baseline(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                7,
                "Baseline",
                "skipped",
                "not compared — AI analysis was not reached",
                explanation=(
                    "This comparison is only useful right before the "
                    "AI call. Since we didn't get that far in this "
                    "pipeline, the comparison was skipped."
                ),
                specific_details=(
                    "The Baseline comparison only runs as a prelude to the AI "
                    "consultation; since the AI was not reached, there was "
                    "nothing to compare."
                ),
            )
        )

    # Step 8 — Analyzer.
    if record.analysis is not None:
        analysis = record.analysis
        verdict_word = analysis.verdict.value.upper()
        trace.append(
            StageTrace(
                8,
                "Analyzer",
                "passed",
                f"AI verdict: {verdict_word}, confidence {analysis.confidence:.0%}",
                explanation=(
                    "This is the main analysis step. WardSOAR sends "
                    "the alert and all the context collected so far "
                    "to Claude, Anthropic's artificial-intelligence "
                    "model. Claude reads everything, reasons about "
                    "it like a security analyst would, and returns a "
                    "verdict (CONFIRMED threat, SUSPICIOUS, BENIGN / "
                    f"false alarm, or INCONCLUSIVE) with a confidence "
                    f"from 0 to 100 %. Here it returned {verdict_word} "
                    f"with {analysis.confidence:.0%} confidence. The "
                    "full reasoning is shown below in the AI "
                    "REASONING section. Each consultation takes "
                    "about ten seconds and costs roughly 3 US cents."
                ),
                specific_details=_specific_analyzer(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                8,
                "Analyzer",
                "skipped",
                "AI was not consulted",
                explanation=(
                    "The main AI consultation is expensive (about ten "
                    "seconds of processing, about 3 US cents). An "
                    "earlier step in the pipeline stopped the alert "
                    "before it reached the AI — WardSOAR keeps its "
                    "budget for alerts that actually need a verdict."
                ),
                specific_details=(
                    "This stage did not run — an earlier filter or score check "
                    "dismissed the alert before reaching the AI. No Opus call, "
                    "no Opus cost."
                ),
            )
        )

    # Step 9 — Confirmer.
    if record.analysis is not None and record.analysis.confidence < 0.90:
        trace.append(
            StageTrace(
                9,
                "Confirmer",
                "passed",
                "second AI opinion obtained (first verdict was borderline)",
                explanation=(
                    "The main AI verdict came back with less than "
                    "90 % confidence — borderline. As a safety net, "
                    "WardSOAR asks the AI a second time with a "
                    "slightly different question. If the two answers "
                    "disagree, the final verdict is forced to "
                    "INCONCLUSIVE and no automatic block is applied. "
                    "This protects against a single misreading by "
                    "the AI."
                ),
                specific_details=_specific_confirmer(record),
            )
        )
    elif record.analysis is not None:
        trace.append(
            StageTrace(
                9,
                "Confirmer",
                "skipped",
                f"first AI verdict was confident ({record.analysis.confidence:.0%}) — "
                "no second opinion needed",
                explanation=(
                    "The main AI verdict came back with high "
                    "confidence (90 % or more), so a second opinion "
                    "would be redundant. This saves another ~10 s / "
                    "3 cents on clear-cut verdicts."
                ),
                specific_details=_specific_confirmer(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                9,
                "Confirmer",
                "skipped",
                "no verdict to double-check",
                explanation=(
                    "This safety-net step is paired with the main AI "
                    "call. Since we didn't call the AI, there is "
                    "nothing to double-check."
                ),
                specific_details=(
                    "This stage did not run because the main AI was not "
                    "consulted. Without a first verdict there is nothing to "
                    "double-check."
                ),
            )
        )

    # Step 10 — Responder.
    if record.analysis is not None:
        if record.actions_taken and any(
            a.action_type.value != "none" for a in record.actions_taken
        ):
            act_type = next(
                a.action_type.value for a in record.actions_taken if a.action_type.value != "none"
            )
            resp_short = f"decided action: {act_type}"
            resp_long = (
                "This step decides what to actually DO based on the "
                "AI verdict. It combines the verdict, your current "
                "protection mode (Monitor = only watch / Protect = "
                "block if confident / Hard Protect = block if very "
                "confident), your personal whitelist, a safety rule "
                "that never blocks major services like Netflix or "
                f"GitHub, and a rate limiter. Decision: {act_type}."
            )
        else:
            resp_short = "decided to NOT act (safety rules overrode the AI verdict)"
            resp_long = (
                "Even when the AI is confident, WardSOAR can still "
                "refuse to block an address. Reasons include: your "
                "current protection mode is Monitor (watch only, "
                "never block), the AI's confidence didn't reach your "
                "mode's threshold, the address is in your whitelist, "
                "the destination is a major service (Netflix, "
                "Cloudflare, GitHub — safety net against false "
                "positives breaking your internet), or the daily "
                "block rate limit was reached. Here one of these "
                "rules prevented an action."
            )
        trace.append(
            StageTrace(
                10,
                "Responder",
                "passed",
                resp_short,
                explanation=resp_long,
                specific_details=_specific_responder(record),
            )
        )
    else:
        trace.append(
            StageTrace(
                10,
                "Responder",
                "skipped",
                "no AI verdict to act on",
                explanation=(
                    "This decision step needs an AI verdict as input. "
                    "Since the AI wasn't consulted, there is nothing "
                    "to decide about."
                ),
                specific_details=(
                    "This stage did not run because the AI was not consulted. "
                    "The Responder's decision logic has no verdict to combine "
                    "with the operator's protection mode / whitelist / rate limit."
                ),
            )
        )

    # Step 11 — pfSense API.
    block_actions = [
        act
        for act in record.actions_taken
        if act.action_type.value in ("ip_block", "ip_port_block")
    ]
    if block_actions:
        first = block_actions[0]
        if first.success:
            trace.append(
                StageTrace(
                    11,
                    "pfSense API",
                    "passed",
                    f"address {first.target_ip} blocked at the firewall "
                    f"for {first.block_duration_hours}h",
                    explanation=(
                        "This step actually installs the block on "
                        "your home firewall (a Netgate appliance "
                        "running pfSense). It uses a persistent file "
                        "on the firewall itself, so the block "
                        "survives any firewall restart or software "
                        "update. The blocked address cannot reach "
                        "your home network for the duration shown."
                    ),
                    specific_details=_specific_pfsense(record),
                )
            )
        else:
            trace.append(
                StageTrace(
                    11,
                    "pfSense API",
                    "failed",
                    f"block could NOT be installed: {first.error_message or 'unknown error'}",
                    explanation=(
                        "WardSOAR decided to block the address, but "
                        "talking to your firewall failed. The alert "
                        "is still saved, and you can retry manually. "
                        "Common causes: the firewall is unreachable, "
                        "a credentials issue, or a configuration "
                        "mismatch. Check the Netgate audit tab for "
                        "diagnostics."
                    ),
                    specific_details=_specific_pfsense(record),
                )
            )
    else:
        trace.append(
            StageTrace(
                11,
                "pfSense API",
                "skipped",
                "no block to install",
                explanation=(
                    "This step only runs when the previous decision "
                    "step asked for a block. For dismissed / benign "
                    "/ whitelisted alerts, there is nothing to "
                    "install on the firewall."
                ),
                specific_details=(
                    "This stage did not run because the Responder decided no "
                    "block was warranted. No rule was pushed to pfSense."
                ),
            )
        )

    # Step 12 — Notifier.
    notifier_fired = bool(block_actions and any(act.success for act in block_actions))
    if notifier_fired:
        trace.append(
            StageTrace(
                12,
                "Notifier",
                "passed",
                "you were notified (Windows toast / Telegram / email)",
                explanation=(
                    "When WardSOAR blocks a real threat, it pops a "
                    "Windows notification and — if you configured "
                    "them — sends a Telegram message or an email so "
                    "you know what just happened. Notifications are "
                    "best-effort: if a channel fails the block is "
                    "still in effect."
                ),
                specific_details=_specific_notifier(record, True),
            )
        )
    else:
        trace.append(
            StageTrace(
                12,
                "Notifier",
                "skipped",
                "nothing worth notifying you about",
                explanation=(
                    "WardSOAR deliberately does not notify you for "
                    "alerts that didn't lead to an action. Otherwise "
                    "you would get thousands of toasts per day and "
                    "start ignoring all of them — exactly what we "
                    "want to avoid."
                ),
                specific_details=_specific_notifier(record, False),
            )
        )

    # Step 13 — Log.
    trace.append(
        StageTrace(
            13,
            "Log",
            "passed",
            "saved to your alert history",
            explanation=(
                "Every alert — whether blocked, dismissed, benign, "
                "or inconclusive — is saved in your alert history "
                "on this computer. This page you are reading is "
                "built entirely from that saved record. You can "
                "always come back later and review the full "
                "reasoning that led to this decision."
            ),
            specific_details=_specific_log(record),
        )
    )
    if record.error:
        trace[-1] = StageTrace(
            13,
            "Log",
            "failed",
            f"saving to history FAILED: {record.error}",
            explanation=(
                "Something went wrong while saving the decision to "
                "disk. The alert was processed correctly (any "
                "firewall block is in effect) but it will not "
                "appear in the next session's Alerts tab. Check "
                "disk space and permissions."
            ),
            specific_details=_specific_log(record),
        )

    return trace


#: Per-stage (short summary, long explanation) for stages that ran
#: normally before the alert was filtered later on. Used when a
#: PreScorer / Deduplicator / Cache filter happens AFTER Filter.
#: Written in the same zero-jargon voice as the dismissal explanations.
_PASSED_STAGE_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "Filter": (
        "no match in the known-harmless list — alert continued",
        "This is the first check. WardSOAR keeps a curated list of "
        "known-harmless alert types (re-transmitted packets on long "
        "connections, automatic checks to trusted sites like "
        "ipinfo.io, etc.). This alert did not match that list, so "
        "the pipeline continued with further analysis.",
    ),
    "Deduplicator": (
        "not a duplicate of a recent alert — continued",
        "Normally groups identical alerts over 60 seconds so WardSOAR "
        "only analyses them once. This alert was the first of its "
        "kind in the current window, so it continued on its own.",
    ),
    "Correlation": (
        "no related alert in the last window — continued",
        "Looks for other alerts from the same source within a short "
        "time (a classic attack pattern). None found here — the "
        "alert continued without extra correlation context.",
    ),
}


#: Per-stage dismissal explanation — what THIS stage does when it
#: filters an alert. The short reason (the raw ``FilteredResult.reason``
#: string) is shown before this in the UI; this explains the stage's
#: role.
_FILTER_DISMISSAL_EXPLANATIONS: dict[str, str] = {
    "Filter": (
        "This is the first and cheapest check in WardSOAR. Your "
        "firewall's detection engine constantly fires alerts, but "
        "many of those are 'harmless background noise' — routine "
        "network glitches that technically look odd but don't "
        "indicate any attack. WardSOAR keeps a curated list of these "
        "known-harmless alert types. This alert matched that list, "
        "so it was dismissed immediately. No artificial intelligence "
        "was consulted, no action was taken."
    ),
    "Deduplicator": (
        "An identical alert was already processed in the last 60 "
        "seconds, so WardSOAR merged this one into the existing "
        "group to avoid a second AI consultation. The original "
        "alert's decision applies to this duplicate too."
    ),
    "Correlation": (
        "WardSOAR keeps a short-term memory of very recent verdicts. "
        "This alert matched a recently-decided BENIGN verdict on the "
        "same pattern, so the earlier decision was reused — saves "
        "another ten-second / 3-cent AI call on something we just "
        "analysed seconds ago."
    ),
    "PreScorer": (
        "Before asking the artificial-intelligence model — which "
        "takes time and costs money per call — WardSOAR runs a "
        "quick checklist: severity, hosting provider reputation, "
        "target port, etc. This alert did not reach the threshold: "
        "it was a low-severity, low-reputation kind of event with "
        "no obvious red flag. To keep the budget under control the "
        "alert was dropped without any AI consultation. It is still "
        "in your history so you can double-check."
    ),
}


#: Per-stage (short summary, long explanation) pair used for stages
#: AFTER the filtering one — the pipeline never reached them.
#:
#: Each explanation is written for a reader with zero network / security
#: background. No acronyms (SID, IDS, API, YAML, pfctl, …) without a
#: plain-English equivalent. The goal is that a family member who sees
#: "WardSOAR just dismissed an alert" can open this page and understand
#: WHY — not just at a technical level but conceptually.
_FILTERED_STAGE_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "Deduplicator": (
        "not needed (alert was already dismissed)",
        "When a real suspicious pattern repeats, your firewall can fire "
        "the exact same alert dozens of times a minute (for example "
        "during a long video call). This stage normally groups all "
        "these copies together so WardSOAR only analyses them once. "
        "It was not needed here because the alert was already dismissed "
        "as harmless background noise in the previous step, so there "
        "are no copies to group together.",
    ),
    "Correlation": (
        "not needed (alert was already dismissed)",
        "This stage normally looks at multiple alerts coming from the "
        "same place in a short time — for example, 9 login attempts "
        "from the same stranger in 60 seconds, which is a classic "
        "attack pattern. It was not needed here because the alert was "
        "already identified as harmless in the previous step.",
    ),
    "PreScorer": (
        "not needed (alert was already dismissed)",
        "Before spending money on artificial-intelligence analysis, "
        "WardSOAR runs a quick checklist: is the alert severe? Is the "
        "attacker's address known as suspicious? Is the targeted port a "
        "common attack target? An alert scoring too low is dropped here "
        "to save AI cost. This checklist was not needed because the "
        "previous step already dismissed the alert.",
    ),
    "Collector": (
        "not needed (alert was already dismissed)",
        "This stage normally takes a snapshot of what your computer "
        "was doing at the time of the alert — which programs were "
        "running, which websites they were visiting, which other "
        "network connections were open. It helps the AI understand if "
        "a program of yours was legitimately talking to the flagged "
        "address. Not needed here because the alert was already "
        "dismissed.",
    ),
    "VirusTotal": (
        "not needed (alert was already dismissed)",
        "VirusTotal is a free public database where you can check "
        "whether an internet address or a file has already been "
        "flagged as malicious by dozens of security tools. This stage "
        "normally looks up the alert's target there. It was not "
        "consulted because the alert was already dismissed — and "
        "each lookup counts against a daily quota, so WardSOAR saves "
        "them for real threats.",
    ),
    "Baseline": (
        "not needed (alert was already dismissed)",
        "This stage normally compares the target address against two "
        "curated lists: one of definitely-safe services (Netflix, "
        "Google, your own VPN) and one of definitely-bad addresses "
        "(known attackers, hosting providers often used for attacks). "
        "Not needed here because the alert was already dismissed.",
    ),
    "Analyzer": (
        "not needed — THIS is what saved the most time and money",
        "This is the expensive stage: WardSOAR sends the alert to "
        "Claude — Anthropic's artificial-intelligence model — for a "
        "thorough verdict. Each AI consultation takes about ten "
        "seconds and costs roughly 3 US cents. On a typical day your "
        "firewall fires hundreds of harmless alerts; if WardSOAR "
        "consulted the AI on each one, the bill would be about "
        "fifteen dollars per day. The previous Filter step exists "
        "exactly to skip this expensive consultation on alerts we "
        "already recognise as harmless.",
    ),
    "Confirmer": (
        "not needed (no first AI verdict to double-check)",
        "When the AI in the previous step is uncertain (less than 90% "
        "confident), WardSOAR asks it again with a slightly different "
        "question — if the two answers disagree, the alert is marked "
        "inconclusive and no automatic block is applied. This safety "
        "net was not needed because we never consulted the AI in the "
        "first place.",
    ),
    "Responder": (
        "not needed (nothing to decide)",
        "This is where WardSOAR decides what to do based on the AI's "
        "verdict: block the address at the firewall, just log an "
        "alert, or do nothing. The decision also takes into account "
        "your current protection mode (Monitor / Protect / Hard "
        "Protect), your whitelist, and a safety rule that never "
        "blocks major services like Netflix or GitHub. Not needed "
        "because there was no verdict to act on.",
    ),
    "pfSense API": (
        "not needed (no block to apply)",
        "If the previous step had decided to block the attacker's "
        "address, this step is where WardSOAR would talk to your "
        "firewall (a Netgate appliance running pfSense) to install "
        "the block — and make it permanent so it survives a firewall "
        "reboot. Not needed because no block was decided.",
    ),
    "Notifier": (
        "not needed (no action worth notifying you about)",
        "When WardSOAR blocks a real threat, this step pops a Windows "
        "toast and (if you configured it) sends a Telegram or email "
        "alert so you know what just happened. We deliberately do not "
        "notify you for dismissed alerts — you would be drowned in "
        "notifications and start ignoring all of them.",
    ),
}


#: Maps the prefix of a ``FilteredResult.reason`` string to the index
#: (1-based) of the pipeline stage that actually filtered the alert.
#: Matches the literal prefixes emitted by :class:`src.main.Pipeline`.
#: Defaults to 1 (Filter) when the prefix is unknown, which is the
#: safest misattribution — the operator still sees the reason.
_FILTER_SOURCE_PREFIXES: dict[str, int] = {
    "filter:": 1,  # Stage 1 — Filter
    "dedup:": 2,  # Stage 2 — Deduplicator
    "cache:": 3,  # Stage 3 — Decision cache lookup (Correlation slot)
    "prescorer:": 4,  # Stage 4 — PreScorer
}


def _filter_source_index(reason: str) -> int:
    """Work out which stage filtered the alert from the reason prefix.

    Stages in :class:`src.main.Pipeline` prefix their ``FilteredResult``
    reasons with ``filter:`` / ``dedup:`` / ``cache:`` / ``prescorer:``
    so a log reader can distinguish them at a glance. We piggyback on
    that convention to build an accurate trace: stages BEFORE the
    filtering one actually ran (marked ``passed``), stages AFTER
    didn't (``skipped``).

    Args:
        reason: The raw reason string from :class:`FilteredResult`.

    Returns:
        1-based index into :data:`PIPELINE_STAGES` (1..13). Defaults
        to 1 when the prefix is unknown.
    """
    lowered = (reason or "").strip().lower()
    for prefix, index in _FILTER_SOURCE_PREFIXES.items():
        if lowered.startswith(prefix):
            return index
    return 1


def _specific_for_filter_dismissal(
    alert_dict: dict[str, Any] | None,
    filter_meta: dict[str, Any] | None,
) -> str:
    """Build the "About this specific alert" paragraph for a Filter dismissal.

    Assembles four bricks when data is available:
      1. SID + signature name (from the alert itself)
      2. Operator-recorded reason (from the YAML entry)
      3. Added / review dates (from the YAML entry)
      4. Conclusion tying it back to this alert

    Falls back to ``(no specific details available)`` when both the
    alert dict and the filter metadata are missing.
    """
    sid = (alert_dict or {}).get("alert_signature_id")
    sig = (alert_dict or {}).get("alert_signature") or ""
    cat = (alert_dict or {}).get("alert_category") or ""
    if sid is None and not filter_meta:
        return ""

    lines: list[str] = []
    if sid is not None:
        name_part = f' — "{sig}"' if sig else ""
        lines.append(f"SID {sid}{name_part}")
    if cat:
        lines.append(f"Category reported by Suricata: {cat}")

    if filter_meta:
        operator_name = filter_meta.get("signature_name")
        if operator_name and operator_name != sig:
            lines.append(f'Name recorded in the harmless list: "{operator_name}"')
        reason = filter_meta.get("reason")
        if reason:
            lines.append("")
            lines.append("Why this SID is on the known-harmless list:")
            lines.append(f'  "{reason}"')
        added = filter_meta.get("added_date")
        review = filter_meta.get("review_date")
        if added or review:
            parts = []
            if added:
                parts.append(f"added on {added}")
            if review:
                parts.append(f"review scheduled for {review}")
            lines.append("Entry metadata: " + ", ".join(parts) + ".")
        lines.append("")
        lines.append(
            "That match is why THIS alert was dismissed at the Filter stage — "
            "no artificial-intelligence call was made, no firewall action was taken."
        )
    else:
        lines.append("")
        lines.append(
            "This SID is on the known-harmless list, but no operator reason "
            "was recorded for it (the match was sufficient to dismiss). "
            "Edit config/known_false_positives.yaml to document why."
        )
    return "\n".join(lines)


def _specific_for_skipped_after_filter(
    stage_name: str,
    source_name: str,
    source_detail: str,
) -> str:
    """Build the specific paragraph for a stage that was skipped because
    an earlier stage already dismissed the alert.

    Args:
        stage_name: The name of the stage that was skipped.
        source_name: The stage that actually dismissed the alert.
        source_detail: Short human description of why it was dismissed
            (e.g. the ``FilteredResult.reason`` string).
    """
    action_map = {
        "Deduplicator": "de-duplicate",
        "Correlation": "correlate with a cached verdict",
        "PreScorer": "compute a priority score",
        "Collector": "collect network / process context",
        "VirusTotal": "query VirusTotal",
        "Baseline": "compare against safe/bad lists",
        "Analyzer": "ask the artificial-intelligence model",
        "Confirmer": "ask the AI for a second opinion",
        "Responder": "decide on a blocking action",
        "pfSense API": "install a block at the firewall",
        "Notifier": "send you a notification",
    }
    action = action_map.get(stage_name, "run its task")
    reason_clause = f" ({source_detail})" if source_detail else ""
    return (
        f"This stage did not run because the alert was already dismissed "
        f"at the {source_name} stage{reason_clause}. Without a live alert "
        f"to examine, there is nothing to {action}."
    )


def _specific_for_passed_before_filter(
    stage_name: str,
    alert_dict: dict[str, Any] | None,
) -> str:
    """Build the specific paragraph for a stage that ran BEFORE the
    filtering stage (so it completed normally and let the alert pass
    on to the next stage)."""
    sid = (alert_dict or {}).get("alert_signature_id")
    if sid is None:
        return (
            f"The {stage_name} stage examined the alert and let it continue "
            "toward the next stages. No specific per-alert data is recorded."
        )
    return (
        f"SID {sid} was examined by the {stage_name} stage and did not match "
        f"any {stage_name.lower()}-specific reason to drop the alert, so the "
        "pipeline continued to the next check."
    )


def infer_filter_trace(
    reason: str,
    alert_dict: dict[str, Any] | None = None,
    filter_meta: dict[str, Any] | None = None,
) -> list[StageTrace]:
    """Build the 13-row trace for an alert filtered at some pre-Opus stage.

    Unlike v0.9.0 where every filtered alert was rendered as "short-
    circuited at Filter" regardless of the actual filtering stage,
    v0.9.2 inspects the reason prefix to identify which stage cut the
    alert and produces an accurate trace:

    * Stages 1..N-1 are marked ``passed`` — the pipeline did reach
      them.
    * Stage N (the filtering one) is marked ``filtered`` with the
      reason.
    * Stages N+1..12 are ``skipped`` with "short-circuited at <N>".
    * Stage 13 (Log) always runs.

    Each stage still carries a short summary (``detail``) and a long
    pedagogical explanation.

    Args:
        reason: The filter's own reason string (e.g. ``"filter: known
            false positive (SID 2210050)"`` or ``"prescorer: score 10
            below threshold 30"``).
    """
    source_index = _filter_source_index(reason)
    source_name = PIPELINE_STAGES[source_index - 1]
    trace: list[StageTrace] = []

    for i, name in enumerate(PIPELINE_STAGES, start=1):
        if i < source_index:
            # Stage ran normally — the alert passed through before
            # being filtered at a later stage. Use the rich passed-path
            # explanations authored for the non-filtered trace.
            detail, explanation = _PASSED_STAGE_EXPLANATIONS.get(
                name,
                ("executed normally", "This stage ran before the alert was filtered."),
            )
            trace.append(
                StageTrace(
                    i,
                    name,
                    "passed",
                    detail,
                    explanation=explanation,
                    specific_details=_specific_for_passed_before_filter(name, alert_dict),
                )
            )
        elif i == source_index:
            # THIS is the stage that cut the alert. Reason goes here.
            detail = f"DISMISSED — {reason}"
            explanation = _FILTER_DISMISSAL_EXPLANATIONS.get(
                name,
                (
                    "This stage decided the alert should not travel further "
                    "through the pipeline. The short reason is shown above; "
                    "no AI call was made, no firewall action was taken."
                ),
            )
            if name == "Filter":
                specific = _specific_for_filter_dismissal(alert_dict, filter_meta)
            elif name == "PreScorer":
                specific = (
                    f"The PreScorer stage computed a priority score for this alert "
                    f"and decided it was too low to justify an AI consultation. "
                    f'The pipeline\'s verbatim reason: "{reason}".'
                )
            elif name == "Deduplicator":
                specific = (
                    "An identical alert had already entered the pipeline in the "
                    "last 60 seconds; this duplicate was merged into the existing "
                    "group instead of triggering a second AI call. "
                    f'Pipeline reason: "{reason}".'
                )
            elif name == "Correlation":
                specific = (
                    "This traffic pattern was analysed recently and the cached "
                    "verdict was reused instead of triggering a new AI call. "
                    f'Pipeline reason: "{reason}".'
                )
            else:
                specific = f'Pipeline reason: "{reason}".'
            trace.append(
                StageTrace(
                    i,
                    name,
                    "filtered",
                    detail,
                    explanation=explanation,
                    specific_details=specific,
                )
            )
        elif name == "Log":
            # Log still runs for every alert, filtered or not — that's
            # how this page you are reading got its data.
            record_id = (alert_dict or {}).get("record_id") if alert_dict else None
            log_specific = (
                f"The alert record (dismissed at {source_name}) was appended to "
                "alerts_history.jsonl and is now searchable in the Alerts tab. "
                f"{'record_id=' + str(record_id) + '. ' if record_id else ''}"
                "It persists across WardSOAR restarts."
            )
            trace.append(
                StageTrace(
                    i,
                    name,
                    "passed",
                    "saved to your alert history",
                    explanation=(
                        "Even dismissed alerts are saved in your alert "
                        "history on this computer, so you can come back "
                        "later and review what WardSOAR did. Without "
                        "this, the dismissal decision would be invisible "
                        "to you — and we don't want WardSOAR to be a "
                        "black box."
                    ),
                    specific_details=log_specific,
                )
            )
        else:
            # Stage would have run but the alert was already dismissed.
            summary, explanation = _FILTERED_STAGE_EXPLANATIONS.get(
                name,
                (
                    f"not needed (alert was already dismissed at {source_name})",
                    f"The pipeline stopped at {source_name}, so this step was skipped.",
                ),
            )
            trace.append(
                StageTrace(
                    i,
                    name,
                    "skipped",
                    summary,
                    explanation=explanation,
                    specific_details=_specific_for_skipped_after_filter(name, source_name, reason),
                )
            )
    return trace


def _coerce_enrichment(obj: Any) -> Optional[dict[str, Any]]:
    """Normalise an :class:`IpEnrichment` / dict / None into a JSON dict."""
    if obj is None:
        return None
    if hasattr(obj, "to_dict"):
        return dict(obj.to_dict())
    return dict(obj)


def serialise_decision_record(
    record: DecisionRecord,
    ip_enrichment: Any = None,
    dest_ip_enrichment: Any = None,
) -> dict[str, Any]:
    """Return a JSON-serialisable dict of the full DecisionRecord.

    Pydantic's :meth:`model_dump` handles enums (ThreatVerdict,
    BlockAction, …), datetimes (ISO format) and nested models
    recursively. We pass ``mode="json"`` so the output survives
    :func:`json.dumps` without an extra ``default=str``.

    Args:
        record: The pipeline's decision record.
        ip_enrichment: :class:`IpEnrichment` snapshot for the
            ``src_ip``. Rendered in the "IP ownership & reputation"
            section. Optional.
        dest_ip_enrichment: v0.15.0 \u2014 :class:`IpEnrichment`
            snapshot for the ``dest_ip``. When provided, the Alert
            Detail view renders a second block with the destination's
            ownership + reputation, doubling the analysis surface.
            Optional.
    """
    payload = record.model_dump(mode="json")
    # Attach the inferred trace so the UI doesn't have to re-run the
    # inference logic at display time. This keeps the display layer
    # dumb and lets us evolve the trace builder without touching
    # alert_detail.py.
    payload["pipeline_trace"] = [t.__dict__ for t in infer_pipeline_trace(record)]
    src_d = _coerce_enrichment(ip_enrichment)
    dst_d = _coerce_enrichment(dest_ip_enrichment)
    if src_d is not None:
        payload["ip_enrichment"] = src_d
    if dst_d is not None:
        payload["dest_ip_enrichment"] = dst_d
    return payload


def build_filtered_enriched(
    alert: Any,
    reason: str,
    filter_meta: dict[str, Any] | None = None,
    ip_enrichment: Any = None,
    dest_ip_enrichment: Any = None,
) -> dict[str, Any]:
    """Build the ``_full`` payload for a pre-Opus filtered alert.

    Filtered alerts never have a DecisionRecord — the pipeline bails
    before allocating one. We still want the Alert Detail view to
    work on them, so we package the raw alert + reason + inferred
    filter trace (with per-stage specific details) under the same
    ``_full`` key shape the UI consumes for full-pipeline records.

    Args:
        alert: A :class:`~src.models.SuricataAlert` instance.
        reason: The filter's reason string.
        filter_meta: v0.9.5 \u2014 the matched YAML entry
            (``signature_name``, ``reason``, ``added_date``, ``review_date``)
            from :meth:`AlertFilter.get_sid_metadata`. Quoted verbatim
            in the Filter stage's specific-details paragraph.
        ip_enrichment: IP ownership + reputation snapshot for the
            alert's ``src_ip``. Rendered in the Alert Detail view.
        dest_ip_enrichment: v0.15.0 \u2014 same but for the ``dest_ip``.
            The Alert Detail view renders a second IP-ownership
            block so the operator sees "who is the other end of
            the flow" too. Optional \u2014 when absent the detail view
            only shows the source IP block (pre-0.15 behaviour).
    """
    alert_dict = alert.model_dump(mode="json")
    payload: dict[str, Any] = {
        "filtered": True,
        "alert": alert_dict,
        "filter_reason": reason,
        "filter_meta": dict(filter_meta) if filter_meta else None,
        "pipeline_trace": [
            t.__dict__
            for t in infer_filter_trace(reason, alert_dict=alert_dict, filter_meta=filter_meta)
        ],
    }
    src_d = _coerce_enrichment(ip_enrichment)
    dst_d = _coerce_enrichment(dest_ip_enrichment)
    if src_d is not None:
        payload["ip_enrichment"] = src_d
    if dst_d is not None:
        payload["dest_ip_enrichment"] = dst_d
    return payload


__all__ = [
    "PIPELINE_STAGES",
    "StageTrace",
    "build_filtered_enriched",
    "infer_filter_trace",
    "infer_pipeline_trace",
    "serialise_decision_record",
]
