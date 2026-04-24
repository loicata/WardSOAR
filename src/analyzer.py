"""Threat analysis using Claude API.

Sends enriched alert context (network, forensic, VirusTotal) to Claude
for intelligent threat assessment and decision making.

Fail-safe: API errors return INCONCLUSIVE verdict, never crash.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import anthropic

from src.models import (
    ForensicResult,
    NetworkContext,
    SuricataAlert,
    SysmonEvent,
    ThreatAnalysis,
    ThreatVerdict,
    VirusTotalResult,
)

logger = logging.getLogger("ward_soar.analyzer")


# How many times to retry a Claude API call on transient errors
# (429 rate limit, 5xx server errors, timeouts). Delays: 2s, 4s, 8s.
_MAX_API_RETRIES = 3
_RETRY_BASE_DELAY_SECONDS = 2

# Per-attempt HTTP timeout for the Claude API call. CLAUDE.md §4
# (Timeout Discipline) requires every external call to have an explicit
# deadline so one slow endpoint cannot stall the pipeline. The SDK's
# default is 600 s, which would let a single hung call block an alert
# for ten minutes before the fail-safe INCONCLUSIVE verdict kicks in.
_API_TIMEOUT_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Analyzer-side circuit breaker
# ---------------------------------------------------------------------------
#
# On 2026-04-20 12:46 → 14:48 the operator's Anthropic credit balance
# went to zero. WardSOAR kept calling the API once per alert for two
# hours — 42 pointless 400 responses, 42 INCONCLUSIVE verdicts, and
# every single alert of that window analysed blindly. The retry path
# already re-raises deterministic 4xx (see _call_with_retry), but the
# caller-side loop kept going with no circuit protection at all.
#
# The breaker here mirrors the one in src/intel/http_client_base.py:
# after N consecutive failures the analyzer trips and returns
# INCONCLUSIVE directly for _CIRCUIT_BREAKER_COOLDOWN_S seconds, without
# even building the prompt. A specific "credit balance too low" path
# extends the cooldown to 60 min because that error only clears when
# the operator recharges — re-trying every 15 min would still spam
# 4 failures/hour.

#: Consecutive non-retryable failures that trip the breaker. Picked
#: tight: Claude 4xx are deterministic, so 3 in a row is already a
#: reliable signal that the next call will fail for the same reason.
_CIRCUIT_BREAKER_THRESHOLD: int = 3

#: Standard cooldown after the breaker trips (seconds). Matches the
#: quota-reset granularity for most minute/hour budgets upstream.
_CIRCUIT_BREAKER_COOLDOWN_S: float = 15 * 60

#: Extended cooldown when the failure is "credit balance too low".
#: Anthropic's credit resets only on operator action (recharge); a
#: 15-min re-attempt would waste another call and another 4xx.
_CIRCUIT_BREAKER_QUOTA_EXHAUSTED_COOLDOWN_S: float = 60 * 60


def _is_credit_exhausted_error(exc: Exception) -> bool:
    """True when the exception message signals an out-of-credit account.

    Anthropic packages this case as a 400 ``invalid_request_error`` with
    the message ``"Your credit balance is too low to access the
    Anthropic API."``. Parsing the JSON would be more rigorous but the
    SDK already collapses the error into a string that the caller sees;
    a substring check is enough and resilient to SDK formatting changes.
    """
    msg = str(exc).lower()
    return "credit balance" in msg and "too low" in msg


# ---------------------------------------------------------------------------
# Context budgeting (v0.7.0)
# ---------------------------------------------------------------------------
#
# Pre-v0.6.6 the analysis prompt dumped the full forensic snapshot on
# every alert, averaging 195 000 input tokens / call (~$2/alert on Opus).
# Two levers fix that:
#
# 1. Prune the serialised JSON to keep only what an analyst would
#    actually read — ACTIVE connections, Sysmon events from the 5
#    minutes preceding the alert, recent DNS cache entries, etc. Dead
#    connections (TIME_WAIT / CLOSE_WAIT) and historical logs rarely
#    carry decision-grade signal on a live alert.
#
# 2. Size the character budget per alert severity. SEV-1 (HIGH) keeps a
#    comfortable budget so Opus never misses a subtle indicator on a
#    real threat; SEV-2/3 (MEDIUM/LOW) — which is 95%+ of the daily
#    noise — gets a tight cap that keeps spending in check.
#
# Both levers compound: the pruned JSON is smaller *and* better-ranked,
# and the budget is spent on the already-relevant bits.


#: Character budgets per severity → ``(network_ctx, forensic, vt_per_engine)``.
#: Values are "characters of JSON" (≈ tokens / 3.5 on English, JSON-ish). They
#: are intentionally generous on SEV-1 so a genuine incident investigation
#: keeps the signal-carrying context.
_CONTEXT_BUDGET: dict[int, dict[str, int]] = {
    1: {"network": 16000, "forensic": 16000, "vt": 4000},
    2: {"network": 6000, "forensic": 10000, "vt": 2500},
    3: {"network": 3000, "forensic": 4000, "vt": 1500},
}
_CONTEXT_BUDGET_DEFAULT: dict[str, int] = _CONTEXT_BUDGET[3]

# Connection states that carry forensic signal. ``TIME_WAIT`` and
# ``CLOSE_WAIT`` are normally stale tails of finished flows and rarely
# tell Opus anything it can't infer from the alert itself.
_ACTIVE_CONN_STATES = {
    "ESTABLISHED",
    "LISTEN",
    "LISTENING",
    "SYN_SENT",
    "SYN_SENT_SENT",
    "SYN_RECV",
    "SYN_RECEIVED",
}

# How far back from the alert timestamp to keep Sysmon events. Events
# older than this window are almost always unrelated to the trigger.
_EVENT_LOOKBACK = timedelta(minutes=5)

# Secondary caps on lists whose items can be many but individually
# small: we keep the most recent N instead of a byte count, since
# character-budget truncation would cut mid-entry and produce invalid
# JSON fragments.
_MAX_DNS_CACHE_ENTRIES = 20
_MAX_WINDOWS_EVENTS = 50


def _budget_for(alert: SuricataAlert) -> dict[str, int]:
    """Character budgets applicable to ``alert`` in the prompt."""
    return _CONTEXT_BUDGET.get(int(alert.alert_severity.value), _CONTEXT_BUDGET_DEFAULT)


def _prune_network_context(ctx: NetworkContext) -> NetworkContext:
    """Drop the low-signal slices of a ``NetworkContext``.

    * ``active_connections`` — keep only live sockets (ESTABLISHED,
      LISTEN, SYN_SENT, SYN_RECV). TIME_WAIT / CLOSE_WAIT are dropped.
    * ``dns_cache`` — keep only the most recent :data:`_MAX_DNS_CACHE_ENTRIES`
      entries. The list ordering preserves host recency.
    * ``arp_cache`` — kept as-is (always small).
    * ``related_alerts`` — kept as-is (already filtered upstream by
      the Deduplicator's grouping window).
    * ``ip_reputation`` — kept as-is (single record).
    """
    live_conns: list[dict[str, Any]] = []
    for conn in ctx.active_connections:
        state = str(conn.get("state", "")).upper()
        if not state or state in _ACTIVE_CONN_STATES:
            # Empty state is kept — some platforms omit the field for
            # UDP or raw sockets where the notion doesn't apply.
            live_conns.append(conn)
    return NetworkContext(
        active_connections=live_conns,
        dns_cache=list(ctx.dns_cache[-_MAX_DNS_CACHE_ENTRIES:]),
        arp_cache=ctx.arp_cache,
        related_alerts=ctx.related_alerts,
        ip_reputation=ctx.ip_reputation,
    )


def _as_aware_utc(value: Any) -> Optional[datetime]:
    """Coerce any parseable timestamp into a timezone-aware UTC ``datetime``.

    Accepts :class:`datetime` objects (naive or aware), ISO-8601 strings
    (``Z`` or ``+HH:MM`` suffix), or anything else — returning ``None``
    when we can't produce a reliable timestamp rather than raising.
    Naive datetimes are *assumed* to be UTC; the collector builds
    Sysmon events that way.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _prune_forensic_result(fr: ForensicResult, alert_time: Optional[datetime]) -> ForensicResult:
    """Drop sysmon / windows events that can't plausibly relate to the alert.

    Events older than :data:`_EVENT_LOOKBACK` before the alert are
    discarded. When the alert's timestamp or an event's timestamp is
    absent or malformed, the event is kept — never dropped silently —
    so the analyst never loses evidence on an edge-case log format.
    ``windows_events`` without any recognisable timestamp are capped to
    the last :data:`_MAX_WINDOWS_EVENTS` by chronological insertion
    order (the collector appends in observed order).
    """
    alert_utc = _as_aware_utc(alert_time)

    # Sysmon: typed timestamps, easy filter.
    recent_sysmon: list[SysmonEvent]
    if alert_utc is None:
        recent_sysmon = list(fr.sysmon_events[-_MAX_WINDOWS_EVENTS:])
    else:
        cutoff = alert_utc - _EVENT_LOOKBACK
        recent_sysmon = []
        for event in fr.sysmon_events:
            event_ts = _as_aware_utc(event.timestamp)
            if event_ts is None or event_ts >= cutoff:
                recent_sysmon.append(event)

    # Windows events: dicts, timestamp key varies by collector version.
    trimmed_windows: list[dict[str, Any]] = []
    for entry in fr.windows_events:
        if alert_utc is not None:
            ts_value = entry.get("timestamp") or entry.get("TimeCreated")
            event_ts = _as_aware_utc(ts_value)
            if event_ts is not None and event_ts < alert_utc - _EVENT_LOOKBACK:
                continue
        trimmed_windows.append(entry)
    trimmed_windows = trimmed_windows[-_MAX_WINDOWS_EVENTS:]

    return ForensicResult(
        suspect_processes=fr.suspect_processes,
        sysmon_events=recent_sysmon,
        suspicious_files=fr.suspicious_files,
        registry_anomalies=fr.registry_anomalies,
        windows_events=trimmed_windows,
        process_tree=fr.process_tree,
    )


def _render_history_section(signals: Optional[Any]) -> str:
    """Render :class:`StatsSignals` into a compact prompt block.

    Returns an empty string when the store has no occurrence for
    this (SID, src_ip) pair — the caller just omits the section.

    The block is intentionally short (a few lines) so it survives
    the character-budget truncation that the rest of the forensic
    JSON dump is subject to.
    """
    if signals is None:
        return ""

    lines = ["\n## Longitudinal history (last 7 days)"]
    lines.append(f"- {signals.total_count} occurrence(s), " f"~{signals.frequency_per_day:.2f}/day")
    if signals.regularity is not None:
        reg_label = (
            "HIGH (beacon-like)"
            if signals.regularity >= 0.8
            else ("moderate" if signals.regularity >= 0.5 else "low")
        )
        lines.append(f"- temporal regularity: {reg_label} ({signals.regularity:.2f})")
    stab_pct = int(signals.verdict_stability * 100)
    lines.append(
        f"- dominant past verdict: {signals.dominant_verdict.upper()} "
        f"({stab_pct}% of occurrences)"
    )
    if signals.novelty:
        lines.append("- novelty: first time seen in the last 3 days — consider a shift in baseline")
    return "\n".join(lines)


def _render_process_risk_section(fr: ForensicResult) -> str:
    """Distil process_risk verdicts into a short prompt-friendly block.

    The forensic JSON dump already carries the same data inside
    ``suspect_processes[].risk``, but character-budget truncation can
    clip it off on SEV-3 alerts and the LLM is better served by an
    explicit list than by JSON scattered at the end of a payload.

    Returns an empty string when no process was attributed to the
    flow or when the scoring block is missing — the caller just
    skips appending the section.
    """
    processes = fr.suspect_processes or []
    rows: list[str] = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        risk = proc.get("risk")
        if not isinstance(risk, dict):
            continue
        name = str(proc.get("name") or "?")
        pid = proc.get("pid")
        verdict = str(risk.get("verdict") or "unknown").upper()
        score = risk.get("score")
        sig_status = str(risk.get("signature_status") or "unknown")
        sig_signer = str(risk.get("signature_signer") or "")
        parent = str(risk.get("parent_name") or "") or None
        services = proc.get("services") or []
        signals = risk.get("signals") or []

        header_parts = [f"{name}"]
        if pid is not None:
            header_parts.append(f"(PID {pid})")
        header_parts.append(f"→ {verdict}")
        if isinstance(score, int):
            header_parts.append(f"({score}/100)")
        header = " ".join(header_parts)

        row_lines = [f"- {header}"]
        sig_line = f"    • signature: {sig_status}"
        if sig_signer:
            sig_line += f" ({sig_signer})"
        row_lines.append(sig_line)
        if parent:
            row_lines.append(f"    • parent: {parent}")
        if services:
            row_lines.append(f"    • services hosted: {', '.join(services)}")
        for s in signals[:6]:  # cap to keep prompt compact
            row_lines.append(f"    • {s}")
        rows.append("\n".join(row_lines))

    if not rows:
        return ""

    return "\n## Process attribution & risk\n" + "\n".join(rows)


DEFAULT_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst operating within an automated "
    "threat detection and response system (SOAR). Your role is to analyze Suricata IDS alerts "
    "enriched with local forensic data and determine whether each alert represents a genuine "
    "threat requiring automated blocking.\n\n"
    "You MUST respond with a valid JSON object containing:\n"
    '{\n    "verdict": "confirmed" | "suspicious" | "benign" | "inconclusive",\n'
    '    "confidence": 0.0-1.0,\n'
    '    "reasoning": "Detailed analysis explanation",\n'
    '    "recommended_actions": ["action1", "action2"],\n'
    '    "ioc_summary": "Summary of indicators of compromise",\n'
    '    "false_positive_indicators": ["indicator1", "indicator2"]\n}\n\n'
    "Be conservative: a false block on legitimate traffic is worse than missing "
    "a low-severity alert.\n\n"
    "When the prompt includes a '## Process attribution & risk' section, treat its "
    "verdicts as primary evidence: they come from a local deterministic scorer that "
    "inspects Authenticode signatures, install paths, parent chains, command-line "
    "patterns, LOLBin misuse and cached VirusTotal hashes on the Windows PC itself. "
    "A process flagged malicious should push you strongly toward CONFIRMED; a process "
    "flagged benign with a trusted Microsoft/Google/Mozilla signature should push you "
    "strongly toward BENIGN unless other signals contradict it."
)


class ThreatAnalyzer:
    """Analyze threats using Claude API with enriched context.

    Args:
        config: Analyzer configuration dict from config.yaml.

    Raises:
        ValueError: If ANTHROPIC_API_KEY is not set.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        # Opus 4.7 — single LLM for the whole verdict (no Sonnet pre-pass,
        # no Confirmer counter-argument). See docs/architecture.md §2.2.
        self._model: str = config.get("model", "claude-opus-4-7")
        self._max_tokens: int = config.get("max_tokens", 4096)
        self._api_key: str = os.getenv("ANTHROPIC_API_KEY", "")

        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        self._system_prompt = self._load_system_prompt(config)

        # Circuit breaker state (per-instance, in-memory on purpose so a
        # process restart gives a clean slate — if the operator restarts
        # after a recharge, we do not want a stale "quota exhausted" flag
        # to block analysis).
        self._consecutive_failures: int = 0
        self._circuit_open_until: float = 0.0  # monotonic seconds; 0 = closed
        self._circuit_reason: str = ""  # human-readable last-trip reason

    def _load_system_prompt(self, config: dict[str, Any]) -> str:
        """Load system prompt from external file or use default.

        Args:
            config: Analyzer configuration.

        Returns:
            System prompt string.
        """
        prompt_file = config.get("system_prompt_file")
        if prompt_file:
            path = Path(prompt_file)
            if path.exists():
                return path.read_text(encoding="utf-8").strip()
            logger.warning("System prompt file not found: %s, using default", prompt_file)
        return DEFAULT_SYSTEM_PROMPT

    async def analyze(
        self,
        alert: SuricataAlert,
        network_context: Optional[NetworkContext] = None,
        forensic_result: Optional[ForensicResult] = None,
        vt_results: Optional[list[VirusTotalResult]] = None,
        history_signals: Optional[Any] = None,
    ) -> ThreatAnalysis:
        """Send enriched context to Claude API for threat analysis.

        Args:
            alert: The triggering Suricata alert.
            network_context: Network enrichment data.
            forensic_result: Local forensic analysis results.
            vt_results: VirusTotal lookup/submission results.
            history_signals: Optional :class:`StatsSignals` from
                :mod:`src.alerts_stats`, rendered into the prompt as
                a "## Longitudinal history" section so Opus can reason
                about patterns over the last week.

        Returns:
            ThreatAnalysis with verdict, confidence, and reasoning.
        """
        # Circuit breaker: if Claude has been failing deterministically
        # (credit exhausted, persistent 4xx), short-circuit before we
        # even build the prompt. Saves a pointless API call and cuts
        # the log noise to one line per alert until cooldown elapses.
        if self._is_circuit_open():
            return ThreatAnalysis(
                verdict=ThreatVerdict.INCONCLUSIVE,
                confidence=0.0,
                reasoning=f"Claude analyzer circuit breaker open: {self._circuit_reason}",
            )

        prompt = self._build_analysis_prompt(
            alert, network_context, forensic_result, vt_results, history_signals=history_signals
        )

        try:
            response_text = await self._call_with_retry(
                system_prompt=self._system_prompt,
                user_prompt=prompt,
            )
            result = self._parse_response(response_text)
            self._record_success()
            return result
        except (
            anthropic.APIError,
            RuntimeError,
            OSError,
            ValueError,
            KeyError,
            IndexError,
            AttributeError,
        ) as exc:
            logger.error("Claude API call failed: %s", exc)
            self._record_failure(exc)
            return ThreatAnalysis(
                verdict=ThreatVerdict.INCONCLUSIVE,
                confidence=0.0,
                reasoning=f"Analysis failed due to API error: {exc}",
            )

    async def _call_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        """Send a prompt to Claude with exponential backoff on transient errors.

        Retries on:
            - ``anthropic.RateLimitError`` (429) — rate limit hit.
            - ``anthropic.APIStatusError`` with 5xx status — server issue.

        Non-retryable errors (401, 4xx other than 429, schema mismatches)
        are re-raised immediately.

        Args:
            system_prompt: System prompt text (ephemeral-cached).
            user_prompt: User message body.

        Returns:
            The raw text of the first content block returned by Claude.

        Raises:
            anthropic.APIError: If all retries are exhausted or the error
                                is non-retryable.
        """
        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_API_RETRIES + 1):
            try:
                client = anthropic.Anthropic(
                    api_key=self._api_key,
                    timeout=_API_TIMEOUT_SECONDS,
                )
                message = client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=[
                        {
                            "type": "text",
                            "text": system_prompt,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=[{"role": "user", "content": user_prompt}],
                )
                content_block = message.content[0]
                return str(content_block.text)  # type: ignore[union-attr]
            except anthropic.RateLimitError as exc:
                last_exc = exc
                if attempt >= _MAX_API_RETRIES:
                    break
                delay = _RETRY_BASE_DELAY_SECONDS * (2**attempt)
                logger.warning(
                    "Claude 429 rate limit (attempt %d/%d) — retrying in %ds",
                    attempt + 1,
                    _MAX_API_RETRIES + 1,
                    delay,
                )
                await asyncio.sleep(delay)
            except anthropic.APITimeoutError as exc:
                # A timeout usually means either a transient network hiccup
                # or an overloaded endpoint. Retry with the same backoff as
                # a 5xx: the next attempt often completes within the 30 s
                # budget even when the first stalled the full window.
                last_exc = exc
                if attempt >= _MAX_API_RETRIES:
                    break
                delay = _RETRY_BASE_DELAY_SECONDS * (2**attempt)
                logger.warning(
                    "Claude API timeout after %.0fs (attempt %d/%d) — retrying in %ds",
                    _API_TIMEOUT_SECONDS,
                    attempt + 1,
                    _MAX_API_RETRIES + 1,
                    delay,
                )
                await asyncio.sleep(delay)
            except anthropic.APIStatusError as exc:
                last_exc = exc
                if exc.status_code < 500 or attempt >= _MAX_API_RETRIES:
                    # 4xx (other than 429) are deterministic failures —
                    # retrying won't help. 5xx past the retry budget
                    # also bubbles up.
                    break
                delay = _RETRY_BASE_DELAY_SECONDS * (2**attempt)
                logger.warning(
                    "Claude %d server error (attempt %d/%d) — retrying in %ds",
                    exc.status_code,
                    attempt + 1,
                    _MAX_API_RETRIES + 1,
                    delay,
                )
                await asyncio.sleep(delay)

        # Exhausted retries — re-raise so callers fall back to INCONCLUSIVE.
        if last_exc is None:
            raise RuntimeError("Claude API call exhausted retries with no exception")
        raise last_exc

    # ------------------------------------------------------------------
    # Circuit breaker
    # ------------------------------------------------------------------

    def _is_circuit_open(self) -> bool:
        """True while the breaker is in its cooldown window."""
        return time.monotonic() < self._circuit_open_until

    def _record_failure(self, exc: Exception) -> None:
        """Register one API failure; trip the breaker when the
        consecutive-failure threshold is reached.

        Detects the "credit balance too low" case and applies a
        longer cooldown because that specific error only clears on
        operator action (recharge) — re-attempting on the 15-min
        tick would waste another deterministic 4xx.
        """
        self._consecutive_failures += 1

        # Credit-exhausted trips the breaker immediately, regardless of
        # the normal threshold: every subsequent call will fail with
        # the same 400 until the account is recharged.
        if _is_credit_exhausted_error(exc):
            self._circuit_open_until = (
                time.monotonic() + _CIRCUIT_BREAKER_QUOTA_EXHAUSTED_COOLDOWN_S
            )
            self._circuit_reason = "Anthropic credit balance exhausted"
            logger.error(
                "Claude analyzer circuit opened: credit balance exhausted — "
                "suppressing analysis for %.0fs (recharge account to resume)",
                _CIRCUIT_BREAKER_QUOTA_EXHAUSTED_COOLDOWN_S,
            )
            return

        if self._consecutive_failures == _CIRCUIT_BREAKER_THRESHOLD:
            self._circuit_open_until = time.monotonic() + _CIRCUIT_BREAKER_COOLDOWN_S
            self._circuit_reason = (
                f"{self._consecutive_failures} consecutive API failures "
                f"(last: {type(exc).__name__})"
            )
            logger.warning(
                "Claude analyzer circuit opened after %d consecutive failures — "
                "suppressing analysis for %.0fs",
                self._consecutive_failures,
                _CIRCUIT_BREAKER_COOLDOWN_S,
            )

    def _record_success(self) -> None:
        """Reset breaker state after a successful call."""
        if self._consecutive_failures > 0 or self._circuit_open_until > 0:
            logger.info("Claude analyzer circuit reset after successful call")
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._circuit_reason = ""

    def _parse_response(self, response_text: str) -> ThreatAnalysis:
        """Parse Claude API response text into ThreatAnalysis.

        Args:
            response_text: Raw text response from Claude.

        Returns:
            Parsed ThreatAnalysis, or INCONCLUSIVE on parse failure.
        """
        try:
            data = json.loads(response_text)
            return ThreatAnalysis(
                verdict=ThreatVerdict(data["verdict"]),
                confidence=float(data["confidence"]),
                reasoning=str(data["reasoning"]),
                recommended_actions=data.get("recommended_actions", []),
                ioc_summary=data.get("ioc_summary", ""),
                false_positive_indicators=data.get("false_positive_indicators", []),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning("Failed to parse Claude response: %s", exc)
            return ThreatAnalysis(
                verdict=ThreatVerdict.INCONCLUSIVE,
                confidence=0.0,
                reasoning=f"Failed to parse API response: {exc}",
            )

    async def deep_analyze(
        self,
        alert: SuricataAlert,
        network_context: Optional[NetworkContext],
        forensic_result: Optional[ForensicResult],
        vt_results: Optional[list[VirusTotalResult]],
        timeline: Optional[list[dict[str, Any]]] = None,
        iocs: Optional[list[dict[str, Any]]] = None,
        attack_techniques: Optional[list[dict[str, Any]]] = None,
    ) -> str:
        """Ask Opus for a full incident narrative post-acquisition.

        Unlike :meth:`analyze` (which produces a verdict as strict JSON),
        deep_analyze returns freeform markdown — the body of the technical
        report included in the deep forensic export. The prompt embeds
        the timeline, extracted IOCs and ATT&CK mapping so the model
        reasons over the full incident context rather than the raw alert.

        Args:
            alert: Originating alert.
            network_context / forensic_result / vt_results: Same
                enrichment data available to :meth:`analyze`.
            timeline: Optional list of timeline entry dicts produced
                by :class:`TimelineBuilder.to_json_list`.
            iocs: Optional STIX-style observables from :class:`IocExtractor`.
            attack_techniques: Optional ATT&CK mapping from :class:`AttackMapper`.

        Returns:
            Markdown string — the body of the incident report. Empty
            string on API failure (the report falls back to a canned
            "Opus unavailable" paragraph).
        """
        prompt = self._build_deep_prompt(
            alert,
            network_context,
            forensic_result,
            vt_results,
            timeline,
            iocs,
            attack_techniques,
        )

        system_prompt = (
            "You are a senior SOC analyst writing a post-incident report for "
            "a small-business owner. Produce well-structured markdown with "
            "these sections in order:\n"
            "1. Executive summary (2-3 plain-language sentences).\n"
            "2. What we observed (brief chronology citing timeline events).\n"
            "3. Risk assessment (who/what is at risk, severity level).\n"
            "4. What we did (responses executed).\n"
            "5. Recommendations (next steps the owner can take).\n"
            "Avoid jargon where possible. Do NOT invent facts outside the data."
        )

        try:
            return await self._call_with_retry(system_prompt=system_prompt, user_prompt=prompt)
        except (
            anthropic.APIError,
            RuntimeError,
            OSError,
            ValueError,
            KeyError,
            IndexError,
            AttributeError,
        ) as exc:
            logger.error("Deep analysis Claude call failed: %s", exc)
            return ""

    def _build_deep_prompt(
        self,
        alert: SuricataAlert,
        network_context: Optional[NetworkContext],
        forensic_result: Optional[ForensicResult],
        vt_results: Optional[list[VirusTotalResult]],
        timeline: Optional[list[dict[str, Any]]],
        iocs: Optional[list[dict[str, Any]]],
        attack_techniques: Optional[list[dict[str, Any]]],
    ) -> str:
        """Compose the deep-analysis prompt with all available enrichment."""
        sections: list[str] = []

        sections.append("## Alert")
        sections.append(f"{alert.alert_signature} (SID {alert.alert_signature_id})")
        sections.append(f"Severity: {alert.alert_severity.value}")
        sections.append(f"Source: {alert.src_ip}:{alert.src_port}")
        sections.append(f"Destination: {alert.dest_ip}:{alert.dest_port}")
        sections.append(f"Timestamp (UTC): {alert.timestamp.isoformat()}")

        if network_context is not None:
            sections.append("\n## Network context")
            sections.append(json.dumps(network_context.model_dump(), default=str, indent=2)[:4000])
        if forensic_result is not None:
            sections.append("\n## Forensic snapshot")
            sections.append(json.dumps(forensic_result.model_dump(), default=str, indent=2)[:6000])
        if vt_results:
            sections.append("\n## VirusTotal / local AV verdicts")
            for vt in vt_results:
                sections.append(json.dumps(vt.model_dump(), default=str, indent=2))
        if timeline:
            sections.append("\n## Timeline")
            sections.append(json.dumps(timeline, default=str, indent=2)[:6000])
        if iocs:
            sections.append("\n## Observables (IOCs)")
            sections.append(json.dumps(iocs, default=str, indent=2)[:4000])
        if attack_techniques:
            sections.append("\n## MITRE ATT&CK candidates")
            sections.append(json.dumps(attack_techniques, default=str, indent=2))

        sections.append(
            "\n## Instructions\n"
            "Write the post-incident report as specified in the system prompt. "
            "Keep it under 1500 words. Use markdown headings and bullet lists."
        )
        return "\n".join(sections)

    def _build_analysis_prompt(
        self,
        alert: SuricataAlert,
        network_context: Optional[NetworkContext],
        forensic_result: Optional[ForensicResult],
        vt_results: Optional[list[VirusTotalResult]],
        history_signals: Optional[Any] = None,
    ) -> str:
        """Build the analysis prompt with all available context.

        The prompt is constructed in two compounding stages:

        1. **Structural pruning** (:func:`_prune_network_context`,
           :func:`_prune_forensic_result`) removes slices whose content
           is almost never decision-grade on a live alert:
           ``TIME_WAIT`` / ``CLOSE_WAIT`` connections, Sysmon events
           more than five minutes old, DNS cache entries older than the
           20 most recent ones. This typically shaves 30-60% of the
           JSON byte count without losing signal.

        2. **Severity-scaled character budget** caps each section in
           proportion to how much scrutiny the alert deserves: SEV-1
           (HIGH) keeps a generous budget so a real investigation never
           misses a faint indicator; SEV-2/3 — which carry 95% of the
           daily volume — get a tight cap that keeps token spend in
           the sub-dollar range per analysis.

        Args:
            alert: The triggering alert. Used both for the prompt's
                "Suricata Alert" header and to size the budget.
            network_context: Enrichment data gathered by the Collector.
            forensic_result: Local Windows forensic snapshot.
            vt_results: VirusTotal engine outputs.

        Returns:
            Formatted prompt string for Claude API.
        """
        budget = _budget_for(alert)
        sections: list[str] = []

        # Alert header — always full, and tiny.
        sections.append("## Suricata Alert")
        sections.append(f"Timestamp: {alert.timestamp.isoformat()}")
        sections.append(f"Source: {alert.src_ip}:{alert.src_port}")
        sections.append(f"Destination: {alert.dest_ip}:{alert.dest_port}")
        sections.append(f"Protocol: {alert.proto}")
        sections.append(f"Signature: {alert.alert_signature}")
        sections.append(f"Signature ID: {alert.alert_signature_id}")
        sections.append(f"Severity: {alert.alert_severity.value}")
        sections.append(f"Category: {alert.alert_category}")

        if network_context:
            pruned_ctx = _prune_network_context(network_context)
            sections.append("\n## Network Context")
            sections.append(
                json.dumps(pruned_ctx.model_dump(), default=str, indent=2)[: budget["network"]]
            )

        if forensic_result:
            pruned_fr = _prune_forensic_result(forensic_result, alert.timestamp)
            sections.append("\n## Local Forensic Analysis")
            sections.append(
                json.dumps(pruned_fr.model_dump(), default=str, indent=2)[: budget["forensic"]]
            )
            # Distil the process_risk scoring (v0.20.x) into a short,
            # LLM-readable block. The JSON dump above already carries
            # the same data, but surfacing the verdicts as plain text
            # makes sure Opus weighs them even when the JSON gets
            # trimmed by the character budget.
            risk_section = _render_process_risk_section(pruned_fr)
            if risk_section:
                sections.append(risk_section)

        if vt_results:
            sections.append("\n## VirusTotal Results")
            for vt in vt_results:
                sections.append(json.dumps(vt.model_dump(), default=str, indent=2)[: budget["vt"]])

        history_block = _render_history_section(history_signals)
        if history_block:
            sections.append(history_block)

        sections.append(
            "\n## Instructions\n"
            "Analyze the above data and respond with a JSON object containing "
            "your verdict, confidence, reasoning, recommended actions, "
            "IOC summary, and false positive indicators."
        )

        return "\n".join(sections)
