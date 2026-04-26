"""Entry point and pipeline orchestration for WardSOAR.

This module wires all pipeline components together and runs
the main processing loop. It contains ONLY orchestration logic —
no business logic belongs here.

Usage:
    python -m src.main
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Optional, Union

from wardsoar.pc import __version__
from wardsoar.core.alert_queue import AlertQueue
from wardsoar.core.analyzer import ThreatAnalyzer
from wardsoar.core.asn_enricher import AsnEnricher
from wardsoar.core.cdn_allowlist import CdnAllowlist
from wardsoar.core.baseline import NetworkBaseline
from wardsoar.pc.collector import ContextCollector
from wardsoar.core.config import AppConfig, WhitelistConfig
from wardsoar.core.decision_cache import DecisionCache
from wardsoar.core.deduplicator import AlertDeduplicator
from wardsoar.core.filter import AlertFilter
from wardsoar.pc.forensic import (
    DeepAnalysisOrchestrator,
    ProtectedEvidenceStorage,
    QuickAcquisitionManager,
)
from wardsoar.pc.forensic.orchestrator import build_default_manager as build_quick_acquirer
from wardsoar.pc.forensics import ForensicAnalyzer
from wardsoar.pc.healthcheck import HealthChecker
from wardsoar.core.known_bad_actors import KnownActorsRegistry
from wardsoar.pc.local_av import DefenderScanner, FileScanOrchestrator, YaraScanner
from wardsoar.core.logger import log_decision
from wardsoar.core.metrics import MetricsCollector
from wardsoar.core.models import DecisionRecord, SuricataAlert, ThreatVerdict
from wardsoar.core.notifier import Notifier
from wardsoar.core.remote_agents import (
    NetgateAgent,
    NoOpAgent,
    RemoteAgent,
    RemoteAgentRegistry,
)
from wardsoar.core.remote_agents.pfsense_ssh import BlockTracker
from wardsoar.core.prescorer import AlertPreScorer
from wardsoar.core.prescorer_feedback import PreScorerFeedbackStore
from wardsoar.core.responder import ThreatResponder
from wardsoar.core.rollback import RollbackManager, RollbackResult
from wardsoar.core.rule_manager import RuleManager
from wardsoar.core.suspect_asns import SuspectAsnRegistry, TorExitFetcher
from wardsoar.core.trusted_temp import TrustedTempRegistry
from wardsoar.core.virustotal import VirusTotalClient
from wardsoar.core.vt_cache import VTCache

logger = logging.getLogger("ward_soar.main")


@dataclass(frozen=True)
class FilteredResult:
    """Returned by process_alert() when an alert is filtered early."""

    reason: str


#: Return type of Pipeline.process_alert().
PipelineResult = Union[DecisionRecord, FilteredResult]


class Pipeline:
    """Orchestrate the full alert processing pipeline.

    Wires all components together and processes alerts
    through the 13-step pipeline defined in CLAUDE.md.

    Args:
        config: Application configuration.
        whitelist: Whitelist configuration.
    """

    def __init__(self, config: AppConfig, whitelist: WhitelistConfig) -> None:
        self._config = config
        self._whitelist = whitelist
        # Cached Netgate audit result — populated by :meth:`audit_netgate`
        # and read by the UI's mode-escalation gate. ``None`` means "no
        # audit has run yet", which the gate treats as "unknown" (allows
        # Monitor, blocks Protect/Hard Protect until the user runs the
        # Netgate check).
        from wardsoar.core.netgate_audit import AuditResult as _AuditResult

        self._last_audit_result: Optional[_AuditResult] = None
        # Tamper detector built lazily in :meth:`_get_tamper_detector`
        # because it needs the SSH handle created further down.
        self._tamper_detector: Optional[object] = None

        # Build the remote enforcement agent based on the operator's
        # answers in the SourcesQuestionnaire (persisted under
        # config.sources). Three branches:
        #
        #   * netgate=True            -> real NetgateAgent (legacy default,
        #                                rétro-compat for configs without
        #                                a sources: key);
        #   * netgate=False
        #     + suricata_local=True   -> WindowsFirewallBlocker (standalone
        #                                PC mode — local netsh-based blocks);
        #   * netgate=False
        #     + suricata_local=False  -> NoOpAgent (degenerate: the
        #                                SourcesQuestionnaire's "≥1 source"
        #                                rule should make this unreachable
        #                                in practice, but the branch
        #                                exists so the pipeline never
        #                                crashes on a hand-edited config).
        netgate_enabled: bool = bool(config.sources.get("netgate", True))
        suricata_local_enabled: bool = bool(config.sources.get("suricata_local", False))
        pfsense_cfg = config.responder.get("pfsense", {})
        ssh_key_path = pfsense_cfg.get("ssh_key_path", "") or os.getenv("WARD_SSH_KEY_PATH", "")

        # ``self._netgate`` is the NetgateAgent typed handle reserved
        # for the Netgate-specific layers (audit / tamper / apply /
        # custom_rules). It is None when Netgate is disabled so those
        # methods can early-return cleanly. ``self._netgate_agent`` is
        # the protocol-typed handle every other consumer takes.
        self._netgate: Optional[NetgateAgent] = None
        self._netgate_agent: RemoteAgent
        agent_registry_name: str
        if netgate_enabled:
            self._netgate = NetgateAgent.from_credentials(
                host=config.network.get("pfsense_ip", "192.168.2.1"),
                ssh_user=pfsense_cfg.get("ssh_user", "admin"),
                ssh_key_path=ssh_key_path,
                ssh_port=int(pfsense_cfg.get("ssh_port", 22)),
                blocklist_table=pfsense_cfg.get("blocklist_table", "blocklist"),
            )
            self._netgate_agent = self._netgate
            agent_registry_name = "netgate"
        elif suricata_local_enabled:
            from wardsoar.pc.local_suricata import (
                SuricataProcess,
                find_suricata_install_dir,
            )
            from wardsoar.pc.local_suricata_agent import LocalSuricataAgent
            from wardsoar.pc.windows_firewall import WindowsFirewallBlocker

            logger.info(
                "config.sources: standalone-PC mode (netgate=False, "
                "suricata_local=True) — composing LocalSuricataAgent "
                "(local Suricata source + Windows Firewall enforcement). "
                "Blocking requires WardSOAR to run with administrator "
                "privileges."
            )

            # Resolve the Suricata install layout. Falls back to a
            # WindowsFirewallBlocker-only registry when Suricata is
            # not installed yet (the wizard catches this earlier; the
            # branch exists so the pipeline survives a hand-edited
            # config).
            suricata_dir = find_suricata_install_dir()
            local_cfg = config.suricata_local if hasattr(config, "suricata_local") else {}
            interface = local_cfg.get("interface", "") if isinstance(local_cfg, dict) else ""

            blocker = WindowsFirewallBlocker()

            if suricata_dir is None or not interface:
                logger.warning(
                    "config.sources: suricata_local=True but "
                    "Suricata is not installed (suricata_dir=%s) "
                    "or no interface configured (interface=%r). "
                    "Falling back to WindowsFirewallBlocker as a "
                    "sink-only enforcement agent. Run the wizard "
                    "to complete the Suricata setup.",
                    suricata_dir,
                    interface,
                )
                self._netgate_agent = blocker
                agent_registry_name = "windows_firewall"
            else:
                from wardsoar.core.config import get_data_dir

                log_dir = get_data_dir() / "suricata"
                config_path = log_dir / "suricata.yaml"
                # Note: suricata.yaml is generated by the wizard
                # at install time. Pipeline does not regenerate
                # it on every boot — that would clobber operator
                # edits.

                process = SuricataProcess(
                    binary_path=suricata_dir / "suricata.exe",
                    config_path=config_path,
                    interface=interface,
                    log_dir=log_dir,
                )
                self._netgate_agent = LocalSuricataAgent(
                    process=process,
                    blocker=blocker,
                )
                agent_registry_name = "local_suricata"
                logger.info(
                    "config.sources: LocalSuricataAgent ready "
                    "(interface=%s, eve_path=%s). Suricata will be "
                    "started by the agent on first stream consumption.",
                    interface,
                    process.eve_path,
                )
        else:
            logger.warning(
                "config.sources: no enforcement agent configured "
                "(netgate=False, suricata_local=False). Verdicts will "
                "still be computed but blocks will go nowhere. The "
                "SourcesQuestionnaire normally prevents this state — "
                "check config.yaml if you reach this branch."
            )
            self._netgate_agent = NoOpAgent()
            agent_registry_name = "no_op"

        # Single in-process registry of named agents — feeds future
        # multi-agent dispatching once VirusSniffAgent lands. For now
        # the registry holds the single active agent under the name
        # the branch above selected.
        self._agent_registry = RemoteAgentRegistry()
        self._agent_registry.register(agent_registry_name, self._netgate_agent)
        from wardsoar.core.config import get_bundle_dir, get_data_dir

        block_tracker = BlockTracker(persist_path=get_data_dir() / "block_tracker.json")
        # Keep a direct handle so the post-reset cleanup can purge the
        # shared tracker without reaching into Responder / RuleManager
        # internals via SLF001.
        self._block_tracker = block_tracker

        # Rollback machinery — see docs/architecture.md §4.
        # Created early so they can be injected into PreScorer / Responder.
        trusted_temp_registry = TrustedTempRegistry(
            persist_path=get_data_dir() / "trusted_temp.json"
        )
        feedback_store = PreScorerFeedbackStore(
            persist_path=get_data_dir() / "prescorer_feedback.json"
        )
        self._trusted_temp = trusted_temp_registry
        self._feedback_store = feedback_store

        # Threat-actor-aware ASN enrichment (Phase 4.5).
        # Resolves alert source IPs to their ASN and weights the result
        # against a curated suspect-ASN list. Fail-safe: every component
        # degrades silently to "no bonus" so a network outage cannot
        # stop the pipeline.
        self._asn_enricher = AsnEnricher(
            cache_path=get_data_dir() / "data" / "asn_cache.db",
        )
        suspect_asn_path = get_bundle_dir() / "config" / "suspect_asns.yaml"
        self._suspect_asn_registry = SuspectAsnRegistry(config_path=suspect_asn_path)
        self._tor_exit_fetcher = TorExitFetcher(registry=self._suspect_asn_registry)

        # Known adversary registry (Phase 4.6). A hit here short-circuits
        # scoring — the high weight guarantees Opus gets asked to judge.
        # See config/known_bad_actors.yaml and docs/architecture.md.
        self._known_actors = KnownActorsRegistry(
            config_path=get_bundle_dir() / "config" / "known_bad_actors.yaml"
        )

        # CDN / major-SaaS allowlist (Phase 7e, v0.7.6).
        # Consulted by the Responder in Hard Protect mode so a
        # legitimate CDN / streaming IP does not get blocked on a
        # low-confidence BENIGN verdict. Empty registry on missing
        # file → Hard Protect stays strict (safe default).
        self._cdn_allowlist = CdnAllowlist(
            config_path=get_bundle_dir() / "config" / "cdn_allowlist.yaml"
        )
        logger.info("cdn_allowlist: %d ASN(s) loaded", len(self._cdn_allowlist))
        for entry in self._known_actors.snapshot():
            logger.info(
                "known_bad_actors: %s (%s) weight=%d — %d IP / %d CIDR / %d domain",
                entry["id"],
                entry["name"],
                entry["weight"],
                entry["ips"],
                entry["cidrs"],
                entry["domains"],
            )

        # Initialize all pipeline components
        self._filter = AlertFilter(config.filter)
        self._deduplicator = AlertDeduplicator(config.deduplicator)
        self._prescorer = AlertPreScorer(config.prescorer, feedback_store=feedback_store)
        self._collector = ContextCollector(config.forensics, config.reputation)
        self._baseline = NetworkBaseline(config.baseline)
        self._forensics = ForensicAnalyzer(config.forensics)
        # Rolling snapshot buffer — level 2 of process attribution
        # (see src/process_snapshot_buffer.py). Attached to the
        # analyzer so every forensic call extends its psutil search
        # back over the last ~60 s of socket history. The background
        # task is started from the engine loop once asyncio is up
        # (see src/ui/engine_bridge.py).
        from wardsoar.pc.process_snapshot_buffer import (
            NetConnectionsBuffer,
            attach_buffer_to_analyzer,
        )

        self._conn_buffer = NetConnectionsBuffer()
        attach_buffer_to_analyzer(self._forensics, self._conn_buffer)

        # PID-keyed cache for risk scoring (v0.20.3). Amortises the
        # ~100 ms cost of scoring a process across bursts of alerts
        # from the same PID — a 50-alert Cloudflare STUN burst costs
        # one scan instead of fifty.
        from wardsoar.pc.process_risk_cache import ProcessRiskCache

        self._process_risk_cache = ProcessRiskCache()

        # Longitudinal alert statistics (v0.22). Persisted SQLite
        # store that feeds the PreScorer + Opus prompt with pattern
        # signals (regularity, novelty, verdict stability) over the
        # last 7 days. The background flush task starts from the
        # engine loop; see src/ui/engine_bridge.py.
        from wardsoar.core.alerts_stats import AlertsStatsStore

        self._alerts_stats = AlertsStatsStore(
            db_path=get_data_dir() / "data" / "alerts_stats.db",
        )

        # VT cache + rate limiter: persistent SQLite co-located with logs so
        # the daily counter survives restarts and WardSOAR does not burn its
        # free-tier quota re-querying the same hashes.
        vt_cfg = config.virustotal
        vt_cache = VTCache(
            db_path=get_data_dir() / "data" / "vt_cache.db",
            ttl_malicious=int(vt_cfg.get("cache_ttl_malicious", 7 * 24 * 3600)),
            ttl_clean=int(vt_cfg.get("cache_ttl_clean", 24 * 3600)),
            max_per_minute=int(vt_cfg.get("max_per_minute", 4)),
            max_per_day=int(vt_cfg.get("max_per_day", 500)),
        )
        self._virustotal = VirusTotalClient(vt_cfg, cache=vt_cache)

        # Privacy-first cascade: Defender → YARA → VirusTotal.
        # See docs/architecture.md section 2 and src/local_av/orchestrator.py.
        #
        # YARA rules directory resolution: config may hand us a relative
        # path (default "config/yara_rules"). In a frozen build the CWD
        # is not the install dir, so we resolve the default against
        # get_bundle_dir() — which points at PyInstaller's ``_internal/``
        # where the rules are actually packaged. Using get_app_dir() here
        # skipped the prefix and left the scanner idle after install.
        yara_cfg = dict(config.local_av.get("yara") or {})
        raw_rules_dir = yara_cfg.get("rules_dir", "config/yara_rules")
        if not os.path.isabs(raw_rules_dir):
            yara_cfg["rules_dir"] = str((get_bundle_dir() / raw_rules_dir).resolve())
        self._scan_cascade = FileScanOrchestrator(
            defender=DefenderScanner(config.local_av.get("defender")),
            yara=YaraScanner(yara_cfg),
            vt_client=self._virustotal,
        )
        self._analyzer = ThreatAnalyzer(config.analyzer)
        self._decision_cache = DecisionCache(config.decision_cache)
        self._responder = ThreatResponder(
            config.responder,
            whitelist,
            self._netgate_agent,
            block_tracker,
            trusted_temp=trusted_temp_registry,
            confidence_threshold=config.analyzer.get("confidence_threshold", 0.7),
            hard_protect_benign_threshold=config.analyzer.get(
                "hard_protect_benign_threshold", 0.99
            ),
            cdn_allowlist=self._cdn_allowlist,
        )
        self._rule_manager = RuleManager(
            config.rule_manager,
            whitelist,
            self._netgate_agent,
            block_tracker,
            block_duration_hours=config.responder.get("block_duration_hours", 24),
        )
        self._notifier = Notifier(config.notifier)
        self._metrics = MetricsCollector(config.metrics)
        self._healthcheck = HealthChecker(config.healthcheck, pfsense_ssh=self._netgate_agent)
        self._queue = AlertQueue(config.alert_queue)

        # Rollback orchestrator — wired last, after rule_manager is built.
        self._rollback_manager = RollbackManager(
            rule_manager=self._rule_manager,
            trusted_temp=trusted_temp_registry,
            feedback_store=feedback_store,
            audit_log_path=get_data_dir() / "logs" / "rollback_audit.jsonl",
        )

        # Kick off a one-shot Tor exit refresh so the registry is primed
        # as soon as the engine starts handling alerts. Non-blocking; if
        # the loop isn't running yet (sync construction path), the first
        # alert will trigger its own refresh via the heartbeat.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._tor_exit_fetcher.refresh(force=True))
        except RuntimeError:
            pass

        # Post-block forensic quick acquisition — captures volatile state
        # right after a successful block so RAM / process / network facts
        # are frozen before they change. See docs/architecture.md §3.
        forensic_cfg = config.forensic
        encryption_scope = str(forensic_cfg.get("encryption_scope", "user"))
        apply_acls = bool(forensic_cfg.get("apply_acls", True))
        evidence_root = get_data_dir() / "evidence"
        self._quick_acquirer: QuickAcquisitionManager = build_quick_acquirer(
            evidence_root=evidence_root,
            encryption_scope=encryption_scope,
            apply_acls=apply_acls,
        )

        # Deep analysis orchestrator — consumes the quick acquisition output,
        # runs Opus deep_analyze, builds the PDF and exports the ZIP bundle.
        deep_storage = ProtectedEvidenceStorage(
            root_dir=evidence_root,
            apply_acls=False,  # reuse the already-hardened subdirs
            encryptor=(
                self._quick_acquirer._storage._encryptor  # noqa: SLF001 — share encryptor
                if hasattr(self._quick_acquirer, "_storage")
                else None
            ),
        )
        self._deep_analysis = DeepAnalysisOrchestrator(
            analyzer=self._analyzer,
            storage=deep_storage,
            export_root=get_data_dir() / "reports",
        )

        # Visible startup banner so overnight logs make it obvious that
        # the pipeline was (re)constructed and which features are armed.
        logger.info("=" * 60)
        logger.info("Pipeline initialised — WardSOAR v%s", __version__)
        logger.info("  prescorer mode:         %s", config.prescorer.get("mode", "learning"))
        logger.info(
            "  prescorer threshold:    %s",
            config.prescorer.get("min_score_for_analysis", 15),
        )
        logger.info("  analyzer model:         %s", config.analyzer.get("model", "?"))
        logger.info(
            "  local AV cascade:       defender=%s yara=%s",
            bool(config.local_av.get("defender", {}).get("enabled", True)),
            bool(config.local_av.get("yara", {}).get("enabled", True)),
        )
        logger.info("  forensic encryption:    %s", encryption_scope)
        logger.info("  evidence root:          %s", evidence_root)
        logger.info("  responder dry_run:      %s", config.responder.get("dry_run", True))
        logger.info("=" * 60)

    def _schedule_quick_acquisition(
        self,
        record: DecisionRecord,
        forensic_result: Any,
    ) -> None:
        """Fire-and-forget post-block forensic capture.

        The quick acquisition is volatile-data only, bounded at about one
        minute by design. We schedule it as a background task so the
        pipeline can return and start processing the next alert.
        """
        # Target PIDs = those correlated with the offending IP in the
        # forensic enrichment step. Fallback to empty list if missing.
        target_pids: list[int] = []
        processes = getattr(forensic_result, "suspect_processes", []) or []
        for proc in processes:
            pid = proc.get("pid") if isinstance(proc, dict) else None
            if isinstance(pid, int):
                target_pids.append(pid)

        alert = record.alert

        async def _runner() -> None:
            try:
                quick_result = await self._quick_acquirer.quick_acquire(
                    alert_id=record.record_id,
                    alert=alert,
                    target_pids=target_pids,
                )
                logger.info(
                    "[post-block] quick acquisition done: dir=%s artefacts=%d memdumps=%d errors=%d",
                    quick_result.incident_dir,
                    quick_result.artefact_count,
                    quick_result.memdump_count,
                    len(quick_result.errors),
                )
            except Exception:  # noqa: BLE001 — never take the worker down
                logger.exception("[post-block] quick acquisition crashed")
                return

            # Deep analysis consumes the in-memory manifest built during
            # quick_acquire. Re-reading from disk would force us to open
            # an already-sealed file — the exact failure mode observed
            # on 2026-04-23 22:40 (WinError 5 Access denied on
            # MANIFEST.json.dpapi). Since the object was just produced
            # in-process and the on-disk bytes hash matches what the
            # manifest itself records, chain-of-custody is preserved.
            manifest = quick_result.manifest
            storage = self._quick_acquirer._storage  # noqa: SLF001

            try:
                if manifest is None:
                    # Idempotent skip landed on an unreadable manifest.
                    # Surface the integrity issue and stop — running deep
                    # analysis without a manifest would produce a bundle
                    # with no chain-of-custody anchor.
                    logger.error(
                        "[post-block] deep analysis skipped — manifest unavailable for %s",
                        quick_result.incident_dir,
                    )
                    return

                deep_result = await self._deep_analysis.run(
                    record=record,
                    incident_dir=quick_result.incident_dir,
                    manifest=manifest,
                    rollback_events=None,
                    include_evidence_in_zip=True,
                )
                logger.info(
                    "[post-block] deep analysis done: zip=%s iocs=%d techniques=%d",
                    deep_result.zip_path,
                    deep_result.ioc_count,
                    deep_result.technique_count,
                )
            except Exception:  # noqa: BLE001 — deep analysis failure must not crash worker
                logger.exception("[post-block] deep analysis crashed")
            finally:
                # Tighten the evidence directory ACLs only after every
                # read/write that the forensic chain needs has happened.
                # Runs even when deep analysis fails, so tamper-resistance
                # is still applied to whatever did land on disk.
                try:
                    storage.seal_directory(quick_result.incident_dir)
                except Exception:  # noqa: BLE001 — sealing is best-effort
                    logger.exception("[post-block] seal_directory failed")

        try:
            asyncio.get_running_loop().create_task(_runner())
        except RuntimeError:
            # No running loop (e.g. called from a sync context) — run it
            # synchronously as a best-effort fallback.
            logger.debug("No running loop; running quick acquisition inline")
            asyncio.run(_runner())

    async def rollback_block(
        self,
        ip: str,
        signature_id: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> RollbackResult:
        """Public entry point for UI-initiated rollbacks.

        Delegates to the RollbackManager and returns its structured result
        so the caller (usually the UI bridge) can surface the outcome.
        """
        return await self._rollback_manager.rollback(
            ip=ip,
            signature_id=signature_id,
            reason=reason,
        )

    async def audit_netgate(self) -> "Any":
        """Run the Phase 7a Netgate audit and cache the result.

        Returns a :class:`src.netgate_audit.AuditResult`. The return
        value is also assigned to :attr:`_last_audit_result` so the
        UI's mode-escalation gate can consult it without re-running
        SSH commands.

        Returns ``None`` when ``config.sources.netgate=False`` — the
        operator declared no Netgate in the SourcesQuestionnaire so
        an audit has nothing to check. The UI is expected to hide
        the Audit button in that mode; this guard is the safety net.
        """
        if self._netgate is None:
            logger.warning(
                "audit_netgate called but Netgate is disabled in config.sources — skipping"
            )
            return None

        from wardsoar.core.netgate_audit import run_audit

        result = await run_audit(self._netgate, self._config)
        self._last_audit_result = result
        logger.info(
            "netgate_audit: %d findings in %.2fs, any_critical_ko=%s",
            len(result.findings),
            result.duration_seconds,
            result.any_critical_ko,
        )
        return result

    @property
    def last_audit_result(self) -> "Any":
        """Most-recent :class:`AuditResult`, or ``None`` if never audited."""
        return self._last_audit_result

    # ------------------------------------------------------------------
    # Phase 7g — Netgate tamper detection
    # ------------------------------------------------------------------

    def _get_tamper_detector(self) -> "Any":
        """Lazy builder for the detector (reuses SSH + a stable path).

        Returns ``None`` when ``config.sources.netgate=False`` — same
        rationale as :meth:`audit_netgate`. Callers
        (``netgate_baseline_captured_at``, ``establish_netgate_baseline``,
        ``check_netgate_tampering``) handle ``None`` by short-circuiting
        their operation.
        """
        if self._netgate is None:
            return None
        if self._tamper_detector is None:
            from wardsoar.core.config import get_data_dir
            from wardsoar.core.netgate_tamper import NetgateTamperDetector

            self._tamper_detector = NetgateTamperDetector(
                ssh=self._netgate,
                baseline_path=get_data_dir() / "netgate_baseline.json",
                host=self._config.network.get("pfsense_ip", ""),
            )
        return self._tamper_detector

    def netgate_baseline_captured_at(self) -> Optional[str]:
        """Return the ISO timestamp of the stored baseline, or ``None``.

        The UI calls this on startup to decide whether to show
        *Establish baseline* or *Re-bless baseline* next to the
        Integrity card.
        """
        detector = self._get_tamper_detector()
        baseline = detector.load_baseline()
        return baseline.captured_at if baseline is not None else None

    async def establish_netgate_baseline(self) -> "Any":
        """Capture a fresh tamper baseline and persist it."""
        detector = self._get_tamper_detector()
        baseline = await detector.establish_baseline()
        logger.warning(
            "netgate_tamper: baseline (re)established — %d surface(s) at %s",
            len(baseline.entries),
            baseline.captured_at,
        )
        return baseline

    def cleanup_netgate_state(self) -> "Any":
        """Purge WardSOAR state tied to a Netgate that just got reset.

        After a factory reset of the Netgate, three local files become
        misleading: the tamper baseline (every surface changed), the
        block tracker (pf table is empty), and the trusted-temp registry
        (quarantine rules are gone). This entry point wipes all three
        atomically — the live :class:`BlockTracker` and
        :class:`TrustedTempRegistry` in-memory state are cleared in the
        same step so the pipeline doesn't silently repopulate the files
        from stale entries.

        The tamper detector is re-created lazily on the next call to
        :meth:`_get_tamper_detector` so its in-memory baseline is also
        dropped. The operator is expected to click *Establish baseline*
        once the Netgate is re-configured.

        Returns:
            A :class:`~src.netgate_reset.NetgateResetCleanupResult`.
        """
        from wardsoar.core.config import get_data_dir
        from wardsoar.core.netgate_reset import cleanup_netgate_state, default_baseline_path

        baseline_path = default_baseline_path(get_data_dir())
        result = cleanup_netgate_state(
            block_tracker=self._block_tracker,
            trusted_temp=self._trusted_temp,
            baseline_path=baseline_path,
        )
        # Force the tamper detector to rebuild on its next use — the
        # previously-built one cached the now-deleted baseline in
        # memory via its load_baseline() return value.
        self._tamper_detector = None
        logger.warning(
            "netgate_reset: operator-initiated cleanup — baseline_removed=%s "
            "blocks_purged=%d trusted_purged=%d",
            result.baseline_removed,
            result.block_entries_purged,
            result.trusted_entries_purged,
        )
        return result

    async def check_netgate_tampering(self) -> "Any":
        """Diff current state vs baseline and return the deviation report."""
        detector = self._get_tamper_detector()
        result = await detector.check_for_tampering()
        if result.any_deviation:
            logger.warning(
                "netgate_tamper: %d deviation(s) detected since baseline",
                len(result.findings),
            )
        else:
            logger.info(
                "netgate_tamper: no deviation vs baseline (ssh_ok=%s, baseline_present=%s)",
                result.ssh_reachable,
                result.baseline_present,
            )
        return result

    # ------------------------------------------------------------------
    # Phase 7c — Custom Suricata rules (Ben-model + KBA IOCs)
    # ------------------------------------------------------------------

    def preview_custom_rules(self) -> "Any":
        """Render (without shipping) the custom rules file for UI preview.

        Returns a :class:`src.netgate_custom_rules.RulesBundle`. The UI
        shows the rendered content in a dialog so the operator can
        read exactly what would be written to the Netgate before
        clicking Deploy.
        """
        from wardsoar.core.netgate_custom_rules import build_bundle

        return build_bundle(self._known_actors)

    async def deploy_custom_rules(self) -> "Any":
        """Build the custom rules and push them to the Netgate via SSH.

        Returns a stub :class:`DeployResult` with an error message when
        ``config.sources.netgate=False`` — same rationale as
        :meth:`audit_netgate`.
        """
        from wardsoar.core.netgate_custom_rules import (
            DeployResult,
            build_bundle,
            deploy_bundle,
        )

        if self._netgate is None:
            return DeployResult(
                success=False,
                bytes_written=0,
                remote_path="",
                error="Netgate disabled in config.sources — no remote rules deployed.",
            )

        bundle = build_bundle(self._known_actors)
        result = await deploy_bundle(self._netgate, bundle)
        if result.success:
            logger.warning(
                "netgate_custom_rules: deployed %d rules (%d bytes) to %s",
                len(bundle.rules),
                result.bytes_written,
                result.remote_path,
            )
        else:
            logger.error("netgate_custom_rules: deploy failed — %s", result.error or "unknown")
        return result

    # ------------------------------------------------------------------
    # Phase 7b -- Safe apply of audit findings
    # ------------------------------------------------------------------

    def _get_netgate_applier(self) -> "Any":
        """Lazy-build the applier so the backup dir is created once.

        Returns ``None`` when ``config.sources.netgate=False`` —
        callers (``apply_netgate_fixes``) short-circuit accordingly.
        """
        if self._netgate is None:
            return None
        cached = getattr(self, "_netgate_applier", None)
        if cached is not None:
            return cached
        from wardsoar.core.config import get_data_dir
        from wardsoar.core.netgate_apply import NetgateApplier

        applier = NetgateApplier(
            ssh=self._netgate,
            backup_dir=get_data_dir() / "netgate_backups",
        )
        self._netgate_applier = applier
        return applier

    async def apply_netgate_fixes(self, fix_ids: list[str]) -> list["Any"]:
        """Apply a list of audit-finding fix ids with safe-apply semantics.

        Delegates to :class:`src.netgate_apply.NetgateApplier`. The
        UI is the only caller; it passes the subset of checked
        findings whose fix id has a registered handler (applicable
        fix ids are exposed via :meth:`netgate_applicable_fix_ids`).

        Returns an empty list when ``config.sources.netgate=False`` —
        same rationale as :meth:`audit_netgate`.
        """
        applier = self._get_netgate_applier()
        if applier is None:
            logger.warning(
                "apply_netgate_fixes called but Netgate is disabled in "
                "config.sources — returning empty result"
            )
            return []
        results: list[Any] = await applier.safe_apply_many(fix_ids)
        return results

    @staticmethod
    def netgate_applicable_fix_ids() -> set[str]:
        """Fix ids that the UI is allowed to offer an Apply button for."""
        from wardsoar.core.netgate_apply import applicable_fix_ids

        return applicable_fix_ids()

    async def process_alert(self, alert: SuricataAlert) -> PipelineResult:
        """Process a single alert through the full pipeline.

        Implements the 13-step pipeline from CLAUDE.md.
        Fail-safe: any error → log, skip blocking, continue.

        Args:
            alert: The incoming Suricata alert.

        Returns:
            DecisionRecord if fully processed, FilteredResult if filtered early.
        """
        import time
        import uuid

        start_time = time.monotonic()
        self._metrics.increment("alerts_total")
        logger.info(
            "[pipeline] Start: %s -> %s (SID %s)",
            alert.src_ip,
            alert.dest_ip,
            alert.alert_signature_id,
        )

        # Step 0 — early process attribution + risk scoring.
        # Runs BEFORE the filter so a malicious local process can
        # override a known-FP suppression, and so the PreScorer sees
        # the risk verdict as one of its factors. Heavy lifting
        # (PowerShell Authenticode, Sysmon Event 3) is amortised via
        # the PID cache — a burst of 50 STUN alerts from chrome.exe
        # costs one scoring call, not fifty.
        from wardsoar.pc.forensics import build_flow_key

        flow = build_flow_key(alert)
        worst_risk_verdict: Optional[str] = None
        try:
            pids = self._forensics.get_pids_for_flow(flow)
            if pids:
                risk_verdicts = [self._process_risk_cache.get_or_scan(p).verdict for p in pids]
                # "Worst" in risk-order. malicious > suspicious > unknown > benign.
                order = {"malicious": 3, "suspicious": 2, "unknown": 1, "benign": 0}
                worst_risk_verdict = max(risk_verdicts, key=lambda v: order.get(v, 0))
                logger.info(
                    "[pipeline] Step 0: process risk %s (pids=%s)",
                    worst_risk_verdict,
                    sorted(pids),
                )
        except Exception:  # noqa: BLE001 — risk scoring must never break the pipeline
            logger.debug("[pipeline] early risk scoring raised", exc_info=True)

        # Step 1: Filter known false positives
        if self._filter.should_suppress(alert, process_risk_verdict=worst_risk_verdict):
            self._metrics.increment("alerts_filtered")
            logger.info("[pipeline] Step 1: filtered (SID %s)", alert.alert_signature_id)
            return FilteredResult(
                reason=f"filter: known false positive (SID {alert.alert_signature_id})"
            )

        # Step 2: Deduplication
        group = self._deduplicator.process_alert(alert)
        if group is None:
            self._metrics.increment("alerts_deduplicated")
            logger.info("[pipeline] Step 2: deduplicated")
            return FilteredResult(reason="dedup: grouped with existing alert")

        # Step 3: Decision cache lookup
        cached = self._decision_cache.lookup(
            alert.src_ip, alert.alert_signature_id, alert.dest_port
        )
        if cached is not None:
            if cached.verdict == ThreatVerdict.BENIGN:
                self._metrics.increment("cache_hits_benign")
                logger.info("[pipeline] Step 3: cache hit (benign)")
                return FilteredResult(reason="cache: recent benign verdict")
            # Confirmed cache hit → fast-track to responder handled below

        # Step 3.5: ASN enrichment (Phase 4.5 — threat-actor-aware scoring).
        # Looks up the source IP against a curated suspect-ASN registry so
        # the PreScorer can react to VPN / proxy / Tor exits independently
        # of reputation lists. Fail-safe: every failure returns None and
        # simply skips the bonus.
        #
        # Tor exit list is refreshed lazily — fire-and-forget so the first
        # alert doesn't pay the fetch latency. The fetcher short-circuits
        # when the interval hasn't elapsed, so this costs nothing after
        # the initial refresh.
        try:
            asyncio.get_running_loop().create_task(self._tor_exit_fetcher.refresh())
        except RuntimeError:
            pass

        asn_info = None
        try:
            asn_info = await self._asn_enricher.lookup(alert.src_ip)
        except Exception:  # noqa: BLE001 — enrichment must never break the pipeline
            logger.debug("[pipeline] ASN enrichment raised for %s", alert.src_ip)
        asn_classification = self._suspect_asn_registry.classify(alert.src_ip, asn_info)
        if asn_classification.total_weight > 0:
            logger.info(
                "[pipeline] ASN match: %s → category=%s weight=%d (+%d bonus)",
                alert.src_ip,
                asn_classification.category,
                asn_classification.weight,
                asn_classification.priority_country_bonus,
            )

        # Step 3.6: Known-adversary check (Phase 4.6).
        # A match here short-circuits normal scoring — emit a WARNING so
        # the operator sees it at the top of the trace even before Opus
        # runs, and log the specific IOC (IP / CIDR / domain) that fired.
        known_actor_match = self._known_actors.classify_ip(alert.src_ip)
        if known_actor_match is not None:
            logger.warning(
                "[KNOWN ADVERSARY] %s: alert from %s matches %s (%s=%s, weight=%d)",
                known_actor_match.actor_id,
                alert.src_ip,
                known_actor_match.name,
                known_actor_match.matched_by,
                known_actor_match.matched_value,
                known_actor_match.weight,
            )

        # Step 4: PreScorer
        # Longitudinal signals (v0.22) — pattern over the last 7 days.
        # Computed before PreScorer so beacon-like regularity / novelty
        # can adjust the score factors directly.
        history_signals: Optional[Any] = None
        try:
            history_signals = self._alerts_stats.compute_signals(
                sid=alert.alert_signature_id, src_ip=alert.src_ip
            )
        except Exception:  # noqa: BLE001 — stats layer must not break the pipeline
            logger.debug("[pipeline] alerts_stats.compute_signals raised", exc_info=True)

        prescore = self._prescorer.score(
            alert,
            alert_group_size=group.count,
            is_suspicious_port=self._baseline.is_suspicious_port(alert.dest_port),
            asn_classification=asn_classification,
            known_actor_match=known_actor_match,
            process_risk_verdict=worst_risk_verdict,
            history_signals=history_signals,
        )
        logger.info(
            "[pipeline] Step 4: prescorer score=%s filtered=%s",
            prescore.total_score,
            prescore.was_filtered,
        )
        if prescore.was_filtered:
            self._metrics.increment("alerts_prescored_out")
            return FilteredResult(
                reason=f"prescorer: score {prescore.total_score} below threshold {prescore.threshold}"
            )

        # Steps 5-8: Context enrichment
        logger.info("[pipeline] Step 5: collecting network context...")
        network_context = await self._collector.collect(alert)
        logger.info("[pipeline] Step 6: running forensics...")
        forensic_result = await self._forensics.analyze(alert)
        logger.info(
            "[pipeline] Step 7: running privacy-first cascade (%d suspect files)...",
            len(forensic_result.suspicious_files),
        )
        vt_results = await self._scan_cascade.scan_files(forensic_result.suspicious_files)

        # Use cached analysis or run new analysis
        if cached is not None:
            analysis = cached
            logger.info("[pipeline] Using cached analysis")
        else:
            # Step 9: Opus verdict — single-pass decision, no Confirmer in v0.5.
            logger.info("[pipeline] Step 9: calling Claude Opus...")
            analysis = await self._analyzer.analyze(
                alert,
                network_context,
                forensic_result,
                vt_results or None,
                history_signals=history_signals,
            )
            logger.info(
                "[pipeline] Step 9: done — verdict=%s confidence=%.2f",
                analysis.verdict.value,
                analysis.confidence,
            )

        # Build decision record
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        record = DecisionRecord(
            record_id=str(uuid.uuid4()),
            timestamp=alert.timestamp,
            alert=alert,
            network_context=network_context,
            forensic_result=forensic_result,
            virustotal_results=vt_results,
            analysis=analysis,
            pipeline_duration_ms=elapsed_ms,
        )

        # Step 11: Responder — always consulted from v0.5.5 onward.
        # Previous versions gated the call on ``verdict == CONFIRMED``,
        # but HARD_PROTECT mode must see every verdict (INCONCLUSIVE,
        # BENIGN-with-low-confidence, API error) to apply its inverted
        # block policy. The Responder's ``_decide_block`` enforces
        # per-mode semantics, so MONITOR and PROTECT produce the same
        # output as before.
        actions = await self._responder.respond(
            analysis,
            alert.src_ip,
            process_id=None,
            asn_info=asn_info,
        )
        record.actions_taken = actions

        # Step 11.5 — Post-block quick forensic acquisition.
        # Fires only when at least one action actually blocked pfSense;
        # scheduled as a background task so the pipeline can return
        # without waiting for process list + memory dumps.
        if any(action.success and action.target_ip == alert.src_ip for action in (actions or [])):
            self._schedule_quick_acquisition(record, forensic_result)

        # Step 12: Log decision
        log_dir = self._config.logging.get("log_dir", "logs")
        log_decision(log_dir, record)

        # Step 13: Cache the verdict
        self._decision_cache.store(
            alert.src_ip, alert.alert_signature_id, alert.dest_port, analysis
        )

        self._metrics.increment("alerts_processed")
        self._metrics.timing("pipeline_duration_ms", float(elapsed_ms))

        # Record the occurrence for longitudinal stats (v0.22). Fire
        # and forget — the store buffers writes and flushes them on
        # a background task, so this call is O(1).
        try:
            self._alerts_stats.record(
                sid=alert.alert_signature_id,
                src_ip=alert.src_ip,
                verdict=analysis.verdict.value if analysis else "unknown",
            )
        except Exception:  # noqa: BLE001 — stats must not break the pipeline
            logger.debug("alerts_stats.record raised", exc_info=True)

        return record


def main() -> int:
    """Application entry point.

    Returns:
        Exit code (0 for success).
    """
    from wardsoar.core.config import DEFAULT_CONFIG_PATH, get_data_dir
    from wardsoar.core.logger import setup_logging

    # Initialise logging first so any failure downstream produces a trace.
    # The trace file (trace_debug.log) always captures at DEBUG — see
    # src/logger.py — so the overnight run leaves a usable diary.
    log_dir = get_data_dir() / "logs"
    setup_logging(str(log_dir), level="INFO")

    needs_wizard = not DEFAULT_CONFIG_PATH.exists()

    # Start the UI application (wizard runs inside if needed)
    from wardsoar.pc.ui.app import WardApp

    app = WardApp(first_run=needs_wizard)
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
