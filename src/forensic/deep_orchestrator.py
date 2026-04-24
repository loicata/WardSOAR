"""End-to-end deep forensic analysis pipeline.

Triggered by the main Pipeline shortly after a successful block, this
module consumes the volatile evidence just captured by
:class:`QuickAcquisitionManager`, asks Opus for a human-readable
narrative, and emits the exportable ZIP bundle that becomes the
"WardSOAR Incident Report" for the operator (see docs/architecture.md §3).

High-level flow:

    decision_record + volatile_incident_dir
        │
        ├── IocExtractor          → STIX 2.1 + CSV observables
        ├── TimelineBuilder       → Plaso-compatible timeline
        ├── AttackMapper          → MITRE ATT&CK candidates
        ├── ThreatAnalyzer.deep_analyze() → markdown narrative
        ├── build_report_pdf()    → REPORT.pdf
        └── DeepReportExporter    → WardSOAR_Incident_*.zip

Run asynchronously as a background task so the main pipeline can
keep processing alerts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.analyzer import ThreatAnalyzer
from src.forensic.attack_mapper import AttackMapper, to_json_list as attack_to_json
from src.forensic.export import (
    DeepReportExporter,
    ExportBundleResult,
    default_zip_name,
)
from src.forensic.ioc_extractor import IocExtractor, to_csv, to_stix_bundle
from src.forensic.manifest import ForensicManifest
from src.forensic.report_pdf import build_report_pdf
from src.forensic.storage import ProtectedEvidenceStorage
from src.forensic.timeline import TimelineBuilder, to_json_list, to_plaso_csv
from src.models import DecisionRecord

logger = logging.getLogger("ward_soar.forensic.deep")


# Sections the LLM is asked to produce.
_EXECUTIVE_HEADING = "executive summary"
_TECHNICAL_HEADING = "technical analysis"


@dataclass
class DeepAnalysisResult:
    """Summary of a deep forensic run.

    Attributes:
        incident_dir: Volatile folder that fed the analysis.
        zip_path: Path of the exported ZIP (``None`` if export failed).
        pdf_path: Path of the rendered REPORT.pdf (may exist even if
                  the ZIP failed).
        opus_report_md: Full Opus narrative (empty on API failure).
        ioc_count: Number of unique observables extracted.
        technique_count: Number of matched ATT&CK techniques.
        timeline_entries: Number of entries in the super timeline.
        warnings: Human-readable issues encountered.
    """

    incident_dir: Path
    zip_path: Optional[Path] = None
    pdf_path: Optional[Path] = None
    opus_report_md: str = ""
    ioc_count: int = 0
    technique_count: int = 0
    timeline_entries: int = 0
    warnings: list[str] = field(default_factory=list)


class DeepAnalysisOrchestrator:
    """Assemble the four analysis stages + the export.

    Args:
        analyzer: Opus client used for the narrative.
        storage: Shared evidence storage (needed to decrypt DPAPI files
                 while exporting).
        export_root: Directory under which incident ZIPs are written.
        version: WardSOAR version embedded in the README.
    """

    def __init__(
        self,
        analyzer: ThreatAnalyzer,
        storage: ProtectedEvidenceStorage,
        export_root: Path,
        version: str = "0.5.0",
    ) -> None:
        self._analyzer = analyzer
        self._storage = storage
        self._export_root = export_root
        self._ioc_extractor = IocExtractor()
        self._timeline_builder = TimelineBuilder()
        self._attack_mapper = AttackMapper()
        self._exporter = DeepReportExporter(storage=storage, version=version)
        self._export_root.mkdir(parents=True, exist_ok=True)

    async def run(
        self,
        record: DecisionRecord,
        incident_dir: Path,
        manifest: ForensicManifest,
        rollback_events: Optional[list[dict[str, Any]]] = None,
        include_evidence_in_zip: bool = True,
    ) -> DeepAnalysisResult:
        """Execute the full deep analysis for one incident.

        Args:
            record: Original DecisionRecord (has alert, analysis, actions).
            incident_dir: Volatile acquisition directory — input to all
                          extractors and source of evidence files for the ZIP.
            manifest: Manifest produced by the quick phase; copied into
                      the ZIP and used for verification.
            rollback_events: Optional rollback audit log slices to embed
                             in the timeline.
            include_evidence_in_zip: When True (default) the full
                evidence tree is bundled (decrypted if necessary).

        Returns:
            DeepAnalysisResult describing every output.
        """
        logger.info(
            "[deep] Starting deep analysis for alert_id=%s dir=%s",
            manifest.alert_id,
            incident_dir,
        )
        warnings: list[str] = []

        # --- 1. IOC extraction (pure, cheap) ---------------------------
        iocs = self._ioc_extractor.extract(record)
        stix_bundle = to_stix_bundle(iocs)
        iocs_csv = to_csv(iocs)
        logger.info("[deep] IOC extractor produced %d observables", len(iocs))

        # --- 2. Timeline builder (pure, cheap) -------------------------
        timeline = self._timeline_builder.build(record, rollback_events=rollback_events)
        timeline_json = to_json_list(timeline)
        timeline_csv = to_plaso_csv(timeline)
        logger.info("[deep] Timeline has %d entries", len(timeline))

        # --- 3. ATT&CK mapping (pure, cheap) ---------------------------
        techniques = self._attack_mapper.map_record(record)
        techniques_json = attack_to_json(techniques)
        logger.info("[deep] MITRE ATT&CK matched %d techniques", len(techniques))

        # --- 4. Opus narrative (expensive, may fail) -------------------
        opus_md = await self._call_opus(record, timeline_json, iocs, techniques_json)
        if not opus_md.strip():
            warnings.append("Opus deep narrative unavailable; report falls back to stats only.")

        exec_md, tech_md = self._split_markdown_sections(opus_md)

        # --- 5. PDF assembly -------------------------------------------
        pdf_path = incident_dir / "REPORT.pdf"
        try:
            build_report_pdf(
                pdf_path,
                title=self._report_title(record),
                generated_at_utc=datetime.now(timezone.utc),
                alert_summary=manifest.alert_summary,
                executive_md=exec_md or opus_md or _fallback_exec(record),
                technical_md=tech_md,
                ioc_rows=iocs,
                attack_rows=techniques_json,
                timeline_rows=timeline_json,
            )
            logger.info("[deep] REPORT.pdf built at %s", pdf_path)
        except Exception as exc:  # noqa: BLE001 — PDF generation is best-effort
            logger.exception("[deep] PDF build failed")
            warnings.append(f"PDF build failed: {exc}")
            pdf_path = None  # type: ignore[assignment]

        # --- 6. ZIP export ---------------------------------------------
        alert_ip = record.alert.src_ip
        output_zip = self._export_root / default_zip_name(alert_ip)
        bundle_result: Optional[ExportBundleResult] = None
        try:
            bundle_result = self._exporter.export(
                incident_dir=incident_dir,
                output_zip=output_zip,
                manifest=manifest,
                pdf_path=pdf_path or incident_dir / "REPORT.pdf",
                opus_report_md=opus_md,
                iocs_stix=stix_bundle,
                iocs_csv=iocs_csv,
                timeline_csv=timeline_csv,
                timeline_json=timeline_json,
                attack_matches=techniques_json,
                include_evidence=include_evidence_in_zip,
            )
            warnings.extend(bundle_result.warnings)
            logger.info(
                "[deep] ZIP built: %s (%.1f KB)",
                bundle_result.zip_path,
                bundle_result.size_bytes / 1024,
            )
        except Exception as exc:  # noqa: BLE001 — export never crashes the worker
            logger.exception("[deep] ZIP export failed")
            warnings.append(f"ZIP export failed: {exc}")

        return DeepAnalysisResult(
            incident_dir=incident_dir,
            zip_path=bundle_result.zip_path if bundle_result else None,
            pdf_path=pdf_path if isinstance(pdf_path, Path) else None,
            opus_report_md=opus_md,
            ioc_count=len(iocs),
            technique_count=len(techniques),
            timeline_entries=len(timeline),
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _call_opus(
        self,
        record: DecisionRecord,
        timeline_json: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        techniques_json: list[dict[str, Any]],
    ) -> str:
        """Wrap the ThreatAnalyzer.deep_analyze call + logging."""
        try:
            result = await self._analyzer.deep_analyze(
                record.alert,
                record.network_context,
                record.forensic_result,
                record.virustotal_results or None,
                timeline=timeline_json,
                iocs=iocs,
                attack_techniques=techniques_json,
            )
            logger.info("[deep] Opus returned %d chars", len(result or ""))
            return result or ""
        except Exception:  # noqa: BLE001 — Opus failure is expected sometimes
            logger.exception("[deep] Opus deep_analyze raised")
            return ""

    @staticmethod
    def _report_title(record: DecisionRecord) -> str:
        """Cover-page title — short and scannable."""
        ip = record.alert.src_ip or "unknown IP"
        verdict = record.analysis.verdict.value.upper() if record.analysis else "INCIDENT"
        return f"{verdict} — {ip}"

    @staticmethod
    def _split_markdown_sections(markdown: str) -> tuple[str, str]:
        """Split the Opus output into executive + technical chunks.

        Heuristic: anything under an ``executive`` heading goes to the
        executive section; everything else is technical. If we can't
        find an explicit executive heading, the whole text becomes the
        executive summary and the technical section is empty.
        """
        lines = markdown.splitlines()
        exec_lines: list[str] = []
        tech_lines: list[str] = []
        current = exec_lines
        exec_seen = False

        for line in lines:
            stripped = line.strip().lower()
            if stripped.startswith(("# ", "## ")):
                heading = stripped.lstrip("#").strip()
                if _EXECUTIVE_HEADING in heading:
                    current = exec_lines
                    exec_seen = True
                    continue
                if any(
                    tag in heading
                    for tag in (
                        _TECHNICAL_HEADING,
                        "what we observed",
                        "risk assessment",
                        "what we did",
                        "recommendations",
                    )
                ):
                    current = tech_lines
                    continue
            current.append(line)

        if not exec_seen:
            return markdown.strip(), ""
        return "\n".join(exec_lines).strip(), "\n".join(tech_lines).strip()


def _fallback_exec(record: DecisionRecord) -> str:
    """Canned executive summary used when Opus is unavailable."""
    alert = record.alert
    return (
        f"WardSOAR blocked traffic from {alert.src_ip} matching "
        f"signature `{alert.alert_signature}` (SID {alert.alert_signature_id}). "
        "Opus was unavailable during the deep analysis, so this report "
        "only contains the machine-extracted artefacts and timeline. "
        "The underlying evidence is preserved in the evidence/ folder."
    )
