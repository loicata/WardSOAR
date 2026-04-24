"""Export a deep forensic incident folder as a portable ZIP bundle.

The bundle is what the operator shares with an expert or authority
(see docs/architecture.md §5). Structure:

    WardSOAR_Incident_<date>_<ip>.zip
    ├── README.txt              ← multilingual "what is this?"
    ├── REPORT.pdf             ← generated human-readable report
    ├── MANIFEST.json           ← chain-of-custody index (copied from volatile)
    ├── iocs.stix21.json        ← observables
    ├── iocs.csv                ← flattened CSV for Excel
    ├── timeline.csv            ← Plaso-compatible super timeline
    ├── timeline.json
    ├── attack_mapping.json     ← MITRE ATT&CK candidates
    ├── opus_report.md          ← Opus deep narrative (full)
    └── evidence/               ← all captured artefacts (optionally DPAPI-decrypted)

Privacy note: when the original evidence is DPAPI-encrypted, the
bundler **decrypts** artefacts into the export directory so the
recipient can read them without WardSOAR. The operator is warned via
the UI and must explicitly choose "include evidence".
"""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from wardsoar.pc.forensic.manifest import ForensicManifest
from wardsoar.pc.forensic.storage import ENCRYPTED_EXTENSION, ProtectedEvidenceStorage

logger = logging.getLogger("ward_soar.forensic.export")


# ---------------------------------------------------------------------------
# README template — English. Law enforcement and forensic analysts
# working with WardSOAR evidence bundles typically expect English.
# ---------------------------------------------------------------------------


_README_TEMPLATE = """\
==============================================================
  Security incident evidence bundle -- WardSOAR
==============================================================

This folder contains evidence from a security incident detected
on the user's PC on {incident_date}.

--- If you are the end user / non-technical --------------

    -> Simply open REPORT.pdf.
       It contains the full incident summary.

--- If you are a security analyst ------------------------

    The evidence/ folder contains:
     * Process list (processes.json)
     * Network state (network_state.json, connections, DNS, ARP)
     * Memory dumps of suspect processes (memdumps/*.dmp)
     * System logs (PowerShell, Sysmon, Event Logs)

    Other useful files:
     * timeline.csv           -- Plaso-compatible super timeline
     * iocs.stix21.json       -- Indicators of compromise (STIX 2.1)
     * attack_mapping.json    -- MITRE ATT&CK mapping
     * MANIFEST.json          -- Index + SHA-256 of every file

    Integrity check: re-run sha256 on each file and compare with
    the value recorded in MANIFEST.json.

--- If you represent law enforcement ---------------------

    -> Read REPORT.pdf for the incident summary.
    -> MANIFEST.json documents the full chain of custody
       (UTC timestamps, hashes, acquisition tool, version).

==============================================================
WardSOAR {version} -- generated at {generated_at}
Alert: {alert_line}
==============================================================
"""


# ---------------------------------------------------------------------------
# Data-classes returned by the module
# ---------------------------------------------------------------------------


@dataclass
class ExportBundleResult:
    """Outcome of a bundle export.

    Attributes:
        zip_path: Absolute path of the created ZIP.
        size_bytes: Size of the ZIP on disk.
        included_evidence: True if the bundle carries the full evidence
            directory (vs. a "report-only" export).
        manifest_sha256: Hash of the bundled MANIFEST.json (for UI display).
    """

    zip_path: Path
    size_bytes: int
    included_evidence: bool
    manifest_sha256: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class DeepReportExporter:
    """Compose the export ZIP from the pieces of a deep analysis.

    Args:
        storage: Shared storage used by the volatile/durable stages.
            Needed because some artefacts may be DPAPI-encrypted and
            must be read back through ``storage.read_sealed``.
        version: WardSOAR version tag included in the README.
    """

    def __init__(
        self,
        storage: ProtectedEvidenceStorage,
        version: str = "0.5.0",
    ) -> None:
        self._storage = storage
        self._version = version

    def export(
        self,
        *,
        incident_dir: Path,
        output_zip: Path,
        manifest: ForensicManifest,
        pdf_path: Path,
        opus_report_md: str,
        iocs_stix: dict[str, Any],
        iocs_csv: str,
        timeline_csv: str,
        timeline_json: list[dict[str, Any]],
        attack_matches: list[dict[str, Any]],
        include_evidence: bool = True,
    ) -> ExportBundleResult:
        """Build ``output_zip`` containing every piece of the deep analysis.

        Args:
            incident_dir: Volatile/durable folder (source of the evidence).
            output_zip: Target ZIP to create (overwritten if exists).
            manifest: The forensic manifest for the incident.
            pdf_path: Path to the already-rendered REPORT.pdf.
            opus_report_md: Full Opus report as markdown (plaintext, for grep).
            iocs_stix / iocs_csv / timeline_csv / timeline_json: outputs from
                the analysis modules.
            attack_matches: MITRE ATT&CK JSON rows.
            include_evidence: If True, the full evidence tree is copied
                into the ZIP (decrypted on the fly if necessary).

        Returns:
            ExportBundleResult with the target ZIP path + metadata.
        """
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        warnings: list[str] = []

        with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # README
            zf.writestr(
                "README.txt",
                self._render_readme(manifest),
            )

            # Report PDF (already written to disk)
            if pdf_path.is_file():
                zf.write(pdf_path, arcname="REPORT.pdf")
            else:
                warnings.append(f"PDF missing at {pdf_path}")

            # Opus raw markdown for archival / reanalysis
            zf.writestr("opus_report.md", opus_report_md or "(Opus report unavailable)\n")

            # Manifest + derived
            manifest_bytes = manifest.to_json_bytes()
            zf.writestr("MANIFEST.json", manifest_bytes)
            manifest_sha = manifest.to_dict()["integrity"]["manifest_sha256"]

            # IOCs
            zf.writestr(
                "iocs.stix21.json",
                json.dumps(iocs_stix, indent=2, default=str),
            )
            zf.writestr("iocs.csv", iocs_csv)

            # Timeline
            zf.writestr("timeline.csv", timeline_csv)
            zf.writestr(
                "timeline.json",
                json.dumps(timeline_json, indent=2, default=str),
            )

            # ATT&CK
            zf.writestr(
                "attack_mapping.json",
                json.dumps(attack_matches, indent=2, default=str),
            )

            # Evidence tree (optional, potentially decrypted)
            if include_evidence:
                for issue in self._copy_evidence(zf, incident_dir):
                    warnings.append(issue)

        size = output_zip.stat().st_size
        logger.info(
            "DeepReport exported: zip=%s size=%d include_evidence=%s warnings=%d",
            output_zip,
            size,
            include_evidence,
            len(warnings),
        )
        return ExportBundleResult(
            zip_path=output_zip,
            size_bytes=size,
            included_evidence=include_evidence,
            manifest_sha256=manifest_sha,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _render_readme(self, manifest: ForensicManifest) -> str:
        """Fill the README template with the incident's specifics."""
        summary = manifest.alert_summary or {}
        alert_line = (
            f"{summary.get('src_ip', '?')} → {summary.get('dest_ip', '?')} "
            f"(SID {summary.get('signature_id', '?')})"
        )
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        incident_date = manifest.acquired_at_utc or generated
        return _README_TEMPLATE.format(
            incident_date=incident_date,
            generated_at=generated,
            alert_line=alert_line,
            version=self._version,
        )

    def _copy_evidence(self, zf: zipfile.ZipFile, incident_dir: Path) -> list[str]:
        """Walk the incident directory and copy every file into evidence/.

        DPAPI-encrypted artefacts (``.dpapi`` suffix) are transparently
        decrypted via ``storage.read_sealed`` before writing — the
        recipient would not be able to decrypt them otherwise.
        """
        warnings: list[str] = []
        if not incident_dir.is_dir():
            warnings.append(f"incident_dir missing: {incident_dir}")
            return warnings

        for path in incident_dir.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(incident_dir.parent.parent).as_posix()
            # Strip "evidence_root" prefix from the archive path so the
            # tree inside the ZIP is rooted at "evidence/".
            arcname = Path("evidence") / path.relative_to(incident_dir).as_posix()

            try:
                if path.name.endswith(ENCRYPTED_EXTENSION):
                    # Decrypt once for the recipient; keep the original
                    # filename without the .dpapi suffix in the ZIP.
                    logical = path.with_suffix("")  # strip .dpapi
                    data = self._storage.read_sealed(logical)
                    stripped = Path("evidence") / logical.relative_to(incident_dir).as_posix()
                    zf.writestr(str(stripped), data)
                else:
                    zf.write(path, arcname=str(arcname))
            except Exception as exc:  # noqa: BLE001 — best-effort per file
                logger.warning("Export: skip %s: %s", rel, exc)
                warnings.append(f"skipped {rel}: {exc}")

        return warnings


def default_zip_name(
    alert_ip: Optional[str],
    when: Optional[datetime] = None,
) -> str:
    """Return a filesystem-safe default name for the export ZIP."""
    ts = (when or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    safe_ip = "".join(c for c in (alert_ip or "unknown") if c.isalnum() or c in ".-_")
    return f"WardSOAR_Incident_{ts}_{safe_ip}.zip"


# ---------------------------------------------------------------------------
# Convenience: assemble the *evidence-only* tree when the UI only needs
# the artefacts, not the ZIP. Used by UI drag-and-drop features down the line.
# ---------------------------------------------------------------------------


def copy_evidence_to(directory: Path, incident_dir: Path) -> int:
    """Copy evidence tree (non-encrypted only) to a plain directory.

    Returns the number of files copied. DPAPI files are skipped — call
    :class:`DeepReportExporter.export` for decrypted output.
    """
    count = 0
    directory.mkdir(parents=True, exist_ok=True)
    for path in incident_dir.rglob("*"):
        if not path.is_file() or path.name.endswith(ENCRYPTED_EXTENSION):
            continue
        target = directory / path.relative_to(incident_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    return count
