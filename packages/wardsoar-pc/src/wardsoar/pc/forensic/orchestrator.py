"""Entry point for post-block quick acquisition.

Chains the other modules together:
    1. :class:`ProtectedEvidenceStorage` creates the incident directory.
    2. :class:`VolatileAcquirer` captures each volatile category.
    3. :class:`MinidumpWriter` dumps target process memory.
    4. Each artefact is written via storage (optionally DPAPI-encrypted)
       and recorded in a :class:`ForensicManifest`.
    5. The manifest itself is written as the final step.

Design goals:
    - **Non-blocking**: callers schedule this as an asyncio task so the
      main pipeline continues handling new alerts immediately.
    - **Fail-safe**: a failure in any step degrades to a manifest entry
      recording the failure rather than aborting the whole acquisition.
    - **Deterministic file layout**: operators and external tools can
      rely on the directory structure without parsing the manifest.

Output layout (``<evidence_root>/<alert_id>/volatile/``):
    MANIFEST.json                (or MANIFEST.json.dpapi when encrypted)
    processes.json(.dpapi)
    network_state.json(.dpapi)
    loaded_dlls.json(.dpapi)
    dns_cache.txt(.dpapi)
    arp_cache.txt(.dpapi)
    routing_table.txt(.dpapi)
    memdumps/pid_<pid>_<name>.dmp(.dpapi)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from wardsoar.pc.forensic.acquisition import VolatileAcquirer
from wardsoar.pc.forensic.encryption import DpapiEncryptor
from wardsoar.pc.forensic.manifest import (
    ForensicManifest,
    ManifestEntry,
    sha256_bytes,
    sha256_file,
)
from wardsoar.pc.forensic.memory import MinidumpWriter
from wardsoar.pc.forensic.storage import ENCRYPTED_EXTENSION, ProtectedEvidenceStorage
from wardsoar.core.models import SuricataAlert

logger = logging.getLogger("ward_soar.forensic.orchestrator")


@dataclass
class QuickAcquisitionResult:
    """Summary of one quick acquisition run.

    Attributes:
        alert_id: The incident identifier used for the directory name.
        incident_dir: Absolute path to the volatile artefact directory.
        manifest_path: Path to the written manifest.
        artefact_count: Number of successfully captured artefacts
                        (excluding the manifest itself).
        memdump_count: Number of process memory dumps successfully written.
        errors: Human-readable errors encountered during acquisition.
        manifest: In-memory manifest object produced by this run. Callers
                  that chain into deep analysis should use this instead of
                  re-reading the sealed file — re-reading requires an open
                  ACL, which breaks once the directory has been tightened
                  to SYSTEM+Administrators.
    """

    alert_id: str
    incident_dir: Path
    manifest_path: Path
    artefact_count: int = 0
    memdump_count: int = 0
    errors: list[str] = field(default_factory=list)
    manifest: Optional[ForensicManifest] = None


class QuickAcquisitionManager:
    """Chain storage + acquisition + memory dumps + manifest.

    Args:
        storage: Writes files with ACL + optional DPAPI.
        acquirer: Captures volatile state (processes, network, DNS…).
        dump_writer: Captures process memory. Optional — if None, the
                     memory-dump stage is skipped silently.
        encryption_tag: Label embedded in the manifest to record how
                        artefacts were stored ("plaintext", "dpapi-user",
                        "dpapi-machine"). Used for later verification.
        acquirer_version: Free-text tag for the manifest.
    """

    def __init__(
        self,
        storage: ProtectedEvidenceStorage,
        acquirer: VolatileAcquirer,
        dump_writer: Optional[MinidumpWriter] = None,
        encryption_tag: str = "plaintext",
        acquirer_version: str = "WardSOAR",
    ) -> None:
        self._storage = storage
        self._acquirer = acquirer
        self._dump_writer = dump_writer
        self._encryption_tag = encryption_tag
        self._acquirer_version = acquirer_version

    async def quick_acquire(
        self,
        alert_id: str,
        alert: Optional[SuricataAlert] = None,
        target_pids: Optional[list[int]] = None,
    ) -> QuickAcquisitionResult:
        """Run the full volatile-acquisition pipeline for one incident.

        Args:
            alert_id: Unique identifier for the incident folder.
            alert: Originating alert (its summary is embedded in the
                   manifest so investigators can re-contextualise later).
            target_pids: PIDs to memory-dump. Usually supplied by the
                         Responder / Forensics correlation (processes
                         with connections to the offending IP).

        Returns:
            QuickAcquisitionResult with paths and counters.
        """
        incident_dir = self._storage.create_incident_dir(alert_id, phase="volatile")

        # Idempotence guard (CLAUDE.md §3). If a manifest already sits in
        # the incident dir, another acquisition ran for this alert_id —
        # possibly because the pipeline retried after a crash, or the
        # Responder fired twice on duplicated alerts. Re-running would
        # overwrite artefacts, race on unlink() during memdump sealing,
        # and inflate the manifest with duplicate entries. Skip instead:
        # return a summary pointing at the existing evidence so the
        # caller can proceed to deep analysis without corruption.
        existing = self._existing_result(incident_dir, alert_id)
        if existing is not None:
            logger.warning(
                "Quick acquisition skipped (idempotent): alert=%s already captured at %s",
                alert_id,
                existing.manifest_path,
            )
            return existing

        manifest = ForensicManifest(
            alert_id=alert_id,
            scope="volatile",
            encryption=self._encryption_tag,
            acquirer=self._acquirer_version,
            alert_summary=self._summarise_alert(alert),
        )
        errors: list[str] = []
        artefact_count = 0
        memdump_count = 0

        # ----- JSON / text artefacts -------------------------------------
        capture_specs = [
            ("processes.json", "process_list", "psutil", self._acquirer.capture_process_list),
            ("network_state.json", "net_state", "psutil", self._acquirer.capture_network_state),
            (
                "dns_cache.txt",
                "dns_cache",
                "powershell:Get-DnsClientCache",
                self._acquirer.capture_dns_cache,
            ),
            ("arp_cache.txt", "arp_cache", "arp.exe", self._acquirer.capture_arp_cache),
            ("routing_table.txt", "routing", "route.exe", self._acquirer.capture_routing_table),
        ]
        for name, type_tag, source, fn in capture_specs:
            try:
                payload = fn()
                entry = self._persist_json(incident_dir, name, payload, type_tag, source)
                manifest.add_entry(entry)
                artefact_count += 1
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("Acquisition step %s failed: %s", name, exc)
                errors.append(f"{name}: {exc}")

        # Loaded DLLs (only meaningful when we have target PIDs).
        if target_pids:
            try:
                payload = self._acquirer.capture_loaded_dlls(target_pids)
                entry = self._persist_json(
                    incident_dir,
                    "loaded_dlls.json",
                    payload,
                    type_tag="loaded_modules",
                    source="psutil",
                )
                manifest.add_entry(entry)
                artefact_count += 1
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("loaded_dlls capture failed: %s", exc)
                errors.append(f"loaded_dlls: {exc}")

        # ----- Process memory dumps --------------------------------------
        if target_pids and self._dump_writer is not None:
            dumps_dir = incident_dir / "memdumps"
            dumps_dir.mkdir(parents=True, exist_ok=True)
            for pid in target_pids:
                dump_entry = self._dump_and_register(dumps_dir, pid)
                if dump_entry is not None:
                    manifest.add_entry(dump_entry)
                    memdump_count += 1

        # ----- Manifest (written LAST so it reflects all artefacts) ------
        manifest_bytes = manifest.to_json_bytes()
        stored_manifest = self._storage.write_and_seal(
            incident_dir / "MANIFEST.json", manifest_bytes
        )

        # Directory sealing is intentionally NOT done here. The deep
        # analysis stage that follows still needs to read artefacts back
        # (via storage.read_sealed), write REPORT.pdf into the same
        # folder, and bundle the evidence into the export ZIP. Tightening
        # the ACLs now would lock the running user out of the very
        # directory it just populated — which is the failure mode
        # observed on 2026-04-23 22:40 where two consecutive deep
        # analyses crashed with WinError 5 Access denied on
        # MANIFEST.json.dpapi.
        #
        # The caller is expected to invoke ``storage.seal_directory``
        # once the deep phase has completed (success or failure). See
        # src/main.py _schedule_quick_acquisition.

        logger.info(
            "Quick acquisition complete: alert=%s artefacts=%d memdumps=%d errors=%d",
            alert_id,
            artefact_count,
            memdump_count,
            len(errors),
        )

        return QuickAcquisitionResult(
            alert_id=alert_id,
            incident_dir=incident_dir,
            manifest_path=stored_manifest,
            artefact_count=artefact_count,
            memdump_count=memdump_count,
            errors=errors,
            manifest=manifest,
        )

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _existing_result(
        self, incident_dir: Path, alert_id: str
    ) -> Optional[QuickAcquisitionResult]:
        """Rebuild a :class:`QuickAcquisitionResult` from a prior run on disk.

        Returns ``None`` when no manifest is found, meaning the caller
        should run a fresh acquisition. Both plaintext and DPAPI-wrapped
        manifests are recognised — the storage helper handles decryption
        when we ask for the counts.
        """
        manifest_plain = incident_dir / "MANIFEST.json"
        manifest_encrypted = manifest_plain.with_suffix(manifest_plain.suffix + ENCRYPTED_EXTENSION)

        if manifest_encrypted.is_file():
            stored_manifest = manifest_encrypted
        elif manifest_plain.is_file():
            stored_manifest = manifest_plain
        else:
            return None

        rebuilt_manifest, artefact_count, memdump_count = self._rehydrate_manifest(manifest_plain)
        return QuickAcquisitionResult(
            alert_id=alert_id,
            incident_dir=incident_dir,
            manifest_path=stored_manifest,
            artefact_count=artefact_count,
            memdump_count=memdump_count,
            errors=[],
            manifest=rebuilt_manifest,
        )

    def _rehydrate_manifest(
        self, manifest_logical_path: Path
    ) -> tuple[Optional[ForensicManifest], int, int]:
        """Re-read the prior manifest from disk for an idempotent skip.

        Returns ``(manifest, artefact_count, memdump_count)``. Failure to
        decode is non-fatal: we report ``(None, 0, 0)`` so the caller
        still sees a skip, and the deep-analysis stage will surface the
        integrity problem when it reads the file itself.
        """
        try:
            raw = self._storage.read_sealed(manifest_logical_path)
            payload = json.loads(raw)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning(
                "Existing manifest at %s is unreadable (%s) — counters set to 0",
                manifest_logical_path,
                exc,
            )
            return None, 0, 0

        entries = payload.get("entries") or []
        memdump = sum(1 for entry in entries if entry.get("type") == "memory_dump")
        # Artefact counter historically excludes memory dumps (see the
        # capture specs in quick_acquire) so the reconstructed counters
        # must stay consistent with a fresh run's semantics.
        artefact = len(entries) - memdump

        try:
            rebuilt = ForensicManifest.from_dict(payload)
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "Manifest at %s has an unexpected schema (%s) — manifest object unavailable",
                manifest_logical_path,
                exc,
            )
            return None, artefact, memdump

        return rebuilt, artefact, memdump

    def _persist_json(
        self,
        incident_dir: Path,
        name: str,
        payload: Any,
        type_tag: str,
        source: str,
    ) -> ManifestEntry:
        """Serialise ``payload`` as JSON, write it, return its manifest row."""
        data = json.dumps(payload, default=str, indent=2).encode("utf-8")
        stored_path = self._storage.write_and_seal(incident_dir / name, data)
        sha = self._hash_stored(stored_path, fallback_bytes=data)
        return ManifestEntry(
            name=name,
            relative_path=name,
            stored_path=stored_path.name,
            size_bytes=stored_path.stat().st_size if stored_path.is_file() else len(data),
            sha256=sha,
            type=type_tag,
            source=source,
        )

    def _dump_and_register(self, dumps_dir: Path, pid: int) -> Optional[ManifestEntry]:
        """Run MiniDumpWriteDump for a single PID and build its manifest row.

        Returns None on failure (logged, nothing to record).
        """
        if self._dump_writer is None:
            return None

        raw_path = dumps_dir / f"pid_{pid}.dmp"
        result = self._dump_writer.dump_process(pid, raw_path)
        if not result.success or result.path is None:
            logger.debug("Memory dump for PID %d skipped: %s", pid, result.error)
            return None

        # Seal the dump (apply read-only and, if configured, DPAPI-encrypt
        # by re-reading the .dmp bytes and writing them through storage).
        dmp_bytes = result.path.read_bytes()
        # Remove the raw (unencrypted) file before re-writing through storage
        # to avoid leaving a plaintext copy alongside the encrypted one.
        try:
            result.path.unlink()
        except OSError:
            logger.debug("Unlink failed for raw dump %s", result.path)

        stored_path = self._storage.write_and_seal(result.path, dmp_bytes)
        relative = stored_path.relative_to(dumps_dir.parent)

        return ManifestEntry(
            name=result.path.name,
            relative_path=str(relative).replace("\\", "/"),
            stored_path=str(relative).replace("\\", "/"),
            size_bytes=stored_path.stat().st_size,
            sha256=sha256_file(stored_path),
            type="memory_dump",
            source="MiniDumpWriteDump",
        )

    @staticmethod
    def _hash_stored(path: Path, fallback_bytes: bytes) -> str:
        """Hash ``path`` on disk; fall back to hashing the pre-write bytes.

        The fallback matters when storage wrote an encrypted blob — the
        manifest records the hash of the stored (encrypted) bytes so a
        later ``verify()`` can validate without decrypting.
        """
        if path.is_file():
            return sha256_file(path)
        return sha256_bytes(fallback_bytes)

    @staticmethod
    def _summarise_alert(alert: Optional[SuricataAlert]) -> dict[str, Any]:
        """Extract a small, stable subset of alert fields for the manifest."""
        if alert is None:
            return {}
        return {
            "timestamp": alert.timestamp.isoformat(),
            "src_ip": alert.src_ip,
            "dest_ip": alert.dest_ip,
            "src_port": alert.src_port,
            "dest_port": alert.dest_port,
            "proto": alert.proto,
            "signature": alert.alert_signature,
            "signature_id": alert.alert_signature_id,
            "severity": alert.alert_severity.value,
        }


def build_default_manager(
    evidence_root: Path,
    encryption_scope: str = "user",
    apply_acls: bool = True,
) -> QuickAcquisitionManager:
    """Factory: wires up storage + acquirer + memory dumper in one call.

    Args:
        evidence_root: Directory under which each incident gets its folder.
        encryption_scope: "user" (default), "machine", or "off" to disable
                          DPAPI wrapping entirely.
        apply_acls: If True (default) restrict evidence directories to
                    SYSTEM + Administrators via icacls. Set to False in
                    tests where the pytest user must still write under
                    the temp directory.

    Returns:
        A ready-to-use :class:`QuickAcquisitionManager`.
    """
    encryptor: Optional[DpapiEncryptor]
    tag: str
    if encryption_scope == "off":
        encryptor = None
        tag = "plaintext"
    else:
        from wardsoar.pc.forensic.encryption import try_build_encryptor

        encryptor = try_build_encryptor(scope=encryption_scope)
        tag = f"dpapi-{encryption_scope}" if encryptor else "plaintext"

    storage = ProtectedEvidenceStorage(
        root_dir=evidence_root, apply_acls=apply_acls, encryptor=encryptor
    )
    return QuickAcquisitionManager(
        storage=storage,
        acquirer=VolatileAcquirer(),
        dump_writer=MinidumpWriter(),
        encryption_tag=tag,
    )
