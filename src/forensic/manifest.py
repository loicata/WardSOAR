"""Chain-of-custody manifest for a forensic acquisition.

The manifest is the contract between "what was on disk at time T" and
anything the operator, an expert, or an auditor inspects later. It
lists every artefact with its SHA-256 and acquisition metadata, and
exposes a :meth:`verify` helper that re-hashes the files and flags any
tampering.

Format is intentionally simple JSON so any third party (Autopsy,
manual review, custom scripts) can parse it without an SDK.

Schema (``schema_version=1``):
    {
        "schema_version": "1",
        "alert_id": "uuid",
        "acquired_at_utc": "ISO-8601",
        "acquirer": "WardSOAR v0.5.0",
        "scope": "volatile" | "durable",
        "encryption": "dpapi-user" | "dpapi-machine" | "plaintext",
        "entries": [
            {
                "name": "processes.json",
                "relative_path": "processes.json",
                "stored_path": "processes.json.dpapi",
                "size_bytes": 1234,
                "sha256": "<hex>",
                "type": "process_list",
                "source": "psutil",
                "captured_at_utc": "ISO-8601"
            },
            ...
        ],
        "integrity": {
            "manifest_sha256": "<hex of the entries list>",
        }
    }
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"


def _utcnow_iso() -> str:
    """Return current UTC time in ISO 8601 with trailing 'Z' normalised."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Stream-hash a file and return the hex digest."""
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of a byte string. Exposed for orchestrator use."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class ManifestEntry:
    """One artefact row in the manifest.

    Attributes:
        name: Human-friendly name (e.g. "processes.json").
        relative_path: Logical path under the incident directory.
        stored_path: Actual file on disk (may differ if encrypted).
        size_bytes: Size of the *stored* file.
        sha256: Hex SHA-256 of the stored bytes.
        type: Semantic type tag for consumers (process_list, net_state, …).
        source: Acquisition mechanism (psutil, powershell:Get-DnsClientCache, …).
        captured_at_utc: ISO timestamp at the end of capture.
    """

    name: str
    relative_path: str
    stored_path: str
    size_bytes: int
    sha256: str
    type: str
    source: str
    captured_at_utc: str = field(default_factory=_utcnow_iso)


@dataclass
class ForensicManifest:
    """In-memory manifest that knows how to write/verify itself.

    Attributes:
        alert_id: Identifier used as the acquisition directory.
        scope: "volatile" | "durable" — which acquisition phase produced it.
        encryption: Tag describing how artefacts are stored on disk.
        acquirer: Free-text identifier for the producing software/version.
        acquired_at_utc: ISO timestamp when the acquisition began.
        entries: List of :class:`ManifestEntry`.
        alert_summary: Lightweight copy of the alert fields useful to the
                       human reader (src_ip, signature, …). Optional.
    """

    alert_id: str
    scope: str = "volatile"
    encryption: str = "plaintext"
    acquirer: str = "WardSOAR"
    acquired_at_utc: str = field(default_factory=_utcnow_iso)
    entries: list[ManifestEntry] = field(default_factory=list)
    alert_summary: dict[str, Any] = field(default_factory=dict)

    def add_entry(self, entry: ManifestEntry) -> None:
        """Append a new artefact description."""
        self.entries.append(entry)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict ready for :func:`json.dump`.

        Also computes ``integrity.manifest_sha256`` — a fingerprint of
        the entries list, useful for external anchoring (e.g. emailing
        the hash to prove the manifest existed at time T).
        """
        entries_payload = [asdict(e) for e in self.entries]
        integrity_hash = sha256_bytes(json.dumps(entries_payload, sort_keys=True).encode("utf-8"))
        return {
            "schema_version": SCHEMA_VERSION,
            "alert_id": self.alert_id,
            "scope": self.scope,
            "encryption": self.encryption,
            "acquirer": self.acquirer,
            "acquired_at_utc": self.acquired_at_utc,
            "entries": entries_payload,
            "alert_summary": self.alert_summary,
            "integrity": {"manifest_sha256": integrity_hash},
        }

    def to_json_bytes(self) -> bytes:
        """Canonical UTF-8 JSON bytes (indented for human review)."""
        return json.dumps(self.to_dict(), indent=2).encode("utf-8")

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, incident_dir: Path) -> list[str]:
        """Re-hash every stored file and report mismatches.

        Args:
            incident_dir: Directory that holds the files referenced by
                          ``stored_path`` in each entry.

        Returns:
            List of human-readable problem descriptions. Empty list
            means all artefacts still match their recorded hashes.
        """
        problems: list[str] = []
        for entry in self.entries:
            path = incident_dir / entry.stored_path
            if not path.is_file():
                problems.append(f"missing: {entry.stored_path}")
                continue
            actual = sha256_file(path)
            if actual != entry.sha256:
                problems.append(
                    f"tampered: {entry.stored_path} "
                    f"(expected {entry.sha256[:12]}…, got {actual[:12]}…)"
                )
        return problems

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ForensicManifest:
        """Rebuild a manifest from JSON (for verification tooling)."""
        entries = [ManifestEntry(**entry) for entry in data.get("entries", [])]
        return cls(
            alert_id=str(data.get("alert_id", "")),
            scope=str(data.get("scope", "volatile")),
            encryption=str(data.get("encryption", "plaintext")),
            acquirer=str(data.get("acquirer", "WardSOAR")),
            acquired_at_utc=str(data.get("acquired_at_utc", _utcnow_iso())),
            entries=entries,
            alert_summary=data.get("alert_summary", {}) or {},
        )
