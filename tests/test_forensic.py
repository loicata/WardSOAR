"""Tests for the post-block forensic quick acquisition package.

Covers each forensic module independently so a regression in one
(encryption, manifest, memory, acquisition, storage, orchestrator)
surfaces with a clear signal rather than a blanket integration failure.

Real Win32 APIs (MiniDumpWriteDump, DPAPI) are exercised where safe;
otherwise the code paths are driven through the public interface with
in-memory doubles.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.forensic.acquisition import VolatileAcquirer
from src.forensic.manifest import (
    ForensicManifest,
    ManifestEntry,
    sha256_bytes,
    sha256_file,
)
from src.forensic.memory import DumpResult, MinidumpWriter
from src.forensic.orchestrator import (
    QuickAcquisitionManager,
    build_default_manager,
)
from src.forensic.storage import ENCRYPTED_EXTENSION, ProtectedEvidenceStorage
from src.models import SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert() -> SuricataAlert:
    """Return a representative alert (used for manifest summaries)."""
    return SuricataAlert(
        timestamp=datetime(2026, 4, 19, 22, 0, 0, tzinfo=timezone.utc),
        src_ip="203.0.113.5",
        src_port=55555,
        dest_ip="192.168.2.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Contoso",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ===========================================================================
# ENCRYPTION
# ===========================================================================


class TestDpapiEncryption:
    """DPAPI round-trip works on Windows; degrades gracefully elsewhere."""

    def test_try_build_encryptor_returns_something_on_windows(self) -> None:
        """On Windows the factory returns a working encryptor; elsewhere None."""
        from src.forensic.encryption import try_build_encryptor

        encryptor = try_build_encryptor()
        if os.name == "nt":
            assert encryptor is not None
            assert encryptor.available is True
        else:  # pragma: no cover — runs only on non-Windows CI
            assert encryptor is None

    @pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
    def test_round_trip(self) -> None:
        from src.forensic.encryption import DpapiEncryptor

        enc = DpapiEncryptor()
        blob = enc.encrypt(b"WardSOAR secret payload")
        assert blob != b"WardSOAR secret payload"
        assert enc.decrypt(blob) == b"WardSOAR secret payload"

    @pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
    def test_corrupt_blob_raises(self) -> None:
        from src.forensic.encryption import DpapiEncryptor, EncryptionUnavailable

        enc = DpapiEncryptor()
        with pytest.raises(EncryptionUnavailable):
            enc.decrypt(b"\x00" * 32)


# ===========================================================================
# STORAGE
# ===========================================================================


class TestProtectedStorage:
    """Basic storage mechanics: directory creation + write-and-seal."""

    def test_creates_incident_dir(self, tmp_path: Path) -> None:
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        incident = storage.create_incident_dir("alert-123", phase="volatile")
        assert incident.is_dir()
        assert incident.name == "volatile"
        assert incident.parent.name == "alert-123"

    def test_sanitises_alert_id(self, tmp_path: Path) -> None:
        """Path separators and special chars are stripped defensively."""
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        incident = storage.create_incident_dir("../evil/id", phase="volatile")
        # All forbidden chars dropped, resulting folder is safe.
        assert ".." not in incident.parts
        assert incident.is_dir()

    def test_write_and_seal_plaintext(self, tmp_path: Path) -> None:
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        incident = storage.create_incident_dir("id", phase="volatile")
        written = storage.write_and_seal(incident / "sample.txt", b"hello")
        assert written == incident / "sample.txt"
        assert written.read_bytes() == b"hello"

    def test_write_and_seal_makes_readonly(self, tmp_path: Path) -> None:
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        incident = storage.create_incident_dir("id", phase="volatile")
        path = storage.write_and_seal(incident / "sealed.txt", b"payload")
        # On Windows, writable is bit 0x80 in stat mode; check by trying to
        # open for write — should fail with PermissionError.
        with pytest.raises((PermissionError, OSError)):
            path.write_bytes(b"overwrite attempt")

    @pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
    def test_write_and_seal_encrypted(self, tmp_path: Path) -> None:
        from src.forensic.encryption import try_build_encryptor

        encryptor = try_build_encryptor()
        storage = ProtectedEvidenceStorage(
            root_dir=tmp_path / "evidence",
            apply_acls=False,
            encryptor=encryptor,
        )
        incident = storage.create_incident_dir("id", phase="volatile")

        original = b"secret evidence"
        written = storage.write_and_seal(incident / "a.json", original)

        assert written.name.endswith(ENCRYPTED_EXTENSION)
        # Raw bytes on disk must NOT match the plaintext.
        assert written.read_bytes() != original
        # But read_sealed must round-trip to the plaintext.
        assert storage.read_sealed(incident / "a.json") == original

    def test_create_incident_dir_does_not_invoke_icacls(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """Regression for v0.7.5.

        Before the fix, ``create_incident_dir`` called
        ``_harden_directory_acl`` inline, which reduced the caller's
        rights to read-only *before* any write could succeed.
        Multiple ``PermissionError: MANIFEST.json.dpapi`` incidents
        were logged on 2026-04-20 as a result. The new contract is
        that directory creation is a pure filesystem mkdir — nobody
        touches ACLs until :meth:`seal_directory` is called.
        """
        calls: list[list[str]] = []

        def _fake_run_icacls(self: ProtectedEvidenceStorage, args: list[str]) -> None:
            calls.append(list(args))
            return None

        monkeypatch.setattr(ProtectedEvidenceStorage, "_run_icacls", _fake_run_icacls)
        storage = ProtectedEvidenceStorage(
            root_dir=tmp_path / "evidence",
            apply_acls=True,  # on Windows this would previously harden inline
        )
        storage.create_incident_dir("abc", phase="volatile")
        assert calls == []

    def test_seal_directory_does_invoke_icacls(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """The sealing step is the new home of the ACL tightening."""
        import os

        if os.name != "nt":
            pytest.skip("seal_directory only hardens on Windows (apply_acls is gated)")

        calls: list[list[str]] = []

        import subprocess

        def _fake_run_icacls(
            self: ProtectedEvidenceStorage, args: list[str]
        ) -> "subprocess.CompletedProcess[str] | None":
            calls.append(list(args))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ProtectedEvidenceStorage, "_run_icacls", _fake_run_icacls)
        storage = ProtectedEvidenceStorage(
            root_dir=tmp_path / "evidence",
            apply_acls=True,
        )
        incident = storage.create_incident_dir("abc", phase="volatile")
        # Operator-level write must still succeed post-creation -- we
        # would not get here if the old bug were back.
        (incident / "probe.txt").write_bytes(b"probe")
        storage.seal_directory(incident)

        # icacls was invoked exactly once, on the incident directory,
        # with the hardening flags we expect.
        assert len(calls) == 1
        flat = " ".join(calls[0])
        assert str(incident) in flat
        assert "/inheritance:r" in flat
        assert "SYSTEM" in flat
        assert "Administrators" in flat

    def test_write_succeeds_after_create_incident_dir(self, tmp_path: Path) -> None:
        """Direct regression for the PermissionError observed on
        2026-04-20 22:59. With ``apply_acls=True`` on Windows, the
        v0.7.4 code raised on the first write_and_seal because the
        directory had been icacls-locked to read-only."""
        storage = ProtectedEvidenceStorage(
            root_dir=tmp_path / "evidence",
            apply_acls=True,
        )
        incident = storage.create_incident_dir("incident-42", phase="volatile")
        # No exception here is the whole point of the test.
        written = storage.write_and_seal(incident / "MANIFEST.json", b"{}\n")
        assert written.is_file()


# ===========================================================================
# MANIFEST
# ===========================================================================


class TestManifest:
    """Schema shape + SHA-256 helpers + verify()."""

    def test_sha256_helpers_match(self, tmp_path: Path) -> None:
        path = tmp_path / "payload.bin"
        path.write_bytes(b"check")
        assert sha256_bytes(b"check") == sha256_file(path)

    def test_to_dict_contains_required_fields(self) -> None:
        m = ForensicManifest(alert_id="abc")
        m.add_entry(
            ManifestEntry(
                name="processes.json",
                relative_path="processes.json",
                stored_path="processes.json",
                size_bytes=10,
                sha256="deadbeef",
                type="process_list",
                source="psutil",
            )
        )
        data = m.to_dict()
        assert data["schema_version"] == "1"
        assert data["alert_id"] == "abc"
        assert data["entries"][0]["name"] == "processes.json"
        assert "integrity" in data
        assert "manifest_sha256" in data["integrity"]

    def test_verify_spots_tamper(self, tmp_path: Path) -> None:
        file_path = tmp_path / "processes.json"
        file_path.write_bytes(b'{"count": 0}')
        manifest = ForensicManifest(alert_id="abc")
        manifest.add_entry(
            ManifestEntry(
                name="processes.json",
                relative_path="processes.json",
                stored_path="processes.json",
                size_bytes=file_path.stat().st_size,
                sha256=sha256_file(file_path),
                type="process_list",
                source="psutil",
            )
        )

        # Untampered: verify() returns empty problem list.
        assert manifest.verify(tmp_path) == []

        # Tamper with the file — verify() must flag it. Have to remove the
        # readonly bit if present (write_and_seal wasn't used here, but
        # pytest fixtures may produce read-only files on some CI).
        import stat as stat_mod

        file_path.chmod(stat_mod.S_IWRITE | stat_mod.S_IREAD)
        file_path.write_bytes(b'{"count": 999}')

        problems = manifest.verify(tmp_path)
        assert problems and "tampered" in problems[0]

    def test_verify_spots_missing_file(self, tmp_path: Path) -> None:
        manifest = ForensicManifest(alert_id="abc")
        manifest.add_entry(
            ManifestEntry(
                name="ghost.json",
                relative_path="ghost.json",
                stored_path="ghost.json",
                size_bytes=1,
                sha256="0",
                type="x",
                source="y",
            )
        )
        problems = manifest.verify(tmp_path)
        assert problems == ["missing: ghost.json"]

    def test_from_dict_round_trip(self) -> None:
        m = ForensicManifest(alert_id="abc", scope="volatile", encryption="dpapi-user")
        m.add_entry(
            ManifestEntry(
                name="x.json",
                relative_path="x.json",
                stored_path="x.json.dpapi",
                size_bytes=10,
                sha256="z",
                type="t",
                source="s",
            )
        )

        raw = m.to_dict()
        rebuilt = ForensicManifest.from_dict(raw)
        assert rebuilt.alert_id == "abc"
        assert rebuilt.encryption == "dpapi-user"
        assert rebuilt.entries[0].stored_path == "x.json.dpapi"


# ===========================================================================
# MEMORY DUMPS
# ===========================================================================


class TestMinidumpWriter:
    """Real MiniDumpWriteDump test on Windows; skipped elsewhere."""

    def test_availability_on_windows(self) -> None:
        writer = MinidumpWriter()
        if os.name == "nt":
            assert writer.available is True
        else:  # pragma: no cover
            assert writer.available is False

    @pytest.mark.skipif(os.name != "nt", reason="MiniDumpWriteDump is Windows-only")
    def test_dump_current_process(self, tmp_path: Path) -> None:
        """Dump our own process — always dumpable (same credentials)."""
        writer = MinidumpWriter()
        output = tmp_path / "self.dmp"
        result = writer.dump_process(os.getpid(), output)

        assert isinstance(result, DumpResult)
        assert result.success is True
        assert result.path == output
        assert output.is_file()
        # Minidump header magic = "MDMP"
        assert output.read_bytes()[:4] == b"MDMP"
        assert result.size_bytes > 4

    @pytest.mark.skipif(os.name != "nt", reason="MiniDumpWriteDump is Windows-only")
    def test_dump_bad_pid(self, tmp_path: Path) -> None:
        writer = MinidumpWriter()
        # PID 1 isn't accessible to user processes on Windows.
        result = writer.dump_process(1, tmp_path / "impossible.dmp")
        assert result.success is False
        assert result.error


# ===========================================================================
# VOLATILE ACQUIRER
# ===========================================================================


class TestVolatileAcquirer:
    """The acquirer touches live OS state; we just verify the shape."""

    def test_capture_process_list_returns_non_empty(self) -> None:
        acq = VolatileAcquirer()
        data = acq.capture_process_list()
        assert "captured_at_utc" in data
        assert data["process_count"] > 0
        # Our own test process must be in there.
        our_pid = os.getpid()
        assert any(p.get("pid") == our_pid for p in data["processes"])

    def test_capture_network_state_has_schema(self) -> None:
        data = VolatileAcquirer().capture_network_state()
        assert set(data.keys()) >= {"captured_at_utc", "connection_count", "connections"}
        assert isinstance(data["connections"], list)

    def test_capture_loaded_dlls_self_pid(self) -> None:
        acq = VolatileAcquirer()
        data = acq.capture_loaded_dlls([os.getpid()])
        assert str(os.getpid()) in data["pid_modules"]

    def test_capture_loaded_dlls_unknown_pid(self) -> None:
        data = VolatileAcquirer().capture_loaded_dlls([999999])
        assert data["pid_modules"]["999999"] == []


# ===========================================================================
# ORCHESTRATOR
# ===========================================================================


class TestOrchestrator:
    """End-to-end: storage + manifest + acquisition cooperate correctly."""

    def _stub_acquirer(self) -> MagicMock:
        """Build a deterministic VolatileAcquirer substitute."""
        acq = MagicMock(spec=VolatileAcquirer)
        acq.capture_process_list.return_value = {"processes": [{"pid": 1}]}
        acq.capture_network_state.return_value = {"connections": []}
        acq.capture_dns_cache.return_value = {"raw": ""}
        acq.capture_arp_cache.return_value = {"raw": ""}
        acq.capture_routing_table.return_value = {"raw": ""}
        acq.capture_loaded_dlls.return_value = {"pid_modules": {}}
        return acq

    @pytest.mark.asyncio
    async def test_quick_acquire_produces_manifest_and_artefacts(self, tmp_path: Path) -> None:
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        mgr = QuickAcquisitionManager(
            storage=storage,
            acquirer=self._stub_acquirer(),
        )

        result = await mgr.quick_acquire(
            alert_id="alert-abc",
            alert=_make_alert(),
            target_pids=[],
        )

        assert result.alert_id == "alert-abc"
        assert result.artefact_count == 5  # processes + net + dns + arp + route
        assert result.manifest_path.is_file()
        assert result.incident_dir.is_dir()

        # Manifest is valid JSON with the expected schema.
        data = json.loads(result.manifest_path.read_bytes())
        assert data["schema_version"] == "1"
        assert data["alert_id"] == "alert-abc"
        # 5 artefacts listed.
        assert len(data["entries"]) == result.artefact_count

    @pytest.mark.asyncio
    async def test_quick_acquire_skips_memdumps_when_no_writer(self, tmp_path: Path) -> None:
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        mgr = QuickAcquisitionManager(
            storage=storage,
            acquirer=self._stub_acquirer(),
            dump_writer=None,
        )

        result = await mgr.quick_acquire(
            alert_id="abc",
            target_pids=[os.getpid()],
        )
        assert result.memdump_count == 0

    @pytest.mark.asyncio
    async def test_quick_acquire_is_idempotent_on_second_call(self, tmp_path: Path) -> None:
        """CLAUDE.md §3 — re-running the same alert_id must not race.

        If the pipeline retries after a crash (or a duplicate alert
        slips past the Deduplicator), a second acquisition on the same
        alert_id previously overwrote the manifest, raced on memdump
        unlink(), and duplicated manifest entries. The orchestrator
        now skips the capture entirely when a prior manifest exists.
        """
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        acq = self._stub_acquirer()
        mgr = QuickAcquisitionManager(storage=storage, acquirer=acq)

        first = await mgr.quick_acquire(alert_id="dup-id", alert=_make_alert())
        assert first.artefact_count == 5

        # Reset the mock so we can prove the second call invoked nothing.
        acq.reset_mock()
        second = await mgr.quick_acquire(alert_id="dup-id", alert=_make_alert())

        # No acquisition method was called on the second pass.
        acq.capture_process_list.assert_not_called()
        acq.capture_network_state.assert_not_called()
        acq.capture_dns_cache.assert_not_called()

        # Reconstructed summary points at the same manifest and reports
        # the same counters so the caller can still chain into deep
        # analysis without noticing the skip.
        assert second.incident_dir == first.incident_dir
        assert second.manifest_path == first.manifest_path
        assert second.artefact_count == first.artefact_count
        assert second.memdump_count == first.memdump_count
        assert second.errors == []

    @pytest.mark.asyncio
    async def test_acquire_step_failure_is_recorded(self, tmp_path: Path) -> None:
        """A raising step is caught, listed in errors, others still run."""
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        acq = self._stub_acquirer()
        acq.capture_dns_cache.side_effect = RuntimeError("powershell blew up")

        mgr = QuickAcquisitionManager(storage=storage, acquirer=acq)
        result = await mgr.quick_acquire(alert_id="abc")

        # 5 specs − 1 failure = 4 artefacts.
        assert result.artefact_count == 4
        assert any("dns_cache.txt" in err for err in result.errors)

    @pytest.mark.asyncio
    async def test_quick_acquire_returns_in_memory_manifest(self, tmp_path: Path) -> None:
        """Regression for 2026-04-23 22:40 Access-denied incident.

        The deep analysis stage previously re-read MANIFEST.json.dpapi
        from disk, which fails with WinError 5 once the directory has
        been sealed. The orchestrator now attaches the in-memory
        manifest object to the result so the caller can chain without
        going back to disk.
        """
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        mgr = QuickAcquisitionManager(storage=storage, acquirer=self._stub_acquirer())

        result = await mgr.quick_acquire(alert_id="inmem", alert=_make_alert())

        assert result.manifest is not None
        assert result.manifest.alert_id == "inmem"
        # In-memory counts match what landed on disk.
        assert len(result.manifest.entries) == result.artefact_count + result.memdump_count

    @pytest.mark.asyncio
    async def test_quick_acquire_does_not_seal_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Quick acquisition must leave the directory writable.

        Deep analysis writes REPORT.pdf into ``incident_dir`` and the
        exporter re-reads every artefact via ``storage.read_sealed``.
        Both require the running user to keep access, so the ACL
        tightening is deferred to the caller (main.py) which invokes
        ``seal_directory`` in a ``finally`` after deep analysis.
        """
        calls: list[list[str]] = []

        def _fake_run_icacls(self: ProtectedEvidenceStorage, args: list[str]) -> None:
            calls.append(list(args))
            return None

        monkeypatch.setattr(ProtectedEvidenceStorage, "_run_icacls", _fake_run_icacls)
        storage = ProtectedEvidenceStorage(
            root_dir=tmp_path / "evidence",
            apply_acls=True,  # would normally invoke icacls when sealed
        )
        mgr = QuickAcquisitionManager(storage=storage, acquirer=self._stub_acquirer())

        await mgr.quick_acquire(alert_id="noseal", alert=_make_alert())

        # No ACL command issued during the acquisition — responsibility
        # moved to the caller.
        assert calls == []

    @pytest.mark.asyncio
    async def test_idempotent_skip_rehydrates_manifest(self, tmp_path: Path) -> None:
        """Second call on the same alert_id rebuilds the manifest from disk.

        Deep analysis needs a manifest object even when the quick phase
        short-circuits on idempotence; losing the manifest here would
        force the chain-of-custody file to be re-read from a potentially
        sealed directory, which is exactly the failure mode we are
        working around.
        """
        storage = ProtectedEvidenceStorage(root_dir=tmp_path / "evidence", apply_acls=False)
        mgr = QuickAcquisitionManager(storage=storage, acquirer=self._stub_acquirer())

        first = await mgr.quick_acquire(alert_id="dup", alert=_make_alert())
        second = await mgr.quick_acquire(alert_id="dup", alert=_make_alert())

        assert first.manifest is not None
        assert second.manifest is not None
        assert second.manifest.alert_id == first.manifest.alert_id
        assert len(second.manifest.entries) == len(first.manifest.entries)

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name != "nt", reason="MiniDumpWriteDump is Windows-only")
    async def test_quick_acquire_captures_self_memory(self, tmp_path: Path) -> None:
        """End-to-end with a real memory dump on the test process."""
        mgr = build_default_manager(
            evidence_root=tmp_path / "evidence",
            encryption_scope="off",  # keep the dump readable so we can check it
            apply_acls=False,  # keep pytest writable under tmp_path
        )
        result = await mgr.quick_acquire(
            alert_id="memtest",
            alert=_make_alert(),
            target_pids=[os.getpid()],
        )
        assert result.memdump_count >= 1
        dmp_files = list((result.incident_dir / "memdumps").glob("*.dmp"))
        assert dmp_files, "no .dmp produced"
        assert dmp_files[0].read_bytes()[:4] == b"MDMP"


# ===========================================================================
# BUILD FACTORY
# ===========================================================================


class TestBuildDefaultManager:
    """Factory integration test."""

    def test_build_default_manager_off_scope(self, tmp_path: Path) -> None:
        mgr = build_default_manager(
            evidence_root=tmp_path / "evidence", encryption_scope="off", apply_acls=False
        )
        assert isinstance(mgr, QuickAcquisitionManager)


# Give pytest's module loader a predictable cwd so storage paths work.
@pytest.fixture(autouse=True)
def _keep_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:  # noqa: ARG001
    """No-op fixture; placeholder for future CWD manipulation if needed."""
    # Intentionally empty — keeps pytest autouse hooks extensible.
    _ = sys  # touch import so the module stays even with unused helpers
