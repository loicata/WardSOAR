"""Tests for the installer helpers (Npcap + Suricata).

Every external interaction is mocked at the boundary:

* :mod:`winreg` (registry probes) → ``patch("winreg.OpenKey")``
* :mod:`httpx` (downloads) → ``patch("httpx.AsyncClient")``
* :mod:`subprocess` (Authenticode + installer launches) →
  ``patch("subprocess.run")``
* :mod:`pathlib.Path.is_file` for presence checks
* :func:`shutil.which` for PATH lookups

No real network calls, no real installers run, no real registry
hits. The tests can run on any Windows host (and will be skipped
gracefully on non-Windows since the module is Windows-only).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# The whole module imports winreg at module load — it cannot be
# imported on non-Windows hosts. CI runs on Windows so this is OK,
# but skip the whole file gracefully on Linux/macOS to keep the
# test runner clean.
if sys.platform != "win32":  # pragma: no cover — non-Windows skip
    pytest.skip("installer_helpers is Windows-only", allow_module_level=True)

from wardsoar.pc.installer_helpers import (  # noqa: E402
    NPCAP_EXPECTED_SIGNER,
    AuthenticodeResult,
    InstallerError,
    _extract_signer_short_name,
    _filename_from_url,
    download_installer,
    install_npcap,
    install_suricata,
    is_npcap_installed,
    is_suricata_installed,
    launch_installer,
    sha256_of,
    verify_authenticode,
)

# ---------------------------------------------------------------------------
# is_npcap_installed
# ---------------------------------------------------------------------------


class TestIsNpcapInstalled:
    """Registry-probe based detection. We mock ``winreg.OpenKey``
    to return either a context manager (key present) or raise
    ``OSError`` (key absent)."""

    def test_returns_true_when_wow6432_key_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_handle = MagicMock()
        fake_handle.__enter__ = MagicMock(return_value=fake_handle)
        fake_handle.__exit__ = MagicMock(return_value=False)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.winreg.OpenKey",
            MagicMock(return_value=fake_handle),
        )
        assert is_npcap_installed() is True

    def test_returns_false_when_key_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_oserror(*_args: Any, **_kwargs: Any) -> Any:
            raise OSError(2, "not found")

        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.winreg.OpenKey",
            raise_oserror,
        )
        assert is_npcap_installed() is False

    def test_returns_true_on_fallback_key_when_wow6432_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two registry candidates are tried in order. If the first
        raises but the second exists, detection still succeeds."""
        call_count = {"n": 0}
        fake_handle = MagicMock()
        fake_handle.__enter__ = MagicMock(return_value=fake_handle)
        fake_handle.__exit__ = MagicMock(return_value=False)

        def open_key(*_args: Any, **_kwargs: Any) -> Any:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError(2, "first miss")
            return fake_handle

        monkeypatch.setattr("wardsoar.pc.installer_helpers.winreg.OpenKey", open_key)
        assert is_npcap_installed() is True
        assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# is_suricata_installed
# ---------------------------------------------------------------------------


class TestIsSuricataInstalled:
    def test_returns_path_when_on_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        binary = tmp_path / "suricata.exe"
        binary.write_bytes(b"\x4d\x5a")  # MZ header — looks like a PE
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.shutil.which",
            lambda name: str(binary) if "suricata" in name else None,
        )
        ok, found_path = is_suricata_installed()
        assert ok is True
        assert found_path == binary

    def test_returns_path_when_in_program_files(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate ProgramFiles via env override + a real file on disk.
        program_files = tmp_path / "Program Files"
        suricata_dir = program_files / "Suricata"
        suricata_dir.mkdir(parents=True)
        binary = suricata_dir / "suricata.exe"
        binary.write_bytes(b"\x4d\x5a")
        monkeypatch.setenv("ProgramFiles", str(program_files))
        monkeypatch.setattr("wardsoar.pc.installer_helpers.shutil.which", lambda _name: None)
        # Block registry probe.
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.winreg.OpenKey",
            MagicMock(side_effect=OSError(2, "not found")),
        )
        ok, found_path = is_suricata_installed()
        assert ok is True
        assert found_path == binary

    def test_returns_false_when_nothing_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # No PATH match, no Program Files install, no registry key.
        monkeypatch.setattr("wardsoar.pc.installer_helpers.shutil.which", lambda _name: None)
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "nonexistent"))
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.winreg.OpenKey",
            MagicMock(side_effect=OSError(2, "not found")),
        )
        ok, found_path = is_suricata_installed()
        assert ok is False
        assert found_path is None


# ---------------------------------------------------------------------------
# download_installer
# ---------------------------------------------------------------------------


def _mock_async_streaming_response(
    status_code: int = 200,
    content_length: int | str = -1,
    chunks: list[bytes] | None = None,
) -> MagicMock:
    """Build an httpx.Response-shaped mock for ``client.stream(...)``."""
    if chunks is None:
        chunks = [b"x" * 1024]
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Content-Length": str(content_length)} if content_length != -1 else {}

    async def aiter_bytes(_chunk_size: int) -> Any:
        for chunk in chunks:
            yield chunk

    resp.aiter_bytes = aiter_bytes
    return resp


class TestDownloadInstaller:
    @pytest.mark.asyncio
    async def test_refuses_non_https_url(self, tmp_path: Path) -> None:
        with pytest.raises(InstallerError, match="non-HTTPS"):
            await download_installer("http://example.com/x.exe", tmp_path / "x.exe")

    @pytest.mark.asyncio
    async def test_writes_streamed_chunks_to_dest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chunks = [b"hello", b" ", b"world"]
        resp = _mock_async_streaming_response(status_code=200, content_length=11, chunks=chunks)
        # ``client.stream`` is an async context manager that yields the response
        stream_cm = AsyncMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=None)

        client = MagicMock()
        client.stream = MagicMock(return_value=stream_cm)
        client_cm = AsyncMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=None)

        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.httpx.AsyncClient",
            MagicMock(return_value=client_cm),
        )

        dest = tmp_path / "x.exe"
        result = await download_installer("https://example.com/x.exe", dest)
        assert result == dest
        assert dest.read_bytes() == b"hello world"

    @pytest.mark.asyncio
    async def test_raises_on_non_200(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _mock_async_streaming_response(status_code=404)
        stream_cm = AsyncMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=None)
        client = MagicMock()
        client.stream = MagicMock(return_value=stream_cm)
        client_cm = AsyncMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.httpx.AsyncClient",
            MagicMock(return_value=client_cm),
        )
        with pytest.raises(InstallerError, match="HTTP 404"):
            await download_installer("https://example.com/x.exe", tmp_path / "x.exe")

    @pytest.mark.asyncio
    async def test_progress_callback_called(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Simulate a 2 MiB download in 1 MiB chunks so the
        # progress callback fires at least twice.
        chunk = b"x" * (1024 * 1024)
        resp = _mock_async_streaming_response(
            status_code=200, content_length=2 * 1024 * 1024, chunks=[chunk, chunk]
        )
        stream_cm = AsyncMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=None)
        client = MagicMock()
        client.stream = MagicMock(return_value=stream_cm)
        client_cm = AsyncMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.httpx.AsyncClient",
            MagicMock(return_value=client_cm),
        )

        progress: list[tuple[int, int]] = []

        async def cb(done: int, total: int) -> None:
            progress.append((done, total))

        await download_installer(
            "https://example.com/x.exe", tmp_path / "x.exe", progress_callback=cb
        )
        assert len(progress) >= 1
        # Final tick: ``done == total``.
        last_done, last_total = progress[-1]
        assert last_done == last_total


# ---------------------------------------------------------------------------
# verify_authenticode
# ---------------------------------------------------------------------------


class TestVerifyAuthenticode:
    def test_unknown_when_powershell_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "x.exe"
        target.write_bytes(b"any")
        monkeypatch.setattr("wardsoar.pc.installer_helpers.win_paths.POWERSHELL", "")
        result = verify_authenticode(target, "Whoever")
        assert result.status == "unknown"
        assert result.signer == ""

    def test_valid_signature_parsed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "x.exe"
        target.write_bytes(b"any")
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.installer_helpers.win_paths.POWERSHELL", str(ps))

        def fake_run(*_a: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"Status":"Valid","Subject":"CN=Insecure.Com LLC, O=Insecure.Com LLC"}',
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = verify_authenticode(target, NPCAP_EXPECTED_SIGNER)
        assert result.status == "valid"
        assert result.signer == "Insecure.Com LLC"

    def test_unsigned_status_mapped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "x.exe"
        target.write_bytes(b"any")
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.installer_helpers.win_paths.POWERSHELL", str(ps))

        def fake_run(*_a: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='{"Status":"NotSigned","Subject":""}', stderr=""
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = verify_authenticode(target, "Anyone")
        assert result.status == "unsigned"
        assert result.signer == ""

    def test_timeout_returns_unknown(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "x.exe"
        target.write_bytes(b"any")
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.installer_helpers.win_paths.POWERSHELL", str(ps))

        def raising_run(*_a: Any, **_kw: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd=["x"], timeout=5)

        monkeypatch.setattr(subprocess, "run", raising_run)
        result = verify_authenticode(target, "X")
        assert result.status == "unknown"


class TestExtractSignerShortName:
    def test_microsoft_subject(self) -> None:
        s = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond"
        assert _extract_signer_short_name(s) == "Microsoft Corporation"

    def test_falls_back_to_o_when_no_cn(self) -> None:
        assert _extract_signer_short_name("O=OISF, C=US") == "OISF"

    def test_empty_subject(self) -> None:
        assert _extract_signer_short_name("") == ""


# ---------------------------------------------------------------------------
# launch_installer
# ---------------------------------------------------------------------------


class TestLaunchInstaller:
    def test_raises_when_file_missing(self, tmp_path: Path) -> None:
        ghost = tmp_path / "nope.exe"
        with pytest.raises(InstallerError, match="installer not found"):
            launch_installer(ghost)

    def test_runs_exe_directly(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        installer = tmp_path / "x.exe"
        installer.write_bytes(b"")
        called: dict[str, Any] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            called["cmd"] = cmd
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        rc = launch_installer(installer)
        assert rc == 0
        assert called["cmd"] == [str(installer)]

    def test_msi_routed_through_msiexec(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        installer = tmp_path / "x.msi"
        installer.write_bytes(b"")
        called: dict[str, Any] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            called["cmd"] = cmd
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        # Pretend MSIEXEC isn't a known win_paths attribute so we
        # exercise the fallback "msiexec.exe" string.
        monkeypatch.delattr("wardsoar.pc.installer_helpers.win_paths.MSIEXEC", raising=False)
        monkeypatch.setattr(subprocess, "run", fake_run)
        rc = launch_installer(installer)
        assert rc == 0
        assert called["cmd"][0] == "msiexec.exe"
        assert "/i" in called["cmd"]
        assert str(installer) in called["cmd"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestFilenameFromUrl:
    def test_simple_url(self) -> None:
        assert _filename_from_url("https://x.com/npcap-1.79.exe", "x.exe") == "npcap-1.79.exe"

    def test_with_query_string(self) -> None:
        assert (
            _filename_from_url("https://x.com/file.exe?v=1&token=abc", "fallback.exe") == "file.exe"
        )

    def test_falls_back_when_url_ends_in_slash(self) -> None:
        assert _filename_from_url("https://x.com/", "fallback.exe") == "fallback.exe"


class TestSha256Of:
    def test_deterministic_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"hello world")
        # Known hash of "hello world".
        assert sha256_of(f) == ("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")


# ---------------------------------------------------------------------------
# install_npcap (orchestration)
# ---------------------------------------------------------------------------


class TestInstallNpcap:
    @pytest.mark.asyncio
    async def test_idempotent_when_already_installed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("wardsoar.pc.installer_helpers.is_npcap_installed", lambda: True)
        outcome = await install_npcap(tmp_path)
        assert outcome.success is True
        assert outcome.detail == "already_installed"

    @pytest.mark.asyncio
    async def test_signer_mismatch_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("wardsoar.pc.installer_helpers.is_npcap_installed", lambda: False)

        async def fake_download(url: str, dest: Path, **_kw: Any) -> Path:
            dest.write_bytes(b"\x4d\x5a")
            return dest

        monkeypatch.setattr("wardsoar.pc.installer_helpers.download_installer", fake_download)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.verify_authenticode",
            lambda _p, _s: AuthenticodeResult(status="valid", signer="EvilCorp"),
        )
        outcome = await install_npcap(tmp_path)
        assert outcome.success is False
        assert "unexpected signer" in outcome.detail

    @pytest.mark.asyncio
    async def test_full_success_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Sequence the registry probe: False before install, True after.
        registry_states = iter([False, True])
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.is_npcap_installed",
            lambda: next(registry_states),
        )

        async def fake_download(url: str, dest: Path, **_kw: Any) -> Path:
            dest.write_bytes(b"\x4d\x5a")
            return dest

        monkeypatch.setattr("wardsoar.pc.installer_helpers.download_installer", fake_download)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.verify_authenticode",
            lambda _p, _s: AuthenticodeResult(status="valid", signer="Insecure.Com LLC"),
        )
        monkeypatch.setattr("wardsoar.pc.installer_helpers.launch_installer", lambda _p: 0)
        outcome = await install_npcap(tmp_path)
        assert outcome.success is True
        assert outcome.detail == "installed"
        assert outcome.installer_path is not None
        assert outcome.installer_path.exists()


class TestInstallSuricata:
    @pytest.mark.asyncio
    async def test_idempotent_when_already_installed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.is_suricata_installed",
            lambda: (True, tmp_path / "suricata.exe"),
        )
        outcome = await install_suricata(tmp_path)
        assert outcome.success is True
        assert outcome.detail == "already_installed"

    @pytest.mark.asyncio
    async def test_msi_3010_treated_as_success(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        states = iter([(False, None), (True, tmp_path / "suricata.exe")])
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.is_suricata_installed",
            lambda: next(states),
        )

        async def fake_download(url: str, dest: Path, **_kw: Any) -> Path:
            dest.write_bytes(b"\x4d\x5a")
            return dest

        monkeypatch.setattr("wardsoar.pc.installer_helpers.download_installer", fake_download)
        monkeypatch.setattr(
            "wardsoar.pc.installer_helpers.verify_authenticode",
            lambda _p, _s: AuthenticodeResult(
                status="valid",
                signer="Open Information Security Foundation",
            ),
        )
        monkeypatch.setattr("wardsoar.pc.installer_helpers.launch_installer", lambda _p: 3010)
        outcome = await install_suricata(tmp_path)
        assert outcome.success is True
