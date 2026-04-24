"""Tests for the svchost → Windows service names resolver."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.svchost_resolver import (
    _services_from_cmdline,
    _services_from_tasklist,
    resolve_services_for_pid,
)


def _fake_completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["tasklist"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


@pytest.fixture
def fake_tasklist_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``_tasklist_exe()`` return a real file path so the guard passes."""
    fake_root = tmp_path
    (fake_root / "System32").mkdir(parents=True)
    (fake_root / "System32" / "tasklist.exe").write_bytes(b"")
    monkeypatch.setattr("src.svchost_resolver.win_paths._SYSTEM_ROOT", str(fake_root))
    return fake_root / "System32" / "tasklist.exe"


# ---------------------------------------------------------------------------
# _services_from_tasklist()
# ---------------------------------------------------------------------------


class TestServicesFromTasklist:
    def test_parses_comma_separated_services(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = '"svchost.exe","1234","BITS,Dnscache,Schedule"\n'

        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return _fake_completed(stdout)

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert _services_from_tasklist(1234) == ["BITS", "Dnscache", "Schedule"]

    def test_parses_comma_space_separated(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Some locales emit ``BITS, Dnscache`` with a space."""
        stdout = '"svchost.exe","1234","BITS, Dnscache"\n'
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(stdout))
        assert _services_from_tasklist(1234) == ["BITS", "Dnscache"]

    def test_na_returns_empty(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = '"notepad.exe","9999","N/A"\n'
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(stdout))
        assert _services_from_tasklist(9999) == []

    def test_missing_exe_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.svchost_resolver.win_paths._SYSTEM_ROOT", str(tmp_path))
        assert _services_from_tasklist(1234) == []

    def test_timeout_returns_empty(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raising_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["tasklist"], timeout=5)

        monkeypatch.setattr(subprocess, "run", raising_run)
        assert _services_from_tasklist(1234) == []

    def test_non_zero_exit_returns_empty(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed("", returncode=1))
        assert _services_from_tasklist(1234) == []


# ---------------------------------------------------------------------------
# _services_from_cmdline()
# ---------------------------------------------------------------------------


class TestServicesFromCmdline:
    def test_picks_s_flag_argument(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import MagicMock

        fake_proc = MagicMock()
        fake_proc.cmdline.return_value = [
            "C:/Windows/System32/svchost.exe",
            "-k",
            "NetworkService",
            "-p",
            "-s",
            "Dnscache",
        ]
        monkeypatch.setattr(
            "src.svchost_resolver.psutil.Process",
            lambda pid: fake_proc,
        )

        assert _services_from_cmdline(1234) == ["Dnscache"]

    def test_missing_s_flag_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import MagicMock

        fake_proc = MagicMock()
        fake_proc.cmdline.return_value = ["C:/Windows/System32/svchost.exe", "-k", "netsvcs"]
        monkeypatch.setattr(
            "src.svchost_resolver.psutil.Process",
            lambda pid: fake_proc,
        )

        assert _services_from_cmdline(1234) == []

    def test_nosuchprocess_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from psutil import NoSuchProcess

        def raise_nsp(pid: int) -> object:
            raise NoSuchProcess(pid)

        monkeypatch.setattr("src.svchost_resolver.psutil.Process", raise_nsp)
        assert _services_from_cmdline(99999) == []


# ---------------------------------------------------------------------------
# resolve_services_for_pid() — integration
# ---------------------------------------------------------------------------


class TestResolveServicesForPid:
    def test_merges_and_dedupes_two_sources(
        self, fake_tasklist_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """tasklist returns ``[BITS, Dnscache]``; cmdline adds ``Dnscache`` —
        the final list must not double it and must stay sorted."""
        stdout = '"svchost.exe","1234","BITS, Dnscache"\n'
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(stdout))

        from unittest.mock import MagicMock

        fake_proc = MagicMock()
        fake_proc.cmdline.return_value = [
            "svchost.exe",
            "-k",
            "netsvcs",
            "-s",
            "Dnscache",
        ]
        monkeypatch.setattr("src.svchost_resolver.psutil.Process", lambda pid: fake_proc)

        services = resolve_services_for_pid(1234)
        assert services == ["BITS", "Dnscache"]

    def test_invalid_pid_returns_empty(self) -> None:
        assert resolve_services_for_pid(0) == []
        assert resolve_services_for_pid(-1) == []
