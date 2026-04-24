"""Tests for the Sysmon availability probe.

Sysmon detection is a thin shell over ``sc query`` — we drive the
subprocess through ``monkeypatch`` to simulate the common outcomes
(running, installed-but-stopped, not installed, environment broken).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.sysmon_probe import (
    SysmonStatus,
    probe_sysmon,
    recommended_install_snippet,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_completed(returncode: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
    """Build a ``CompletedProcess`` without touching the real shell."""
    return subprocess.CompletedProcess(
        args=["sc", "query", "Sysmon64"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


@pytest.fixture
def fake_sc_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a dummy sc.exe path that ``Path.is_file()`` will accept.

    The probe refuses to run when ``win_paths.SC`` does not resolve to
    a real file. We point it at a temp file so the downstream logic is
    actually exercised.
    """
    sc = tmp_path / "sc.exe"
    sc.write_bytes(b"")
    monkeypatch.setattr("src.sysmon_probe.win_paths.SC", str(sc))
    return sc


# ---------------------------------------------------------------------------
# probe_sysmon()
# ---------------------------------------------------------------------------


class TestProbeSysmon:
    def test_reports_healthy_when_sysmon64_runs(
        self, fake_sc_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return _fake_completed(
                0,
                "SERVICE_NAME: Sysmon64\n        TYPE               : 10  WIN32_OWN_PROCESS"
                "\n        STATE              : 4  RUNNING ",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        status = probe_sysmon()

        assert status.installed is True
        assert status.running is True
        assert status.service_name == "Sysmon64"
        assert status.healthy is True
        assert status.error == ""

    def test_reports_installed_but_stopped(
        self, fake_sc_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return _fake_completed(
                0,
                "SERVICE_NAME: Sysmon64\n        STATE              : 1  STOPPED ",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        status = probe_sysmon()

        assert status.installed is True
        assert status.running is False
        assert status.service_name == "Sysmon64"
        assert status.healthy is False

    def test_reports_not_installed_when_both_services_missing(
        self, fake_sc_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # sc exits non-zero for missing services (1060).
        monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: _fake_completed(1060, ""))

        status = probe_sysmon()

        assert status.installed is False
        assert status.running is False
        assert status.service_name == ""
        assert status.healthy is False
        assert status.error == ""

    def test_falls_back_to_sysmon_x86_when_sysmon64_missing(
        self, fake_sc_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        def fake_run(
            cmd: list[str], *_args: object, **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            name = cmd[-1]
            calls.append(name)
            if name == "Sysmon64":
                return _fake_completed(1060, "")
            return _fake_completed(
                0, "SERVICE_NAME: Sysmon\n        STATE              : 4  RUNNING"
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        status = probe_sysmon()

        assert calls == ["Sysmon64", "Sysmon"]
        assert status.installed is True
        assert status.running is True
        assert status.service_name == "Sysmon"

    def test_timeout_is_treated_as_not_installed(
        self, fake_sc_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hung ``sc query`` must not block the pipeline startup."""

        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["sc"], timeout=5)

        monkeypatch.setattr(subprocess, "run", fake_run)

        status = probe_sysmon()

        assert status.installed is False
        assert status.error == ""  # TimeoutExpired is treated as "service absent"

    def test_missing_sc_exe_reports_environment_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-Windows host or sc.exe wiped — probe cannot even run."""
        bogus = tmp_path / "nonexistent" / "sc.exe"
        monkeypatch.setattr("src.sysmon_probe.win_paths.SC", str(bogus))

        status = probe_sysmon()

        assert status.installed is False
        assert status.error  # populated


class TestRecommendedInstallSnippet:
    def test_snippet_contains_official_urls_and_one_liner(self) -> None:
        snippet = recommended_install_snippet()

        assert "download.sysinternals.com" in snippet
        assert "SwiftOnSecurity/sysmon-config" in snippet
        assert "-accepteula" in snippet
        assert "sysmonconfig-export.xml" in snippet


class TestSysmonStatus:
    def test_healthy_requires_installed_and_running(self) -> None:
        assert SysmonStatus().healthy is False
        assert SysmonStatus(installed=True, running=False).healthy is False
        assert SysmonStatus(installed=False, running=True).healthy is False
        assert SysmonStatus(installed=True, running=True).healthy is True
