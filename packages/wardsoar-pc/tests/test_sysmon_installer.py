"""Tests for the Sysmon installer launcher.

Spawning an elevated PowerShell via UAC is not something we can
exercise in a unit test — the actual subprocess call is mocked.
The behaviour we *do* test is the guard rails: missing PowerShell,
missing script, and the composition of the outer PowerShell
command.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from wardsoar.pc.sysmon_installer import (
    InstallLaunchResult,
    describe_script_location,
    find_install_script,
    launch_install_script,
)


@pytest.fixture
def _real_repo_data_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Override the conftest's ``WARDSOAR_DATA_DIR`` sandbox for tests
    that specifically verify the on-disk install-sysmon.ps1 resolution.

    The repo-level conftest isolates every test from the operator's
    data directory by pointing ``WARDSOAR_DATA_DIR`` at a pytest
    tmp_path. That is what we want almost everywhere — except for
    these three tests which assert that ``find_install_script()``
    actually locates the PowerShell file shipped inside the repo at
    ``<repo>/scripts/install-sysmon.ps1``.
    """
    monkeypatch.delenv("WARDSOAR_DATA_DIR", raising=False)


@pytest.fixture
def with_installed_scripts(
    _real_repo_data_dir: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Drop a fake install-sysmon.ps1 where ``find_install_script`` expects it.

    The default resolver first looks under ``<repo>/scripts/`` — which
    already exists in the repo — so we only need to neutralise the
    PowerShell lookup to exercise the non-repo branches.
    """
    fake_ps = tmp_path / "powershell.exe"
    fake_ps.write_bytes(b"")
    monkeypatch.setattr("wardsoar.pc.sysmon_installer.win_paths.POWERSHELL", str(fake_ps))
    return fake_ps


class TestFindInstallScript:
    def test_repo_script_is_found(self, _real_repo_data_dir: None) -> None:
        """The repo ships the script, so find_install_script() returns it."""
        result = find_install_script()
        assert result is not None
        assert result.name == "install-sysmon.ps1"

    def test_describe_script_location_returns_path(self, _real_repo_data_dir: None) -> None:
        location = describe_script_location()
        assert "install-sysmon.ps1" in location


class TestLaunchInstallScript:
    def test_missing_powershell_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Point POWERSHELL at a non-existent file.
        monkeypatch.setattr(
            "wardsoar.pc.sysmon_installer.win_paths.POWERSHELL", str(tmp_path / "ghost.exe")
        )
        result = launch_install_script()
        assert result.started is False
        assert "PowerShell" in result.error

    def test_missing_script_returns_error(
        self, with_installed_scripts: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If neither the repo nor the bundle path has the script."""
        monkeypatch.setattr("wardsoar.pc.sysmon_installer.find_install_script", lambda: None)
        result = launch_install_script()
        assert result.started is False
        assert "install-sysmon.ps1" in result.error

    def test_happy_path_spawns_powershell(
        self, with_installed_scripts: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured_args: list[list[str]] = []

        def fake_popen(args: list[str], **_kwargs: object) -> MagicMock:
            captured_args.append(list(args))
            return MagicMock()

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        result = launch_install_script()

        assert result.started is True
        assert result.error == ""
        assert result.script_path.endswith("install-sysmon.ps1")
        # Outer command must go through ``Start-Process -Verb RunAs``
        # so UAC actually fires. That is the whole point of the module.
        assert len(captured_args) == 1
        joined = " ".join(captured_args[0])
        assert "-Verb RunAs" in joined
        assert "install-sysmon.ps1" in joined

    def test_popen_oserror_returns_failure(
        self, with_installed_scripts: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raising_popen(*_args: object, **_kwargs: object) -> MagicMock:
            raise OSError("child spawn failed")

        monkeypatch.setattr(subprocess, "Popen", raising_popen)

        result = launch_install_script()

        assert result.started is False
        assert "child spawn failed" in result.error


class TestInstallLaunchResult:
    def test_defaults(self) -> None:
        r = InstallLaunchResult(started=True, script_path="/x")
        assert r.error == ""
