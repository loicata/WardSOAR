"""Tests for SuricataProcess + config generation + interface listing.

External interactions mocked at the boundary:

* :func:`subprocess.Popen` for process spawn
* :mod:`psutil` for ``Process``, ``net_if_addrs``
* file system via ``tmp_path``
* :func:`shutil.which` and ``ProgramFiles`` for the install lookup
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

if sys.platform != "win32":  # pragma: no cover — non-Windows skip
    pytest.skip("local_suricata is Windows-only", allow_module_level=True)

import psutil  # noqa: E402

from wardsoar.pc.local_suricata import (  # noqa: E402
    EVE_JSON_FILENAME,
    SuricataProcess,
    find_suricata_install_dir,
    generate_suricata_config,
    list_network_interfaces,
)

# ---------------------------------------------------------------------------
# SuricataProcess
# ---------------------------------------------------------------------------


def _setup_proc_files(
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    """Create dummy binary + config + log dir on disk."""
    binary = tmp_path / "suricata.exe"
    binary.write_bytes(b"\x4d\x5a")  # MZ magic — looks like a PE
    config = tmp_path / "suricata.yaml"
    config.write_text("vars: {}\n", encoding="utf-8")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return binary, config, log_dir


class TestSuricataProcessLifecycle:
    @pytest.fixture(autouse=True)
    def stub_npf_resolver(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Skip the Get-NetAdapter PowerShell call across the lifecycle suite.

        The resolver has its own dedicated tests; here we only care about
        Popen wiring, idempotence, etc., and we don't want the friendly
        name lookup running on the test host (it would crash on non-
        Windows CI and is environment-dependent on Windows).
        """
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata._resolve_interface_to_npf",
            lambda name: name,
        )

    @pytest.mark.asyncio
    async def test_eve_path_property(self, tmp_path: Path) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)
        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        assert proc.eve_path == log_dir / EVE_JSON_FILENAME

    @pytest.mark.asyncio
    async def test_is_running_false_before_start(self, tmp_path: Path) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)
        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        assert proc.is_running() is False
        assert proc.pid is None

    @pytest.mark.asyncio
    async def test_start_fails_when_binary_missing(self, tmp_path: Path) -> None:
        config = tmp_path / "suricata.yaml"
        config.write_text("", encoding="utf-8")
        proc = SuricataProcess(
            tmp_path / "ghost.exe",
            config,
            "Ethernet",
            tmp_path / "logs",
        )
        ok = await proc.start()
        assert ok is False
        assert proc.pid is None

    @pytest.mark.asyncio
    async def test_start_fails_when_config_missing(self, tmp_path: Path) -> None:
        binary = tmp_path / "suricata.exe"
        binary.write_bytes(b"\x4d\x5a")
        proc = SuricataProcess(
            binary,
            tmp_path / "ghost.yaml",
            "Ethernet",
            tmp_path / "logs",
        )
        ok = await proc.start()
        assert ok is False

    @pytest.mark.asyncio
    async def test_start_invokes_popen_with_correct_args(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)

        captured: dict[str, Any] = {}
        fake_popen = MagicMock()
        fake_popen.pid = 4242
        fake_popen.poll = MagicMock(return_value=None)  # still running

        def popen_factory(cmd: list[str], **kwargs: Any) -> Any:
            captured["cmd"] = cmd
            return fake_popen

        # psutil.Process must report alive for is_running() to return True
        # post-start; we mock it minimally.
        fake_psutil_proc = MagicMock()
        fake_psutil_proc.is_running.return_value = True
        fake_psutil_proc.status.return_value = "running"
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata.psutil.Process",
            MagicMock(return_value=fake_psutil_proc),
        )
        monkeypatch.setattr(subprocess, "Popen", popen_factory)

        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        ok = await proc.start()
        assert ok is True
        assert proc.pid == 4242
        cmd = captured["cmd"]
        assert str(binary) in cmd
        assert "-c" in cmd
        assert str(config) in cmd
        assert "-i" in cmd
        assert "Ethernet" in cmd
        assert "-l" in cmd

    @pytest.mark.asyncio
    async def test_start_idempotent_when_already_running(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)
        proc = SuricataProcess(binary, config, "Ethernet", log_dir)

        # First start.
        fake_popen = MagicMock(pid=1111, poll=MagicMock(return_value=None))
        monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=fake_popen))
        fake_ps = MagicMock()
        fake_ps.is_running.return_value = True
        fake_ps.status.return_value = "running"
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata.psutil.Process",
            MagicMock(return_value=fake_ps),
        )
        await proc.start()

        # Second start — must NOT call Popen again.
        popen_spy = MagicMock(side_effect=AssertionError("Popen should not be called twice"))
        monkeypatch.setattr(subprocess, "Popen", popen_spy)
        ok = await proc.start()
        assert ok is True

    @pytest.mark.asyncio
    async def test_start_detects_immediate_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If Suricata crashes within the startup grace window
        (e.g. bad config, missing Npcap), start() returns False."""
        binary, config, log_dir = _setup_proc_files(tmp_path)
        # poll() returns 1 immediately = process exited.
        fake_popen = MagicMock(pid=9999, poll=MagicMock(return_value=1), returncode=1)
        monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=fake_popen))
        # is_running before start returns False (so we proceed).
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata.psutil.Process",
            MagicMock(side_effect=psutil.NoSuchProcess(9999)),
        )
        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        ok = await proc.start()
        assert ok is False
        assert proc.pid is None

    @pytest.mark.asyncio
    async def test_stop_idempotent_when_not_running(self, tmp_path: Path) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)
        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        ok = await proc.stop()
        assert ok is True

    @pytest.mark.asyncio
    async def test_stop_graceful_terminate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary, config, log_dir = _setup_proc_files(tmp_path)

        # State transitions on terminate(): poll() returns None
        # (alive) until terminate() flips ``_terminated`` to True,
        # then poll() returns 0 (exited cleanly). This mirrors how a
        # real subprocess.Popen behaves and avoids the "exit during
        # startup" false positive where the startup grace loop
        # polled the same iterator and consumed the only "alive"
        # return.
        state: dict[str, bool] = {"terminated": False}

        def fake_poll() -> int | None:
            return 0 if state["terminated"] else None

        def fake_terminate() -> None:
            state["terminated"] = True

        fake_popen = MagicMock(pid=5555)
        fake_popen.poll = MagicMock(side_effect=fake_poll)
        fake_popen.terminate = MagicMock(side_effect=fake_terminate)
        fake_popen.returncode = 0
        monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=fake_popen))

        # psutil reports alive throughout the start/stop transition.
        fake_ps = MagicMock()
        fake_ps.is_running.return_value = True
        fake_ps.status.return_value = "running"
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata.psutil.Process",
            MagicMock(return_value=fake_ps),
        )

        proc = SuricataProcess(binary, config, "Ethernet", log_dir)
        ok_start = await proc.start()
        assert ok_start is True
        ok_stop = await proc.stop()
        assert ok_stop is True
        fake_popen.terminate.assert_called_once()
        # State cleaned: PID None after stop.
        assert proc.pid is None


# ---------------------------------------------------------------------------
# generate_suricata_config
# ---------------------------------------------------------------------------


class TestGenerateSuricataConfig:
    def test_writes_file_with_substitutions(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config" / "suricata.yaml"
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        # Lay down a couple of rule files so the generator emits them
        # (it filters _DEFAULT_RULE_FILES against on-disk presence).
        (rule_dir / "drop.rules").write_text("# drop rules", encoding="utf-8")
        (rule_dir / "emerging-malware.rules").write_text("# malware", encoding="utf-8")
        result = generate_suricata_config(
            config_path=config_path,
            interface="Ethernet 2",
            log_dir=tmp_path / "logs",
            rule_dir=rule_dir,
            classification_file=tmp_path / "classification.config",
            reference_config_file=tmp_path / "reference.config",
        )
        assert result == config_path
        assert config_path.is_file()
        content = config_path.read_text(encoding="utf-8")
        assert "Ethernet 2" in content
        assert "eve.json" in content
        # Both rule files we laid on disk must show up in the rule list.
        assert "drop.rules" in content
        assert "emerging-malware.rules" in content

    def test_paths_use_native_backslashes_on_windows(self, tmp_path: Path) -> None:
        """Suricata 8.x on Windows requires native backslash paths for
        ``default-rule-path``. Forward slashes there cause Suricata to
        concatenate paths incorrectly when locating the per-rule files,
        leading to ``No such file or directory`` errors at startup.
        Pin this rendering invariant."""
        config_path = tmp_path / "suricata.yaml"
        generate_suricata_config(
            config_path=config_path,
            interface="Ethernet",
            log_dir=Path(r"C:\some\log"),
            rule_dir=Path(r"C:\rules"),
            classification_file=Path(r"C:\rules\classification.config"),
            reference_config_file=Path(r"C:\rules\reference.config"),
        )
        content = config_path.read_text(encoding="utf-8")
        assert r"C:\some\log" in content
        assert r"C:\rules" in content

    def test_eve_log_does_not_use_invalid_8x_options(self, tmp_path: Path) -> None:
        """Regression: Suricata 8.x rejects ``metadata: yes`` and
        ``http-body: yes`` under ``eve-log.types.alert``. The wizard
        used to emit both, which crashed Suricata at output-module
        setup with a generic ``output module 'eve-log': setup failed``.
        """
        config_path = tmp_path / "suricata.yaml"
        generate_suricata_config(
            config_path=config_path,
            interface="Ethernet",
            log_dir=tmp_path,
            rule_dir=tmp_path,
            classification_file=tmp_path / "c.config",
            reference_config_file=tmp_path / "r.config",
        )
        content = config_path.read_text(encoding="utf-8")
        # Strip comment lines so the warning text in the template
        # itself doesn't trigger the regression.
        non_comment = "\n".join(
            line for line in content.splitlines() if not line.lstrip().startswith("#")
        )
        assert "metadata: yes" not in non_comment
        assert "http-body: yes" not in non_comment


# ---------------------------------------------------------------------------
# _resolve_interface_to_npf — friendly name -> NPF device path
# ---------------------------------------------------------------------------


class TestResolveInterfaceToNpf:
    """Translate friendly adapter names to ``\\Device\\NPF_{guid}``.

    Suricata 8.x on Windows crashes hard when ``-i`` is a friendly
    adapter name; only NPF paths bind cleanly. The wizard collects
    the friendly name from the picker, so the runtime spawn must
    translate.
    """

    def test_passes_through_existing_npf_path(self) -> None:
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        path = r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}"
        assert _resolve_interface_to_npf(path) == path

    def test_passes_through_rpcap_uri(self) -> None:
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        uri = "rpcap://10.0.0.1:2002/eth0"
        assert _resolve_interface_to_npf(uri) == uri

    def test_empty_string_passes_through(self) -> None:
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        assert _resolve_interface_to_npf("") == ""

    def test_friendly_name_resolved_to_npf_via_get_netadapter(self) -> None:
        from unittest.mock import patch
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        fake_completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "{12345678-1234-1234-1234-123456789ABC}\r\n",
                "stderr": "",
            },
        )()
        with patch("wardsoar.pc.local_suricata.subprocess.run", return_value=fake_completed):
            result = _resolve_interface_to_npf("Ethernet")
        assert result == r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}"

    def test_friendly_name_passed_through_when_lookup_fails(self) -> None:
        from unittest.mock import patch
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        fake_completed = type(
            "Completed",
            (),
            {"returncode": 1, "stdout": "", "stderr": "no such adapter"},
        )()
        with patch("wardsoar.pc.local_suricata.subprocess.run", return_value=fake_completed):
            result = _resolve_interface_to_npf("NonexistentAdapter")
        assert result == "NonexistentAdapter"

    def test_unexpected_output_passes_through(self) -> None:
        from unittest.mock import patch
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        fake_completed = type(
            "Completed",
            (),
            {"returncode": 0, "stdout": "garbage no braces", "stderr": ""},
        )()
        with patch("wardsoar.pc.local_suricata.subprocess.run", return_value=fake_completed):
            result = _resolve_interface_to_npf("Ethernet")
        assert result == "Ethernet"

    def test_subprocess_error_passes_through(self) -> None:
        from unittest.mock import patch
        from wardsoar.pc.local_suricata import _resolve_interface_to_npf

        with patch(
            "wardsoar.pc.local_suricata.subprocess.run",
            side_effect=OSError("ENOENT"),
        ):
            result = _resolve_interface_to_npf("Ethernet")
        assert result == "Ethernet"

    def test_idempotent_overwrite(self, tmp_path: Path) -> None:
        config_path = tmp_path / "suricata.yaml"
        first = generate_suricata_config(
            config_path=config_path,
            interface="Ethernet",
            log_dir=tmp_path / "logs",
            rule_dir=tmp_path / "rules",
            classification_file=tmp_path / "rules" / "classification.config",
            reference_config_file=tmp_path / "rules" / "reference.config",
        )
        first_content = first.read_text(encoding="utf-8")
        # Same args → same content.
        second = generate_suricata_config(
            config_path=config_path,
            interface="Ethernet",
            log_dir=tmp_path / "logs",
            rule_dir=tmp_path / "rules",
            classification_file=tmp_path / "rules" / "classification.config",
            reference_config_file=tmp_path / "rules" / "reference.config",
        )
        assert second.read_text(encoding="utf-8") == first_content


# ---------------------------------------------------------------------------
# list_network_interfaces
# ---------------------------------------------------------------------------


class TestListNetworkInterfaces:
    def test_filters_virtual_adapters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_addr = MagicMock()
        fake_addr.address = "192.168.2.50"
        fake_addr.family = MagicMock()
        fake_addr.family.name = "AF_INET"

        adapters = {
            "Ethernet": [fake_addr],
            "Loopback Pseudo-Interface 1": [fake_addr],
            "vEthernet (WSL)": [fake_addr],
            "Hyper-V Virtual Switch": [fake_addr],
            "Docker": [fake_addr],
        }
        monkeypatch.setattr("wardsoar.pc.local_suricata.psutil.net_if_addrs", lambda: adapters)
        result = list_network_interfaces()
        names = [name for name, _ in result]
        assert "Ethernet" in names
        assert "Loopback Pseudo-Interface 1" not in names
        assert "vEthernet (WSL)" not in names
        assert "Hyper-V Virtual Switch" not in names
        assert "Docker" not in names

    def test_returns_empty_on_psutil_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raising_addrs() -> Any:
            raise psutil.Error("test")

        monkeypatch.setattr("wardsoar.pc.local_suricata.psutil.net_if_addrs", raising_addrs)
        assert list_network_interfaces() == []

    def test_renders_address_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ipv4 = MagicMock()
        ipv4.address = "192.168.2.100"
        ipv4.family = MagicMock(name="AF_INET")
        ipv4.family.name = "AF_INET"

        mac = MagicMock()
        mac.address = "aa:bb:cc:dd:ee:ff"
        mac.family = MagicMock(name="AF_LINK")
        mac.family.name = "AF_LINK"

        adapters = {"Ethernet": [ipv4, mac]}
        monkeypatch.setattr("wardsoar.pc.local_suricata.psutil.net_if_addrs", lambda: adapters)
        result = list_network_interfaces()
        assert len(result) == 1
        name, summary = result[0]
        assert name == "Ethernet"
        assert "192.168.2.100" in summary
        assert "aa:bb:cc:dd:ee:ff" in summary


# ---------------------------------------------------------------------------
# find_suricata_install_dir
# ---------------------------------------------------------------------------


class TestFindSuricataInstallDir:
    def test_finds_via_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        binary = tmp_path / "suricata.exe"
        binary.write_bytes(b"")
        monkeypatch.setattr(
            "wardsoar.pc.local_suricata.shutil.which",
            lambda name: str(binary) if "suricata" in name else None,
        )
        result = find_suricata_install_dir()
        assert result == tmp_path

    def test_finds_via_program_files(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        program_files = tmp_path / "Program Files"
        suricata_dir = program_files / "Suricata"
        suricata_dir.mkdir(parents=True)
        binary = suricata_dir / "suricata.exe"
        binary.write_bytes(b"")
        monkeypatch.setenv("ProgramFiles", str(program_files))
        monkeypatch.setattr("wardsoar.pc.local_suricata.shutil.which", lambda _name: None)
        result = find_suricata_install_dir()
        assert result == suricata_dir

    def test_returns_none_when_not_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("wardsoar.pc.local_suricata.shutil.which", lambda _name: None)
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "nonexistent"))
        assert find_suricata_install_dir() is None
