"""Tests for WardSOAR local forensic analysis.

Forensics is HIGH (85% coverage). All system calls are mocked.
Fail-safe: if any forensic check fails, return empty results.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.pc.forensics import (
    FlowKey,
    ForensicAnalyzer,
    _conn_matches_flow,
    _is_local_ip,
    _select_external_ip,
    build_flow_key,
)
from wardsoar.core.models import ForensicResult, SuricataAlert, SuricataAlertSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(src_ip: str = "10.0.0.1") -> SuricataAlert:
    """Create a test alert."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


class TestIsLocalIp:
    """RFC1918 / loopback / link-local detection."""

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.168.2.100",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ],
    )
    def test_private_addresses_are_local(self, ip: str) -> None:
        assert _is_local_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "162.159.207.0",
            "34.117.59.81",
            "2001:4860:4860::8888",
        ],
    )
    def test_public_addresses_are_not_local(self, ip: str) -> None:
        assert _is_local_ip(ip) is False

    def test_malformed_input_returns_false(self) -> None:
        """Garbage input must not raise — caller will still feed it to
        psutil which handles its own errors."""
        assert _is_local_ip("") is False
        assert _is_local_ip("not.an.ip") is False
        assert _is_local_ip("192.168.256.1") is False  # bad octet


class TestSelectExternalIp:
    """Direction-aware picking of the remote peer."""

    def test_pc_initiates_flow_returns_dest(self) -> None:
        """Typical case: STUN / TLS / STREAM retrans from the PC."""
        alert = _make_alert(src_ip="192.168.2.100")
        alert = alert.model_copy(update={"dest_ip": "162.159.207.0"})
        assert _select_external_ip(alert) == "162.159.207.0"

    def test_external_attacker_returns_src(self) -> None:
        """Inbound traffic from an external IP towards the PC."""
        alert = _make_alert(src_ip="203.0.113.5")
        alert = alert.model_copy(update={"dest_ip": "192.168.2.100"})
        assert _select_external_ip(alert) == "203.0.113.5"

    def test_both_local_falls_back_to_src(self) -> None:
        """LAN-to-LAN scan: no ambiguity to resolve, keep the pre-fix
        behaviour (src_ip) so existing tests on lateral alerts stand."""
        alert = _make_alert(src_ip="192.168.2.50")
        alert = alert.model_copy(update={"dest_ip": "192.168.2.100"})
        assert _select_external_ip(alert) == "192.168.2.50"

    def test_both_public_falls_back_to_src(self) -> None:
        """Unusual (no LAN touch) but seen on some captures — keep
        src_ip as the defensive default."""
        alert = _make_alert(src_ip="203.0.113.5")
        alert = alert.model_copy(update={"dest_ip": "198.51.100.9"})
        assert _select_external_ip(alert) == "203.0.113.5"


class TestBuildFlowKey:
    """Direction-aware 5-tuple extraction from a Suricata alert."""

    def test_pc_initiates_returns_initiator_flow(self) -> None:
        alert = SuricataAlert(
            timestamp=datetime(2026, 4, 23, 9, 0, tzinfo=timezone.utc),
            src_ip="192.168.2.100",
            src_port=55555,
            dest_ip="162.159.207.0",
            dest_port=443,
            proto="TCP",
            alert_signature="x",
            alert_signature_id=1,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        flow = build_flow_key(alert)

        assert flow.pc_is_initiator is True
        assert flow.local_ip == "192.168.2.100"
        assert flow.local_port == 55555
        assert flow.remote_ip == "162.159.207.0"
        assert flow.remote_port == 443
        assert flow.proto == "TCP"

    def test_attacker_towards_pc_returns_receiver_flow(self) -> None:
        alert = SuricataAlert(
            timestamp=datetime(2026, 4, 23, 9, 0, tzinfo=timezone.utc),
            src_ip="203.0.113.5",
            src_port=40000,
            dest_ip="192.168.2.100",
            dest_port=22,
            proto="TCP",
            alert_signature="SSH brute force",
            alert_signature_id=2,
            alert_severity=SuricataAlertSeverity.HIGH,
        )
        flow = build_flow_key(alert)

        assert flow.pc_is_initiator is False
        assert flow.local_ip == "192.168.2.100"
        assert flow.local_port == 22
        assert flow.remote_ip == "203.0.113.5"
        assert flow.remote_port == 40000

    def test_both_local_keeps_src_as_local(self) -> None:
        """LAN-to-LAN alert: keep the pre-fix default so legacy tests
        that rely on ``src_ip`` continue to work."""
        alert = SuricataAlert(
            timestamp=datetime(2026, 4, 23, 9, 0, tzinfo=timezone.utc),
            src_ip="192.168.2.50",
            src_port=44444,
            dest_ip="192.168.2.100",
            dest_port=445,
            proto="TCP",
            alert_signature="SMB scan",
            alert_signature_id=3,
            alert_severity=SuricataAlertSeverity.MEDIUM,
        )
        flow = build_flow_key(alert)

        assert flow.pc_is_initiator is False
        assert flow.local_ip == "192.168.2.50"
        assert flow.remote_ip == "192.168.2.100"


class TestConnMatchesFlow:
    """Strict 5-tuple matching for psutil.net_connections sockets."""

    @staticmethod
    def _conn(
        laddr_port: int,
        raddr_ip: str = "",
        raddr_port: int = 0,
    ) -> MagicMock:
        """Build a mock psutil ``sconn`` with just the fields the matcher reads."""
        c = MagicMock()
        c.laddr = MagicMock(port=laddr_port, ip="0.0.0.0")
        if raddr_ip:
            c.raddr = MagicMock(ip=raddr_ip, port=raddr_port)
        else:
            c.raddr = None
        return c

    def _outbound_flow(self) -> FlowKey:
        return FlowKey(
            local_ip="192.168.2.100",
            local_port=55555,
            remote_ip="162.159.207.0",
            remote_port=443,
            proto="TCP",
            pc_is_initiator=True,
        )

    def _inbound_flow(self) -> FlowKey:
        return FlowKey(
            local_ip="192.168.2.100",
            local_port=22,
            remote_ip="203.0.113.5",
            remote_port=40000,
            proto="TCP",
            pc_is_initiator=False,
        )

    def test_outbound_exact_match(self) -> None:
        conn = self._conn(55555, "162.159.207.0", 443)
        assert _conn_matches_flow(conn, self._outbound_flow()) is True

    def test_outbound_wrong_remote_port_rejected(self) -> None:
        """Same remote IP but different remote port → different flow,
        must not attribute (this is the disambiguation the 5-tuple
        gives us over the old raddr-only match)."""
        conn = self._conn(55555, "162.159.207.0", 8080)
        assert _conn_matches_flow(conn, self._outbound_flow()) is False

    def test_outbound_wrong_local_port_rejected(self) -> None:
        conn = self._conn(55444, "162.159.207.0", 443)
        assert _conn_matches_flow(conn, self._outbound_flow()) is False

    def test_inbound_listener_matches_by_local_port_only(self) -> None:
        """LISTEN / UDP-without-raddr + PC receiver → match listeners."""
        conn = self._conn(22)  # no raddr
        assert _conn_matches_flow(conn, self._inbound_flow()) is True

    def test_outbound_without_raddr_rejected(self) -> None:
        """PC initiator + no raddr → not a match (outbound sockets with
        no remote state are usually unrelated half-open sockets)."""
        conn = self._conn(55555)
        assert _conn_matches_flow(conn, self._outbound_flow()) is False

    def test_inbound_established_socket_matches(self) -> None:
        conn = self._conn(22, "203.0.113.5", 40000)
        assert _conn_matches_flow(conn, self._inbound_flow()) is True


class TestGetProcessesByFlow:
    """Integration: analyzer picks the right PID via 5-tuple match."""

    @pytest.mark.asyncio
    async def test_outbound_flow_picks_only_the_matching_socket(self) -> None:
        """Two concurrent flows to the same remote, different local
        ports → only the one with the exact local_port matches."""
        analyzer = ForensicAnalyzer({})

        match = MagicMock(pid=1111)
        match.laddr = MagicMock(port=55555, ip="0.0.0.0")
        match.raddr = MagicMock(ip="162.159.207.0", port=443)

        other = MagicMock(pid=2222)
        other.laddr = MagicMock(port=55444, ip="0.0.0.0")
        other.raddr = MagicMock(ip="162.159.207.0", port=443)

        with patch("wardsoar.pc.forensics.psutil.net_connections", return_value=[match, other]):
            with patch("wardsoar.pc.forensics.psutil.Process") as mock_proc:
                mock_proc.side_effect = lambda pid: MagicMock(
                    name=lambda: "chrome.exe",
                    exe=lambda: "C:/chrome.exe",
                    cmdline=lambda: ["chrome.exe"],
                )
                flow = FlowKey(
                    local_ip="192.168.2.100",
                    local_port=55555,
                    remote_ip="162.159.207.0",
                    remote_port=443,
                    proto="TCP",
                    pc_is_initiator=True,
                )
                processes = await analyzer.get_processes_by_flow(flow)

        pids = [p["pid"] for p in processes]
        assert pids == [1111]

    @pytest.mark.asyncio
    async def test_inbound_flow_catches_listener_even_without_raddr(self) -> None:
        """PC-receiver + the accepted socket has already gone → fall
        back on the listener on local_port."""
        analyzer = ForensicAnalyzer({})

        listener = MagicMock(pid=4321)
        listener.laddr = MagicMock(port=22, ip="0.0.0.0")
        listener.raddr = None

        with patch("wardsoar.pc.forensics.psutil.net_connections", return_value=[listener]):
            with patch("wardsoar.pc.forensics.psutil.Process") as mock_proc:
                mock_proc.side_effect = lambda pid: MagicMock(
                    name=lambda: "sshd.exe",
                    exe=lambda: "C:/sshd.exe",
                    cmdline=lambda: ["sshd.exe"],
                )
                flow = FlowKey(
                    local_ip="192.168.2.100",
                    local_port=22,
                    remote_ip="203.0.113.5",
                    remote_port=40000,
                    proto="TCP",
                    pc_is_initiator=False,
                )
                processes = await analyzer.get_processes_by_flow(flow)

        assert [p["pid"] for p in processes] == [4321]

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self) -> None:
        analyzer = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil.net_connections", return_value=[]):
            flow = FlowKey(
                local_ip="192.168.2.100",
                local_port=55555,
                remote_ip="1.2.3.4",
                remote_port=443,
                proto="TCP",
                pc_is_initiator=True,
            )
            assert await analyzer.get_processes_by_flow(flow) == []


class TestAnalyzeRoutesRemoteIp:
    """Regression: analyze() must correlate on the *external* side.

    Before the fix, ``get_processes_by_remote_ip`` received
    ``alert.src_ip`` even when that was the LAN IP — psutil then found
    zero matches because ``conn.raddr`` is always the remote peer. The
    test below would have failed silently (empty suspect_processes)
    with the old code.
    """

    @pytest.mark.asyncio
    async def test_lan_src_alert_uses_dest_ip_for_correlation(self) -> None:
        analyzer = ForensicAnalyzer({})
        alert = _make_alert(src_ip="192.168.2.100")
        alert = alert.model_copy(update={"dest_ip": "162.159.207.0"})

        seen: list[str] = []

        async def fake_lookup(ip: str) -> list[dict[str, object]]:
            seen.append(ip)
            return []

        # Patch the lookup and disable the other checks to keep the
        # test focused on the routing decision.
        analyzer.get_processes_by_remote_ip = fake_lookup  # type: ignore[method-assign]
        analyzer.query_sysmon_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        analyzer.query_windows_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        analyzer.check_registry_persistence = AsyncMock(return_value=[])  # type: ignore[method-assign]
        analyzer.find_suspicious_files = AsyncMock(return_value=[])  # type: ignore[method-assign]

        await analyzer.analyze(alert)

        assert seen == ["162.159.207.0"]


class TestForensicAnalyzerInit:
    """Tests for ForensicAnalyzer initialization."""

    def test_construction_defaults(self) -> None:
        fa = ForensicAnalyzer({})
        assert fa._correlation_window == 300
        assert "Sysmon" in fa._sysmon_channel

    def test_custom_config(self) -> None:
        fa = ForensicAnalyzer(
            {
                "correlation_window": 600,
                "sysmon_channel": "Custom/Channel",
            }
        )
        assert fa._correlation_window == 600
        assert fa._sysmon_channel == "Custom/Channel"


# ---------------------------------------------------------------------------
# get_processes_by_remote_ip tests
# ---------------------------------------------------------------------------


class TestGetProcessesByRemoteIp:
    """Tests for ForensicAnalyzer.get_processes_by_remote_ip."""

    @pytest.mark.asyncio
    async def test_returns_matching_processes(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil") as mock_psutil:
            # Mock a network connection to the target IP
            mock_conn = MagicMock()
            mock_conn.raddr = MagicMock(ip="10.0.0.1")
            mock_conn.laddr = MagicMock(ip="192.168.1.100")
            mock_conn.pid = 1234
            mock_psutil.net_connections.return_value = [mock_conn]

            # Mock process info
            mock_proc = MagicMock()
            mock_proc.pid = 1234
            mock_proc.name.return_value = "suspicious.exe"
            mock_proc.exe.return_value = "C:\\Temp\\suspicious.exe"
            mock_proc.cmdline.return_value = ["suspicious.exe", "--flag"]
            mock_psutil.Process.return_value = mock_proc

            result = await fa.get_processes_by_remote_ip("10.0.0.1")
            assert len(result) == 1
            assert result[0]["pid"] == 1234
            assert result[0]["name"] == "suspicious.exe"

    @pytest.mark.asyncio
    async def test_no_matching_connections(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = []
            result = await fa.get_processes_by_remote_ip("10.0.0.1")
            assert result == []

    @pytest.mark.asyncio
    async def test_error_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil") as mock_psutil:
            mock_psutil.net_connections.side_effect = PermissionError("Denied")
            result = await fa.get_processes_by_remote_ip("10.0.0.1")
            assert result == []


# ---------------------------------------------------------------------------
# build_process_tree tests
# ---------------------------------------------------------------------------


class TestBuildProcessTree:
    """Tests for ForensicAnalyzer.build_process_tree."""

    @pytest.mark.asyncio
    async def test_returns_process_tree(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil") as mock_psutil:
            mock_proc = MagicMock()
            mock_proc.pid = 1234
            mock_proc.name.return_value = "child.exe"
            mock_proc.exe.return_value = "C:\\child.exe"
            mock_proc.ppid.return_value = 500

            mock_parent = MagicMock()
            mock_parent.pid = 500
            mock_parent.name.return_value = "parent.exe"
            mock_parent.exe.return_value = "C:\\parent.exe"
            mock_parent.ppid.return_value = 1

            mock_proc.parents.return_value = [mock_parent]
            mock_psutil.Process.return_value = mock_proc

            result = await fa.build_process_tree(1234)
            assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_nonexistent_pid_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.psutil") as mock_psutil:
            mock_psutil.Process.side_effect = psutil_no_such_process()
            result = await fa.build_process_tree(99999)
            assert result == []


def psutil_no_such_process() -> Exception:
    """Create a psutil.NoSuchProcess-like error for mocking."""
    import psutil

    return psutil.NoSuchProcess(99999)


# ---------------------------------------------------------------------------
# query_sysmon_events tests
# ---------------------------------------------------------------------------


class TestQuerySysmonEvents:
    """Tests for ForensicAnalyzer.query_sysmon_events."""

    @pytest.mark.asyncio
    async def test_returns_parsed_events(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[]"  # No events
            mock_sub.run.return_value = mock_result

            result = await fa.query_sysmon_events(_make_alert())
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_error_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_sub.run.side_effect = FileNotFoundError("powershell not found")
            result = await fa.query_sysmon_events(_make_alert())
            assert result == []

    @pytest.mark.asyncio
    async def test_stdout_none_returns_empty(self) -> None:
        """Regression for 2026-04-20 15:12 pipeline errors
        ``AttributeError: 'NoneType' object has no attribute 'strip'``.

        A crashed PowerShell child can deliver ``stdout=None`` even
        under ``capture_output=True, text=True``. The old code called
        ``result.stdout.strip()`` directly and let the AttributeError
        propagate out of the whole analysis pipeline, killing the
        alert. The guarded version returns an empty event list
        instead — fail-safe, consistent with the FileNotFoundError
        path above.
        """
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = None  # <-- the pathological case
            mock_sub.run.return_value = mock_result

            result = await fa.query_sysmon_events(_make_alert())
            assert result == []


# ---------------------------------------------------------------------------
# check_registry_persistence tests
# ---------------------------------------------------------------------------


class TestCheckRegistryPersistence:
    """Tests for ForensicAnalyzer.check_registry_persistence."""

    @pytest.mark.asyncio
    async def test_returns_entries(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_sub.run.return_value = mock_result

            result = await fa.check_registry_persistence()
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_error_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_sub.run.side_effect = OSError("Failed")
            result = await fa.check_registry_persistence()
            assert result == []


# ---------------------------------------------------------------------------
# find_suspicious_files tests
# ---------------------------------------------------------------------------


class TestFindSuspiciousFiles:
    """Tests for ForensicAnalyzer.find_suspicious_files."""

    @pytest.mark.asyncio
    async def test_returns_files(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.Path") as mock_path_cls:
            mock_dir = MagicMock()
            mock_dir.exists.return_value = False
            mock_path_cls.return_value = mock_dir
            # No directories exist in test env
            result = await fa.find_suspicious_files(_make_alert())
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_error_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.os") as mock_os:
            mock_os.environ = {}
            mock_os.path.expanduser.side_effect = OSError("fail")
            result = await fa.find_suspicious_files(_make_alert())
            assert isinstance(result, list)


# ---------------------------------------------------------------------------
# find_suspicious_files FILTER tests — freshness, size, extension, exclusion
# ---------------------------------------------------------------------------


class TestFindSuspiciousFilesFilters:
    """Verify each filter rejects the right files before they reach VT/Defender.

    Shared approach: patch SUSPICIOUS_DIRECTORIES to a single real directory
    populated with files via tmp_path. The alert timestamp is anchored to
    `datetime.now(UTC)` so freshness tests line up with real file mtimes.
    """

    def _alert_now(self) -> SuricataAlert:
        return SuricataAlert(
            timestamp=datetime.now(timezone.utc),
            src_ip="10.0.0.1",
            src_port=12345,
            dest_ip="192.168.1.100",
            dest_port=443,
            proto="TCP",
            alert_signature="Test",
            alert_signature_id=1000,
            alert_severity=SuricataAlertSeverity.HIGH,
        )

    def _write_file(self, directory: Path, name: str, size: int = 2048) -> Path:
        """Create a file with a given size."""
        path = directory / name
        path.write_bytes(b"\x00" * size)
        return path

    @pytest.mark.asyncio
    async def test_filters_by_extension(self, tmp_path: Path) -> None:
        """Only files with whitelisted extensions are kept."""
        self._write_file(tmp_path, "malware.exe")
        self._write_file(tmp_path, "readme.txt")  # not executable
        self._write_file(tmp_path, "photo.jpg")  # not executable
        self._write_file(tmp_path, "script.ps1")

        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES", [str(tmp_path)]):
            result = await fa.find_suspicious_files(self._alert_now())

        names = {Path(f["path"]).name for f in result}
        assert "malware.exe" in names
        assert "script.ps1" in names
        assert "readme.txt" not in names
        assert "photo.jpg" not in names

    @pytest.mark.asyncio
    async def test_filters_by_size_min(self, tmp_path: Path) -> None:
        """Files smaller than min_size_bytes are skipped."""
        self._write_file(tmp_path, "too_small.exe", size=100)  # < 1 KB
        self._write_file(tmp_path, "ok.exe", size=2048)

        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES", [str(tmp_path)]):
            result = await fa.find_suspicious_files(self._alert_now())

        names = {Path(f["path"]).name for f in result}
        assert "too_small.exe" not in names
        assert "ok.exe" in names

    @pytest.mark.asyncio
    async def test_filters_by_size_max(self, tmp_path: Path) -> None:
        """Files above max_size_bytes are skipped (size cap override in config)."""
        self._write_file(tmp_path, "small.exe", size=2048)
        self._write_file(tmp_path, "big.exe", size=100_000)

        fa = ForensicAnalyzer({"suspicious_files": {"max_size_bytes": 50_000}})
        with patch("wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES", [str(tmp_path)]):
            result = await fa.find_suspicious_files(self._alert_now())

        names = {Path(f["path"]).name for f in result}
        assert "small.exe" in names
        assert "big.exe" not in names

    @pytest.mark.asyncio
    async def test_filters_by_freshness_too_old(self, tmp_path: Path) -> None:
        """Files modified long before the alert are skipped."""
        import os as _os

        old_file = self._write_file(tmp_path, "old.exe")
        # Set mtime 1 hour in the past — far outside freshness window
        past = time.time() - 3600
        _os.utime(old_file, (past, past))

        recent = self._write_file(tmp_path, "recent.exe")

        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES", [str(tmp_path)]):
            result = await fa.find_suspicious_files(self._alert_now())

        names = {Path(f["path"]).name for f in result}
        assert Path(old_file).name not in names
        assert Path(recent).name in names

    @pytest.mark.asyncio
    async def test_filters_by_app_exclusion(self, tmp_path: Path) -> None:
        """Files whose path matches an APP_EXCLUSIONS fragment are skipped."""
        # Create the Chrome-like directory structure the exclusions target.
        chrome_dir = tmp_path / "Google" / "Chrome" / "User Data"
        chrome_dir.mkdir(parents=True)
        chrome_binary = self._write_file(chrome_dir, "chrome_helper.exe")

        normal = self._write_file(tmp_path, "malware.exe")

        fa = ForensicAnalyzer({})
        with patch(
            "wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES",
            [str(tmp_path), str(chrome_dir)],
        ):
            result = await fa.find_suspicious_files(self._alert_now())

        paths = {f["path"] for f in result}
        assert str(normal) in paths
        assert str(chrome_binary) not in paths

    @pytest.mark.asyncio
    async def test_config_override_extra_exclusions(self, tmp_path: Path) -> None:
        """Config-supplied fragments extend APP_EXCLUSIONS."""
        self._write_file(tmp_path, "custom_app_helper.exe")
        self._write_file(tmp_path, "real.exe")

        fa = ForensicAnalyzer({"suspicious_files": {"excluded_path_fragments": ["custom_app"]}})
        with patch("wardsoar.pc.forensics.SUSPICIOUS_DIRECTORIES", [str(tmp_path)]):
            result = await fa.find_suspicious_files(self._alert_now())

        names = {Path(f["path"]).name for f in result}
        assert "custom_app_helper.exe" not in names
        assert "real.exe" in names


# ---------------------------------------------------------------------------
# analyze (integration) tests
# ---------------------------------------------------------------------------


class TestAnalyze:
    """Tests for ForensicAnalyzer.analyze (full pipeline)."""

    @pytest.mark.asyncio
    async def test_returns_forensic_result(self) -> None:
        fa = ForensicAnalyzer({})
        fa.get_processes_by_remote_ip = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.build_process_tree = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.query_sysmon_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.query_windows_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.check_registry_persistence = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.find_suspicious_files = AsyncMock(return_value=[])  # type: ignore[method-assign]

        result = await fa.analyze(_make_alert())
        assert isinstance(result, ForensicResult)

    @pytest.mark.asyncio
    async def test_partial_failure_still_returns_result(self) -> None:
        """If one forensic check fails, others should still work."""
        fa = ForensicAnalyzer({})
        fa.get_processes_by_remote_ip = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("Failed")
        )
        fa.build_process_tree = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.query_sysmon_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.query_windows_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.check_registry_persistence = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.find_suspicious_files = AsyncMock(return_value=[])  # type: ignore[method-assign]

        result = await fa.analyze(_make_alert())
        assert isinstance(result, ForensicResult)
        assert result.suspect_processes == []

    @pytest.mark.asyncio
    async def test_analyze_with_processes_builds_tree(self) -> None:
        """When suspect processes are found, process trees are built."""
        fa = ForensicAnalyzer({})
        fa.get_processes_by_remote_ip = AsyncMock(  # type: ignore[method-assign]
            return_value=[{"pid": 1234, "name": "test.exe", "exe": "C:\\test.exe", "cmdline": []}]
        )
        fa.build_process_tree = AsyncMock(  # type: ignore[method-assign]
            return_value=[{"pid": 1234, "name": "test.exe", "exe": "C:\\test.exe"}]
        )
        fa.query_sysmon_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.query_windows_events = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.check_registry_persistence = AsyncMock(return_value=[])  # type: ignore[method-assign]
        fa.find_suspicious_files = AsyncMock(return_value=[])  # type: ignore[method-assign]

        result = await fa.analyze(_make_alert())
        assert len(result.process_tree) == 1
        assert result.process_tree[0]["pid"] == 1234


# ---------------------------------------------------------------------------
# query_windows_events tests
# ---------------------------------------------------------------------------


class TestQueryWindowsEvents:
    """Tests for ForensicAnalyzer.query_windows_events."""

    @pytest.mark.asyncio
    async def test_returns_events(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = '[{"Id": 4624, "TimeCreated": "2026-03-15T10:00:00"}]'
            mock_sub.run.return_value = mock_result

            result = await fa.query_windows_events(_make_alert())
            assert len(result) == 1
            assert result[0]["Id"] == 4624

    @pytest.mark.asyncio
    async def test_empty_output_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_sub.run.return_value = mock_result

            result = await fa.query_windows_events(_make_alert())
            assert result == []

    @pytest.mark.asyncio
    async def test_error_returns_empty(self) -> None:
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_sub.run.side_effect = FileNotFoundError()
            result = await fa.query_windows_events(_make_alert())
            assert result == []

    @pytest.mark.asyncio
    async def test_single_event_dict(self) -> None:
        """PowerShell returns a dict instead of list for single event."""
        fa = ForensicAnalyzer({})
        with patch("wardsoar.pc.forensics.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = '{"Id": 4688, "TimeCreated": "2026-03-15T10:00:00"}'
            mock_sub.run.return_value = mock_result

            result = await fa.query_windows_events(_make_alert())
            assert len(result) == 1


# ---------------------------------------------------------------------------
# _parse_sysmon_json tests
# ---------------------------------------------------------------------------


class TestParseSysmonJson:
    """Tests for ForensicAnalyzer._parse_sysmon_json."""

    def test_parse_valid_json(self) -> None:
        fa = ForensicAnalyzer({})
        json_str = '[{"Id": 3, "TimeCreated": "2026-03-15T10:00:00", "Message": "Network"}]'
        result = fa._parse_sysmon_json(json_str)
        assert len(result) == 1
        assert result[0].event_id == 3

    def test_parse_single_dict(self) -> None:
        fa = ForensicAnalyzer({})
        json_str = '{"Id": 1, "TimeCreated": "2026-03-15T10:00:00", "Message": "Process"}'
        result = fa._parse_sysmon_json(json_str)
        assert len(result) == 1

    def test_parse_invalid_json(self) -> None:
        fa = ForensicAnalyzer({})
        result = fa._parse_sysmon_json("{bad json")
        assert result == []

    def test_parse_entry_with_bad_fields(self) -> None:
        fa = ForensicAnalyzer({})
        json_str = '[{"bad": "data"}]'
        result = fa._parse_sysmon_json(json_str)
        assert len(result) == 1  # Still creates event with defaults
