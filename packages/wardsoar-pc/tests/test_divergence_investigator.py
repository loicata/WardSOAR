"""Tests for :class:`DivergenceInvestigator` — CRITICAL module.

Each of the 6 checks is exercised in isolation (so we can verify
the fail-safe contract — a check that errors must not crash the
others), then in combination via :meth:`investigate` to verify the
explanation precedence (loopback > vpn > lan_only >
suricata_local_dead > unexplained).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

if sys.platform != "win32":  # pragma: no cover — non-Windows skip
    pytest.skip("divergence_investigator is Windows-only", allow_module_level=True)

import psutil  # noqa: E402

from wardsoar.core.models import DivergenceFindings, SourceCorroboration  # noqa: E402
from wardsoar.pc.divergence_investigator import DivergenceInvestigator  # noqa: E402


def _alert(src: str = "1.2.3.4", dst: str = "5.6.7.8") -> dict[str, Any]:
    return {"event_type": "alert", "src_ip": src, "dest_ip": dst}


# ---------------------------------------------------------------------------
# investigate() — non-divergent corroboration
# ---------------------------------------------------------------------------


class TestNonDivergentCorroboration:
    """When the corroboration is not DIVERGENCE_*, investigate
    returns an empty findings (no checks run)."""

    @pytest.mark.asyncio
    async def test_match_confirmed_returns_empty_findings(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.MATCH_CONFIRMED)
        assert findings == DivergenceFindings()

    @pytest.mark.asyncio
    async def test_single_source_returns_empty_findings(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.SINGLE_SOURCE)
        assert findings == DivergenceFindings()


# ---------------------------------------------------------------------------
# Loopback check
# ---------------------------------------------------------------------------


class TestLoopback:
    @pytest.mark.asyncio
    async def test_127_loopback_is_detected(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("127.0.0.1", "127.0.0.1"), SourceCorroboration.DIVERGENCE_B
        )
        assert findings.is_loopback is True
        assert findings.is_explained is True
        assert findings.explanation == "loopback_traffic"

    @pytest.mark.asyncio
    async def test_ipv6_loopback_is_detected(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert("::1", "::1"), SourceCorroboration.DIVERGENCE_B)
        assert findings.is_loopback is True

    @pytest.mark.asyncio
    async def test_external_ip_is_not_loopback(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_loopback is False

    @pytest.mark.asyncio
    async def test_invalid_ip_returns_false(self) -> None:
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("not-an-ip", "5.6.7.8"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_loopback is False


# ---------------------------------------------------------------------------
# VPN check
# ---------------------------------------------------------------------------


class TestVpn:
    @pytest.mark.asyncio
    async def test_detects_tun_interface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_stats = {
            "Ethernet": MagicMock(isup=True),
            "tun0": MagicMock(isup=True),
        }
        monkeypatch.setattr(
            "wardsoar.pc.divergence_investigator.psutil.net_if_stats",
            lambda: fake_stats,
        )
        inv = DivergenceInvestigator()
        # Pick an unrelated event so loopback / lan_only don't pre-empt.
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_vpn is True
        assert findings.explanation == "vpn_traffic"

    @pytest.mark.asyncio
    async def test_ignores_inactive_vpn_interface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_stats = {
            "Ethernet": MagicMock(isup=True),
            "tap0": MagicMock(isup=False),  # not up
        }
        monkeypatch.setattr(
            "wardsoar.pc.divergence_investigator.psutil.net_if_stats",
            lambda: fake_stats,
        )
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_vpn is False

    @pytest.mark.asyncio
    async def test_psutil_failure_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raising_stats() -> Any:
            raise psutil.Error("test")

        monkeypatch.setattr(
            "wardsoar.pc.divergence_investigator.psutil.net_if_stats", raising_stats
        )
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_vpn is False


# ---------------------------------------------------------------------------
# LAN-only check
# ---------------------------------------------------------------------------


class TestLanOnly:
    @pytest.mark.asyncio
    async def test_two_rfc1918_addresses_is_lan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Mock VPN check off so it doesn't pre-empt explanation.
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("192.168.2.10", "10.0.0.5"), SourceCorroboration.DIVERGENCE_B
        )
        assert findings.is_lan_only is True
        assert findings.explanation == "lan_only_traffic"

    @pytest.mark.asyncio
    async def test_one_public_ip_breaks_lan_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("192.168.2.10", "8.8.8.8"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.is_lan_only is False

    @pytest.mark.asyncio
    async def test_custom_local_subnet_cidr_is_lan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Operator-configured CIDRs (e.g. for VPN-internal subnets
        like 100.64.0.0/10 with Tailscale) qualify as LAN."""
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        inv = DivergenceInvestigator(local_subnets_cidr=["100.64.0.0/10"])
        findings = await inv.investigate(
            _alert("100.64.0.5", "100.64.0.10"), SourceCorroboration.DIVERGENCE_B
        )
        assert findings.is_lan_only is True

    @pytest.mark.asyncio
    async def test_invalid_cidr_in_init_logged_not_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Should NOT raise.
        DivergenceInvestigator(local_subnets_cidr=["not-a-cidr"])
        assert any("ignoring invalid local subnet" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Suricata-alive check
# ---------------------------------------------------------------------------


class TestSuricataAlive:
    @pytest.mark.asyncio
    async def test_no_process_returns_unknown(self) -> None:
        inv = DivergenceInvestigator(suricata_process=None)
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.suricata_local_state == "unknown"

    @pytest.mark.asyncio
    async def test_running_process_reports_running(self) -> None:
        proc = MagicMock()
        proc.is_running.return_value = True
        inv = DivergenceInvestigator(suricata_process=proc)
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.suricata_local_state == "running"

    @pytest.mark.asyncio
    async def test_dead_process_explains_divergence_and_bumps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Per Q3: a dead local Suricata explains the divergence
        (is_explained=True) AND triggers verdict bumping (the
        bumper looks at explanation==suricata_local_dead).

        We mock other checks to ensure they don't pre-empt this
        explanation."""
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        proc = MagicMock()
        proc.is_running.return_value = False
        inv = DivergenceInvestigator(suricata_process=proc)
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"),  # public IPs → not LAN, not loopback
            SourceCorroboration.DIVERGENCE_A,
        )
        assert findings.suricata_local_state == "dead"
        assert findings.is_explained is True
        assert findings.explanation == "suricata_local_dead"


# ---------------------------------------------------------------------------
# Sysmon check
# ---------------------------------------------------------------------------


class TestSysmon:
    @pytest.mark.asyncio
    async def test_powershell_missing_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.win_paths.POWERSHELL", "")
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.sysmon_correlation == []
        assert "sysmon" not in findings.checks_run

    @pytest.mark.asyncio
    async def test_parses_sysmon_array_response(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.win_paths.POWERSHELL", str(ps))
        sample_events = [
            {"Id": 3, "Time": "2026-04-26T10:00:00", "Message": "Network connect to 1.2.3.4"},
            {"Id": 1, "Time": "2026-04-26T10:00:01", "Message": "Process create powershell.exe"},
        ]

        def fake_run(*_a: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(sample_events),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.sysmon_correlation == sample_events
        assert "sysmon" in findings.checks_run

    @pytest.mark.asyncio
    async def test_parses_sysmon_single_event_response(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PowerShell ConvertTo-Json emits a single object (not an
        array) when only one event matches. The investigator
        normalises this to a list."""
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.win_paths.POWERSHELL", str(ps))
        single_event = {"Id": 3, "Time": "2026-04-26T10:00:00", "Message": "Network connect"}

        def fake_run(*_a: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(single_event),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.sysmon_correlation == [single_event]

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        ps = tmp_path / "powershell.exe"
        ps.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.win_paths.POWERSHELL", str(ps))

        def raising_run(*_a: Any, **_kw: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd=["x"], timeout=5)

        monkeypatch.setattr(subprocess, "run", raising_run)
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.sysmon_correlation == []


# ---------------------------------------------------------------------------
# Snapshot check
# ---------------------------------------------------------------------------


class TestSnapshot:
    @pytest.mark.asyncio
    async def test_no_buffer_returns_empty_dict(self) -> None:
        inv = DivergenceInvestigator(netconns_buffer=None)
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        assert findings.snapshot_summary == {}

    @pytest.mark.asyncio
    async def test_buffer_count_surfaced(self) -> None:
        buffer = MagicMock()
        buffer.snapshot_count = MagicMock(return_value=42)
        inv = DivergenceInvestigator(netconns_buffer=buffer)
        findings = await inv.investigate(
            _alert("1.2.3.4", "5.6.7.8"), SourceCorroboration.DIVERGENCE_A
        )
        assert findings.snapshot_summary["snapshots_in_buffer"] == 42
        assert findings.snapshot_summary["src_ip"] == "1.2.3.4"
        assert findings.snapshot_summary["dest_ip"] == "5.6.7.8"


# ---------------------------------------------------------------------------
# Explanation precedence (Q2 doctrine)
# ---------------------------------------------------------------------------


class TestExplanationPrecedence:
    """The explanation token follows a fixed priority: loopback >
    vpn > lan_only > suricata_local_dead > unexplained.
    """

    @pytest.mark.asyncio
    async def test_loopback_wins_over_vpn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Both checks return True; loopback should be reported.
        fake_stats = {"tun0": MagicMock(isup=True)}
        monkeypatch.setattr(
            "wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: fake_stats
        )
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("127.0.0.1", "127.0.0.1"), SourceCorroboration.DIVERGENCE_B
        )
        assert findings.explanation == "loopback_traffic"
        assert findings.is_loopback is True
        assert findings.is_vpn is True  # both flags true, but loopback won the explanation

    @pytest.mark.asyncio
    async def test_vpn_wins_over_lan_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_stats = {"tun0": MagicMock(isup=True)}
        monkeypatch.setattr(
            "wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: fake_stats
        )
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("192.168.2.10", "192.168.2.20"), SourceCorroboration.DIVERGENCE_B
        )
        assert findings.is_vpn is True
        assert findings.is_lan_only is True
        assert findings.explanation == "vpn_traffic"

    @pytest.mark.asyncio
    async def test_unexplained_when_no_check_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        inv = DivergenceInvestigator()
        findings = await inv.investigate(
            _alert("8.8.8.8", "1.1.1.1"),  # public, no VPN, suricata=None=unknown
            SourceCorroboration.DIVERGENCE_A,
        )
        assert findings.is_explained is False
        assert findings.explanation == "unexplained"


# ---------------------------------------------------------------------------
# checks_run list
# ---------------------------------------------------------------------------


class TestChecksRun:
    @pytest.mark.asyncio
    async def test_always_includes_five_checks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("wardsoar.pc.divergence_investigator.psutil.net_if_stats", lambda: {})
        inv = DivergenceInvestigator()
        findings = await inv.investigate(_alert(), SourceCorroboration.DIVERGENCE_A)
        # snapshot, suricata_alive, loopback, vpn, lan_only — sysmon
        # is conditional on returning events.
        assert "snapshot" in findings.checks_run
        assert "suricata_alive" in findings.checks_run
        assert "loopback" in findings.checks_run
        assert "vpn" in findings.checks_run
        assert "lan_only" in findings.checks_run
