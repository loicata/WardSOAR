"""Tests for the Sysmon Event 3 flow attribution (level 3)."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from src.forensics import FlowKey
from src.sysmon_events import (
    SysmonFlowHit,
    _run_sysmon_event3_query,
    _try_match,
    find_pids_for_flow,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _outbound_flow() -> FlowKey:
    return FlowKey(
        local_ip="192.168.2.100",
        local_port=55555,
        remote_ip="162.159.207.0",
        remote_port=443,
        proto="TCP",
        pc_is_initiator=True,
    )


def _inbound_flow() -> FlowKey:
    return FlowKey(
        local_ip="192.168.2.100",
        local_port=22,
        remote_ip="203.0.113.5",
        remote_port=40000,
        proto="TCP",
        pc_is_initiator=False,
    )


def _event(
    initiated: bool,
    pid: int = 4242,
    image: str = "C:/Teams.exe",
    source_ip: str = "",
    source_port: int = 0,
    dest_ip: str = "",
    dest_port: int = 0,
    guid: str = "{abc-123}",
) -> dict[str, object]:
    return {
        "ProcessId": str(pid),
        "Image": image,
        "ProcessGuid": guid,
        "Initiated": "true" if initiated else "false",
        "SourceIp": source_ip,
        "SourcePort": str(source_port),
        "DestinationIp": dest_ip,
        "DestinationPort": str(dest_port),
        "TimeCreated": "2026-04-23T09:00:00.123+00:00",
    }


@pytest.fixture
def fake_powershell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``win_paths.POWERSHELL`` at a valid file so the guard passes."""
    ps = tmp_path / "powershell.exe"
    ps.write_bytes(b"")
    monkeypatch.setattr("src.sysmon_events.win_paths.POWERSHELL", str(ps))
    return ps


# ---------------------------------------------------------------------------
# _try_match()
# ---------------------------------------------------------------------------


class TestTryMatch:
    def test_initiated_outbound_event_matches_outbound_flow(self) -> None:
        event = _event(
            initiated=True,
            source_ip="192.168.2.100",
            source_port=55555,
            dest_ip="162.159.207.0",
            dest_port=443,
        )
        hit = _try_match(event, _outbound_flow())

        assert hit is not None
        assert hit.pid == 4242
        assert hit.image == "C:/Teams.exe"
        assert hit.initiated is True
        assert hit.local_port == 55555
        assert hit.remote_ip == "162.159.207.0"

    def test_non_initiated_event_matches_inbound_flow(self) -> None:
        event = _event(
            initiated=False,
            source_ip="203.0.113.5",
            source_port=40000,
            dest_ip="192.168.2.100",
            dest_port=22,
            pid=1234,
            image="C:/sshd.exe",
        )
        hit = _try_match(event, _inbound_flow())

        assert hit is not None
        assert hit.pid == 1234
        assert hit.initiated is False

    def test_wrong_local_port_rejected(self) -> None:
        event = _event(
            initiated=True,
            source_port=9999,
            dest_ip="162.159.207.0",
            dest_port=443,
        )
        assert _try_match(event, _outbound_flow()) is None

    def test_wrong_remote_port_rejected(self) -> None:
        event = _event(
            initiated=True,
            source_port=55555,
            dest_ip="162.159.207.0",
            dest_port=8080,
        )
        assert _try_match(event, _outbound_flow()) is None

    def test_missing_pid_returns_none(self) -> None:
        event = _event(initiated=True)
        event["ProcessId"] = "0"
        assert _try_match(event, _outbound_flow()) is None

    def test_unparseable_ports_return_none(self) -> None:
        event = _event(initiated=True)
        event["SourcePort"] = "not-a-number"
        assert _try_match(event, _outbound_flow()) is None


# ---------------------------------------------------------------------------
# _run_sysmon_event3_query()
# ---------------------------------------------------------------------------


class TestRunQuery:
    def test_powershell_missing_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.sysmon_events.win_paths.POWERSHELL", str(tmp_path / "ghost.exe"))
        result = _run_sysmon_event3_query(datetime.now(timezone.utc), 30)
        assert result == []

    def test_happy_path_parses_list(
        self, fake_powershell: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = json.dumps([_event(initiated=True), _event(initiated=False)])

        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _run_sysmon_event3_query(datetime.now(timezone.utc), 30)

        assert len(result) == 2
        assert all(isinstance(entry, dict) for entry in result)

    def test_single_event_dict_wrapped_in_list(
        self, fake_powershell: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = json.dumps(_event(initiated=True))

        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _run_sysmon_event3_query(datetime.now(timezone.utc), 30)

        assert len(result) == 1

    def test_timeout_returns_empty(
        self, fake_powershell: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["ps"], timeout=10)

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _run_sysmon_event3_query(datetime.now(timezone.utc), 30)
        assert result == []

    def test_invalid_json_returns_empty(
        self, fake_powershell: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _run_sysmon_event3_query(datetime.now(timezone.utc), 30)
        assert result == []


# ---------------------------------------------------------------------------
# find_pids_for_flow() — integration
# ---------------------------------------------------------------------------


class TestFindPidsForFlow:
    @pytest.mark.asyncio
    async def test_returns_hit_for_matching_outbound_event(self) -> None:
        event = _event(
            initiated=True,
            pid=9999,
            image="C:/Teams.exe",
            source_ip="192.168.2.100",
            source_port=55555,
            dest_ip="162.159.207.0",
            dest_port=443,
        )

        with patch(
            "src.sysmon_events._run_sysmon_event3_query",
            return_value=[event],
        ):
            hits = await find_pids_for_flow(
                _outbound_flow(), datetime(2026, 4, 23, 9, 0, tzinfo=timezone.utc)
            )

        assert len(hits) == 1
        assert hits[0].pid == 9999
        assert hits[0].image == "C:/Teams.exe"
        assert isinstance(hits[0], SysmonFlowHit)

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self) -> None:
        unrelated = _event(
            initiated=True,
            source_port=1111,
            dest_ip="1.2.3.4",
            dest_port=80,
        )
        with patch(
            "src.sysmon_events._run_sysmon_event3_query",
            return_value=[unrelated],
        ):
            hits = await find_pids_for_flow(
                _outbound_flow(), datetime(2026, 4, 23, 9, 0, tzinfo=timezone.utc)
            )
        assert hits == []

    @pytest.mark.asyncio
    async def test_naive_alert_time_is_coerced_to_utc(self) -> None:
        """Pipelines sometimes pass a naive ``datetime``. The query
        must not raise and must still return matching hits."""
        event = _event(
            initiated=True,
            source_port=55555,
            dest_ip="162.159.207.0",
            dest_port=443,
        )

        with patch(
            "src.sysmon_events._run_sysmon_event3_query",
            return_value=[event],
        ):
            hits = await find_pids_for_flow(_outbound_flow(), datetime(2026, 4, 23, 9, 0))

        assert len(hits) == 1
