"""Tests for the N-source flavour of :class:`DivergenceInvestigator`.

Exercises :meth:`investigate_n` and the helper
:meth:`_check_suricata_alive_per_source`. The legacy :meth:`investigate`
keeps its own test file (``test_divergence_investigator.py``); this
file proves the new entry point produces the same verdict-bumping
signals when fed a :class:`CorroborationStatus` carrying multiple
sources.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from wardsoar.core.corroboration import (
    CorroborationStatus,
    CorroborationVerdict,
)
from wardsoar.pc.divergence_investigator import DivergenceInvestigator


def _alert(src: str, dst: str, sig: int = 100) -> dict[str, Any]:
    return {
        "src_ip": src,
        "dest_ip": dst,
        "alert": {"signature_id": sig, "signature": "TEST"},
    }


def _process(running: bool) -> MagicMock:
    proc = MagicMock()
    proc.is_running = MagicMock(return_value=running)
    return proc


@pytest.mark.asyncio
class TestSuricataAlivePerSource:
    async def test_empty_processes_dict_returns_empty(self) -> None:
        inv = DivergenceInvestigator()
        states = await inv._check_suricata_alive_per_source()  # noqa: SLF001
        assert states == {}

    async def test_per_source_states_reported(self) -> None:
        inv = DivergenceInvestigator(
            processes_by_name={
                "local": _process(True),
                "pi": _process(False),
            },
        )
        states = await inv._check_suricata_alive_per_source()  # noqa: SLF001
        assert states == {"local": "running", "pi": "dead"}

    async def test_per_source_check_failure_falls_back_to_unknown(self) -> None:
        broken = MagicMock()
        broken.is_running = MagicMock(side_effect=RuntimeError("boom"))
        inv = DivergenceInvestigator(processes_by_name={"broken": broken})
        states = await inv._check_suricata_alive_per_source()  # noqa: SLF001
        assert states == {"broken": "unknown"}


@pytest.mark.asyncio
class TestInvestigateN:
    async def test_non_divergent_status_returns_empty_findings(self) -> None:
        inv = DivergenceInvestigator()
        status = CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_FULL,
            matching_sources=("a", "b"),
        )
        findings = await inv.investigate_n(_alert("1.1.1.1", "2.2.2.2"), status)
        assert findings.checks_run == []
        assert findings.is_explained is False

    async def test_pending_status_returns_empty_findings(self) -> None:
        inv = DivergenceInvestigator()
        status = CorroborationStatus(
            verdict=CorroborationVerdict.PENDING,
            matching_sources=("a",),
        )
        findings = await inv.investigate_n(_alert("1.1.1.1", "2.2.2.2"), status)
        assert findings.checks_run == []

    async def test_divergence_runs_full_battery(self) -> None:
        inv = DivergenceInvestigator()
        status = CorroborationStatus(
            verdict=CorroborationVerdict.DIVERGENCE,
            matching_sources=("a",),
            silent_sources=("b",),
        )
        findings = await inv.investigate_n(_alert("8.8.8.8", "1.1.1.1"), status)
        assert "snapshot" in findings.checks_run
        assert "suricata_alive" in findings.checks_run
        assert "loopback" in findings.checks_run
        assert "vpn" in findings.checks_run
        assert "lan_only" in findings.checks_run

    async def test_dead_source_explains_as_suricata_local_dead(self) -> None:
        inv = DivergenceInvestigator(
            processes_by_name={
                "local": _process(False),  # dead
                "pi": _process(True),
            },
        )
        status = CorroborationStatus(
            verdict=CorroborationVerdict.DIVERGENCE,
            matching_sources=("pi",),
            silent_sources=("local",),
        )
        findings = await inv.investigate_n(_alert("8.8.8.8", "1.1.1.1"), status)
        assert findings.explanation == "suricata_local_dead"
        assert findings.is_explained is True
        assert findings.suricata_states == {"local": "dead", "pi": "running"}

    async def test_loopback_explanation_takes_priority_over_dead_source(self) -> None:
        # When loopback is true, the explanation ladder picks it
        # before checking dead processes — same priority ordering
        # as the legacy investigate().
        inv = DivergenceInvestigator(
            processes_by_name={"local": _process(False)},
        )
        status = CorroborationStatus(
            verdict=CorroborationVerdict.DIVERGENCE,
            matching_sources=("pi",),
            silent_sources=("local",),
        )
        findings = await inv.investigate_n(_alert("127.0.0.1", "127.0.0.1"), status)
        assert findings.explanation == "loopback_traffic"
        assert findings.is_explained is True

    async def test_match_majority_also_runs_battery(self) -> None:
        # MATCH_MAJORITY means at least one source dissented or stayed
        # silent — the investigator needs to surface why.
        inv = DivergenceInvestigator()
        status = CorroborationStatus(
            verdict=CorroborationVerdict.MATCH_MAJORITY,
            matching_sources=("a", "b"),
            silent_sources=("c",),
            threshold_ratio=0.5,
        )
        findings = await inv.investigate_n(_alert("8.8.8.8", "1.1.1.1"), status)
        assert findings.checks_run, "expected investigation to run on MATCH_MAJORITY"
