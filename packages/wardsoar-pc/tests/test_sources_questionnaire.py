"""Tests for the source-topology answer dataclass.

Up to v0.22.x this module also exercised the standalone
``SourcesQuestionnaire`` ``QDialog``. The dialog was retired in
v0.23.x — its four pages were inlined as the head of the
``SetupWizard`` — and only :class:`SourceChoices` survives. The
invariant helpers (``at_least_one_source``, ``coverage_warnings``)
remain a pure-Python contract that the wizard, the
``RemoteAgentRegistry`` wire-up and the ``config.yaml`` generator
all consume, so they keep their own focused tests here.
"""

from __future__ import annotations

from wardsoar.pc.ui.sources_questionnaire import SourceChoices


class TestSourceChoices:
    """The pure-Python dataclass at the heart of the questionnaire."""

    def test_at_least_one_source_true_when_netgate(self) -> None:
        assert SourceChoices(True, False, False).at_least_one_source()

    def test_at_least_one_source_true_when_virus_sniff(self) -> None:
        assert SourceChoices(False, True, False).at_least_one_source()

    def test_at_least_one_source_true_when_suricata(self) -> None:
        assert SourceChoices(False, False, True).at_least_one_source()

    def test_at_least_one_source_false_when_all_off(self) -> None:
        assert not SourceChoices(False, False, False).at_least_one_source()

    def test_no_warnings_when_netgate_plus_suricata(self) -> None:
        """Full coverage = no warnings to surface."""
        warnings = SourceChoices(True, False, True).coverage_warnings()
        assert warnings == []

    def test_loopback_warning_when_netgate_alone(self) -> None:
        """Netgate without local Suricata = loopback / VPN gap."""
        warnings = SourceChoices(True, False, False).coverage_warnings()
        assert any("loopback" in w.lower() for w in warnings)

    def test_exclusivity_warning_when_both_remote_agents(self) -> None:
        """Netgate + Virus Sniff configured = runtime exclusivity warning."""
        warnings = SourceChoices(True, True, True).coverage_warnings()
        assert any("cannot both be active" in w.lower() for w in warnings)

    def test_standalone_warning_when_suricata_only(self) -> None:
        """No remote agent = no LAN-wide visibility."""
        warnings = SourceChoices(False, False, True).coverage_warnings()
        assert any("standalone pc" in w.lower() for w in warnings)
