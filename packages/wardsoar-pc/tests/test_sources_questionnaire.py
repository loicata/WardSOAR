"""Tests for the upstream source-topology questionnaire (v0.22.20).

Two layers:

  * :class:`SourceChoices` is a pure dataclass (no Qt) — its invariant
    helpers (``at_least_one_source``, ``coverage_warnings``) are tested
    in isolation;
  * :class:`SourcesQuestionnaire` is a ``QDialog`` — exercised via the
    shared session ``qapp`` fixture, asserting initial state, the
    forced-Yes rule on the Suricata page when both other answers are
    No, the navigation flow, and the recap.
"""

from __future__ import annotations

import sys

import pytest
from PySide6.QtWidgets import QApplication, QDialog
from qfluentwidgets import Theme, setTheme

from wardsoar.pc.ui.sources_questionnaire import (
    PAGE_NETGATE,
    PAGE_RECAP,
    PAGE_SURICATA_LOCAL,
    PAGE_VIRUS_SNIFF,
    TOTAL_PAGES,
    SourceChoices,
    SourcesQuestionnaire,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Shared QApplication — same pattern as test_ui.py."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    setTheme(Theme.DARK)
    return app


# ---------------------------------------------------------------------------
# SourceChoices invariants
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# SourcesQuestionnaire — QDialog behaviour
# ---------------------------------------------------------------------------


class TestSourcesQuestionnaireConstruction:
    """Construction + initial state."""

    def test_construction_lands_on_first_page(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            assert q._current_page == PAGE_NETGATE
            assert q._stack.count() == TOTAL_PAGES
        finally:
            q.deleteLater()

    def test_default_choices_are_all_no(self, qapp: QApplication) -> None:
        """The questionnaire starts with no source selected.

        The Suricata default flips to Yes only after the operator
        explicitly answers No to both Netgate and Virus Sniff via
        the radio buttons (handled by the forced-Yes rule).
        """
        q = SourcesQuestionnaire()
        try:
            assert q.choices == SourceChoices(False, False, False)
        finally:
            q.deleteLater()


class TestForcedSuricataRule:
    """The "≥1 source" invariant is enforced on the Suricata page."""

    def test_suricata_forced_yes_when_no_remote_agents(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            # Both remote-agent radios stay on the No default.
            q._netgate_choice = False
            q._virus_sniff_choice = False
            q._refresh_suricata_page()
            assert q.choices.suricata_local is True
            assert q._suricata_yes.isChecked()
            assert not q._suricata_yes.isEnabled()
            assert not q._suricata_no.isEnabled()
        finally:
            q.deleteLater()

    def test_suricata_optional_when_netgate_selected(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            q._netgate_choice = True
            q._virus_sniff_choice = False
            q._refresh_suricata_page()
            # Operator gets to choose now — radios re-enabled.
            assert q._suricata_yes.isEnabled()
            assert q._suricata_no.isEnabled()
        finally:
            q.deleteLater()


class TestNavigation:
    """Next / Back move through the four pages in order."""

    def test_next_advances_through_pages(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            q._go_next()  # Netgate -> Virus Sniff
            assert q._current_page == PAGE_VIRUS_SNIFF
            q._go_next()  # Virus Sniff -> Suricata
            assert q._current_page == PAGE_SURICATA_LOCAL
            q._go_next()  # Suricata -> Recap
            assert q._current_page == PAGE_RECAP
        finally:
            q.deleteLater()

    def test_back_returns_to_previous_page(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            q._go_next()
            q._go_next()
            assert q._current_page == PAGE_SURICATA_LOCAL
            q._go_back()
            assert q._current_page == PAGE_VIRUS_SNIFF
            q._go_back()
            assert q._current_page == PAGE_NETGATE
        finally:
            q.deleteLater()

    def test_back_on_first_page_is_noop(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            assert q._current_page == PAGE_NETGATE
            q._go_back()
            assert q._current_page == PAGE_NETGATE
        finally:
            q.deleteLater()

    def test_finish_button_label_on_recap(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            for _ in range(TOTAL_PAGES - 1):
                q._go_next()
            assert q._current_page == PAGE_RECAP
            assert q._next_button.text() == "Finish"
        finally:
            q.deleteLater()


class TestRecap:
    """Recap page renders the choices and any coverage warnings."""

    def test_recap_text_lists_all_three_choices(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            q._netgate_choice = True
            q._suricata_choice = True
            q._refresh_recap()
            text = q._recap_text.toPlainText()
            assert "Netgate" in text
            assert "Virus Sniff" in text
            assert "Suricata" in text
        finally:
            q.deleteLater()

    def test_recap_warnings_text_clean_when_no_gaps(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            # Netgate + local Suricata = no gaps to flag.
            q._netgate_choice = True
            q._suricata_choice = True
            q._refresh_recap()
            assert "No coverage gaps" in q._warnings_text.toPlainText()
        finally:
            q.deleteLater()

    def test_recap_warnings_text_lists_loopback_gap(self, qapp: QApplication) -> None:
        q = SourcesQuestionnaire()
        try:
            q._netgate_choice = True
            q._suricata_choice = False
            q._refresh_recap()
            assert "loopback" in q._warnings_text.toPlainText().lower()
        finally:
            q.deleteLater()


class TestFinishGuard:
    """Belt-and-braces guard against the impossible "no source" finish."""

    def test_finish_refuses_when_no_source(self, qapp: QApplication) -> None:
        """Even if the forced-Yes rule is bypassed by direct attribute
        manipulation (a future regression scenario), ``_on_finish``
        refuses to accept the dialog."""
        q = SourcesQuestionnaire()
        try:
            q._netgate_choice = False
            q._virus_sniff_choice = False
            q._suricata_choice = False  # bypass the forced-Yes rule
            q._on_finish()
            # Dialog stays open — result() is the unset default.
            assert q.result() == QDialog.DialogCode.Rejected

        finally:
            q.deleteLater()
