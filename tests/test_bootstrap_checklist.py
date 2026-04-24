"""Tests for the Netgate bootstrap checklist state + step registry."""

from __future__ import annotations

import json
from pathlib import Path

from src.bootstrap_checklist import (
    BOOTSTRAP_STEPS,
    KIND_PFSENSE_UI,
    KIND_WARDSOAR,
    KIND_WINDOWS,
    BootstrapChecklistState,
    default_persist_path,
    step_by_id,
)

# ---------------------------------------------------------------------------
# Step registry shape
# ---------------------------------------------------------------------------


class TestBootstrapSteps:
    """Static guarantees on the :data:`BOOTSTRAP_STEPS` tuple.

    The tuple is imported by the UI card and by the markdown guide —
    drifting fields here silently breaks both.
    """

    def test_has_twelve_steps(self) -> None:
        # 1 Sysmon install + 5 pfSense UI clicks + 4 WardSOAR actions +
        # 2 extra pfSense clicks (activate custom rules, wizard) = 12.
        assert len(BOOTSTRAP_STEPS) == 12

    def test_ids_are_unique(self) -> None:
        ids = [step.id for step in BOOTSTRAP_STEPS]
        assert len(set(ids)) == len(ids)

    def test_numbers_are_contiguous_from_one(self) -> None:
        numbers = [step.number for step in BOOTSTRAP_STEPS]
        assert numbers == list(range(1, len(BOOTSTRAP_STEPS) + 1))

    def test_every_kind_is_recognised(self) -> None:
        allowed = {KIND_PFSENSE_UI, KIND_WARDSOAR, KIND_WINDOWS}
        for step in BOOTSTRAP_STEPS:
            assert step.kind in allowed, step

    def test_sysmon_step_is_first_and_of_kind_windows(self) -> None:
        """Regression: the Sysmon install is step 1 so an operator sees
        it before any Netgate work — process attribution relies on it."""
        first = BOOTSTRAP_STEPS[0]
        assert first.id == "sysmon_install"
        assert first.number == 1
        assert first.kind == KIND_WINDOWS

    def test_title_and_description_are_non_empty(self) -> None:
        for step in BOOTSTRAP_STEPS:
            assert step.title.strip(), step
            assert step.description.strip(), step


class TestStepById:
    def test_known_step_is_returned(self) -> None:
        result = step_by_id("audit")
        assert result is not None
        assert result.id == "audit"
        assert result.kind == KIND_WARDSOAR

    def test_unknown_step_returns_none(self) -> None:
        assert step_by_id("nope") is None


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


class TestBootstrapChecklistState:
    def test_default_state_has_nothing_checked(self, tmp_path: Path) -> None:
        path = tmp_path / "bootstrap_checklist.json"
        state = BootstrapChecklistState(persist_path=path)

        for step in BOOTSTRAP_STEPS:
            assert state.is_checked(step.id) is False
        assert state.progress() == (0, len(BOOTSTRAP_STEPS))
        assert not path.exists()

    def test_set_checked_persists_across_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "bootstrap_checklist.json"
        state = BootstrapChecklistState(persist_path=path)
        state.set_checked("audit", True)
        state.set_checked("deploy_rules", True)

        # Round-trip through a fresh instance — simulates a WardSOAR
        # restart mid-bootstrap.
        reloaded = BootstrapChecklistState(persist_path=path)
        assert reloaded.is_checked("audit") is True
        assert reloaded.is_checked("deploy_rules") is True
        assert reloaded.is_checked("establish_baseline") is False
        assert reloaded.progress() == (2, len(BOOTSTRAP_STEPS))

    def test_uncheck_is_persisted(self, tmp_path: Path) -> None:
        path = tmp_path / "bootstrap_checklist.json"
        state = BootstrapChecklistState(persist_path=path)
        state.set_checked("audit", True)
        state.set_checked("audit", False)

        reloaded = BootstrapChecklistState(persist_path=path)
        assert reloaded.is_checked("audit") is False

    def test_corrupt_file_does_not_raise(self, tmp_path: Path) -> None:
        path = tmp_path / "bootstrap_checklist.json"
        path.write_text("not json at all", encoding="utf-8")

        state = BootstrapChecklistState(persist_path=path)

        # Starts from an empty state and remains functional.
        assert state.progress() == (0, len(BOOTSTRAP_STEPS))
        state.set_checked("audit", True)
        assert state.is_checked("audit") is True

    def test_non_dict_payload_is_ignored(self, tmp_path: Path) -> None:
        """A JSON list or scalar must not crash the loader."""
        path = tmp_path / "bootstrap_checklist.json"
        path.write_text(json.dumps(["audit", "deploy_rules"]), encoding="utf-8")

        state = BootstrapChecklistState(persist_path=path)

        # The loader saw a list — falls back to an empty dict.
        assert state.progress() == (0, len(BOOTSTRAP_STEPS))

    def test_progress_ignores_unknown_keys(self, tmp_path: Path) -> None:
        """Left-over ids from a renamed step must not inflate progress."""
        path = tmp_path / "bootstrap_checklist.json"
        path.write_text(
            json.dumps(
                {
                    "audit": True,
                    "ghost_step": True,  # unknown id
                }
            ),
            encoding="utf-8",
        )
        state = BootstrapChecklistState(persist_path=path)
        assert state.progress() == (1, len(BOOTSTRAP_STEPS))

    def test_reset_all_drops_every_tick_and_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bootstrap_checklist.json"
        state = BootstrapChecklistState(persist_path=path)
        state.set_checked("audit", True)
        state.set_checked("deploy_rules", True)
        assert path.is_file()

        state.reset_all()

        assert state.progress() == (0, len(BOOTSTRAP_STEPS))
        assert not path.exists()

    def test_snapshot_returns_shallow_copy(self, tmp_path: Path) -> None:
        state = BootstrapChecklistState(persist_path=tmp_path / "cl.json")
        state.set_checked("audit", True)
        snap = state.snapshot()
        snap["audit"] = False  # mutate the copy

        # Internal state is not affected.
        assert state.is_checked("audit") is True


class TestDefaultPersistPath:
    def test_uses_bootstrap_checklist_json_under_data_dir(self, tmp_path: Path) -> None:
        assert default_persist_path(tmp_path) == tmp_path / "bootstrap_checklist.json"
