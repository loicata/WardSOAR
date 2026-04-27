"""Architectural tests for the dual-source wiring (Step 9 — Q4 doctrine).

These tests do *not* boot Qt or any actual agent. They verify the
intended structure of the dispatch in ``ui/app.py`` and the matching
log in ``main.py`` so that:

  - Both single-source paths still exist and are still reachable.
  - The new dual-source dispatch sits *before* the single-source
    branches (because the boolean evaluation orders Python `if`s
    by appearance, picking the most specific case first).
  - ``NSourceCorrelator`` is referenced inside the new method
    (DualSourceCorrelator was retired in v0.24 — the N-source
    correlator subsumes its 2-source contract).
  - The reconciliation window is read from
    ``config.suricata_local.reconciliation_window_s`` and clamped
    to ``[30, 180]`` per Q1 doctrine.
  - The local-agent ``startup`` is scheduled (Suricata spawn) so the
    eve.json starts populating before the consumer tails it.
  - The pipeline (main.py) emits a clear "dual-source mode active"
    log on init when both flags are set, so the operator's log
    surface always reflects the active configuration.

The tests inspect source code as text — that's intentional. A
runtime assertion would require Qt / a real Pipeline / both source
agents, which is heavier than this thin contract deserves. If the
text-level wires drift, the assertions point at the exact line that
must be re-aligned.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_APP_PATH = _REPO / "packages" / "wardsoar-pc" / "src" / "wardsoar" / "pc" / "ui" / "app.py"
_MAIN_PATH = _REPO / "packages" / "wardsoar-pc" / "src" / "wardsoar" / "pc" / "main.py"


@pytest.fixture(scope="module")
def app_source() -> str:
    return _APP_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def main_source() -> str:
    return _MAIN_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ui/app.py: dispatch + new method
# ---------------------------------------------------------------------------


class TestDispatchOrdering:
    """The dispatch in MainWindow._on_engine_started picks the dual-source
    branch first when both flags are set, so the single-source ``elif``s
    never accidentally swallow it."""

    def test_dual_source_branch_appears_before_single_source(self, app_source: str) -> None:
        # The "if netgate_on and local_on" must precede the
        # "elif netgate_on" / "elif local_on" branches.
        dual_idx = app_source.find("if netgate_on and local_on:")
        netgate_only_idx = app_source.find("elif netgate_on:")
        local_only_idx = app_source.find("elif local_on:")
        assert dual_idx > 0, "missing dual-source dispatch"
        assert netgate_only_idx > dual_idx, "single-Netgate branch must follow dual-source"
        assert local_only_idx > netgate_only_idx, "single-local branch must follow Netgate"

    def test_dispatch_uses_typed_booleans(self, app_source: str) -> None:
        # bool() coercion guarantees the dispatch never picks up a
        # truthy non-bool value (e.g. a stale string from a hand-
        # edited config).
        assert "netgate_on = bool(sources.get(" in app_source
        assert "local_on = bool(sources.get(" in app_source

    def test_dual_source_method_exists(self, app_source: str) -> None:
        assert "def _start_dual_source_stream_consumer(" in app_source


class TestDualSourceMethod:
    """The new method builds the right object graph."""

    def test_method_imports_dual_source_correlator(self, app_source: str) -> None:
        # The method must import the correlator from core. The
        # exact ``from`` line is inside the method body so we
        # search for the symbol within a generous window after
        # the def.
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None, "dual-source method body not found"
        body = match.group(1)
        assert "from wardsoar.core.remote_agents.n_source_correlator import NSourceCorrelator" in body

    def test_method_constructs_both_agents(self, app_source: str) -> None:
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "NetgateAgent.from_credentials(" in body
        assert "LocalSuricataAgent(" in body

    def test_method_clamps_window_to_30_180(self, app_source: str) -> None:
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "max(30.0, min(180.0," in body, "Q1 [30, 180] clamp missing"

    def test_method_reads_reconciliation_window_from_config(self, app_source: str) -> None:
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "reconciliation_window_s" in body

    def test_method_does_not_schedule_startup_on_main_loop(self, app_source: str) -> None:
        """Regression guard for v0.25.5.

        Earlier versions called ``loop.create_task(local_agent.startup())``
        from the main UI thread, which silently dropped the spawn because
        Qt does not run an asyncio loop. Startup is now delegated to
        ``NSourceCorrelator._pump`` so it runs on the consumer's loop.
        """
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "loop.create_task(local_agent.startup())" not in body, (
            "Startup must NOT be scheduled on the main thread loop — "
            "NSourceCorrelator._pump now drives startup on the consumer loop"
        )

    def test_method_wraps_correlator_in_consumer(self, app_source: str) -> None:
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "NSourceCorrelator(" in body
        assert "AgentStreamConsumer(correlator)" in body

    def test_method_handles_missing_local_install_with_fallback(self, app_source: str) -> None:
        # When the local Suricata install is missing, the method
        # must NOT raise — it falls back to a Netgate-only stream
        # so the operator still has a working pipeline. The
        # WARNING log invites them to run the wizard.
        match = re.search(
            r"def _start_dual_source_stream_consumer\(.*?\n(.*?)(?=\n    def |\Z)",
            app_source,
            re.DOTALL,
        )
        assert match is not None
        body = match.group(1)
        assert "if suricata_dir is None or not interface:" in body
        assert "fallback" in body.lower() or "fallback" in body
        # AgentStreamConsumer is built around the external agent
        # in the fallback (no correlator).
        fallback_section = body.split("if suricata_dir is None or not interface:")[1]
        fallback_section = fallback_section.split("log_dir = get_data_dir()")[0]
        assert "AgentStreamConsumer(external_agent)" in fallback_section


# ---------------------------------------------------------------------------
# main.py: dual-source log line
# ---------------------------------------------------------------------------


class TestPipelineDualSourceLog:
    """The Pipeline.__init__ emits a clear log when both flags are set
    so the operator can see the dual-source mode is active in the
    standard log output."""

    def test_dual_source_log_present(self, main_source: str) -> None:
        # The exact format isn't critical, but the key tokens
        # must appear on the same INFO log line so a grep on
        # 'dual-source' surfaces the activation.
        assert "dual-source mode" in main_source

    def test_dual_source_log_mentions_perimeter_enforcement(self, main_source: str) -> None:
        # Q4 doctrine: in dual-source mode the perimeter
        # (NetgateAgent) is the enforcer. The log must say so —
        # this is the one place the operator sees the routing
        # decision documented at runtime.
        assert "perimeter" in main_source

    def test_dual_source_log_references_correlator(self, main_source: str) -> None:
        assert "DualSourceCorrelator" in main_source
