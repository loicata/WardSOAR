"""Unit tests for the dashboard's divergence widget (Step 11).

Covers the rolling 24 h counter (``record_divergence``) and the
activity-tab event rewriter (``DIVERGENCE`` branch in
``_rewrite_event``). The dashboard is heavy (Qt charts, pixmaps),
so the dashboard tests run inside a single qapp fixture; the
activity-rewriter tests are pure functions and run without Qt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

# Activity rewriter is a pure function — import without Qt boot.
from wardsoar.pc.ui.views.activity_view import _rewrite_event

# ---------------------------------------------------------------------------
# QApplication fixture for the dashboard widget tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def qapp() -> Generator[object, None, None]:
    """Create a single QApplication for all dashboard tests in this module.
    QtCharts requires a running QApplication; we cannot construct the
    DashboardView without one."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    created = False
    if app is None:
        app = QApplication([])
        created = True
    yield app
    if created:
        # QApplication.quit() is unsafe across pytest collection;
        # a graceful no-op is the right behaviour — the OS reclaims
        # the resources on interpreter exit.
        pass


@pytest.fixture
def dashboard(qapp: object) -> object:
    """Construct a DashboardView with the qapp fixture in scope."""
    from wardsoar.pc.ui.views.dashboard import DashboardView

    return DashboardView()


# ---------------------------------------------------------------------------
# DashboardView.record_divergence
# ---------------------------------------------------------------------------


class TestDashboardRecordDivergence:
    def test_card_hidden_until_first_divergence(self, dashboard: object) -> None:
        # Step 11 doctrine: keep the dashboard clean for single-source
        # operators — the divergence card stays hidden until at least
        # one divergence is recorded.
        # ``isHidden()`` distinguishes "explicitly hidden" from
        # "not currently shown because the parent isn't shown" —
        # the former is what we want to assert in a unit test.
        assert dashboard._divergence_card.isHidden() is True  # type: ignore[attr-defined]

    def test_first_record_reveals_card(self, dashboard: object) -> None:
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="loopback_traffic",
            is_unexplained=False,
        )
        # After the first record, the explicit-hide bit is cleared.
        assert dashboard._divergence_card.isHidden() is False  # type: ignore[attr-defined]

    def test_unexplained_drives_counter(self, dashboard: object) -> None:
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained",
            is_unexplained=True,
        )
        assert dashboard._divergence_value.text() == "1"  # type: ignore[attr-defined]
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained",
            is_unexplained=True,
        )
        assert dashboard._divergence_value.text() == "2"  # type: ignore[attr-defined]

    def test_explained_does_not_drive_counter(self, dashboard: object) -> None:
        # Loopback / VPN / LAN-only are recorded but do NOT increment
        # the headline counter — the operator only sees actionable
        # divergences in the card.
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="vpn_traffic",
            is_unexplained=False,
        )
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="lan_only_traffic",
            is_unexplained=False,
        )
        assert dashboard._divergence_value.text() == "0"  # type: ignore[attr-defined]

    def test_24h_pruning(self, dashboard: object) -> None:
        # Inject one entry 25 h ago and one fresh; only the fresh one
        # survives pruning, so the counter reads 1.
        old_ts = datetime.now(timezone.utc) - timedelta(hours=25)
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained",
            is_unexplained=True,
            ts=old_ts,
        )
        # Pruning happens on the next record_divergence call — push
        # a fresh entry to trigger the cleanup.
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained",
            is_unexplained=True,
        )
        assert dashboard._divergence_value.text() == "1"  # type: ignore[attr-defined]
        records = list(dashboard._divergence_records)  # type: ignore[attr-defined]
        assert len(records) == 1, f"expected 1 entry post-prune, got {records}"

    def test_mixed_window_counts_only_unexplained(self, dashboard: object) -> None:
        # Insert: 1 unexplained, 2 explained, 1 suricata-dead. The
        # unexplained-class count is 2 (unexplained + suricata-dead);
        # the explained ones are still buffered for future panels but
        # do not influence the headline.
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained", is_unexplained=True
        )
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="loopback_traffic", is_unexplained=False
        )
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="vpn_traffic", is_unexplained=False
        )
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="suricata_local_dead", is_unexplained=True
        )
        assert dashboard._divergence_value.text() == "2"  # type: ignore[attr-defined]

    def test_explicit_timestamp_used(self, dashboard: object) -> None:
        ts = datetime(2026, 4, 26, 14, 30, 0, tzinfo=timezone.utc)
        dashboard.record_divergence(  # type: ignore[attr-defined]
            explanation="unexplained",
            is_unexplained=True,
            ts=ts,
        )
        records = list(dashboard._divergence_records)  # type: ignore[attr-defined]
        assert records[0][0] == ts


# ---------------------------------------------------------------------------
# Activity event rewriter (pure function — no Qt needed)
# ---------------------------------------------------------------------------


class TestActivityRewriterDivergence:
    def test_loopback_renders_as_info(self) -> None:
        label, msg, color = _rewrite_event("DIVERGENCE", "loopback_traffic")
        assert "info" in label.lower()
        assert "loopback" in msg.lower()
        assert color is not None
        # Info blue: (0, 120, 212)
        assert color.blue() > 200

    def test_vpn_renders_as_info(self) -> None:
        label, msg, color = _rewrite_event("DIVERGENCE", "vpn_traffic")
        assert "info" in label.lower()
        assert "vpn" in msg.lower()
        assert color is not None

    def test_lan_only_renders_as_info(self) -> None:
        label, msg, color = _rewrite_event("DIVERGENCE", "lan_only_traffic")
        assert "info" in label.lower()
        assert "lan only" in msg.lower()
        assert color is not None

    def test_suricata_dead_renders_as_warning(self) -> None:
        label, msg, color = _rewrite_event("DIVERGENCE", "suricata_local_dead")
        assert "warning" in label.lower()
        assert "suricata" in msg.lower()
        assert color is not None
        # Warning orange: (255, 152, 0) — high red, mid green, low blue.
        assert color.red() > 200 and color.green() > 100 and color.blue() < 100

    def test_unexplained_renders_as_alert(self) -> None:
        label, msg, color = _rewrite_event("DIVERGENCE", "unexplained")
        assert "alert" in label.lower()
        assert "unexplained" in msg.lower()
        assert color is not None
        # Alert red: (244, 67, 54).
        assert color.red() > 200 and color.green() < 100

    def test_unknown_explanation_renders_as_alert(self) -> None:
        # Fail-safe: an unknown explanation token (e.g. a future
        # explanation we forgot to register) must still produce a
        # visible row — falls back to the alert tier.
        label, msg, color = _rewrite_event("DIVERGENCE", "some_future_token")
        assert "alert" in label.lower()
        assert color is not None

    def test_event_dispatch_case_insensitive(self) -> None:
        # The DIVERGENCE branch matches event_upper, so any case is
        # accepted as input.
        label_lower, _, _ = _rewrite_event("divergence", "unexplained")
        label_mixed, _, _ = _rewrite_event("Divergence", "unexplained")
        label_upper, _, _ = _rewrite_event("DIVERGENCE", "unexplained")
        assert label_lower == label_mixed == label_upper
