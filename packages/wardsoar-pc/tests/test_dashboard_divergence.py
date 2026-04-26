"""Unit tests for the divergence event rewriter on the Activity tab.

The dashboard divergence card was retired alongside the rest of the
left-hand stats column (Alerts Today / Blocked Today / System Health)
when ``System Health`` migrated to the dedicated System tab. The
``DIVERGENCE`` annotation rule on the Activity tab is the surviving
surface for divergence visibility and is what these tests cover.
"""

from __future__ import annotations

# Activity rewriter is a pure function — import without Qt boot.
from wardsoar.pc.ui.views.activity_view import _rewrite_event

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
