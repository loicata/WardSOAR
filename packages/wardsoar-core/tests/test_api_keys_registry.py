"""Tests for :mod:`src.api_keys_registry`.

Guard the invariants that the UI layers (keys_view, setup_wizard)
rely on: every tier has its specs, env_vars are unique, signup URLs
are well-formed, manual checks have a ``{ip}`` placeholder.
"""

from __future__ import annotations

from urllib.parse import urlparse

from wardsoar.core.api_keys_registry import (
    API_KEY_SPECS,
    AUTO_ENABLED_SOURCES,
    MANUAL_CHECKS,
    specs_by_tier,
)


class TestRegistryInvariants:
    """Structural invariants the UI code depends on."""

    def test_env_vars_are_unique(self) -> None:
        env_vars = [spec.env_var for spec in API_KEY_SPECS]
        assert len(env_vars) == len(set(env_vars)), "Duplicate env_var in API_KEY_SPECS"

    def test_display_labels_are_non_empty(self) -> None:
        for spec in API_KEY_SPECS:
            assert spec.display_label.strip(), f"Empty label for {spec.env_var}"

    def test_exactly_one_required_spec(self) -> None:
        required = [spec for spec in API_KEY_SPECS if spec.required]
        assert len(required) == 1, "Only Anthropic should be required"
        assert required[0].env_var == "ANTHROPIC_API_KEY"

    def test_signup_urls_are_valid(self) -> None:
        for spec in API_KEY_SPECS:
            if spec.signup_url is None:
                continue
            parsed = urlparse(spec.signup_url)
            assert parsed.scheme == "https", f"{spec.env_var}: non-https signup URL"
            assert parsed.netloc, f"{spec.env_var}: empty signup URL host"

    def test_every_tier_has_at_least_one_spec(self) -> None:
        for tier in ("required", "essential", "useful", "paid", "notification"):
            assert specs_by_tier(tier), f"Tier {tier!r} has no keys"


class TestAutoEnabledSources:
    """Auto-enabled list is rendered verbatim in the UI \u2014 ensure it is sane."""

    def test_auto_enabled_names_are_unique(self) -> None:
        names = [s.name for s in AUTO_ENABLED_SOURCES]
        assert len(names) == len(set(names))

    def test_auto_enabled_has_expected_count(self) -> None:
        # The Keys tab copy advertises "11 intelligence sources".
        # If this changes, the copy must be updated too.
        assert len(AUTO_ENABLED_SOURCES) == 11


class TestManualChecks:
    """Each manual check must render the operator's IP safely."""

    def test_every_url_template_has_ip_placeholder(self) -> None:
        for mc in MANUAL_CHECKS:
            assert "{ip}" in mc.url_template, f"{mc.name}: missing {{ip}} placeholder"

    def test_urls_become_valid_after_formatting(self) -> None:
        for mc in MANUAL_CHECKS:
            url = mc.url_template.format(ip="185.199.109.133")
            parsed = urlparse(url)
            assert parsed.scheme == "https", f"{mc.name}: non-https URL"
            assert parsed.netloc, f"{mc.name}: empty URL host"

    def test_relevance_tags_are_known(self) -> None:
        allowed = {"high", "medium"}
        for mc in MANUAL_CHECKS:
            assert mc.relevance in allowed, f"{mc.name}: bad relevance tag"

    def test_high_relevance_checks_come_first(self) -> None:
        """UI renders them in order; operator-facing ordering matters."""
        saw_medium = False
        for mc in MANUAL_CHECKS:
            if mc.relevance == "medium":
                saw_medium = True
            elif mc.relevance == "high" and saw_medium:
                raise AssertionError(f"{mc.name}: HIGH relevance appears after a MEDIUM entry")
