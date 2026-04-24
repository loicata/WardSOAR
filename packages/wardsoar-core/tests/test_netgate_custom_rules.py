"""Tests for Phase 7c — WardSOAR custom Suricata rules.

Two surfaces:

* :func:`src.netgate_custom_rules.build_bundle` — pure function; input
  is a registry, output is a :class:`RulesBundle`. Deterministic,
  easy to assert against.
* :func:`src.netgate_custom_rules.deploy_bundle` — IO layer that
  writes a heredoc command over SSH. We mock the SSH to assert the
  command shape and the reaction to errors.

No real Suricata or Netgate involved.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

from wardsoar.core.netgate_custom_rules import (
    REMOTE_RULES_PATH,
    RulesBundle,
    build_bundle,
    deploy_bundle,
)

# ---------------------------------------------------------------------------
# Fake registry — shape matches what the private _ActorEntry dataclass
# exposes, so build_bundle's duck typing works.
# ---------------------------------------------------------------------------


@dataclass
class _FakeActor:
    actor_id: str
    name: str
    ips: set[str] = field(default_factory=set)
    cidrs: list[object] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)


@dataclass
class _FakeRegistry:
    _actors: list[_FakeActor] = field(default_factory=list)


def _registry_with_one_actor() -> _FakeRegistry:
    reg = _FakeRegistry(
        _actors=[
            _FakeActor(
                actor_id="VINE-2025-001",
                name="Ben Hutchinson (ex Vine Fibre)",
                ips={"84.203.112.137"},
                cidrs=[ipaddress.ip_network("84.203.112.0/24", strict=False)],
                domains={"evil.example"},
            ),
        ]
    )
    return reg


# ---------------------------------------------------------------------------
# build_bundle
# ---------------------------------------------------------------------------


class TestBuildBundle:
    def test_empty_registry_yields_ben_pattern_rules_only(self) -> None:
        bundle = build_bundle(None)
        assert bundle.actor_count == 0
        assert bundle.ioc_count == 0
        # Three hand-written signatures must always be present — they
        # are the minimum viable WardSOAR ruleset.
        sids = sorted(r.sid for r in bundle.rules)
        assert 1_200_001 in sids
        assert 1_200_002 in sids
        assert 1_200_003 in sids

    def test_actor_rules_include_ip_cidr_and_domains(self) -> None:
        bundle = build_bundle(_registry_with_one_actor())
        rendered = bundle.render()
        # IP rule
        assert "84.203.112.137" in rendered
        # CIDR rule
        assert "84.203.112.0/24" in rendered
        # TLS SNI + DNS rules for the domain
        assert "tls.sni" in rendered and "evil.example" in rendered
        assert "dns.query" in rendered
        # ioc_count counts 4 items (1 IP + 1 CIDR + 1 domain × 2 rules).
        assert bundle.ioc_count == 4

    def test_sids_are_in_reserved_range(self) -> None:
        bundle = build_bundle(_registry_with_one_actor())
        for entry in bundle.rules:
            assert 1_000_000 <= entry.sid < 2_000_000, entry

    def test_sids_are_unique(self) -> None:
        bundle = build_bundle(_registry_with_one_actor())
        sids = [r.sid for r in bundle.rules]
        assert len(sids) == len(set(sids))

    def test_malformed_ip_is_dropped_silently(self) -> None:
        reg = _FakeRegistry(
            _actors=[
                _FakeActor(
                    actor_id="BAD",
                    name="bad",
                    ips={"not-an-ip", "203.0.113.1"},
                ),
            ]
        )
        bundle = build_bundle(reg)
        rendered = bundle.render()
        assert "not-an-ip" not in rendered
        assert "203.0.113.1" in rendered

    def test_domain_with_spaces_or_semicolons_is_dropped(self) -> None:
        reg = _FakeRegistry(
            _actors=[
                _FakeActor(
                    actor_id="BAD",
                    name="bad",
                    domains={"ok.example", "spaces here.tld", "semi;colon.tld"},
                ),
            ]
        )
        bundle = build_bundle(reg)
        rendered = bundle.render()
        assert "ok.example" in rendered
        assert "spaces here.tld" not in rendered
        assert "semi;colon.tld" not in rendered

    def test_rendered_header_contains_metadata(self) -> None:
        bundle = build_bundle(_registry_with_one_actor())
        rendered = bundle.render()
        assert "WardSOAR custom Suricata rules" in rendered
        assert bundle.generated_at in rendered
        assert str(bundle.actor_count) in rendered

    def test_actor_name_with_quotes_does_not_break_rule(self) -> None:
        """Msg escaping must neutralise ``"`` and ``;``."""
        reg = _FakeRegistry(
            _actors=[
                _FakeActor(
                    actor_id="Q",
                    name='name with "quote" and ;semi;',
                    ips={"203.0.113.9"},
                ),
            ]
        )
        bundle = build_bundle(reg)
        rendered = bundle.render()
        # Double quotes inside the message text must have been replaced,
        # otherwise the rule would have an unterminated msg: field.
        assert 'msg:"WardSOAR KBA Q — name with' in rendered
        assert '"quote"' not in rendered  # original still present would break the rule
        assert ";semi;" not in rendered


# ---------------------------------------------------------------------------
# deploy_bundle
# ---------------------------------------------------------------------------


class TestDeployBundle:
    @pytest.mark.asyncio
    async def test_deploy_writes_heredoc_to_expected_path(self) -> None:
        bundle = build_bundle(None)

        class _Recorder:
            def __init__(self) -> None:
                self.captured_cmd = ""

            async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
                self.captured_cmd = cmd
                return (True, "")

        ssh = _Recorder()
        result = await deploy_bundle(ssh, bundle)  # type: ignore[arg-type]
        assert result.success is True
        assert result.remote_path == REMOTE_RULES_PATH
        assert result.bytes_written > 0
        assert f"cat > {REMOTE_RULES_PATH}" in ssh.captured_cmd
        assert "__WARDSOAR_EOF__" in ssh.captured_cmd

    @pytest.mark.asyncio
    async def test_deploy_reports_ssh_failure(self) -> None:
        bundle = build_bundle(None)
        ssh = type("X", (), {})()
        ssh.run_read_only = AsyncMock(return_value=(False, "Permission denied"))
        result = await deploy_bundle(ssh, bundle)  # type: ignore[arg-type]
        assert result.success is False
        assert result.error is not None
        assert "Permission denied" in result.error

    @pytest.mark.asyncio
    async def test_deploy_refuses_when_content_contains_sentinel(self) -> None:
        """Heredoc delimiter collision must abort before touching SSH."""
        # Craft a bundle whose rendered text embeds the sentinel line.
        bundle = RulesBundle(
            generated_at="now",
            actor_count=0,
            ioc_count=0,
            rules=[],
        )
        # Monkeypatch render to return poisoned content
        poisoned = "some content\n__WARDSOAR_EOF__\nmore\n"
        bundle_render_orig = bundle.render
        try:
            object.__setattr__(bundle, "render", lambda: poisoned)  # type: ignore[misc]
        except Exception:
            pytest.skip("frozen dataclass — skip monkeypatch variant")
        ssh = type("X", (), {})()
        ssh.run_read_only = AsyncMock(return_value=(True, ""))
        result = await deploy_bundle(ssh, bundle)  # type: ignore[arg-type]
        assert result.success is False
        assert "sentinel" in (result.error or "").lower()
        ssh.run_read_only.assert_not_awaited()
        # Restore to avoid bleeding state across tests.
        try:
            object.__setattr__(bundle, "render", bundle_render_orig)  # type: ignore[misc]
        except Exception:
            pass
