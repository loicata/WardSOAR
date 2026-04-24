"""Tests for Phase 7a — Netgate configuration audit.

Every SSH call is replaced with a canned response fixture so the
suite never reaches a real network. Each test covers either:

* the aggregation pipeline (``run()`` returning a structured result
  that the UI and the mode-escalation gate rely on), or
* one specific check, asserting that the finding is produced with
  the right tier / status / fix identifier from a representative
  command output.

The audit's SSH commands are hard-coded string literals on the
auditor — never interpolate user input at call sites — so there's no
injection surface to exercise here.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from wardsoar.core.netgate_audit import (
    CAT_OUTPUT,
    CAT_PF,
    CAT_SURICATA,
    NetgateAuditor,
    STATUS_CRITICAL,
    STATUS_OK,
    STATUS_WARNING,
    TIER_CRITICAL,
    TIER_RECOMMENDED,
    AuditFinding,
    AuditResult,
    run_audit,
)
from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH

# ---------------------------------------------------------------------------
# Fake SSH — canned responses keyed by exact command.
# ---------------------------------------------------------------------------


class _FakeSSH:
    """Minimal stand-in for :class:`PfSenseSSH`.

    The auditor only ever calls :meth:`check_status` and
    :meth:`run_read_only`, so those are the only methods we need to
    mimic. Each instance holds a mapping of command string to
    ``(success, stdout)``; missing commands degrade to a fail-safe
    "unreachable" response so the check produces UNKNOWN rather than
    crashing.
    """

    def __init__(
        self,
        responses: dict[str, tuple[bool, str]],
        status_ok: bool = True,
        status_msg: str = "pfSense SSH reachable",
    ) -> None:
        self._responses = responses
        self._status_ok = status_ok
        self._status_msg = status_msg

    async def check_status(self) -> tuple[bool, str]:  # noqa: D401
        return (self._status_ok, self._status_msg)

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        if cmd in self._responses:
            return self._responses[cmd]
        return (False, f"no canned response for: {cmd!r}")


def _default_healthy_responses() -> dict[str, tuple[bool, str]]:
    """A mapping that makes every check pass — used as a baseline."""
    yaml_blob = (
        "runmode: workers\n"
        "af-packet:\n"
        "  - interface: igc0\n"
        "host-mem-cap: 512 mb\n"
        "stream:\n"
        "  memcap: 64 mb\n"
        "flow:\n"
        "  memcap: 128 mb\n"
        "default-rule-path: /usr/local/etc/suricata/rules\n"
        "rule-files:\n"
        "  - emerging-all.rules\n"
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      types:\n"
        "        - alert\n"
        "        - dns\n"
        "        - tls\n"
        "        - http\n"
        "        - ssh\n"
        "        - flow\n"
        "  - file-store:\n"
        "      enabled: no\n"
        "http:\n"
        "  enabled: yes\n"
        "tls:\n"
        "  enabled: yes\n"
        "dns:\n"
        "  enabled: yes\n"
        "ssh:\n"
        "  enabled: yes\n"
    )
    return {
        NetgateAuditor._CMD_PFCTL_INFO: (True, "Status: Enabled"),
        NetgateAuditor._CMD_PFCTL_TABLES: (True, "blocklist\nbogons\nvirusprot\n"),
        NetgateAuditor._CMD_PKG_SURICATA: (True, "Name           : pfSense-pkg-suricata\n"),
        NetgateAuditor._CMD_SURICATA_INSTANCES: (True, "suricata_abc123_igc0\n"),
        NetgateAuditor._CMD_SURICATA_PIDS: (True, "12345 /usr/local/bin/suricata -c ...\n"),
        NetgateAuditor._CMD_SURICATA_VERSION: (True, "Suricata version 7.0.4 RELEASE\n"),
        NetgateAuditor._CMD_SURICATA_YAML: (True, yaml_blob),
        NetgateAuditor._CMD_SURICATA_RULES_COUNT: (True, "    48521 total\n"),
        NetgateAuditor._CMD_NTPQ: (True, "*time.cloudflare.com\n+ntp2.example\n"),
        NetgateAuditor._CMD_DATE: (True, "1713616800\n"),
        NetgateAuditor._CMD_DF_VAR_LOG: (
            True,
            "Filesystem 1024-blocks   Used Avail Capacity Mounted\n"
            "/dev/ada0s1a 1000000   500000 500000    50% /var/log\n",
        ),
        NetgateAuditor._CMD_UNAME: (True, "FreeBSD 14.0-RELEASE amd64\n"),
        NetgateAuditor._CMD_PFSENSE_VERSION: (True, "2.7.2\n"),
        NetgateAuditor._CMD_IFCONFIG_SHORT: (True, "igc0 igc1 lo0\n"),
        NetgateAuditor._CMD_CONFIG_XML_HEAD: (True, "<?xml version='1.0'?>\n<pfsense>"),
        "stat -f '%m %z' '/var/log/suricata/eve.json' 2>&1 || true": (
            True,
            "1713616790 1048576\n",  # 10 s before "now"
        ),
        # Phase 7h — alias type check. Healthy baseline is a fully
        # migrated Netgate: url-table alias with the seed file on disk.
        NetgateAuditor._CMD_BLOCKLIST_ALIAS_TYPE: (
            True,
            "urltable\n---\nseed_ok\n",
        ),
    }


def _make_auditor(
    responses: dict[str, tuple[bool, str]] | None = None,
    *,
    status_ok: bool = True,
    eve_path: str = "/var/log/suricata/eve.json",
) -> NetgateAuditor:
    ssh = _FakeSSH(responses or _default_healthy_responses(), status_ok=status_ok)
    return NetgateAuditor(ssh=ssh, eve_json_path=eve_path)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Top-level run() aggregate behaviour
# ---------------------------------------------------------------------------


class TestAuditAggregation:
    """``run()`` is the only entry point the UI uses — the shape of
    its ``AuditResult`` is load-bearing for the mode-escalation gate
    and the JSON export."""

    @pytest.mark.asyncio
    async def test_healthy_netgate_reports_zero_critical_ko(self) -> None:
        result = await _make_auditor().run()
        assert result.ssh_reachable is True
        assert result.any_critical_ko is False
        # Every finding must be filled in, never None silently.
        for finding in result.findings:
            assert finding.id
            assert finding.tier in {"critical", "recommended", "advanced"}
            assert finding.status in {"ok", "warning", "critical", "unknown"}

    @pytest.mark.asyncio
    async def test_ssh_unreachable_produces_single_critical_finding(self) -> None:
        auditor = _make_auditor(status_ok=False)
        result = await auditor.run()
        assert result.ssh_reachable is False
        assert result.any_critical_ko is True
        assert len(result.findings) == 1
        assert result.findings[0].id == "ssh.reachable"

    @pytest.mark.asyncio
    async def test_to_dict_is_json_serialisable(self) -> None:
        """The UI and the JSON export consume ``.to_dict()`` directly."""
        import json

        result = await _make_auditor().run()
        payload = result.to_dict()
        # Smoke: no pydantic-specific types leak into the dict.
        json.dumps(payload)
        assert "findings" in payload
        assert payload["ssh_reachable"] is True

    @pytest.mark.asyncio
    async def test_crashing_check_does_not_abort_the_run(self, monkeypatch) -> None:
        """One broken check must not take the whole audit down."""
        auditor = _make_auditor()

        async def _boom(self: NetgateAuditor) -> AuditFinding:
            raise RuntimeError("canary")

        # Replace one specific check with a crasher.
        monkeypatch.setattr(NetgateAuditor, "_check_disk_space", _boom)
        result = await auditor.run()
        ids = [f.id for f in result.findings]
        # The crashed check still shows up as an "unknown" finding.
        assert any(fid.startswith("internal.") for fid in ids), ids
        # And the other checks still completed — at least the healthy pf check.
        assert "pf.pfctl_alive" in ids

    @pytest.mark.asyncio
    async def test_run_audit_helper_uses_config(self) -> None:
        """The convenience helper reads eve path + blocklist from config."""
        ssh = _FakeSSH(_default_healthy_responses())
        fake_config = MagicMock()
        fake_config.watcher = {
            "ssh": {"remote_eve_path": "/var/log/suricata/eve.json"},
            "eve_json_path": "/tmp/should-not-be-used",
        }
        fake_config.responder = {"pfsense": {"blocklist_table": "blocklist"}}
        result = await run_audit(ssh=ssh, config=fake_config)  # type: ignore[arg-type]
        assert result.ssh_reachable is True


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


class TestCriticalChecks:
    """Critical checks block the mode-escalation gate — each one must
    correctly detect the broken scenario and be tagged as critical."""

    @pytest.mark.asyncio
    async def test_missing_blocklist_table_is_critical(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_PFCTL_TABLES] = (True, "bogons\nvirusprot\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "pf.blocklist_table")
        assert finding.tier == TIER_CRITICAL
        assert finding.status == STATUS_CRITICAL
        assert finding.category == CAT_PF

    @pytest.mark.asyncio
    async def test_missing_suricata_package_is_critical(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_PKG_SURICATA] = (True, "pkg: No package(s) matching\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.package_installed")
        assert finding.status == STATUS_CRITICAL
        assert finding.category == CAT_SURICATA
        assert result.any_critical_ko is True

    @pytest.mark.asyncio
    async def test_no_suricata_instance_is_critical(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_INSTANCES] = (True, "\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.instance_present")
        assert finding.status == STATUS_CRITICAL

    @pytest.mark.asyncio
    async def test_suricata_not_running_is_critical(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_PIDS] = (True, "\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.process_running")
        assert finding.status == STATUS_CRITICAL

    @pytest.mark.asyncio
    async def test_missing_eve_file_is_critical(self) -> None:
        responses = _default_healthy_responses()
        responses["stat -f '%m %z' '/var/log/suricata/eve.json' 2>&1 || true"] = (
            True,
            "stat: /var/log/suricata/eve.json: No such file or directory\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "output.eve_file_exists")
        assert finding.status == STATUS_CRITICAL


class TestRecommendedChecks:
    """Recommended checks surface tuning opportunities but do not
    block mode escalation."""

    @pytest.mark.asyncio
    async def test_stale_eve_file_is_warning(self) -> None:
        """mtime 10 min ago → warning, not critical."""
        responses = _default_healthy_responses()
        responses["stat -f '%m %z' '/var/log/suricata/eve.json' 2>&1 || true"] = (
            True,
            "1713616200 1048576\n",  # 10 min before "now"
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "output.eve_file_recent")
        assert finding.status == STATUS_WARNING
        assert finding.tier == TIER_RECOMMENDED

    @pytest.mark.asyncio
    async def test_very_stale_eve_file_is_critical(self) -> None:
        """mtime > 30 min ago escalates the severity."""
        responses = _default_healthy_responses()
        responses["stat -f '%m %z' '/var/log/suricata/eve.json' 2>&1 || true"] = (
            True,
            "1713614000 1048576\n",  # > 40 min before "now"
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "output.eve_file_recent")
        assert finding.status == STATUS_CRITICAL
        # But the finding remains in the "recommended" tier per spec —
        # a stale log is a warning signal, not a hard-blocking one, so
        # any_critical_ko is driven by tier + status *together*.
        assert finding.tier == TIER_RECOMMENDED

    @pytest.mark.asyncio
    async def test_ntp_desynced_reports_warning(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_NTPQ] = (True, " pool.ntp.org\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "security.ntp_synced")
        assert finding.status == STATUS_WARNING

    @pytest.mark.asyncio
    async def test_modest_rules_count_is_warning(self) -> None:
        """Between 1 k and 10 k rules → warning (enough to detect
        something but far from an ET Open full load)."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_RULES_COUNT] = (True, "    3200 total\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.rules_loaded")
        assert finding.status == STATUS_WARNING

    @pytest.mark.asyncio
    async def test_near_empty_rules_count_is_critical(self) -> None:
        """< 1 k rules is effectively "no detection" — critical status."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_RULES_COUNT] = (True, "     800 total\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.rules_loaded")
        assert finding.status == STATUS_CRITICAL

    @pytest.mark.asyncio
    async def test_runmode_single_is_warning(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (True, "runmode: single\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.runmode")
        assert finding.status == STATUS_WARNING
        assert "workers" in finding.expected_value

    @pytest.mark.asyncio
    async def test_pcap_on_freebsd_is_ok(self) -> None:
        """v0.8.1 — libpcap on FreeBSD/pfSense is the canonical IDS
        capture method and exactly what WardSOAR needs. It MUST NOT
        trigger a warning, contrary to the v0.8.0 behaviour which
        blindly flagged anything not labelled ``af-packet`` (a
        Linux-only concept)."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\npcap:\n  - interface: igc0\n",
        )
        responses[NetgateAuditor._CMD_UNAME] = (True, "FreeBSD 14.0-RELEASE amd64\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.afpacket")
        assert finding.status == STATUS_OK, finding.current_value
        assert "libpcap" in finding.current_value
        # And the fix description makes clear no action is needed.
        assert "No action needed" in finding.fix_description

    @pytest.mark.asyncio
    async def test_netmap_on_freebsd_is_ok_but_warned_in_text(self) -> None:
        """netmap = inline IPS — bypasses WardSOAR's pipeline. Status
        stays OK (the config itself is valid) but the current_value
        surfaces the WardSOAR implication so the operator reading the
        finding understands the trade-off."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\nnetmap:\n  - interface: igc0\n",
        )
        responses[NetgateAuditor._CMD_UNAME] = (True, "FreeBSD 14.0-RELEASE amd64\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.afpacket")
        assert finding.status == STATUS_OK
        assert "netmap" in finding.current_value
        assert "bypasses WardSOAR" in finding.current_value

    @pytest.mark.asyncio
    async def test_no_capture_method_detected_warns(self) -> None:
        """If the YAML doesn't declare any capture method, something
        is wrong — surface as WARNING so the operator investigates."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (True, "runmode: workers\n")
        responses[NetgateAuditor._CMD_UNAME] = (True, "FreeBSD 14.0-RELEASE amd64\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.afpacket")
        assert finding.status == STATUS_WARNING

    @pytest.mark.asyncio
    async def test_missing_afpacket_on_linux_still_warns(self) -> None:
        """Linux semantics are preserved: libpcap without af-packet
        remains sub-optimal on a Linux Suricata deployment."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\npcap:\n  - interface: eth0\n",
        )
        responses[NetgateAuditor._CMD_UNAME] = (True, "Linux 6.1 x86_64\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.afpacket")
        assert finding.status == STATUS_WARNING

    @pytest.mark.asyncio
    async def test_missing_eve_event_types_is_warning(self) -> None:
        responses = _default_healthy_responses()
        # YAML missing DNS + flow in the types list
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\naf-packet: []\n"
            "outputs:\n"
            "  - eve-log:\n"
            "      types:\n"
            "        - alert\n"
            "        - http\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "output.eve_event_types")
        assert finding.status == STATUS_WARNING


class TestParserRegressionsFromLiveNetgate:
    """Regression tests for the five false positives reported on a live
    pfSense 25.11 Netgate 4200 in v0.7.1. Each test feeds the auditor
    the *exact* shape of output the real box produces and asserts the
    finding comes out healthy.

    Before these fixes, the audit reported "package missing" on a box
    where Suricata was actively writing eve.json with 50 000+ rules
    loaded, "WAN not attached" when Suricata lived on igc2, and
    "parsers / event types / memcap not detected" on a perfectly
    standard pfSense config.
    """

    @pytest.mark.asyncio
    async def test_real_pfsense_pkg_info_output_reports_installed(self) -> None:
        """``pkg info pfSense-pkg-suricata`` prints a multi-line block.

        The previous check used ``pkg info -e`` which yields an empty
        stdout (sets exit code only) -- so the "Name" substring check
        always failed.
        """
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_PKG_SURICATA] = (
            True,
            "pfSense-pkg-suricata-7.0.11_1\n"
            "Name           : pfSense-pkg-suricata\n"
            "Version        : 7.0.11_1\n"
            "Installed on   : Mon Apr 14 2026\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.package_installed")
        assert finding.status == STATUS_OK
        # Version was extracted for the details panel.
        assert "7.0.11" in finding.current_value

    @pytest.mark.asyncio
    async def test_igc2_interface_is_accepted_as_routable(self) -> None:
        """The Netgate 4200 WAN is typically ``igc2`` or ``igc3``.

        The previous check only accepted ``wan / igc0 / igb0 / em0``
        and flagged anything else as a warning.
        """
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_INSTANCES] = (True, "suricata_52678_igc2\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.attached_to_wan")
        assert finding.status == STATUS_OK
        assert "igc2" in finding.current_value

    @pytest.mark.asyncio
    async def test_loopback_instance_still_flagged(self) -> None:
        """``lo0`` / ``pflog0`` bindings genuinely indicate misconfig.

        The relaxation to "any routable interface" must NOT open the
        door to accepting loopback or pflog.
        """
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_INSTANCES] = (True, "suricata_abc_lo0\n")
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.attached_to_wan")
        assert finding.status == STATUS_WARNING

    @pytest.mark.asyncio
    async def test_nested_http_tls_dns_ssh_parsers_are_detected(self) -> None:
        """pfSense's real suricata.yaml nests the parsers under
        ``app-layer.protocols``. The old grep pulled only top-level
        lines (``^`` anchor), so every parser was reported missing.

        Now that :data:`_CMD_SURICATA_YAML` dumps the first 500 lines
        of the file verbatim, the per-parser regex
        ``{proto}:\\s*\\n\\s*enabled:\\s*yes`` matches through the
        indentation.
        """
        realistic_yaml = (
            "default-log-dir: /var/log/suricata/suricata_abc_igc2\n"
            "stats:\n"
            "  enabled: yes\n"
            "outputs:\n"
            "  - eve-log:\n"
            "      enabled: yes\n"
            "      types:\n"
            "        - alert\n"
            "        - dns\n"
            "        - tls\n"
            "        - http\n"
            "        - ssh\n"
            "        - flow\n"
            "  - file-store:\n"
            "      enabled: no\n"
            "app-layer:\n"
            "  protocols:\n"
            "    http:\n"
            "      enabled: yes\n"
            "    tls:\n"
            "      enabled: yes\n"
            "    dns:\n"
            "      enabled: yes\n"
            "    ssh:\n"
            "      enabled: yes\n"
            "stream:\n"
            "  memcap: 64 MB\n"
            "host-mem-cap: 16 MB\n"
            "runmode: workers\n"
            "af-packet:\n"
            "  - interface: igc2\n"
        )
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (True, realistic_yaml)
        result = await _make_auditor(responses).run()

        parsers = _find(result, "suricata.protocol_parsers")
        events = _find(result, "output.eve_event_types")
        memcap = _find(result, "suricata.memcap")

        assert parsers.status == STATUS_OK, parsers.current_value
        assert events.status == STATUS_OK, events.current_value
        assert memcap.status == STATUS_OK, memcap.current_value

    @pytest.mark.asyncio
    async def test_memcap_16mb_is_sane(self) -> None:
        """pfSense ships ``host-mem-cap: 16 MB`` as the default. A
        home Netgate 4200 has plenty of headroom, but 16 MB is the
        factory value and the audit should not flag it."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\naf-packet: []\nhost-mem-cap: 16 MB\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.memcap")
        assert finding.status == STATUS_OK
        assert "16" in (finding.details or "")

    @pytest.mark.asyncio
    async def test_memcap_nested_bytes_form_is_sane(self) -> None:
        """Regression for v0.7.3 — Suricata 7.x / pfSense 25.x writes:

            host:
              memcap: 33554432
              memcap-policy: ignore

        i.e. raw byte integer nested under ``host:``. The v0.7.2
        audit incorrectly reported "not detected" because it only
        matched the legacy ``host-mem-cap: 32mb`` top-level form.
        """
        yaml_body = (
            "runmode: workers\n"
            "af-packet:\n"
            "  - interface: igc2\n"
            "host:\n"
            "  hash-size: 4096\n"
            "  prealloc: 1000\n"
            "  memcap: 33554432\n"  # 32 MB in bytes
            "  memcap-policy: ignore\n"
        )
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (True, yaml_body)
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.memcap")
        assert finding.status == STATUS_OK, finding.current_value
        # 33 554 432 bytes / 1024**2 == 32 MB.
        assert "32 MB" in finding.current_value

    @pytest.mark.asyncio
    async def test_memcap_nested_too_small_warns(self) -> None:
        """2 MB host.memcap is below pfSense default and should warn."""
        yaml_body = (
            "host:\n"
            "  memcap: 2097152\n"  # 2 MB
        )
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (True, yaml_body)
        result = await _make_auditor(responses).run()
        finding = _find(result, "suricata.memcap")
        assert finding.status == STATUS_WARNING


class TestAliasPersistentCheck:
    """Phase 7h audit check: ``pf.alias_persistent``.

    The check distinguishes four states on the pfSense side:

    * ``urltable`` + seed file present → OK (fully migrated)
    * ``urltable`` + seed file missing → WARNING (partial migration —
      re-applying the fix is safe)
    * ``host`` → WARNING (pre-migration; blocks evaporate on reload)
    * ``""`` (alias not in config.xml) → WARNING (operator removed it
      or never created it)

    Only the first is OK; the rest surface as WARNING so the UI nudges
    the operator to click Apply. They stay in the RECOMMENDED tier
    because the in-memory pf table can still be populated — the gate
    does not refuse Protect / Hard Protect on this finding alone.
    """

    @pytest.mark.asyncio
    async def test_urltable_with_seed_is_ok(self) -> None:
        result = await _make_auditor().run()  # default is fully migrated
        finding = _find(result, "pf.alias_persistent")
        assert finding.status == STATUS_OK
        assert finding.tier == TIER_RECOMMENDED
        assert "urltable" in finding.current_value

    @pytest.mark.asyncio
    async def test_host_type_alias_warns(self) -> None:
        """The bug state: alias is still host-type, pfSense wipes our
        blocks on every reload."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_BLOCKLIST_ALIAS_TYPE] = (
            True,
            "host\n---\nseed_missing\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "pf.alias_persistent")
        assert finding.status == STATUS_WARNING
        assert "host" in finding.current_value
        # Fix description steers the operator to the Apply button.
        assert "pf.alias_persistent" in finding.fix_description

    @pytest.mark.asyncio
    async def test_urltable_but_seed_missing_warns(self) -> None:
        """Partial migration — XML was updated but the seed file was
        deleted or never written. Same remedy (re-apply fix)."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_BLOCKLIST_ALIAS_TYPE] = (
            True,
            "urltable\n---\nseed_missing\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "pf.alias_persistent")
        assert finding.status == STATUS_WARNING
        assert "seed file missing" in finding.current_value

    @pytest.mark.asyncio
    async def test_alias_absent_warns(self) -> None:
        """Alias removed from config.xml altogether."""
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_BLOCKLIST_ALIAS_TYPE] = (
            True,
            "\n---\nseed_missing\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "pf.alias_persistent")
        assert finding.status == STATUS_WARNING
        assert "not found" in finding.current_value

    @pytest.mark.asyncio
    async def test_ssh_failure_reports_unknown(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_BLOCKLIST_ALIAS_TYPE] = (False, "timeout")
        result = await _make_auditor(responses).run()
        finding = _find(result, "pf.alias_persistent")
        assert finding.status in {"unknown"}
        # Fix description still nudges the operator, even when the
        # detection could not confirm the state.
        assert "urltable" in finding.fix_description


class TestAdvancedChecks:
    """Advanced checks produce informational or low-priority findings."""

    @pytest.mark.asyncio
    async def test_file_store_off_is_ok(self) -> None:
        result = await _make_auditor().run()
        finding = _find(result, "output.file_store_off")
        assert finding.status == STATUS_OK

    @pytest.mark.asyncio
    async def test_file_store_on_is_warning(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_SURICATA_YAML] = (
            True,
            "runmode: workers\naf-packet: []\n"
            "outputs:\n"
            "  - file-store:\n"
            "      enabled: yes\n",
        )
        result = await _make_auditor(responses).run()
        finding = _find(result, "output.file_store_off")
        assert finding.status == STATUS_WARNING


class TestAuditResultQueries:
    """The derived views of :class:`AuditResult` drive the UI — make
    sure they aggregate correctly."""

    @pytest.mark.asyncio
    async def test_counts_by_tier(self) -> None:
        responses = _default_healthy_responses()
        responses[NetgateAuditor._CMD_PFCTL_TABLES] = (True, "bogons\n")  # force 1 critical
        result = await _make_auditor(responses).run()
        counts = result.counts_by_tier()
        assert counts["critical"].get("critical", 0) >= 1
        assert counts["critical"].get("ok", 0) >= 1

    @pytest.mark.asyncio
    async def test_findings_by_category(self) -> None:
        result = await _make_auditor().run()
        by_cat = result.findings_by_category()
        assert CAT_SURICATA in by_cat
        assert CAT_PF in by_cat
        assert CAT_OUTPUT in by_cat

    @pytest.mark.asyncio
    async def test_any_critical_ko_ignores_non_critical_failures(self) -> None:
        """A warning, even on a critical *tier*, is not a KO."""
        # Stale eve.json → critical STATUS on a recommended TIER → no gate trigger.
        responses = _default_healthy_responses()
        responses["stat -f '%m %z' '/var/log/suricata/eve.json' 2>&1 || true"] = (
            True,
            "1713614000 1048576\n",  # > 40 min old
        )
        result = await _make_auditor(responses).run()
        # The stale-eve finding is critical-status but its tier is "recommended",
        # so the gate should *not* fire on it alone — confirm by cross-checking
        # there are no critical-tier failures.
        critical_fails = [
            f for f in result.findings if f.tier == TIER_CRITICAL and f.status != STATUS_OK
        ]
        assert critical_fails == [], [f.id for f in critical_fails]
        # And the convenience property agrees.
        assert result.any_critical_ko is False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find(result: AuditResult, finding_id: str) -> AuditFinding:
    for f in result.findings:
        if f.id == finding_id:
            return f
    raise AssertionError(f"No finding with id={finding_id!r} in: {[x.id for x in result.findings]}")


# ---------------------------------------------------------------------------
# Sanity on the SSH wrapper we added (run_read_only)
# ---------------------------------------------------------------------------


class TestSshPublicWrapper:
    """``PfSenseSSH.run_read_only`` was added for the auditor — smoke-test
    that it delegates to ``_run_cmd`` with the caller's args."""

    @pytest.mark.asyncio
    async def test_run_read_only_delegates(self) -> None:
        ssh = PfSenseSSH(
            host="127.0.0.1",
            ssh_user="admin",
            ssh_key_path="/tmp/nonexistent-key",
            ssh_port=22,
        )
        ssh._run_cmd = AsyncMock(return_value=(True, "ok"))  # type: ignore[assignment]
        success, out = await ssh.run_read_only("pfctl -s info", timeout=7)
        assert success is True
        assert out == "ok"
        ssh._run_cmd.assert_awaited_once_with("pfctl -s info", timeout=7)
