"""Tests for ``src.pfsense_alias_migrate``.

Two layers:

* The pure ``migrate_xml_in_place`` transform is exercised against
  hand-crafted mini-configs — no SSH, no filesystem. Every shape
  the operator might legitimately see in pfSense 24+/25.x config.xml
  is covered.
* The async orchestrator ``migrate_alias_to_urltable`` is exercised
  against a programmable fake SSH that records the exact command
  batch, so regressions in the 7-step order surface as failed
  ordering assertions.
"""

from __future__ import annotations

import pytest

from src.pfsense_alias_migrate import (
    AliasMigrationResult,
    REMOTE_CONFIG_XML_PATH,
    migrate_alias_to_urltable,
    migrate_xml_in_place,
)
from src.pfsense_aliastable import DEFAULT_ALIAS_DIR, DEFAULT_ALIAS_FILE_PATH

# ---------------------------------------------------------------------------
# Fixtures — mini config.xml snippets
# ---------------------------------------------------------------------------


def _host_alias(address: str = "") -> str:
    """Build a realistic pfSense host-type alias block.

    Real ``config.xml`` indents with tabs; we mirror that so regex
    tests exercise the actual whitespace pattern.
    """
    return (
        "<aliases>\n"
        "\t\t<alias>\n"
        "\t\t\t<name>blocklist</name>\n"
        "\t\t\t<type>host</type>\n"
        "\t\t\t<address>" + address + "</address>\n"
        "\t\t\t<descr>WardSOAR blocklist</descr>\n"
        "\t\t\t<detail>WardSOAR</detail>\n"
        "\t\t</alias>\n"
        "</aliases>\n"
    )


def _urltable_alias() -> str:
    """An already-migrated alias block — migration must no-op on it."""
    return (
        "<aliases>\n"
        "\t\t<alias>\n"
        "\t\t\t<name>blocklist</name>\n"
        "\t\t\t<type>urltable</type>\n"
        "\t\t\t<url>file:///var/db/aliastables/wardsoar_blocklist.txt</url>\n"
        "\t\t\t<updatefreq>1</updatefreq>\n"
        "\t\t\t<descr>WardSOAR blocklist</descr>\n"
        "\t\t</alias>\n"
        "</aliases>\n"
    )


def _sibling_alias() -> str:
    """An unrelated alias that MUST be left untouched by the migration."""
    return (
        "\t\t<alias>\n"
        "\t\t\t<name>admin_nets</name>\n"
        "\t\t\t<type>network</type>\n"
        "\t\t\t<address>10.0.0.0/24</address>\n"
        "\t\t</alias>\n"
    )


# ---------------------------------------------------------------------------
# Pure transform
# ---------------------------------------------------------------------------


class TestMigrateXmlInPlace:
    def test_flips_type_to_urltable(self) -> None:
        xml = _host_alias()
        new_xml, preserved = migrate_xml_in_place(xml)
        assert "<type>urltable</type>" in new_xml
        assert "<type>host</type>" not in new_xml
        assert preserved == []

    def test_removes_address_element(self) -> None:
        xml = _host_alias("1.2.3.4 5.6.7.8")
        new_xml, preserved = migrate_xml_in_place(xml)
        assert "<address>" not in new_xml
        # The two IPs are reported so the caller can seed them into
        # the url-table file.
        assert preserved == ["1.2.3.4", "5.6.7.8"]

    def test_inserts_url_and_updatefreq(self) -> None:
        xml = _host_alias()
        new_xml, _ = migrate_xml_in_place(xml)
        assert "<url>file://" + DEFAULT_ALIAS_FILE_PATH + "</url>" in new_xml
        assert "<updatefreq>1</updatefreq>" in new_xml

    def test_idempotent_on_already_urltable(self) -> None:
        """A second migration must be a byte-identical no-op."""
        xml = _urltable_alias()
        new_xml, preserved = migrate_xml_in_place(xml)
        assert new_xml == xml
        assert preserved == []

    def test_noop_on_missing_alias(self) -> None:
        xml = (
            "<aliases>\n"
            "\t\t<alias>\n"
            "\t\t\t<name>other_alias</name>\n"
            "\t\t\t<type>host</type>\n"
            "\t\t</alias>\n"
            "</aliases>\n"
        )
        new_xml, preserved = migrate_xml_in_place(xml, alias_name="blocklist")
        assert new_xml == xml
        assert preserved == []

    def test_leaves_sibling_aliases_untouched(self) -> None:
        xml = (
            "<aliases>\n"
            + _sibling_alias()
            + "\t\t<alias>\n"
            + "\t\t\t<name>blocklist</name>\n"
            + "\t\t\t<type>host</type>\n"
            + "\t\t\t<address></address>\n"
            + "\t\t</alias>\n"
            + "</aliases>\n"
        )
        new_xml, _ = migrate_xml_in_place(xml)
        # Sibling preserved byte-identical.
        assert "<name>admin_nets</name>" in new_xml
        assert "<address>10.0.0.0/24</address>" in new_xml
        # Target alias migrated.
        assert "<type>urltable</type>" in new_xml

    def test_custom_alias_name(self) -> None:
        xml = (
            "<aliases>\n"
            "\t\t<alias>\n"
            "\t\t\t<name>custom_drop</name>\n"
            "\t\t\t<type>host</type>\n"
            "\t\t\t<address>9.9.9.9</address>\n"
            "\t\t</alias>\n"
            "</aliases>\n"
        )
        new_xml, preserved = migrate_xml_in_place(xml, alias_name="custom_drop")
        assert "<type>urltable</type>" in new_xml
        assert preserved == ["9.9.9.9"]

    def test_preserves_ips_with_tabs_and_spaces(self) -> None:
        xml = _host_alias("1.2.3.4\t5.6.7.8  9.9.9.9")
        _, preserved = migrate_xml_in_place(xml)
        assert preserved == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]

    def test_preserves_ips_empty_address_tag(self) -> None:
        """The common post-install shape: the alias exists but its
        ``<address>`` is empty."""
        xml = _host_alias("")
        _, preserved = migrate_xml_in_place(xml)
        assert preserved == []

    def test_removes_stale_url_tag_before_insertion(self) -> None:
        """Defensive: if a previous partial migration left a ``<url>``
        tag in an otherwise host-type alias, the re-migration must not
        duplicate it."""
        xml = (
            "<aliases>\n"
            "\t\t<alias>\n"
            "\t\t\t<name>blocklist</name>\n"
            "\t\t\t<type>host</type>\n"
            "\t\t\t<address>10.0.0.1</address>\n"
            "\t\t\t<url>file:///tmp/stale.txt</url>\n"
            "\t\t\t<updatefreq>7</updatefreq>\n"
            "\t\t</alias>\n"
            "</aliases>\n"
        )
        new_xml, preserved = migrate_xml_in_place(xml)
        assert new_xml.count("<url>") == 1
        assert "file:///tmp/stale.txt" not in new_xml
        assert DEFAULT_ALIAS_FILE_PATH in new_xml
        assert "<updatefreq>1</updatefreq>" in new_xml
        assert "<updatefreq>7</updatefreq>" not in new_xml
        assert preserved == ["10.0.0.1"]


# ---------------------------------------------------------------------------
# Orchestrator — fake SSH
# ---------------------------------------------------------------------------


class _FakeSSH:
    """Same shape as the fake used in test_pfsense_aliastable."""

    def __init__(
        self,
        responses: dict[str, tuple[bool, str]] | None = None,
        default: tuple[bool, str] = (True, ""),
    ) -> None:
        self._responses = responses or {}
        self._default = default
        self.calls: list[str] = []

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        self.calls.append(cmd)
        for needle, reply in self._responses.items():
            if needle in cmd:
                return reply
        return self._default


class TestMigrateOrchestrator:
    @pytest.mark.asyncio
    async def test_full_success_path_issues_seven_steps_in_order(self) -> None:
        """Full happy path: pull config → seed file → push XML → reload
        → pfctl replace → verify. The ordering matters (seeding before
        push avoids a transient ``file missing`` error in pfSense logs)
        so we assert index ordering, not just set membership."""
        host_xml = _host_alias("1.2.3.4 5.6.7.8")
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, host_xml),
                # verify phase: pfctl -s Tables + wc -l
                "pfctl -s Tables": (True, "blocklist\n---\n2\n"),
            },
            default=(True, ""),
        )

        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]

        assert result.success is True
        assert result.preserved_entries == 2

        def _find(needle: str) -> int:
            for i, c in enumerate(ssh.calls):
                if needle in c:
                    return i
            return -1

        idx_read = _find(f"cat {REMOTE_CONFIG_XML_PATH}")
        idx_seed = _find(f"cat > {DEFAULT_ALIAS_FILE_PATH}")
        idx_push = _find(f"cat > {REMOTE_CONFIG_XML_PATH}.tmp")
        idx_reload = _find("/etc/rc.filter_configure")
        idx_replace = _find("pfctl -t blocklist -T replace")
        idx_verify = _find("pfctl -s Tables")

        assert idx_read < idx_seed < idx_push < idx_reload < idx_replace < idx_verify, ssh.calls

    @pytest.mark.asyncio
    async def test_already_urltable_is_no_op_success(self) -> None:
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, _urltable_alias()),
            }
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is True
        assert result.preserved_entries == 0
        assert "no change needed" in result.message
        # Critically: nothing beyond the single read was attempted.
        assert len(ssh.calls) == 1

    @pytest.mark.asyncio
    async def test_config_read_failure_aborts(self) -> None:
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (False, "permission denied"),
            }
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "failed to read config.xml" in result.message

    @pytest.mark.asyncio
    async def test_seed_failure_short_circuits_before_push(self) -> None:
        """If the seed step fails, we MUST NOT push the new XML.
        Otherwise pfSense would apply a url-table alias pointing at a
        file we never wrote, which in the transient window between
        push and seed could surface spurious alerts."""
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, _host_alias("1.2.3.4")),
                f"mkdir -p {DEFAULT_ALIAS_DIR}": (False, "read-only fs"),
            },
            default=(True, ""),
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "could not seed alias file" in result.message
        # No XML push was attempted.
        assert not any(f"cat > {REMOTE_CONFIG_XML_PATH}.tmp" in c for c in ssh.calls)

    @pytest.mark.asyncio
    async def test_push_failure_is_reported(self) -> None:
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, _host_alias()),
                f"cat > {REMOTE_CONFIG_XML_PATH}.tmp": (False, "disk full"),
            },
            default=(True, ""),
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "config.xml push failed" in result.message

    @pytest.mark.asyncio
    async def test_reload_failure_is_reported(self) -> None:
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, _host_alias()),
                "/etc/rc.filter_configure": (False, "pfSense config reload aborted"),
            },
            default=(True, ""),
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "pfSense filter reload failed" in result.message

    @pytest.mark.asyncio
    async def test_final_verify_failure_reports_ko(self) -> None:
        """The 7th step checks ``pfctl -s Tables`` still lists our
        alias. If it doesn't, the migration is reported as failed so
        NetgateApplier can restore the XML backup."""
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, _host_alias()),
                "pfctl -s Tables": (True, "bogons\n---\n0\n"),  # no blocklist
            },
            default=(True, ""),
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "post-migration verification" in result.message

    @pytest.mark.asyncio
    async def test_heredoc_sentinel_collision_refuses_push(self) -> None:
        """A crafted config.xml containing our sentinel would break the
        heredoc and land the Netgate in half-written state — so we
        refuse rather than attempt the write."""
        poisoned = _host_alias("1.2.3.4") + "\n<!-- __WARDSOAR_XML_EOF__ -->\n"
        ssh = _FakeSSH(
            responses={
                f"cat {REMOTE_CONFIG_XML_PATH}": (True, poisoned),
            },
            default=(True, ""),
        )
        result = await migrate_alias_to_urltable(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "heredoc sentinel" in result.message


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


def test_result_is_frozen() -> None:
    result = AliasMigrationResult(True, 0, "ok")
    with pytest.raises((AttributeError, TypeError, Exception)):
        result.success = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Shell-syntax regression — guards the ``&&``-after-heredoc bug.
# ---------------------------------------------------------------------------


class TestGeneratedScriptsParseInPosixSh:
    """Validate every multi-line SSH script the orchestrator issues.

    The first v0.8.0 MSI shipped with a shell-syntax bug: the
    ``push_cmd`` placed ``&& mv …`` on a line BY ITSELF after the
    heredoc terminator, which POSIX sh rejects ("syntax error near
    unexpected token '&&'"). The Netgate accepted the SSH command
    but the shell's ash failed to parse it, so Apply returned "apply
    handler reported failure" with no diagnostic. Piping every
    generated script through ``sh -n`` (parse-only) catches the
    regression before it ships.
    """

    @staticmethod
    def _run_sh_n(script: str) -> tuple[bool, str]:
        import shutil
        import subprocess

        sh_path = shutil.which("sh")
        if sh_path is None:  # pragma: no cover
            pytest.skip("POSIX sh unavailable — cannot validate syntax")
        # Bandit S603/S607 suppressed: parse-only, absolute path, no
        # operator input flows through.
        proc = subprocess.run(  # nosec B603 B607
            [sh_path, "-n"],
            input=script,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0, proc.stderr

    @pytest.mark.asyncio
    async def test_all_migration_scripts_are_valid_sh(self) -> None:
        captured: list[str] = []

        class _CaptureSSH:
            async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
                captured.append(cmd)
                # Drive the orchestrator through every step by
                # returning the happy-path output for each command.
                if f"cat {REMOTE_CONFIG_XML_PATH}" in cmd and "<<" not in cmd:
                    return (True, _host_alias("1.2.3.4"))
                if "pfctl -s Tables" in cmd:
                    return (True, "blocklist\n---\n1\n")
                return (True, "")

        result = await migrate_alias_to_urltable(_CaptureSSH())  # type: ignore[arg-type]
        assert result.success is True, result.message

        # Not every captured command is a multi-line script — the
        # single-line ones are trivially valid, but parsing them
        # through sh -n doesn't hurt. What we really guard here is
        # any script that carries a heredoc (`<<`), because that is
        # the only place the `&&`-on-new-line bug could re-appear.
        heredoc_scripts = [s for s in captured if "<<" in s]
        assert heredoc_scripts, "orchestrator did not issue a heredoc script"
        for script in heredoc_scripts:
            ok, stderr = self._run_sh_n(script)
            assert ok, f"sh -n rejected:\n{stderr}\n---\n{script}"
