"""Tests for ``src.pfsense_suricata_tune`` — runmode Apply (Phase 7b.2).

Two layers like ``test_pfsense_alias_migrate``:

* The pure ``patch_runmode`` transform against hand-crafted XML
  fixtures — idempotence, multi-instance handling, unrelated
  ``<rule>`` elements outside Suricata untouched, missing-tag
  insertion path.
* The async orchestrator against a fake SSH: happy-path ordering,
  idempotent no-op when already workers, each failure mode reports
  the correct reason, generated shell is valid POSIX sh.
"""

from __future__ import annotations

import pytest

from src.pfsense_suricata_tune import (
    SuricataTuneResult,
    apply_suricata_runmode,
    patch_runmode,
)

# ---------------------------------------------------------------------------
# XML fixtures — mirror the real pfSense Suricata package layout
# ---------------------------------------------------------------------------


def _suricata_instance(uuid: str = "52678", runmode: str = "autofp") -> str:
    """Realistic minimal Suricata instance record.

    Tabs mimic pfSense's own indent style (4 tabs inside <rule>).
    """
    return (
        "\t\t<rule>\n"
        "\t\t\t<interface>wan</interface>\n"
        "\t\t\t<enable>on</enable>\n"
        f"\t\t\t<uuid>{uuid}</uuid>\n"
        "\t\t\t<descr><![CDATA[WAN]]></descr>\n"
        f"\t\t\t<runmode>{runmode}</runmode>\n"
        "\t\t\t<autofp_scheduler>hash</autofp_scheduler>\n"
        "\t\t\t<max_pending_packets>1024</max_pending_packets>\n"
        "\t\t</rule>\n"
    )


def _suricata_instance_without_runmode(uuid: str = "99999") -> str:
    """An instance missing the ``<runmode>`` tag — rarer but possible
    on older saves. The patcher must insert one."""
    return (
        "\t\t<rule>\n"
        "\t\t\t<interface>opt1</interface>\n"
        f"\t\t\t<uuid>{uuid}</uuid>\n"
        "\t\t\t<enable>on</enable>\n"
        "\t\t</rule>\n"
    )


def _non_suricata_rule() -> str:
    """A sibling ``<rule>`` element in a different section — must be
    left untouched by the patcher. This happens e.g. with pf rules
    which are also stored as <rule>."""
    return (
        "\t\t<rule>\n"
        "\t\t\t<id></id>\n"
        "\t\t\t<tracker>1700000000</tracker>\n"
        "\t\t\t<type>pass</type>\n"
        "\t\t\t<interface>lan</interface>\n"
        "\t\t\t<descr><![CDATA[allow all from LAN]]></descr>\n"
        "\t\t</rule>\n"
    )


def _wrap_in_config(body: str) -> str:
    return "<?xml version='1.0'?>\n<pfsense>\n" + body + "</pfsense>\n"


# ---------------------------------------------------------------------------
# Pure transform
# ---------------------------------------------------------------------------


class TestPatchRunmode:
    def test_flips_single_instance_to_workers(self) -> None:
        xml = _wrap_in_config(_suricata_instance(runmode="autofp"))
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 1
        assert "<runmode>workers</runmode>" in new_xml
        assert "<runmode>autofp</runmode>" not in new_xml

    def test_idempotent_when_already_workers(self) -> None:
        xml = _wrap_in_config(_suricata_instance(runmode="workers"))
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 0
        assert new_xml == xml

    def test_touches_every_instance(self) -> None:
        xml = _wrap_in_config(
            _suricata_instance(uuid="52678", runmode="autofp")
            + _suricata_instance(uuid="99999", runmode="autofp")
        )
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 2
        # Both instances flipped, no stale autofp runmode left. We
        # check the exact tag string rather than the bare "autofp"
        # substring because ``<autofp_scheduler>`` — a sibling tag —
        # legitimately contains "autofp" in its name even after the
        # runmode itself switches to workers.
        assert new_xml.count("<runmode>workers</runmode>") == 2
        assert "<runmode>autofp</runmode>" not in new_xml

    def test_mixed_state_only_changes_outdated(self) -> None:
        """One already workers, one still autofp — only the second
        counts as a change."""
        xml = _wrap_in_config(
            _suricata_instance(uuid="52678", runmode="workers")
            + _suricata_instance(uuid="99999", runmode="autofp")
        )
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 1
        assert new_xml.count("<runmode>workers</runmode>") == 2

    def test_inserts_runmode_when_missing(self) -> None:
        xml = _wrap_in_config(_suricata_instance_without_runmode())
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 1
        assert "<runmode>workers</runmode>" in new_xml

    def test_leaves_non_suricata_rules_untouched(self) -> None:
        """Sibling ``<rule>`` elements (e.g. pf filter rules) share
        the tag name. The patcher MUST NOT touch records that do not
        carry a ``<uuid>``."""
        xml = _wrap_in_config(_non_suricata_rule() + _suricata_instance(runmode="autofp"))
        new_xml, changed = patch_runmode(xml, target="workers")
        assert changed == 1
        # The pf rule is still there, byte-identical.
        assert "<tracker>1700000000</tracker>" in new_xml
        assert "<type>pass</type>" in new_xml
        assert new_xml.count("<runmode>workers</runmode>") == 1

    def test_rejects_invalid_target(self) -> None:
        with pytest.raises(ValueError, match="invalid Suricata runmode"):
            patch_runmode("<pfsense/>", target="single-threaded")

    def test_accepts_autofp_target(self) -> None:
        """Autofp is the safe rollback target — the transform must
        accept it even though workers is the usual choice."""
        xml = _wrap_in_config(_suricata_instance(runmode="workers"))
        new_xml, changed = patch_runmode(xml, target="autofp")
        assert changed == 1
        assert "<runmode>autofp</runmode>" in new_xml

    def test_accepts_single_target(self) -> None:
        xml = _wrap_in_config(_suricata_instance(runmode="workers"))
        _, changed = patch_runmode(xml, target="single")
        assert changed == 1


# ---------------------------------------------------------------------------
# Orchestrator — fake SSH
# ---------------------------------------------------------------------------


class _FakeSSH:
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


class _StatefulSSH:
    """SSH stand-in that lets each ``run_read_only`` call return a
    different scripted response.

    The v0.8.4 orchestrator calls ``grep -E '^runmode:'`` TWICE — once
    as a pre-commit probe and at least once as a post-commit verify.
    These two calls want different answers in most tests (pre = autofp,
    post = workers). ``responses`` is an ordered list of ``(predicate,
    reply)`` tuples; ``predicate`` is either a substring that must
    appear in the command, or ``None`` to match any command. The
    first matching entry is consumed.
    """

    def __init__(self, responses: list[tuple[str | None, tuple[bool, str]]]) -> None:
        self._responses: list[tuple[str | None, tuple[bool, str]]] = list(responses)
        self.calls: list[str] = []

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        self.calls.append(cmd)
        for i, (needle, reply) in enumerate(self._responses):
            if needle is None or needle in cmd:
                self._responses.pop(i)
                return reply
        return (True, "")


class TestApplySuricataRunmode:
    """Orchestrator tests for v0.8.4 (write_config-based flow).

    The new flow is deliberately simple: probe YAML → run PHP commit
    script → verify YAML. No XML surgery in Python, no per-handler
    guesswork about which pfSense internal to invoke.
    """

    @pytest.mark.asyncio
    async def test_happy_path_full_sequence(self) -> None:
        """Pre-probe shows autofp → commit runs → post-verify shows workers."""
        ssh = _StatefulSSH(
            [
                # Pre-commit probe: YAML shows autofp.
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                # Commit payload: PHP write_config + restart.
                (
                    "php <<",
                    (
                        True,
                        "PFSENSE_VERSION=25.11.1-RELEASE\n"
                        "API: config_get_path\n"
                        "RULES_COUNT=1\n"
                        "RULE uuid=52678 runmode_before=autofp\n"
                        "CHANGED=1\n"
                        "ACTION: write_config\n"
                        "REGEN_TARGET=/usr/local/etc/suricata/suricata_52678_igc2/suricata.yaml\n"
                        "ACTION: suricata_create_yaml x1\n"
                        "---\n"
                        "starting WAN\n",
                    ),
                ),
                # Post-commit verify: YAML now shows workers.
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: workers\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]

        assert result.success is True
        assert result.instances_changed == 1
        assert "write_config" in result.message

        # Strict ordering: probe → php commit → verify.
        def _find(needle: str) -> int:
            for i, c in enumerate(ssh.calls):
                if needle in c:
                    return i
            return -1

        idx_probe = _find("grep -E '^runmode:'")
        idx_commit = _find("php <<")
        # Find the SECOND grep occurrence (the verify).
        greps = [i for i, c in enumerate(ssh.calls) if "grep -E '^runmode:'" in c]
        assert len(greps) >= 2, ssh.calls
        idx_verify = greps[-1]
        assert idx_probe < idx_commit < idx_verify, ssh.calls

    @pytest.mark.asyncio
    async def test_already_in_sync_is_true_noop(self) -> None:
        """Pre-probe alone shows target → no commit issued, no restart."""
        ssh = _StatefulSSH(
            [
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: workers\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]

        assert result.success is True
        assert result.instances_changed == 0
        assert "already run with runmode=workers" in result.message
        # No PHP heredoc, no rc.d/suricata touch.
        assert not any("php <<" in c for c in ssh.calls)
        assert not any("rc.d/suricata" in c for c in ssh.calls)

    @pytest.mark.asyncio
    async def test_commit_ssh_failure_is_reported(self) -> None:
        """PHP returning non-zero exit → asyncssh ok=False → clear error."""
        ssh = _StatefulSSH(
            [
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                ("php <<", (False, "PHP Parse error: syntax error, line 5\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "commit (write_config + restart) failed" in result.message

    @pytest.mark.asyncio
    async def test_no_rules_in_config_is_reported(self) -> None:
        """``ACTION: NO_RULES`` in the PHP output → PHP context loaded
        but no Suricata instances exist. Exit 2 → asyncssh ok=False."""
        ssh = _StatefulSSH(
            [
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                ("php <<", (False, "RULES_COUNT=0\nACTION: NO_RULES\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]
        assert result.success is False
        # The error surfaces via the generic commit-failed path since
        # PHP exited non-zero. Either phrasing is acceptable as long
        # as the operator can see the NO_RULES marker in the output.
        assert (
            "NO_RULES" in result.message
            or "commit (write_config + restart) failed" in result.message
        )

    @pytest.mark.asyncio
    async def test_verify_stays_ko_after_retries(self) -> None:
        """PHP commit succeeds but post-verify keeps seeing autofp on
        every retry. We surface the last grep AND the commit output
        tail so the operator has everything needed to diagnose."""
        ssh = _StatefulSSH(
            [
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                (
                    "php <<",
                    (
                        True,
                        "RULES_COUNT=1\n"
                        "CHANGED=1\n"
                        "ACTION: write_config\n"
                        "ACTION: suricata_create_yaml x1\n",
                    ),
                ),
                # All 4 verify retries hit the same stale YAML.
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: autofp\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]
        assert result.success is False
        assert "verify failed" in result.message
        # Enrichment: message carries evidence from both sides.
        assert "runmode: autofp" in result.message
        assert "write_config" in result.message

    @pytest.mark.asyncio
    async def test_invalid_target_short_circuits(self) -> None:
        ssh = _StatefulSSH([])
        result = await apply_suricata_runmode(ssh, target="nonsense")  # type: ignore[arg-type]
        assert result.success is False
        assert "invalid runmode target" in result.message
        # No SSH call issued.
        assert ssh.calls == []

    @pytest.mark.asyncio
    async def test_probe_ssh_failure_still_runs_commit(self) -> None:
        """If the pre-probe grep errors, we continue to the commit
        rather than failing hard — the commit itself will verify
        success at the end. Previously a probe failure would've
        masked a perfectly legitimate drift recovery."""
        ssh = _StatefulSSH(
            [
                ("grep -E '^runmode:'", (False, "ssh timeout")),
                (
                    "php <<",
                    (
                        True,
                        "RULES_COUNT=1\n"
                        "CHANGED=1\n"
                        "ACTION: write_config\n"
                        "ACTION: suricata_create_yaml x1\n",
                    ),
                ),
                ("grep -E '^runmode:'", (True, "/path.yaml:runmode: workers\n")),
            ]
        )
        result = await apply_suricata_runmode(ssh)  # type: ignore[arg-type]
        assert result.success is True
        assert any("php <<" in c for c in ssh.calls)


# ---------------------------------------------------------------------------
# Shell-syntax regression — push_cmd must survive ``sh -n``.
# ---------------------------------------------------------------------------


class TestPushCmdShellSyntax:
    """Guards the same ``&&``-after-heredoc class of bugs we hit in
    the Phase 7h alias_migrate push_cmd. Every multi-line script
    built by the orchestrator is piped through ``sh -n`` for parse
    validation."""

    @staticmethod
    def _run_sh_n(script: str) -> tuple[bool, str]:
        import shutil
        import subprocess

        sh_path = shutil.which("sh")
        if sh_path is None:  # pragma: no cover
            pytest.skip("POSIX sh unavailable")
        # Bandit S603/S607 suppressed: test-only, parse mode, no
        # operator input flows.
        proc = subprocess.run(  # nosec B603 B607
            [sh_path, "-n"],
            input=script,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0, proc.stderr

    @pytest.mark.asyncio
    async def test_commit_script_parses_in_posix_sh(self) -> None:
        """The v0.8.4 orchestrator issues exactly ONE heredoc payload
        (the PHP commit script + rc.d restart). That payload must
        survive ``sh -n`` so we don't re-introduce the ``&&``-after-
        heredoc class of bug we hit in v0.8.0."""
        captured: list[str] = []

        class _CaptureSSH:
            async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
                captured.append(cmd)
                if "php <<" in cmd:
                    return (
                        True,
                        "RULES_COUNT=1\n"
                        "CHANGED=1\n"
                        "ACTION: write_config\n"
                        "ACTION: suricata_create_yaml x1\n",
                    )
                if "grep -E '^runmode:'" in cmd:
                    # First call = probe (autofp), subsequent = verify (workers).
                    already_committed = any("php <<" in c for c in captured[:-1])
                    if already_committed:
                        return (True, "/path.yaml:runmode: workers\n")
                    return (True, "/path.yaml:runmode: autofp\n")
                return (True, "")

        result = await apply_suricata_runmode(_CaptureSSH())  # type: ignore[arg-type]
        assert result.success is True

        heredoc_scripts = [s for s in captured if "<<" in s]
        # Exactly one: the PHP commit payload. No XML push anymore.
        assert len(heredoc_scripts) == 1, captured
        for script in heredoc_scripts:
            ok, stderr = self._run_sh_n(script)
            assert ok, f"sh -n rejected:\n{stderr}\n---\n{script}"


def test_result_is_frozen() -> None:
    result = SuricataTuneResult(True, 1, "ok")
    with pytest.raises((AttributeError, TypeError, Exception)):
        result.success = False  # type: ignore[misc]
