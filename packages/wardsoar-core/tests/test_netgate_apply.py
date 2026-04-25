"""Tests for Phase 7b — Netgate safe-apply.

The module ships three SSH-only handlers and an infrastructure layer
(backup, verify, rollback). Every path in the infrastructure is
exercised here against a fake SSH so no Netgate is ever touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardsoar.core.netgate_apply import (
    HandlerSpec,
    NetgateApplier,
    applicable_fix_ids,
)

# ---------------------------------------------------------------------------
# Fake SSH — records every command so tests can assert on call order.
# ---------------------------------------------------------------------------


class _FakeSSH:
    """Programmable ``NetgateAgent`` stand-in for the safe-apply harness.

    Mirrors only the surface the ``NetgateApplier`` and shipped handlers
    actually call — ``run_read_only`` for SSH-style probes plus the two
    Netgate-specific operations (``migrate_alias_to_urltable``,
    ``apply_suricata_runmode``) that wrap the legacy free functions.
    The ``apply_*_result`` knobs let a test pre-program the outcome the
    Netgate-specific handlers should observe without faking the underlying
    free function.
    """

    def __init__(
        self,
        responses: dict[str, tuple[bool, str]] | None = None,
        default: tuple[bool, str] = (True, ""),
        migrate_alias_result: object | None = None,
        suricata_runmode_result: object | None = None,
    ) -> None:
        self._responses = responses or {}
        self._default = default
        self.calls: list[str] = []
        self._host = "fake-netgate"
        self._migrate_alias_result = migrate_alias_result
        self._suricata_runmode_result = suricata_runmode_result
        self.migrate_alias_calls: int = 0
        self.suricata_runmode_calls: list[str] = []

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        self.calls.append(cmd)
        for needle, reply in self._responses.items():
            if needle in cmd:
                return reply
        return self._default

    async def migrate_alias_to_urltable(self, alias_name: str = "blocklist") -> object:
        from wardsoar.core.remote_agents.pfsense_alias_migrate import AliasMigrationResult

        self.migrate_alias_calls += 1
        if self._migrate_alias_result is not None:
            return self._migrate_alias_result
        return AliasMigrationResult(success=True, preserved_entries=0, message="fake ok")

    async def apply_suricata_runmode(self, target: str = "workers") -> object:
        from wardsoar.core.remote_agents.pfsense_suricata_tune import SuricataTuneResult

        self.suricata_runmode_calls.append(target)
        if self._suricata_runmode_result is not None:
            return self._suricata_runmode_result
        return SuricataTuneResult(success=True, instances_changed=1, message="fake ok")


def _make_applier(tmp_path: Path, ssh: _FakeSSH | None = None) -> NetgateApplier:
    return NetgateApplier(
        ssh=ssh or _FakeSSH(),  # type: ignore[arg-type]
        backup_dir=tmp_path / "backups",
    )


# ===========================================================================
# Handler registry surface
# ===========================================================================


class TestHandlerRegistry:
    def test_applicable_fix_ids_ships_five_handlers(self) -> None:
        ids = applicable_fix_ids()
        # v0.7.1: three SSH-only handlers.
        assert "suricata.rules_loaded" in ids
        assert "suricata.process_running" in ids
        assert "pf.blocklist_table" in ids
        # v0.8.0: one config.xml-touching handler for the persistent
        # blocklist migration (Phase 7h).
        assert "pf.alias_persistent" in ids
        # v0.8.1: Suricata runmode tuning (Phase 7b.2).
        assert "suricata.runmode" in ids

    def test_unknown_fix_id_yields_failure_without_ssh_calls(self, tmp_path: Path) -> None:
        ssh = _FakeSSH()
        applier = _make_applier(tmp_path, ssh)
        import asyncio

        result = asyncio.run(applier.safe_apply("does.not.exist"))
        assert result.success is False
        assert result.backup_created is False
        assert "No registered handler" in (result.error or "")
        assert ssh.calls == []


# ===========================================================================
# Config.xml backup + rotation
# ===========================================================================


class TestConfigBackup:
    @pytest.mark.asyncio
    async def test_backup_writes_file_on_touches_config_handler(self, tmp_path: Path) -> None:
        """A handler flagged ``touches_config_xml=True`` triggers a backup.

        The shipped handlers are SSH-only, so we inject a throwaway
        registry entry to exercise the backup path directly.
        """
        from wardsoar.core import netgate_apply

        async def _apply(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        stub = HandlerSpec(
            apply_fn=_apply,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=True,
            description="test stub",
        )
        netgate_apply._HANDLERS["test.touches_config"] = stub
        try:
            ssh = _FakeSSH(
                responses={
                    "cat /cf/conf/config.xml": (
                        True,
                        "<?xml version='1.0'?>\n<pfsense>test</pfsense>\n",
                    ),
                }
            )
            applier = _make_applier(tmp_path, ssh)
            result = await applier.safe_apply("test.touches_config")
            assert result.success is True
            assert result.backup_created is True
            assert result.backup is not None
            assert result.backup.path.exists()
            assert result.backup.size_bytes > 0
        finally:
            netgate_apply._HANDLERS.pop("test.touches_config", None)

    @pytest.mark.asyncio
    async def test_ssh_only_handler_skips_backup(self, tmp_path: Path) -> None:
        """``touches_config_xml=False`` handlers must NOT take a backup.

        Validated via the shipped ``suricata.process_running`` handler:
        only the apply + verify commands appear in the call trace,
        not the ``cat /cf/conf/config.xml`` round trip.
        """
        ssh = _FakeSSH(
            default=(True, "12345 /usr/local/bin/suricata -c x"),
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("suricata.process_running")
        assert result.success is True
        assert result.backup_created is False
        joined = "\n".join(ssh.calls)
        assert "cat /cf/conf/config.xml" not in joined

    @pytest.mark.asyncio
    async def test_backup_rotation_keeps_at_most_max(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:

        from wardsoar.core import netgate_apply

        # Small cap so we can assert behaviour cheaply.
        monkeypatch.setattr(netgate_apply, "_MAX_BACKUPS", 3)

        async def _apply(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        stub = HandlerSpec(
            apply_fn=_apply,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=True,
            description="stub",
        )
        netgate_apply._HANDLERS["test.rotation"] = stub
        try:
            ssh = _FakeSSH(
                responses={
                    "cat /cf/conf/config.xml": (True, "<pfsense/>\n"),
                }
            )
            applier = _make_applier(tmp_path, ssh)
            for i in range(6):
                # Different reasons → different filenames so each
                # iteration yields a fresh file (same-second collisions
                # would otherwise replace rather than accumulate).
                stub_with_suffix = HandlerSpec(
                    apply_fn=_apply,  # type: ignore[arg-type]
                    verify_fn=_verify,  # type: ignore[arg-type]
                    touches_config_xml=True,
                    description=f"stub {i}",
                )
                fix_id = f"test.rotation.{i}"
                netgate_apply._HANDLERS[fix_id] = stub_with_suffix
                await applier.safe_apply(fix_id)
            backups = list((tmp_path / "backups").glob("config_*.xml"))
            assert len(backups) <= 3
        finally:
            netgate_apply._HANDLERS.pop("test.rotation", None)
            for i in range(6):
                netgate_apply._HANDLERS.pop(f"test.rotation.{i}", None)


# ===========================================================================
# Verify + rollback
# ===========================================================================


class TestVerifyAndRollback:
    @pytest.mark.asyncio
    async def test_verify_failure_triggers_rollback_when_backup_exists(
        self, tmp_path: Path
    ) -> None:
        """Apply succeeds but verify fails → backup must be restored."""
        from wardsoar.core import netgate_apply

        async def _apply(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "mutation applied"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return False, "still KO"

        stub = HandlerSpec(
            apply_fn=_apply,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=True,
            description="stub",
        )
        netgate_apply._HANDLERS["test.rollback"] = stub
        try:
            ssh = _FakeSSH(
                responses={
                    "cat /cf/conf/config.xml": (True, "<pfsense/>\n"),
                }
            )
            applier = _make_applier(tmp_path, ssh)
            result = await applier.safe_apply("test.rollback")
            assert result.success is False
            assert result.verify_passed is False
            assert result.rollback_performed is True
            # A restore command with the heredoc sentinel was sent.
            assert any("__WARDSOAR_CFG_EOF__" in c for c in ssh.calls)
        finally:
            netgate_apply._HANDLERS.pop("test.rollback", None)

    @pytest.mark.asyncio
    async def test_ssh_only_verify_failure_no_rollback(self, tmp_path: Path) -> None:
        """SSH-only handlers never backed up → no rollback is attempted."""
        from wardsoar.core import netgate_apply

        async def _apply(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return False, "still broken"

        stub = HandlerSpec(
            apply_fn=_apply,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=False,
            description="stub",
        )
        netgate_apply._HANDLERS["test.ssh_only_fail"] = stub
        try:
            ssh = _FakeSSH()
            applier = _make_applier(tmp_path, ssh)
            result = await applier.safe_apply("test.ssh_only_fail")
            assert result.success is False
            assert result.backup_created is False
            assert result.rollback_performed is False
        finally:
            netgate_apply._HANDLERS.pop("test.ssh_only_fail", None)

    @pytest.mark.asyncio
    async def test_backup_empty_remote_aborts_mutation(self, tmp_path: Path) -> None:
        """If ``cat config.xml`` returns empty, we refuse to mutate.

        This guards against catting an empty / corrupted config right
        before writing over it -- the backup would be useless.
        """
        from wardsoar.core import netgate_apply

        async def _apply(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "should never run"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "should never run"

        stub = HandlerSpec(
            apply_fn=_apply,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=True,
            description="stub",
        )
        netgate_apply._HANDLERS["test.empty_config"] = stub
        try:
            ssh = _FakeSSH(
                responses={
                    "cat /cf/conf/config.xml": (True, ""),  # empty read
                }
            )
            applier = _make_applier(tmp_path, ssh)
            result = await applier.safe_apply("test.empty_config")
            assert result.success is False
            assert result.backup_created is False
            assert "back up" in (result.error or "").lower()
        finally:
            netgate_apply._HANDLERS.pop("test.empty_config", None)


# ===========================================================================
# Shipped SSH-only handlers
# ===========================================================================


class TestShippedHandlers:
    @pytest.mark.asyncio
    async def test_rules_loaded_success_path(self, tmp_path: Path) -> None:
        """Apply runs the updater, verify parses the rules count."""
        ssh = _FakeSSH(
            responses={
                "suricata_updaterules": (True, "Rules updated successfully"),
                "find /usr/local/etc/suricata": (True, "   48521 total\n"),
            }
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("suricata.rules_loaded")
        assert result.success is True
        assert result.verify_passed is True

    @pytest.mark.asyncio
    async def test_rules_loaded_low_count_fails_verify(self, tmp_path: Path) -> None:
        ssh = _FakeSSH(
            responses={
                "suricata_updaterules": (True, "updated"),
                "find /usr/local/etc/suricata": (True, "    800 total\n"),
            }
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("suricata.rules_loaded")
        assert result.success is False
        assert result.verify_passed is False

    @pytest.mark.asyncio
    async def test_suricata_start_success(self, tmp_path: Path) -> None:
        ssh = _FakeSSH(
            responses={
                "rc.d/suricata start": (True, "starting"),
                "pgrep -lf '^/usr/local/bin/suricata'": (
                    True,
                    "12345 /usr/local/bin/suricata -c x\n",
                ),
            },
            default=(True, "12345 /usr/local/bin/suricata -c x"),
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("suricata.process_running")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_blocklist_table_create_then_verify(self, tmp_path: Path) -> None:
        ssh = _FakeSSH(
            responses={
                "pfctl -t blocklist -T create": (True, "1 table(s) created"),
                "pfctl -s Tables": (True, "blocklist\nbogons\n"),
            },
            default=(True, ""),
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("pf.blocklist_table")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_alias_persistent_takes_backup_then_migrates(self, tmp_path: Path) -> None:
        """``pf.alias_persistent`` must be config-XML-touching, so the
        applier pulls a full backup before letting the migration run.

        We wire the fake SSH to satisfy the 7-step migration
        orchestrator (cat config.xml → seed file → push XML → reload
        → pfctl replace → verify) AND the applier's own verify step.
        """
        host_alias_xml = (
            "<?xml version='1.0'?>\n"
            "<pfsense>\n"
            "\t<aliases>\n"
            "\t\t<alias>\n"
            "\t\t\t<name>blocklist</name>\n"
            "\t\t\t<type>host</type>\n"
            "\t\t\t<address>1.2.3.4</address>\n"
            "\t\t\t<descr>WardSOAR blocklist</descr>\n"
            "\t\t</alias>\n"
            "\t</aliases>\n"
            "</pfsense>\n"
        )
        ssh = _FakeSSH(
            responses={
                # Applier's backup command — FIRST call against config.xml.
                "cat /cf/conf/config.xml 2>/dev/null || true": (True, host_alias_xml),
                # Migration orchestrator reads the same path with a
                # slightly different redirect. Match it too.
                "cat /cf/conf/config.xml 2>/dev/null": (True, host_alias_xml),
                # pfctl -s Tables is called both by the migration's
                # verify step (step 7) AND by the applier's verify_fn
                # when it doesn't match the grep pipeline — return a
                # reasonable table listing.
                "pfctl -s Tables": (True, "blocklist\n---\n1\n"),
                # Post-migration verifier: composed grep|test. Must
                # report "OK" so the applier's verify_fn accepts.
                "grep -A 5 '<name>blocklist</name>'": (True, "OK\n"),
            },
            default=(True, ""),
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("pf.alias_persistent")

        assert result.backup_created is True
        assert result.backup is not None
        assert result.backup.path.exists()
        # Full migration ran to completion and verified.
        assert result.success is True
        assert result.verify_passed is True
        assert result.rollback_performed is False

    @pytest.mark.asyncio
    async def test_alias_persistent_verify_failure_triggers_rollback(self, tmp_path: Path) -> None:
        """If the final verifier reports KO, the config.xml backup must
        be restored — otherwise we'd leave the Netgate in a partially
        migrated state."""
        host_alias_xml = (
            "<?xml version='1.0'?>\n"
            "<pfsense>\n"
            "\t<aliases>\n"
            "\t\t<alias>\n"
            "\t\t\t<name>blocklist</name>\n"
            "\t\t\t<type>host</type>\n"
            "\t\t\t<address></address>\n"
            "\t\t</alias>\n"
            "\t</aliases>\n"
            "</pfsense>\n"
        )
        ssh = _FakeSSH(
            responses={
                "cat /cf/conf/config.xml 2>/dev/null || true": (True, host_alias_xml),
                "cat /cf/conf/config.xml 2>/dev/null": (True, host_alias_xml),
                "pfctl -s Tables": (True, "blocklist\n---\n0\n"),
                # Verifier reports KO — the alias block still says
                # "host" (simulating a Netgate that silently reverted
                # the XML during filter_configure).
                "grep -A 5 '<name>blocklist</name>'": (True, "KO xml=1 file=0\n"),
            },
            default=(True, ""),
        )
        applier = _make_applier(tmp_path, ssh)
        result = await applier.safe_apply("pf.alias_persistent")

        assert result.success is False
        assert result.verify_passed is False
        assert result.rollback_performed is True
        # The restore heredoc appears in the call trace.
        assert any("__WARDSOAR_CFG_EOF__" in c for c in ssh.calls)


# ===========================================================================
# safe_apply_many ordering + early stop
# ===========================================================================


class TestSafeApplyMany:
    @pytest.mark.asyncio
    async def test_runs_in_order(self, tmp_path: Path) -> None:
        ssh = _FakeSSH(
            responses={
                "suricata_updaterules": (True, ""),
                "find /usr/local/etc/suricata": (True, "    48521 total\n"),
                "rc.d/suricata start": (True, ""),
                "pgrep -lf '^/usr/local/bin/suricata'": (
                    True,
                    "111 /usr/local/bin/suricata -c x\n",
                ),
                "pfctl -t blocklist -T create": (True, ""),
                "pfctl -s Tables": (True, "blocklist\n"),
            },
            default=(True, ""),
        )
        applier = _make_applier(tmp_path, ssh)
        ids = [
            "suricata.rules_loaded",
            "suricata.process_running",
            "pf.blocklist_table",
        ]
        results = await applier.safe_apply_many(ids)
        assert [r.fix_id for r in results] == ids
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_halts_when_a_non_rollback_failure_happens(self, tmp_path: Path) -> None:
        """An SSH-only failure without rollback breaks the chain."""
        from wardsoar.core import netgate_apply

        async def _apply_fail(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return False, "apply blew up"

        async def _verify(_ssh: "_FakeSSH") -> tuple[bool, str]:
            return True, "ok"

        stub = HandlerSpec(
            apply_fn=_apply_fail,  # type: ignore[arg-type]
            verify_fn=_verify,  # type: ignore[arg-type]
            touches_config_xml=False,
            description="stub fail",
        )
        netgate_apply._HANDLERS["test.failure"] = stub
        try:
            applier = _make_applier(tmp_path, _FakeSSH())
            results = await applier.safe_apply_many(["test.failure", "suricata.rules_loaded"])
            # Second one should NOT have run because the first failed
            # and left no rollback (SSH-only handler).
            assert len(results) == 1
            assert results[0].success is False
        finally:
            netgate_apply._HANDLERS.pop("test.failure", None)
