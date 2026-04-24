"""Tests for ``src.pfsense_aliastable`` — file-backed persistent blocklist.

Every asyncssh call is replaced by a programmable fake that records
the exact command batch issued, so each test asserts both the logical
outcome AND the ordering of writes-then-pfctl-replace that gives the
module its atomicity guarantee.
"""

from __future__ import annotations

import pytest

from wardsoar.core.remote_agents.pfsense_aliastable import (
    DEFAULT_ALIAS_DIR,
    DEFAULT_ALIAS_FILE_PATH,
    DEFAULT_TABLE_NAME,
    BlocklistSyncResult,
    PersistentBlocklist,
)

# ---------------------------------------------------------------------------
# Fake SSH — matches ``PfSenseSSH.run_read_only`` signature.
# ---------------------------------------------------------------------------


class _FakeSSH:
    """Programmable stand-in for :class:`src.pfsense_ssh.PfSenseSSH`.

    ``responses`` maps a substring of the command string to the
    ``(success, output)`` tuple we want returned when that substring
    matches. If no match is found, ``default`` is returned. Every call
    is logged into :attr:`calls`, in order, so tests can assert on the
    exact sequence WardSOAR issues against pfSense.
    """

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


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestEntryValidation:
    """``_is_valid_entry`` gates every write — it MUST be loose enough
    for CIDR, strict enough to refuse shell-injection artefacts."""

    def test_plain_ipv4_accepted(self) -> None:
        assert PersistentBlocklist._is_valid_entry("10.0.0.1") is True

    def test_ipv6_accepted(self) -> None:
        assert PersistentBlocklist._is_valid_entry("2001:db8::1") is True

    def test_cidr_accepted(self) -> None:
        # Ben's typical VPS range — 84.203.112.0/24 is the operator's
        # own real example from the whitelist file.
        assert PersistentBlocklist._is_valid_entry("84.203.112.0/24") is True

    def test_garbage_rejected(self) -> None:
        assert PersistentBlocklist._is_valid_entry("not-an-ip") is False

    def test_injection_attempt_rejected(self) -> None:
        assert PersistentBlocklist._is_valid_entry("10.0.0.1; rm -rf /") is False

    def test_empty_rejected(self) -> None:
        assert PersistentBlocklist._is_valid_entry("") is False


# ---------------------------------------------------------------------------
# Read path
# ---------------------------------------------------------------------------


class TestReadEntries:
    @pytest.mark.asyncio
    async def test_missing_file_returns_empty_list(self) -> None:
        """``cat`` on a missing file returns nothing on stdout; we treat
        that as an empty blocklist (the common post-install state)."""
        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.read_entries() == []

    @pytest.mark.asyncio
    async def test_parses_each_line(self) -> None:
        ssh = _FakeSSH(default=(True, "10.0.0.1\n10.0.0.2\n192.168.42.0/24\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.read_entries() == ["10.0.0.1", "10.0.0.2", "192.168.42.0/24"]

    @pytest.mark.asyncio
    async def test_strips_comments_and_blank_lines(self) -> None:
        ssh = _FakeSSH(
            default=(
                True,
                "# WardSOAR persistent blocklist\n"
                "\n"
                "10.0.0.1\n"
                "  \n"
                "# added 2026-04-21\n"
                "10.0.0.2\n",
            )
        )
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.read_entries() == ["10.0.0.1", "10.0.0.2"]

    @pytest.mark.asyncio
    async def test_drops_malformed_lines_without_failing(self) -> None:
        """Operator hand-edit typos must not break the Responder. We
        simply skip the bad line and return the rest."""
        ssh = _FakeSSH(default=(True, "10.0.0.1\nnot-an-ip\n10.0.0.2\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.read_entries() == ["10.0.0.1", "10.0.0.2"]

    @pytest.mark.asyncio
    async def test_command_uses_configured_path(self) -> None:
        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(
            ssh,  # type: ignore[arg-type]
            file_path="/custom/path.txt",
        )
        await lst.read_entries()
        assert any("/custom/path.txt" in c for c in ssh.calls)


# ---------------------------------------------------------------------------
# Write path — full batch ordering
# ---------------------------------------------------------------------------


class TestWritePath:
    @pytest.mark.asyncio
    async def test_add_first_ip_emits_mkdir_then_atomic_write_then_pfctl(self) -> None:
        """Canonical batch: cat (read) → mkdir → write+mv → pfctl replace."""
        ssh = _FakeSSH(default=(True, ""))  # empty file at start
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("10.0.0.1")

        assert result.success is True
        assert result.size_before == 0
        assert result.size_after == 1

        # The four phases, in order. Use ``in`` rather than
        # ``startswith`` because the atomic-write script prepends
        # ``set -e`` before the ``cat > …`` line, and future hardening
        # may prepend more. The substring needle still uniquely
        # identifies each phase.
        cats = [i for i, c in enumerate(ssh.calls) if f"cat {DEFAULT_ALIAS_FILE_PATH}" in c]
        mkdirs = [i for i, c in enumerate(ssh.calls) if f"mkdir -p {DEFAULT_ALIAS_DIR}" in c]
        writes = [i for i, c in enumerate(ssh.calls) if f"cat > {DEFAULT_ALIAS_FILE_PATH}.tmp" in c]
        replaces = [
            i for i, c in enumerate(ssh.calls) if f"pfctl -t {DEFAULT_TABLE_NAME} -T replace" in c
        ]
        assert cats and mkdirs and writes and replaces, ssh.calls
        assert cats[0] < mkdirs[0] < writes[0] < replaces[0]

    @pytest.mark.asyncio
    async def test_add_already_present_is_idempotent_and_triggers_pfctl(self) -> None:
        """A second add of the same IP must still re-sync the pf table.
        This is the cheapest way to recover from a pfSense reload wiping
        the live table while the file remained intact."""
        ssh = _FakeSSH(default=(True, "10.0.0.1\n"))  # already in the file
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("10.0.0.1")

        assert result.success is True
        assert result.size_before == 1
        assert result.size_after == 1
        # pfctl replace was still issued, even though the file content
        # is unchanged.
        assert any(f"pfctl -t {DEFAULT_TABLE_NAME} -T replace" in c for c in ssh.calls), ssh.calls

    @pytest.mark.asyncio
    async def test_add_invalid_ip_short_circuits_without_ssh(self) -> None:
        ssh = _FakeSSH()
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("not-an-ip")
        assert result.success is False
        assert "invalid entry" in (result.error or "")
        # No SSH touched.
        assert ssh.calls == []

    @pytest.mark.asyncio
    async def test_remove_missing_ip_still_flushes(self) -> None:
        ssh = _FakeSSH(default=(True, "10.0.0.1\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.remove("10.0.0.2")  # never was in the file
        assert result.success is True
        assert result.size_before == 1
        assert result.size_after == 1
        # Flush happened — a pfctl replace call is present.
        assert any("pfctl -t" in c for c in ssh.calls)

    @pytest.mark.asyncio
    async def test_remove_present_shrinks_the_list(self) -> None:
        ssh = _FakeSSH(default=(True, "10.0.0.1\n10.0.0.2\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.remove("10.0.0.1")
        assert result.success is True
        assert result.size_before == 2
        assert result.size_after == 1

    @pytest.mark.asyncio
    async def test_replace_all_drops_invalid_entries_silently(self) -> None:
        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.replace_all(["10.0.0.1", "not-an-ip", "10.0.0.2"])
        assert result.success is True
        assert result.size_after == 2

    @pytest.mark.asyncio
    async def test_replace_all_deduplicates(self) -> None:
        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.replace_all(["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.1"])
        assert result.success is True
        assert result.size_after == 2


# ---------------------------------------------------------------------------
# Failure / recovery semantics
# ---------------------------------------------------------------------------


class TestFailureModes:
    @pytest.mark.asyncio
    async def test_mkdir_failure_aborts_before_write(self) -> None:
        """If the alias directory can't be created, we must NOT attempt
        the write — the `.tmp` rename would land nowhere useful."""
        ssh = _FakeSSH(
            responses={
                "mkdir -p": (False, "read-only filesystem"),
            },
            default=(True, ""),
        )
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("10.0.0.1")
        assert result.success is False
        assert "mkdir failed" in (result.error or "")
        # No write attempt was made.
        assert not any("cat > " in c for c in ssh.calls)

    @pytest.mark.asyncio
    async def test_atomic_write_failure_is_reported(self) -> None:
        ssh = _FakeSSH(
            responses={
                "cat > ": (False, "disk full"),
            },
            default=(True, ""),
        )
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("10.0.0.1")
        assert result.success is False
        assert "atomic write failed" in (result.error or "")

    @pytest.mark.asyncio
    async def test_pfctl_replace_failure_keeps_file_authoritative(self) -> None:
        """Scenario: disk write succeeded, pfctl reload failed.
        The file on disk is up-to-date. We return ``success=True`` (the
        file is the source of truth and pfSense will pick it up on the
        next reload) but annotate ``error`` so the caller can log it."""
        ssh = _FakeSSH(
            responses={
                "pfctl -t ": (False, "pfctl: no such table"),
            },
            default=(True, ""),
        )
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        result = await lst.add("10.0.0.1")
        assert result.success is True  # file is truth
        assert result.error is not None
        assert "pfctl replace failed" in (result.error or "")

    @pytest.mark.asyncio
    async def test_sentinel_collision_refuses_write(self) -> None:
        """If a hypothetical payload contained the heredoc sentinel
        (cannot normally happen with IP-only content, but the guard is
        there) we refuse the write rather than break the stream."""
        # Craft a fake entry that passes _is_valid_entry (valid IP)
        # but monkey-patch the payload so the sentinel appears. We
        # cover the sentinel-detection branch by replace_all with a
        # pre-seasoned list containing the sentinel string disguised
        # as a comment — which read_entries strips but _is_valid_entry
        # rejects. So instead we exercise the branch directly via the
        # internal ``_flush`` call.
        ssh = _FakeSSH()
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        crafted: list[str] = ["10.0.0.1", "__WARDSOAR_ALIAS_EOF__"]
        # Bypass validation so the sentinel reaches the payload.
        result = await lst._flush(crafted, size_before=0)
        assert result.success is False
        assert "sentinel" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# File existence probe
# ---------------------------------------------------------------------------


class TestFileExists:
    @pytest.mark.asyncio
    async def test_present(self) -> None:
        ssh = _FakeSSH(default=(True, "yes\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.file_exists() is True

    @pytest.mark.asyncio
    async def test_absent(self) -> None:
        ssh = _FakeSSH(default=(True, "no\n"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.file_exists() is False

    @pytest.mark.asyncio
    async def test_ssh_failure_returns_false(self) -> None:
        ssh = _FakeSSH(default=(False, "timeout"))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        assert await lst.file_exists() is False


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


def test_result_is_frozen() -> None:
    """``BlocklistSyncResult`` is intentionally frozen so a caller
    cannot mutate the returned record in place — keeps audit logs
    deterministic."""
    result = BlocklistSyncResult(True, 0, 1)
    with pytest.raises((AttributeError, TypeError, Exception)):
        result.size_after = 99  # type: ignore[misc]


class TestTmpPathUniqueness:
    """Regression for the 2026-04-23 22:40 tmp-collision incident.

    Two ``_flush`` calls that shared the same ``.tmp`` path made the
    second ``mv`` fail with "No such file or directory". The staging
    path now carries a per-call suffix (pid + monotonic ns) so
    independent writers never collide on it, even when the outer
    asyncio lock on :class:`PfSenseSSH` is bypassed (e.g. by an
    out-of-process helper that also stages under ``/var/db/aliastables``).
    """

    @pytest.mark.asyncio
    async def test_tmp_suffix_starts_with_dot_tmp_but_is_unique(self) -> None:
        """The tmp path keeps the legacy ``.tmp`` prefix (so tooling
        like backup/cleanup scripts matching ``*.tmp`` still picks it
        up) but adds a pid+time suffix so two calls never share it."""
        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]

        await lst.add("10.0.0.1")
        first_calls = list(ssh.calls)
        ssh.calls.clear()

        await lst.add("10.0.0.2")
        second_calls = list(ssh.calls)

        tmp_prefix = f"cat > {DEFAULT_ALIAS_FILE_PATH}.tmp"
        first_write = next(c for c in first_calls if tmp_prefix in c)
        second_write = next(c for c in second_calls if tmp_prefix in c)

        # Same prefix (so matching rules / regex on ``.tmp`` still work)
        # but the suffix (pid + monotonic) differs between calls.
        assert first_write != second_write, (
            "two flushes produced the same staging path — " "concurrent writers would collide on it"
        )

    @pytest.mark.asyncio
    async def test_tmp_suffix_only_characters_are_safe_for_sh(self) -> None:
        """The dynamic suffix must not introduce shell metacharacters
        that would break the heredoc-delimited write script."""
        import re

        ssh = _FakeSSH(default=(True, ""))
        lst = PersistentBlocklist(ssh)  # type: ignore[arg-type]
        await lst.add("10.0.0.1")

        write_cmd = next(c for c in ssh.calls if f"{DEFAULT_ALIAS_FILE_PATH}.tmp" in c)
        # Extract the tmp path — from ``cat > `` up to the next space.
        match = re.search(rf"cat > ({re.escape(DEFAULT_ALIAS_FILE_PATH)}\.tmp\S*)", write_cmd)
        assert match, write_cmd
        tmp_path = match.group(1)
        # Only filename-safe characters: dots, digits, hex, no spaces or
        # shell metacharacters.
        assert re.fullmatch(r"[A-Za-z0-9/._]+", tmp_path), tmp_path


# ---------------------------------------------------------------------------
# Shell-syntax regression — pipe every generated script through ``sh -n``.
# ---------------------------------------------------------------------------


class TestGeneratedScriptShellSyntax:
    """Hard guard against the ``&&`` on-a-line-by-itself bug (v0.8.0).

    The original implementation placed ``&& mv …`` on the line
    *after* a heredoc terminator, which POSIX sh parses as a syntax
    error. The Netgate's /bin/sh (FreeBSD ash) rejected the script
    silently — Apply returned "apply handler reported failure" with
    no clue which step broke. Regression caught on real hardware
    during Phase 7h bring-up.

    Every script we build here must survive ``sh -n`` (parse-only
    mode) on POSIX sh. The test transparently skips on Windows CI
    runners that lack sh — maintainers on Linux / macOS / WSL will
    catch a regression before merge.
    """

    @staticmethod
    def _run_sh_n(script: str) -> tuple[bool, str]:
        """Validate ``script`` with ``sh -n``. Returns (ok, stderr)."""
        import shutil
        import subprocess

        sh_path = shutil.which("sh")
        if sh_path is None:  # pragma: no cover — skipped via pytest.skip
            pytest.skip("POSIX sh unavailable — cannot validate syntax")
        # Bandit S603/S607 suppressed: this is test-only, runs a
        # known absolute path with parse-only mode (no execution of
        # our script, just the parser), no user input flows here.
        proc = subprocess.run(  # nosec B603 B607
            [sh_path, "-n"],
            input=script,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0, proc.stderr

    @pytest.mark.asyncio
    async def test_atomic_write_script_parses(self) -> None:
        """The ``_flush`` write command must be valid POSIX sh."""
        captured_scripts: list[str] = []

        class _CaptureSSH:
            async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
                captured_scripts.append(cmd)
                # Return an empty file on every read so _flush proceeds
                # through the whole batch.
                return (True, "")

        lst = PersistentBlocklist(_CaptureSSH())  # type: ignore[arg-type]
        await lst.add("10.0.0.1")

        # The "cat > …tmp" script is the one that used to carry the
        # syntax bug. Find it and parse it.
        write_scripts = [s for s in captured_scripts if f"cat > {DEFAULT_ALIAS_FILE_PATH}.tmp" in s]
        assert write_scripts, captured_scripts

        ok, stderr = self._run_sh_n(write_scripts[0])
        assert ok, f"sh -n rejected the write script:\n{stderr}\n---\n{write_scripts[0]}"

    @pytest.mark.asyncio
    async def test_atomic_write_script_executes_end_to_end(self, tmp_path: "object") -> None:
        """Beyond syntax, the script must actually produce the target
        file when piped to sh with a rewritten remote path.

        We rewrite ``/var/db/aliastables/wardsoar_blocklist.txt`` and
        its ``.tmp`` sibling to paths under tmp_path, then pipe the
        captured script to ``sh``. Success = file exists + has the
        expected content.
        """
        import shutil
        import subprocess
        from pathlib import Path

        if shutil.which("sh") is None:  # pragma: no cover
            pytest.skip("POSIX sh unavailable — cannot exercise script")

        captured_scripts: list[str] = []

        class _CaptureSSH:
            async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
                captured_scripts.append(cmd)
                return (True, "")

        lst = PersistentBlocklist(_CaptureSSH())  # type: ignore[arg-type]
        await lst.add("198.51.100.42")

        write_script = next(
            s for s in captured_scripts if f"cat > {DEFAULT_ALIAS_FILE_PATH}.tmp" in s
        )

        tmp_dir = Path(str(tmp_path))
        local_target = tmp_dir / "wardsoar_blocklist.txt"
        rewritten = write_script.replace(
            DEFAULT_ALIAS_FILE_PATH, str(local_target).replace("\\", "/")
        )

        # Bandit S603/S607 suppressed: test-only, sh from PATH, input
        # is our own generated script — not operator input.
        proc = subprocess.run(  # nosec B603 B607
            ["sh"],
            input=rewritten,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"sh execution failed:\nstderr={proc.stderr}"
        assert local_target.exists(), "atomic write did not produce the target file"
        assert "198.51.100.42" in local_target.read_text(encoding="utf-8")
