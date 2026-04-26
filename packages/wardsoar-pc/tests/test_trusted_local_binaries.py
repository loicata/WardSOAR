"""Tests for the operator-managed trusted-local-binaries whitelist.

Covers the YAML loader, the in-memory mtime cache, schema
validation, and the public :func:`is_trusted` lookup. The module
must never raise on unexpected input — the scorer treats a
missing / malformed file as "no whitelist entries" and proceeds
with its default heuristics.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from wardsoar.pc import trusted_local_binaries as tlb

# YAML always quotes SHA-256 strings; an unquoted purely-numeric
# 64-char value would be parsed as a Python int and dropped by the
# loader (with a warning). Tests below quote consistently.
_HASH_A = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
_HASH_B = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
_HASH_DEAD = "deadbeef00000000000000000000000000000000000000000000000000000000"


def _yaml_one(sha: str) -> str:
    return 'trusted:\n  - sha256: "' + sha + '"\n'


# Reset the module-level cache between tests so they cannot bleed
# state into each other through the singleton.
@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    tlb._CACHE.path = None
    tlb._CACHE.mtime = -1.0
    tlb._CACHE.hashes = frozenset()


class TestLoadTrustedHashes:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "absent.yaml"
        assert tlb.load_trusted_hashes(path=target) == frozenset()

    def test_empty_yaml_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "empty.yaml"
        target.write_text("", encoding="utf-8")
        assert tlb.load_trusted_hashes(path=target) == frozenset()

    def test_valid_entries_loaded(self, tmp_path: Path) -> None:
        target = tmp_path / "trusted.yaml"
        target.write_text(
            "trusted:\n"
            f'  - sha256: "{_HASH_A}"\n'
            f"    notes: Hobby tool\n"
            f'  - sha256: "{_HASH_B}"\n',
            encoding="utf-8",
        )
        hashes = tlb.load_trusted_hashes(path=target)
        assert _HASH_A in hashes
        assert _HASH_B in hashes

    def test_uppercase_normalised_to_lower(self, tmp_path: Path) -> None:
        target = tmp_path / "case.yaml"
        target.write_text(
            "trusted:\n"
            '  - sha256: "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"\n',
            encoding="utf-8",
        )
        hashes = tlb.load_trusted_hashes(path=target)
        assert "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" in hashes

    def test_malformed_sha_dropped_silently(self, tmp_path: Path) -> None:
        target = tmp_path / "mixed.yaml"
        target.write_text(
            "trusted:\n"
            "  - sha256: not-a-real-hash\n"
            f'  - sha256: "{_HASH_A}"\n'
            '  - sha256: "1234"\n'
            "  - notes: missing-sha-field-only\n",
            encoding="utf-8",
        )
        hashes = tlb.load_trusted_hashes(path=target)
        assert hashes == frozenset({_HASH_A})

    def test_unquoted_numeric_sha_is_dropped_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An unquoted purely-numeric SHA-256 is parsed as ``int`` by
        YAML. Reverse-converting via ``str(int)`` would yield a hex
        value totally unrelated to what the operator typed, so the
        loader drops it and warns the operator to add quotes."""
        target = tmp_path / "unquoted.yaml"
        target.write_text(
            "trusted:\n"
            "  - sha256: 1111111111111111111111111111111111111111111111111111111111111111\n",
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            hashes = tlb.load_trusted_hashes(path=target)
        assert hashes == frozenset()
        assert any("wrap the value in quotes" in r.message for r in caplog.records)

    def test_missing_trusted_key_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "wrong_root.yaml"
        target.write_text("other_key: 1\n", encoding="utf-8")
        assert tlb.load_trusted_hashes(path=target) == frozenset()

    def test_corrupted_yaml_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "broken.yaml"
        target.write_text("trusted:\n  - sha256: [unclosed\n", encoding="utf-8")
        # Must not raise.
        assert tlb.load_trusted_hashes(path=target) == frozenset()

    def test_top_level_list_is_ignored(self, tmp_path: Path) -> None:
        """A top-level list (instead of a mapping) must not crash —
        we just treat the file as containing zero entries."""
        target = tmp_path / "list.yaml"
        target.write_text(f'- sha256: "{_HASH_A}"\n', encoding="utf-8")
        assert tlb.load_trusted_hashes(path=target) == frozenset()

    def test_mtime_change_invalidates_cache(self, tmp_path: Path) -> None:
        target = tmp_path / "live.yaml"
        sha1 = "1" * 64
        sha2 = "2" * 64
        target.write_text(_yaml_one(sha1), encoding="utf-8")
        first = tlb.load_trusted_hashes(path=target)
        assert sha1 in first

        # ``time.sleep`` ensures the mtime actually changes on
        # filesystems with 1-second resolution (NTFS, FAT32).
        time.sleep(1.1)
        target.write_text(_yaml_one(sha2), encoding="utf-8")
        second = tlb.load_trusted_hashes(path=target)
        assert sha2 in second
        assert sha1 not in second

    def test_cache_hit_does_not_reread_file(self, tmp_path: Path) -> None:
        target = tmp_path / "stable.yaml"
        sha1 = "a" * 64
        sha2 = "b" * 64
        target.write_text(_yaml_one(sha1), encoding="utf-8")
        first = tlb.load_trusted_hashes(path=target)

        # Mutate the file in place but freeze its mtime to the
        # previous value — the cache must keep returning the original
        # snapshot.
        original_mtime = target.stat().st_mtime
        target.write_text(_yaml_one(sha2), encoding="utf-8")
        os.utime(target, (original_mtime, original_mtime))

        second = tlb.load_trusted_hashes(path=target)
        assert second == first  # served from cache; the file change is invisible


class TestIsTrusted:
    def test_match_returns_true(self, tmp_path: Path) -> None:
        target = tmp_path / "trusted.yaml"
        target.write_text(_yaml_one(_HASH_DEAD), encoding="utf-8")
        assert tlb.is_trusted(_HASH_DEAD, path=target) is True

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        target = tmp_path / "trusted.yaml"
        target.write_text(_yaml_one(_HASH_DEAD), encoding="utf-8")
        assert tlb.is_trusted(_HASH_DEAD.upper(), path=target) is True

    def test_unknown_hash_returns_false(self, tmp_path: Path) -> None:
        target = tmp_path / "trusted.yaml"
        target.write_text(_yaml_one(_HASH_DEAD), encoding="utf-8")
        assert tlb.is_trusted("0" * 64, path=target) is False

    def test_empty_input_returns_false(self) -> None:
        assert tlb.is_trusted("") is False

    def test_malformed_input_returns_false(self) -> None:
        assert tlb.is_trusted("not-a-hash") is False
        assert tlb.is_trusted("0xdeadbeef") is False
