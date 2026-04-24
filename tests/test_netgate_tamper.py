"""Tests for Phase 7g — Netgate tamper detection.

The detector is tiny but its contract matters: a false positive is a
loud "your box was compromised" modal, and a false negative means we
missed an actual intrusion. Every scenario below exercises one
transition of the three-state flow:

    no-baseline → established → (clean | deviation | ssh-down)

SSH is replaced by a fake so the tests never touch a real appliance.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.netgate_tamper import (
    NetgateTamperDetector,
    SEV_HIGH,
    TamperBaseline,
    _SURFACES,
)

# ---------------------------------------------------------------------------
# Fake SSH — each test wires the responses it needs.
# ---------------------------------------------------------------------------


class _FakeSSH:
    def __init__(
        self,
        outputs: dict[str, tuple[bool, str]] | None = None,
        status_ok: bool = True,
    ) -> None:
        self._outputs = outputs or {}
        self._status_ok = status_ok
        self._host = "test-netgate"

    async def check_status(self) -> tuple[bool, str]:
        return (self._status_ok, "ok" if self._status_ok else "ssh down")

    async def run_read_only(self, cmd: str, timeout: int = 10) -> tuple[bool, str]:
        if cmd in self._outputs:
            return self._outputs[cmd]
        # By default every surface returns the same placeholder so the
        # test defines a single consistent "snapshot" across runs.
        return (True, "default")


def _responses_for(content_per_surface: dict[str, str]) -> dict[str, tuple[bool, str]]:
    """Map a (surface id → output) dict onto the actual command strings."""
    out: dict[str, tuple[bool, str]] = {}
    id_to_cmd = {s.id: s.command for s in _SURFACES}
    for sid, text in content_per_surface.items():
        cmd = id_to_cmd.get(sid)
        if cmd is not None:
            out[cmd] = (True, text)
    return out


# ---------------------------------------------------------------------------
# Baseline establishment + persistence
# ---------------------------------------------------------------------------


class TestEstablishBaseline:

    @pytest.mark.asyncio
    async def test_establish_creates_file_with_all_surfaces(self, tmp_path: Path) -> None:
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        baseline = await detector.establish_baseline()
        assert detector.has_baseline() is True
        # Each surface must have a recorded entry — use the module's
        # canonical list so adding a surface later fails the test until
        # we also extend the fake responses.
        assert set(baseline.entries.keys()) == {s.id for s in _SURFACES}
        for entry in baseline.entries.values():
            assert entry.sha256  # non-empty hash
            assert entry.summary

    @pytest.mark.asyncio
    async def test_establish_then_load_roundtrips(self, tmp_path: Path) -> None:
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        baseline = await detector.establish_baseline()
        reloaded = detector.load_baseline()
        assert reloaded is not None
        assert set(reloaded.entries.keys()) == set(baseline.entries.keys())
        # Each hash is preserved across serialisation.
        for sid, entry in baseline.entries.items():
            assert reloaded.entries[sid].sha256 == entry.sha256

    def test_load_missing_file_returns_none(self, tmp_path: Path) -> None:
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "does-not-exist.json",
        )
        assert detector.has_baseline() is False
        assert detector.load_baseline() is None

    def test_malformed_baseline_yields_none(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text("{ not valid json", encoding="utf-8")
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=path,
        )
        assert detector.load_baseline() is None


# ---------------------------------------------------------------------------
# Tamper diff semantics
# ---------------------------------------------------------------------------


class TestTamperCheck:

    @pytest.mark.asyncio
    async def test_no_baseline_yields_baseline_absent(self, tmp_path: Path) -> None:
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        result = await detector.check_for_tampering()
        assert result.baseline_present is False
        assert result.any_deviation is False
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_clean_netgate_reports_no_deviation(self, tmp_path: Path) -> None:
        # Same fake SSH → same output across two captures → no diff.
        ssh = _FakeSSH()
        detector = NetgateTamperDetector(
            ssh=ssh,  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()
        result = await detector.check_for_tampering()
        assert result.baseline_present is True
        assert result.any_deviation is False

    @pytest.mark.asyncio
    async def test_authorised_key_added_is_detected(self, tmp_path: Path) -> None:
        """A new SSH key in authorized_keys must trip the HIGH finding."""
        initial = _FakeSSH(
            _responses_for({"auth.root_authorized_keys": "ssh-ed25519 AAAA operator@host"})
        )
        tampered = _FakeSSH(
            _responses_for(
                {
                    "auth.root_authorized_keys": (
                        "ssh-ed25519 AAAA operator@host\n" "ssh-ed25519 BBBB attacker@evil\n"
                    )
                }
            )
        )

        detector = NetgateTamperDetector(
            ssh=initial,  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()

        detector._ssh = tampered  # swap the SSH handle
        result = await detector.check_for_tampering()
        assert result.any_deviation is True
        ids = [f.id for f in result.findings]
        assert "auth.root_authorized_keys" in ids
        finding = next(f for f in result.findings if f.id == "auth.root_authorized_keys")
        assert finding.severity == SEV_HIGH

    @pytest.mark.asyncio
    async def test_config_xml_hash_change_is_detected(self, tmp_path: Path) -> None:
        initial = _FakeSSH(_responses_for({"config.config_xml": "abcd1234"}))
        tampered = _FakeSSH(_responses_for({"config.config_xml": "abcd1234 tampered"}))

        detector = NetgateTamperDetector(
            ssh=initial,  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()
        detector._ssh = tampered
        result = await detector.check_for_tampering()
        assert any(f.id == "config.config_xml" for f in result.findings)

    @pytest.mark.asyncio
    async def test_ssh_error_during_capture_is_not_a_mismatch(self, tmp_path: Path) -> None:
        """Transient SSH failure must not be flagged as tampering."""
        initial = _FakeSSH(_responses_for({"packages.list": "pfSense-kernel 2.7.2"}))
        detector = NetgateTamperDetector(
            ssh=initial,  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()

        # New SSH whose packages.list command fails.
        tampered_ssh = _FakeSSH(
            _responses_for({"packages.list": ""}),  # filled below
        )
        id_to_cmd = {s.id: s.command for s in _SURFACES}
        tampered_ssh._outputs[id_to_cmd["packages.list"]] = (False, "ssh: timeout")
        detector._ssh = tampered_ssh

        result = await detector.check_for_tampering()
        assert all(f.id != "packages.list" for f in result.findings)

    @pytest.mark.asyncio
    async def test_ssh_unreachable_returns_error_result(self, tmp_path: Path) -> None:
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()

        detector._ssh = _FakeSSH(status_ok=False)
        result = await detector.check_for_tampering()
        assert result.ssh_reachable is False
        assert result.any_deviation is False
        assert result.error is not None


# ---------------------------------------------------------------------------
# Serialisation (UI boundary)
# ---------------------------------------------------------------------------


class TestSerialisation:

    @pytest.mark.asyncio
    async def test_result_to_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        import json

        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        await detector.establish_baseline()
        result = await detector.check_for_tampering()
        json.dumps(result.to_dict())

    @pytest.mark.asyncio
    async def test_baseline_json_is_stable_across_writes(self, tmp_path: Path) -> None:
        """Rewriting a baseline with identical content must not trip ``any_deviation``."""
        detector = NetgateTamperDetector(
            ssh=_FakeSSH(),  # type: ignore[arg-type]
            baseline_path=tmp_path / "baseline.json",
        )
        b1 = await detector.establish_baseline()
        b2 = await detector.establish_baseline()
        # Entries match — only timestamps differ.
        for sid, entry in b1.entries.items():
            assert b2.entries[sid].sha256 == entry.sha256


# ---------------------------------------------------------------------------
# TamperBaseline.from_json robustness
# ---------------------------------------------------------------------------


class TestBaselineFromJson:

    def test_discards_non_dict_entries(self) -> None:
        raw = {
            "host": "h",
            "captured_at": "2026-04-20T12:00:00+00:00",
            "entries": {
                "good": {
                    "id": "good",
                    "title": "t",
                    "severity": "high",
                    "sha256": "abc",
                    "summary": "s",
                    "captured_at": "2026-04-20T12:00:00+00:00",
                },
                "bad": "not-a-dict",
                "also-bad": 42,
            },
        }
        parsed = TamperBaseline.from_json(raw)
        assert set(parsed.entries.keys()) == {"good"}

    def test_handles_missing_entries_key(self) -> None:
        parsed = TamperBaseline.from_json({"host": "h", "captured_at": ""})
        assert parsed.entries == {}
