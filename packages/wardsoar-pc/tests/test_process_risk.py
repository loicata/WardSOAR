"""Tests for the local process risk scorer.

Covers the pure helpers (verdict bands, trusted-signer match,
base64 entropy check, signer extraction) and the end-to-end
:func:`scan_process` by mocking psutil + the Authenticode query.
"""

from __future__ import annotations

import base64
import subprocess
from unittest.mock import MagicMock

import pytest

from wardsoar.pc.process_risk import (
    ProcessRiskResult,
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    _extract_signer_short_name,
    _is_trusted_signer,
    _looks_like_binary_base64,
    _verdict_for,
    scan_process,
)

# ---------------------------------------------------------------------------
# _verdict_for — threshold mapping
# ---------------------------------------------------------------------------


class TestVerdictFor:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (0, VERDICT_BENIGN),
            (10, VERDICT_BENIGN),
            (19, VERDICT_BENIGN),
            (20, VERDICT_UNKNOWN),
            (49, VERDICT_UNKNOWN),
            (50, VERDICT_SUSPICIOUS),
            (79, VERDICT_SUSPICIOUS),
            (80, VERDICT_MALICIOUS),
            (100, VERDICT_MALICIOUS),
        ],
    )
    def test_band_boundaries(self, score: int, expected: str) -> None:
        assert _verdict_for(score) == expected


# ---------------------------------------------------------------------------
# _is_trusted_signer
# ---------------------------------------------------------------------------


class TestTrustedSigner:
    def test_microsoft_matches(self) -> None:
        assert _is_trusted_signer("Microsoft Corporation") is True

    def test_google_matches_with_llc_suffix(self) -> None:
        assert _is_trusted_signer("Google LLC") is True

    def test_random_ltd_does_not_match(self) -> None:
        assert _is_trusted_signer("Obscure Ltd") is False

    def test_empty_is_not_trusted(self) -> None:
        assert _is_trusted_signer("") is False


# ---------------------------------------------------------------------------
# _looks_like_binary_base64
# ---------------------------------------------------------------------------


class TestBase64Entropy:
    def test_random_bytes_are_flagged(self) -> None:
        import os

        blob = base64.b64encode(os.urandom(200)).decode("ascii")
        assert _looks_like_binary_base64(blob) is True

    def test_ascii_text_is_not_flagged(self) -> None:
        """Long base64 of ASCII text has high printable ratio — not
        suspicious, so the scorer should not trip on it."""
        text = ("All lorem ipsum dolor sit amet consectetur adipiscing " * 10).encode("utf-8")
        blob = base64.b64encode(text).decode("ascii")
        assert _looks_like_binary_base64(blob) is False

    def test_empty_string_returns_false(self) -> None:
        """Guard against the zero-division in the printable-ratio calc."""
        assert _looks_like_binary_base64("") is False


# ---------------------------------------------------------------------------
# _extract_signer_short_name
# ---------------------------------------------------------------------------


class TestExtractSignerShortName:
    def test_parses_microsoft_subject(self) -> None:
        subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US"
        assert _extract_signer_short_name(subject) == "Microsoft Corporation"

    def test_parses_single_o_when_no_cn(self) -> None:
        assert _extract_signer_short_name("O=Google LLC, C=US") == "Google LLC"

    def test_empty_subject_returns_empty(self) -> None:
        assert _extract_signer_short_name("") == ""


# ---------------------------------------------------------------------------
# scan_process — integration
# ---------------------------------------------------------------------------


def _mock_process(
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    exe: str,
    cmdline: list[str],
    parent_name: str | None = None,
) -> None:
    """Patch psutil.Process so scan_process sees deterministic state."""
    proc = MagicMock()
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.cmdline.return_value = cmdline
    if parent_name is not None:
        parent = MagicMock()
        parent.name.return_value = parent_name
        proc.parent.return_value = parent
    else:
        proc.parent.return_value = None
    monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)


def _stub_signature(
    monkeypatch: pytest.MonkeyPatch, status: str = "valid", signer: str = "Microsoft Corporation"
) -> None:
    monkeypatch.setattr(
        "wardsoar.pc.process_risk._check_signature",
        lambda path: (status, signer),
    )


class TestScanProcessHappyPaths:
    def test_microsoft_svchost_is_benign(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_process(
            monkeypatch,
            name="svchost.exe",
            exe=r"C:\Windows\System32\svchost.exe",
            cmdline=["svchost.exe", "-k", "NetworkService"],
            parent_name="services.exe",
        )
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        result = scan_process(1234)

        assert isinstance(result, ProcessRiskResult)
        assert result.verdict == VERDICT_BENIGN
        assert result.score < 20
        assert result.signature_status == "valid"
        assert "Microsoft Corporation" in result.signature_signer

    def test_unsigned_from_temp_is_suspicious(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_process(
            monkeypatch,
            name="evil.exe",
            exe=r"C:\Users\loic\AppData\Local\Temp\evil.exe",
            cmdline=["evil.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        result = scan_process(2222)

        assert result.verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)
        assert any("Unsigned" in s for s in result.signals)
        assert any("user-writable" in s or "temp" in s.lower() for s in result.signals)

    def test_word_spawning_powershell_is_malicious(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_process(
            monkeypatch,
            name="powershell.exe",
            exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            cmdline=[
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                "ZQBjAGgAbwAgAHAAdwBuAGUAZAA=",
            ],
            parent_name="winword.exe",
        )
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        result = scan_process(3333)

        # Even though the binary is Microsoft-signed, the parent /
        # cmdline combo should push this to suspicious or malicious.
        assert result.verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)
        assert any("winword.exe" in s.lower() for s in result.signals)
        assert any("EncodedCommand" in s for s in result.signals)

    def test_hash_mismatch_is_malicious(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``hash_mismatch`` means the binary bytes differ from what
        was signed — a strong tamper indicator."""
        _mock_process(
            monkeypatch,
            name="notepad.exe",
            exe=r"C:\Windows\System32\notepad.exe",
            cmdline=["notepad.exe"],
        )
        _stub_signature(monkeypatch, "hash_mismatch", "Microsoft Corporation")

        result = scan_process(4444)

        assert result.verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)
        assert any("altered" in s.lower() or "mismatch" in s.lower() for s in result.signals)


class TestAgeSignal:
    """Phase A — process creation-time heuristic."""

    def test_fresh_process_adds_points(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time as _time

        _mock_process(
            monkeypatch,
            name="evil.exe",
            exe=r"C:\Users\loic\AppData\Local\Temp\evil.exe",
            cmdline=["evil.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        # Override create_time on the mocked process.
        proc = MagicMock()
        proc.name.return_value = "evil.exe"
        proc.exe.return_value = r"C:\Users\loic\AppData\Local\Temp\evil.exe"
        proc.cmdline.return_value = ["evil.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = _time.time() - 60  # 1 min ago
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)

        result = scan_process(1111)

        assert any("very fresh" in s.lower() for s in result.signals)

    def test_old_process_subtracts_points(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time as _time

        proc = MagicMock()
        proc.name.return_value = "svchost.exe"
        proc.exe.return_value = r"C:\Windows\System32\svchost.exe"
        proc.cmdline.return_value = ["svchost.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = _time.time() - 48 * 3600  # 48 h ago
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        result = scan_process(2222)

        assert any("uptime" in s.lower() for s in result.signals)


class TestTreeDepthSignal:
    """Long parent chain = exploit pattern."""

    def test_deep_chain_adds_points(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Fake a 6-hop chain: cmd.exe ← net.exe ← wmic.exe ←
        # powershell.exe ← winword.exe ← explorer.exe
        def _parent(name: str) -> MagicMock:
            p = MagicMock()
            p.name.return_value = name
            return p

        parents = [
            _parent("wmic.exe"),
            _parent("powershell.exe"),
            _parent("cmd.exe"),
            _parent("winword.exe"),
            _parent("explorer.exe"),
        ]
        proc = MagicMock()
        proc.name.return_value = "net.exe"
        proc.exe.return_value = r"C:\Windows\System32\net.exe"
        proc.cmdline.return_value = ["net.exe", "user"]
        proc.parent.return_value = parents[0]
        proc.parents.return_value = parents
        proc.create_time.return_value = 0.0
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        result = scan_process(3333)

        assert any("parent chain" in s.lower() for s in result.signals)


class TestDefenderSignal:
    """Windows Defender verdict integration."""

    def test_defender_hit_marks_malicious(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        # Fake a binary on disk + point MPCMDRUN at it too (valid file).
        exe = tmp_path / "payload.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"fake bytes")
        monkeypatch.setattr(_pr.win_paths, "MPCMDRUN", str(exe))

        # Clear the module-level cache so each test is independent.
        _pr._DEFENDER_VERDICT_CACHE.clear()

        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout="Threat Trojan:Win32/Emotet!MTB identified.\n",
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        _mock_process(
            monkeypatch,
            name="payload.exe",
            exe=str(exe),
            cmdline=["payload.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        result = scan_process(4444)

        assert result.verdict == VERDICT_MALICIOUS
        assert any("Defender" in s and "Trojan" in s for s in result.signals)

    def test_defender_clean_lowers_score(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "clean.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"clean bytes")
        monkeypatch.setattr(_pr.win_paths, "MPCMDRUN", str(exe))
        _pr._DEFENDER_VERDICT_CACHE.clear()

        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        _mock_process(
            monkeypatch,
            name="clean.exe",
            exe=str(exe),
            cmdline=["clean.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        result = scan_process(5555)

        assert any("scanned clean" in s.lower() for s in result.signals)

    def test_trusted_signer_skips_defender(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        """Microsoft-signed binaries should not even be scanned."""
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "notepad.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"any")
        monkeypatch.setattr(_pr.win_paths, "MPCMDRUN", str(exe))
        _pr._DEFENDER_VERDICT_CACHE.clear()

        called: list[object] = []

        def spy_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            called.append(args)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", spy_run)

        _mock_process(
            monkeypatch,
            name="notepad.exe",
            exe=str(exe),
            cmdline=["notepad.exe"],
        )
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        scan_process(6666)

        assert called == []


class TestDllLoadsetSignal:
    """Phase C-light — DLL path heuristic on loaded modules."""

    def _make_map(self, path: str) -> MagicMock:
        entry = MagicMock()
        entry.path = path
        return entry

    def test_dll_from_temp_adds_signal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from wardsoar.pc import process_risk as _pr

        proc = MagicMock()
        proc.name.return_value = "chrome.exe"
        proc.exe.return_value = r"C:\Program Files\Google\chrome.exe"
        proc.cmdline.return_value = ["chrome.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = [
            self._make_map(r"C:\Windows\System32\ntdll.dll"),
            self._make_map(r"C:\Users\loic\AppData\Local\Temp\rogue.dll"),
        ]
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "valid", "Google LLC")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(9999)

        assert any("Suspicious DLL" in s and "rogue.dll" in s for s in result.signals)

    def test_only_system_dlls_no_signal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from wardsoar.pc import process_risk as _pr

        proc = MagicMock()
        proc.name.return_value = "chrome.exe"
        proc.exe.return_value = r"C:\Program Files\Google\chrome.exe"
        proc.cmdline.return_value = ["chrome.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = [
            self._make_map(r"C:\Windows\System32\ntdll.dll"),
            self._make_map(r"C:\Program Files\Google\chrome.dll"),
        ]
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "valid", "Google LLC")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(10000)

        assert not any("Suspicious DLL" in s for s in result.signals)

    def test_memory_maps_error_is_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``AccessDenied`` on memory_maps must not propagate."""
        from psutil import AccessDenied

        from wardsoar.pc import process_risk as _pr

        proc = MagicMock()
        proc.name.return_value = "protected.exe"
        proc.exe.return_value = r"C:\Windows\System32\protected.exe"
        proc.cmdline.return_value = []
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.side_effect = AccessDenied("protected")
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(11111)  # must not raise

        assert isinstance(result, ProcessRiskResult)


class TestYaraSignal:
    """Phase B — YARA rule match contribution."""

    def test_matching_rule_adds_signal(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "infected.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"any bytes")

        # Reset caches + force the loader to return a fake rules object.
        _pr._YARA_VERDICT_CACHE.clear()
        _pr._YARA_COMPILED_RULES = None
        _pr._YARA_LOAD_ATTEMPTED = True  # skip compile attempt

        fake_match = MagicMock()
        fake_match.rule = "Mal_EmotetLoader"
        fake_rules = MagicMock()
        fake_rules.match.return_value = [fake_match]
        monkeypatch.setattr(_pr, "_load_yara_rules", lambda: fake_rules)

        _mock_process(
            monkeypatch,
            name="infected.exe",
            exe=str(exe),
            cmdline=["infected.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")
        # Isolate from Defender/VT side-effects.
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(7777)

        assert any("YARA match" in s and "Mal_EmotetLoader" in s for s in result.signals)

    def test_no_rules_no_signal(self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object") -> None:
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "benign.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"bytes")
        _pr._YARA_VERDICT_CACHE.clear()
        monkeypatch.setattr(_pr, "_load_yara_rules", lambda: None)

        _mock_process(
            monkeypatch,
            name="benign.exe",
            exe=str(exe),
            cmdline=["benign.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(8888)

        assert not any("YARA" in s for s in result.signals)

    def test_multiple_matches_capped_at_60(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "x.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"bytes")
        _pr._YARA_VERDICT_CACHE.clear()

        def many_matches(*_a: object, **_kw: object) -> list[MagicMock]:
            return [MagicMock(rule=f"Rule_{i}") for i in range(10)]

        fake_rules = MagicMock()
        fake_rules.match = many_matches
        monkeypatch.setattr(_pr, "_load_yara_rules", lambda: fake_rules)

        delta, _signal = _pr._yara_signal(str(exe))
        assert delta == 60  # 30 * 10 clamped to 60


class TestVTCacheSignal:
    """Phase 3 — VT cache lookup integration with scan_process."""

    def test_cached_malicious_pushes_verdict_to_malicious(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.core.models import VirusTotalResult

        exe = tmp_path / "payload.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"fake exe bytes" * 20)

        _mock_process(
            monkeypatch,
            name="payload.exe",
            exe=str(exe),
            cmdline=["payload.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        def fake_lookup(self: object, h: str) -> VirusTotalResult:
            return VirusTotalResult(
                file_hash=h,
                detection_count=42,
                total_engines=70,
                detection_ratio=0.6,
                is_malicious=True,
                threat_labels=["trojan.generic"],
            )

        monkeypatch.setattr("wardsoar.core.vt_cache.VTCache.lookup", fake_lookup)

        result = scan_process(5555)

        assert result.verdict == VERDICT_MALICIOUS
        assert any("VirusTotal" in s and "42/70" in s for s in result.signals)

    def test_cached_clean_downgrades_score(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.core.models import VirusTotalResult

        exe = tmp_path / "custom.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"legit payload" * 10)

        _mock_process(
            monkeypatch,
            name="custom.exe",
            exe=str(exe),
            cmdline=["custom.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        def fake_clean(self: object, h: str) -> VirusTotalResult:
            return VirusTotalResult(
                file_hash=h,
                detection_count=0,
                total_engines=70,
                detection_ratio=0.0,
                is_malicious=False,
            )

        monkeypatch.setattr("wardsoar.core.vt_cache.VTCache.lookup", fake_clean)

        result = scan_process(6666)

        assert any("clean" in s.lower() and "virustotal" in s.lower() for s in result.signals)

    def test_trusted_signer_skips_vt_lookup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        exe = tmp_path / "notepad.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"any content")

        _mock_process(
            monkeypatch,
            name="notepad.exe",
            exe=str(exe),
            cmdline=["notepad.exe"],
        )
        _stub_signature(monkeypatch, "valid", "Microsoft Corporation")

        called: list[str] = []

        def spy_lookup(self: object, h: str) -> None:
            called.append(h)
            return None

        monkeypatch.setattr("wardsoar.core.vt_cache.VTCache.lookup", spy_lookup)

        scan_process(7777)

        assert called == []

    def test_cache_miss_adds_no_signal(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        exe = tmp_path / "unknown.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"mystery bytes")

        _mock_process(
            monkeypatch,
            name="unknown.exe",
            exe=str(exe),
            cmdline=["unknown.exe"],
        )
        _stub_signature(monkeypatch, "unsigned", "")

        monkeypatch.setattr("wardsoar.core.vt_cache.VTCache.lookup", lambda self, h: None)

        result = scan_process(8888)

        assert not any("VirusTotal" in s for s in result.signals)


class TestScanProcessFailSafe:
    def test_no_such_process_returns_neutral(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from psutil import NoSuchProcess

        def raise_nsp(pid: int) -> MagicMock:
            raise NoSuchProcess(pid)

        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", raise_nsp)

        result = scan_process(99999)

        assert result.verdict == VERDICT_UNKNOWN
        assert result.score == 50
        assert any("accessible" in s.lower() for s in result.signals)


class TestProcessRiskResultSerialization:
    def test_to_dict_contains_expected_keys(self) -> None:
        result = ProcessRiskResult(
            pid=1234,
            score=42,
            verdict=VERDICT_UNKNOWN,
            signals=["x", "y"],
            signature_status="valid",
            signature_signer="Contoso",
            parent_name="explorer.exe",
        )
        payload = result.to_dict()
        assert payload["score"] == 42
        assert payload["verdict"] == VERDICT_UNKNOWN
        assert payload["signals"] == ["x", "y"]
        assert payload["signature_status"] == "valid"
        assert payload["signature_signer"] == "Contoso"
        assert payload["parent_name"] == "explorer.exe"


# ---------------------------------------------------------------------------
# _check_signature (PowerShell wrapper)
# ---------------------------------------------------------------------------


class TestUserInstalledProgramsPath:
    """Per-user installed-programs directory should earn a small bonus.

    The intent: legitimate hobby tools / Electron apps / PyInstaller
    builds that drop into ``%LOCALAPPDATA%\\Programs\\`` are unsigned
    yet not malicious. Without the bonus, a single unsigned signal
    pushes a 50-baseline binary straight to ``suspicious``.
    """

    def test_path_emits_signal(self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object") -> None:
        import time as _time

        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "myhobbyapp.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"bytes")

        # Fake the resolved exe to look like %LOCALAPPDATA%\Programs.
        # ``create_time`` sits between the fresh and stale thresholds
        # so the age signal contributes 0 — we want a clean score we
        # can pin.
        proc = MagicMock()
        proc.name.return_value = "myhobbyapp.exe"
        proc.exe.return_value = r"C:\Users\loic\AppData\Local\Programs\MyHobbyApp\myhobbyapp.exe"
        proc.cmdline.return_value = ["myhobbyapp.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = _time.time() - 3600  # 1 h ago — neutral
        proc.memory_maps.return_value = []
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "unsigned", "")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))
        # Pin the whitelist to empty so option C cannot intervene.
        monkeypatch.setattr(_pr.trusted_local_binaries, "is_trusted", lambda h: False)

        result = scan_process(13131)

        assert any("installed-programs" in s.lower() for s in result.signals)
        # Without the bonus the score would be 70 (baseline + unsigned),
        # which sits squarely in ``suspicious`` (50–79). The bonus must
        # tip it down by exactly 5 — anything more would risk masking
        # real unsigned malware living in this directory class.
        baseline_unsigned = 70
        assert result.score == baseline_unsigned - 5
        assert result.verdict == VERDICT_SUSPICIOUS  # still suspicious — option C handles the rest

    def test_temp_path_still_dominates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        """A binary somehow under ``\\Temp\\`` must still earn the +25
        suspect-path penalty even if the path also contains the
        ``\\AppData\\Local\\`` prefix; the temp signal is additive."""
        from wardsoar.pc import process_risk as _pr

        proc = MagicMock()
        proc.name.return_value = "evil.exe"
        proc.exe.return_value = r"C:\Users\loic\AppData\Local\Temp\evil.exe"
        proc.cmdline.return_value = ["evil.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = []
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        _stub_signature(monkeypatch, "unsigned", "")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr.trusted_local_binaries, "is_trusted", lambda h: False)

        result = scan_process(14141)

        # Should NOT have the user-installed bonus — the matching
        # branch is an ``elif`` after Program Files, and ``\Temp\``
        # is not in either trusted category.
        assert not any("installed-programs" in s.lower() for s in result.signals)
        assert any("user-writable" in s.lower() or "temp" in s.lower() for s in result.signals)


class TestTrustedLocalWhitelist:
    """Operator-managed SHA-256 whitelist must short-circuit scoring."""

    def test_trusted_hash_returns_benign_immediately(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        # Real file on disk so ``_sha256_file`` returns a non-None hash.
        exe = tmp_path / "trusted_tool.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"deterministic content")

        proc = MagicMock()
        proc.name.return_value = "trusted_tool.exe"
        proc.exe.return_value = str(exe)
        proc.cmdline.return_value = ["trusted_tool.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = []
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)

        # Pin the whitelist to "match anything that is hashable".
        monkeypatch.setattr(_pr.trusted_local_binaries, "is_trusted", lambda h: True)

        # Sentinels: if any of these are reached, the short-circuit
        # failed and the test should fail loudly.
        def _must_not_run(*_a: object, **_kw: object) -> object:
            raise AssertionError("scan_process must short-circuit before this helper")

        monkeypatch.setattr(_pr, "_check_signature", _must_not_run)
        monkeypatch.setattr(_pr, "_defender_signal", _must_not_run)
        monkeypatch.setattr(_pr, "_yara_signal", _must_not_run)
        monkeypatch.setattr(_pr, "_vt_cache_signal", _must_not_run)

        result = scan_process(15151)

        assert result.verdict == VERDICT_BENIGN
        assert result.score == 0
        assert any("Trusted local binary" in s for s in result.signals)
        assert result.signature_status == "unknown"
        assert result.signature_signer == ""
        assert result.parent_name is None

    def test_untrusted_hash_proceeds_to_full_scoring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: "object"
    ) -> None:
        from wardsoar.pc import process_risk as _pr

        exe = tmp_path / "unknown.exe"  # type: ignore[attr-defined]
        exe.write_bytes(b"bytes")

        proc = MagicMock()
        proc.name.return_value = "unknown.exe"
        proc.exe.return_value = str(exe)
        proc.cmdline.return_value = ["unknown.exe"]
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = []
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)
        monkeypatch.setattr(_pr.trusted_local_binaries, "is_trusted", lambda h: False)
        _stub_signature(monkeypatch, "unsigned", "")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        result = scan_process(16161)

        # Full scoring ran: unsigned contributed +20, no early exit.
        assert any("Unsigned" in s for s in result.signals)
        assert not any("Trusted local binary" in s for s in result.signals)

    def test_unhashable_path_does_not_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``proc.exe()`` may legitimately return ``""`` for system
        processes — the short-circuit must remain safe."""
        from wardsoar.pc import process_risk as _pr

        proc = MagicMock()
        proc.name.return_value = "system"
        proc.exe.return_value = ""
        proc.cmdline.return_value = []
        proc.parent.return_value = None
        proc.parents.return_value = []
        proc.create_time.return_value = 0.0
        proc.memory_maps.return_value = []
        monkeypatch.setattr("wardsoar.pc.process_risk.psutil.Process", lambda pid: proc)

        called: list[str] = []
        monkeypatch.setattr(
            _pr.trusted_local_binaries, "is_trusted", lambda h: called.append(h) or False
        )
        _stub_signature(monkeypatch, "unknown", "")
        monkeypatch.setattr(_pr, "_defender_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_yara_signal", lambda p: (0, ""))
        monkeypatch.setattr(_pr, "_vt_cache_signal", lambda p: (0, ""))

        scan_process(17171)  # must not raise

        # No hash, so the whitelist must not have been consulted.
        assert called == []


class TestCheckSignature:
    def test_missing_exe_path_returns_unknown(self) -> None:
        from wardsoar.pc.process_risk import _check_signature

        assert _check_signature("") == ("unknown", "")

    def test_nonexistent_path_returns_unknown(self, tmp_path: "object") -> None:
        from wardsoar.pc.process_risk import _check_signature

        ghost = str(tmp_path) + r"\nope.exe"  # type: ignore[operator]
        assert _check_signature(ghost) == ("unknown", "")

    def test_timeout_returns_unknown(
        self, tmp_path: "object", monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wardsoar.pc.process_risk import _check_signature

        # Create a real file so the is_file() guard passes.
        target = tmp_path / "dummy.exe"  # type: ignore[attr-defined]
        target.write_bytes(b"")

        def raising_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["ps"], timeout=5)

        monkeypatch.setattr(subprocess, "run", raising_run)
        # Must point POWERSHELL at a real file so the guard passes.
        ps = target  # reuse
        monkeypatch.setattr("wardsoar.pc.process_risk.win_paths.POWERSHELL", str(ps))

        result = _check_signature(str(target))
        assert result == ("unknown", "")

    def test_parses_valid_json(self, tmp_path: "object", monkeypatch: pytest.MonkeyPatch) -> None:
        from wardsoar.pc.process_risk import _check_signature

        target = tmp_path / "dummy.exe"  # type: ignore[attr-defined]
        target.write_bytes(b"")
        monkeypatch.setattr("wardsoar.pc.process_risk.win_paths.POWERSHELL", str(target))

        def fake_run(*_a: object, **_kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"Status":"Valid","Subject":"CN=Microsoft Corporation, O=Microsoft"}',
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        status, signer = _check_signature(str(target))
        assert status == "valid"
        assert signer == "Microsoft Corporation"
