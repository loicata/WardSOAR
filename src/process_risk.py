"""Local-only risk scoring for a Windows process.

Once the flow-attribution pipeline (:mod:`src.forensics`) identifies
which PID opened the socket behind a Suricata alert, the next
question is "is that process benign or should I worry?". This
module answers with a 0-100 score built from six local signals —
no network call, no reliance on the live socket still being
open, no VT quota burnt:

    1. Authenticode signature (trust anchor)
    2. Binary install path (system / program files / user temp / download)
    3. Parent process identity (Office spawning powershell is bad)
    4. Command line (``-EncodedCommand``, LOLBAS patterns, base64 blobs)
    5. LOLBin usage (rundll32, regsvr32, mshta, certutil, wmic, mshta, bitsadmin)
    6. Binary name heuristics (DLL side-loading, masquerading paths)

The scoring is intentionally additive/subtractive around a 50-point
neutral baseline so a single positive signal can downgrade an
otherwise suspicious process (and vice versa). The final verdict
maps to four bands:

    score <  20  →  benign      🟢
    score 20-49  →  unknown     ⚪
    score 50-79  →  suspicious  🟡
    score ≥  80  →  malicious   🔴

The UI turns the verdict into a coloured badge next to the
``suspect_processes`` entry; the ``signals`` list is surfaced as a
tooltip so the operator can audit the reasoning.

Fail-safe: any subprocess / psutil / filesystem failure degrades to
a neutral score with an appropriate signal rather than raising.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import subprocess  # nosec B404 — invoked with absolute paths, operator-triggered
import time
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import TimeoutExpired  # nosec B404
from typing import Any, Optional

import psutil
from psutil import AccessDenied, NoSuchProcess

from src import win_paths

logger = logging.getLogger("ward_soar.process_risk")


# ---------------------------------------------------------------------------
# Score thresholds
# ---------------------------------------------------------------------------

VERDICT_BENIGN = "benign"
VERDICT_UNKNOWN = "unknown"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

_NEUTRAL_BASELINE = 50

#: Threshold mapping score → verdict. Kept as a tuple of
#: ``(upper_bound, verdict)`` evaluated in order; the first match wins.
_SCORE_BANDS: tuple[tuple[int, str], ...] = (
    (20, VERDICT_BENIGN),
    (50, VERDICT_UNKNOWN),
    (80, VERDICT_SUSPICIOUS),
    (101, VERDICT_MALICIOUS),
)

#: Timeout for the Authenticode PowerShell call. Fast in practice
#: (30-80 ms for a cached file), but clamped so a hung Event Log /
#: slow disk can never stall a forensic run.
_SIGNATURE_TIMEOUT_SECONDS = 5


# ---------------------------------------------------------------------------
# Signer trust list
# ---------------------------------------------------------------------------

#: Substrings found in ``SignerCertificate.Subject`` that mark a
#: publisher as first-party trusted. Match is case-insensitive and
#: deliberately narrow — we do not want to auto-trust every "Ltd"
#: on the planet. Extend by adding to this tuple, never by adding
#: fuzzy matches downstream.
_TRUSTED_SIGNERS: tuple[str, ...] = (
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Mozilla Corporation",
    "Apple Inc",
    "Cisco Systems",
    "Adobe Inc",
    "Adobe Systems",
    "Oracle America",
    "JetBrains",
    "GitHub",
    "Python Software Foundation",
    "Spotify AB",
    "Valve",
    "Riot Games",
    "Logitech",
    "Dropbox",
    "Slack Technologies",
    "Zoom Video",
    "NVIDIA",
    "Intel Corporation",
    "Realtek",
    "Lenovo",
    "Dell Inc",
    "HP Inc",
    "AnthropicPBC",  # our own key when we eventually sign WardSOAR
)


# ---------------------------------------------------------------------------
# Path categories
# ---------------------------------------------------------------------------

_SYSTEM_PATH_PREFIXES: tuple[str, ...] = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\servicing",
    r"c:\windows\winsxs",
    r"c:\windows\microsoft.net",
)

_PROGRAM_FILES_PREFIXES: tuple[str, ...] = (
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata\microsoft",
)

_SUSPECT_PATH_PREFIXES: tuple[str, ...] = (
    r"c:\users\public",
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\downloads",
    r"c:\temp",
    r"c:\windows\temp",
)


# ---------------------------------------------------------------------------
# LOLBins & cmdline heuristics
# ---------------------------------------------------------------------------

#: LOLBAS (Living Off the Land Binaries and Scripts) — legitimate
#: system tools commonly abused for execution, download or persistence.
#: A suspicious *argument pattern* on one of these binaries triggers a
#: heavy score bump.
_LOLBIN_EXECUTABLES: frozenset[str] = frozenset(
    {
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "msiexec.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "cscript.exe",
        "wscript.exe",
        "forfiles.exe",
        "hh.exe",
    }
)

#: Argument patterns that turn a LOLBin into a near-certain attack.
_LOLBIN_SUSPECT_PATTERNS: tuple[str, ...] = (
    r"\burlmon\b",
    r"\bjavascript:",
    r"\bvbscript:",
    r"\bhttp://",
    r"\bhttps://",
    r"\bftp://",
    r"\\\\[^\\\s]+\\",  # UNC path
    r"\bscrobj\.dll\b",
    r"\burl\.dll\b",
    r"\.vbs\b",
    r"\.wsf\b",
    r"\bdecodehex\b",
    r"\bencodehex\b",
    r"-urlcache",
    r"-decode",
    r"-encode",
)

#: Generic command-line markers worth scoring on any process.
_CMDLINE_SUSPECT_PATTERNS: tuple[tuple[str, int, str], ...] = (
    # (pattern, score_delta, human-readable signal)
    (r"-enc\b|-encodedcommand\b", 40, "PowerShell -EncodedCommand argument"),
    (r"-nop\b|-noprofile\b", 5, "PowerShell -NoProfile flag"),
    (r"-w\s*hidden\b|-windowstyle\s+hidden\b", 15, "Hidden window style"),
    (r"-exec\s*bypass\b|-executionpolicy\s+bypass\b", 20, "Execution policy bypass"),
    (r"iex\s*\(|invoke-expression", 25, "PowerShell Invoke-Expression"),
    (r"downloadstring\b|downloadfile\b|webclient", 25, "Network download primitive"),
    (r"frombase64string", 20, "Base64 decode in command line"),
    (r"reflection\.assembly::load", 30, "Reflective assembly load"),
    (r"\bmimikatz\b|\bprocdump\b", 60, "Known offensive tool name"),
)

#: Regex that matches a long-ish base64 blob. Tuned so a legitimate
#: GUID or short token does not trigger; ~80+ printable chars is the
#: sweet spot for obfuscated payloads.
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{80,}")


#: Parent/child combinations that historically indicate an attack
#: chain (Office document spawns powershell, browser spawns cmd, …).
#: Keys are parent names (case-insensitive); values are suspect
#: children. Missing parent → no signal.
_SUSPECT_PARENT_CHILD: dict[str, frozenset[str]] = {
    "winword.exe": frozenset(
        {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe"}
    ),
    "excel.exe": frozenset(
        {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe"}
    ),
    "outlook.exe": frozenset(
        {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe"}
    ),
    "powerpnt.exe": frozenset(
        {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe"}
    ),
    "chrome.exe": frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe"}),
    "msedge.exe": frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe"}),
    "firefox.exe": frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe"}),
    "acrobat.exe": frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe"}),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


#: Absolute ceiling on the binary size we hash + check. 64 MB covers
#: every legitimate Windows exe; anything bigger (an installer extract
#: etc.) is skipped to avoid blocking scan_process on a 2 GB file.
_MAX_HASH_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ProcessRiskResult:
    """Score + rationale for one process.

    Attributes:
        pid: Process ID scored.
        score: 0–100 integer (0 = strongly benign, 100 = strongly
            malicious). Clamped at both ends.
        verdict: ``benign`` / ``unknown`` / ``suspicious`` / ``malicious``.
        signals: Short human-readable strings describing each
            positive or negative factor that affected the score.
            Sorted by impact, positives first.
        signature_status: ``valid`` / ``invalid`` / ``unsigned`` /
            ``hash_mismatch`` / ``unknown`` (subprocess failure).
        signature_signer: Short signer subject name (e.g. ``Microsoft
            Corporation``). Empty when unsigned or unknown.
        parent_name: Lower-cased parent process name, if retrievable.
    """

    pid: int
    score: int
    verdict: str
    signals: list[str] = field(default_factory=list)
    signature_status: str = "unknown"
    signature_signer: str = ""
    parent_name: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for inclusion in a forensic result JSON."""
        return {
            "score": self.score,
            "verdict": self.verdict,
            "signals": list(self.signals),
            "signature_status": self.signature_status,
            "signature_signer": self.signature_signer,
            "parent_name": self.parent_name,
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_process(pid: int) -> ProcessRiskResult:
    """Score ``pid`` on the six local signals.

    Never raises. Returns a neutral-score result on unrecoverable
    failure (process vanished, access denied) so callers can surface
    "unknown" rather than crash their pipeline.
    """
    try:
        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()
        exe_path = proc.exe() or ""
        cmdline = proc.cmdline() or []
    except (NoSuchProcess, AccessDenied, OSError) as exc:
        logger.debug("Cannot inspect PID %d for risk scoring: %s", pid, exc)
        return ProcessRiskResult(
            pid=pid,
            score=_NEUTRAL_BASELINE,
            verdict=VERDICT_UNKNOWN,
            signals=["Process no longer accessible"],
        )

    score = _NEUTRAL_BASELINE
    signals: list[tuple[int, str]] = []  # (absolute-delta, text) — sorted at end

    # ---- Signature ---------------------------------------------------
    sig_status, sig_signer = _check_signature(exe_path)
    if sig_status == "valid" and _is_trusted_signer(sig_signer):
        score -= 30
        signals.append((30, f"Signed by trusted publisher: {sig_signer}"))
    elif sig_status == "valid":
        score -= 15
        signals.append((15, f"Signed (non-trusted publisher: {sig_signer or 'unknown'})"))
    elif sig_status == "unsigned":
        score += 20
        signals.append((20, "Unsigned binary"))
    elif sig_status == "hash_mismatch":
        score += 50
        signals.append((50, "Authenticode hash mismatch — binary likely altered"))
    elif sig_status == "invalid":
        score += 35
        signals.append((35, "Invalid Authenticode signature"))
    # "unknown" → no delta, we just could not check

    # ---- Path --------------------------------------------------------
    path_lower = exe_path.lower()
    if any(path_lower.startswith(p) for p in _SYSTEM_PATH_PREFIXES):
        score -= 15
        signals.append((15, "Runs from Windows system directory"))
    elif any(path_lower.startswith(p) for p in _PROGRAM_FILES_PREFIXES):
        score -= 10
        signals.append((10, "Runs from Program Files"))
    if any(sub in path_lower for sub in _SUSPECT_PATH_PREFIXES):
        score += 25
        signals.append((25, "Runs from user-writable / temp directory"))

    # ---- Parent process ---------------------------------------------
    parent_name: Optional[str] = None
    try:
        parent = proc.parent()
        if parent is not None:
            parent_name = (parent.name() or "").lower()
    except (NoSuchProcess, AccessDenied):
        pass
    if parent_name:
        suspect_children = _SUSPECT_PARENT_CHILD.get(parent_name)
        if suspect_children and name in suspect_children:
            score += 30
            signals.append(
                (30, f"Parent {parent_name} spawning {name} is a classic attack pattern")
            )

    # ---- Command-line heuristics ------------------------------------
    joined_cmdline = " ".join(cmdline)
    low_cmdline = joined_cmdline.lower()

    for pattern, delta, text in _CMDLINE_SUSPECT_PATTERNS:
        if re.search(pattern, low_cmdline):
            score += delta
            signals.append((delta, text))

    # Base64 blob heuristic: scored only when long (80+ chars) AND
    # decodes to high-entropy bytes. A plain UUID would not match the
    # length, but a legitimate long token might; we sanity-check by
    # attempting the decode.
    for blob in _BASE64_BLOB_RE.findall(joined_cmdline):
        if _looks_like_binary_base64(blob):
            score += 20
            signals.append((20, f"Long base64 blob in cmdline ({len(blob)} chars)"))
            break  # one flag is enough — no need to double-dip

    # ---- LOLBin pattern check ---------------------------------------
    if name in _LOLBIN_EXECUTABLES:
        if any(re.search(pat, low_cmdline) for pat in _LOLBIN_SUSPECT_PATTERNS):
            score += 35
            signals.append((35, f"LOLBin ({name}) with suspicious arguments"))

    # ---- Process age --------------------------------------------------
    # Very fresh processes that immediately do network are more
    # suspicious than long-running services; very old ones (boot-time)
    # are probably legit baseline. Neutral in between.
    age_delta, age_signal = _age_signal(proc)
    if age_signal:
        score += age_delta
        signals.append((abs(age_delta), age_signal))

    # ---- Process tree depth from a system root -----------------------
    # A deep parent chain from explorer/services (>=5 hops) is the
    # shape of an exploit: explorer → office → powershell → wmic →
    # net → ... Legitimate user apps are rarely more than 3-4 hops.
    depth_delta, depth_signal = _tree_depth_signal(proc)
    if depth_signal:
        score += depth_delta
        signals.append((abs(depth_delta), depth_signal))

    # ---- Windows Defender verdict ------------------------------------
    # Cheap when the binary is already Microsoft-signed or when the
    # hash is cached. Otherwise spawns MpCmdRun once per unique
    # binary. Skipped when we already trust the signature to avoid
    # burning local AV cycles on svchost.exe / chrome.exe.
    if not (sig_status == "valid" and _is_trusted_signer(sig_signer)):
        def_delta, def_signal = _defender_signal(exe_path)
        if def_signal:
            score += def_delta
            signals.append((abs(def_delta), def_signal))

    # ---- YARA rules scan ---------------------------------------------
    # Same skip heuristic as Defender (trusted signatures are not worth
    # scanning). Matches are additive up to a cap so ten rules on the
    # same family do not pin the score to 100 on their own.
    if not (sig_status == "valid" and _is_trusted_signer(sig_signer)):
        yara_delta, yara_signal = _yara_signal(exe_path)
        if yara_signal:
            score += yara_delta
            signals.append((abs(yara_delta), yara_signal))

    # ---- DLL load-set heuristic (Phase C light) ----------------------
    # A process that has loaded DLLs from non-system paths (Temp,
    # Downloads, AppData\\Local\\Temp, …) is a weak-but-real signal
    # of DLL side-loading or manual injection via ``LoadLibrary``.
    # This helper does NOT try to detect memory-only injection (that
    # would need VirtualQueryEx / PPL access) — it only walks the
    # list ``psutil`` already exposes.
    dll_delta, dll_signal = _dll_loadset_signal(proc)
    if dll_signal:
        score += dll_delta
        signals.append((abs(dll_delta), dll_signal))

    # ---- Layer 3: VirusTotal cache lookup ---------------------------
    # Skip when Authenticode already trusts the binary — Microsoft /
    # trusted-publisher code is almost never worth a VT call; the
    # binary hash is also a privacy cost (leaks through past VT
    # queries). For the remaining population (unsigned, untrusted
    # signer, invalid signature), the cache is consulted. Cache miss
    # means no signal — we never burn the VT quota from the scorer.
    if not (sig_status == "valid" and _is_trusted_signer(sig_signer)):
        vt_delta, vt_signal = _vt_cache_signal(exe_path)
        if vt_signal:
            score += vt_delta
            signals.append((abs(vt_delta), vt_signal))

    # ---- Clamp + verdict --------------------------------------------
    score = max(0, min(100, score))
    verdict = _verdict_for(score)

    # Sort signals: biggest impact first, then lexicographic.
    signals.sort(key=lambda s: (-s[0], s[1]))

    return ProcessRiskResult(
        pid=pid,
        score=score,
        verdict=verdict,
        signals=[text for _delta, text in signals],
        signature_status=sig_status,
        signature_signer=sig_signer,
        parent_name=parent_name,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verdict_for(score: int) -> str:
    """Map a numeric score to a verdict label."""
    for upper, verdict in _SCORE_BANDS:
        if score < upper:
            return verdict
    return VERDICT_MALICIOUS


def _is_trusted_signer(signer: str) -> bool:
    """True when ``signer`` contains any entry of :data:`_TRUSTED_SIGNERS`."""
    if not signer:
        return False
    lower = signer.lower()
    return any(trust.lower() in lower for trust in _TRUSTED_SIGNERS)


def _looks_like_binary_base64(blob: str) -> bool:
    """Sanity-check that a base64 candidate decodes into high-entropy bytes.

    Prevents flagging long legitimate tokens that happen to live in the
    base64 charset (UUIDs, session ids). Attempts a decode; if the
    result has a printable-ratio below 80%, treat it as "binary" and
    therefore suspicious.
    """
    try:
        decoded = base64.b64decode(blob, validate=False)
    except (binascii.Error, ValueError):
        return False
    if not decoded:
        return False
    printable = sum(1 for byte in decoded if 0x20 <= byte <= 0x7E or byte in (0x09, 0x0A, 0x0D))
    return (printable / len(decoded)) < 0.8


def _check_signature(exe_path: str) -> tuple[str, str]:
    """Invoke PowerShell ``Get-AuthenticodeSignature`` on ``exe_path``.

    Returns:
        Tuple ``(status, signer_short_subject)``.
        ``status`` is one of ``valid`` / ``invalid`` /
        ``unsigned`` / ``hash_mismatch`` / ``unknown``.
        ``signer_short_subject`` is the first ``CN=<…>`` / ``O=<…>``
        value from the certificate subject, empty when the file is
        unsigned or on query failure.
    """
    if not exe_path:
        return "unknown", ""
    path = Path(exe_path)
    if not path.is_file():
        return "unknown", ""

    ps_exe = getattr(win_paths, "POWERSHELL", None)
    if not ps_exe or not Path(str(ps_exe)).is_file():
        return "unknown", ""

    # Use -LiteralPath so filenames with brackets / dollars / etc. are
    # handled without glob expansion. ConvertTo-Json emits the fields
    # we care about (Status, SubjectName); Status strings come from
    # ``[System.Management.Automation.SignatureStatus]`` enum.
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{path}';"
        "if($sig){"
        " $obj = @{"
        "  Status = $sig.Status.ToString();"
        "  Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }"
        " };"
        " $obj | ConvertTo-Json -Compress"
        '} else { \'{"Status":"Unknown","Subject":""}\' }'
    )

    try:
        result = subprocess.run(  # nosec B603 — absolute path + hardcoded args
            [str(ps_exe), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=_SIGNATURE_TIMEOUT_SECONDS,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (FileNotFoundError, OSError, TimeoutExpired) as exc:
        logger.debug("Authenticode check failed for %s: %s", exe_path, exc)
        return "unknown", ""

    if result.returncode != 0 or not result.stdout:
        return "unknown", ""

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return "unknown", ""

    raw_status = str(payload.get("Status") or "").lower()
    raw_subject = str(payload.get("Subject") or "")

    status_map = {
        "valid": "valid",
        "notsigned": "unsigned",
        "hashmismatch": "hash_mismatch",
        "notsupportedfiletype": "unknown",
        "incompatible": "unknown",
    }
    status = status_map.get(raw_status, "invalid" if raw_status else "unknown")
    signer = _extract_signer_short_name(raw_subject)
    return status, signer


#: Thresholds (seconds) for the process-age signal. Very fresh =
#: more suspicious when a Suricata alert fires on it; very old =
#: trusted baseline (boot-time services).
_AGE_FRESH_SECONDS = 5 * 60  # <5 min since launch
_AGE_STALE_SECONDS = 24 * 3600  # >24 h since launch

#: Depth threshold for the parent-chain heuristic. A chain longer
#: than this — measured from a system root like explorer.exe — is
#: usually not a legitimate app pattern.
_TREE_DEPTH_THRESHOLD = 5

#: Names that anchor the tree-depth walk: we count hops back to any
#: of these before deciding whether the current process is too far
#: downstream. Adding a new root means a new "natural baseline" for
#: descendants.
_TREE_DEPTH_ROOTS: frozenset[str] = frozenset(
    {
        "explorer.exe",
        "services.exe",
        "wininit.exe",
        "winlogon.exe",
        "system",
        "systemd",  # WSL interop edge case
    }
)

#: Cache the Defender verdict in-process for the lifetime of the
#: scorer. VTCache (SQLite) already persists verdicts across restarts;
#: this layer skips the hash computation + subprocess even on
#: back-to-back calls for the same PID before anything else cached.
_DEFENDER_VERDICT_CACHE: dict[str, tuple[int, str]] = {}

#: YARA verdict cache — keyed by binary path. Compiled rules are kept
#: separately in ``_YARA_COMPILED_RULES`` so we do not re-compile the
#: rules directory on every scan.
_YARA_VERDICT_CACHE: dict[str, tuple[int, str]] = {}
_YARA_COMPILED_RULES: Any = None
_YARA_LOAD_ATTEMPTED: bool = False
_YARA_TIMEOUT_SECONDS = 10

#: Per-call timeout for the Defender scan. MpCmdRun is usually fast
#: on small executables (<500 ms) but can take a few seconds if the
#: engine is busy. Clamped so the scorer never stalls the pipeline.
_DEFENDER_TIMEOUT_SECONDS = 30


def _age_signal(proc: "psutil.Process") -> tuple[int, str]:
    """Return a score delta + signal text based on process uptime."""
    try:
        age = max(0.0, time.time() - float(proc.create_time()))
    except (NoSuchProcess, AccessDenied, OSError):
        return 0, ""
    if age < _AGE_FRESH_SECONDS:
        return 10, f"Process is very fresh ({int(age)} s since launch)"
    if age > _AGE_STALE_SECONDS:
        return -5, f"Long-running process ({int(age // 3600)} h uptime)"
    return 0, ""


def _tree_depth_signal(proc: "psutil.Process") -> tuple[int, str]:
    """Count the parent hops until a system root; flag long chains."""
    try:
        parents = proc.parents()
    except (NoSuchProcess, AccessDenied, OSError):
        return 0, ""

    depth_to_root = 0
    for parent in parents:
        depth_to_root += 1
        try:
            parent_name = (parent.name() or "").lower()
        except (NoSuchProcess, AccessDenied):
            continue
        if parent_name in _TREE_DEPTH_ROOTS:
            break

    if depth_to_root >= _TREE_DEPTH_THRESHOLD:
        return 20, (
            f"Long parent chain — {depth_to_root} hops from a system root, "
            "consistent with exploitation chains"
        )
    return 0, ""


def _defender_signal(exe_path: str) -> tuple[int, str]:
    """Run Windows Defender on ``exe_path`` and map the verdict to a delta.

    Returns ``(0, "")`` on any failure or when MpCmdRun is missing.
    Defender hits are memoised in :data:`_DEFENDER_VERDICT_CACHE` so a
    flood of alerts on the same binary runs one scan.
    """
    if not exe_path:
        return 0, ""
    path = Path(exe_path)
    if not path.is_file():
        return 0, ""

    mpcmdrun = getattr(win_paths, "MPCMDRUN", None)
    if not mpcmdrun or not Path(str(mpcmdrun)).is_file():
        return 0, ""

    cache_key = str(path)
    cached = _DEFENDER_VERDICT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    try:
        result = subprocess.run(  # nosec B603 — absolute path + hardcoded args
            [
                str(mpcmdrun),
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                str(path),
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            timeout=_DEFENDER_TIMEOUT_SECONDS,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (FileNotFoundError, OSError, TimeoutExpired) as exc:
        logger.debug("Defender scan failed for %s: %s", exe_path, exc)
        return 0, ""

    # MpCmdRun conventions:
    #   rc=0  → clean
    #   rc=2  → threat detected
    #   rc!=0,2 → inconclusive / environment issue
    if result.returncode == 2:
        threat = _extract_defender_threat(result.stdout or "")
        signal = (
            f"Windows Defender flagged the binary: {threat}"
            if threat
            else "Windows Defender flagged the binary"
        )
        verdict = (70, signal)
        _DEFENDER_VERDICT_CACHE[cache_key] = verdict
        return verdict
    if result.returncode == 0:
        verdict = (-15, "Windows Defender: binary scanned clean")
        _DEFENDER_VERDICT_CACHE[cache_key] = verdict
        return verdict

    return 0, ""


#: Paths we consider "normal" for a loaded DLL. Anything outside
#: these roots suggests the DLL was dropped by the process itself or
#: hand-loaded via ``LoadLibrary`` — the classic pattern for DLL
#: side-loading (cobaltstrike, plugx, …). Match is case-insensitive.
_DLL_SYSTEM_ROOTS: tuple[str, ...] = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\windows\microsoft.net",
    r"c:\windows\assembly",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata\microsoft",
)

#: Suspect path fragments for a loaded DLL. A DLL under any of these
#: earns the full delta; multiple hits are accumulated up to a cap.
_DLL_SUSPECT_FRAGMENTS: tuple[str, ...] = (
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\downloads\\",
    r"\users\public\\",
    r"c:\temp\\",
    r"c:\windows\temp",
)


def _dll_loadset_signal(proc: "psutil.Process") -> tuple[int, str]:
    """Flag processes that have a DLL loaded from a user-writable path.

    Walks ``proc.memory_maps()`` (psutil), case-insensitively matches
    against a small suspect-path list, and returns a ``(delta, text)``
    tuple. Delta grows with the number of suspicious DLLs, capped
    at +40 so a noisy but legitimate loader (rare) does not pin the
    score on DLLs alone.

    Returns ``(0, "")`` on any error — psutil denies memory_maps for
    protected processes on non-admin sessions, that is expected.
    """
    try:
        maps = proc.memory_maps(grouped=False)
    except (NoSuchProcess, AccessDenied, OSError, NotImplementedError):
        return 0, ""

    suspect_paths: list[str] = []
    for entry in maps:
        path = (getattr(entry, "path", "") or "").lower()
        if not path or not path.endswith(".dll"):
            continue
        # Skip anything clearly in a system / Program Files tree.
        if any(path.startswith(root) for root in _DLL_SYSTEM_ROOTS):
            continue
        if any(frag in path for frag in _DLL_SUSPECT_FRAGMENTS):
            suspect_paths.append(path)

    if not suspect_paths:
        return 0, ""

    delta = min(40, 15 * len(suspect_paths))
    # Trim + dedupe the display list so the tooltip stays readable.
    unique_display = sorted({Path(p).name for p in suspect_paths})[:4]
    more = len(set(suspect_paths)) - len(unique_display)
    suffix = f" (+{more} more)" if more > 0 else ""
    signal = (
        f"Suspicious DLL(s) loaded from user-writable path: {', '.join(unique_display)}{suffix}"
    )
    return delta, signal


def _load_yara_rules() -> Any:
    """Compile the project's YARA rules once and keep them in memory.

    Returns the compiled rules object (``yara.Rules``) or ``None``
    when the directory is missing, empty, or a rule has a syntax
    error. Any failure is logged at DEBUG — the scorer simply
    skips the YARA signal in that case.
    """
    global _YARA_COMPILED_RULES, _YARA_LOAD_ATTEMPTED  # noqa: PLW0603 — cached singletons
    if _YARA_LOAD_ATTEMPTED:
        return _YARA_COMPILED_RULES
    _YARA_LOAD_ATTEMPTED = True

    try:
        import yara
    except ImportError:
        logger.debug("yara-python not installed — process-risk YARA layer disabled")
        return None

    try:
        from src.config import get_bundle_dir
    except Exception:  # noqa: BLE001 — config module optional in tests
        return None

    rules_dir = get_bundle_dir() / "config" / "yara_rules"
    if not rules_dir.is_dir():
        logger.debug("YARA rules dir missing: %s", rules_dir)
        return None

    files: dict[str, str] = {}
    for path in sorted(rules_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}:
            files[path.stem] = str(path)
    if not files:
        return None

    try:
        _YARA_COMPILED_RULES = yara.compile(filepaths=files)
        logger.info("process_risk: YARA rules compiled (%d file[s])", len(files))
    except Exception as exc:  # noqa: BLE001 — any yara error disables the layer
        logger.debug("YARA compile failed in process_risk: %s", exc)
        _YARA_COMPILED_RULES = None
    return _YARA_COMPILED_RULES


def _yara_signal(exe_path: str) -> tuple[int, str]:
    """Match ``exe_path`` against the compiled YARA rules.

    Returns ``(score_delta, signal_text)``:
        * match → ``(min(60, 30 * n_matches), "YARA match: rule1, rule2, …")``
        * no match / no rules → ``(0, "")``

    The cap at +60 avoids turning an alert into malicious purely on
    ten rules from the same family. Verdict is cached by path so a
    flood on the same PID runs one match.
    """
    if not exe_path:
        return 0, ""
    path = Path(exe_path)
    if not path.is_file():
        return 0, ""

    cached = _YARA_VERDICT_CACHE.get(str(path))
    if cached is not None:
        return cached

    rules = _load_yara_rules()
    if rules is None:
        return 0, ""

    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.debug("YARA: cannot read %s: %s", exe_path, exc)
        return 0, ""

    try:
        matches = rules.match(data=data, timeout=_YARA_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 — yara-python raises many subclasses
        logger.debug("YARA match error for %s: %s", exe_path, exc)
        return 0, ""

    if not matches:
        verdict = (0, "")
        _YARA_VERDICT_CACHE[str(path)] = verdict
        return verdict

    rule_names = [m.rule for m in matches]
    delta = min(60, 30 * len(rule_names))
    signal = f"YARA match: {', '.join(rule_names[:5])}"
    if len(rule_names) > 5:
        signal += f" (+{len(rule_names) - 5} more)"
    verdict = (delta, signal)
    _YARA_VERDICT_CACHE[str(path)] = verdict
    return verdict


def _extract_defender_threat(stdout: str) -> str:
    """Parse MpCmdRun output for the ``Threat <name> identified.`` line."""
    match = re.search(r"Threat\s+([^\s]+?)\s+identified\.", stdout)
    return match.group(1) if match else ""


def _sha256_file(path: str) -> Optional[str]:
    """Hash a file on disk, returning ``None`` on any failure.

    Bounded by :data:`_MAX_HASH_BYTES` so a giant installer binary
    cannot stall the scorer. Chunks of 1 MB keep memory flat.
    """
    try:
        p = Path(path)
        if not p.is_file():
            return None
        if p.stat().st_size > _MAX_HASH_BYTES:
            return None
    except OSError:
        return None

    sha = hashlib.sha256()
    try:
        with p.open("rb") as f:
            while True:
                chunk = f.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                sha.update(chunk)
    except OSError:
        return None
    return sha.hexdigest()


def _vt_cache_signal(exe_path: str) -> tuple[int, str]:
    """Consult :class:`VTCache` for the binary hash of ``exe_path``.

    Returns a ``(score_delta, signal_text)`` tuple:
        * **cache hit, malicious** → ``(+60, "VirusTotal: N/M engines flagged (cached)")``
        * **cache hit, clean** → ``(-25, "VirusTotal: clean (cached)")``
        * **cache miss / error** → ``(0, "")`` — scorer adds nothing.

    Never raises. Deliberately does *not* call the VT API itself; the
    scorer only reads from the cache that the main pipeline has
    already populated. This keeps scan_process local and fast.
    """
    if not exe_path:
        return 0, ""

    file_hash = _sha256_file(exe_path)
    if file_hash is None:
        return 0, ""

    try:
        from src.config import get_data_dir
        from src.vt_cache import VTCache
    except Exception:  # noqa: BLE001 — optional dependency path
        return 0, ""

    try:
        cache = VTCache(db_path=get_data_dir() / "data" / "vt_cache.db")
    except Exception:  # noqa: BLE001 — SQLite init failures must not break forensics
        logger.debug("VTCache init raised in process_risk", exc_info=True)
        return 0, ""

    try:
        entry = cache.lookup(file_hash)
    except Exception:  # noqa: BLE001
        logger.debug("VTCache lookup raised in process_risk", exc_info=True)
        return 0, ""

    if entry is None:
        return 0, ""

    if entry.is_malicious:
        ratio = (
            f"{entry.detection_count}/{entry.total_engines}"
            if entry.total_engines
            else str(entry.detection_count)
        )
        return 60, f"VirusTotal: {ratio} engines flagged the binary (cached)"
    return -25, "VirusTotal: binary rated clean (cached)"


def _extract_signer_short_name(subject: str) -> str:
    """Extract ``O=``/``CN=`` short name from a certificate Subject string."""
    if not subject:
        return ""
    # Certificate subjects look like
    # "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, ...".
    for key in ("CN=", "O="):
        for chunk in subject.split(","):
            chunk = chunk.strip()
            if chunk.startswith(key):
                return chunk[len(key) :].strip('"')
    return subject[:64]  # fallback: trimmed raw


__all__ = (
    "ProcessRiskResult",
    "VERDICT_BENIGN",
    "VERDICT_MALICIOUS",
    "VERDICT_SUSPICIOUS",
    "VERDICT_UNKNOWN",
    "scan_process",
)
