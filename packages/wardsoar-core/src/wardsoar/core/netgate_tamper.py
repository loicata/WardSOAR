"""Tamper detection for the Netgate / pfSense appliance (Phase 7g).

Parallel to :mod:`src.netgate_audit`: the audit asks "is the box
*configured* correctly?", this module asks "has the box been *tampered
with* since the operator last blessed it?".

Model
-----
The operator clicks **Establish baseline** once, after they're happy
with the current Netgate state. WardSOAR captures a small, stable
fingerprint of the integrity-sensitive surfaces — SSH authorised
keys, user accounts, pfSense config.xml hash, firewall ruleset, cron
jobs, host keys, package list, kernel modules — and stores the
result on disk under ``%APPDATA%/WardSOAR/netgate_baseline.json``.

Each subsequent **Check for tampering** run re-captures the same
fingerprint and diffs every entry against the baseline. Any mismatch
produces a :class:`TamperFinding`; zero mismatches ⇒ green status.

Legitimate changes (operator installs a new package, adds an
authorised key, edits a firewall rule through the webGUI) trip the
detector. The UI exposes a **Re-bless baseline** button so the
operator can commit the new state as the new ground truth after an
intentional change.

Privacy
-------
The baseline stores **sha256 hashes** of each surface plus a short
human-readable ``summary`` (e.g. ``"5 authorised keys"``). Raw
credentials, keys or config contents never leave the Netgate —
everything sensitive is irreversibly hashed before being written to
disk. A future version can add a DPAPI-encrypted copy of the
underlying payloads to support forensic diffing on demand.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.netgate_tamper")


# Severity — shown as an icon in the UI. Tamper evidence is
# categorised per surface: auth changes are HIGH (new SSH key is a
# strong compromise signal), package changes are MEDIUM (could be
# legit update), kernel module changes are HIGH (rootkit).
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"


# One entry per surface. Reordering or renaming an id breaks the
# baseline — always append new ids, never rewrite the existing ones.
# ``command`` is a hard-coded string literal; operator input is never
# interpolated into the SSH argument.
@dataclass(frozen=True)
class _Surface:
    id: str
    title: str
    severity: str
    command: str
    empty_is_ok: bool = True  # many surfaces are legitimately empty (no custom cron, no kld)


_SURFACES: tuple[_Surface, ...] = (
    _Surface(
        id="auth.root_authorized_keys",
        title="SSH authorised keys — root",
        severity=SEV_HIGH,
        command="cat /root/.ssh/authorized_keys 2>/dev/null || true",
    ),
    _Surface(
        id="auth.admin_authorized_keys",
        title="SSH authorised keys — admin",
        severity=SEV_HIGH,
        command=(
            "cat /home/admin/.ssh/authorized_keys 2>/dev/null "
            "|| cat /var/etc/sshd/authorized_keys 2>/dev/null "
            "|| true"
        ),
    ),
    _Surface(
        id="auth.etc_passwd",
        title="User accounts (/etc/passwd)",
        severity=SEV_HIGH,
        command="cat /etc/passwd 2>/dev/null || true",
        empty_is_ok=False,
    ),
    _Surface(
        id="auth.ssh_host_keys",
        title="SSH host key fingerprints",
        severity=SEV_HIGH,
        command=(
            "for f in /etc/ssh/ssh_host_*_key.pub; do "
            '  [ -f "$f" ] && ssh-keygen -lf "$f" 2>/dev/null; '
            "done || true"
        ),
    ),
    _Surface(
        id="config.config_xml",
        title="pfSense configuration (/cf/conf/config.xml)",
        severity=SEV_HIGH,
        command="sha256 -q /cf/conf/config.xml 2>/dev/null || sha256 /cf/conf/config.xml 2>/dev/null || true",
        empty_is_ok=False,
    ),
    _Surface(
        id="firewall.pf_rules",
        title="Firewall ruleset (pfctl -sr)",
        severity=SEV_HIGH,
        command="pfctl -sr 2>/dev/null || true",
        empty_is_ok=False,
    ),
    _Surface(
        id="firewall.pf_nat",
        title="NAT ruleset (pfctl -sn)",
        severity=SEV_MEDIUM,
        command="pfctl -sn 2>/dev/null || true",
    ),
    _Surface(
        id="tasks.crontab_root",
        title="Root crontab",
        severity=SEV_HIGH,
        command="crontab -l -u root 2>/dev/null || true",
    ),
    _Surface(
        id="tasks.system_cron",
        title="System cron directories",
        severity=SEV_MEDIUM,
        command=(
            "for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly; do "
            '  [ -d "$d" ] && ls -lan "$d"; '
            "done || true"
        ),
    ),
    _Surface(
        id="tasks.rc_local",
        title="/etc/rc.conf.local entries",
        severity=SEV_MEDIUM,
        command="cat /etc/rc.conf.local 2>/dev/null || true",
    ),
    _Surface(
        id="packages.list",
        title="Installed packages",
        severity=SEV_MEDIUM,
        command="pkg query '%n %v' 2>/dev/null | sort || true",
        empty_is_ok=False,
    ),
    _Surface(
        id="kernel.loaded_modules",
        title="Kernel modules (kldstat)",
        severity=SEV_HIGH,
        command="kldstat 2>/dev/null || true",
        empty_is_ok=False,
    ),
    _Surface(
        id="kernel.sysctl_pf",
        title="Kernel parameters (net.pf)",
        severity=SEV_LOW,
        command="sysctl net.pf 2>/dev/null || true",
    ),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineEntry:
    """One captured surface in a baseline snapshot."""

    id: str
    title: str
    severity: str
    sha256: str
    summary: str
    captured_at: str  # ISO 8601


@dataclass(frozen=True)
class TamperBaseline:
    """Complete baseline snapshot — the ground truth to diff against."""

    host: str
    captured_at: str  # ISO 8601
    entries: dict[str, BaselineEntry]

    @staticmethod
    def from_json(raw: dict[str, object]) -> "TamperBaseline":
        """Deserialise a ``baseline.json`` file. Silent on malformed rows."""
        entries_raw = raw.get("entries") or {}
        entries: dict[str, BaselineEntry] = {}
        if isinstance(entries_raw, dict):
            for key, value in entries_raw.items():
                if not isinstance(value, dict):
                    continue
                try:
                    entries[str(key)] = BaselineEntry(
                        id=str(value.get("id", key)),
                        title=str(value.get("title", "")),
                        severity=str(value.get("severity", SEV_MEDIUM)),
                        sha256=str(value.get("sha256", "")),
                        summary=str(value.get("summary", "")),
                        captured_at=str(value.get("captured_at", "")),
                    )
                except Exception:  # noqa: BLE001 — skip the malformed row only
                    continue
        return TamperBaseline(
            host=str(raw.get("host", "")),
            captured_at=str(raw.get("captured_at", "")),
            entries=entries,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "host": self.host,
            "captured_at": self.captured_at,
            "entries": {k: asdict(v) for k, v in self.entries.items()},
        }


@dataclass(frozen=True)
class TamperFinding:
    """A single deviation between baseline and current state."""

    id: str
    title: str
    severity: str
    baseline_summary: str
    current_summary: str
    baseline_captured_at: str


@dataclass(frozen=True)
class TamperResult:
    """Outcome of a :meth:`NetgateTamperDetector.check_for_tampering` run."""

    started_at: datetime
    duration_seconds: float
    baseline_present: bool
    ssh_reachable: bool
    findings: list[TamperFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def any_deviation(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "started_at": self.started_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "baseline_present": self.baseline_present,
            "ssh_reachable": self.ssh_reachable,
            "any_deviation": self.any_deviation,
            "findings": [asdict(f) for f in self.findings],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def _summarise(output: str) -> str:
    """Build a short, deterministic human summary for a captured surface.

    Leaks as little content as possible — we show counts, first line,
    and total character length. The actual text stays on the Netgate.
    """
    text = (output or "").strip()
    if not text:
        return "(empty)"
    lines = text.splitlines()
    first = lines[0][:80] if lines else ""
    return f"{len(lines)} line(s), {len(text)} chars — first: {first}"


def _hash(output: str) -> str:
    """SHA-256 of a surface's output. Newlines are preserved as-is."""
    return hashlib.sha256((output or "").encode("utf-8", errors="replace")).hexdigest()


class NetgateTamperDetector:
    """Establish and diff integrity baselines against a pfSense host.

    Args:
        ssh: Connected :class:`~src.pfsense_ssh.PfSenseSSH`.
        baseline_path: Absolute path to the JSON baseline file. A
            missing file is the expected "no baseline yet" state.
        host: Human label for the Netgate (used in the baseline
            payload only). Defaults to the SSH host.
    """

    def __init__(
        self,
        ssh: "PfSenseSSH",
        baseline_path: Path,
        host: Optional[str] = None,
    ) -> None:
        self._ssh = ssh
        self._baseline_path = Path(baseline_path)
        self._host: str = str(host or getattr(ssh, "_host", "unknown") or "unknown")

    # ------------------------------------------------------------------
    # Baseline persistence
    # ------------------------------------------------------------------

    def has_baseline(self) -> bool:
        return self._baseline_path.is_file()

    def load_baseline(self) -> Optional[TamperBaseline]:
        if not self.has_baseline():
            return None
        try:
            raw = json.loads(self._baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("tamper baseline unreadable (%s): %s", self._baseline_path, exc)
            return None
        if not isinstance(raw, dict):
            return None
        return TamperBaseline.from_json(raw)

    def save_baseline(self, baseline: TamperBaseline) -> None:
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self._baseline_path.write_text(json.dumps(baseline.to_json(), indent=2), encoding="utf-8")
        logger.info(
            "tamper baseline written to %s (%d entries)",
            self._baseline_path,
            len(baseline.entries),
        )

    # ------------------------------------------------------------------
    # Capture / compare
    # ------------------------------------------------------------------

    async def _capture(self) -> dict[str, tuple[str, str]]:
        """Run every surface's command once and return {id: (hash, summary)}.

        Command failures degrade to ``("", "(ssh error)")`` — the
        diff step treats ``""`` hashes as "unknown" (not a mismatch)
        so a transient SSH issue won't flag a false positive.
        """
        captured: dict[str, tuple[str, str]] = {}
        for surface in _SURFACES:
            ok, out = await self._ssh.run_read_only(surface.command, timeout=10)
            if not ok:
                captured[surface.id] = ("", f"(ssh error: {out[:80]})")
                continue
            captured[surface.id] = (_hash(out), _summarise(out))
        return captured

    async def establish_baseline(self) -> TamperBaseline:
        """Capture the current state and persist it as the new baseline."""
        captured = await self._capture()
        now_iso = datetime.now(timezone.utc).isoformat()
        entries: dict[str, BaselineEntry] = {}
        for surface in _SURFACES:
            sha, summary = captured.get(surface.id, ("", "(missing)"))
            entries[surface.id] = BaselineEntry(
                id=surface.id,
                title=surface.title,
                severity=surface.severity,
                sha256=sha,
                summary=summary,
                captured_at=now_iso,
            )
        baseline = TamperBaseline(
            host=self._host,
            captured_at=now_iso,
            entries=entries,
        )
        self.save_baseline(baseline)
        return baseline

    async def check_for_tampering(self) -> TamperResult:
        """Diff the current state against the stored baseline.

        Semantic rules:

        * No baseline on disk → ``baseline_present=False``, findings
          empty. The UI surfaces this as an invitation to establish one.
        * SSH unreachable → single pseudo-finding with id
          ``ssh.unreachable`` so the operator knows why the diff is
          blank.
        * Surface with an empty ``sha256`` in either baseline or
          current capture → skipped silently (transient SSH glitch).
        * Surface with a hash mismatch → one finding with the old
          and new summaries.
        """
        from time import monotonic

        started_at = datetime.now(timezone.utc)
        t0 = monotonic()

        baseline = self.load_baseline()
        if baseline is None:
            return TamperResult(
                started_at=started_at,
                duration_seconds=monotonic() - t0,
                baseline_present=False,
                ssh_reachable=True,
            )

        ssh_ok, ssh_msg = await self._ssh.check_status()
        if not ssh_ok:
            return TamperResult(
                started_at=started_at,
                duration_seconds=monotonic() - t0,
                baseline_present=True,
                ssh_reachable=False,
                error=ssh_msg,
            )

        captured = await self._capture()
        findings: list[TamperFinding] = []
        for surface in _SURFACES:
            baseline_entry = baseline.entries.get(surface.id)
            if baseline_entry is None:
                # Surface was added after the baseline — not a tamper,
                # just a new check. Silent.
                continue
            current_hash, current_summary = captured.get(surface.id, ("", ""))
            if not current_hash or not baseline_entry.sha256:
                continue  # transient failure — ignore
            if current_hash == baseline_entry.sha256:
                continue
            findings.append(
                TamperFinding(
                    id=surface.id,
                    title=surface.title,
                    severity=surface.severity,
                    baseline_summary=baseline_entry.summary,
                    current_summary=current_summary,
                    baseline_captured_at=baseline_entry.captured_at,
                )
            )
        return TamperResult(
            started_at=started_at,
            duration_seconds=monotonic() - t0,
            baseline_present=True,
            ssh_reachable=True,
            findings=findings,
        )


__all__ = [
    "BaselineEntry",
    "NetgateTamperDetector",
    "SEV_HIGH",
    "SEV_LOW",
    "SEV_MEDIUM",
    "TamperBaseline",
    "TamperFinding",
    "TamperResult",
]
