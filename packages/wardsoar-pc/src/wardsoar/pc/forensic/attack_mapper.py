"""Map captured evidence to MITRE ATT&CK techniques.

The goal isn't to produce a forensic-grade ATT&CK mapping (that needs
human review); it's to give the analyst a jump-off point. The mapper
scans Suricata categories + signature strings + Sysmon descriptions
for well-known keyword patterns and attaches the matching technique
IDs with a ``confidence`` score.

Each matched technique carries:
    - ``technique_id``: ATT&CK identifier (e.g. ``T1059.001``).
    - ``name``: short human name.
    - ``tactic``: one of the 14 ATT&CK tactics.
    - ``confidence``: 0.0-1.0, derived from number of matching triggers.
    - ``triggers``: the verbatim phrases that matched, for audit.

The mapping table is deliberately small and curated — a bigger table
means more false positives. Extend it only when a pattern is
unambiguous in this context.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from wardsoar.core.models import DecisionRecord


@dataclass
class TechniqueMatch:
    """A single ATT&CK technique attributed to the incident."""

    technique_id: str
    name: str
    tactic: str
    confidence: float
    triggers: list[str] = field(default_factory=list)


@dataclass
class _Rule:
    """Internal mapping rule (not exposed)."""

    technique_id: str
    name: str
    tactic: str
    # Lowercase substrings that, if found in evidence text, count as a
    # single match point.
    keywords: tuple[str, ...]


# Curated keyword→technique map. IDs and tactics from ATT&CK 14.1.
# Kept short on purpose: every entry has been validated against the
# kinds of evidence WardSOAR actually collects.
_RULES: tuple[_Rule, ...] = (
    _Rule(
        technique_id="T1046",
        name="Network Service Scanning",
        tactic="Discovery",
        keywords=("et scan", "scan", "port scan", "nmap"),
    ),
    _Rule(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        keywords=("et c2", "http beacon", "c2", "cobalt strike", "beacon"),
    ),
    _Rule(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        keywords=("powershell", "windowspowershell", "ps1", "-enc ", "encodedcommand"),
    ),
    _Rule(
        technique_id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic="Execution",
        keywords=("cmd.exe", "cmd /c", "cmd /k"),
    ),
    _Rule(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        keywords=("brute", "et scan ssh brute", "password guessing"),
    ),
    _Rule(
        technique_id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        keywords=("et phishing", "phishing", "spoofed sender"),
    ),
    _Rule(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        keywords=("exfil", "large post", "data exfiltration", "dns tunneling"),
    ),
    _Rule(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion",
        keywords=("et policy", "lateral movement", "psexec"),
    ),
    _Rule(
        technique_id="T1204.002",
        name="User Execution: Malicious File",
        tactic="Execution",
        keywords=("et malware", "malware", "trojan", "dropper", "loader"),
    ),
    _Rule(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        keywords=("wget", "curl", "file download", "tool transfer"),
    ),
    _Rule(
        technique_id="T1547.001",
        name="Registry Run Keys",
        tactic="Persistence",
        keywords=("run", "runonce", "registry persistence"),
    ),
    _Rule(
        technique_id="T1057",
        name="Process Discovery",
        tactic="Discovery",
        keywords=("ps -ef", "tasklist", "process list"),
    ),
    _Rule(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        keywords=("mimikatz", "lsass", "credential dumping", "sekurlsa"),
    ),
    _Rule(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        keywords=("ransomware", "encrypted for impact", "cryptolocker"),
    ),
)


class AttackMapper:
    """Match evidence text against the curated ATT&CK rules.

    A "trigger" is any unique lowercased keyword that appears anywhere
    in the aggregated evidence text; confidence is computed as
    ``min(1.0, triggers / expected_triggers_for_full_confidence)``.
    """

    # How many matching keywords are "enough" to call it high-confidence.
    _FULL_CONFIDENCE_TRIGGERS = 3

    def map_record(self, record: DecisionRecord) -> list[TechniqueMatch]:
        """Return the list of techniques triggered by the record.

        Args:
            record: DecisionRecord with alert + forensic result.

        Returns:
            Matches sorted by descending confidence then by technique_id.
        """
        haystack = self._haystack(record).lower()
        matches: list[TechniqueMatch] = []

        for rule in _RULES:
            hits = [kw for kw in rule.keywords if kw in haystack]
            if not hits:
                continue
            confidence = min(1.0, len(hits) / self._FULL_CONFIDENCE_TRIGGERS)
            matches.append(
                TechniqueMatch(
                    technique_id=rule.technique_id,
                    name=rule.name,
                    tactic=rule.tactic,
                    confidence=round(confidence, 2),
                    triggers=hits,
                )
            )

        matches.sort(key=lambda m: (-m.confidence, m.technique_id))
        return matches

    # ------------------------------------------------------------------
    # Text gathering
    # ------------------------------------------------------------------

    def _haystack(self, record: DecisionRecord) -> str:
        """Concatenate every text field into one searchable blob."""
        chunks: list[str] = []
        alert = record.alert
        chunks.extend(
            [
                alert.alert_signature or "",
                alert.alert_category or "",
            ]
        )

        fr = record.forensic_result
        if fr is not None:
            for proc in getattr(fr, "suspect_processes", []) or []:
                if isinstance(proc, dict):
                    chunks.append(str(proc.get("name", "")))
                    chunks.append(str(proc.get("exe", "")))
                    cmdline = proc.get("cmdline", "")
                    if isinstance(cmdline, list):
                        chunks.append(" ".join(str(c) for c in cmdline))
                    else:
                        chunks.append(str(cmdline))
            for ev in getattr(fr, "sysmon_events", []) or []:
                desc = getattr(ev, "description", None) or getattr(ev, "Message", None)
                if desc:
                    chunks.append(str(desc))
            for ev in getattr(fr, "windows_events", []) or []:
                if isinstance(ev, dict):
                    chunks.append(str(ev.get("Message", "")))
            for sf in getattr(fr, "suspicious_files", []) or []:
                if isinstance(sf, dict):
                    chunks.append(str(sf.get("path", "")))
            for ra in getattr(fr, "registry_anomalies", []) or []:
                if isinstance(ra, dict):
                    chunks.append(str(ra.get("key", "")))
                    chunks.append(str(ra.get("raw", "")))

        # ThreatAnalysis reasoning + IOC summary are rich text.
        if record.analysis is not None:
            chunks.append(record.analysis.reasoning or "")
            chunks.append(record.analysis.ioc_summary or "")

        # VirusTotal labels are very high-signal.
        for vt in record.virustotal_results or []:
            chunks.extend(str(label) for label in vt.threat_labels)

        return " || ".join(chunks)


def to_json_list(matches: Iterable[TechniqueMatch]) -> list[dict[str, Any]]:
    """Serialise matches into JSON-ready dicts for reporting."""
    return [asdict(m) for m in matches]
