"""YARA local file scanner.

Loads YARA rules from a directory at startup (compiled once) and scans
individual files without network calls. Matches are returned as a
VirusTotalResult-shaped verdict so the rest of the pipeline does not
need to know whether the detection came from VT, Defender, or YARA.

If the rules directory is empty or missing, the scanner stays enabled
but returns None for every scan — the cascade continues to VT.

Fail-safe: compilation errors disable the scanner rather than crashing
the pipeline; per-file scan errors return None.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yara

from wardsoar.core.models import VirusTotalResult

logger = logging.getLogger("ward_soar.yara")


DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_RULES_DIR = "config/yara_rules"
_YARA_EXTENSIONS = frozenset({".yar", ".yara"})


class YaraScanner:
    """Compile a directory of YARA rules once, scan files against them.

    Args:
        config: YARA configuration dict. Supported keys:
            enabled (bool)           — default True
            rules_dir (str)          — default "config/yara_rules"
            timeout_seconds (int)    — per-scan timeout, default 10
            treat_match_as_malicious (bool) — default True; a YARA match
                                     stops the cascade before VT is called
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        cfg = config or {}
        self._enabled: bool = bool(cfg.get("enabled", True))
        self._rules_dir: Path = Path(cfg.get("rules_dir", DEFAULT_RULES_DIR))
        self._timeout: int = int(cfg.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
        self._match_is_malicious: bool = bool(cfg.get("treat_match_as_malicious", True))

        # Eagerly compile the rules so startup — not runtime — surfaces
        # syntax errors in custom rules.
        self._rules: Optional[yara.Rules] = self._compile_rules() if self._enabled else None

    def _compile_rules(self) -> Optional[yara.Rules]:
        """Discover *.yar / *.yara in rules_dir and compile them together.

        Returns None if the directory is missing, empty, or every rule
        has a syntax error.
        """
        if not self._rules_dir.is_dir():
            logger.info("YARA rules directory not found: %s — scanner idle", self._rules_dir)
            return None

        files: dict[str, str] = {}
        for path in sorted(self._rules_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in _YARA_EXTENSIONS:
                files[path.stem] = str(path)

        if not files:
            logger.info("YARA rules directory empty: %s — scanner idle", self._rules_dir)
            return None

        try:
            compiled = yara.compile(filepaths=files)
            logger.info("YARA scanner armed with %d rule file(s)", len(files))
            return compiled
        except yara.SyntaxError as exc:
            logger.error("YARA compilation failed: %s — scanner disabled", exc)
            return None
        except yara.Error as exc:
            logger.error("YARA generic error at load: %s — scanner disabled", exc)
            return None

    def is_armed(self) -> bool:
        """Return True if at least one rule compiled successfully."""
        return self._rules is not None

    async def scan(self, file_path: str, file_hash: str) -> Optional[VirusTotalResult]:
        """Match a file against every loaded YARA rule.

        Args:
            file_path: Absolute path to the file.
            file_hash: Pre-computed SHA-256 (embedded in the result).

        Returns:
            A VirusTotalResult (lookup_type="yara") when at least one rule
            matches; None otherwise, or when the scanner is idle / errored.
        """
        if self._rules is None:
            return None

        # Read the file ourselves instead of handing the path to libyara.
        # libyara's built-in file opener fails on long / Unicode Windows
        # paths — reading in Python bypasses that limitation and keeps the
        # semantics identical (scan is against file contents, not path).
        try:
            data = Path(file_path).read_bytes()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.warning("YARA: cannot read %s: %s", file_path, exc)
            return None

        try:
            matches = self._rules.match(data=data, timeout=self._timeout)
        except yara.TimeoutError:
            logger.warning("YARA scan timed out for %s", file_path)
            return None
        except yara.Error as exc:
            logger.warning("YARA scan error for %s: %s", file_path, exc)
            return None

        if not matches:
            return None

        rule_names = [m.rule for m in matches]
        logger.info("YARA match on %s: %s", file_path, rule_names)

        return VirusTotalResult(
            file_hash=file_hash,
            file_name=Path(file_path).name,
            detection_count=len(rule_names),
            total_engines=len(rule_names),
            detection_ratio=1.0 if rule_names else 0.0,
            is_malicious=self._match_is_malicious,
            threat_labels=[f"yara:{name}" for name in rule_names],
            lookup_type="yara",
        )
