"""Filter known false positive Suricata alerts before analysis.

Suppresses alerts matching known false positive signatures,
categories, or (signature + destination) pairs configured
in known_false_positives.yaml.

Fail-safe: if the config file is missing or corrupt, filter NOTHING.
No anti-FP layer is allowed to block an alert from reaching the Analyzer.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from wardsoar.core.models import SuricataAlert

logger = logging.getLogger("ward_soar.filter")


class AlertFilter:
    """Filter out known false positive alerts.

    Args:
        config: Filter configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._enabled = config.get("enabled", True)
        self._log_suppressed = config.get("log_suppressed", True)
        self._suppressed_sids: set[int] = set()
        self._suppressed_categories: set[str] = set()
        self._suppressed_pairs: list[dict[str, Any]] = []
        # v0.9.5 — keep the full YAML entry per SID / category / pair so
        # the Alert Detail view can render a specific "why filtered"
        # paragraph that quotes the operator's own reason, signature
        # name and review dates. Metadata is read-only for the pipeline
        # but surfaced via ``get_sid_metadata`` / ``get_category_metadata``.
        self._sid_metadata: dict[int, dict[str, Any]] = {}
        self._category_metadata: dict[str, dict[str, Any]] = {}
        self._pair_metadata: list[dict[str, Any]] = []

        if self._enabled:
            # Resolve the config file path with two rules:
            #   1. If the operator supplies an absolute path, use it as-is.
            #   2. If the path is relative (default:
            #      ``config/known_false_positives.yaml``), try the PyInstaller
            #      bundle directory FIRST -- that's where our shipped copy
            #      lives in an installed MSI. Fall back to the raw relative
            #      path (honours the cwd) only if the bundle copy is absent,
            #      so operator overrides at the project root still win in
            #      development.
            #
            # Bug history: prior to v0.6.5 this used ``Path(config_file)``
            # directly, which in a frozen MSI resolved against the current
            # working directory (typically the user's profile or the
            # install root, never ``_internal/``). The shipped YAML was
            # therefore ignored in production, and ~460 daily self-
            # contamination alerts (ipinfo.io + torproject.org) slipped
            # past stage 1 to be caught later by dedup / cache / prescorer
            # at much greater cost.
            from wardsoar.core.config import get_bundle_dir

            raw_path = str(config.get("config_file", "config/known_false_positives.yaml"))
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                bundle_candidate = (get_bundle_dir() / raw_path).resolve()
                if bundle_candidate.is_file():
                    candidate = bundle_candidate
            if candidate.is_file():
                self._load_false_positives(candidate)
            else:
                logger.warning(
                    "known_false_positives file not found (tried %s) -- filter stage 1 disabled",
                    candidate,
                )

            # v0.9.0 — merge in the user overlay from APPDATA.
            # The overlay lets the Alert Detail view append SIDs at
            # runtime without modifying the read-only bundled file.
            # It never removes entries; hand-edit the YAML for that.
            try:
                from wardsoar.core.user_false_positives import user_overlay_path

                overlay = user_overlay_path()
                if overlay.is_file():
                    before = len(self._suppressed_sids)
                    self._load_false_positives(overlay)
                    logger.info(
                        "Merged %d SID(s) from user overlay %s",
                        len(self._suppressed_sids) - before,
                        overlay,
                    )
            except Exception:  # noqa: BLE001 — overlay failure must not kill pipeline
                logger.warning("Could not merge user FP overlay", exc_info=True)

    def get_sid_metadata(self, sid: int) -> dict[str, Any] | None:
        """Return the YAML entry for a suppressed SID (or None).

        Used by the Alert Detail view to render a specific "why filtered"
        paragraph that quotes the operator's own ``reason``, ``signature_name``,
        ``added_date`` and ``review_date``.
        """
        entry = self._sid_metadata.get(int(sid))
        return dict(entry) if entry else None

    def get_category_metadata(self, category: str) -> dict[str, Any] | None:
        """Return the YAML entry for a suppressed alert category (or None)."""
        entry = self._category_metadata.get(category)
        return dict(entry) if entry else None

    def get_pair_metadata(self, sid: int, dest_ip: str) -> dict[str, Any] | None:
        """Return the YAML entry for a (SID, dest_ip) pair (or None)."""
        for entry in self._pair_metadata:
            if int(entry.get("signature_id", 0)) == int(sid) and entry.get("dest_ip") == dest_ip:
                return dict(entry)
        return None

    def add_sid_live(self, sid: int) -> None:
        """Insert a SID into the in-memory suppression set immediately.

        Allows the Alert Detail UI to apply an "Add to false positives"
        click without restarting WardSOAR. The overlay file is still
        written by the caller (``user_false_positives.append_sid``) so
        the change survives a restart; this method makes the change
        effective on the very next alert.
        """
        if sid > 0:
            self._suppressed_sids.add(int(sid))

    def _load_false_positives(self, path: Path) -> None:
        """Load false positive definitions from YAML file.

        Fail-safe: if the file is corrupt or has unexpected structure,
        log a warning and filter nothing.

        Args:
            path: Path to known_false_positives.yaml.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.warning("Corrupt YAML in false positives file: %s", path)
            return

        if not isinstance(raw, dict):
            logger.warning("Unexpected format in false positives file: %s", path)
            return

        self._load_suppressed_signatures(raw)
        self._load_suppressed_categories(raw)
        self._load_suppressed_pairs(raw)

        logger.info(
            "Loaded false positives: %d signatures, %d categories, %d pairs",
            len(self._suppressed_sids),
            len(self._suppressed_categories),
            len(self._suppressed_pairs),
        )

    def _load_suppressed_signatures(self, raw: dict[str, Any]) -> None:
        """Extract suppressed signature IDs from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("suppressed_signatures", None) or []:
            if "signature_id" in entry:
                sid = int(entry["signature_id"])
                self._suppressed_sids.add(sid)
                self._sid_metadata[sid] = dict(entry)

    def _load_suppressed_categories(self, raw: dict[str, Any]) -> None:
        """Extract suppressed alert categories from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("suppressed_categories", None) or []:
            if "category" in entry:
                cat = entry["category"]
                self._suppressed_categories.add(cat)
                self._category_metadata[cat] = dict(entry)

    def _load_suppressed_pairs(self, raw: dict[str, Any]) -> None:
        """Extract suppressed (signature_id, dest_ip) pairs from parsed YAML.

        Args:
            raw: Parsed YAML content.
        """
        for entry in raw.get("suppressed_pairs", None) or []:
            if "signature_id" in entry and "dest_ip" in entry:
                pair = {"signature_id": int(entry["signature_id"]), "dest_ip": entry["dest_ip"]}
                self._suppressed_pairs.append(pair)
                self._pair_metadata.append(dict(entry))

    def should_suppress(
        self,
        alert: SuricataAlert,
        process_risk_verdict: str | None = None,
    ) -> bool:
        """Check if an alert matches a known false positive pattern.

        A malicious-rated local process (from :mod:`src.process_risk`)
        **overrides** the FP list: if the PC side of the flow is a
        confirmed malicious binary, we do not care that the SID is
        otherwise noisy — the alert must reach Opus. The override is
        intentionally narrow: only ``malicious`` disables the filter;
        ``suspicious`` / ``unknown`` / ``benign`` keep legacy behaviour.

        Args:
            alert: The Suricata alert to check.
            process_risk_verdict: Optional verdict from the risk
                scorer for the process attributed to this flow.
                ``None`` means no process attribution happened
                (reverts to legacy behaviour).

        Returns:
            True if the alert should be suppressed, False otherwise.
        """
        if not self._enabled:
            return False

        if process_risk_verdict == "malicious":
            # Never suppress an alert generated by a malicious process.
            # We log at INFO so the override is visible in the audit log
            # — if a legitimate flow trips both a known FP and a
            # malicious verdict, the operator wants to see it.
            logger.warning(
                "Filter override: SID %d (%s) would normally suppress, but the "
                "attributed process is rated MALICIOUS — propagating alert",
                alert.alert_signature_id,
                alert.alert_signature,
            )
            return False

        # Check signature ID
        if alert.alert_signature_id in self._suppressed_sids:
            if self._log_suppressed:
                logger.info(
                    "Suppressed alert SID %d (%s) — known false positive",
                    alert.alert_signature_id,
                    alert.alert_signature,
                )
            return True

        # Check category
        if alert.alert_category and alert.alert_category in self._suppressed_categories:
            if self._log_suppressed:
                logger.info(
                    "Suppressed alert category '%s' — known false positive",
                    alert.alert_category,
                )
            return True

        # Check (signature_id, dest_ip) pairs
        for pair in self._suppressed_pairs:
            if (
                alert.alert_signature_id == pair["signature_id"]
                and alert.dest_ip == pair["dest_ip"]
            ):
                if self._log_suppressed:
                    logger.info(
                        "Suppressed alert SID %d -> %s — known false positive pair",
                        alert.alert_signature_id,
                        alert.dest_ip,
                    )
                return True

        return False
