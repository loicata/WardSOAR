"""Tests for WardSOAR structured logging.

Covers: JSONFormatter, setup_logging, and log_decision.
Coverage target: 80% (STANDARD).
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wardsoar.core.logger import JSONFormatter, log_decision, setup_logging
from wardsoar.core.models import (
    DecisionRecord,
    SuricataAlert,
    SuricataAlertSeverity,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_timestamp() -> datetime:
    """Return a fixed UTC timestamp."""
    return datetime(2026, 3, 15, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture()
def sample_alert(sample_timestamp: datetime) -> SuricataAlert:
    """Return a minimal valid SuricataAlert."""
    return SuricataAlert(
        timestamp=sample_timestamp,
        src_ip="10.0.0.1",
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="ET MALWARE Test",
        alert_signature_id=2024897,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


@pytest.fixture()
def sample_decision(sample_alert: SuricataAlert, sample_timestamp: datetime) -> DecisionRecord:
    """Return a minimal DecisionRecord."""
    return DecisionRecord(
        record_id="test-001",
        timestamp=sample_timestamp,
        alert=sample_alert,
    )


# ---------------------------------------------------------------------------
# JSONFormatter tests
# ---------------------------------------------------------------------------


class TestJSONFormatter:
    """Tests for JSONFormatter."""

    def test_format_basic_record(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert "timestamp" in parsed
        assert "module" in parsed

    def test_format_with_extra_data(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Alert processed",
            args=None,
            exc_info=None,
        )
        record.extra_data = {"alert_id": 123, "verdict": "benign"}  # type: ignore[attr-defined]
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["data"]["alert_id"] == 123
        assert parsed["data"]["verdict"] == "benign"

    def test_format_with_exception(self) -> None:
        formatter = JSONFormatter()
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error occurred",
                args=None,
                exc_info=exc_info,
            )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "Test error" in parsed["exception"]


# ---------------------------------------------------------------------------
# setup_logging tests
# ---------------------------------------------------------------------------


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_creates_logger(self, tmp_path: Path) -> None:
        logger = setup_logging(str(tmp_path))
        assert logger.name == "ward_soar"
        # Logger itself is set to DEBUG so the overnight trace file captures
        # everything; individual handlers respect the requested level.
        assert logger.level == logging.DEBUG

    def test_creates_log_directory(self, tmp_path: Path) -> None:
        log_dir = tmp_path / "logs" / "nested"
        setup_logging(str(log_dir))
        assert log_dir.exists()

    def test_creates_log_file(self, tmp_path: Path) -> None:
        logger = setup_logging(str(tmp_path))
        logger.info("Test message")
        log_file = tmp_path / "ward_soar.log"
        assert log_file.exists()
        # The file now contains the startup banner and our test message —
        # parse line-by-line and find the one we care about.
        lines = [line for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        messages = [json.loads(line)["message"] for line in lines]
        assert "Test message" in messages

    def test_custom_level(self, tmp_path: Path) -> None:
        logger = setup_logging(str(tmp_path), level="DEBUG")
        assert logger.level == logging.DEBUG

    def test_invalid_level_defaults_to_info_handler(self, tmp_path: Path) -> None:
        """Invalid level falls back to INFO on the user-facing handlers.

        The logger itself stays at DEBUG (trace file always captures);
        the rotating/console handlers should reflect the requested level
        which, for an invalid input, defaults to INFO.
        """
        logger = setup_logging(str(tmp_path), level="INVALID")
        # Find the rotating file handler that targets ward_soar.log.
        rotating = [
            h
            for h in logger.handlers
            if isinstance(h, logging.handlers.RotatingFileHandler)
            and h.baseFilename.endswith("ward_soar.log")
        ]
        assert rotating, "ward_soar.log handler is missing"
        assert rotating[0].level == logging.INFO

    def test_has_file_and_console_handlers(self, tmp_path: Path) -> None:
        # Remove existing handlers to avoid duplication from previous tests
        existing = logging.getLogger("ward_soar")
        existing.handlers.clear()
        logger = setup_logging(str(tmp_path))
        handler_types = [type(h).__name__ for h in logger.handlers]
        assert "RotatingFileHandler" in handler_types
        assert "StreamHandler" in handler_types

    def test_creates_trace_debug_file(self, tmp_path: Path) -> None:
        """Overnight trace file must be created with DEBUG content."""
        logger = setup_logging(str(tmp_path))
        logger.debug("debug-only message")
        trace_file = tmp_path / "trace_debug.log"
        assert trace_file.exists()
        assert "debug-only message" in trace_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# log_decision tests
# ---------------------------------------------------------------------------


class TestLogDecision:
    """Tests for log_decision function."""

    def test_writes_jsonl(self, tmp_path: Path, sample_decision: DecisionRecord) -> None:
        log_decision(str(tmp_path), sample_decision)
        log_file = tmp_path / "decisions.jsonl"
        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["record_id"] == "test-001"

    def test_appends_multiple_records(
        self, tmp_path: Path, sample_decision: DecisionRecord
    ) -> None:
        log_decision(str(tmp_path), sample_decision)
        log_decision(str(tmp_path), sample_decision)
        log_file = tmp_path / "decisions.jsonl"
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_creates_directory_if_missing(
        self, tmp_path: Path, sample_decision: DecisionRecord
    ) -> None:
        nested = tmp_path / "deep" / "nested"
        log_decision(str(nested), sample_decision)
        assert (nested / "decisions.jsonl").exists()
