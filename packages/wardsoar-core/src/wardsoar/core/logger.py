"""Structured JSON logging for audit trail and application events."""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from wardsoar.core.models import DecisionRecord


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


def setup_logging(log_dir: str, level: str = "INFO") -> logging.Logger:
    """Configure application logging with file rotation.

    Ships with an *always-on* DEBUG trace file for overnight observability:
    ``trace_debug.log`` captures every log record at DEBUG+ irrespective of
    the requested level, so we have a detailed audit trail when something
    goes wrong in production. Rotated at 25 MB x 5.

    Args:
        log_dir: Directory for log files.
        level: Logging level (DEBUG, INFO, WARNING, ERROR) for the main
            stream; the trace file is always DEBUG regardless.

    Returns:
        Configured logger instance.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("ward_soar")
    # The logger itself is at the lower of DEBUG and the requested level so
    # the trace handler never starves for records.
    requested_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(min(logging.DEBUG, requested_level))
    # Ensure children like ward_soar.forensic.* propagate through us.
    logger.propagate = False

    # --- Main app log (JSON, rotating, respects requested level) ---------
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / "ward_soar.log",
        maxBytes=10_485_760,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(requested_level)
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # --- Overnight trace log (always DEBUG, textual, bigger rotation) ----
    # Added so the nightly run leaves a usable diary even if the JSON log
    # is filtered to INFO. Textual format is easier to tail visually.
    trace_handler = logging.handlers.RotatingFileHandler(
        log_path / "trace_debug.log",
        maxBytes=25 * 1024 * 1024,  # 25 MB
        backupCount=5,
        encoding="utf-8",
    )
    trace_handler.setLevel(logging.DEBUG)
    trace_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)-5s] %(name)-38s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(trace_handler)

    # Console handler for development / interactive runs.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(requested_level)
    console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)

    logger.info(
        "Logging initialised — level=%s, trace file=%s",
        level,
        log_path / "trace_debug.log",
    )
    return logger


def log_decision(log_dir: str, record: DecisionRecord) -> None:
    """Append a decision record to the JSONL audit log.

    Args:
        log_dir: Directory for log files.
        record: Complete decision record to log.
    """
    log_path = Path(log_dir) / "decisions.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(record.model_dump_json() + "\n")
