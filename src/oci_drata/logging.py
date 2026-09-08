"""Structured JSON logging with secret redaction.

Emits one JSON object per log record. Redaction filter runs on message and
``extra`` values before formatting, so interpolated tokens/PEM bodies can't leak.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from oci_drata.redaction import is_forbidden_key, redact_text

_RESERVED_RECORD_ATTRS = frozenset(logging.makeLogRecord({}).__dict__.keys()) | {
    "message",
    "asctime",
}


def _redact_value(key: str, value: Any) -> Any:
    if is_forbidden_key(key):
        return "<redacted>"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, item) for item in value]
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(str(record.msg))
        for attr_name, attr_value in list(record.__dict__.items()):
            if attr_name in _RESERVED_RECORD_ATTRS:
                continue
            record.__dict__[attr_name] = _redact_value(attr_name, attr_value)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for attr_name, attr_value in record.__dict__.items():
            if attr_name in _RESERVED_RECORD_ATTRS or attr_name in payload:
                continue
            payload[attr_name] = attr_value
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, sort_keys=True)


def configure_logging(level: str = "INFO", *, stream: Any = None) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(level.upper())
