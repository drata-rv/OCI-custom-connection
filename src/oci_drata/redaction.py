"""Secret-shaped-value detection, shared by config inline-secret rejection
(:mod:`oci_drata.config`) and log/exception redaction (:mod:`oci_drata.logging`)."""

from __future__ import annotations

import re

# Credential field/key names; compared case-insensitively, separators stripped.
FORBIDDEN_INLINE_KEYS = frozenset(
    {
        "token",
        "apitoken",
        "password",
        "passphrase",
        "privatekey",
        "private_key",
        "secret",
        "bearer",
        "authorization",
    }
)

PEM_PATTERN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

# JWT/bearer-token shape: 3 dot-separated base64url segments, min length per
# segment to avoid matching OCIDs, URLs, file paths.
BEARER_SHAPE_PATTERN = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

REDACTED_MARKER = "<redacted>"


def is_forbidden_key(key: str) -> bool:
    normalized = str(key).lower().replace("-", "").replace("_", "")
    return normalized in FORBIDDEN_INLINE_KEYS or normalized.endswith("secretref")


def redact_text(text: str) -> str:
    """Best-effort redaction of secret-shaped substrings in text (log messages,
    exception strings). Does not replace keeping secrets out of text upstream."""

    redacted = PEM_PATTERN.sub(REDACTED_MARKER, text)
    redacted = BEARER_SHAPE_PATTERN.sub(REDACTED_MARKER, redacted)
    return redacted
