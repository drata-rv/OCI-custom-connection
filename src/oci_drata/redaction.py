"""Shared secret-shaped-value detection, used by both configuration
inline-secret rejection (:mod:`oci_drata.config`) and log/exception
redaction (:mod:`oci_drata.logging`). Keeping one definition avoids the two
call sites drifting apart.
"""

from __future__ import annotations

import re

# Field/key names that indicate a credential. Compared case-insensitively
# after stripping separators, e.g. "Private-Key" -> "privatekey".
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

# Loose JWT/bearer-token shape: three dot-separated base64url segments.
# Deliberately conservative (minimum segment lengths) to avoid flagging
# OCIDs, URLs, or file paths, which never take this shape.
BEARER_SHAPE_PATTERN = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

REDACTED_MARKER = "<redacted>"


def is_forbidden_key(key: str) -> bool:
    normalized = str(key).lower().replace("-", "").replace("_", "")
    return normalized in FORBIDDEN_INLINE_KEYS or normalized.endswith("secretref")


def redact_text(text: str) -> str:
    """Best-effort redaction of secret-shaped substrings in free text, for
    use on log messages and exception strings. Not a substitute for keeping
    secrets out of the text in the first place."""

    redacted = PEM_PATTERN.sub(REDACTED_MARKER, text)
    redacted = BEARER_SHAPE_PATTERN.sub(REDACTED_MARKER, redacted)
    return redacted
