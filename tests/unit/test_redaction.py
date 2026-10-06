from __future__ import annotations

from oci_drata.redaction import redact_text


def test_redact_text_masks_pem_block() -> None:
    text = "prefix -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- suffix"
    redacted = redact_text(text)
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "<redacted>" in redacted


def test_redact_text_masks_bearer_shaped_value() -> None:
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = f"Authorization: Bearer {fake_jwt}"
    redacted = redact_text(text)
    assert fake_jwt not in redacted
    assert "<redacted>" in redacted


