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




def test_secret_passed_as_a_log_argument_is_redacted_and_noisy_libraries_stay_quiet() -> None:
    import io
    import logging

    from oci_drata.logging import configure_logging

    stream = io.StringIO()
    configure_logging("DEBUG", stream=stream)
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ\n-----END PRIVATE KEY-----"

    logging.getLogger("botocore.parsers").debug("Response body: %s", '{"SecretString": "' + pem + '"}')
    logging.getLogger("oci_drata.x").warning("token %s", "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc")

    output = stream.getvalue()
    assert "BEGIN PRIVATE KEY" not in output and "aaaaaaaaaaaa.bbbbbbbbbbbb" not in output  # redacted
    assert "Response body" not in output  # botocore DEBUG never reaches the log at all
