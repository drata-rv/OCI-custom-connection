from __future__ import annotations

from oci_drata.redaction import is_forbidden_key, redact_text


def test_is_forbidden_key_matches_common_variants() -> None:
    for key in ["token", "Token", "API_TOKEN", "apiToken", "password", "PassPhrase", "private_key", "PrivateKey", "secretRef", "drataApiTokenSecretRef"]:
        assert is_forbidden_key(key), key


def test_is_forbidden_key_does_not_match_safe_keys() -> None:
    for key in ["region", "compartmentId", "displayName", "recordId", "connectionId", "profile"]:
        assert not is_forbidden_key(key), key


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


def test_redact_text_leaves_ocids_and_urls_alone() -> None:
    text = "compartmentId=ocid1.compartment.oc1..aaaaaaaa region=us-ashburn-1 url=https://public-api.drata.com/public/v2"
    assert redact_text(text) == text
