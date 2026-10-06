"""aws_secretsmanager secretRefs, and OCI credentials supplied as a secret (no key file)."""

from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace

import pytest

from oci_drata import config
from oci_drata.config import ConfigError, SecretRef
from oci_drata.oci_auth import AuthError, build_signer


def _throwaway_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


PEM = _throwaway_pem()
OCI_CREDENTIALS = {
    "user": "ocid1.user.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhh",
    "tenancy": "ocid1.tenancy.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhh",
    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
    "region": "us-ashburn-1",
    "key_content": PEM.replace("\n", "\\n"),  # a single-line paste: literal backslash-n
}


def _app_config(credentials_ref: SecretRef, tenancy: str = OCI_CREDENTIALS["tenancy"]) -> SimpleNamespace:
    return SimpleNamespace(
        oci=SimpleNamespace(
            authentication=SimpleNamespace(
                type="api_signing_user", config_file=None, profile=None, private_key_passphrase_secret_ref=None,
                credentials_secret_ref=credentials_ref,
            ),
            expected_tenancy_ocid=tenancy,
        )
    )


@pytest.fixture
def secrets_manager(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = SimpleNamespace(
        calls=0,
        store={"oci/creds": json.dumps(OCI_CREDENTIALS), "drata/token": json.dumps({"token": "t0ken"})},
    )

    class _Client:
        def get_secret_value(self, SecretId: str) -> dict:
            state.calls += 1
            return {"SecretString": state.store[SecretId]}

    botocore_exceptions = types.ModuleType("botocore.exceptions")
    botocore_exceptions.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    botocore_exceptions.BotoCoreError = type("BotoCoreError", (Exception,), {})  # type: ignore[attr-defined]
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **kwargs: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service, **kwargs: _Client()))
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.exceptions", botocore_exceptions)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setattr(config, "_aws_secret_cache", {})
    return state


def test_secrets_manager_ref_reads_a_json_field_and_is_fetched_once(secrets_manager: SimpleNamespace) -> None:
    ref = SecretRef(provider="aws_secretsmanager", name="drata/token", key="token")

    assert ref.resolve() == "t0ken"
    assert ref.resolve() == "t0ken"
    assert secrets_manager.calls == 1  # a run resolves the Drata token several times


def test_oci_credentials_secret_builds_a_signer_with_an_inline_key_and_no_key_file(
    secrets_manager: SimpleNamespace,
) -> None:
    ref = SecretRef(provider="aws_secretsmanager", name="oci/creds")

    signer = build_signer(_app_config(ref))
    assert "key_file" not in signer.base_config
    assert signer.base_config["key_content"] == PEM  # literal "\n" escapes turned back into newlines

    with pytest.raises(AuthError, match="does not match"):
        build_signer(_app_config(ref, tenancy="ocid1.tenancy.oc1..someoneelse"))


def test_a_key_that_does_not_load_fails_as_an_auth_error_naming_no_key_material(
    secrets_manager: SimpleNamespace,
) -> None:
    secrets_manager.store["oci/creds"] = json.dumps({**OCI_CREDENTIALS, "key_content": "not a pem key"})

    with pytest.raises(AuthError, match="could not be loaded") as raised:
        build_signer(_app_config(SecretRef(provider="aws_secretsmanager", name="oci/creds")))

    assert "not a pem key" not in str(raised.value)


def test_missing_secret_names_the_fix(monkeypatch: pytest.MonkeyPatch, secrets_manager: SimpleNamespace) -> None:
    from botocore.exceptions import ClientError

    class _Denied:
        def get_secret_value(self, SecretId: str) -> dict:
            error = ClientError()
            error.response = {"Error": {"Code": "AccessDeniedException"}}  # type: ignore[attr-defined]
            raise error

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service, **kwargs: _Denied()))

    with pytest.raises(ConfigError, match="secretsmanager:GetSecretValue"):
        SecretRef(provider="aws_secretsmanager", name="nope").resolve()
