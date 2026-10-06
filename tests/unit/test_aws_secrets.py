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

OCI_CREDENTIALS = {
    "user": "ocid1.user.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhh",
    "tenancy": "ocid1.tenancy.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhh",
    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
    "region": "us-ashburn-1",
    "key_content": "-----BEGIN PRIVATE KEY-----\\nMIIBVQ\\n-----END PRIVATE KEY-----",  # single-line paste: literal \n
}


@pytest.fixture
def secrets_manager(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    store = {"oci/creds": json.dumps(OCI_CREDENTIALS), "drata/token": json.dumps({"token": "t0ken"})}
    state = SimpleNamespace(calls=0)

    class _Client:
        def get_secret_value(self, SecretId: str) -> dict:
            state.calls += 1
            return {"SecretString": store[SecretId]}

    botocore_exceptions = types.ModuleType("botocore.exceptions")
    botocore_exceptions.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    botocore_exceptions.BotoCoreError = type("BotoCoreError", (Exception,), {})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service: _Client()))
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.exceptions", botocore_exceptions)
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
    def app_config(tenancy: str) -> SimpleNamespace:
        return SimpleNamespace(
            oci=SimpleNamespace(
                authentication=SimpleNamespace(
                    type="api_signing_user", config_file=None, profile=None, private_key_passphrase_secret_ref=None,
                    credentials_secret_ref=SecretRef(provider="aws_secretsmanager", name="oci/creds"),
                ),
                expected_tenancy_ocid=tenancy,
            )
        )

    signer = build_signer(app_config(OCI_CREDENTIALS["tenancy"]))
    assert "key_file" not in signer.base_config
    assert signer.base_config["key_content"] == "-----BEGIN PRIVATE KEY-----\nMIIBVQ\n-----END PRIVATE KEY-----"

    with pytest.raises(AuthError, match="does not match"):
        build_signer(app_config("ocid1.tenancy.oc1..someoneelse"))


def test_missing_secret_names_the_fix(monkeypatch: pytest.MonkeyPatch, secrets_manager: SimpleNamespace) -> None:
    from botocore.exceptions import ClientError

    class _Denied:
        def get_secret_value(self, SecretId: str) -> dict:
            error = ClientError()
            error.response = {"Error": {"Code": "AccessDeniedException"}}  # type: ignore[attr-defined]
            raise error

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service: _Denied()))

    with pytest.raises(ConfigError, match="secretsmanager:GetSecretValue"):
        SecretRef(provider="aws_secretsmanager", name="nope").resolve()
