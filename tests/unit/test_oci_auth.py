from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oci_drata.oci_auth import AuthError, TenancySigner, build_signer, endpoint_client, regional_client
from oci_drata.security import OciOperationNotAllowedError


def _app_config(config_file: Path) -> SimpleNamespace:
    return SimpleNamespace(
        oci=SimpleNamespace(
            authentication=SimpleNamespace(
                type="api_signing_user", config_file=str(config_file), profile="DEFAULT",
                private_key_passphrase_secret_ref=None,
            ),
            expected_tenancy_ocid="ocid1.tenancy.oc1..t1",
        )
    )


def test_build_signer_rejects_group_or_world_accessible_config_file(tmp_path: Path) -> None:
    """Only key_file's permissions were checked before -- but an operator can put
    pass_phrase directly in this ini file instead of using a secretRef, and
    tenancy/user/fingerprint here are sensitive even without that."""

    config_file = tmp_path / "config"
    config_file.write_text("[DEFAULT]\ntenancy=t1\nuser=u1\nfingerprint=f1\nkey_file=/dev/null\n")
    config_file.chmod(0o644)  # world-readable

    with pytest.raises(AuthError, match="must not be group/world accessible"):
        build_signer(_app_config(config_file))


def test_build_signer_rejects_authentication_type_field(tmp_path: Path) -> None:
    """oci.config.validate_config() takes a more permissive path (skipping user/
    tenancy/fingerprint checks) when this ini-level field is set -- this project only
    implements/expects a plain api_signing_user profile."""

    key_file = tmp_path / "key.pem"
    key_file.write_text("not a real key, never read this far")
    key_file.chmod(0o600)
    config_file = tmp_path / "config"
    config_file.write_text(
        f"[DEFAULT]\nauthentication_type=instance_principal\ntenancy=t1\nuser=u1\n"
        f"fingerprint=f1\nkey_file={key_file}\n"
    )
    config_file.chmod(0o600)

    with pytest.raises(AuthError, match="authentication_type"):
        build_signer(_app_config(config_file))


def test_repr_allowlists_region_only_never_leaks_account_metadata() -> None:
    """repr() must never expose tenancy/user OCIDs, key fingerprint, or
    the private key's filesystem path -- account metadata that could end up in a log line
    or exception traceback just because something formatted this object."""

    signer = TenancySigner(
        base_config={
            "region": "us-ashburn-1",
            "tenancy": "ocid1.tenancy.oc1..sensitive",
            "user": "ocid1.user.oc1..sensitive",
            "fingerprint": "aa:bb:cc:dd:ee:ff",
            "key_file": "/home/operator/.oci/oci_api_key.pem",
            "pass_phrase": "super-secret",
        }
    )
    text = repr(signer)
    assert text == "TenancySigner(authentication_type='api_signing_user', region='us-ashburn-1')"
    assert "sensitive" not in text
    assert "fingerprint" not in text
    assert "aa:bb:cc:dd:ee:ff" not in text
    assert "key_file" not in text
    assert "oci_api_key.pem" not in text
    assert "pass_phrase" not in text
    assert "super-secret" not in text


def test_repr_handles_missing_region() -> None:
    signer = TenancySigner(base_config={"tenancy": "ocid1.tenancy.oc1..x"})
    text = repr(signer)
    assert text == "TenancySigner(authentication_type='api_signing_user', region=None)"
    assert "tenancy" not in text


class _FakeOciClient:
    def __init__(self, config: dict) -> None:
        self.config = config

    def list_instances(self, **kwargs):
        return ["ok"]

    def create_instance(self, **kwargs):
        return "should never run"


def test_regional_client_returns_a_guarded_client() -> None:
    """P2 (runtime OCI operation guard): every client regional_client() hands to a
    collector must be wrapped, not just returned raw -- this is the one call site every
    collector goes through to obtain a client, so this is where the guard has to attach."""

    signer = TenancySigner(base_config={"region": "us-ashburn-1"})
    client = regional_client(_FakeOciClient, signer, region="us-ashburn-1")

    assert client.list_instances() == ["ok"]
    with pytest.raises(OciOperationNotAllowedError):
        client.create_instance()


class _FakeKmsManagementClient:
    def __init__(self, config: dict, service_endpoint: str) -> None:
        self.config = config
        self.service_endpoint = service_endpoint

    def list_keys(self, **kwargs):
        return ["ok"]

    def create_key(self, **kwargs):
        return "should never run"


def test_endpoint_client_passes_service_endpoint_and_returns_a_guarded_client() -> None:
    """KmsManagementClient (and anything else needing a per-resource endpoint
    instead of the region's default one) takes service_endpoint as a required
    positional arg regional_client() has no way to supply -- endpoint_client is
    the dedicated construction path for that shape, same guard as regional_client."""

    signer = TenancySigner(base_config={"region": "us-ashburn-1"})
    client = endpoint_client(
        _FakeKmsManagementClient, signer, region="us-ashburn-1",
        service_endpoint="https://vault1.kms.us-ashburn-1.oraclecloud.com",
    )

    assert client.list_keys() == ["ok"]
    with pytest.raises(OciOperationNotAllowedError):
        client.create_key()
