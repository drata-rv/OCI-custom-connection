from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oci_drata.oci_auth import AuthError, TenancySigner, build_signer


def _app_config(config_file: Path) -> SimpleNamespace:
    return SimpleNamespace(
        oci=SimpleNamespace(
            authentication=SimpleNamespace(
                type="api_signing_user", config_file=str(config_file), profile="DEFAULT",
                private_key_passphrase_secret_ref=None, credentials_secret_ref=None,
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


class _FakeOciClient:
    def __init__(self, config: dict) -> None:
        self.config = config

    def list_instances(self, **kwargs):
        return ["ok"]

    def create_instance(self, **kwargs):
        return "should never run"


class _FakeKmsManagementClient:
    def __init__(self, config: dict, service_endpoint: str) -> None:
        self.config = config
        self.service_endpoint = service_endpoint

    def list_keys(self, **kwargs):
        return ["ok"]

    def create_key(self, **kwargs):
        return "should never run"


