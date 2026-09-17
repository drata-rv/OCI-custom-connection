from __future__ import annotations

import pytest

from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.security import OciOperationNotAllowedError


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
