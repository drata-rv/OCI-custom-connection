"""A switched-off domain must never touch OCI -- the README's per-toggle IAM grants depend on it."""

from __future__ import annotations

import pytest

from oci_drata.collection.cloud_guard import collect_cloud_guard
from oci_drata.collection.compute import collect_compute
from oci_drata.collection.database_autonomous import collect_autonomous_database
from oci_drata.collection.database_base import collect_database_base
from oci_drata.collection.identity import collect_identity
from oci_drata.collection.kms_vault import collect_kms_vault
from oci_drata.collection.load_balancer import collect_load_balancer
from oci_drata.collection.monitoring import collect_monitoring
from oci_drata.collection.networking import collect_networking
from oci_drata.collection.object_storage import collect_object_storage
from oci_drata.collection.storage import collect_storage
from oci_drata.collection.vpn import collect_vpn
from oci_drata.collection.waf import collect_waf
from oci_drata.config import OciServicesConfig

COLLECTORS = [
    collect_compute, collect_storage, collect_networking, collect_database_base,
    collect_autonomous_database, collect_vpn, collect_identity, collect_object_storage,
    collect_cloud_guard, collect_monitoring, collect_load_balancer, collect_waf, collect_kms_vault,
]


@pytest.mark.parametrize("collect", COLLECTORS, ids=lambda f: f.__name__)
def test_disabled_domain_never_touches_oci(collect) -> None:
    all_off = OciServicesConfig(
        compute=False, network_exposure=False, block_storage=False,
        base_database=False, autonomous_database=False, site_to_site_vpn=False,
    )

    # Bare objects as signer/discovery: any attempt to use either raises AttributeError.
    result = collect(object(), object(), all_off)

    assert result.complete
    assert result.operations
    assert all(op.status == "skipped" for op in result.operations)
