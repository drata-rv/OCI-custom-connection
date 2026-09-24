from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.database_autonomous import collect_autonomous_database
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        approved_regions=("us-ashburn-1",), approved_compartment_ids=("ocid1.compartment.oc1..c1",)
    )


def test_collect_autonomous_database_merges_concurrent_per_adb_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """backups/dataguard/peers per ADB was a fully serial loop. Two
    ADBs with distinct backup/dataguard/peer data must merge correctly (keyed by the
    right ADB id) regardless of which worker thread produced which result."""

    adb1 = oci.database.models.AutonomousDatabaseSummary(id="adb1", compartment_id="c1")
    adb2 = oci.database.models.AutonomousDatabaseSummary(id="adb2", compartment_id="c1")
    backup1 = oci.database.models.AutonomousDatabaseBackupSummary(id="bkp1", autonomous_database_id="adb1")
    peer2 = oci.database.models.AutonomousDatabasePeerSummary(id="adb2-peer", region="us-phoenix-1")

    class _PeerCollection:
        def __init__(self, items):
            self.items = items

    client = MagicMock()
    client.list_autonomous_databases.return_value = _response(data=[adb1, adb2])

    def backups_side_effect(**kwargs):
        backups = {"adb1": [backup1], "adb2": []}[kwargs["autonomous_database_id"]]
        return _response(data=backups)

    def dg_side_effect(**kwargs):
        return _response(data=[])

    def peers_side_effect(**kwargs):
        peers = {"adb1": [], "adb2": [peer2]}[kwargs["autonomous_database_id"]]
        return _response(data=_PeerCollection(peers))

    client.list_autonomous_database_backups.side_effect = backups_side_effect
    client.list_autonomous_database_dataguard_associations.side_effect = dg_side_effect
    client.list_autonomous_database_peers.side_effect = peers_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.database_autonomous.regional_client",
        lambda client_cls, signer, *, region: client,
    )

    result = collect_autonomous_database(
        signer=MagicMock(), discovery=discovery, services=_services(autonomous_database=True)
    )

    assert {a.id for a in result.autonomous_databases} == {"adb1", "adb2"}
    assert [b.id for b in result.autonomous_database_backups] == ["bkp1"]
    assert result.autonomous_database_peers_by_adb_id["adb1"] == []
    assert [p.id for p in result.autonomous_database_peers_by_adb_id["adb2"]] == ["adb2-peer"]
    assert result.complete
