from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.database_base import collect_database_base
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


def test_collect_database_base_merges_concurrent_multi_level_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """list_db_homes/list_databases/(list_backups+list_data_guard_
    associations) were each a fully serial per-item loop, one level per db_system/
    db_home/database. Two independent db_system->db_home->database chains (sys1/home1/
    db1 and sys2/home2/db2) must merge correctly at every level regardless of which
    worker thread produced which result."""

    sys1 = oci.database.models.DbSystemSummary(id="sys1", compartment_id="c1")
    sys2 = oci.database.models.DbSystemSummary(id="sys2", compartment_id="c1")
    home1 = oci.database.models.DbHomeSummary(id="home1", compartment_id="c1", db_system_id="sys1")
    home2 = oci.database.models.DbHomeSummary(id="home2", compartment_id="c1", db_system_id="sys2")
    db1 = oci.database.models.DatabaseSummary(id="db1", compartment_id="c1", db_home_id="home1")
    db2 = oci.database.models.DatabaseSummary(id="db2", compartment_id="c1", db_home_id="home2")
    backup1 = oci.database.models.BackupSummary(id="bkp1", compartment_id="c1", database_id="db1")
    dg2 = oci.database.models.DataGuardAssociation(id="dg2", database_id="db2")

    client = MagicMock()
    client.list_db_systems.return_value = _response(data=[sys1, sys2])

    def db_homes_side_effect(**kwargs):
        homes = {"sys1": [home1], "sys2": [home2]}[kwargs["db_system_id"]]
        return _response(data=homes)

    def databases_side_effect(**kwargs):
        dbs = {"home1": [db1], "home2": [db2]}[kwargs["db_home_id"]]
        return _response(data=dbs)

    def backups_side_effect(**kwargs):
        backups = {"db1": [backup1], "db2": []}[kwargs["database_id"]]
        return _response(data=backups)

    def dg_side_effect(**kwargs):
        dgs = {"db1": [], "db2": [dg2]}[kwargs["database_id"]]
        return _response(data=dgs)

    client.list_db_homes.side_effect = db_homes_side_effect
    client.list_databases.side_effect = databases_side_effect
    client.list_backups.side_effect = backups_side_effect
    client.list_data_guard_associations.side_effect = dg_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.database_base.regional_client",
        lambda client_cls, signer, *, region: client,
    )

    result = collect_database_base(
        signer=MagicMock(), discovery=discovery, services=_services(base_database=True)
    )

    assert {s.id for s in result.db_systems} == {"sys1", "sys2"}
    assert {h.id for h in result.db_homes} == {"home1", "home2"}
    assert {d.id for d in result.databases} == {"db1", "db2"}
    assert [b.id for b in result.backups] == ["bkp1"]
    assert [g.id for g in result.data_guard_associations] == ["dg2"]
    assert result.complete
