from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.vpn import collect_vpn
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


def test_collect_vpn_merges_concurrent_per_connection_tunnel_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """P2-1 regression: list_ip_sec_connection_tunnels per connection was a fully
    serial loop. Two connections' tunnels (c1/t1, c2/t2) must merge correctly, keyed
    by the right connection id, regardless of which worker thread produced which."""

    conn1 = oci.core.models.IPSecConnection(id="c1", compartment_id="c1")
    conn2 = oci.core.models.IPSecConnection(id="c2", compartment_id="c1")
    tunnel1 = oci.core.models.IPSecConnectionTunnel(
        id="t1", status="UP", routing="STATIC", ike_version="V2",
        bgp_session_info=oci.core.models.BgpSessionInfo(),
    )
    tunnel2 = oci.core.models.IPSecConnectionTunnel(
        id="t2", status="DOWN", routing="STATIC", ike_version="V2",
        bgp_session_info=oci.core.models.BgpSessionInfo(),
    )

    client = MagicMock()
    client.list_ip_sec_connections.return_value = _response(data=[conn1, conn2])

    def tunnels_side_effect(**kwargs):
        tunnels = {"c1": [tunnel1], "c2": [tunnel2]}[kwargs["ipsc_id"]]
        return _response(data=tunnels)

    client.list_ip_sec_connection_tunnels.side_effect = tunnels_side_effect
    client.list_cpes.return_value = _response(data=[])
    client.list_drgs.return_value = _response(data=[])
    client.list_drg_attachments.return_value = _response(data=[])

    monkeypatch.setattr(
        "oci_drata.collection.vpn.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_vpn(signer=MagicMock(), discovery=discovery, services=_services(site_to_site_vpn=True))

    assert [t.id for t in result.tunnels_by_connection_id["c1"]] == ["t1"]
    assert [t.id for t in result.tunnels_by_connection_id["c2"]] == ["t2"]
    assert result.complete


def test_collect_vpn_merges_concurrent_per_drg_route_table_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """P2-1 regression: list_drg_route_tables + per-table list_drg_route_rules per DRG
    was a fully serial loop. Two DRGs with distinct route tables/rules must merge
    correctly, keyed by the right DRG/table id."""

    drg1 = oci.core.models.Drg(id="drg1", compartment_id="c1")
    drg2 = oci.core.models.Drg(id="drg2", compartment_id="c1")
    attachment1 = oci.core.models.DrgAttachment(
        id="att1", compartment_id="c1", drg_id="drg1",
        network_details=oci.core.models.IpsecTunnelDrgAttachmentNetworkDetails(id="t1"),
    )
    attachment2 = oci.core.models.DrgAttachment(
        id="att2", compartment_id="c1", drg_id="drg2",
        network_details=oci.core.models.IpsecTunnelDrgAttachmentNetworkDetails(id="t2"),
    )
    table1 = oci.core.models.DrgRouteTable(id="table1")
    table2 = oci.core.models.DrgRouteTable(id="table2")
    rule1 = oci.core.models.DrgRouteRule(id="rule1")
    rule2 = oci.core.models.DrgRouteRule(id="rule2")

    client = MagicMock()
    client.list_ip_sec_connections.return_value = _response(data=[])
    client.list_cpes.return_value = _response(data=[])
    client.list_drgs.return_value = _response(data=[drg1, drg2])
    client.list_drg_attachments.return_value = _response(data=[attachment1, attachment2])

    def route_tables_side_effect(**kwargs):
        tables = {"drg1": [table1], "drg2": [table2]}[kwargs["drg_id"]]
        return _response(data=tables)

    def route_rules_side_effect(**kwargs):
        rules = {"table1": [rule1], "table2": [rule2]}[kwargs["drg_route_table_id"]]
        return _response(data=rules)

    client.list_drg_route_tables.side_effect = route_tables_side_effect
    client.list_drg_route_rules.side_effect = route_rules_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.vpn.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_vpn(signer=MagicMock(), discovery=discovery, services=_services(site_to_site_vpn=True))

    assert [t.id for t in result.drg_route_tables_by_drg_id["drg1"]] == ["table1"]
    assert [t.id for t in result.drg_route_tables_by_drg_id["drg2"]] == ["table2"]
    assert [r.id for r in result.drg_route_rules_by_route_table_id["table1"]] == ["rule1"]
    assert [r.id for r in result.drg_route_rules_by_route_table_id["table2"]] == ["rule2"]
    assert result.complete
