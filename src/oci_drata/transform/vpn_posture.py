"""Site-to-Site VPN redundancy derivation (spec 5.8, 15).

Missing from tunnels_by_connection_id -> unknown; present with zero tunnels ->
not_redundant (a provable zero, not unknown).
"""

from __future__ import annotations

import dataclasses

from oci_drata.models import IpsecConnection, IpsecTunnel

_UP_STATUS = "UP"


def derive_vpn_posture(
    connections: list[IpsecConnection],
    *,
    tunnels_by_connection_id: dict[str, list[IpsecTunnel]],
    minimum_tunnel_count: int,
    minimum_up_tunnel_count: int,
) -> list[IpsecConnection]:
    resolved: list[IpsecConnection] = []
    for connection in connections:
        if connection.id not in tunnels_by_connection_id:
            resolved.append(
                dataclasses.replace(
                    connection,
                    tunnel_ids=(),
                    tunnel_count=0,
                    up_tunnel_count=0,
                    redundancy_status="unknown",
                )
            )
            continue

        tunnels = tunnels_by_connection_id[connection.id]
        tunnel_count = len(tunnels)
        up_tunnel_count = sum(1 for t in tunnels if t.status == _UP_STATUS)
        redundant = tunnel_count >= minimum_tunnel_count and up_tunnel_count >= minimum_up_tunnel_count
        resolved.append(
            dataclasses.replace(
                connection,
                tunnel_ids=tuple(sorted(t.id for t in tunnels)),
                tunnel_count=tunnel_count,
                up_tunnel_count=up_tunnel_count,
                redundancy_status="redundant" if redundant else "not_redundant",
            )
        )
    return resolved
