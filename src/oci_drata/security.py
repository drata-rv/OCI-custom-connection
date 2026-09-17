"""Allow/deny lists enforcing read-only, least-privilege OCI access, enforced twice:

- ``tests/unit/test_operation_allowlist.py`` ast-scans ``src/oci_drata/collection`` at
  build time and fails on any call not in :data:`ALLOWED_OCI_OPERATIONS` or matching
  :data:`FORBIDDEN_OPERATION_PREFIXES`/:data:`FORBIDDEN_OPERATIONS`.
- :class:`GuardedOciClient` (returned by ``oci_auth.regional_client``) checks every
  ``list_*``/``get_*`` attribute access against the same allow/deny lists at the moment
  of the call, not just at CI time -- catches a dynamically resolved or aliased method
  name the static AST scan can't see (``getattr(client, name)()``, a rebound method).
"""

from __future__ import annotations

from typing import Any

# Mutation/lifecycle/credential-retrieval prefixes; forbidden regardless of allowlist membership.
FORBIDDEN_OPERATION_PREFIXES: tuple[str, ...] = (
    "create_",
    "update_",
    "delete_",
    "change_",
    "move_",
    "terminate_",
    "launch_",
    "attach_",
    "detach_",
    "rotate_",
    "generate_",
    "register_",
    "deregister_",
    "enable_",
    "disable_",
    "start_",
    "stop_",
    "restart_",
    "shrink_",
    "fail_over_",
    "failover_",
    "switch_over_",
    "switchover_",
    "reinstate_",
    "migrate_",
    "upgrade_",
    "activate_",
    "configure_",
    "add_",
    "remove_",
    "execute_",
    "instance_action",
)

# get_*/list_*-shaped operations that return credentials/secrets/unrestricted
# metadata; denylisted by exact name since they'd pass the prefix check.
FORBIDDEN_OPERATIONS: frozenset[str] = frozenset(
    {
        "get_windows_instance_initial_credentials",
        "get_ip_sec_connection_tunnel_shared_secret",
        "get_autonomous_database_wallet",
        "get_autonomous_database_regional_wallet",
        "get_instance_credentials",
        "list_instance_credentials",
    }
)

# Allowed list_*/get_* operations, grouped by collector module. Keep in sync with
# the collectors that call these names.
ALLOWED_OCI_OPERATIONS: frozenset[str] = frozenset(
    {
        # Discovery (collection/discovery.py)
        "get_tenancy",
        "list_region_subscriptions",
        "list_compartments",
        "list_availability_domains",
        # Compute and Windows classification (collection/compute.py)
        "list_instances",
        "get_instance",
        "get_image",
        "list_vnic_attachments",
        "get_vnic",
        "list_private_ips",
        "get_public_ip_by_private_ip_id",
        # Boot and block storage (collection/storage.py)
        "list_boot_volumes",
        "list_boot_volume_attachments",
        "list_volumes",
        "list_volume_attachments",
        # Network exposure (collection/networking.py)
        "list_vcns",
        "list_subnets",
        "list_route_tables",
        "list_internet_gateways",
        "list_security_lists",
        "list_network_security_groups",
        "list_network_security_group_security_rules",
        "list_network_security_group_vnics",
        # Base Database Service (collection/database_base.py)
        "list_db_systems",
        "get_db_system",
        "list_db_homes",
        "get_db_home",
        "list_databases",
        "get_database",
        "list_backups",
        "get_backup",
        "list_data_guard_associations",
        "get_data_guard_association",
        # Autonomous Database (collection/database_autonomous.py)
        "list_autonomous_databases",
        "get_autonomous_database",
        "list_autonomous_database_backups",
        "get_autonomous_database_backup",
        "list_autonomous_database_dataguard_associations",
        "get_autonomous_database_dataguard_association",
        "list_autonomous_database_peers",
        # Exadata detection, minimal, no drill-down (collection/exadata_detection.py)
        "list_cloud_vm_clusters",
        "list_exadata_infrastructures",
        "list_cloud_exadata_infrastructures",
        "list_autonomous_exadata_infrastructures",
        # Site-to-Site VPN (collection/vpn.py)
        "list_ip_sec_connections",
        "get_ip_sec_connection",
        "list_ip_sec_connection_tunnels",
        "get_ip_sec_connection_tunnel",
        "list_cpes",
        "get_cpe",
        "list_drgs",
        "get_drg",
        "list_drg_attachments",
        "list_drg_route_rules",
        "list_drg_route_tables",
    }
)


def is_forbidden_operation(name: str) -> bool:
    if name in FORBIDDEN_OPERATIONS:
        return True
    return any(name.startswith(prefix) for prefix in FORBIDDEN_OPERATION_PREFIXES)


def is_allowed_operation(name: str) -> bool:
    return name in ALLOWED_OCI_OPERATIONS and not is_forbidden_operation(name)


class OciOperationNotAllowedError(Exception):
    """Raised by GuardedOciClient when a list_*/get_*-shaped attribute access resolves
    to a name outside ALLOWED_OCI_OPERATIONS, or matches a forbidden name/prefix."""


class GuardedOciClient:
    """Wraps a raw OCI SDK client object; every ``list_*``/``get_*`` attribute access is
    checked against the allow/deny lists above at the moment of access, fail-closed on
    anything not explicitly allowed. Any other attribute (non-operation methods,
    internal client state) passes through untouched -- this only narrows the operation
    surface, it never changes behavior for an allowed call.

    Defense in depth alongside test_operation_allowlist.py's static AST scan: this
    catches a name the scan can't see because it's resolved dynamically
    (``getattr(client, name)()``) or through an alias, not just a literal
    ``client.list_x(...)`` call site.
    """

    def __init__(self, client: Any) -> None:
        object.__setattr__(self, "_client", client)

    def __getattr__(self, name: str) -> Any:
        client = object.__getattribute__(self, "_client")
        attr = getattr(client, name)
        if not callable(attr):
            return attr
        # Checked regardless of name shape -- a mutation-shaped call (create_*,
        # terminate_*, ...) resolved dynamically (getattr(client, name)()) must be
        # blocked here too, not only when it matches the list_/get_ check below.
        if is_forbidden_operation(name):
            raise OciOperationNotAllowedError(
                f"OCI operation {name!r} is forbidden (mutation/lifecycle/credential-"
                f"retrieval-shaped) -- refusing to call it"
            )
        if (name.startswith("list_") or name.startswith("get_")) and not is_allowed_operation(name):
            raise OciOperationNotAllowedError(
                f"OCI operation {name!r} is not in the read-only allowlist "
                f"(security.ALLOWED_OCI_OPERATIONS) -- refusing to call it"
            )
        return attr

    def __setattr__(self, name: str, value: Any) -> None:
        raise OciOperationNotAllowedError(
            f"refusing to set attribute {name!r} on a guarded OCI client"
        )
