"""Explicit allow/deny lists enforcing the read-only, least-privilege
security posture (spec: "Never call OCI mutation or secret-retrieval
operations", "Never retrieve VPN shared secrets, database credentials,
wallets, or unrestricted instance metadata").

This is not just documentation: ``tests/unit/test_operation_allowlist.py``
statically scans every module under ``src/oci_drata/collection`` with
:mod:`ast` and fails the build if any OCI client method call is not in
:data:`ALLOWED_OCI_OPERATIONS`, or if it matches
:data:`FORBIDDEN_OPERATION_PREFIXES`/:data:`FORBIDDEN_OPERATIONS` outright.
A collector cannot silently grow a mutating or secret-retrieving call.
"""

from __future__ import annotations

# Any OCI SDK method whose name starts with one of these prefixes is a
# mutation, lifecycle, or credential/secret-retrieval operation and must
# never be called by a collector, regardless of allowlist membership below.
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

# Specific operations that exist in the SDK, are exact-name matches for a
# "get_*"/"list_*" shape, but return credentials, secrets, or unrestricted
# metadata rather than configuration evidence. Denylisted by exact name even
# though they would otherwise pass the prefix check.
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

# Every OCI SDK "list_*"/"get_*" operation a collector is permitted to call,
# grouped by spec section for traceability. Keep in lockstep with
# TRACEABILITY.md and with the collectors that actually call these names.
ALLOWED_OCI_OPERATIONS: frozenset[str] = frozenset(
    {
        # 5.1 Discovery
        "get_tenancy",
        "list_region_subscriptions",
        "list_compartments",
        "list_availability_domains",
        # 5.2 Compute and Windows classification
        "list_instances",
        "get_instance",
        "get_image",
        "list_vnic_attachments",
        "get_vnic",
        "list_private_ips",
        "get_public_ip_by_private_ip_id",
        # 5.3 Boot and block storage
        "list_boot_volumes",
        "list_boot_volume_attachments",
        "list_volumes",
        "list_volume_attachments",
        # 5.4 Network exposure
        "list_vcns",
        "list_subnets",
        "list_route_tables",
        "list_internet_gateways",
        "list_security_lists",
        "list_network_security_groups",
        "list_network_security_group_security_rules",
        "list_network_security_group_vnics",
        # 5.5 Base Database Service
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
        # 5.6 Autonomous Database
        "list_autonomous_databases",
        "get_autonomous_database",
        "list_autonomous_database_backups",
        "get_autonomous_database_backup",
        "list_autonomous_database_dataguard_associations",
        "get_autonomous_database_dataguard_association",
        "list_autonomous_database_peers",
        # 5.7 Exadata detection (minimal, no drill-down)
        "list_cloud_vm_clusters",
        "list_exadata_infrastructures",
        "list_cloud_exadata_infrastructures",
        "list_autonomous_exadata_infrastructures",
        # 5.8 Site-to-Site VPN
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
