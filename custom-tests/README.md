# Custom Tests

Example Drata Advanced Test Builder JSON for this OCI Custom Connection.
Paste into Monitoring > Create test > Advanced editor, after selecting
this connection's uploaded record as the data source.

- `admin-port-exposure.json` -- fails if any `resources.instances[].effectiveIngressExposure != not_exposed`. Mirrors `OCI-COMPUTE-ADMIN-PORT-EXPOSURE`.
- `autonomous-db-public-endpoint.json` -- fails if any `resources.autonomousDatabases[].publicEndpointPresent != false`. Mirrors `OCI-ADB-PUBLIC-ENDPOINT-PRESENT`.
- `customer-managed-key-volumes.json` -- fails if any `resources.bootVolumes[]`/`blockVolumes[].customerManagedKeyPresent != true`. Mirrors `OCI-STORAGE-CUSTOMER-MANAGED-KEY`; only meaningful when `decisions.requireCustomerManagedVolumeKeys` is enabled for this deployment.
- `customer-managed-key-databases.json` -- fails if any `resources.databases[]`/`autonomousDatabases[].kmsKeyId` is null. Mirrors `OCI-DATABASE-CUSTOMER-MANAGED-KEY`; only meaningful when `decisions.requireCustomerManagedDatabaseKeys` is enabled.
- `vpn-tunnel-redundancy.json` -- fails if any `resources.ipsecConnections[].redundancyStatus != redundant`. Mirrors `OCI-VPN-TUNNEL-REDUNDANCY`.
- `snapshot-completeness.json` -- fails unless top-level `snapshotStatus == complete`.
- `snapshot-freshness.json` -- static-cutoff proxy on `collectedAt`; the cutoff value is a placeholder you must advance manually, it is not a rolling `now - collectedAt` check.
