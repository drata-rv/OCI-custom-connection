"""One-off: push two sample flat records straight from config.yaml, for
building/testing a Custom Test against real evidenceType data. Reads
connectionId/flatResourceId/baseUrl/token straight out of config.yaml --
nothing to edit, nothing to look up by hand."""

import os
import sys

import requests
import yaml

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

drata = yaml.safe_load(open(CONFIG_PATH))["drata"]
if not drata.get("flatResourceId"):
    raise SystemExit("drata.flatResourceId is null in config.yaml -- register the flat-schema resource first")

token_env_name = drata["apiTokenSecretRef"]["name"]
token = os.environ.get(token_env_name)
if not token:
    raise SystemExit(f"environment variable {token_env_name} is not set")

url = (
    f"{drata['baseUrl'].rstrip('/')}/custom-connections/"
    f"{drata['connectionId']}/resources/{drata['flatResourceId']}/records"
)

records = [
    {
        "id": "demo-test-flagged-001", "evidenceType": "instance", "name": "demo-web-public",
        "timestamp": "2026-09-23T00:00:00Z", "region": "us-ashburn-1", "compartmentId": None,
        "osClassification": None, "hasPublicAddress": True, "publicIngressPorts": [22, 80],
        "hasRangedPublicIngress": False, "kmsKeyId": None, "publicEndpointHostname": None,
        "mfaActivated": None, "userId": None, "keyCreatedAt": None, "statements": [],
        "publicAccessType": None, "versioning": None, "cloudGuardStatus": None,
        "alarmEnabled": None, "alarmNamespace": None, "alarmQuery": None, "isPrivate": None,
        "loadBalancerId": None, "backendSetHealthStatus": None, "vaultId": None,
        "autoRotationEnabled": None, "lastRotationAt": None,
    },
    {
        "id": "demo-test-clean-001", "evidenceType": "instance", "name": "demo-web-private",
        "timestamp": "2026-09-23T00:00:00Z", "region": "us-ashburn-1", "compartmentId": None,
        "osClassification": None, "hasPublicAddress": False, "publicIngressPorts": [],
        "hasRangedPublicIngress": False, "kmsKeyId": None, "publicEndpointHostname": None,
        "mfaActivated": None, "userId": None, "keyCreatedAt": None, "statements": [],
        "publicAccessType": None, "versioning": None, "cloudGuardStatus": None,
        "alarmEnabled": None, "alarmNamespace": None, "alarmQuery": None, "isPrivate": None,
        "loadBalancerId": None, "backendSetHealthStatus": None, "vaultId": None,
        "autoRotationEnabled": None, "lastRotationAt": None,
    },
]

response = requests.post(
    url,
    json={"data": records},
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    timeout=30,
)
print(response.status_code, response.text[:500])
