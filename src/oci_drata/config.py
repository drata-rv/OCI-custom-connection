"""Deployment config loading and secretRef resolution.

Inline credentials are rejected; secrets resolve only via secretRef (env var, file, or AWS
Secrets Manager), lazily, per caller.
OCI_DRATA__-prefixed env vars override non-secret settings after YAML load, before secret resolution.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import os
import stat
import threading
import time
import urllib.parse
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from oci_drata.redaction import (
    BEARER_SHAPE_PATTERN,
    PEM_PATTERN,
    REDACTED_MARKER,
    is_forbidden_key,
)

logger = logging.getLogger(__name__)

ENV_OVERRIDE_PREFIX = "OCI_DRATA__"
SECRET_PROVIDERS = ("env", "file", "aws_secretsmanager")
# A secret fetched from AWS Secrets Manager is reused for this long within one process, so a run
# that resolves the same token several times (early check, upsert, delete) calls AWS once.
_AWS_SECRET_TTL_SECONDS = 300.0
_aws_secret_cache: dict[str, tuple[float, str]] = {}
_aws_secret_lock = threading.Lock()
DEFAULT_DRATA_HOSTNAME = "public-api.drata.com"
DEFAULT_PUBLIC_SOURCE_CIDRS = ("0.0.0.0/0", "::/0")


class ConfigError(Exception):
    """Raised for invalid, insecure, or unresolvable configuration."""


# --------------------------------------------------------------------------
# Secret references
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SecretRef:
    """Pointer to a secret value. Never carries the value itself."""

    provider: str  # "env" | "file" | "aws_secretsmanager"
    name: str | None = None  # env var name, or Secrets Manager secret name/ARN
    path: str | None = None
    key: str | None = None  # aws_secretsmanager only: field to read when the secret is a JSON object

    def resolve(self) -> str:
        if self.provider == "env":
            if not self.name:
                raise ConfigError("secretRef provider 'env' requires 'name'")
            value = os.environ.get(self.name)
            if not value:
                raise ConfigError(
                    f"drata.apiTokenSecretRef points at environment variable {self.name!r}, "
                    f"but it is not set (or is empty) in this shell. The token itself is "
                    f"never written into config.yaml -- export it in the same shell before "
                    f"running: export {self.name}=\"<your Drata API token>\". To persist it "
                    f"across shells, add that export to your shell profile "
                    f"(~/.zshrc or ~/.bashrc), or switch apiTokenSecretRef to "
                    f"{{provider: file, path: ...}} and put the token in that file instead."
                )
            return value
        if self.provider == "file":
            if not self.path:
                raise ConfigError("secretRef provider 'file' requires 'path'")
            file_path = Path(self.path).expanduser()
            if not file_path.is_file():
                raise ConfigError(
                    f"drata.apiTokenSecretRef points at file {self.path!r}, but it does not "
                    f"exist. Create it with the token as its only contents, e.g.: "
                    f"install -m 600 /path/to/your/token/file {self.path}"
                )
            mode = file_path.stat().st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError(
                    f"secret file {self.path!r} must not be group- or world-accessible -- "
                    f"chmod 600 {self.path}"
                )
            value = file_path.read_text(encoding="utf-8").strip()
            if not value:
                raise ConfigError(f"secret file {self.path!r} exists but is empty: {self.path}")
            return value
        if self.provider == "aws_secretsmanager":
            if not self.name:
                raise ConfigError("secretRef provider 'aws_secretsmanager' requires 'name' (secret name or ARN)")
            return _resolve_aws_secret(self.name, self.key)
        raise ConfigError(f"unsupported secretRef provider: {self.provider!r}")

    def __repr__(self) -> str:  # never leak name/path ambiguity into logs as a value
        target = self.path if self.provider == "file" else self.name
        return f"SecretRef(provider={self.provider!r}, target={target!r})"


def _resolve_aws_secret(secret_id: str, key: str | None) -> str:
    """Reads one secret from AWS Secrets Manager (boto3 ships with the Lambda Python runtime).
    Needs ``secretsmanager:GetSecretValue`` on the secret, plus ``kms:Decrypt`` if it uses a
    customer-managed key."""

    with _aws_secret_lock:
        cached = _aws_secret_cache.get(secret_id)
        if cached is not None and time.time() - cached[0] >= _AWS_SECRET_TTL_SECONDS:
            del _aws_secret_cache[secret_id]  # don't keep an expired plaintext around
            cached = None
    if cached is not None:
        text = cached[1]
    else:
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:
            raise ConfigError(
                "secretRef provider 'aws_secretsmanager' needs boto3 -- it is preinstalled in AWS Lambda; "
                "elsewhere: pip install boto3"
            ) from exc
        try:
            # Short, bounded calls: a function with no route to AWS fails fast instead of hanging.
            client = boto3.client(
                "secretsmanager",
                config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 3, "mode": "standard"}),
            )
            response = client.get_secret_value(SecretId=secret_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "unknown")
            raise ConfigError(
                f"could not read Secrets Manager secret {secret_id!r} ({code}). Check the name/ARN and "
                f"region, and that this role is allowed secretsmanager:GetSecretValue on it "
                f"(plus kms:Decrypt if it uses a customer-managed key)."
            ) from exc
        except BotoCoreError as exc:
            raise ConfigError(f"could not reach Secrets Manager for secret {secret_id!r}: {exc}") from exc
        text = response.get("SecretString") or ""
        if not text.strip():
            raise ConfigError(f"Secrets Manager secret {secret_id!r} has no SecretString (binary secrets are unsupported)")
        with _aws_secret_lock:
            _aws_secret_cache[secret_id] = (time.time(), text)

    if key is None:
        return text.strip()
    try:
        value = json.loads(text)[key]
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError(f"Secrets Manager secret {secret_id!r} is not a JSON object with a {key!r} field") from exc
    if not isinstance(value, str) or not value:
        raise ConfigError(f"field {key!r} of Secrets Manager secret {secret_id!r} must be a non-empty string")
    return value


def _looks_like_secret_ref(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and "provider" in value
        and value.get("provider") in SECRET_PROVIDERS
    )


def _parse_secret_ref(value: Any, *, context: str) -> SecretRef | None:
    if value is None:
        return None
    if not _looks_like_secret_ref(value):
        raise ConfigError(
            f"{context}: expected a secretRef object ({{provider: env|file|aws_secretsmanager, ...}}) or null, "
            f"got a literal value -- inline secrets are rejected"
        )
    provider = value["provider"]
    if provider not in SECRET_PROVIDERS:
        raise ConfigError(f"{context}: unsupported secretRef provider {provider!r}")
    unknown = sorted(set(value) - {"provider", "name", "path", "key"})
    if unknown:
        raise ConfigError(
            f"{context}: unrecognized secretRef field(s) {unknown!r} -- a secretRef holds only "
            f"provider, name, path and key; it never carries the secret itself"
        )
    return SecretRef(provider=provider, name=value.get("name"), path=value.get("path"), key=value.get("key"))


# --------------------------------------------------------------------------
# Inline-secret rejection
# --------------------------------------------------------------------------


def _scan_for_inline_secrets(node: Any, *, path: str = "$") -> None:
    """Raise ConfigError if the parsed YAML tree contains anything that looks
    like an embedded credential rather than a reference to one."""

    if isinstance(node, Mapping):
        if _looks_like_secret_ref(node):
            return  # its fields are checked, and unknown ones rejected, by _parse_secret_ref
        for key, value in node.items():
            child_path = f"{path}.{key}"
            if is_forbidden_key(key):
                if value is not None and not _looks_like_secret_ref(value):
                    raise ConfigError(
                        f"{child_path}: field name suggests a credential; only null or a "
                        f"secretRef object is permitted here, never a literal value"
                    )
            _scan_for_inline_secrets(value, path=child_path)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _scan_for_inline_secrets(item, path=f"{path}[{index}]")
    elif isinstance(node, str):
        if PEM_PATTERN.search(node):
            raise ConfigError(f"{path}: inline PEM private-key material is not permitted")
        if BEARER_SHAPE_PATTERN.fullmatch(node.strip()):
            raise ConfigError(
                f"{path}: value has the shape of a bearer token; use a secretRef instead"
            )


# --------------------------------------------------------------------------
# Non-secret environment overrides
# --------------------------------------------------------------------------


def _apply_env_overrides(
    raw: MutableMapping[str, Any], env: Mapping[str, str]
) -> MutableMapping[str, Any]:
    overrides = {
        key[len(ENV_OVERRIDE_PREFIX) :]: value
        for key, value in env.items()
        if key.startswith(ENV_OVERRIDE_PREFIX)
    }
    for dotted, raw_value in sorted(overrides.items()):
        segments = [seg for seg in dotted.split("__") if seg]
        if not segments:
            continue
        _apply_single_override(raw, segments, raw_value, dotted_name=dotted)
    return raw


def _apply_single_override(
    raw: MutableMapping[str, Any], segments: Sequence[str], raw_value: str, *, dotted_name: str
) -> None:
    node: Any = raw
    for segment in segments[:-1]:
        matched_key = _match_key(node, segment)
        if matched_key is None:
            raise ConfigError(
                f"environment override {ENV_OVERRIDE_PREFIX}{dotted_name} targets an unknown "
                f"path segment {segment!r}; overrides may only touch existing config keys"
            )
        if is_forbidden_key(matched_key):
            # Every segment is checked, not just the leaf: provider/name/path aren't
            # credential-shaped names, so skipping this would let an override reach
            # inside a secretRef and redirect which env var or file a secret resolves from.
            raise ConfigError(
                f"environment override {ENV_OVERRIDE_PREFIX}{dotted_name} passes through a "
                f"credential field {matched_key!r}; overrides may never reach inside one, "
                f"even to change a non-secret subfield"
            )
        node = node[matched_key]
        if not isinstance(node, MutableMapping):
            raise ConfigError(
                f"environment override {ENV_OVERRIDE_PREFIX}{dotted_name} does not resolve to "
                f"an object at segment {segment!r}"
            )

    leaf_segment = segments[-1]
    matched_key = _match_key(node, leaf_segment)
    if matched_key is None:
        raise ConfigError(
            f"environment override {ENV_OVERRIDE_PREFIX}{dotted_name} targets an unknown key "
            f"{leaf_segment!r}; overrides may only touch existing config keys"
        )
    if is_forbidden_key(matched_key):
        raise ConfigError(
            f"environment override {ENV_OVERRIDE_PREFIX}{dotted_name} targets a credential "
            f"field; secrets must use their documented secretRef, never a plain override"
        )

    current = node[matched_key]
    node[matched_key] = _coerce_override_value(current, raw_value)


def _match_key(node: Any, segment: str) -> str | None:
    if not isinstance(node, Mapping):
        return None
    for key in node:
        if str(key).lower() == segment.lower():
            return str(key)
    return None


def _coerce_override_value(current: Any, raw_value: str) -> Any:
    if isinstance(current, bool):
        lowered = raw_value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
        raise ConfigError(f"cannot coerce override value {raw_value!r} to boolean")
    if isinstance(current, int):
        return int(raw_value)
    if isinstance(current, list):
        return [item.strip() for item in raw_value.split(",") if item.strip()]
    return raw_value


# --------------------------------------------------------------------------
# Typed configuration model
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class DeploymentConfig:
    name: str


@dataclasses.dataclass(frozen=True)
class OciAuthenticationConfig:
    type: str
    # Set when credentials come from an OCI SDK config file; unused with credentials_secret_ref.
    config_file: str | None
    profile: str | None
    private_key_passphrase_secret_ref: SecretRef | None
    # A secret holding the SDK config as JSON ({user, fingerprint, tenancy, region, key_content,
    # [pass_phrase]}) -- for hosts with no filesystem to keep ~/.oci on, e.g. AWS Lambda.
    credentials_secret_ref: SecretRef | None = None


@dataclasses.dataclass(frozen=True)
class OciRegionsConfig:
    allow: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class OciCompartmentsConfig:
    roots: tuple[str, ...]
    exclude_ocids: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class OciServicesConfig:
    compute: bool
    network_exposure: bool
    block_storage: bool
    base_database: bool
    autonomous_database: bool
    site_to_site_vpn: bool
    # Broader trust footprint than the other domains: reads user MFA status, API key
    # ages, and raw IAM policy statement text. Opt-in, off unless explicitly enabled --
    # see README Section 4 for the additional least-privilege policy grant it needs.
    identity: bool = False
    object_storage: bool = False
    cloud_guard: bool = False
    monitoring: bool = False
    load_balancer: bool = False
    waf: bool = False
    kms_vault: bool = False


@dataclasses.dataclass(frozen=True)
class OciConfig:
    authentication: OciAuthenticationConfig
    expected_tenancy_ocid: str
    regions: OciRegionsConfig
    compartments: OciCompartmentsConfig
    services: OciServicesConfig


@dataclasses.dataclass(frozen=True)
class DecisionsConfig:
    public_source_cidrs: tuple[str, ...] = DEFAULT_PUBLIC_SOURCE_CIDRS


@dataclasses.dataclass(frozen=True)
class DrataConfig:
    base_url: str
    connection_id: int
    # Custom Connection resource registered with schemas/flat-record.schema.json.
    resource_id: int
    api_token_secret_ref: SecretRef
    allow_alternate_host: bool = False


@dataclasses.dataclass(frozen=True)
class RuntimeConfig:
    max_payload_bytes: int
    max_concurrency: int
    log_level: str
    dry_run: bool


@dataclasses.dataclass(frozen=True)
class AppConfig:
    deployment: DeploymentConfig
    oci: OciConfig
    decisions: DecisionsConfig
    drata: DrataConfig
    runtime: RuntimeConfig


def _require(mapping: Mapping[str, Any], key: str, *, context: str) -> Any:
    if key not in mapping or mapping[key] is None:
        raise ConfigError(f"{context}: missing required field {key!r}")
    return mapping[key]


def _require_bool(mapping: Mapping[str, Any], key: str, *, context: str) -> bool:
    """YAML only produces a real bool for an unquoted true/false literal -- a quoted
    "false" parses as the string "false", and bool("false") is True. Reject anything
    that isn't already a native bool instead of coercing it."""

    value = _require(mapping, key, context=context)
    if not isinstance(value, bool):
        raise ConfigError(
            f"{context}.{key}: expected true or false (unquoted), got {value!r} "
            f"({type(value).__name__}) -- a quoted string is not a boolean"
        )
    return value


def _require_int(
    mapping: Mapping[str, Any],
    key: str,
    *,
    context: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    value = _require(mapping, key, context=context)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{context}.{key}: expected an integer, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{context}.{key}: must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{context}.{key}: must be <= {maximum}, got {value}")
    return value


def _optional_bool(mapping: Mapping[str, Any], key: str, *, context: str, default: bool) -> bool:
    """Like _require_bool, but absent means `default` instead of a ConfigError --
    for a field added after existing deployments were configured, where requiring
    it would break every config.yaml that predates it."""

    if key not in mapping or mapping[key] is None:
        return default
    value = mapping[key]
    if not isinstance(value, bool):
        raise ConfigError(
            f"{context}.{key}: expected true or false (unquoted), got {value!r} "
            f"({type(value).__name__}) -- a quoted string is not a boolean"
        )
    return value


def _require_cidr_list(mapping: Mapping[str, Any], key: str, *, context: str) -> tuple[str, ...]:
    """Validates here, before collection -- an empty reference set would silently
    make every exposure check resolve to not_exposed, regardless of actual rules."""

    raw_list = _require(mapping, key, context=context)
    if not isinstance(raw_list, list) or not raw_list:
        raise ConfigError(f"{context}.{key}: must be a non-empty list of CIDRs")
    cidrs = []
    for item in raw_list:
        if not isinstance(item, str):
            raise ConfigError(f"{context}.{key}: {item!r} is not a CIDR string")
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{context}.{key}: {item!r} is not a valid CIDR: {exc}") from exc
        cidrs.append(item)
    return tuple(cidrs)


def _check_known_keys(
    mapping: Any, allowed: frozenset[str], *, context: str, legacy: frozenset[str] = frozenset()
) -> None:
    if not isinstance(mapping, Mapping):
        return
    ignored = set(mapping) & legacy
    if ignored:
        logger.warning(
            "%s: ignoring %s -- no longer used, safe to delete from config.yaml", context, sorted(ignored)
        )
    unknown = set(mapping) - allowed - legacy
    if unknown:
        raise ConfigError(
            f"{context}: unrecognized field(s) {sorted(unknown)!r} -- check for a typo "
            f"against the documented field names in config.example.yaml"
        )


def _validate_drata_base_url(url: str, *, allow_alternate_host: bool) -> None:
    """Fails before the API token is ever resolved or sent anywhere -- a tampered or
    typo'd baseUrl must not silently become a place the bearer token gets POSTed to."""

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ConfigError(f"drata.baseUrl must use https, got {url!r}")
    if parsed.username or parsed.password:
        raise ConfigError("drata.baseUrl must not embed credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError("drata.baseUrl must not include a query string or fragment")
    if not parsed.hostname:
        raise ConfigError(f"drata.baseUrl has no hostname: {url!r}")
    if ".." in parsed.path.split("/"):
        raise ConfigError(f"drata.baseUrl path must not contain '..': {url!r}")
    if parsed.hostname != DEFAULT_DRATA_HOSTNAME:
        if not allow_alternate_host:
            raise ConfigError(
                f"drata.baseUrl hostname {parsed.hostname!r} is not the expected "
                f"{DEFAULT_DRATA_HOSTNAME!r} -- set drata.allowAlternateHost: true to "
                f"explicitly opt in if this deployment genuinely targets a different "
                f"Drata endpoint (e.g. a regional or dedicated instance)"
            )
        logger.warning(
            "drata.baseUrl targets a non-default host",
            extra={"hostname": parsed.hostname},
        )


_TOP_LEVEL_KEYS = frozenset({"deployment", "oci", "decisions", "drata", "runtime"})
_DEPLOYMENT_KEYS = frozenset({"name"})
# Keys earlier versions required or accepted that no longer have any effect. Still tolerated
# so an existing config.yaml keeps loading after an upgrade.
_LEGACY_DEPLOYMENT_KEYS = frozenset({"snapshotDisplayName"})
_LEGACY_DECISIONS_KEYS = frozenset(
    {
        "administrativePorts", "minimumVpnTunnelCount", "minimumUpVpnTunnelCount",
        "freshnessHours", "requireCustomerManagedVolumeKeys", "requireCustomerManagedDatabaseKeys",
    }
)
_OCI_KEYS = frozenset(
    {"authentication", "expectedTenancyOcid", "regions", "compartments", "services"}
)
_OCI_AUTH_KEYS = frozenset(
    {"type", "configFile", "profile", "privateKeyPassphraseSecretRef", "credentialsSecretRef"}
)
_OCI_REGIONS_KEYS = frozenset({"allow"})
_OCI_COMPARTMENTS_KEYS = frozenset({"roots", "excludeOcids"})
_OCI_SERVICES_KEYS = frozenset(
    {
        "compute", "networkExposure", "blockStorage", "baseDatabase",
        "autonomousDatabase", "siteToSiteVpn", "identity",
        "objectStorage", "cloudGuard", "monitoring", "loadBalancer", "waf", "kmsVault",
    }
)
_DECISIONS_KEYS = frozenset({"publicSourceCidrs"})
_DRATA_KEYS = frozenset(
    {"baseUrl", "connectionId", "resourceId", "apiTokenSecretRef", "allowAlternateHost"}
)
_RUNTIME_KEYS = frozenset({"maxPayloadBytes", "maxConcurrency", "logLevel", "dryRun"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _build_app_config(raw: Mapping[str, Any]) -> AppConfig:
    _check_known_keys(raw, _TOP_LEVEL_KEYS, context="$")

    dep = _require(raw, "deployment", context="$")
    _check_known_keys(dep, _DEPLOYMENT_KEYS, context="deployment", legacy=_LEGACY_DEPLOYMENT_KEYS)
    deployment_name = _require(dep, "name", context="deployment")
    if not isinstance(deployment_name, str) or not deployment_name.strip() or len(deployment_name) > 200:
        raise ConfigError("deployment.name must be a non-empty string of at most 200 characters")
    deployment = DeploymentConfig(name=deployment_name)

    oci_raw = _require(raw, "oci", context="$")
    _check_known_keys(oci_raw, _OCI_KEYS, context="oci")

    auth_raw = _require(oci_raw, "authentication", context="oci")
    _check_known_keys(auth_raw, _OCI_AUTH_KEYS, context="oci.authentication")
    credentials_secret_ref = _parse_secret_ref(
        auth_raw.get("credentialsSecretRef"), context="oci.authentication.credentialsSecretRef"
    )
    if credentials_secret_ref is None:
        config_file = _require(auth_raw, "configFile", context="oci.authentication")
        profile = _require(auth_raw, "profile", context="oci.authentication")
    else:
        config_file = auth_raw.get("configFile")
        profile = auth_raw.get("profile")
    authentication = OciAuthenticationConfig(
        type=_require(auth_raw, "type", context="oci.authentication"),
        config_file=config_file,
        profile=profile,
        private_key_passphrase_secret_ref=_parse_secret_ref(
            auth_raw.get("privateKeyPassphraseSecretRef"),
            context="oci.authentication.privateKeyPassphraseSecretRef",
        ),
        credentials_secret_ref=credentials_secret_ref,
    )

    regions_raw = _require(oci_raw, "regions", context="oci")
    _check_known_keys(regions_raw, _OCI_REGIONS_KEYS, context="oci.regions")
    regions = OciRegionsConfig(allow=tuple(_require(regions_raw, "allow", context="oci.regions")))
    if not regions.allow:
        raise ConfigError("oci.regions.allow must list at least one region")

    compartments_raw = _require(oci_raw, "compartments", context="oci")
    _check_known_keys(compartments_raw, _OCI_COMPARTMENTS_KEYS, context="oci.compartments")
    roots = tuple(_require(compartments_raw, "roots", context="oci.compartments"))
    if not roots:
        raise ConfigError("oci.compartments.roots must list at least one root")
    compartments = OciCompartmentsConfig(
        roots=roots,
        exclude_ocids=tuple(compartments_raw.get("excludeOcids") or ()),
    )

    services_raw = _require(oci_raw, "services", context="oci")
    _check_known_keys(services_raw, _OCI_SERVICES_KEYS, context="oci.services")
    services = OciServicesConfig(
        compute=_require_bool(services_raw, "compute", context="oci.services"),
        network_exposure=_require_bool(services_raw, "networkExposure", context="oci.services"),
        block_storage=_require_bool(services_raw, "blockStorage", context="oci.services"),
        base_database=_require_bool(services_raw, "baseDatabase", context="oci.services"),
        autonomous_database=_require_bool(
            services_raw, "autonomousDatabase", context="oci.services"
        ),
        site_to_site_vpn=_require_bool(services_raw, "siteToSiteVpn", context="oci.services"),
        identity=_optional_bool(services_raw, "identity", context="oci.services", default=False),
        object_storage=_optional_bool(
            services_raw, "objectStorage", context="oci.services", default=False
        ),
        cloud_guard=_optional_bool(services_raw, "cloudGuard", context="oci.services", default=False),
        monitoring=_optional_bool(services_raw, "monitoring", context="oci.services", default=False),
        load_balancer=_optional_bool(
            services_raw, "loadBalancer", context="oci.services", default=False
        ),
        waf=_optional_bool(services_raw, "waf", context="oci.services", default=False),
        kms_vault=_optional_bool(services_raw, "kmsVault", context="oci.services", default=False),
    )

    oci_config = OciConfig(
        authentication=authentication,
        expected_tenancy_ocid=_require(oci_raw, "expectedTenancyOcid", context="oci"),
        regions=regions,
        compartments=compartments,
        services=services,
    )

    decisions_raw = raw.get("decisions") or {}
    _check_known_keys(decisions_raw, _DECISIONS_KEYS, context="decisions", legacy=_LEGACY_DECISIONS_KEYS)
    decisions = DecisionsConfig(
        public_source_cidrs=(
            _require_cidr_list(decisions_raw, "publicSourceCidrs", context="decisions")
            if "publicSourceCidrs" in decisions_raw
            else DEFAULT_PUBLIC_SOURCE_CIDRS
        )
    )

    drata_raw = _require(raw, "drata", context="$")
    _check_known_keys(drata_raw, _DRATA_KEYS, context="drata")
    api_token_secret_ref = _parse_secret_ref(
        _require(drata_raw, "apiTokenSecretRef", context="drata"),
        context="drata.apiTokenSecretRef",
    )
    if api_token_secret_ref is None:
        raise ConfigError("drata.apiTokenSecretRef is required")

    base_url = _require(drata_raw, "baseUrl", context="drata")
    allow_alternate_host = bool(drata_raw.get("allowAlternateHost", False))
    _validate_drata_base_url(base_url, allow_alternate_host=allow_alternate_host)

    drata = DrataConfig(
        base_url=base_url,
        connection_id=_require_int(drata_raw, "connectionId", context="drata", minimum=1),
        resource_id=_require_int(drata_raw, "resourceId", context="drata", minimum=1),
        api_token_secret_ref=api_token_secret_ref,
        allow_alternate_host=allow_alternate_host,
    )

    runtime_raw = _require(raw, "runtime", context="$")
    _check_known_keys(runtime_raw, _RUNTIME_KEYS, context="runtime")
    log_level = _require(runtime_raw, "logLevel", context="runtime")
    if not isinstance(log_level, str) or log_level.upper() not in _LOG_LEVELS:
        raise ConfigError(
            f"runtime.logLevel: expected one of {sorted(_LOG_LEVELS)!r}, got {log_level!r}"
        )
    runtime = RuntimeConfig(
        max_payload_bytes=_require_int(runtime_raw, "maxPayloadBytes", context="runtime", minimum=1),
        max_concurrency=_require_int(runtime_raw, "maxConcurrency", context="runtime", minimum=1, maximum=32),
        log_level=log_level.upper(),
        dry_run=_require_bool(runtime_raw, "dryRun", context="runtime"),
    )

    return AppConfig(
        deployment=deployment,
        oci=oci_config,
        decisions=decisions,
        drata=drata,
        runtime=runtime,
    )


def load_config(
    path: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> AppConfig:
    """Load, validate, and type the deployment configuration file.

    Does not resolve any secret -- callers resolve each secretRef at point of use.
    """

    env = os.environ if env is None else env
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ConfigError(f"configuration file not found: {config_path}")

    text = config_path.read_text(encoding="utf-8")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"configuration file is not valid YAML: {exc}") from exc
    if not isinstance(raw, MutableMapping):
        raise ConfigError("configuration file must contain a YAML mapping at the top level")

    _scan_for_inline_secrets(raw)
    _apply_env_overrides(raw, env)
    _scan_for_inline_secrets(raw)  # overrides could reintroduce a literal secret

    return _build_app_config(raw)


# --------------------------------------------------------------------------
# Redaction helpers for logging -- never print resolved secrets
# --------------------------------------------------------------------------


def redact_config_for_display(raw: Mapping[str, Any]) -> Any:
    """Return a copy of a raw config mapping safe to log: secretRef targets
    and any residual credential-shaped fields are replaced with a marker."""

    if isinstance(raw, Mapping):
        out: dict[str, Any] = {}
        for key, value in raw.items():
            if is_forbidden_key(key):
                out[key] = REDACTED_MARKER if value is not None else None
            else:
                out[key] = redact_config_for_display(value)
        return out
    if isinstance(raw, list):
        return [redact_config_for_display(item) for item in raw]
    return raw
