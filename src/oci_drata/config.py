"""Deployment config loading and secretRef resolution.

Inline credentials are rejected; secrets resolve only via secretRef, lazily, per caller.
OCI_DRATA__-prefixed env vars override non-secret settings after YAML load, before secret resolution.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import os
import stat
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
DEFAULT_DRATA_HOSTNAME = "public-api.drata.com"


class ConfigError(Exception):
    """Raised for invalid, insecure, or unresolvable configuration."""


# --------------------------------------------------------------------------
# Secret references
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SecretRef:
    """Pointer to a secret value. Never carries the value itself."""

    provider: str  # "env" | "file"
    name: str | None = None
    path: str | None = None

    def resolve(self) -> str:
        if self.provider == "env":
            if not self.name:
                raise ConfigError("secretRef provider 'env' requires 'name'")
            value = os.environ.get(self.name)
            if not value:
                raise ConfigError(
                    f"required secret environment variable is missing or empty: {self.name}"
                )
            return value
        if self.provider == "file":
            if not self.path:
                raise ConfigError("secretRef provider 'file' requires 'path'")
            file_path = Path(self.path).expanduser()
            if not file_path.is_file():
                raise ConfigError(f"secret file does not exist: {self.path}")
            mode = file_path.stat().st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError(
                    f"secret file must not be group- or world-accessible: {self.path}"
                )
            value = file_path.read_text(encoding="utf-8").strip()
            if not value:
                raise ConfigError(f"secret file is empty: {self.path}")
            return value
        raise ConfigError(f"unsupported secretRef provider: {self.provider!r}")

    def __repr__(self) -> str:  # never leak name/path ambiguity into logs as a value
        target = self.name if self.provider == "env" else self.path
        return f"SecretRef(provider={self.provider!r}, target={target!r})"


def _looks_like_secret_ref(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and "provider" in value
        and value.get("provider") in ("env", "file")
    )


def _parse_secret_ref(value: Any, *, context: str) -> SecretRef | None:
    if value is None:
        return None
    if not _looks_like_secret_ref(value):
        raise ConfigError(
            f"{context}: expected a secretRef object ({{provider: env|file, ...}}) or null, "
            f"got a literal value -- inline secrets are rejected"
        )
    provider = value["provider"]
    if provider not in ("env", "file"):
        raise ConfigError(f"{context}: unsupported secretRef provider {provider!r}")
    return SecretRef(provider=provider, name=value.get("name"), path=value.get("path"))


# --------------------------------------------------------------------------
# Inline-secret rejection
# --------------------------------------------------------------------------


def _scan_for_inline_secrets(node: Any, *, path: str = "$") -> None:
    """Raise ConfigError if the parsed YAML tree contains anything that looks
    like an embedded credential rather than a reference to one."""

    if isinstance(node, Mapping):
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
    snapshot_display_name: str


@dataclasses.dataclass(frozen=True)
class OciAuthenticationConfig:
    type: str
    config_file: str
    profile: str
    private_key_passphrase_secret_ref: SecretRef | None


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
    exadata_detection: bool
    site_to_site_vpn: bool
    # Broader trust footprint than the other domains: reads user MFA status, API key
    # ages, and raw IAM policy statement text. Opt-in, off unless explicitly enabled --
    # see README Section 4 for the additional least-privilege policy grant it needs.
    identity: bool = False
    object_storage: bool = False
    cloud_guard: bool = False
    monitoring: bool = False


@dataclasses.dataclass(frozen=True)
class OciConfig:
    authentication: OciAuthenticationConfig
    expected_tenancy_ocid: str
    regions: OciRegionsConfig
    compartments: OciCompartmentsConfig
    services: OciServicesConfig


@dataclasses.dataclass(frozen=True)
class DecisionsConfig:
    administrative_ports: tuple[int, ...]
    public_source_cidrs: tuple[str, ...]
    minimum_vpn_tunnel_count: int
    minimum_up_vpn_tunnel_count: int
    freshness_hours: int
    require_customer_managed_volume_keys: bool
    require_customer_managed_database_keys: bool


@dataclasses.dataclass(frozen=True)
class DrataConfig:
    base_url: str
    connection_id: int
    resource_id: int
    record_id: str
    api_token_secret_ref: SecretRef
    allow_alternate_host: bool = False
    # Resource ID of a second Custom Connection resource registered with
    # schemas/flat-record.schema.json (see PLAN.md). None/absent leaves the
    # flat-record publish path disabled entirely -- default behavior is
    # unchanged from before that path existed.
    flat_resource_id: int | None = None


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


def _optional_int(
    mapping: Mapping[str, Any], key: str, *, context: str, minimum: int | None = None
) -> int | None:
    if key not in mapping or mapping[key] is None:
        return None
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{context}.{key}: expected an integer or null, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{context}.{key}: must be >= {minimum}, got {value}")
    return value


def _require_port_list(mapping: Mapping[str, Any], key: str, *, context: str) -> tuple[int, ...]:
    raw_list = _require(mapping, key, context=context)
    if not isinstance(raw_list, list) or not raw_list:
        raise ConfigError(f"{context}.{key}: must be a non-empty list of ports")
    ports = []
    for item in raw_list:
        if isinstance(item, bool) or not isinstance(item, int) or not (1 <= item <= 65535):
            raise ConfigError(f"{context}.{key}: {item!r} is not a valid port (1-65535)")
        ports.append(item)
    return tuple(ports)


def _require_cidr_list(mapping: Mapping[str, Any], key: str, *, context: str) -> tuple[str, ...]:
    """Fails at config-load time, before any OCI collection, rather than letting a
    malformed or empty entry silently make transform.exposure.ExposureConfig's reference
    set empty -- which would make every exposure check resolve to not_exposed regardless
    of what the collected security rules actually allow."""

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


def _check_known_keys(mapping: Any, allowed: frozenset[str], *, context: str) -> None:
    if not isinstance(mapping, Mapping):
        return
    unknown = set(mapping) - allowed
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
_DEPLOYMENT_KEYS = frozenset({"name", "snapshotDisplayName"})
_OCI_KEYS = frozenset(
    {"authentication", "expectedTenancyOcid", "regions", "compartments", "services"}
)
_OCI_AUTH_KEYS = frozenset({"type", "configFile", "profile", "privateKeyPassphraseSecretRef"})
_OCI_REGIONS_KEYS = frozenset({"allow"})
_OCI_COMPARTMENTS_KEYS = frozenset({"roots", "excludeOcids"})
_OCI_SERVICES_KEYS = frozenset(
    {
        "compute", "networkExposure", "blockStorage", "baseDatabase",
        "autonomousDatabase", "exadataDetection", "siteToSiteVpn", "identity",
        "objectStorage", "cloudGuard", "monitoring",
    }
)
_DECISIONS_KEYS = frozenset(
    {
        "administrativePorts", "publicSourceCidrs", "minimumVpnTunnelCount",
        "minimumUpVpnTunnelCount", "freshnessHours", "requireCustomerManagedVolumeKeys",
        "requireCustomerManagedDatabaseKeys",
    }
)
_DRATA_KEYS = frozenset(
    {
        "baseUrl", "connectionId", "resourceId", "recordId", "apiTokenSecretRef",
        "allowAlternateHost", "flatResourceId",
    }
)
_RUNTIME_KEYS = frozenset({"maxPayloadBytes", "maxConcurrency", "logLevel", "dryRun"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _build_app_config(raw: Mapping[str, Any]) -> AppConfig:
    _check_known_keys(raw, _TOP_LEVEL_KEYS, context="$")

    dep = _require(raw, "deployment", context="$")
    _check_known_keys(dep, _DEPLOYMENT_KEYS, context="deployment")
    deployment = DeploymentConfig(
        name=_require(dep, "name", context="deployment"),
        snapshot_display_name=_require(dep, "snapshotDisplayName", context="deployment"),
    )

    oci_raw = _require(raw, "oci", context="$")
    _check_known_keys(oci_raw, _OCI_KEYS, context="oci")

    auth_raw = _require(oci_raw, "authentication", context="oci")
    _check_known_keys(auth_raw, _OCI_AUTH_KEYS, context="oci.authentication")
    authentication = OciAuthenticationConfig(
        type=_require(auth_raw, "type", context="oci.authentication"),
        config_file=_require(auth_raw, "configFile", context="oci.authentication"),
        profile=_require(auth_raw, "profile", context="oci.authentication"),
        private_key_passphrase_secret_ref=_parse_secret_ref(
            auth_raw.get("privateKeyPassphraseSecretRef"),
            context="oci.authentication.privateKeyPassphraseSecretRef",
        ),
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
        exadata_detection=_require_bool(
            services_raw, "exadataDetection", context="oci.services"
        ),
        site_to_site_vpn=_require_bool(services_raw, "siteToSiteVpn", context="oci.services"),
        identity=_optional_bool(services_raw, "identity", context="oci.services", default=False),
        object_storage=_optional_bool(
            services_raw, "objectStorage", context="oci.services", default=False
        ),
        cloud_guard=_optional_bool(services_raw, "cloudGuard", context="oci.services", default=False),
        monitoring=_optional_bool(services_raw, "monitoring", context="oci.services", default=False),
    )

    oci_config = OciConfig(
        authentication=authentication,
        expected_tenancy_ocid=_require(oci_raw, "expectedTenancyOcid", context="oci"),
        regions=regions,
        compartments=compartments,
        services=services,
    )

    decisions_raw = _require(raw, "decisions", context="$")
    _check_known_keys(decisions_raw, _DECISIONS_KEYS, context="decisions")
    decisions = DecisionsConfig(
        administrative_ports=_require_port_list(
            decisions_raw, "administrativePorts", context="decisions"
        ),
        public_source_cidrs=_require_cidr_list(
            decisions_raw, "publicSourceCidrs", context="decisions"
        ),
        minimum_vpn_tunnel_count=_require_int(
            decisions_raw, "minimumVpnTunnelCount", context="decisions", minimum=0
        ),
        minimum_up_vpn_tunnel_count=_require_int(
            decisions_raw, "minimumUpVpnTunnelCount", context="decisions", minimum=0
        ),
        freshness_hours=_require_int(decisions_raw, "freshnessHours", context="decisions", minimum=1),
        require_customer_managed_volume_keys=_require_bool(
            decisions_raw, "requireCustomerManagedVolumeKeys", context="decisions"
        ),
        require_customer_managed_database_keys=_require_bool(
            decisions_raw, "requireCustomerManagedDatabaseKeys", context="decisions"
        ),
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
        record_id=_require(drata_raw, "recordId", context="drata"),
        api_token_secret_ref=api_token_secret_ref,
        allow_alternate_host=allow_alternate_host,
        flat_resource_id=_optional_int(drata_raw, "flatResourceId", context="drata", minimum=1),
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
        max_concurrency=_require_int(runtime_raw, "maxConcurrency", context="runtime", minimum=1),
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
