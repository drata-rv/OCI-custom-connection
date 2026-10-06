"""OCI authentication (API-signing user) and dynamic regional client construction.
Region/tenancy/client are never hard-coded; region must come from the validated
config allowlist (see :mod:`oci_drata.collection.discovery`).

Credentials come from an OCI SDK config file + key file, or -- for hosts with no
filesystem to keep them on, e.g. AWS Lambda -- from a secret holding the same fields as
JSON, with the PEM inline (``key_content``) so no key ever touches disk.
"""

from __future__ import annotations

import dataclasses
import json
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, cast

import oci

from oci_drata.config import AppConfig, ConfigError, SecretRef
from oci_drata.security import GuardedOciClient

T = TypeVar("T")


class AuthError(Exception):
    """Raised when OCI authentication cannot be established safely."""


@dataclasses.dataclass(frozen=True)
class TenancySigner:
    """Resolved OCI SDK config for the API-signing user.

    ``base_config`` is the private key file path -- or, with ``credentialsSecretRef``, the key
    itself (``key_content``) -- plus any passphrase. Never log, ``asdict`` or ``vars`` it; the
    custom ``__repr__`` below is what keeps it out of logs and tracebacks.
    """

    base_config: dict[str, str]
    # Idle HTTPS connections each client keeps; set to the fan-out width by runner.run().
    pool_size: int = 8

    def region_config(self, region: str) -> dict[str, str]:
        cfg = dict(self.base_config)
        cfg["region"] = region
        return cfg

    def __repr__(self) -> str:
        """Allowlists the two safe fields instead of blocklisting sensitive ones --
        base_config carries tenancy/user OCIDs, key fingerprint, and private key
        path, which must not leak into logs or tracebacks."""

        return (
            "TenancySigner(authentication_type='api_signing_user', "
            f"region={self.base_config.get('region')!r})"
        )


_SECRET_CONFIG_KEYS = frozenset({"user", "fingerprint", "tenancy", "region", "key_content", "pass_phrase"})


def _config_from_secret(ref: SecretRef) -> dict[str, str]:
    """The SDK config dict held in a secret. Only the documented SDK fields are accepted --
    notably never ``authentication_type`` or a key/token file path -- so a secret can't
    redirect authentication to anything but a plain API-signing key."""

    try:
        raw = json.loads(ref.resolve())
    except ConfigError as exc:
        raise AuthError(str(exc)) from exc
    except ValueError as exc:
        raise AuthError(f"oci.authentication.credentialsSecretRef ({ref!r}) is not valid JSON") from exc
    if not isinstance(raw, dict) or not all(isinstance(v, str) for v in raw.values()):
        raise AuthError(
            f"oci.authentication.credentialsSecretRef ({ref!r}) must be a JSON object of strings: "
            f"user, fingerprint, tenancy, region, key_content[, pass_phrase]"
        )
    if set(raw) - _SECRET_CONFIG_KEYS:
        # Field names are not echoed: they come from the secret, and a mistyped one can be a value.
        raise AuthError(
            f"oci.authentication.credentialsSecretRef ({ref!r}) has fields other than "
            f"{sorted(_SECRET_CONFIG_KEYS)}"
        )
    config = dict(raw)
    # A PEM pasted into a single-line secret field usually arrives with literal "\n" escapes.
    if "key_content" in config:
        config["key_content"] = config["key_content"].replace("\\n", "\n")
    return config


def _config_from_file(auth: Any) -> dict[str, str]:
    config_file = Path(auth.config_file).expanduser()
    if not config_file.is_file():
        raise AuthError(f"OCI SDK config file not found: {config_file}")
    config_file_mode = config_file.stat().st_mode
    if config_file_mode & (stat.S_IRWXG | stat.S_IRWXO):
        # Config file itself can carry pass_phrase directly (instead of via
        # privateKeyPassphraseSecretRef), plus tenancy/user/fingerprint --
        # sensitive metadata needing the same fail-closed check as key_file.
        raise AuthError(f"OCI SDK config file must not be group/world accessible: {config_file}")

    try:
        raw_config = oci.config.from_file(str(config_file), auth.profile)
    except Exception as exc:
        raise AuthError(
            f"failed to load OCI SDK config profile {auth.profile!r} from {config_file}: {exc}"
        ) from exc

    if "authentication_type" in raw_config:
        # validate_config() skips user/tenancy/fingerprint checks when this INI field
        # is set (e.g. instance_principal) -- distinct from this app's own auth.type
        # checked above. Reject before validate_config sees it.
        raise AuthError(
            f"OCI SDK config profile {auth.profile!r} sets 'authentication_type', which "
            f"this project doesn't support -- only a plain api_signing_user profile "
            f"(tenancy/user/fingerprint/key_file) is accepted"
        )

    key_file_value = raw_config.get("key_file")
    if not key_file_value:
        raise AuthError(f"OCI SDK config profile {auth.profile!r} has no key_file entry")
    key_file = Path(key_file_value).expanduser()
    if not key_file.is_file():
        raise AuthError(f"OCI private key file not found: {key_file}")
    mode = key_file.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise AuthError(f"OCI private key file must not be group/world accessible: {key_file}")
    return dict(raw_config)


def _check_private_key_loads(config: dict[str, str]) -> None:
    """validate_config accepts an empty or non-PEM key; load it now, so a bad key or passphrase
    fails here with a clear AuthError (exception type only: never echo key material)."""

    try:
        if config.get("key_content"):
            oci.signer.load_private_key(config["key_content"], config.get("pass_phrase"))
        else:
            oci.signer.load_private_key_from_file(
                str(Path(config["key_file"]).expanduser()), config.get("pass_phrase")
            )
    except Exception as exc:
        raise AuthError(
            f"OCI private key could not be loaded ({type(exc).__name__}) -- check that it is a PEM "
            f"private key and that pass_phrase / privateKeyPassphraseSecretRef is right"
        ) from exc


def build_signer(app_config: AppConfig, *, pool_size: int = 8) -> TenancySigner:
    """Load and validate the API-signing user's OCI SDK configuration.

    Fails closed: raises :class:`AuthError` on any missing file, permission
    problem, validation error, or tenancy mismatch.
    """

    auth = app_config.oci.authentication
    if auth.type != "api_signing_user":
        raise AuthError(
            f"unsupported authentication type {auth.type!r}; only 'api_signing_user' is "
            f"implemented"
        )

    raw_config = (
        _config_from_secret(auth.credentials_secret_ref)
        if auth.credentials_secret_ref is not None
        else _config_from_file(auth)
    )

    if auth.private_key_passphrase_secret_ref is not None:
        raw_config["pass_phrase"] = auth.private_key_passphrase_secret_ref.resolve()

    try:
        oci.config.validate_config(raw_config)
    except Exception as exc:
        raise AuthError(f"OCI SDK config failed validation: {exc}") from exc
    _check_private_key_loads(raw_config)

    tenancy_ocid = raw_config.get("tenancy")
    if tenancy_ocid != app_config.oci.expected_tenancy_ocid:
        raise AuthError(
            "OCI SDK config tenancy does not match configured oci.expectedTenancyOcid "
            f"(config file tenancy={tenancy_ocid!r})"
        )

    return TenancySigner(base_config=raw_config, pool_size=pool_size)


def _tune(client: Any, pool_size: int) -> Any:
    """One HTTPS pool per client (= per service x region). The SDK default keeps 10 connections;
    a pool as wide as the threads that share the client avoids discarded connections and their
    extra TLS handshakes, and no wider, so idle sockets stay far below Lambda's 1,024 file
    descriptors."""

    client.base_client.session.mount("https://", oci.base_client.OCIHTTPAdapter(pool_maxsize=pool_size))
    return client


def regional_client(client_cls: Callable[..., T], signer: TenancySigner, *, region: str) -> T:
    """Construct an OCI SDK client bound to one region (caller-supplied, never
    hard-coded).

    Returns a GuardedOciClient, cast back to T -- runtime enforcement alongside
    test_operation_allowlist.py's static AST scan (see security.py). Unrecognized
    operations raise at call time, not caught by mypy since attribute access is
    untyped (Any)."""

    # NoneRetryStrategy: some SDK operations retry by themselves (up to 8 attempts / 600 s),
    # invisibly to our deadline and request-slot accounting. pagination.py is the one retry layer.
    client = client_cls(signer.region_config(region), retry_strategy=oci.retry.NoneRetryStrategy())
    return cast(T, GuardedOciClient(_tune(client, signer.pool_size)))


def endpoint_client(
    client_cls: Callable[..., T], signer: TenancySigner, *, region: str, service_endpoint: str
) -> T:
    """Like regional_client, for a client needing an explicit per-resource
    endpoint instead of the region's default -- e.g. KmsManagementClient, whose
    endpoint comes per-vault from ``management_endpoint`` (see
    collection/kms_vault.py). Still wrapped in GuardedOciClient; only the
    endpoint differs."""

    client = client_cls(
        signer.region_config(region), service_endpoint, retry_strategy=oci.retry.NoneRetryStrategy()
    )
    return cast(T, GuardedOciClient(_tune(client, signer.pool_size)))
