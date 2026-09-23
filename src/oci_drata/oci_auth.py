"""OCI authentication (API-signing user) and dynamic regional client construction.
Region/tenancy/client are never hard-coded; region must come from the validated
config allowlist (see :mod:`oci_drata.collection.discovery`).
"""

from __future__ import annotations

import dataclasses
import stat
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar, cast

import oci

from oci_drata.config import AppConfig
from oci_drata.security import GuardedOciClient

T = TypeVar("T")


class AuthError(Exception):
    """Raised when OCI authentication cannot be established safely."""


@dataclasses.dataclass(frozen=True)
class TenancySigner:
    """Resolved OCI SDK config for the API-signing user.

    Holds only the private key file path, not key material. Do not log
    ``base_config`` -- may carry a resolved passphrase.
    """

    base_config: dict[str, str]

    def region_config(self, region: str) -> dict[str, str]:
        cfg = dict(self.base_config)
        cfg["region"] = region
        return cfg

    def __repr__(self) -> str:
        """base_config carries tenancy/user OCIDs, key fingerprint, and the private
        key's filesystem path -- account metadata that shouldn't appear in logs or
        exception tracebacks just because something formatted this object. Allowlist the
        two fields safe to show rather than blocklist the sensitive ones."""

        return (
            "TenancySigner(authentication_type='api_signing_user', "
            f"region={self.base_config.get('region')!r})"
        )


def build_signer(app_config: AppConfig) -> TenancySigner:
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

    config_file = Path(auth.config_file).expanduser()
    if not config_file.is_file():
        raise AuthError(f"OCI SDK config file not found: {config_file}")
    config_file_mode = config_file.stat().st_mode
    if config_file_mode & (stat.S_IRWXG | stat.S_IRWXO):
        # Only key_file was checked before -- but an operator can set pass_phrase
        # directly in this ini file instead of privateKeyPassphraseSecretRef, and
        # tenancy/user/fingerprint here are sensitive account metadata even without
        # that. Same fail-closed check as the key file itself.
        raise AuthError(f"OCI SDK config file must not be group/world accessible: {config_file}")

    try:
        raw_config = oci.config.from_file(str(config_file), auth.profile)
    except Exception as exc:
        raise AuthError(
            f"failed to load OCI SDK config profile {auth.profile!r} from {config_file}: {exc}"
        ) from exc

    if "authentication_type" in raw_config:
        # oci.config.validate_config() takes a different, more permissive path
        # (skipping user/tenancy/fingerprint validation) when this ini-level field is
        # set to e.g. instance_principal -- this project only implements and expects
        # api_signing_user (checked above, but that's this app's own config.yaml
        # field, a different thing from this OCI-SDK-ini-level one). Reject before
        # validate_config ever sees it, rather than relying on the weaker validation
        # path it would otherwise take.
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

    if auth.private_key_passphrase_secret_ref is not None:
        raw_config["pass_phrase"] = auth.private_key_passphrase_secret_ref.resolve()

    try:
        oci.config.validate_config(raw_config)
    except Exception as exc:
        raise AuthError(f"OCI SDK config failed validation: {exc}") from exc

    tenancy_ocid = raw_config.get("tenancy")
    if tenancy_ocid != app_config.oci.expected_tenancy_ocid:
        raise AuthError(
            "OCI SDK config tenancy does not match configured oci.expectedTenancyOcid "
            f"(config file tenancy={tenancy_ocid!r})"
        )

    return TenancySigner(base_config=raw_config)


def regional_client(client_cls: Callable[[dict[str, str]], T], signer: TenancySigner, *, region: str) -> T:
    """Construct an OCI SDK client bound to one region; region is always
    caller-supplied, never hard-coded.

    Returns a GuardedOciClient wrapping the real client, not the client itself --
    runtime enforcement alongside test_operation_allowlist.py's static AST scan
    (see security.py). Cast back to T: GuardedOciClient proxies every attribute
    access (as Any); an unrecognized operation raises at call time, same as a
    raw OCI client call, just not statically checked by mypy."""

    return cast(T, GuardedOciClient(client_cls(signer.region_config(region))))


def endpoint_client(
    client_cls: Callable[..., T], signer: TenancySigner, *, region: str, service_endpoint: str
) -> T:
    """Like regional_client, but for a client class that needs an explicit
    per-resource service endpoint instead of the region's default one --
    e.g. KmsManagementClient, whose endpoint is resolved per-vault from that
    vault's own ``management_endpoint`` field (see collection/kms_vault.py).
    Still wrapped in GuardedOciClient, same as every other client this project
    constructs -- the endpoint differs, the allowlist enforcement doesn't."""

    return cast(T, GuardedOciClient(client_cls(signer.region_config(region), service_endpoint)))
