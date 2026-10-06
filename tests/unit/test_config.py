from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oci_drata.config import ConfigError, SecretRef, load_config

SAMPLE_CONFIG = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"


def _sample_config_with_real_drata_ids(tmp_path: Path) -> Path:
    """connectionId/resourceId in config.example.yaml are invalid placeholders (0);
    tests not exercising that rejection need a copy with real-shaped ids."""

    raw = yaml.safe_load(SAMPLE_CONFIG.read_text())
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    return _write_config(tmp_path, raw)


def _valid_config_dict() -> dict:
    raw = yaml.safe_load(SAMPLE_CONFIG.read_text())
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    return raw


def _write_config(tmp_path: Path, raw: dict, *, name: str = "config.yaml") -> Path:
    config_path = tmp_path / name
    config_path.write_text(yaml.safe_dump(raw))
    return config_path


def test_sample_config_loads(tmp_path: Path) -> None:
    cfg = load_config(_sample_config_with_real_drata_ids(tmp_path), env={"DRATA_API_TOKEN": "unused"})
    assert cfg.deployment.name == "example-production"
    assert cfg.oci.regions.allow == ("us-ashburn-1", "us-phoenix-1")
    assert cfg.oci.compartments.roots == ("tenancy",)
    assert cfg.runtime.dry_run is True
    assert cfg.drata.api_token_secret_ref == SecretRef(provider="env", name="DRATA_API_TOKEN")


@pytest.mark.parametrize(
    "bad_yaml",
    [
        "drata:\n  apiTokenSecretRef:\n    token: literal-token-value\n",
        "oci:\n  authentication:\n    privateKeyPassphraseSecretRef:\n      passphrase: literal\n",
        "x: |\n  -----BEGIN RSA PRIVATE KEY-----\n  abcd\n  -----END RSA PRIVATE KEY-----\n",
        "x: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n",
    ],
)
def test_inline_secret_rejected(tmp_path: Path, bad_yaml: str) -> None:
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(bad_yaml)
    with pytest.raises(ConfigError):
        load_config(config_file)


def test_env_override_regions_and_bool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = load_config(
        _sample_config_with_real_drata_ids(tmp_path),
        env={
            "DRATA_API_TOKEN": "unused",
            "OCI_DRATA__OCI__REGIONS__ALLOW": "eu-frankfurt-1,uk-london-1",
            "OCI_DRATA__RUNTIME__DRYRUN": "false",
            "OCI_DRATA__RUNTIME__MAXCONCURRENCY": "16",
        },
    )
    assert cfg.oci.regions.allow == ("eu-frankfurt-1", "uk-london-1")
    assert cfg.runtime.dry_run is False
    assert cfg.runtime.max_concurrency == 16


def test_env_override_cannot_target_secret_field() -> None:
    with pytest.raises(ConfigError, match="credential"):
        load_config(
            SAMPLE_CONFIG,
            env={
                "DRATA_API_TOKEN": "unused",
                "OCI_DRATA__DRATA__APITOKENSECRETREF": "sk-literal-token",
            },
        )


def test_secret_ref_env_provider_missing_raises() -> None:
    with pytest.raises(ConfigError, match="is not set"):
        SecretRef(provider="env", name="DOES_NOT_EXIST_XYZ").resolve()


def test_secret_ref_file_provider_rejects_world_readable(tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("value123")
    secret_file.chmod(0o644)  # group/world readable
    with pytest.raises(ConfigError, match="group- or world-accessible"):
        SecretRef(provider="file", path=str(secret_file)).resolve()


# --------------------------------------------------------------------------
# Strict field validation: loose bool()/int() conversion used to accept a
# quoted "false" as truthy, zero/negative ids, out-of-range ports, unknown keys.
# --------------------------------------------------------------------------


def test_quoted_false_string_is_rejected_not_silently_true(tmp_path: Path) -> None:
    """bool("false") is True in Python; a quoted boolean must raise a config error,
    not silently invert the toggle."""

    raw = _valid_config_dict()
    raw["oci"]["services"]["compute"] = "false"  # YAML string, not a bool
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="oci.services.compute"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


# --------------------------------------------------------------------------
# publicSourceCidrs: malformed/empty entries must fail before collection --
# an empty reference set makes every rule's source fail to resolve as public.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# drata.baseUrl allowlist: without it, the bearer token could be sent to any
# host.
# --------------------------------------------------------------------------


def test_alternate_drata_host_requires_explicit_override(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["drata"]["baseUrl"] = "https://drata.internal.example.com/public/v2"
    raw["drata"]["allowAlternateHost"] = True
    config_path = _write_config(tmp_path, raw)
    cfg = load_config(config_path, env={"DRATA_API_TOKEN": "unused"})
    assert cfg.drata.base_url == "https://drata.internal.example.com/public/v2"
    assert cfg.drata.allow_alternate_host is True


