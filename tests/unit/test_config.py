from __future__ import annotations

from pathlib import Path

import pytest

from oci_drata.config import ConfigError, SecretRef, load_config, redact_config_for_display

SAMPLE_CONFIG = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"


def test_sample_config_loads() -> None:
    cfg = load_config(SAMPLE_CONFIG, env={"DRATA_API_TOKEN": "unused"})
    assert cfg.deployment.name == "example-production"
    assert cfg.oci.regions.allow == ("us-ashburn-1", "us-phoenix-1")
    assert cfg.oci.compartments.roots == ("tenancy",)
    assert cfg.runtime.dry_run is True
    assert cfg.drata.api_token_secret_ref == SecretRef(provider="env", name="DRATA_API_TOKEN")


def test_missing_config_file_raises() -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/path/config.yaml")


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


def test_env_override_regions_and_bool(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config(
        SAMPLE_CONFIG,
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


def test_env_override_unknown_path_rejected() -> None:
    with pytest.raises(ConfigError, match="unknown"):
        load_config(SAMPLE_CONFIG, env={"DRATA_API_TOKEN": "unused", "OCI_DRATA__NOPE__X": "y"})


def test_secret_ref_env_provider_missing_raises() -> None:
    with pytest.raises(ConfigError, match="missing or empty"):
        SecretRef(provider="env", name="DOES_NOT_EXIST_XYZ").resolve()


def test_secret_ref_env_provider_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "value123")
    assert SecretRef(provider="env", name="MY_SECRET").resolve() == "value123"


def test_secret_ref_file_provider_rejects_world_readable(tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("value123")
    secret_file.chmod(0o644)  # group/world readable
    with pytest.raises(ConfigError, match="group- or world-accessible"):
        SecretRef(provider="file", path=str(secret_file)).resolve()


def test_secret_ref_file_provider_resolves_when_owner_only(tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("value123\n")
    secret_file.chmod(0o600)
    assert SecretRef(provider="file", path=str(secret_file)).resolve() == "value123"


def test_secret_ref_file_provider_rejects_empty_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("")
    secret_file.chmod(0o600)
    with pytest.raises(ConfigError, match="empty"):
        SecretRef(provider="file", path=str(secret_file)).resolve()


def test_redact_config_for_display_masks_secret_ref() -> None:
    import yaml

    raw = yaml.safe_load(SAMPLE_CONFIG.read_text())
    redacted = redact_config_for_display(raw)
    assert redacted["drata"]["apiTokenSecretRef"] == "<redacted>"
    assert redacted["oci"]["regions"]["allow"] == ["us-ashburn-1", "us-phoenix-1"]
