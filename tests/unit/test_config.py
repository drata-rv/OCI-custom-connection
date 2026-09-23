from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oci_drata.config import ConfigError, SecretRef, load_config, redact_config_for_display

SAMPLE_CONFIG = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"


def _sample_config_with_real_drata_ids(tmp_path: Path) -> Path:
    """config.example.yaml's connectionId/resourceId are deliberately invalid
    placeholders (0) so an unedited copy fails config load, not just upload -- tests that
    aren't specifically exercising that placeholder need a copy with real-shaped ids."""

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


def test_sample_config_placeholder_drata_ids_rejected_unedited() -> None:
    """config.example.yaml's connectionId: 0 / resourceId: 0 must fail at config-load
    time if a customer forgets to replace them, not silently pass through to a
    confusing failure at Drata upload time."""

    with pytest.raises(ConfigError, match="connectionId"):
        load_config(SAMPLE_CONFIG, env={"DRATA_API_TOKEN": "unused"})


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


def test_env_override_cannot_reach_inside_a_secret_ref_to_redirect_it() -> None:
    """A leaf-only check would still let this through: apiTokenSecretRef itself isn't
    the segment being assigned, only traversed through -- provider/name/path aren't
    credential-shaped names themselves, so this would otherwise silently redirect
    which env var the real token resolves from."""

    with pytest.raises(ConfigError, match="credential"):
        load_config(
            SAMPLE_CONFIG,
            env={
                "DRATA_API_TOKEN": "unused",
                "OCI_DRATA__DRATA__APITOKENSECRETREF__NAME": "ATTACKER_CONTROLLED_VAR",
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
    raw = yaml.safe_load(SAMPLE_CONFIG.read_text())
    redacted = redact_config_for_display(raw)
    assert redacted["drata"]["apiTokenSecretRef"] == "<redacted>"
    assert redacted["oci"]["regions"]["allow"] == ["us-ashburn-1", "us-phoenix-1"]


# --------------------------------------------------------------------------
# Strict field validation (P1: loose bool()/int() conversion accepted a quoted
# "false" as truthy, zero/negative ids, out-of-range ports, and unknown keys)
# --------------------------------------------------------------------------


def test_quoted_false_string_is_rejected_not_silently_true(tmp_path: Path) -> None:
    """bool("false") is True in Python -- a YAML author quoting a boolean by habit must
    get a config error, not a silently-inverted service toggle."""

    raw = _valid_config_dict()
    raw["oci"]["services"]["compute"] = "false"  # YAML string, not a bool
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="oci.services.compute"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


@pytest.mark.parametrize("bad_value", [0, -1, 1.5, "1"])
def test_zero_or_non_bool_service_toggle_rejected(tmp_path: Path, bad_value) -> None:
    raw = _valid_config_dict()
    raw["oci"]["services"]["compute"] = bad_value
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="oci.services.compute"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


@pytest.mark.parametrize("bad_id", [0, -1])
def test_non_positive_connection_and_resource_id_rejected(tmp_path: Path, bad_id) -> None:
    raw = _valid_config_dict()
    raw["drata"]["connectionId"] = bad_id
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="connectionId"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


@pytest.mark.parametrize("bad_concurrency", [0, -3])
def test_non_positive_max_concurrency_rejected(tmp_path: Path, bad_concurrency) -> None:
    raw = _valid_config_dict()
    raw["runtime"]["maxConcurrency"] = bad_concurrency
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="maxConcurrency"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


@pytest.mark.parametrize("bad_bytes", [0, -1])
def test_non_positive_max_payload_bytes_rejected(tmp_path: Path, bad_bytes) -> None:
    raw = _valid_config_dict()
    raw["runtime"]["maxPayloadBytes"] = bad_bytes
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="maxPayloadBytes"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


@pytest.mark.parametrize("bad_ports", [[0], [65536], [22, -1], [22, 3389.5]])
def test_out_of_range_administrative_port_rejected(tmp_path: Path, bad_ports) -> None:
    raw = _valid_config_dict()
    raw["decisions"]["administrativePorts"] = bad_ports
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="administrativePorts"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_empty_administrative_ports_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["decisions"]["administrativePorts"] = []
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="administrativePorts"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_unknown_top_level_key_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["deploymnet"] = raw.pop("deployment")  # typo'd key alongside everything else intact
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="unrecognized"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_unknown_nested_key_rejected(tmp_path: Path) -> None:
    """A typo'd optional field (e.g. excludeOcids misspelled) must be rejected -- .get()
    on the correctly-spelled key would otherwise default to empty while the typo'd key
    sits there unused."""

    raw = _valid_config_dict()
    raw["oci"]["compartments"]["excludeOcid"] = ["ocid1.compartment.oc1..typo"]
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="oci.compartments"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_empty_compartment_roots_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["oci"]["compartments"]["roots"] = []
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="oci.compartments.roots"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_invalid_log_level_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["runtime"]["logLevel"] = "VERBOSE"
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="logLevel"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


# --------------------------------------------------------------------------
# publicSourceCidrs: malformed/empty entries must fail before collection, not
# silently make ExposureConfig's reference set empty (-> everything not_exposed)
# --------------------------------------------------------------------------


def test_malformed_public_source_cidr_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["decisions"]["publicSourceCidrs"] = ["0.0.0.0/0", "not-a-cidr"]
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="publicSourceCidrs"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_empty_public_source_cidrs_rejected(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["decisions"]["publicSourceCidrs"] = []
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="publicSourceCidrs"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_valid_public_source_cidrs_load(tmp_path: Path) -> None:
    cfg = load_config(_sample_config_with_real_drata_ids(tmp_path), env={"DRATA_API_TOKEN": "unused"})
    assert cfg.decisions.public_source_cidrs == ("0.0.0.0/0", "::/0")


# --------------------------------------------------------------------------
# drata.baseUrl allowlist (P1: arbitrary host accepted, bearer token could be
# sent anywhere)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://public-api.drata.com/public/v2",  # not https
        "https://user:pass@public-api.drata.com/public/v2",  # embedded credentials
        "https://public-api.drata.com/public/v2?x=1",  # query string
        "https://public-api.drata.com/public/v2#frag",  # fragment
        "https://public-api.drata.com/../public/v2",  # path traversal
        "https://evil.example.com/public/v2",  # non-default host, no override
    ],
)
def test_invalid_drata_base_url_rejected(tmp_path: Path, bad_url: str) -> None:
    raw = _valid_config_dict()
    raw["drata"]["baseUrl"] = bad_url
    config_path = _write_config(tmp_path, raw)
    with pytest.raises(ConfigError, match="baseUrl"):
        load_config(config_path, env={"DRATA_API_TOKEN": "unused"})


def test_alternate_drata_host_requires_explicit_override(tmp_path: Path) -> None:
    raw = _valid_config_dict()
    raw["drata"]["baseUrl"] = "https://drata.internal.example.com/public/v2"
    raw["drata"]["allowAlternateHost"] = True
    config_path = _write_config(tmp_path, raw)
    cfg = load_config(config_path, env={"DRATA_API_TOKEN": "unused"})
    assert cfg.drata.base_url == "https://drata.internal.example.com/public/v2"
    assert cfg.drata.allow_alternate_host is True


def test_default_drata_host_loads_without_override_flag(tmp_path: Path) -> None:
    cfg = load_config(_sample_config_with_real_drata_ids(tmp_path), env={"DRATA_API_TOKEN": "unused"})
    assert cfg.drata.allow_alternate_host is False
