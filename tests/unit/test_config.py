"""Configuration loading and validation."""

from pathlib import Path

import pytest

from docker_security_agent.config import ConfigError, expand_env, load_settings


def test_real_config_loads():
    s = load_settings()
    assert s.experiment.default_model in s.models
    assert {"docker", "trivy"} <= set(s.mcp.servers)
    # The approved Docker tools must never include anything that executes or mutates.
    forbidden = {
        "container_exec",
        "container_archive_get",
        "secret_inspect",
        "container_logs",
        "swarm_join_tokens",
        "swarm_unlock_key",
        "run_container",
        "container_create",
    }
    assert not forbidden & set(s.mcp.servers["docker"].allowed_tools)
    assert "scan_filesystem" not in s.mcp.servers["trivy"].allowed_tools
    assert s.mcp.docker_host.startswith("unix://")  # h4: the Docker socket, no proxy


def test_profile_names_filled_from_keys():
    s = load_settings()
    for name, profile in s.models.items():
        assert profile.name == name


def test_expand_env_with_default(monkeypatch):
    monkeypatch.setenv("SOME_URL", "http://x:1/v1")
    monkeypatch.delenv("MISSING_VAR", raising=False)
    data = {"a": "${SOME_URL}", "b": ["${MISSING_VAR:-fallback}"], "c": 3}
    assert expand_env(data) == {"a": "http://x:1/v1", "b": ["fallback"], "c": 3}


def test_unknown_profile_raises():
    s = load_settings()
    with pytest.raises(ConfigError, match="Unknown model profile"):
        s.get_profile("does-not-exist")


def test_invalid_config_is_reported(tmp_path: Path):
    real = load_settings().config_dir
    for f in real.glob("*.yaml"):
        (tmp_path / f.name).write_text(f.read_text())
    (tmp_path / "models.yaml").write_text(
        "profiles:\n  broken:\n    provider: nope\n    model: x\n"
    )
    with pytest.raises(ConfigError, match="Invalid configuration"):
        load_settings(tmp_path)


def test_missing_file_is_reported(tmp_path: Path):
    with pytest.raises(ConfigError, match="Missing configuration file"):
        load_settings(tmp_path)


def test_api_key_comes_from_env_only(monkeypatch):
    s = load_settings()
    profile = s.models["openai-primary"]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert profile.api_key() is None
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    assert profile.api_key() == "sk-test-not-real"
    assert "sk-test" not in str(profile.public_dict())
