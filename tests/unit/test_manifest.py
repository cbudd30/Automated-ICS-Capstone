"""Run manifests: hashing, write-once file, tamper detection."""

import json

import pytest

from docker_security_agent.config import ConfigError
from docker_security_agent.manifest import (
    build_manifest,
    manifest_document,
    parse_manifest_document,
    write_manifest,
)
from docker_security_agent.schemas.reports import DockerEndpointInfo


def _manifest(settings, run_id="run-1", **overrides):
    args = dict(
        settings=settings,
        run_id=run_id,
        mode="deterministic",
        objective="obj",
        profile=None,
        named_session=False,
        snapshot_id="snap-1",
        scan_ids=[3, 1, 2],
        docker_endpoint=None,
    )
    args.update(overrides)
    return build_manifest(**args)


def test_config_hash_covers_experiment_not_run_identity_or_acquisition(settings):
    endpoint = DockerEndpointInfo(docker_host="unix:///var/run/docker.sock")
    a = _manifest(settings)
    b = _manifest(settings, run_id="run-2", mode="live", docker_endpoint=endpoint)
    assert a.experiment.evidence.scan_ids == [1, 2, 3]
    assert a.config_sha256() == b.config_sha256()
    assert a.manifest_sha256() != b.manifest_sha256()

    settings.agent.limits.max_turns += 1  # irrelevant without a model
    assert _manifest(settings).config_sha256() == a.config_sha256()
    settings.rules.disabled_rules = ["C001"]
    assert _manifest(settings).config_sha256() != a.config_sha256()
    profile = settings.get_profile(None)
    with_model = _manifest(settings, profile=profile)
    assert with_model.experiment.sampling["assessment_agent"].temperature == profile.temperature
    assert "api_key" not in json.dumps(manifest_document(with_model)).replace("api_key_env", "")


def test_manifest_file_is_write_once_and_tamper_evident(settings, tmp_path):
    m = _manifest(settings)
    path = write_manifest(m, tmp_path)
    with pytest.raises(FileExistsError):
        write_manifest(m, tmp_path)
    assert parse_manifest_document(path.read_text()) == m

    doc = json.loads(path.read_text())
    doc["manifest"]["experiment"]["evidence"]["scan_ids"] = [1]
    with pytest.raises(ConfigError, match="modified after the run"):
        parse_manifest_document(json.dumps(doc))
    with pytest.raises(ConfigError, match="not a valid run manifest"):
        parse_manifest_document("{}")


def test_framework_info_falls_back_to_image_build_provenance(tmp_path, monkeypatch):
    # tmp_path is not a git checkout, like /app inside the container image.
    from docker_security_agent.manifest import framework_info

    monkeypatch.delenv("DOCKER_AUDIT_BUILD_COMMIT", raising=False)
    assert framework_info(tmp_path).commit == "unknown"

    monkeypatch.setenv("DOCKER_AUDIT_BUILD_COMMIT", "abc123")
    monkeypatch.setenv("DOCKER_AUDIT_BUILD_DIRTY", "true")
    info = framework_info(tmp_path)
    assert (info.commit, info.dirty) == ("abc123", True)

    monkeypatch.setenv("DOCKER_AUDIT_BUILD_DIRTY", "false")
    assert framework_info(tmp_path).dirty is False
