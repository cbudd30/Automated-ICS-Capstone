"""Run manifests: the immutable record of how one assessment run was configured.

A manifest is frozen once the run's evidence is known (snapshot + scans) and
before the agent starts. It is written to ``outputs/<run_id>/manifest.json``
(created once, then made read-only) and stored in the ``runs`` row together
with two hashes:

* ``manifest_sha256`` - the whole manifest. Identifies this exact run record.
* ``config_sha256``   - only the ``experiment`` block: what the run was asked
  to do (scenario, objective, pinned evidence, prompt bundle, schemas, per-role
  models + sampling, limits, rules, logging). Two runs with the same
  ``config_sha256`` had the same experimental configuration; re-running from a
  manifest reproduces it.

Everything outside ``experiment`` describes the run instance (ID, time, code
commit) or how the evidence was acquired (live MCP servers, Docker endpoint,
scan settings). Acquisition does not belong in the config hash because the
deterministic evidence is pinned by ``snapshot_id`` + ``scan_ids``.

Re-running a manifest: a deterministic run is replayed on its pinned evidence
(no Docker access). An agent run investigates live Docker with MCP tools, so
it cannot be replayed; it is re-run live with the same configuration, and must
start from the same range baseline when the original did.

The JSON file is self-verifying: ``{"manifest": {...}, "manifest_sha256": ...}``.

Reference: experiment framework section 29 (immutable experiment configuration)
and coding guide section 25 (run manifest).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from docker_security_agent import PROMPT_VERSION, __version__
from docker_security_agent.config import ConfigError, ModelProfile, Settings
from docker_security_agent.memory.database import SCHEMA_VERSION
from docker_security_agent.schemas.reports import AgentAssessment, DockerEndpointInfo, Report

MANIFEST_VERSION = "2"  # 2: agent runs are MCP-only; no findings_in_prompt
MANIFEST_FILENAME = "manifest.json"

# The single agent role of this tool. The reference framework has several
# (actor, critic, ...); models/sampling are keyed by role so more can be added.
ASSESSOR_ROLE = "assessment_agent"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Manifest model
# ---------------------------------------------------------------------------


class FrameworkInfo(_Frozen):
    package_version: str
    commit: str  # git HEAD, or "unknown" outside a git checkout
    dirty: bool  # uncommitted changes to tracked files at run time


class Evidence(_Frozen):
    snapshot_id: str
    scan_ids: list[int]


class RangeRef(_Frozen):
    """The named range baseline a run started from (see inventory/baseline.py)."""

    name: str
    fingerprint_sha256: str
    baseline_snapshot_id: str


class RangeCheck(_Frozen):
    """How the start state was verified for a live run."""

    verified_at: datetime  # inventory matched the baseline at this time
    last_reset_at: datetime | None  # start of the most recent verified reset
    last_reset_matched: bool | None


class PromptBundle(_Frozen):
    version: str  # PROMPT_VERSION
    instructions_sha256: str  # the exact agent instructions text


class SchemaVersions(_Frozen):
    report_version: str
    db_schema_version: int
    assessment_schema_sha256: str  # JSON schema the LLM output must satisfy


class Sampling(_Frozen):
    temperature: float | None
    max_tokens: int | None


class AgentSettings(_Frozen):
    max_turns: int
    max_tool_calls: int
    max_duration_seconds: float
    max_tool_result_chars: int
    named_session: bool  # True = --session was used; earlier conversation may be in context


class LoggingFlags(_Frozen):
    record_tool_calls: bool
    record_findings: bool
    record_conversation: bool  # SDK session DB holds prompts + responses
    tracing_enabled: bool  # SDK trace upload to OpenAI


class ExperimentBlock(_Frozen):
    """Everything covered by ``config_sha256``."""

    scenario_id: str
    objective: str
    range_baseline: RangeRef | None  # None = not checked against a named baseline
    evidence: Evidence
    prompt_bundle: PromptBundle
    schema_versions: SchemaVersions
    models: dict[str, dict[str, Any]]  # role -> model profile (no secrets); {} = no LLM
    sampling: dict[str, Sampling]  # role -> sampling parameters
    agent: AgentSettings | None  # None = deterministic run
    rules: dict[str, Any]
    logging: LoggingFlags


class MCPServerRecord(_Frozen):
    name: str
    role: str
    command: str
    args: list[str]
    env_names: list[str]  # names only: values are machine-specific
    allowed_tools: list[str]


class Acquisition(_Frozen):
    mode: Literal["live", "replay", "deterministic"]
    docker_endpoint: DockerEndpointInfo | None  # None when Docker was not contacted
    range_check: RangeCheck | None  # live runs with --range-baseline only
    mcp_servers: list[MCPServerRecord]
    argument_policy: dict[str, Any]
    redaction: dict[str, Any]
    scan: dict[str, Any]


class ReplayOf(_Frozen):
    run_id: str
    manifest_sha256: str


class RunManifest(_Frozen):
    manifest_version: str = MANIFEST_VERSION
    run_id: str
    created_at: datetime
    replay_of: ReplayOf | None = None
    framework: FrameworkInfo
    experiment: ExperimentBlock
    acquisition: Acquisition

    def manifest_sha256(self) -> str:
        return _sha256(self.model_dump(mode="json"))

    def config_sha256(self) -> str:
        return _sha256(self.experiment.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256(data: Any) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def framework_info(project_root: Path) -> FrameworkInfo:
    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(
                ["git", *args],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip()

    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=no")
    if commit is None and os.environ.get("DOCKER_AUDIT_BUILD_COMMIT"):
        # Container image (no .git inside): use what the image build recorded
        # (Dockerfile build args, filled in by deploy/agent/build.sh).
        commit = os.environ["DOCKER_AUDIT_BUILD_COMMIT"]
        status = "dirty" if os.environ.get("DOCKER_AUDIT_BUILD_DIRTY") == "true" else ""
    return FrameworkInfo(
        package_version=__version__,
        commit=commit or "unknown",
        dirty=bool(status) if status is not None else False,
    )


def prompt_bundle() -> PromptBundle:
    # Imported here: the agent module pulls in the Agents SDK.
    from docker_security_agent.agents.security_assessment import INSTRUCTIONS

    return PromptBundle(version=PROMPT_VERSION, instructions_sha256=_text_sha256(INSTRUCTIONS))


def schema_versions() -> SchemaVersions:
    return SchemaVersions(
        report_version=Report.model_fields["report_version"].default,
        db_schema_version=SCHEMA_VERSION,
        assessment_schema_sha256=_sha256(AgentAssessment.model_json_schema()),
    )


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def build_manifest(
    *,
    settings: Settings,
    run_id: str,
    mode: Literal["live", "replay", "deterministic"],
    objective: str,
    profile: ModelProfile | None,
    named_session: bool,
    snapshot_id: str,
    scan_ids: list[int],
    docker_endpoint: DockerEndpointInfo | None,
    replay_of: ReplayOf | None = None,
    range_baseline: RangeRef | None = None,
    range_check: RangeCheck | None = None,
) -> RunManifest:
    agent = settings.agent
    models: dict[str, dict[str, Any]] = {}
    sampling: dict[str, Sampling] = {}
    agent_settings = None
    if profile is not None:
        models[ASSESSOR_ROLE] = profile.public_dict()
        sampling[ASSESSOR_ROLE] = Sampling(
            temperature=profile.temperature, max_tokens=profile.max_tokens
        )
        agent_settings = AgentSettings(**agent.limits.model_dump(), named_session=named_session)
    live = docker_endpoint is not None
    return RunManifest(
        run_id=run_id,
        created_at=datetime.now(UTC),
        replay_of=replay_of,
        framework=framework_info(settings.project_root),
        experiment=ExperimentBlock(
            scenario_id=settings.experiment.scenario_id,
            objective=objective,
            range_baseline=range_baseline,
            evidence=Evidence(snapshot_id=snapshot_id, scan_ids=sorted(scan_ids)),
            prompt_bundle=prompt_bundle(),
            schema_versions=schema_versions(),
            models=models,
            sampling=sampling,
            agent=agent_settings,
            rules=settings.rules.model_dump(mode="json"),
            logging=LoggingFlags(
                record_tool_calls=True,
                record_findings=True,
                record_conversation=profile is not None,
                tracing_enabled=agent.tracing_enabled if profile is not None else False,
            ),
        ),
        acquisition=Acquisition(
            mode=mode,
            docker_endpoint=docker_endpoint,
            range_check=range_check,
            mcp_servers=[
                MCPServerRecord(
                    name=s.name,
                    role=s.role,
                    command=s.command,
                    args=s.args,
                    env_names=sorted(s.env),
                    allowed_tools=s.allowed_tools,
                )
                for s in settings.mcp.enabled_servers()
            ]
            if live
            else [],
            argument_policy=settings.mcp.argument_policy.model_dump(mode="json") if live else {},
            redaction=settings.mcp.redaction.model_dump(mode="json") if live else {},
            scan=settings.experiment.scan.model_dump(mode="json") if live else {},
        ),
    )


# ---------------------------------------------------------------------------
# Writing / reading
# ---------------------------------------------------------------------------


def manifest_document(manifest: RunManifest) -> dict[str, Any]:
    return {
        "manifest": manifest.model_dump(mode="json"),
        "manifest_sha256": manifest.manifest_sha256(),
        "config_sha256": manifest.config_sha256(),
    }


def write_manifest(manifest: RunManifest, output_dir: Path) -> Path:
    """Create ``<output_dir>/<run_id>/manifest.json`` once and make it read-only."""
    run_dir = output_dir / manifest.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / MANIFEST_FILENAME
    with path.open("x") as fh:  # never overwrite an existing manifest
        json.dump(manifest_document(manifest), fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(path, 0o444)
    return path


def parse_manifest_document(text: str, source: str = "manifest") -> RunManifest:
    """Parse and verify a manifest document. Raises ConfigError if it was altered."""
    try:
        doc = json.loads(text)
        manifest = RunManifest.model_validate(doc["manifest"])
        recorded = doc["manifest_sha256"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError(f"{source} is not a valid run manifest: {exc}") from exc
    if manifest.manifest_version != MANIFEST_VERSION:
        raise ConfigError(
            f"{source} has manifest_version {manifest.manifest_version}; "
            f"this version of the tool reads {MANIFEST_VERSION}"
        )
    actual = manifest.manifest_sha256()
    if actual != recorded:
        raise ConfigError(
            f"{source} does not match its recorded hash (recorded {recorded[:12]}, "
            f"actual {actual[:12]}): the manifest was modified after the run."
        )
    return manifest


# ---------------------------------------------------------------------------
# Re-running
# ---------------------------------------------------------------------------


def drift(manifest: RunManifest, project_root: Path) -> tuple[list[str], list[str]]:
    """Differences between the manifest and the code running now.

    Returns (blocking, informational). Blocking drift means the same config
    cannot be reproduced: the prompt or an output schema changed.
    """
    exp = manifest.experiment
    blocking = []
    if exp.prompt_bundle != prompt_bundle():
        blocking.append(
            f"prompt bundle changed ({exp.prompt_bundle.version} -> {PROMPT_VERSION}, "
            "or the instructions text differs)"
        )
    if exp.schema_versions != schema_versions():
        blocking.append("report / database / agent-output schema changed")
    info = []
    now = framework_info(project_root)
    if now.commit != manifest.framework.commit:
        info.append(
            f"framework commit differs: manifest {manifest.framework.commit[:12]}, "
            f"now {now.commit[:12]}"
        )
    if manifest.framework.dirty:
        info.append("the original run used uncommitted code changes")
    return blocking, info


def apply_manifest(settings: Settings, manifest: RunManifest) -> tuple[Settings, str | None]:
    """Settings reconfigured to match the manifest's experiment block.

    Returns (settings, model profile name or None for a deterministic re-run).
    """
    exp = manifest.experiment
    settings = settings.model_copy(deep=True)
    settings.experiment.scenario_id = exp.scenario_id
    settings.experiment.objective = exp.objective
    settings.rules = type(settings.rules).model_validate(exp.rules)
    settings.agent.tracing_enabled = exp.logging.tracing_enabled
    if exp.agent is not None:
        a = exp.agent
        settings.agent.limits = type(settings.agent.limits)(
            max_turns=a.max_turns,
            max_tool_calls=a.max_tool_calls,
            max_duration_seconds=a.max_duration_seconds,
            max_tool_result_chars=a.max_tool_result_chars,
        )
    profile_name = None
    if ASSESSOR_ROLE in exp.models:
        profile = ModelProfile.model_validate(exp.models[ASSESSOR_ROLE])
        # Same name as the original; replaces any local profile of that name.
        settings.models[profile.name] = profile
        profile_name = profile.name
    return settings, profile_name
