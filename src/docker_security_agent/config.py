"""Configuration loading.

All behaviour is driven by five YAML files in ``config/`` plus environment
variables (optionally from a ``.env`` file):

    models.yaml          -> ``ModelProfile`` per profile name
    agent.yaml           -> ``AgentConfig``  (limits, session DB, tracing)
    mcp_servers.yaml     -> ``MCPConfig``    (servers, tool allow-lists, redaction)
    security_rules.yaml  -> ``RulesConfig``  (rule toggles, severities, lists)
    experiment.yaml      -> ``ExperimentConfig`` (objective, scan options, paths)

Every file is parsed into a Pydantic model, so a typo or a wrong type fails
immediately with a readable error (``docker-audit doctor`` surfaces these).

Strings may contain ``${VAR}`` or ``${VAR:-default}`` placeholders, which are
expanded from the environment. That keeps secrets and machine-specific URLs
out of the YAML files.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, field_validator

# ---------------------------------------------------------------------------
# Environment placeholder expansion
# ---------------------------------------------------------------------------

# Matches ${NAME} and ${NAME:-default}. NAME = letters, digits, underscore.
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: Any) -> Any:
    """Recursively replace ``${VAR:-default}`` placeholders in strings.

    Works on nested dicts/lists so it can be applied to a whole YAML document.
    A placeholder with no default and no matching env var becomes "".
    """
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


class ConfigError(Exception):
    """Raised when a configuration file is missing or invalid."""


# ---------------------------------------------------------------------------
# models.yaml
# ---------------------------------------------------------------------------

Provider = Literal["openai", "ollama", "vllm"]


class ModelProfile(BaseModel):
    """One named model configuration (see config/models.yaml for field docs)."""

    name: str = ""  # filled in from the YAML key by the loader
    provider: Provider
    model: str
    base_url: str | None = None
    api_key_env: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    timeout_seconds: float = 120.0
    max_retries: int = 2
    structured_output: Literal["native", "prompted"] = "native"
    # Ollama only: warn when the model's context window is smaller than this.
    min_context_tokens: int = 16384
    description: str = ""

    @field_validator("model")
    @classmethod
    def _model_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("model identifier must not be empty")
        return v

    def api_key(self) -> str | None:
        """Read the API key from the environment (never stored in config)."""
        return os.environ.get(self.api_key_env) if self.api_key_env else None

    def public_dict(self) -> dict[str, Any]:
        """Profile as a dict that is safe to store/report (no secrets)."""
        return self.model_dump(exclude={"description"})


# ---------------------------------------------------------------------------
# agent.yaml
# ---------------------------------------------------------------------------


class AgentLimits(BaseModel):
    max_turns: int = 30
    max_tool_calls: int = 40
    max_duration_seconds: float = 1200
    max_tool_result_chars: int = 12000


class SessionConfig(BaseModel):
    db_path: str = "data/agent_sessions.db"


class AgentConfig(BaseModel):
    name: str = "DockerSecurityAssessmentAgent"
    limits: AgentLimits = Field(default_factory=AgentLimits)
    session: SessionConfig = Field(default_factory=SessionConfig)
    tracing_enabled: bool = False
    # False: the first message only summarises the environment and the agent
    # must gather findings with tools. True: medium+ findings are listed inline.
    findings_in_prompt: bool = False


# ---------------------------------------------------------------------------
# mcp_servers.yaml
# ---------------------------------------------------------------------------


class ServerSetup(BaseModel):
    """Optional self-installation for an MCP server (used for the Trivy plugin)."""

    auto_install: bool = False
    check_command: list[str] = Field(default_factory=list)
    check_contains: str = ""
    install_command: list[str] = Field(default_factory=list)


class MCPServerConfig(BaseModel):
    """How to launch one MCP server and which of its tools are approved."""

    name: str = ""  # filled in from the YAML key
    enabled: bool = True
    role: Literal["docker_inspection", "image_scanner"]
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    client_session_timeout_seconds: float = 60
    allowed_tools: list[str]
    setup: ServerSetup | None = None


class ScanImagePolicy(BaseModel):
    restrict_targets_to_inventory: bool = True
    allowed_scan_types: list[str] = Field(default_factory=lambda: ["vuln"])
    forced_output_format: str = "json"


class ArgumentPolicy(BaseModel):
    scan_image: ScanImagePolicy = Field(default_factory=ScanImagePolicy)


class RedactionConfig(BaseModel):
    env_value_allowlist: list[str] = Field(default_factory=list)
    sensitive_key_patterns: list[str] = Field(default_factory=list)
    sensitive_key_exceptions: list[str] = Field(default_factory=list)


class MCPConfig(BaseModel):
    docker_host: str = "tcp://127.0.0.1:2375"
    require_proxy: bool = True
    servers: dict[str, MCPServerConfig]
    argument_policy: ArgumentPolicy = Field(default_factory=ArgumentPolicy)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)

    def enabled_servers(self) -> list[MCPServerConfig]:
        return [s for s in self.servers.values() if s.enabled]

    def server_for_role(self, role: str) -> MCPServerConfig | None:
        """First enabled server with the given role (docker_inspection / image_scanner)."""
        return next((s for s in self.enabled_servers() if s.role == role), None)


# ---------------------------------------------------------------------------
# security_rules.yaml
# ---------------------------------------------------------------------------

Severity = Literal["critical", "high", "medium", "low", "info"]


class RulesConfig(BaseModel):
    disabled_rules: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    include_stopped_containers: bool = True
    ignore_containers: list[str] = Field(default_factory=list)
    dangerous_capabilities: dict[str, Severity] = Field(default_factory=dict)
    docker_socket_paths: list[str] = Field(default_factory=list)
    sensitive_host_paths: list[str] = Field(default_factory=list)
    home_directory_roots: list[str] = Field(default_factory=list)
    sensitive_home_subpaths: list[str] = Field(default_factory=list)
    secret_env_name_patterns: list[str] = Field(default_factory=list)
    vulnerability_min_severity: Severity = "low"


# ---------------------------------------------------------------------------
# experiment.yaml
# ---------------------------------------------------------------------------


class ScanConfig(BaseModel):
    enabled: bool = True
    scope: Literal["used", "all"] = "used"
    max_images: int = 0
    severities: list[str] = Field(
        default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    )
    page_size: int = 500


class NetworkScanConfig(BaseModel):
    """Configuration for the nmap-based network scanner (NetworkAssessmentAgent)."""

    enabled: bool = True
    # ICS-safe timing template. T2=polite, T3=normal. Never T4/T5 on live ICS.
    timing: str = "T2"
    # Wall-clock timeout per subnet. Large /24s with slow ICS devices may need more.
    timeout_per_subnet_seconds: float = 300.0
    # Run ICS NSE discovery scripts (modbus-discover, s7-info, etc.) after port scan.
    run_ics_scripts: bool = True
    # Only scan subnets with a prefix >= this value (prevents accidentally scanning
    # huge corporate ranges; /24 = 256 hosts is the safe default).
    min_prefix_length: int = 24


class ExperimentConfig(BaseModel):
    # Names the environment/scenario being assessed; recorded in run manifests.
    scenario_id: str = "unspecified"
    objective: str
    default_model: str
    scan: ScanConfig = Field(default_factory=ScanConfig)
    network_scan: NetworkScanConfig = Field(default_factory=NetworkScanConfig)
    data_dir: str = "data"
    output_dir: str = "outputs"


# ---------------------------------------------------------------------------
# Aggregate settings
# ---------------------------------------------------------------------------


class Settings(BaseModel):
    """Everything the application needs, loaded once at startup."""

    project_root: Path
    config_dir: Path
    models: dict[str, ModelProfile]
    agent: AgentConfig
    mcp: MCPConfig
    rules: RulesConfig
    experiment: ExperimentConfig

    # ---- convenience path helpers (all relative paths are project-relative)

    def resolve(self, path: str | Path) -> Path:
        p = Path(path)
        return p if p.is_absolute() else self.project_root / p

    @property
    def data_dir(self) -> Path:
        return self.resolve(self.experiment.data_dir)

    @property
    def output_dir(self) -> Path:
        return self.resolve(self.experiment.output_dir)

    @property
    def assessment_db_path(self) -> Path:
        return self.data_dir / "assessments.db"

    @property
    def session_db_path(self) -> Path:
        return self.resolve(self.agent.session.db_path)

    def get_profile(self, name: str | None) -> ModelProfile:
        """Look up a model profile, falling back to experiment.default_model."""
        key = name or self.experiment.default_model
        if key not in self.models:
            known = ", ".join(sorted(self.models))
            raise ConfigError(f"Unknown model profile '{key}'. Known profiles: {known}")
        return self.models[key]


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Missing configuration file: {path}")
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return expand_env(data)


def find_project_root(start: Path | None = None) -> Path:
    """Walk upwards from ``start`` (default: cwd) to the dir holding pyproject.toml."""
    here = (start or Path.cwd()).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "pyproject.toml").exists() and (candidate / "config").is_dir():
            return candidate
    # Fall back to the source checkout this module lives in.
    return Path(__file__).resolve().parents[2]


def load_settings(config_dir: Path | str | None = None) -> Settings:
    """Load ``.env`` and all YAML files into a validated ``Settings`` object.

    ``config_dir`` defaults to ``$DOCKER_AUDIT_CONFIG_DIR`` or ``<project>/config``.
    Raises ``ConfigError`` with a human-readable message on any problem.
    """
    root = find_project_root()
    # .env values do NOT override variables already set in the real environment.
    load_dotenv(root / ".env", override=False)

    cfg_dir = Path(config_dir or os.environ.get("DOCKER_AUDIT_CONFIG_DIR") or root / "config")

    try:
        raw_models = _read_yaml(cfg_dir / "models.yaml").get("profiles", {})
        models = {name: ModelProfile(name=name, **body) for name, body in raw_models.items()}

        agent = AgentConfig(**_read_yaml(cfg_dir / "agent.yaml"))

        raw_mcp = _read_yaml(cfg_dir / "mcp_servers.yaml")
        raw_mcp["servers"] = {
            name: {"name": name, **body} for name, body in raw_mcp.get("servers", {}).items()
        }
        mcp = MCPConfig(**raw_mcp)

        rules = RulesConfig(**_read_yaml(cfg_dir / "security_rules.yaml"))
        experiment = ExperimentConfig(**_read_yaml(cfg_dir / "experiment.yaml"))
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration in {cfg_dir}:\n{exc}") from exc

    return Settings(
        project_root=root,
        config_dir=cfg_dir,
        models=models,
        agent=agent,
        mcp=mcp,
        rules=rules,
        experiment=experiment,
    )
