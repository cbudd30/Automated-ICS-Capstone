"""Report models.

Three families live here:

1. ``AgentAssessment`` - the structured output the LLM must return: its own
   findings, each backed by evidence it read with MCP tools. It is kept
   deliberately simple (only required fields, no dicts, no defaults) because
   strict JSON-schema mode at OpenAI, and many local models, cope badly with
   optional/complex schemas.

2. ``Report`` - the deterministic report (``deterministic_report.json`` /
   ``.md``): inventory, rule findings, scanner results and run metrics. It is
   produced without any AI and is independent of the agent report.

3. ``AgentReport`` - the agent report (``agent_report.json`` / ``.md``): only
   what the agent found, as it reported it (not checked against the data).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from docker_security_agent.schemas.findings import Finding

# ---------------------------------------------------------------------------
# 1. What the LLM returns
# ---------------------------------------------------------------------------


class AgentEvidence(BaseModel):
    """One fact the agent read from a tool result."""

    tool: str = Field(description="Tool whose output showed this, e.g. container_inspect")
    field: str = Field(
        description="Field path in that output, e.g. HostConfig.Privileged or Mounts.Source"
    )
    value: str = Field(description="The value you observed, copied from the tool output")


class AgentFinding(BaseModel):
    """One security issue the agent found by itself."""

    title: str
    resource_name: str = Field(description="Exact name of the affected container, image or network")
    severity: Literal["critical", "high", "medium", "low", "info"]
    evidence: list[AgentEvidence]
    vulnerability_ids: list[str] = Field(
        description="CVE/GHSA IDs copied from Trivy findings for this resource; [] otherwise"
    )
    explanation: str = Field(description="Why this matters in an OT/ICS context")


class ContainerSection(BaseModel):
    """One container's part of the assessment, written by the agent as it goes (h2).

    Same finding schema as the final assessment: structured findings with
    tool/field/value evidence, not a free-text summary. The harness merges the
    sections' findings into ``AgentAssessment.findings`` before the report is built.
    """

    resource_name: str = Field(description="Exact name of the container this section covers")
    findings: list[AgentFinding] = Field(description="Every issue found on this container")
    evidence_refs: list[str] = Field(
        description="References (E1, E2...) of the tool results this section is based on"
    )
    notes: list[str] = Field(description="What you could not verify for this container; [] if none")


class AgentAssessment(BaseModel):
    """Structured output of DockerSecurityAssessmentAgent."""

    executive_summary: str
    overall_risk: Literal["critical", "high", "medium", "low"]
    findings: list[AgentFinding] = Field(description="Most urgent first")
    limitations: list[str]


# ---------------------------------------------------------------------------
# 2. The final report
# ---------------------------------------------------------------------------


class ModelInfo(BaseModel):
    profile: str
    provider: str
    model: str
    settings: dict[str, Any] = Field(default_factory=dict)


class MCPServerInfo(BaseModel):
    name: str
    role: str
    command: str
    version: str = ""
    approved_tools: list[str] = Field(default_factory=list)
    connected: bool = False
    error: str | None = None


class DockerEndpointInfo(BaseModel):
    """Which Docker API endpoint a live run used (the tools had full access to it)."""

    docker_host: str
    docker_version: str = ""


class ContainerRow(BaseModel):
    name: str
    image: str
    state: str
    user: str
    privileged: bool
    networks: list[str]
    published_ports: list[str]
    finding_count: int = 0


class ImageRow(BaseModel):
    name: str
    id: str
    digest: str | None
    created: str
    size_mb: float
    used_by: list[str]
    vuln_counts: dict[str, int] = Field(default_factory=dict)
    scan_status: str = "not scanned"


class NetworkRow(BaseModel):
    name: str
    driver: str
    internal: bool
    subnets: list[str]
    containers: list[str]


class ImageVulnerabilitySummary(BaseModel):
    image: str
    image_id: str
    digest: str | None
    scanner_version: str
    counts: dict[str, int]
    top_vulnerabilities: list[dict[str, Any]]  # highest-severity first, capped


class PrioritizedEntry(BaseModel):
    rank: int
    finding_id: str
    title: str
    resource_name: str
    severity: str


class RunMetrics(BaseModel):
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    collection_seconds: float = 0.0
    scan_seconds: float = 0.0
    agent_seconds: float = 0.0
    tool_calls_total: int = 0
    tool_calls_agent: int = 0
    tool_calls_blocked: int = 0
    tool_calls_by_name: dict[str, int] = Field(default_factory=dict)
    model_requests: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


class ReportSummary(BaseModel):
    overall_risk: str  # highest severity found by the rules and scanner
    executive_summary: str
    containers_total: int
    containers_running: int
    images_total: int
    networks_total: int
    volumes_total: int
    findings_by_severity: dict[str, int]
    vulnerable_images: int
    total_vulnerabilities: dict[str, int]


class Report(BaseModel):
    """Contents of deterministic_report.json (the .md is rendered from this)."""

    report_version: str = "2.0"
    run_id: str
    status: str
    objective: str
    generated_at: datetime
    model: ModelInfo | None
    prompt_version: str
    mcp_servers: list[MCPServerInfo]
    docker_endpoint: DockerEndpointInfo | None = None  # None when Docker was not contacted
    manifest_sha256: str | None = None  # outputs/<run_id>/manifest.json (see manifest.py)
    config_sha256: str | None = None  # same value = same experimental configuration
    snapshot_id: str
    snapshot_captured_at: datetime
    docker_version: str
    docker_platform: str
    summary: ReportSummary
    containers: list[ContainerRow]
    images: list[ImageRow]
    networks: list[NetworkRow]
    findings: list[Finding]  # confirmed (rule + scanner), sorted
    vulnerabilities: list[ImageVulnerabilitySummary]
    prioritized: list[PrioritizedEntry]
    recommendations: list[str]
    limitations: list[str]
    errors: list[str]
    metrics: RunMetrics


class AgentReport(BaseModel):
    """Contents of agent_report.json: only what the agent found by itself."""

    report_version: str = "2.0"
    run_id: str
    generated_at: datetime
    model: ModelInfo
    prompt_version: str
    agent_status: str  # ok / error / timeout / max_turns / invalid_output
    snapshot_id: str
    executive_summary: str
    overall_risk: str | None  # None when the agent produced no valid assessment
    findings: list[Finding]  # the agent's claims (status potential), in the agent's order
    limitations: list[str]
    errors: list[str]
    metrics: RunMetrics
