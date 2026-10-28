"""Report models.

Four families live here:

1. ``AgentAssessment`` - the structured output the LLM must return: its own
   findings, each backed by evidence it read with MCP tools. It is kept
   deliberately simple (only required fields, no dicts, no defaults) because
   strict JSON-schema mode at OpenAI, and many local models, cope badly with
   optional/complex schemas.

2. ``Report`` - the deterministic report (``deterministic_report.json`` /
   ``.md``): inventory, rule findings, scanner results and run metrics. It is
   the answer key the agent is compared against.

3. ``AgentReport`` - the agent report (``agent_report.json`` / ``.md``): only
   what the agent found, after validation.

4. ``Comparison`` - agent vs deterministic (``comparison.json`` / ``.md``):
   which deterministic findings the agent found or missed, and what it
   reported beyond them.
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
    remediation: str


class AgentAssessment(BaseModel):
    """Structured output of DockerSecurityAssessmentAgent."""

    executive_summary: str
    overall_risk: Literal["critical", "high", "medium", "low"]
    findings: list[AgentFinding] = Field(description="Most urgent first")
    recommendations: list[str]
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
    """Which Docker API endpoint a live run used, and whether it was the read-only proxy."""

    docker_host: str
    require_proxy: bool  # config setting; False = the proxy requirement was disabled
    proxy_verified: bool  # the endpoint refused GET /secrets with 403 (read-only proxy)
    docker_version: str = ""

    @property
    def unenforced_warning(self) -> str | None:
        """Text for the run's security warning, or None when the proxy was enforced."""
        if self.require_proxy:
            return None
        detected = (
            "the read-only proxy was nevertheless detected"
            if self.proxy_verified
            else "the endpoint was NOT verified as the read-only proxy, so the MCP servers "
            "may have had full, unfiltered Docker API access"
        )
        return (
            f"SECURITY: require_proxy is disabled for this run. Docker endpoint "
            f"'{self.docker_host}': {detected}."
        )


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
    redactions: int = 0
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
    docker_endpoint: DockerEndpointInfo | None = None  # None in replay mode (no Docker access)
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
    findings: list[Finding]  # validated (status potential), in the agent's order
    rejected: list[Finding]  # failed validation (kept for transparency)
    out_of_scope: list[Finding]  # about excluded assessment infrastructure
    recommendations: list[str]
    limitations: list[str]
    validation_notes: list[str]
    errors: list[str]
    metrics: RunMetrics


# ---------------------------------------------------------------------------
# 4. Agent vs deterministic
# ---------------------------------------------------------------------------


class FindingRef(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    resource_name: str
    severity: str


class MatchedFinding(BaseModel):
    """A deterministic finding and the agent findings that cover it."""

    deterministic: FindingRef
    agent_finding_ids: list[str]
    agent_severity: str  # highest severity the agent gave it
    severity_agreement: Literal["same", "higher", "lower"]  # agent vs deterministic


class SeverityRecall(BaseModel):
    severity: str
    total: int
    found: int


class ComparisonScores(BaseModel):
    deterministic_total: int
    found: int
    missed: int
    recall: float  # found / total (0..1)
    weighted_recall: float  # weighted by severity rank: critical 4 ... low 1, info 0
    by_severity: list[SeverityRecall]
    agent_total: int  # agent findings, excluding out-of-scope ones
    agent_matched: int  # cover at least one deterministic finding
    agent_unmatched: int  # validated, but cover no deterministic finding
    agent_rejected: int  # failed validation
    match_rate: float  # agent_matched / agent_total (0..1)
    rejection_rate: float  # agent_rejected / agent_total (0..1)


class Comparison(BaseModel):
    """Contents of comparison.json."""

    report_version: str = "2.0"
    run_id: str
    generated_at: datetime
    model: ModelInfo
    agent_status: str
    snapshot_id: str
    scores: ComparisonScores
    found: list[MatchedFinding]  # deterministic findings the agent found
    missed: list[FindingRef]  # deterministic findings the agent did not find
    agent_unmatched: list[FindingRef]  # validated agent findings outside the rules
    agent_rejected: list[FindingRef]  # agent findings that failed validation
    agent_out_of_scope: list[FindingRef]  # agent findings on excluded infrastructure
    method: list[str]  # how matching works, for the reader
