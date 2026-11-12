"""The agent report: ``agent_report.json`` + ``agent_report.md``.

Only what the agent found by itself with MCP tools, exactly as it reported
it: the findings are the agent's claims and are not checked against the
collected data. Nothing from the deterministic rules is mixed in: if the
agent missed an issue, it is simply absent here. If the agent failed
(timeout, invalid output...), the report says so and has no findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from docker_security_agent.reporting.generator import (
    _finding_block,
    _md_escape,
    metrics_markdown,
    write_files,
)
from docker_security_agent.schemas.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingSource,
    FindingStatus,
    Severity,
)
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    AgentReport,
    MCPServerInfo,
    ModelInfo,
    RunMetrics,
)
from docker_security_agent.security.findings import finding_id, severity_counts

AGENT_REPORT = "agent_report"


def agent_findings(assessment: AgentAssessment) -> list[Finding]:
    """The agent's findings in the report's ``Finding`` format, in the agent's order.

    Every one is an unchecked claim: status ``potential``, confidence ``low``.
    Exact repeats (same resource and title) are dropped: they would get the same
    finding ID.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for f in assessment.findings:
        name = f.resource_name.strip().lstrip("/")
        fid = finding_id("AGENT", name, f.title)
        if fid in seen:
            continue
        seen.add(fid)
        findings.append(
            Finding(
                id=fid,
                rule_id="AGENT",
                title=f.title,
                resource_type="unknown",
                resource_name=name,
                category=Category.OTHER,
                severity=Severity(f.severity),
                confidence=Confidence.LOW,
                status=FindingStatus.POTENTIAL,
                source=FindingSource.AGENT,
                evidence=[
                    Evidence(source=f"agent:{e.tool}", resource=name, path=e.field, value=e.value)
                    for e in f.evidence
                ],
                explanation=f.explanation,
                remediation="",  # the agent documents issues; analysts decide fixes (v9)
                references=sorted({v.strip().upper() for v in f.vulnerability_ids if v.strip()}),
            )
        )
    return findings


def build_agent_report(
    *,
    run_id: str,
    model: ModelInfo,
    prompt_version: str,
    agent_status: str,
    snapshot_id: str,
    assessment: AgentAssessment | None,
    errors: list[str],
    metrics: RunMetrics,
) -> AgentReport:
    if assessment is None:
        return AgentReport(
            run_id=run_id,
            generated_at=datetime.now(UTC),
            model=model,
            prompt_version=prompt_version,
            agent_status=agent_status,
            snapshot_id=snapshot_id,
            executive_summary=(
                f"The agent produced no valid assessment (status: {agent_status}). "
                "See errors below."
            ),
            overall_risk=None,
            findings=[],
            limitations=[],
            errors=list(errors),
            metrics=metrics,
        )
    a = assessment
    return AgentReport(
        run_id=run_id,
        generated_at=datetime.now(UTC),
        model=model,
        prompt_version=prompt_version,
        agent_status=agent_status,
        snapshot_id=snapshot_id,
        executive_summary=a.executive_summary,
        overall_risk=a.overall_risk,
        findings=agent_findings(a),
        limitations=a.limitations,
        errors=list(errors),
        metrics=metrics,
    )


def render_agent_markdown(r: AgentReport, mcp_servers: list[MCPServerInfo]) -> str:
    md: list[str] = []
    md.append(f"# Agent Security Assessment — `{r.run_id}`\n")
    risk = r.overall_risk.upper() if r.overall_risk else "n/a"
    md.append(
        f"**Agent status:** {r.agent_status} · **Overall risk (agent):** {risk} · "
        f"**Generated:** {r.generated_at:%Y-%m-%d %H:%M UTC}\n"
    )
    md.append(
        f"**Model:** `{r.model.profile}` ({r.model.provider} / `{r.model.model}`) · "
        f"**Prompt:** {r.prompt_version} · **Snapshot:** `{r.snapshot_id}`\n"
    )
    md.append(
        "> What the agent found by itself with read-only MCP tools. It did not see the "
        "deterministic findings. The findings are the agent's own claims and were not "
        "checked against the collected data: review them by hand.\n"
    )

    md.append("## 1. Summary\n")
    md.append(f"{r.executive_summary}\n")
    sev = severity_counts(r.findings)
    md.append(
        f"Findings: {len(r.findings)} ("
        + ", ".join(f"{s.value} {sev[s.value]}" for s in Severity if sev[s.value])
        + ")\n"
    )

    md.append("\n## 2. Findings\n")
    if r.findings:
        for f in r.findings:
            md.append(_finding_block(f))
    else:
        md.append("_None._\n")

    md.append("\n## 3. Limitations (stated by the agent)\n")
    md.append(
        "\n".join(f"- {lim}" for lim in r.limitations) + "\n" if r.limitations else "_None._\n"
    )
    if r.errors:
        md.append("\n**Errors / notes during the run:**\n")
        md.append("\n".join(f"- {_md_escape(n)}" for n in r.errors) + "\n")

    md.append("\n## 4. Execution metrics\n")
    md.append(metrics_markdown(r.metrics, mcp_servers))
    return "\n".join(md)


def write_agent_report(
    report: AgentReport, mcp_servers: list[MCPServerInfo], output_dir: Path
) -> Path:
    """Write the agent report (.json + .md); return the .md path."""
    return write_files(
        output_dir,
        report.run_id,
        AGENT_REPORT,
        report.model_dump_json(indent=2),
        render_agent_markdown(report, mcp_servers),
    )
