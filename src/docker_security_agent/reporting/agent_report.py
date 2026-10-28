"""The agent report: ``agent_report.json`` + ``agent_report.md``.

Only what the agent found by itself with MCP tools, after validation
(security/validation.py). Nothing from the deterministic rules is mixed in:
if the agent missed an issue, it is simply absent here, and comparison.md
lists it as missed. If the agent failed (timeout, invalid output...), the
report says so and has no findings.
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
from docker_security_agent.schemas.findings import Severity
from docker_security_agent.schemas.reports import AgentReport, MCPServerInfo, ModelInfo, RunMetrics
from docker_security_agent.security.findings import severity_counts
from docker_security_agent.security.validation import ValidationOutcome

AGENT_REPORT = "agent_report"


def build_agent_report(
    *,
    run_id: str,
    model: ModelInfo,
    prompt_version: str,
    agent_status: str,
    snapshot_id: str,
    validation: ValidationOutcome | None,
    errors: list[str],
    metrics: RunMetrics,
) -> AgentReport:
    if validation is None:
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
            rejected=[],
            out_of_scope=[],
            recommendations=[],
            limitations=[],
            validation_notes=[],
            errors=list(errors),
            metrics=metrics,
        )
    a = validation.assessment
    return AgentReport(
        run_id=run_id,
        generated_at=datetime.now(UTC),
        model=model,
        prompt_version=prompt_version,
        agent_status=agent_status,
        snapshot_id=snapshot_id,
        executive_summary=a.executive_summary,
        overall_risk=a.overall_risk,
        findings=validation.findings,
        rejected=validation.rejected,
        out_of_scope=validation.out_of_scope,
        recommendations=a.recommendations,
        limitations=a.limitations,
        validation_notes=validation.notes,
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
        "deterministic findings. Every finding below passed evidence validation and still "
        "needs human review. What it missed is in `comparison.md`.\n"
    )

    md.append("## 1. Summary\n")
    md.append(f"{r.executive_summary}\n")
    sev = severity_counts(r.findings)
    md.append(
        f"Findings: {len(r.findings)} ("
        + ", ".join(f"{s.value} {sev[s.value]}" for s in Severity if sev[s.value])
        + f") · rejected: {len(r.rejected)} · out of scope: {len(r.out_of_scope)}\n"
    )

    md.append("\n## 2. Findings\n")
    if r.findings:
        for f in r.findings:
            md.append(_finding_block(f))
    else:
        md.append("_None._\n")

    md.append("\n## 3. Rejected findings (failed evidence validation)\n")
    if r.rejected:
        for f in r.rejected:
            md.append(f"- **{f.title}** (`{f.resource_name}`): {'; '.join(f.validation_notes)}")
        md.append("")
    else:
        md.append("_None._\n")
    if r.out_of_scope:
        md.append("\n**Out of scope (assessment infrastructure, not counted):** ")
        md.append(", ".join(f"{f.title} (`{f.resource_name}`)" for f in r.out_of_scope) + "\n")

    md.append("\n## 4. Recommendations\n")
    md.append(
        "\n".join(f"{i}. {rec}" for i, rec in enumerate(r.recommendations, 1)) + "\n"
        if r.recommendations
        else "_None._\n"
    )

    md.append("\n## 5. Limitations (stated by the agent)\n")
    md.append(
        "\n".join(f"- {lim}" for lim in r.limitations) + "\n" if r.limitations else "_None._\n"
    )
    notes = [f"validation: {n}" for n in r.validation_notes] + r.errors
    if notes:
        md.append("\n**Errors / notes during the run:**\n")
        md.append("\n".join(f"- {_md_escape(n)}" for n in notes) + "\n")

    md.append("\n## 6. Execution metrics\n")
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
