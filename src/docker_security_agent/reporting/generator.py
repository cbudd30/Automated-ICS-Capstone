"""Build the deterministic ``Report`` and write ``deterministic_report.json`` + ``.md``.

Every run writes this report. It contains no LLM output at all: it is what the
rules and the scanner found, and it is the answer key the agent's own report
is compared against (see agent_report.py and comparison_report.py).

``build_report`` merges three sources into one validated ``Report`` object:

1. the inventory snapshot      -> container / image / network tables
2. confirmed findings          -> rule + scanner findings (facts), ordered by
                                  severity (running resources and configuration
                                  issues first within a severity)
3. run metadata                -> MCP servers, metrics, errors

``render_markdown`` turns the Report into a human-readable document. The
JSON file is the source of truth; the Markdown is derived from it. The table
and finding helpers here are shared by the other two reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.findings import Finding, Severity
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import (
    ContainerRow,
    DockerEndpointInfo,
    ImageRow,
    ImageVulnerabilitySummary,
    MCPServerInfo,
    ModelInfo,
    NetworkRow,
    PrioritizedEntry,
    Report,
    ReportSummary,
    RunMetrics,
)
from docker_security_agent.security.findings import severity_counts
from docker_security_agent.security.vulnerability_parser import SEVERITY_ORDER, sort_vulns

# Always-true limitations of this tool.
STANDARD_LIMITATIONS = [
    "Metadata-only assessment: no runtime behaviour, network traffic or in-container files "
    "were inspected, and no active scanning was performed.",
    "Image vulnerabilities come from Trivy's database at scan time; exploitability depends on "
    "whether the vulnerable code is reachable, which was not tested.",
    "Secret values were redacted before analysis; credential findings are based on variable "
    "names and patterns only.",
    "Findings reflect the Docker state at the snapshot time only; historical runs are not "
    "evidence of current state.",
]


def _deterministic_risk(findings: list[Finding]) -> str:
    """Overall risk without the LLM: the highest severity present (info -> low)."""
    top = Severity.max([f.severity for f in findings])
    return top.value if top != Severity.INFO else "low"


def build_report(
    *,
    run_id: str,
    status: str,
    objective: str,
    model: ModelInfo | None,
    prompt_version: str,
    mcp_servers: list[MCPServerInfo],
    snapshot: InventorySnapshot,
    docker_endpoint: DockerEndpointInfo | None = None,
    manifest_sha256: str | None = None,
    config_sha256: str | None = None,
    findings: list[Finding],
    scans: list[ImageScanResult],
    errors: list[str],
    metrics: RunMetrics,
) -> Report:
    findings = sorted(findings, key=lambda f: f.sort_key())
    by_resource: dict[str, int] = {}
    for f in findings:
        by_resource[f.resource_name] = by_resource.get(f.resource_name, 0) + 1
    scans_by_image = {s.image_id: s for s in scans}

    # ---- inventory tables
    containers = [
        ContainerRow(
            name=c.name,
            image=c.image_ref,
            state=c.state,
            user=c.user or "(default: root)",
            privileged=c.privileged,
            networks=c.networks,
            published_ports=[
                f"{p.host_ip or '0.0.0.0'}:{p.host_port}->{p.container_port}/{p.protocol}"
                for p in c.ports
            ],
            finding_count=by_resource.get(c.name, 0),
        )
        for c in snapshot.containers
    ]
    used_ids = set(snapshot.used_image_ids())
    images = []
    for img in snapshot.images:
        if img.id not in used_ids and img.id not in scans_by_image:
            continue  # keep the report focused on images that matter
        scan = scans_by_image.get(img.id)
        images.append(
            ImageRow(
                name=img.display_name,
                id=img.id.removeprefix("sha256:")[:12],
                digest=img.digest,
                created=img.created[:19],
                size_mb=round(img.size / 1e6, 1),
                used_by=sorted(c.name for c in snapshot.containers if c.image_id == img.id),
                vuln_counts=scan.counts if scan else {},
                scan_status=(scan.status if scan else "not scanned"),
            )
        )
    networks = [
        NetworkRow(
            name=n.name,
            driver=n.driver,
            internal=n.internal,
            subnets=n.subnets,
            containers=n.containers,
        )
        for n in snapshot.networks
    ]

    # ---- vulnerabilities
    vuln_summaries = []
    totals = {s: 0 for s in SEVERITY_ORDER}
    for scan in scans:
        if scan.status != "ok":
            continue
        img = snapshot.image_by_id(scan.image_id)
        for k, v in scan.counts.items():
            totals[k] = totals.get(k, 0) + v
        vuln_summaries.append(
            ImageVulnerabilitySummary(
                image=img.display_name if img else scan.image_ref,
                image_id=scan.image_id,
                digest=scan.digest,
                scanner_version=scan.scanner_version,
                counts=scan.counts,
                top_vulnerabilities=[
                    v.model_dump(exclude={"finding_key", "target"})
                    for v in sort_vulns(scan.vulnerabilities)[:10]
                ],
            )
        )

    # ---- prioritisation: severity first; within a severity, issues on
    # RUNNING containers before stopped ones (they are exploitable now).
    by_id = {f.id: f for f in findings}
    running = {c.name for c in snapshot.containers if c.running}
    image_users = {
        img.display_name: {c.name for c in snapshot.containers if c.image_id == img.id}
        for img in snapshot.images
    }

    def _priority_key(f: Finding) -> tuple:
        if f.resource_type == "container":
            stopped = f.resource_name not in running
        elif f.resource_type == "image":
            stopped = not (image_users.get(f.resource_name, set()) & running)
        else:
            stopped = False
        # Within a severity: live resources first, then configuration
        # findings (direct, certain impact) before CVE findings (impact
        # depends on reachability), then the usual confidence/name order.
        is_vuln = f.rule_id == "V001"
        return (-f.severity.rank, stopped, is_vuln, *f.sort_key()[1:])

    candidates = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]
    prioritized = [
        PrioritizedEntry(
            rank=i,
            finding_id=f.id,
            title=f.title,
            resource_name=f.resource_name,
            severity=f.severity.value,
        )
        for i, f in enumerate(sorted(candidates, key=_priority_key)[:15], start=1)
    ]

    # ---- summary
    sev = severity_counts(findings)
    summary_text = (
        f"Deterministic checks (rules and Trivy) produced {len(findings)} findings "
        f"({sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, "
        f"{sev['low']} low, {sev['info']} info). No AI was involved in this report."
    )
    # Recommendations = remediation of the top findings (deduplicated).
    recommendations = list(
        dict.fromkeys(p.title + ": " + by_id[p.finding_id].remediation for p in prioritized[:8])
    )
    limitations = list(STANDARD_LIMITATIONS)

    if snapshot.collection_errors:
        limitations.append(
            "Some inventory data could not be collected: " + "; ".join(snapshot.collection_errors)
        )
    empty_scans = [s.image_ref for s in scans if s.status == "ok" and s.total == 0]
    if empty_scans:
        limitations.append(
            "Trivy reported zero vulnerabilities for: " + ", ".join(empty_scans) + ". This can "
            "mean the image is clean OR that Trivy does not support the image's OS/package "
            "manager (e.g. Kali Linux); treat these as 'not assessed' until verified."
        )
    failed_scans = [s for s in scans if s.status != "ok"]
    if failed_scans:
        limitations.append(
            "Image scans failed for: " + ", ".join(s.image_ref for s in failed_scans)
        )

    summary = ReportSummary(
        overall_risk=_deterministic_risk(findings),
        executive_summary=summary_text,
        containers_total=len(snapshot.containers),
        containers_running=sum(c.running for c in snapshot.containers),
        images_total=len(snapshot.images),
        networks_total=len(snapshot.networks),
        volumes_total=len(snapshot.volumes),
        findings_by_severity=severity_counts(findings),
        vulnerable_images=sum(1 for s in scans if s.status == "ok" and s.total > 0),
        total_vulnerabilities=totals,
    )

    return Report(
        run_id=run_id,
        status=status,
        objective=objective,
        generated_at=datetime.now(UTC),
        model=model,
        prompt_version=prompt_version,
        mcp_servers=mcp_servers,
        docker_endpoint=docker_endpoint,
        manifest_sha256=manifest_sha256,
        config_sha256=config_sha256,
        snapshot_id=snapshot.snapshot_id,
        snapshot_captured_at=snapshot.captured_at,
        docker_version=snapshot.docker_version,
        docker_platform=snapshot.docker_platform,
        summary=summary,
        containers=containers,
        images=images,
        networks=networks,
        findings=findings,
        vulnerabilities=vuln_summaries,
        prioritized=prioritized,
        recommendations=recommendations,
        limitations=limitations,
        errors=list(errors),
        metrics=metrics,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _md_escape(text: str) -> str:
    """Keep table cells intact: pipes and newlines would break the table."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows]
    return "\n".join(out) + "\n"


def _finding_block(f: Finding) -> str:
    lines = [
        f"#### {_SEV_ICON.get(f.severity.value, '')} `{f.id}` — {f.title}",
        "",
        f"- **Resource:** {f.resource_type} `{f.resource_name}`",
        f"- **Category:** {f.category.value} · **Severity:** {f.severity.value} · "
        f"**Confidence:** {f.confidence.value} · **Status:** {f.status.value} "
        f"({f.source.value})",
        "- **Evidence:**",
    ]
    lines += [
        f"  - `{e.path}` = `{_md_escape(e.value)}`" + (f" — {e.note}" if e.note else "")
        for e in f.evidence
    ]
    lines += [
        "",
        f"**Why it matters:** {f.explanation}",
        "",
        f"**Remediation:** {f.remediation}",
        "",
    ]
    if f.validation_notes:
        lines += [f"**Validation:** {'; '.join(f.validation_notes)}", ""]
    if f.references:
        lines += ["**References:** " + ", ".join(f.references), ""]
    return "\n".join(lines)


def _endpoint_line(e: DockerEndpointInfo) -> str:
    proxy = (
        "read-only proxy verified" if e.proxy_verified else "**NOT verified as read-only proxy**"
    )
    return f"`{e.docker_host}` ({proxy}; require_proxy: {str(e.require_proxy).lower()})"


def render_markdown(r: Report) -> str:
    s = r.summary
    md: list[str] = []
    md.append(f"# Deterministic Security Assessment — `{r.run_id}`\n")
    md.append(
        f"**Status:** {r.status} · **Overall risk:** {s.overall_risk.upper()} "
        f"(highest severity found) · **Generated:** {r.generated_at:%Y-%m-%d %H:%M UTC}\n"
    )
    md.append(
        f"**Source:** rules + Trivy only, no AI · **Snapshot:** `{r.snapshot_id}`"
        + (
            f" · **Agent model in this run:** `{r.model.profile}` (see agent_report.md and "
            "comparison.md)"
            if r.model
            else ""
        )
        + "\n"
    )
    if r.manifest_sha256:
        md.append(
            f"**Manifest:** `manifest.json` · sha256 `{r.manifest_sha256}` · "
            f"config `{r.config_sha256}`\n"
        )
    if r.docker_endpoint and r.docker_endpoint.unenforced_warning:
        md.append(f"> [!CAUTION]\n> **{r.docker_endpoint.unenforced_warning}**\n")

    md.append("## 1. Assessment summary\n")
    md.append(f"{s.executive_summary}\n")
    md.append(f"**Objective:** {r.objective}\n")
    md.append(
        _table(
            ["Critical", "High", "Medium", "Low", "Info"],
            [
                [
                    str(s.findings_by_severity.get(k, 0))
                    for k in ("critical", "high", "medium", "low", "info")
                ]
            ],
        )
    )

    md.append("\n## 2. Docker environment overview\n")
    md.append(
        f"- Docker engine: {r.docker_version} ({r.docker_platform})\n"
        + (
            f"- Docker API endpoint: {_endpoint_line(r.docker_endpoint)}\n"
            if r.docker_endpoint
            else ""
        )
        + f"- Snapshot captured: {r.snapshot_captured_at:%Y-%m-%d %H:%M:%S UTC}\n"
        f"- Containers: {s.containers_total} ({s.containers_running} running) · Images: "
        f"{s.images_total} · Networks: {s.networks_total} · Volumes: {s.volumes_total}\n"
        f"- Images with known vulnerabilities: {s.vulnerable_images} · Total vulnerabilities: "
        + ", ".join(f"{k} {v}" for k, v in s.total_vulnerabilities.items() if v)
        + "\n"
    )

    md.append("\n## 3. Container inventory\n")
    md.append(
        _table(
            [
                "Container",
                "Image",
                "State",
                "User",
                "Privileged",
                "Networks",
                "Published ports",
                "Findings",
            ],
            [
                [
                    c.name,
                    c.image,
                    c.state,
                    c.user,
                    "yes" if c.privileged else "no",
                    ", ".join(c.networks),
                    ", ".join(c.published_ports) or "-",
                    str(c.finding_count),
                ]
                for c in r.containers
            ],
        )
    )

    md.append("\n## 4. Image inventory\n")
    md.append(
        _table(
            ["Image", "ID", "Digest", "Size (MB)", "Used by", "Scan", "Vulnerabilities"],
            [
                [
                    i.name,
                    i.id,
                    (i.digest or "-")[:40],
                    str(i.size_mb),
                    ", ".join(i.used_by) or "-",
                    i.scan_status,
                    ", ".join(f"{k[0]}:{v}" for k, v in i.vuln_counts.items() if v) or "-",
                ]
                for i in r.images
            ],
        )
    )

    md.append("\n## 5. Network configuration\n")
    md.append(
        _table(
            ["Network", "Driver", "Internal", "Subnets", "Containers"],
            [
                [
                    n.name,
                    n.driver,
                    "yes" if n.internal else "no",
                    ", ".join(n.subnets) or "-",
                    ", ".join(n.containers) or "-",
                ]
                for n in r.networks
            ],
        )
    )

    md.append("\n## 6. Prioritized findings\n")
    md.append(
        "Ordered by severity; within a severity, running resources and configuration issues "
        "first.\n"
    )
    md.append(
        _table(
            ["#", "Severity", "Finding", "Resource"],
            [
                [str(p.rank), p.severity, f"`{p.finding_id}` {p.title}", p.resource_name]
                for p in r.prioritized
            ],
        )
    )

    config_findings = [f for f in r.findings if f.rule_id != "V001"]
    md.append(f"\n## 7. Security misconfigurations ({len(config_findings)})\n")
    md.append(
        "Confirmed by deterministic rules. Each finding lists the exact Docker field "
        "that supports it.\n"
    )
    for f in config_findings:
        md.append(_finding_block(f))

    md.append("\n## 8. Known image vulnerabilities\n")
    md.append(
        "Reported by Trivy; CVE IDs, severities and versions are copied verbatim from "
        "the scanner.\n"
    )
    for v in r.vulnerabilities:
        md.append(f"### {v.image}\n")
        md.append(
            f"Digest: `{v.digest or 'n/a'}` · Scanner: Trivy {v.scanner_version} · "
            f"Counts: " + ", ".join(f"{k} {n}" for k, n in v.counts.items() if n) + "\n"
        )
        md.append(
            _table(
                ["ID", "Severity", "Package", "Installed", "Fixed"],
                [
                    [
                        t["vuln_id"],
                        t["severity"],
                        t["package"],
                        t["installed_version"],
                        t["fixed_version"] or "-",
                    ]
                    for t in v.top_vulnerabilities
                ],
            )
        )
    for f in [f for f in r.findings if f.rule_id == "V001"]:
        md.append(_finding_block(f))

    md.append("\n## 9. Remediation recommendations\n")
    md.append(
        "\n".join(f"{i}. {rec}" for i, rec in enumerate(r.recommendations, 1)) + "\n"
        if r.recommendations
        else "_None._\n"
    )

    md.append("\n## 10. Limitations and unknowns\n")
    md.append("\n".join(f"- {lim}" for lim in r.limitations) + "\n")
    if r.errors:
        md.append("\n**Errors / notes during the run:**\n")
        md.append("\n".join(f"- {_md_escape(e)}" for e in r.errors) + "\n")

    md.append("\n## 11. Execution metrics\n")
    md.append(metrics_markdown(r.metrics, r.mcp_servers))
    return "\n".join(md)


def metrics_markdown(m: RunMetrics, mcp_servers: list[MCPServerInfo]) -> str:
    """Metrics + MCP server tables (shared with the agent report)."""
    md: list[str] = []
    md.append(
        _table(
            ["Metric", "Value"],
            [
                [
                    "Duration (total / collect / scan / agent)",
                    f"{m.duration_seconds}s / {m.collection_seconds}s / {m.scan_seconds}s / "
                    f"{m.agent_seconds}s",
                ],
                [
                    "Tool calls (total / by agent / blocked)",
                    f"{m.tool_calls_total} / {m.tool_calls_agent} / {m.tool_calls_blocked}",
                ],
                ["Values redacted", str(m.redactions)],
                ["Model requests", str(m.model_requests)],
                [
                    "Tokens (in / out / total)",
                    f"{m.input_tokens if m.input_tokens is not None else 'n/a'} / "
                    f"{m.output_tokens if m.output_tokens is not None else 'n/a'} / "
                    f"{m.total_tokens if m.total_tokens is not None else 'n/a'}",
                ],
            ],
        )
    )
    md.append("\n**MCP servers:**\n")
    md.append(
        _table(
            ["Server", "Role", "Version", "Connected", "Approved tools"],
            [
                [
                    srv.name,
                    srv.role,
                    srv.version or "-",
                    "yes" if srv.connected else f"no ({srv.error or ''})",
                    ", ".join(srv.approved_tools),
                ]
                for srv in mcp_servers
            ],
        )
    )
    if m.tool_calls_by_name:
        md.append(
            "\n**Tool calls by name:** "
            + ", ".join(f"`{k}`×{v}" for k, v in sorted(m.tool_calls_by_name.items()))
            + "\n"
        )
    return "\n".join(md)


DETERMINISTIC_REPORT = "deterministic_report"


def write_files(output_dir: Path, run_id: str, stem: str, json_text: str, md: str) -> Path:
    """Write outputs/<run_id>/<stem>.json and <stem>.md; return the .md path."""
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{stem}.json").write_text(json_text)
    md_path = run_dir / f"{stem}.md"
    md_path.write_text(md)
    return md_path


def write_report(report: Report, output_dir: Path) -> Path:
    """Write the deterministic report (.json + .md); return the .md path."""
    return write_files(
        output_dir,
        report.run_id,
        DETERMINISTIC_REPORT,
        report.model_dump_json(indent=2),
        render_markdown(report),
    )
