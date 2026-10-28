"""SQLite persistence and report generation."""

import json
from datetime import UTC, datetime

import grfics
import pytest

from docker_security_agent.memory.database import SCHEMA_VERSION
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.reporting.agent_report import (
    build_agent_report,
    render_agent_markdown,
    write_agent_report,
)
from docker_security_agent.reporting.comparison_report import (
    render_comparison_markdown,
    write_comparison,
)
from docker_security_agent.reporting.generator import build_report, render_markdown, write_report
from docker_security_agent.schemas.observations import ImageScanResult, ToolCallRecord
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    AgentEvidence,
    AgentFinding,
    AgentReport,
    Comparison,
    ModelInfo,
    Report,
    RunMetrics,
)
from docker_security_agent.security import rules
from docker_security_agent.security.comparison import compare
from docker_security_agent.security.validation import validate_agent_output
from docker_security_agent.security.vulnerability_parser import (
    count_by_severity,
    parse_findings_page,
    vulnerability_findings,
)


@pytest.fixture
def repo(tmp_path):
    r = AssessmentRepository(tmp_path / "a.db")
    yield r
    r.close()


@pytest.fixture
def scans(snapshot):
    vulns = parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    return [
        ImageScanResult(
            image_id=image.id,
            image_ref=image.tags[0],
            scanner_version="0.68.2",
            scanned_at=datetime.now(UTC),
            counts=count_by_severity(vulns),
            vulnerabilities=vulns,
        )
    ]


def _create(repo, run_id="run-1"):
    repo.create_run(
        run_id=run_id,
        mode="live",
        objective="obj",
        model_profile="local-qwen",
        model_provider="ollama",
        model_id="qwen3",
        model_config={"temperature": 0.2},
        prompt_version="v1",
        session_id=run_id,
    )


def test_run_lifecycle(repo):
    _create(repo)
    repo.update_run("run-1", status="completed", errors_json=["x"], metrics_json={"a": 1})
    run = repo.get_run("run-1")
    assert run["status"] == "completed" and json.loads(run["errors_json"]) == ["x"]
    assert repo.list_runs()[0]["run_id"] == "run-1"
    with pytest.raises(ValueError):
        repo.update_run("run-1", objective="cannot change")


def test_snapshot_roundtrip_and_dedupe(repo, snapshot):
    repo.save_snapshot(snapshot)
    repo.save_snapshot(snapshot)  # same ID -> stored once
    assert len(repo.list_snapshots()) == 1
    loaded = repo.load_snapshot(snapshot.snapshot_id)
    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.compute_id() == snapshot.snapshot_id
    assert [c.name for c in loaded.containers] == [c.name for c in snapshot.containers]


def test_scans_findings_tool_calls(repo, snapshot, settings, scans):
    _create(repo)
    repo.save_snapshot(snapshot)
    repo.save_scan("run-1", snapshot.snapshot_id, scans[0])
    loaded = repo.load_scans_for_snapshot(snapshot.snapshot_id)
    assert len(loaded) == 1 and len(loaded[0].vulnerabilities) == 3
    assert loaded[0].counts == scans[0].counts

    findings = rules.evaluate(snapshot, settings.rules)
    repo.save_findings("run-1", findings)
    assert {f.id for f in repo.load_findings("run-1")} == {f.id for f in findings}

    repo.save_tool_calls(
        "run-1",
        [
            ToolCallRecord(
                timestamp=datetime.now(UTC),
                phase="agent",
                server="docker",
                tool="container_inspect",
                arguments={"id_or_name": "plc"},
                status="ok",
                duration_ms=12,
            )
        ],
    )
    assert repo.load_tool_calls("run-1")[0]["tool"] == "container_inspect"


MODEL = ModelInfo(profile="local-qwen", provider="ollama", model="qwen3")


def _report(snapshot, settings, scans):
    findings = rules.evaluate(snapshot, settings.rules) + vulnerability_findings(scans, snapshot)
    return build_report(
        run_id="run-x",
        status="completed",
        objective="obj",
        model=None,
        prompt_version="v4",
        mcp_servers=[],
        snapshot=snapshot,
        findings=findings,
        scans=scans,
        errors=[],
        metrics=RunMetrics(started_at=datetime.now(UTC)),
    ), findings


def _agent_outputs(snapshot, scans, findings):
    assessment = AgentAssessment(
        executive_summary="Router bridges zones.",
        overall_risk="high",
        findings=[
            AgentFinding(
                title="Router bridges DMZ and ICS",
                resource_name="router",
                severity="high",
                evidence=[
                    AgentEvidence(
                        tool="container_inspect", field="NetworkSettings.Networks", value="3"
                    )
                ],
                vulnerability_ids=[],
                explanation="pivot",
                remediation="split",
            )
        ],
        recommendations=["Split networks"],
        limitations=["none"],
    )
    validation = validate_agent_output(assessment, snapshot, scans)
    report = build_agent_report(
        run_id="run-x",
        model=MODEL,
        prompt_version="v4",
        agent_status="ok",
        snapshot_id=snapshot.snapshot_id,
        validation=validation,
        errors=[],
        metrics=RunMetrics(started_at=datetime.now(UTC)),
    )
    comparison = compare(
        run_id="run-x",
        model=MODEL,
        agent_status="ok",
        deterministic=findings,
        validation=validation,
        snapshot=snapshot,
    )
    return report, comparison


def test_deterministic_report_has_no_agent_content(snapshot, settings, scans):
    report, _ = _report(snapshot, settings, scans)
    assert report.summary.overall_risk == "critical"
    assert report.prioritized
    # configuration critical on a running container ranks before the image CVE critical
    assert report.prioritized[0].finding_id.startswith("F-C008")
    assert report.summary.vulnerable_images == 1
    assert "No AI was involved" in report.summary.executive_summary
    assert report.recommendations  # remediation of the top findings


def test_markdown_has_all_sections_and_files_are_written(snapshot, settings, scans, tmp_path):
    report, findings = _report(snapshot, settings, scans)
    md = render_markdown(report)
    for heading in (
        "1. Assessment summary",
        "2. Docker environment overview",
        "3. Container inventory",
        "4. Image inventory",
        "5. Network configuration",
        "6. Prioritized findings",
        "7. Security misconfigurations",
        "8. Known image vulnerabilities",
        "9. Remediation recommendations",
        "10. Limitations and unknowns",
        "11. Execution metrics",
    ):
        assert f"## {heading}" in md, heading
    assert "CVE-2026-103111" in md
    md_path = write_report(report, tmp_path)
    json_path = md_path.with_suffix(".json")
    assert md_path.name == "deterministic_report.md"
    assert Report.model_validate_json(json_path.read_text()).run_id == "run-x"
    assert md_path.read_text() == md
    # No secret values anywhere in the outputs.
    for secret in ("Sup3rS3cret!", "some-long-secret-you-generate", "hunter2"):
        assert secret not in json_path.read_text() and secret not in md


def test_agent_report_and_comparison_files(snapshot, settings, scans, tmp_path, repo):
    _, findings = _report(snapshot, settings, scans)
    agent_report, comparison = _agent_outputs(snapshot, scans, findings)
    assert [f.resource_name for f in agent_report.findings] == ["router"]
    assert agent_report.overall_risk == "high"
    assert ("N002", "router") in {
        (m.deterministic.rule_id, m.deterministic.resource_name) for m in comparison.found
    }

    md = render_agent_markdown(agent_report, [])
    for heading in ("1. Summary", "2. Findings", "3. Rejected findings", "6. Execution metrics"):
        assert f"## {heading}" in md, heading
    cmp_md = render_comparison_markdown(comparison)
    for heading in ("1. Scores", "2. Missed by the agent", "3. Found by the agent"):
        assert f"## {heading}" in cmp_md, heading

    a_path = write_agent_report(agent_report, [], tmp_path)
    c_path = write_comparison(comparison, tmp_path)
    assert (a_path.name, c_path.name) == ("agent_report.md", "comparison.md")
    assert AgentReport.model_validate_json(a_path.with_suffix(".json").read_text())
    assert Comparison.model_validate_json(c_path.with_suffix(".json").read_text())

    # stored and reloaded from SQLite
    _create(repo, "run-x")
    repo.save_agent_report("run-x", agent_report)
    repo.save_comparison("run-x", comparison)
    assert repo.load_agent_report("run-x") == agent_report
    assert repo.load_comparison("run-x").scores == comparison.scores
    assert repo.load_report("run-x") is None


def test_agent_report_without_valid_assessment():
    report = build_agent_report(
        run_id="r",
        model=MODEL,
        prompt_version="v4",
        agent_status="timeout",
        snapshot_id="snap-1",
        validation=None,
        errors=["agent: too slow"],
        metrics=RunMetrics(started_at=datetime.now(UTC)),
    )
    assert report.overall_risk is None and report.findings == []
    assert "timeout" in report.executive_summary
    assert "agent: too slow" in render_agent_markdown(report, [])


def test_old_database_is_migrated(tmp_path):
    import sqlite3

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """CREATE TABLE schema_info (version INTEGER NOT NULL);
        INSERT INTO schema_info VALUES (1);
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
            finished_at TEXT, status TEXT NOT NULL, mode TEXT NOT NULL,
            objective TEXT NOT NULL, model_profile TEXT, model_provider TEXT,
            model_id TEXT, model_config_json TEXT, prompt_version TEXT,
            mcp_servers_json TEXT, snapshot_id TEXT, session_id TEXT,
            agent_status TEXT, errors_json TEXT, metrics_json TEXT, report_json TEXT);"""
    )
    conn.close()

    repo = AssessmentRepository(db)
    cols = {r["name"] for r in repo.conn.execute("PRAGMA table_info(runs)")}
    assert {
        "docker_endpoint_json",
        "manifest_sha256",
        "config_sha256",
        "manifest_json",
        "agent_report_json",
        "comparison_json",
    } <= cols
    assert repo.conn.execute("SELECT version FROM schema_info").fetchone()[0] == SCHEMA_VERSION
    repo.close()
