"""Matching the agent's findings to the deterministic findings (the answer key)."""

from datetime import UTC, datetime

import grfics
import pytest

from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    AgentEvidence,
    AgentFinding,
    ModelInfo,
)
from docker_security_agent.security import rules
from docker_security_agent.security.comparison import compare
from docker_security_agent.security.validation import validate_agent_output
from docker_security_agent.security.vulnerability_parser import (
    count_by_severity,
    parse_findings_page,
    vulnerability_findings,
)

MODEL = ModelInfo(profile="scripted", provider="ollama", model="scripted")


@pytest.fixture
def evidence(snapshot, settings):
    vulns = parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    scans = [
        ImageScanResult(
            image_id=image.id,
            image_ref=image.tags[0],
            scanned_at=datetime.now(UTC),
            counts=count_by_severity(vulns),
            vulnerabilities=vulns,
        )
    ]
    findings = rules.evaluate(snapshot, settings.rules) + vulnerability_findings(scans, snapshot)
    return findings, scans


def _f(resource, field="", value="", *, title="Issue", vulns=(), severity="high"):
    return AgentFinding(
        title=title,
        resource_name=resource,
        severity=severity,
        evidence=[AgentEvidence(tool="container_inspect", field=field, value=value)]
        if field
        else [],
        vulnerability_ids=list(vulns),
        explanation="x",
        remediation="y",
    )


def _compare(snapshot, evidence, *agent_findings):
    findings, scans = evidence
    validation = validate_agent_output(
        AgentAssessment(
            executive_summary="s",
            overall_risk="high",
            findings=list(agent_findings),
            recommendations=[],
            limitations=[],
        ),
        snapshot,
        scans,
    )
    return compare(
        run_id="r",
        model=MODEL,
        agent_status="ok",
        deterministic=findings,
        validation=validation,
        snapshot=snapshot,
    )


def _found(c) -> set[tuple[str, str]]:
    return {(m.deterministic.rule_id, m.deterministic.resource_name) for m in c.found}


def test_nothing_reported_means_everything_missed(snapshot, evidence):
    c = _compare(snapshot, evidence)
    findings, _ = evidence
    assert c.scores.found == 0 and c.scores.missed == len(findings)
    assert c.scores.recall == 0 and c.scores.weighted_recall == 0
    assert {m.finding_id for m in c.missed} == {f.id for f in findings}


def test_matching_by_resource_and_field(snapshot, evidence):
    c = _compare(
        snapshot,
        evidence,
        _f("router", "HostConfig.CapAdd[1]", "NET_RAW", title="caps"),  # list index ignored
        # a prefix of the rule's path (NetworkSettings.Networks.<network>)
        _f("router", "NetworkSettings.Networks", "3 networks", title="networks"),
        _f("plc", "HostConfig.PortBindings.8080/tcp", "8080", title="ports"),  # longer path
    )
    assert {("C002", "router"), ("N002", "router"), ("N001", "plc")} <= _found(c)
    assert ("C002", "plc") not in _found(c)  # same field, other container
    assert c.scores.agent_matched == 3 and c.scores.agent_unmatched == 0


def test_shared_fields_are_decided_by_the_agents_wording(snapshot, evidence):
    socket = _f("simulation", "Mounts.Source", "/var/run/docker.sock", title="Socket")
    vague = _f("simulation", "Mounts", "a volume", title="Something mounted")
    assert ("C008", "simulation") in _found(_compare(snapshot, evidence, socket))
    c = _compare(snapshot, evidence, vague)
    assert ("C008", "simulation") not in _found(c)
    assert c.scores.agent_unmatched == 1  # validated, but not the socket finding


def test_image_findings_can_be_reported_on_a_container(snapshot, evidence):
    by_container = _f("plc", title="pcre2", vulns=["CVE-2026-103111"])
    tag_via_container = _f("plc", "Config.Image", "fortiphyd/grfics-plc:latest", title="latest")
    c = _compare(snapshot, evidence, by_container, tag_via_container)
    assert ("V001", "fortiphyd/grfics-plc:latest") in _found(c)
    assert ("I001", "fortiphyd/grfics-plc:latest") in _found(c)


def test_rejected_findings_never_count(snapshot, evidence):
    c = _compare(
        snapshot,
        evidence,
        _f("ghost", "HostConfig.Privileged", "true"),
        _f("router", title="pcre2", vulns=["CVE-2026-103111"]),  # CVE of another image
    )
    assert c.scores.found == 0 and c.scores.agent_rejected == 2
    assert c.scores.rejection_rate == 1.0


def test_scores_and_severity_agreement(snapshot, evidence):
    findings, _ = evidence
    socket = next(f for f in findings if f.rule_id == "C008")  # critical
    c = _compare(
        snapshot,
        evidence,
        _f("simulation", "Mounts", "/var/run/docker.sock", severity="medium"),
    )
    [m] = [m for m in c.found if m.deterministic.finding_id == socket.id]
    assert m.agent_severity == "medium" and m.severity_agreement == "lower"
    total_weight = sum(f.severity.rank for f in findings)
    assert c.scores.weighted_recall == round(socket.severity.rank / total_weight, 3)
    crit = next(b for b in c.scores.by_severity if b.severity == "critical")
    assert crit.found >= 1 and crit.total >= crit.found
