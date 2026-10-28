"""Validation of the LLM's structured output against evidence."""

from datetime import UTC, datetime

import grfics
import pytest

from docker_security_agent.schemas.findings import Confidence, FindingStatus
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import AgentAssessment, AgentEvidence, AgentFinding
from docker_security_agent.security.validation import (
    inspect_path_exists,
    validate_agent_output,
    value_matches,
)
from docker_security_agent.security.vulnerability_parser import parse_findings_page


@pytest.fixture
def scans(snapshot):
    vulns = parse_findings_page(grfics.trivy_findings_page(None, 10))[0]
    image = next(i for i in snapshot.images if i.tags == ["fortiphyd/grfics-plc:latest"])
    return [
        ImageScanResult(
            image_id=image.id,
            image_ref=image.tags[0],
            scanned_at=datetime.now(UTC),
            vulnerabilities=vulns,
        )
    ]


def _finding(resource, *evidence, title="Finding", vulns=(), explanation="x"):
    return AgentFinding(
        title=title,
        resource_name=resource,
        severity="high",
        evidence=[AgentEvidence(tool="container_inspect", field=f, value=v) for f, v in evidence],
        vulnerability_ids=list(vulns),
        explanation=explanation,
        remediation="y",
    )


def _assessment(*findings, **overrides):
    base = dict(
        executive_summary="Risky.",
        overall_risk="high",
        findings=list(findings),
        recommendations=[],
        limitations=[],
    )
    base.update(overrides)
    return AgentAssessment(**base)


def test_invented_cves_are_scrubbed_from_text(snapshot, scans):
    a = _assessment(
        executive_summary="See CVE-2026-103111 and CVE-1999-0001.",
        recommendations=["Patch CVE-2021-44228 now"],
    )
    out = validate_agent_output(a, snapshot, scans)
    assert "CVE-2026-103111" in out.assessment.executive_summary  # real (from scanner)
    assert "CVE-1999-0001" not in out.assessment.executive_summary
    assert "[unverified CVE removed]" in out.assessment.recommendations[0]


def test_findings_are_grounded_or_rejected(snapshot, scans):
    good = _finding(
        "simulation", ("Mounts.Source", "/var/run/docker.sock"), title="Docker socket mounted"
    )
    ghost = _finding("does-not-exist", ("HostConfig.Privileged", "true"), title="Ghost")
    fake_cve = _finding(
        "plc", title="Log4Shell", vulns=["CVE-2021-44228"], explanation="CVE-2021-44228 in plc"
    )
    vague = _finding("plc", ("I just feel it", "bad"), title="Vague")
    out = validate_agent_output(_assessment(good, ghost, fake_cve, vague), snapshot, scans)

    assert [f.title for f in out.findings] == ["Docker socket mounted"]
    [accepted] = out.findings
    assert accepted.status == FindingStatus.POTENTIAL and accepted.confidence == Confidence.MEDIUM
    assert [(e.path, e.value) for e in accepted.evidence] == [
        ("Mounts.Source", "/var/run/docker.sock")
    ]
    rejected = {f.title: f for f in out.rejected}
    assert set(rejected) == {"Ghost", "Log4Shell", "Vague"}
    assert all(f.status == FindingStatus.REJECTED for f in out.rejected)
    assert "not found in the inventory" in rejected["Ghost"].validation_notes[0]
    assert "CVE-2021-44228" in " ".join(rejected["Log4Shell"].validation_notes)
    assert any("no verifiable evidence" in n for n in rejected["Vague"].validation_notes)


def test_cves_must_belong_to_the_resources_image(snapshot, scans):
    # Trivy reported CVE-2026-103111 for the plc image only.
    on_plc = _finding("plc", title="pcre2 on plc", vulns=["CVE-2026-103111"])
    on_image = _finding("fortiphyd/grfics-plc:latest", title="pcre2", vulns=["CVE-2026-103111"])
    on_router = _finding("router", title="pcre2 on router", vulns=["CVE-2026-103111"])
    out = validate_agent_output(_assessment(on_plc, on_image, on_router), snapshot, scans)
    assert [f.title for f in out.findings] == ["pcre2 on plc", "pcre2"]
    assert out.findings[0].references == ["CVE-2026-103111"]
    assert [(e.path, e.value) for e in out.findings[0].evidence] == [
        ("vulnerability", "CVE-2026-103111")
    ]
    [wrong] = out.rejected
    assert "other images, not router" in wrong.validation_notes[0]


@pytest.mark.parametrize(
    "field",
    [
        "HostConfig.ThisFieldDoesNotExist",  # right section prefix, invented field
        "Config.Totally.Made.Up",
        "RepoTags",  # real image field, but plc is a container
    ],
)
def test_field_must_exist_on_the_named_resource(snapshot, scans, field):
    out = validate_agent_output(_assessment(_finding("plc", (field, "x"))), snapshot, scans)
    assert out.findings == []
    assert out.rejected[0].status == FindingStatus.REJECTED


@pytest.mark.parametrize(
    ("resource", "field", "value"),
    [
        ("plc", "HostConfig.PortBindings", "8080"),
        ("/plc", "Config.Labels.com.docker.compose.service", "plc"),  # dotted key
        ("plc", "Mounts[0].Source", ""),
        ("plc", "HostConfig.CapAdd", "NET_ADMIN"),
        ("fortiphyd/grfics-plc:latest", "RepoTags", "fortiphyd/grfics-plc:latest"),
        ("b-ics-net", "IPAM", ""),
    ],
)
def test_existing_field_is_accepted(snapshot, scans, resource, field, value):
    out = validate_agent_output(_assessment(_finding(resource, (field, value))), snapshot, scans)
    assert [f.status for f in out.findings] == [FindingStatus.POTENTIAL]
    assert out.findings[0].confidence == Confidence.MEDIUM
    assert out.rejected == []


def test_wrong_value_lowers_confidence_but_keeps_the_finding(snapshot, scans):
    out = validate_agent_output(
        _assessment(_finding("plc", ("HostConfig.Privileged", "true"))), snapshot, scans
    )
    [f] = out.findings  # the field exists; the model paraphrases values, so no rejection
    assert f.confidence == Confidence.LOW
    assert f.evidence[0].note == "value differs from the inspect data"
    assert "some observed values differ from the inspect data" in f.validation_notes


def test_unverified_fields_are_dropped_from_an_accepted_finding(snapshot, scans):
    out = validate_agent_output(
        _assessment(
            _finding(
                "simulation",
                ("Mounts.Source", "/var/run/docker.sock"),
                ("HostConfig.NotARealField", "x"),
            )
        ),
        snapshot,
        scans,
    )
    [f] = out.findings
    assert [e.path for e in f.evidence] == ["Mounts.Source"]
    assert f.validation_notes == ["unverified fields ignored: HostConfig.NotARealField"]


def test_infrastructure_and_duplicates_are_set_aside(snapshot, scans):
    plc = _finding("plc", ("HostConfig.CapAdd", "NET_ADMIN"), title="NET_ADMIN")
    out = validate_agent_output(
        _assessment(plc, plc, _finding("router", ("HostConfig.CapAdd", "NET_RAW"), title="Raw")),
        snapshot,
        scans,
        ignored_containers=["rout*"],
    )
    assert [f.title for f in out.findings] == ["NET_ADMIN"]
    assert [f.title for f in out.out_of_scope] == ["Raw"]
    assert any("reported twice" in n for n in out.notes)


def test_value_matches():
    assert value_matches([["NET_ADMIN", "NET_RAW"]], "NET_RAW")
    assert value_matches([True], "true")
    assert value_matches(["/var/run/docker.sock", "/a"], "/var/run/docker.sock")
    assert value_matches([None], "null") and value_matches([None], "")
    assert not value_matches([False], "true")
    assert not value_matches(["/a"], "/var/run/docker.sock")


def test_inspect_path_exists():
    doc = {
        "HostConfig": {"CapAdd": None, "Binds": ["/a:/b"]},
        "Config": {"Labels": {"com.docker.compose.project": "grfics"}},
        "Mounts": [{"Source": "/a"}, {"Source": "/b", "RW": True}],
    }
    assert inspect_path_exists(doc, "HostConfig.CapAdd")  # present even when null
    assert inspect_path_exists(doc, "Config.Labels.com.docker.compose.project")
    assert inspect_path_exists(doc, "Mounts.1.RW")
    assert inspect_path_exists(doc, "Mounts[1].RW")
    assert inspect_path_exists(doc, ".Mounts.RW")  # unindexed: any element
    assert not inspect_path_exists(doc, "Mounts[0].RW")
    assert not inspect_path_exists(doc, "Mounts[5]")
    assert not inspect_path_exists(doc, "HostConfig.CapAdd.NET_ADMIN")  # cannot descend into null
    assert not inspect_path_exists(doc, "HostConfig.Privileged")
    assert not inspect_path_exists(doc, "")
