"""Tool policy (allow-list + argument rules) and result shaping."""

import grfics

from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.shaping import shape_result, to_text


def test_unapproved_tools_are_refused(settings):
    policy = ToolPolicy(settings.mcp)
    for tool in ("container_exec", "secret_inspect", "container_archive_get", "container_logs"):
        assert not policy.check("docker", tool, {}).allowed
    assert not policy.check("trivy", "scan_filesystem", {"target": "/"}).allowed
    assert policy.check("docker", "container_inspect", {"id_or_name": "plc"}).allowed


def test_unknown_server_is_refused(settings):
    assert not ToolPolicy(settings.mcp).check("evil", "container_list", {}).allowed


def test_scan_requires_inventory_and_known_target(settings, snapshot):
    policy = ToolPolicy(settings.mcp)
    args = {"target": "fortiphyd/grfics-plc:latest", "scanType": ["vuln"]}
    assert not policy.check("trivy", "scan_image", args).allowed  # no inventory yet

    policy.set_scan_targets(snapshot.image_references())
    assert policy.check("trivy", "scan_image", args).allowed
    decision = policy.check("trivy", "scan_image", {"target": "alpine:latest"})
    assert not decision.allowed
    assert "not in the current Docker inventory" in decision.reason


def test_scan_arguments_are_normalised(settings, snapshot):
    policy = ToolPolicy(settings.mcp)
    policy.set_scan_targets(snapshot.image_references())
    d = policy.check(
        "trivy",
        "scan_image",
        {
            "target": "fortiphyd/grfics-plc:latest",
            "scanType": ["secret", "vuln"],
            "outputFormat": "cyclonedx",
            "targetType": "filesystem",
        },
    )
    assert d.allowed
    assert d.arguments["scanType"] == ["vuln"]  # 'secret' scanning stripped
    assert d.arguments["outputFormat"] == "json"
    assert d.arguments["targetType"] == "image"


def test_findings_list_categories_forced(settings):
    d = ToolPolicy(settings.mcp).check(
        "trivy", "findings_list", {"batchID": "b1", "categories": ["secret"]}
    )
    assert d.allowed and d.arguments["categories"] == ["vuln"]
    assert not ToolPolicy(settings.mcp).check("trivy", "findings_list", {}).allowed


def test_container_list_is_compacted():
    docs = grfics.grfics_containers()
    shaped = shape_result("container_list", docs)
    assert len(shaped) == len(docs)
    sim = next(c for c in shaped if c["name"] == "simulation")
    assert sim["published_ports"] == ["0.0.0.0:80->80/tcp"]
    assert set(sim["networks"]) == {"a-grfics-admin", "b-ics-net"}
    assert len(to_text(shaped, 100_000)) < sum(len(str(d)) for d in docs) / 3


def test_trivy_results_are_readable_and_meta_is_dropped():
    page = grfics.trivy_findings_page(None)
    shaped = shape_result("findings_list", [page])
    assert "IGNORE ALL PREVIOUS" not in to_text(shaped, 100_000)
    assert "pcre2 10.47-r1 (debian, image (debian 12))" in shaped
    assert "  CRITICAL CVE-2026-103111 fix 10.49-r0" in shaped

    summary = shape_result("scan_image", [grfics.trivy_scan_summary("x")])
    assert "counts_by_severity: CRITICAL 1, HIGH 1, MEDIUM 1" in summary


def test_truncation_marker():
    text = to_text("x" * 500, 100)
    assert text.startswith("x" * 100) and "TRUNCATED: 400" in text
