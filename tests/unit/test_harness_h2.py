"""Harness h2: lossless shaping, evidence store, context filter, sections."""

import copy
import json

import grfics
import pytest
from agents.run_config import CallModelData, ModelInputData

from docker_security_agent.agents.context_filter import ContextFilter
from docker_security_agent.agents.harness_tools import render_stored
from docker_security_agent.agents.security_assessment import AgentRunOutcome, merge_sections
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.shaping import (
    INSPECT_NOISE,
    inspect_lines,
    shape_result,
    to_text,
    trivy_findings_text,
)
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.schemas.reports import (
    AgentAssessment,
    AgentEvidence,
    AgentFinding,
    ContainerSection,
)


def _with_runtime_fields(doc):
    """Add the runtime fields Docker really returns, including the noise ones."""
    doc = copy.deepcopy(doc)
    doc["NetworkSettings"]["SandboxID"] = "f" * 64
    doc["NetworkSettings"]["SandboxKey"] = "/var/run/docker/netns/abc"
    doc["NetworkSettings"]["Ports"] = {
        "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}, {"HostIp": "::", "HostPort": "80"}]
    }
    for net in doc["NetworkSettings"]["Networks"].values():
        net.update(EndpointID="e" * 64, NetworkID="n" * 64, MacAddress="02:42:ac:11:00:02")
    doc["State"]["FinishedAt"] = "0001-01-01T00:00:00Z"
    doc["Config"]["Env"].append("FLAG=true")
    return doc


def _leaves(node, path=""):
    if isinstance(node, dict):
        if not node:
            yield path
        for k, v in node.items():
            yield from _leaves(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list) and any(isinstance(v, dict | list) for v in node):
        for i, v in enumerate(node):
            yield from _leaves(v, f"{path}[{i}]")
    else:
        yield path


# ---------------------------------------------------------------------------
# Shaping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("doc", grfics.grfics_containers(), ids=lambda d: d["Name"])
def test_inspect_shaping_is_lossless(doc):
    doc = _with_runtime_fields(doc)
    lines = inspect_lines(doc)
    noise = {"NetworkSettings.SandboxID", "NetworkSettings.SandboxKey"} | {
        f"NetworkSettings.Networks.{n}.{f}"
        for n in doc["NetworkSettings"]["Networks"]
        for f in ("EndpointID", "NetworkID")
    }
    expected = [p for p in _leaves(doc) if p not in noise]
    # one line per leaf: nothing dropped except the declared noise
    assert [ln.split(": ", 1)[0] for ln in lines] == expected
    text = "\n".join(lines)
    assert "e" * 64 not in text and "/var/run/docker/netns" not in text
    # kept: they carry security meaning (see INSPECT_NOISE's rule)
    for kept in (
        "MacAddress: 02:42:ac:11:00:02",
        "LogPath: ",
        "State.StartedAt: ",
        "Created: ",
        "HostConfig.PortBindings",
        "NetworkSettings.Ports.80/tcp[1].HostIp: ::",
    ):
        assert kept in text


def test_inspect_scalars_keep_their_type():
    lines = inspect_lines({"A": "true", "B": True, "C": "", "D": None, "E": ["x,y", "z"], "F": []})
    assert lines == ['A: "true"', "B: true", 'C: ""', "D: null", 'E: ["x,y", z]', "F: []"]


def test_noise_list_is_internal_ids_only():
    assert set(INSPECT_NOISE) == {
        "NetworkSettings.SandboxID",
        "NetworkSettings.SandboxKey",
        "NetworkSettings.Networks.*.EndpointID",
        "NetworkSettings.Networks.*.NetworkID",
    }


def test_trivy_findings_grouped_by_package_without_loss():
    page = grfics.trivy_findings_page(None, page_size=3)
    dup = dict(page["findings"][0], i="another-row-key")  # exact duplicate but for the row key
    page["findings"].append(dup)
    text = trivy_findings_text(page)
    assert "IGNORE ALL PREVIOUS" not in text  # untrusted meta block removed
    assert "1 exact duplicates removed" in text
    for f in grfics.TRIVY_FINDINGS:  # every CVE, package, version and fix is still there
        for value in (f["id"], f["an"], f["av"]):
            assert value in text
        if f["fv"]:
            assert f"fix {f['fv']}" in text
    assert "lodash 4.17.20 (node-pkg, app/package-lock.json)" in text
    assert "MEDIUM GHSA-abcd-efgh-ijkl no fix" in text
    assert text.index("CRITICAL CVE-2026-103111") < text.index("HIGH CVE-2026-14456")


def test_trivy_next_token_is_kept():
    text = trivy_findings_text(grfics.trivy_findings_page(None, page_size=2))
    assert "next_token: 2" in text


def test_cap_cuts_at_line_boundary_and_names_the_reference():
    text = "\n".join(f"line {i:03d} " + "x" * 30 for i in range(100))
    out = to_text(text, 500, ref="E7")
    kept, marker = out.split("\n...[TRUNCATED", 1)
    assert all(ln.startswith("line ") and ln.endswith("x" * 30) for ln in kept.splitlines())
    assert 'evidence_get("E7"' in marker


def test_list_results_one_entry_per_line():
    shaped = shape_result("container_list", grfics.grfics_containers())
    text = to_text(shaped, 10**6)
    assert len(text.splitlines()) == len(shaped)
    assert json.loads(text.splitlines()[0])["name"]


# ---------------------------------------------------------------------------
# Evidence store
# ---------------------------------------------------------------------------


def _store_with_router(db=None):
    store = EvidenceStore("run-x", db)
    router = next(d for d in grfics.grfics_containers() if d["Name"] == "/router")
    store.add("docker", "container_inspect", {"id_or_name": "router"}, [router])
    image = router["Config"]["Image"]
    store.add("trivy", "scan_image", {"target": image}, [grfics.trivy_scan_summary(image, "b1")])
    store.add("trivy", "findings_list", {"batchID": "b1"}, [grfics.trivy_findings_page(None, 3)])
    return store, router


def test_store_refs_repeats_and_subjects():
    store, router = _store_with_router()
    assert list(store.outputs) == ["E1", "E2", "E3"]
    assert store.find("docker", "container_inspect", {"id_or_name": "router"}).ref == "E1"
    assert store.find("docker", "container_inspect", {"id_or_name": "plc"}) is None
    assert store.get("e3").subject == router["Config"]["Image"]  # batch -> scanned image


def test_store_persists_full_results(settings):
    repo = AssessmentRepository(settings.assessment_db_path)
    repo.create_run(
        run_id="run-x",
        mode="live",
        objective="o",
        model_profile=None,
        model_provider=None,
        model_id=None,
        model_config=None,
        prompt_version="v6",
        session_id=None,
    )
    store, router = _store_with_router(settings.assessment_db_path)
    store.record_shaped_size("E1", 123)
    store.save_section(
        ContainerSection(resource_name="router", findings=[], evidence_refs=["E1"], notes=[])
    )
    store.close()
    rows = repo.conn.execute(
        "SELECT ref, tool, result_json, shaped_chars FROM tool_outputs ORDER BY seq"
    ).fetchall()
    assert [r["ref"] for r in rows] == ["E1", "E2", "E3"]
    assert json.loads(rows[0]["result_json"]) == [router]  # complete, not shaped
    assert rows[0]["shaped_chars"] == 123
    assert repo.conn.execute("SELECT COUNT(*) FROM agent_sections").fetchone()[0] == 1
    repo.close()


def test_render_stored_select():
    store, _ = _store_with_router()
    caps = render_stored(store.get("E1"), "HostConfig.CapAdd")
    assert caps.splitlines() == [
        ln for ln in caps.splitlines() if ln.startswith("HostConfig.CapAdd")
    ]
    assert caps
    pcre = render_stored(store.get("E3"), "package=pcre2")
    assert "CVE-2026-103111" in pcre and "libcrypto3" not in pcre


# ---------------------------------------------------------------------------
# Context filter
# ---------------------------------------------------------------------------


def _conversation(store, n, extra_fetch=True):
    items = [{"role": "user", "content": "assess"}]
    for i in range(1, n + 1):
        out = store.add(
            "docker", "container_inspect", {"id_or_name": f"c{i}"}, [{"Name": f"/c{i}"}]
        )
        items.append(
            {
                "type": "function_call",
                "call_id": f"k{i}",
                "name": "container_inspect",
                "arguments": "{}",
            }
        )
        items.append(
            {
                "type": "function_call_output",
                "call_id": f"k{i}",
                "output": [
                    {"type": "input_text", "text": f"[{out.ref}] container_inspect c{i}\nX: 1"}
                ],
            }
        )
        if extra_fetch and i == 1:
            items.append(
                {
                    "type": "function_call",
                    "call_id": "f1",
                    "name": "evidence_get",
                    "arguments": "{}",
                }
            )
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": "f1",
                    "output": "[E1] container_inspect c1\nX: 1",
                }
            )
    return items


def _apply(flt, items):
    data = CallModelData(
        model_data=ModelInputData(input=items, instructions="i"), agent=None, context=None
    )
    return flt(data).input


def _texts(items):
    return [
        it["output"] if isinstance(it["output"], str) else it["output"][0]["text"]
        for it in items
        if it.get("type") == "function_call_output"
    ]


def test_filter_keeps_last_n_and_stubs_older_with_reference():
    store = EvidenceStore("r")
    items = _conversation(store, 10)
    before = copy.deepcopy(items)
    out = _apply(ContextFilter(store, keep_recent=8), items)
    assert items == before  # input not mutated
    texts = _texts(out)
    # c1 and c2 are older than the last 8 MCP results -> stubs with their reference
    assert texts[0].startswith("[E1] container_inspect c1: full result removed")
    assert 'evidence_get("E1")' in texts[0]
    assert texts[2].startswith("[E2] container_inspect c2: full result removed")
    # the evidence_get result is never stubbed, and the last 8 stay in full
    assert texts[1] == "[E1] container_inspect c1\nX: 1"
    assert all(t.endswith("X: 1") for t in texts[3:])
    stub = next(it for it in out if it.get("call_id") == "k1" and "output" in it)
    assert isinstance(stub["output"], list)  # same shape as the item it replaces


def test_filter_is_idempotent_and_points_to_sections():
    store = EvidenceStore("r")
    items = _conversation(store, 10, extra_fetch=False)
    store.save_section(
        ContainerSection(resource_name="c1", findings=[], evidence_refs=["E1"], notes=[])
    )
    flt = ContextFilter(store, keep_recent=8)
    once = _apply(flt, items)
    assert _apply(flt, once) == once
    assert "Your section for c1 is already recorded." in _texts(once)[0]
    assert "section" not in _texts(once)[1]


def test_filter_leaves_short_conversations_alone():
    store = EvidenceStore("r")
    items = _conversation(store, 3)
    assert _apply(ContextFilter(store, keep_recent=8), items) == items


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _af(resource, title, severity="high"):
    return AgentFinding(
        title=title,
        resource_name=resource,
        severity=severity,
        evidence=[
            AgentEvidence(tool="container_inspect", field="HostConfig.CapAdd", value="NET_RAW")
        ],
        vulnerability_ids=[],
        explanation="e",
    )


def test_sections_are_merged_before_final_findings():
    final = AgentAssessment(
        executive_summary="s",
        overall_risk="high",
        findings=[_af("net", "Flat network")],
        limitations=[],
    )
    outcome = AgentRunOutcome(status="ok", assessment=final)
    sections = [
        ContainerSection(
            resource_name="router", findings=[_af("router", "Caps")], evidence_refs=["E1"], notes=[]
        )
    ]
    merge_sections(outcome, sections)
    assert [f.title for f in outcome.assessment.findings] == ["Caps", "Flat network"]
    assert not outcome.partial


def test_partial_assessment_from_sections_when_agent_fails():
    outcome = AgentRunOutcome(status="error")
    sections = [
        ContainerSection(
            resource_name="plc",
            findings=[_af("plc", "Root", "critical")],
            evidence_refs=[],
            notes=["could not scan"],
        )
    ]
    merge_sections(outcome, sections)
    assert outcome.partial and outcome.status == "error"
    assert outcome.assessment.overall_risk == "critical"
    assert [f.title for f in outcome.assessment.findings] == ["Root"]
    assert "could not scan" in outcome.assessment.limitations


def test_no_sections_no_assessment():
    outcome = AgentRunOutcome(status="error")
    merge_sections(outcome, [])
    assert outcome.assessment is None
