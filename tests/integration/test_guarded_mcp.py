"""GuardedMCPServer against a real MCP subprocess (the fake docker/trivy servers).

These tests prove the security properties end-to-end over the real MCP
protocol: hidden tools, call-time refusal, unredacted results (harness h3), and
inventory collection.
"""

import json

import pytest

from docker_security_agent.inventory.collector import collect_snapshot
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.registry import build_servers, connect, inspect_server_tools
from docker_security_agent.security.scanner import scan_images

pytestmark = pytest.mark.integration


def _servers(settings, max_calls=40):
    recorder = ToolCallRecorder(max_calls)
    policy = ToolPolicy(settings.mcp)
    servers = build_servers(settings, policy, recorder)
    return servers, policy, recorder


def _calls(tmp_path):
    path = tmp_path / "mcp_calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def test_dangerous_tools_are_hidden_and_refused(fake_mcp_settings, tmp_path):
    servers, _, recorder = _servers(fake_mcp_settings)
    async with connect(servers) as manager:
        assert len(manager.active_servers) == 2
        docker = next(s for s in manager.active_servers if s.name == "docker")
        trivy = next(s for s in manager.active_servers if s.name == "trivy")

        # The server registers container_exec / secret_list ...
        inv = await inspect_server_tools(docker)
        assert {"container_exec", "secret_list"} <= set(inv.available)
        # ... but the agent-facing tool list does not contain them.
        visible = {t.name for t in await docker.list_tools(None, None)}
        assert visible == set(fake_mcp_settings.mcp.servers["docker"].allowed_tools)
        assert "scan_filesystem" not in {t.name for t in await trivy.list_tools(None, None)}

        # Even a direct call (e.g. hallucinated tool name) is refused before it is sent.
        result = await docker.call_tool("container_exec", {"id_or_name": "plc", "cmd": "id"})
        assert result.is_error and "Refused by policy" in result.content[0].text
        result = await trivy.call_tool("scan_filesystem", {"target": "/", "scanType": ["vuln"]})
        assert result.is_error

    called = {c["tool"] for c in _calls(tmp_path)}
    assert "container_exec" not in called and "scan_filesystem" not in called
    assert recorder.blocked() == 2


async def test_agent_results_are_unredacted_and_shaped(fake_mcp_settings):
    servers, _, _ = _servers(fake_mcp_settings)
    async with connect(servers) as manager:
        docker = next(s for s in manager.active_servers if s.name == "docker")
        hmi = (await docker.call_tool("container_inspect", {"id_or_name": "HMI"})).content[0].text
        # h3: credentials reach the agent as-is (finding them is part of the lab)
        assert "MYSQL_ROOT_PASSWORD=Sup3rS3cret!" in hmi and "<redacted>" not in hmi
        listing = (await docker.call_tool("container_list", {"all": True})).content[0].text
        assert "ResolvConfPath" not in listing  # compacted summary, not raw inspect docs
        assert '"name":"simulation"' in listing


async def test_collect_snapshot_over_mcp(fake_mcp_settings):
    servers, _, recorder = _servers(fake_mcp_settings)
    async with connect(servers) as manager:
        docker = next(s for s in manager.active_servers if s.name == "docker")
        snap = await collect_snapshot(docker)
    assert {c.name for c in snap.containers} >= {"simulation", "router", "plc", "hardened"}
    assert snap.docker_version == "29.7.2"
    assert "Sup3rS3cret!" in snap.model_dump_json()  # h3: stored unredacted
    assert all(r.phase == "collector" and r.status == "ok" for r in recorder.records)


async def test_scan_pipeline_paginates_and_respects_inventory(fake_mcp_settings, tmp_path):
    servers, policy, _ = _servers(fake_mcp_settings)
    async with connect(servers) as manager:
        docker = next(s for s in manager.active_servers if s.name == "docker")
        trivy = next(s for s in manager.active_servers if s.name == "trivy")
        snap = await collect_snapshot(docker)

        # Without the inventory being registered, the agent cannot scan anything.
        refused = await trivy.call_tool(
            "scan_image", {"target": "fortiphyd/grfics-plc:latest", "scanType": ["vuln"]}
        )
        assert refused.is_error

        policy.set_scan_targets(snap.image_references())
        fake_mcp_settings.experiment.scan.max_images = 2
        scans = await scan_images(trivy, snap, fake_mcp_settings.experiment.scan)
        assert len(scans) == 2 and all(s.status == "ok" for s in scans)
        assert [v.vuln_id for v in scans[0].vulnerabilities] == [
            "CVE-2026-103111",
            "CVE-2026-14456",
            "GHSA-abcd-efgh-ijkl",
        ]
        # Arbitrary images (not in inventory) stay blocked even after registration.
        blocked = await trivy.call_tool(
            "scan_image", {"target": "evil/miner:latest", "scanType": ["vuln"]}
        )
        assert blocked.is_error

    pages = [c for c in _calls(tmp_path) if c["tool"] == "findings_list"]
    assert any(p["args"]["token"] == "2" for p in pages)  # second page was fetched
    assert all(
        c["args"]["scanType"] == ["vuln"] for c in _calls(tmp_path) if c["tool"] == "scan_image"
    )


async def test_unavailable_server_is_dropped_gracefully(fake_mcp_settings):
    fake_mcp_settings.mcp.servers["trivy"].args = ["-c", "import sys; sys.exit(3)"]
    servers, _, _ = _servers(fake_mcp_settings)
    async with connect(servers) as manager:
        assert [s.name for s in manager.active_servers] == ["docker"]
        assert [s.name for s in manager.failed_servers] == ["trivy"]
