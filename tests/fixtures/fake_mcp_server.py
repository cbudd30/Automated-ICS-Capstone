"""A fake MCP server (stdio) that imitates docker-mcp-server or trivy-mcp.

Integration tests launch this script as a real MCP subprocess, exactly like
the application launches the real servers, so the whole client path
(SDK MCPServerStdio -> GuardedMCPServer -> policy/shaping) is
exercised without Docker, Trivy or network access.

    python fake_mcp_server.py docker   # docker-mcp-server look-alike
    python fake_mcp_server.py trivy    # trivy-mcp look-alike

The docker variant deliberately ALSO registers dangerous tools
(``container_exec``, ``secret_list``) so tests can prove they are hidden from
the agent and refused at call time. Every call is appended to the file named
by $FAKE_MCP_CALL_LOG (if set) so tests can assert what was really invoked.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import grfics  # noqa: E402  (fixture data next to this file)
from mcp.server.mcpserver import MCPServer  # noqa: E402


def _log(tool: str, args: dict[str, Any]) -> None:
    path = os.environ.get("FAKE_MCP_CALL_LOG")
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps({"tool": tool, "args": args}) + "\n")


def build_docker() -> MCPServer:
    server = MCPServer("fake-docker")

    @server.tool()
    def system_version():
        _log("system_version", {})
        return grfics.system_version()

    @server.tool()
    def container_list(all: bool = False, sparse: bool = False):
        _log("container_list", {"all": all})
        docs = grfics.grfics_containers()
        return docs if all else [d for d in docs if d["State"]["Running"]]

    @server.tool()
    def container_inspect(id_or_name: str):
        _log("container_inspect", {"id_or_name": id_or_name})
        for d in grfics.grfics_containers():
            if d["Name"].lstrip("/") == id_or_name or d["Id"].startswith(id_or_name):
                return d
        raise ValueError(f"No such container: {id_or_name}")

    @server.tool()
    def image_list():
        _log("image_list", {})
        return grfics.grfics_images()

    @server.tool()
    def network_list():
        _log("network_list", {})
        return grfics.grfics_networks()

    @server.tool()
    def volume_list():
        _log("volume_list", {})
        return grfics.grfics_volumes()

    # ---- tools that must NEVER be reachable by the agent
    @server.tool()
    def container_exec(id_or_name: str, cmd: str):
        _log("container_exec", {"id_or_name": id_or_name, "cmd": cmd})
        return "EXECUTED"  # the test fails if this is ever logged

    @server.tool()
    def secret_list():
        _log("secret_list", {})
        return [{"Name": "db_password", "Value": "TopSecretValue"}]

    return server


def build_trivy() -> MCPServer:
    server = MCPServer("fake-trivy")

    @server.tool()
    def trivy_version():
        return "v0.68.2-fake"

    @server.tool()
    def scan_image(
        target: str,
        targetType: str,
        scanType: list[str],
        outputFormat: str = "json",
        severities: list[str] | None = None,
        fixedOnly: bool = False,
    ):
        _log("scan_image", {"target": target, "scanType": scanType, "outputFormat": outputFormat})
        return grfics.trivy_scan_summary(target, batch_id=f"batch-{target}")

    @server.tool()
    def findings_list(
        batchID: str, minSeverity: str, categories: list[str], limit: int = 100, token: str = ""
    ):
        _log("findings_list", {"batchID": batchID, "token": token, "categories": categories})
        return grfics.trivy_findings_page(token or None)

    @server.tool()
    def findings_get(batchID: str, id: str):
        return next((f for f in grfics.TRIVY_FINDINGS if f["i"] == id), "finding not found")

    @server.tool()
    def scan_filesystem(target: str, scanType: list[str]):
        _log("scan_filesystem", {"target": target})
        return "FILESYSTEM SCANNED"  # must never be reachable

    return server


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "docker"
    (build_docker() if kind == "docker" else build_trivy()).run("stdio")
