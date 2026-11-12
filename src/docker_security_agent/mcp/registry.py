"""MCP server registry: build servers from config, health-check them, set them up.

Responsibilities:

* ``check_docker_endpoint`` - make sure Docker answers at ``docker_host``.
* ``ensure_server_setup``   - install the trivy-mcp plugin on demand (the
  "dynamic install" for servers that are not Python packages; docker-mcp-server
  needs nothing because ``uvx`` fetches the pinned version itself).
* ``trivy_db_status`` / ``download_trivy_db`` - trivy-mcp always runs Trivy
  with ``--skip-update``, so the vulnerability DB must already be present.
* ``build_servers``         - create one ``GuardedMCPServer`` per enabled server.
* ``connect``               - connect a set of servers with the SDK's
  ``MCPServerManager``; servers that fail to start are dropped (graceful
  degradation) and reported instead of crashing the run.
* ``inspect_server_tools``  - list a connected server's tools and compare them
  with the approved list (``docker-audit mcp check``).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from agents.mcp import MCPServerManager

from docker_security_agent.config import MCPServerConfig, Settings
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.servers import GuardedMCPServer

# ---------------------------------------------------------------------------
# Docker endpoint check
# ---------------------------------------------------------------------------


@dataclass
class DockerEndpointStatus:
    docker_host: str
    reachable: bool = False
    docker_version: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def check_docker_endpoint(settings: Settings, timeout: float = 5.0) -> DockerEndpointStatus:
    """Ask Docker for its version at ``docker_host`` (unix:// socket or tcp://).

    The agent's tools have full Docker access (there is no read-only proxy
    since 2026-11-09); what keeps them inside Docker is that Docker Desktop
    shares no Mac folders and that the agent itself runs in a container
    (deploy/agent). See docs/running-the-agent.md.
    """
    host = settings.mcp.docker_host
    status = DockerEndpointStatus(docker_host=host)
    parsed = urlparse(host)
    if parsed.scheme == "unix":
        transport, base = httpx.HTTPTransport(uds=parsed.path), "http://docker"
    elif parsed.scheme == "tcp":
        transport, base = None, f"http://{parsed.hostname}:{parsed.port or 2375}"
    else:
        status.problems.append(f"docker_host '{host}' must start with unix:// or tcp://")
        return status
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            version = client.get(f"{base}/version")
    except httpx.HTTPError as exc:
        status.problems.append(
            f"Cannot reach Docker at {host}: {exc}. Is Docker Desktop running?"
        )
        return status
    status.reachable = version.status_code == 200
    if status.reachable:
        status.docker_version = version.json().get("Version", "")
    else:
        status.problems.append(f"Docker at {host} answered /version with {version.status_code}")
    return status


# ---------------------------------------------------------------------------
# Server setup (dynamic install of the Trivy plugin) and the Trivy DB
# ---------------------------------------------------------------------------


@dataclass
class SetupStatus:
    server: str
    command_found: bool
    ready: bool
    installed_now: bool = False
    message: str = ""


def ensure_server_setup(cfg: MCPServerConfig, install: bool) -> SetupStatus:
    """Make sure a server's executable (and plugin, if any) is available.

    ``install=True`` runs the configured install command when the check fails.
    """
    if shutil.which(cfg.command) is None:
        hint = (
            "Install uv: https://docs.astral.sh/uv/"
            if cfg.command == "uvx"
            else ("Install Trivy: brew install trivy" if cfg.command == "trivy" else "")
        )
        return SetupStatus(cfg.name, False, False, message=f"'{cfg.command}' not on PATH. {hint}")

    setup = cfg.setup
    if setup is None or not setup.check_command:
        return SetupStatus(cfg.name, True, True, message="no setup required")

    def _check() -> bool:
        out = subprocess.run(setup.check_command, capture_output=True, text=True, timeout=60)
        return out.returncode == 0 and setup.check_contains in (out.stdout + out.stderr)

    if _check():
        return SetupStatus(cfg.name, True, True, message="ready")
    if not (install and setup.auto_install and setup.install_command):
        return SetupStatus(
            cfg.name,
            True,
            False,
            message=f"not installed; run: {' '.join(setup.install_command)}",
        )
    proc = subprocess.run(setup.install_command, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not _check():
        return SetupStatus(
            cfg.name, True, False, message=f"install failed: {proc.stderr.strip()[-500:]}"
        )
    return SetupStatus(cfg.name, True, True, installed_now=True, message="installed")


def trivy_db_status() -> dict[str, Any]:
    """Return Trivy's vulnerability-DB metadata (empty dict if not downloaded)."""
    if shutil.which("trivy") is None:
        return {}
    proc = subprocess.run(
        ["trivy", "version", "--format", "json"], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        return {}
    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    db = info.get("VulnerabilityDB") or {}
    return {"trivy_version": info.get("Version", ""), **db}


def download_trivy_db() -> tuple[bool, str]:
    """Download/refresh Trivy's vulnerability DB (needs internet, ~120 MB)."""
    proc = subprocess.run(
        ["trivy", "image", "--download-db-only", "--quiet"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()[-500:]


# ---------------------------------------------------------------------------
# Building and connecting servers
# ---------------------------------------------------------------------------


def build_servers(
    settings: Settings,
    policy: ToolPolicy,
    recorder: ToolCallRecorder,
    roles: set[str] | None = None,
) -> list[GuardedMCPServer]:
    """Create (but do not connect) a GuardedMCPServer for each enabled server."""
    servers = []
    for cfg in settings.mcp.enabled_servers():
        if roles and cfg.role not in roles:
            continue
        servers.append(
            GuardedMCPServer(
                cfg,
                docker_host=settings.mcp.docker_host,
                policy=policy,
                recorder=recorder,
                max_result_chars=settings.agent.limits.max_tool_result_chars,
            )
        )
    return servers


def connect(servers: list[GuardedMCPServer]) -> MCPServerManager:
    """Return an MCPServerManager; use it as ``async with connect(...) as mgr``.

    ``drop_failed_servers=True`` means a broken server is removed from
    ``mgr.active_servers`` and listed in ``mgr.failed_servers`` / ``mgr.errors``
    instead of aborting the whole run. The generous connect timeout covers the
    first ``uvx`` launch, which downloads docker-mcp-server.
    """
    return MCPServerManager(
        servers,
        connect_timeout_seconds=180,
        cleanup_timeout_seconds=15,
        drop_failed_servers=True,
        connect_in_parallel=True,
    )


@dataclass
class ToolInventory:
    server: str
    available: list[str]  # every tool the server registered
    approved: list[str]  # approved in config
    exposed: list[str]  # approved AND available (what the agent sees)
    missing: list[str]  # approved but NOT offered by the server
    schema_problems: list[str]


async def inspect_server_tools(server: GuardedMCPServer) -> ToolInventory:
    """Compare the tools a connected server offers with the approved list.

    ``list_tools`` on the SDK object is already filtered, so we go through the
    underlying MCP session to see the full, unfiltered tool surface.
    """
    assert server.session is not None, "server must be connected"
    listed = await server.session.list_tools()
    all_tools = {t.name: t for t in listed.tools}
    approved = server.config.allowed_tools
    exposed = [t for t in approved if t in all_tools]
    missing = [t for t in approved if t not in all_tools]
    problems = []
    for name in exposed:
        schema = all_tools[name].input_schema or {}
        if schema.get("type") != "object":
            problems.append(f"{name}: input schema is not a JSON object schema")
    return ToolInventory(
        server=server.name,
        available=sorted(all_tools),
        approved=list(approved),
        exposed=exposed,
        missing=missing,
        schema_problems=problems,
    )
