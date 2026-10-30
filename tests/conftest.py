"""Shared pytest fixtures.

* ``settings``  - the real config/ files, but with data/output directories
                  redirected to a temp dir so tests never touch real data.
* ``snapshot``  - an InventorySnapshot parsed from the GRFICS-like fixtures.
* ``fake_mcp_settings`` - settings whose MCP servers are the fake stdio
                  servers in tests/fixtures/fake_mcp_server.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from builders import build_snapshot  # noqa: E402  (tests/fixtures/builders.py)

from docker_security_agent.config import Settings, load_settings  # noqa: E402
from docker_security_agent.schemas.assets import InventorySnapshot  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = load_settings()
    s.experiment.data_dir = str(tmp_path / "data")
    s.experiment.output_dir = str(tmp_path / "outputs")
    s.agent.session.db_path = str(tmp_path / "data" / "sessions.db")
    return s


@pytest.fixture
def snapshot(settings: Settings) -> InventorySnapshot:
    return build_snapshot(settings)


@pytest.fixture
def fake_mcp_settings(settings: Settings, tmp_path: Path) -> Settings:
    """Point both MCP servers at the fake stdio server (no Docker/Trivy needed)."""
    script = str(FIXTURES / "fake_mcp_server.py")
    call_log = tmp_path / "mcp_calls.jsonl"
    settings.mcp.servers["nmap"].enabled = False  # no fake for it; never start the real one
    for name, kind in (("docker", "docker"), ("trivy", "trivy")):
        cfg = settings.mcp.servers[name]
        cfg.command = sys.executable
        cfg.args = [script, kind]
        cfg.env = {**cfg.env, "FAKE_MCP_CALL_LOG": str(call_log)}
        cfg.client_session_timeout_seconds = 30
        cfg.setup = None
    # Allow-list for the fake docker server mirrors the real config, minus
    # tools the fake does not implement.
    settings.mcp.servers["docker"].allowed_tools = [
        "container_list",
        "container_inspect",
        "image_list",
        "network_list",
        "volume_list",
        "system_version",
    ]
    return settings
