"""End-to-end tests against the REAL Docker environment (opt-in).

Run with:   uv run pytest -m e2e            (Docker + proxy + Trivy)
            uv run pytest -m "e2e and llm"  (also needs the default Ollama model)

Requirements: Docker Desktop running, the read-only socket proxy started
(deploy/socket-proxy/compose.yml), docker-mcp-server reachable through uvx,
and Trivy + trivy-mcp installed with its DB downloaded (`docker-audit setup`).

The key assertion is READ-ONLY behaviour: the set of containers (with their
state), images, networks and volumes must be identical before and after the
assessment, and the proxy's access log must not contain a single new
non-GET/HEAD request.
"""

import shutil
import subprocess

import httpx
import pytest

from docker_security_agent.mcp.registry import check_docker_endpoint
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.pipeline import AssessOptions, run_assessment

pytestmark = pytest.mark.e2e

PROXY_CONTAINER = "docker-audit-socket-proxy"


@pytest.fixture
def live_settings(settings):
    status = check_docker_endpoint(settings)
    if not status.ok:
        pytest.skip("read-only Docker proxy not available: " + "; ".join(status.problems))
    return settings


def docker_state(settings) -> dict:
    """Read-only fingerprint of the Docker host (via the proxy, GET only)."""
    base = settings.mcp.docker_host.replace("tcp://", "http://")
    with httpx.Client(base_url=base, timeout=20) as c:
        return {
            "containers": sorted(
                (x["Id"], x["State"], x["ImageID"])
                for x in c.get("/containers/json", params={"all": 1}).json()
            ),
            "images": sorted(x["Id"] for x in c.get("/images/json").json()),
            "networks": sorted(x["Id"] for x in c.get("/networks").json()),
            "volumes": sorted(v["Name"] for v in c.get("/volumes").json()["Volumes"] or []),
        }


def proxy_write_requests() -> int | None:
    """Count non-GET/HEAD requests in the proxy access log (None if unavailable)."""
    if shutil.which("docker") is None:
        return None
    out = subprocess.run(["docker", "logs", PROXY_CONTAINER], capture_output=True, text=True)
    if out.returncode != 0:
        return None
    log = out.stdout + out.stderr
    return sum(log.count(f'"{m} ') for m in ("POST", "PUT", "DELETE", "PATCH"))


async def test_deterministic_assessment_is_read_only(live_settings):
    settings = live_settings
    settings.experiment.scan.max_images = 1  # keep the test fast
    before_state = docker_state(settings)
    before_writes = proxy_write_requests()

    result = await run_assessment(settings, AssessOptions(use_agent=False))

    # 1-7: servers connected, inventory, findings, scans, SQLite, reports
    report = result.report
    assert result.status in ("completed", "completed_with_errors")
    assert report.summary.containers_total == len(before_state["containers"])
    assert report.findings, "expected at least one finding on a real host"
    assert {s.name for s in report.mcp_servers if s.connected} == {"docker", "trivy"}
    assert len(report.vulnerabilities) <= 1
    assert result.md_path.exists() and result.md_path.with_suffix(".json").exists()
    repo = AssessmentRepository(settings.assessment_db_path)
    assert repo.get_run(result.run_id)["status"] == result.status
    assert repo.load_tool_calls(result.run_id)
    repo.close()

    # 8: nothing changed
    assert docker_state(settings) == before_state
    after_writes = proxy_write_requests()
    if before_writes is not None:
        assert after_writes == before_writes, "a write request reached the Docker proxy"


@pytest.mark.llm
async def test_agent_assessment_is_read_only(live_settings):
    settings = live_settings
    settings.agent.limits.max_turns = 15
    settings.agent.limits.max_tool_calls = 12
    before_state = docker_state(settings)
    before_writes = proxy_write_requests()

    result = await run_assessment(settings, AssessOptions(scan=False))

    assert result.report.model is not None
    assert result.report.findings
    assert docker_state(settings) == before_state
    if before_writes is not None:
        assert proxy_write_requests() == before_writes
