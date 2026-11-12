"""Collect a Docker inventory snapshot through the Docker inspection MCP server.

This is the *deterministic* evidence-collection step: the application (not
the LLM) calls a fixed set of read-only tools so that every run - whatever
model is used - starts from the same, complete picture of the environment.

All calls go through ``GuardedMCPServer.collect`` so they are policy-checked
and recorded exactly like agent calls.

Tools used (all on the approved list):
    system_version   -> Docker engine version / platform
    container_list   -> full inspect document of every container (all=True)
    image_list       -> inspect document of every local image
    network_list     -> every network
    volume_list      -> every named volume
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from docker_security_agent.inventory.parsers import (
    parse_container,
    parse_image,
    parse_network,
    parse_volume,
)
from docker_security_agent.mcp.servers import GuardedMCPServer, ToolCallFailed
from docker_security_agent.schemas.assets import InventorySnapshot


def _dicts(items: list[Any]) -> list[dict[str, Any]]:
    return [i for i in items if isinstance(i, dict)]


async def collect_snapshot(server: GuardedMCPServer) -> InventorySnapshot:
    """Build an ``InventorySnapshot``. Partial failures are recorded, not fatal."""
    snapshot = InventorySnapshot(captured_at=datetime.now(UTC))

    async def _try(tool: str, args: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        try:
            return _dicts(await server.collect(tool, args or {}))
        except ToolCallFailed as exc:
            snapshot.collection_errors.append(f"{tool}: {exc}")
            return []

    version = await _try("system_version")
    if version:
        snapshot.docker_version = str(version[0].get("Version", ""))
        snapshot.docker_platform = str((version[0].get("Platform") or {}).get("Name", ""))

    # all=True includes stopped containers; non-sparse gives full inspect docs.
    snapshot.containers = [parse_container(d) for d in await _try("container_list", {"all": True})]
    snapshot.images = [parse_image(d) for d in await _try("image_list", {})]
    snapshot.networks = [parse_network(d) for d in await _try("network_list", {})]
    snapshot.volumes = [parse_volume(d) for d in await _try("volume_list", {})]

    finalize_snapshot(snapshot)
    return snapshot


def finalize_snapshot(snapshot: InventorySnapshot) -> InventorySnapshot:
    """Derive cross-references, sort for determinism, and compute the ID.

    ``network_list`` does not include member containers, so membership is
    derived from each container's ``NetworkSettings.Networks``.
    """
    members: dict[str, list[str]] = {}
    for c in snapshot.containers:
        for net in c.networks:
            members.setdefault(net, []).append(c.name)
    for n in snapshot.networks:
        n.containers = sorted(members.get(n.name, []))

    # Stable ordering => stable snapshot hash.
    snapshot.containers.sort(key=lambda c: c.name)
    snapshot.images.sort(key=lambda i: i.id)
    snapshot.networks.sort(key=lambda n: n.name)
    snapshot.volumes.sort(key=lambda v: v.name)
    snapshot.snapshot_id = snapshot.compute_id()
    return snapshot
