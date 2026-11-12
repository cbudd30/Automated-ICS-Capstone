"""Typed Docker assets and the inventory snapshot.

``docker inspect`` output is large and deeply nested. The parsers in
``inventory/parsers.py`` copy the *security-relevant* fields into these flat,
typed models so the rule engine and the report never have to dig through raw
JSON. The raw inspect document is kept alongside in
``raw`` so evidence can always be traced back to the original field.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PortBinding(BaseModel):
    """One published port: container port -> host IP:port."""

    container_port: str  # e.g. "80"
    protocol: str  # tcp / udp / sctp
    host_ip: str  # "" or "0.0.0.0" or "::" means all interfaces
    host_port: str

    @property
    def all_interfaces(self) -> bool:
        """True when the port is reachable on every host interface."""
        return self.host_ip in ("", "0.0.0.0", "::")


class MountInfo(BaseModel):
    """One mount (bind mount, named volume, or tmpfs)."""

    type: str  # bind / volume / tmpfs / npipe
    source: str  # host path (bind) or volume name
    destination: str  # path inside the container
    read_write: bool  # False = mounted read-only


class ContainerAsset(BaseModel):
    """Security-relevant view of one container (from ``docker inspect``)."""

    id: str
    name: str
    image_ref: str  # image as written by the user, e.g. "fortiphyd/grfics-plc"
    image_id: str  # sha256:... content ID of the image actually used
    state: str  # running / exited / restarting / ...
    created: str = ""
    # --- identity & privileges
    user: str = ""  # Config.User ("" means the image default, usually root)
    privileged: bool = False
    cap_add: list[str] = Field(default_factory=list)
    cap_drop: list[str] = Field(default_factory=list)
    security_opt: list[str] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)  # host device paths
    # --- namespaces ("host" means the host's namespace is shared)
    network_mode: str = ""
    pid_mode: str = ""
    ipc_mode: str = ""
    uts_mode: str = ""
    userns_mode: str = ""
    # --- filesystem
    readonly_rootfs: bool = False
    mounts: list[MountInfo] = Field(default_factory=list)
    # --- network
    ports: list[PortBinding] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)  # network names
    ip_addresses: dict[str, str] = Field(default_factory=dict)  # network -> IP
    sysctls: dict[str, str] = Field(default_factory=dict)
    # --- resources
    memory_limit: int = 0  # bytes, 0 = unlimited
    nano_cpus: int = 0  # 1e9 = one CPU, 0 = unlimited
    cpu_quota: int = 0
    pids_limit: int | None = None  # None/0/-1 = unlimited
    restart_policy: str = ""
    # --- metadata
    env_names: list[str] = Field(default_factory=list)  # names only, never values
    labels: dict[str, str] = Field(default_factory=dict)
    compose_project: str | None = None
    compose_service: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @property
    def running(self) -> bool:
        return self.state == "running"


class ImageAsset(BaseModel):
    """Security-relevant view of one local image (from ``docker image inspect``)."""

    id: str  # sha256:...
    tags: list[str] = Field(default_factory=list)  # repo:tag names
    digests: list[str] = Field(default_factory=list)  # repo@sha256:... (immutable)
    created: str = ""
    architecture: str = ""
    os: str = ""
    size: int = 0
    user: str = ""  # default USER baked into the image
    exposed_ports: list[str] = Field(default_factory=list)
    env_names: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @property
    def display_name(self) -> str:
        """Human-friendly name: first tag, else the short image ID."""
        return self.tags[0] if self.tags else self.id.removeprefix("sha256:")[:12]

    @property
    def digest(self) -> str | None:
        """Immutable content digest, if the image has one."""
        return self.digests[0] if self.digests else None


class NetworkAsset(BaseModel):
    """One Docker network."""

    id: str
    name: str
    driver: str = ""  # bridge / macvlan / host / overlay / null
    scope: str = ""
    internal: bool = False  # True = no route to the outside world
    attachable: bool = False
    subnets: list[str] = Field(default_factory=list)
    gateways: list[str] = Field(default_factory=list)
    containers: list[str] = Field(default_factory=list)  # names (derived from containers)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


class VolumeAsset(BaseModel):
    """One named Docker volume."""

    name: str
    driver: str = ""
    mountpoint: str = ""
    scope: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    created: str = ""  # CreatedAt; shows whether a range reset recreated the volume


class InventorySnapshot(BaseModel):
    """Everything collected from Docker at one point in time.

    The ``snapshot_id`` is a content hash, so two collections of an unchanged
    environment produce the same ID. Model-comparison runs reuse a snapshot
    by ID to guarantee every model sees identical evidence.
    """

    snapshot_id: str = ""
    captured_at: datetime
    docker_version: str = ""
    docker_platform: str = ""
    containers: list[ContainerAsset] = Field(default_factory=list)
    images: list[ImageAsset] = Field(default_factory=list)
    networks: list[NetworkAsset] = Field(default_factory=list)
    volumes: list[VolumeAsset] = Field(default_factory=list)
    collection_errors: list[str] = Field(default_factory=list)

    def compute_id(self) -> str:
        """Hash the parsed, security-relevant data (not timestamps) into a stable ID.

        The ``raw`` inspect documents are excluded on purpose: they contain
        volatile values (health-check logs, PIDs, start times) that change
        every few seconds without any configuration change.
        """
        payload = self.model_dump(
            mode="json",
            exclude={
                "snapshot_id": True,
                "captured_at": True,
                "containers": {"__all__": {"raw", "created"}},
                "images": {"__all__": {"raw"}},
                "networks": {"__all__": {"raw"}},
                "volumes": {"__all__": {"created"}},
            },
        )
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return f"snap-{digest[:16]}"

    # ---- lookup helpers used by rules and policy

    def image_by_id(self, image_id: str) -> ImageAsset | None:
        return next((i for i in self.images if i.id == image_id), None)

    def container_by_name(self, name: str) -> ContainerAsset | None:
        name = name.lstrip("/")
        return next((c for c in self.containers if c.name == name or c.id.startswith(name)), None)

    def used_image_ids(self) -> list[str]:
        """Image IDs referenced by at least one container (stable order)."""
        seen: dict[str, None] = {}
        for c in self.containers:
            if c.image_id:
                seen.setdefault(c.image_id, None)
        return list(seen)

    def image_references(self) -> set[str]:
        """Every string that legitimately identifies a local image.

        Used by the policy layer to decide whether a Trivy scan target is
        "in inventory": full IDs, short IDs, tags and digests all count.
        """
        refs: set[str] = set()
        for img in self.images:
            refs.add(img.id)
            refs.add(img.id.removeprefix("sha256:"))
            refs.add(img.id.removeprefix("sha256:")[:12])
            refs.update(img.tags)
            refs.update(img.digests)
        for c in self.containers:
            if c.image_ref:
                refs.add(c.image_ref)
        return refs

