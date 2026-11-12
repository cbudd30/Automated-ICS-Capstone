"""Parse raw Docker API documents into typed assets.

Each ``parse_*`` function takes one JSON document exactly as docker-mcp-server
returns it (which is the Docker Engine API's inspect format) and returns the
matching model from ``schemas/assets.py``.

Docker's JSON uses ``null`` liberally (e.g. ``"CapAdd": null``), so every
lookup is written defensively with ``or {}`` / ``or []``.
"""

from __future__ import annotations

from typing import Any

from docker_security_agent.schemas.assets import (
    ContainerAsset,
    ImageAsset,
    MountInfo,
    NetworkAsset,
    PortBinding,
    VolumeAsset,
)


def _env_names(env: list[str] | None) -> list[str]:
    """["A=1", "B=2"] -> ["A", "B"]  (values are never kept)."""
    return [e.split("=", 1)[0] for e in env or [] if isinstance(e, str)]


def _normalise_cap(cap: str) -> str:
    """Docker accepts both "NET_ADMIN" and "CAP_NET_ADMIN"; normalise to the former."""
    return cap.upper().removeprefix("CAP_")


def parse_container(doc: dict[str, Any]) -> ContainerAsset:
    """Full ``docker inspect <container>`` document -> ContainerAsset."""
    cfg = doc.get("Config") or {}
    host = doc.get("HostConfig") or {}
    state = doc.get("State") or {}
    net_settings = doc.get("NetworkSettings") or {}
    networks = net_settings.get("Networks") or {}
    labels = cfg.get("Labels") or {}

    # Published ports live in HostConfig.PortBindings:
    #   {"80/tcp": [{"HostIp": "", "HostPort": "80"}]}
    ports: list[PortBinding] = []
    for cport, bindings in (host.get("PortBindings") or {}).items():
        port, _, proto = cport.partition("/")
        for b in bindings or []:
            ports.append(
                PortBinding(
                    container_port=port,
                    protocol=proto or "tcp",
                    host_ip=b.get("HostIp") or "",
                    host_port=str(b.get("HostPort") or ""),
                )
            )

    # Mounts: the top-level "Mounts" array covers binds, volumes and tmpfs.
    mounts = [
        MountInfo(
            type=m.get("Type", ""),
            source=m.get("Source") or m.get("Name") or "",
            destination=m.get("Destination", ""),
            read_write=bool(m.get("RW", True)),
        )
        for m in doc.get("Mounts") or []
    ]

    devices = [d.get("PathOnHost", "") for d in host.get("Devices") or [] if d.get("PathOnHost")]

    return ContainerAsset(
        id=doc.get("Id", ""),
        name=(doc.get("Name") or "").lstrip("/"),
        image_ref=cfg.get("Image", ""),
        image_id=doc.get("Image", ""),
        state=state.get("Status", "unknown"),
        created=doc.get("Created", ""),
        user=cfg.get("User") or "",
        privileged=bool(host.get("Privileged")),
        cap_add=[_normalise_cap(c) for c in host.get("CapAdd") or []],
        cap_drop=[_normalise_cap(c) for c in host.get("CapDrop") or []],
        security_opt=list(host.get("SecurityOpt") or []),
        devices=devices,
        network_mode=host.get("NetworkMode") or "",
        pid_mode=host.get("PidMode") or "",
        ipc_mode=host.get("IpcMode") or "",
        uts_mode=host.get("UTSMode") or "",
        userns_mode=host.get("UsernsMode") or "",
        readonly_rootfs=bool(host.get("ReadonlyRootfs")),
        # Docker returns Mounts (and sometimes port bindings) in a different
        # order on each call; sort so the snapshot hash only changes when the
        # configuration does.
        mounts=sorted(mounts, key=lambda m: (m.destination, m.source)),
        ports=sorted(ports, key=lambda p: (p.container_port, p.protocol, p.host_ip, p.host_port)),
        networks=sorted(networks.keys()),
        ip_addresses={
            name: n.get("IPAddress", "") for name, n in networks.items() if n.get("IPAddress")
        },
        sysctls={k: str(v) for k, v in (host.get("Sysctls") or {}).items()},
        memory_limit=int(host.get("Memory") or 0),
        nano_cpus=int(host.get("NanoCpus") or 0),
        cpu_quota=int(host.get("CpuQuota") or 0),
        pids_limit=host.get("PidsLimit"),
        restart_policy=((host.get("RestartPolicy") or {}).get("Name") or "no"),
        env_names=_env_names(cfg.get("Env")),
        labels=labels,
        compose_project=labels.get("com.docker.compose.project"),
        compose_service=labels.get("com.docker.compose.service"),
        raw=doc,
    )


def parse_image(doc: dict[str, Any]) -> ImageAsset:
    """``docker image inspect`` document -> ImageAsset."""
    cfg = doc.get("Config") or {}
    tags = [t for t in doc.get("RepoTags") or [] if t and t != "<none>:<none>"]
    digests = [d for d in doc.get("RepoDigests") or [] if d and "<none>" not in d]
    # The raw image config is big (layer list, history); keep only what's useful.
    slim_raw = {
        "Id": doc.get("Id"),
        "RepoTags": tags,
        "RepoDigests": digests,
        "Created": doc.get("Created"),
        "Architecture": doc.get("Architecture"),
        "Os": doc.get("Os"),
        "Config": {
            "User": cfg.get("User"),
            "ExposedPorts": cfg.get("ExposedPorts"),
            "Env": cfg.get("Env"),
            "Entrypoint": cfg.get("Entrypoint"),
            "Cmd": cfg.get("Cmd"),
            "Labels": cfg.get("Labels"),
        },
    }
    return ImageAsset(
        id=doc.get("Id", ""),
        tags=tags,
        digests=digests,
        created=doc.get("Created", "") or "",
        architecture=doc.get("Architecture", "") or "",
        os=doc.get("Os", "") or "",
        size=int(doc.get("Size") or 0),
        user=cfg.get("User") or "",
        exposed_ports=sorted((cfg.get("ExposedPorts") or {}).keys()),
        env_names=_env_names(cfg.get("Env")),
        labels=cfg.get("Labels") or {},
        raw=slim_raw,
    )


def parse_network(doc: dict[str, Any]) -> NetworkAsset:
    """``docker network inspect`` / list entry -> NetworkAsset."""
    ipam_cfg = (doc.get("IPAM") or {}).get("Config") or []
    return NetworkAsset(
        id=doc.get("Id", ""),
        name=doc.get("Name", ""),
        driver=doc.get("Driver", "") or "",
        scope=doc.get("Scope", "") or "",
        internal=bool(doc.get("Internal")),
        attachable=bool(doc.get("Attachable")),
        subnets=[c["Subnet"] for c in ipam_cfg if c.get("Subnet")],
        gateways=[c["Gateway"] for c in ipam_cfg if c.get("Gateway")],
        raw={
            k: doc.get(k) for k in ("Name", "Id", "Driver", "Scope", "Internal", "IPAM", "Options")
        },
    )


def parse_volume(doc: dict[str, Any]) -> VolumeAsset:
    """``docker volume inspect`` / list entry -> VolumeAsset."""
    return VolumeAsset(
        name=doc.get("Name", ""),
        driver=doc.get("Driver", "") or "",
        mountpoint=doc.get("Mountpoint", "") or "",
        scope=doc.get("Scope", "") or "",
        labels=doc.get("Labels") or {},
        created=doc.get("CreatedAt", "") or "",
    )
