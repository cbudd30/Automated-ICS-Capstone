"""Deterministic security rules.

Each rule is a small, pure Python function that looks at typed assets from the
inventory snapshot and returns zero or more ``Finding`` objects. No LLM is
involved, so these findings are *confirmed* facts with ``high`` confidence
(unless the rule is a heuristic, in which case it says so).

How rules are organised
-----------------------
* The ``@rule(...)`` decorator registers a function in ``RULES`` together with
  its metadata (ID, title, category, default severity, scope).
* ``scope`` decides what the function receives:
    - ``"container"`` -> called once per container: fn(container, ctx)
    - ``"network"``   -> called once per network:   fn(network, ctx)
    - ``"image"``     -> called once per *used* image: fn(image, ctx)
* ``evaluate(snapshot, config)`` runs every enabled rule and returns the
  findings sorted most-severe first.
* Severities can be overridden and rules disabled in
  ``config/security_rules.yaml`` without touching this code.

Rule ID prefixes:  C container | N network | R resources | S secrets hygiene
                   I image hygiene     (V = vulnerabilities, see scanner.py)

Every finding includes ``Evidence`` with the exact inspect field path and the
observed value, so a reviewer can reproduce it with ``docker inspect``.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from docker_security_agent.config import RulesConfig
from docker_security_agent.schemas.assets import (
    ContainerAsset,
    ImageAsset,
    InventorySnapshot,
    NetworkAsset,
)
from docker_security_agent.schemas.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from docker_security_agent.security.findings import make_finding

# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    category: Category
    severity: Severity  # default; may be overridden in config
    scope: str  # container | network | image
    func: Callable[..., list[Finding]]


RULES: dict[str, RuleMeta] = {}


def rule(
    rule_id: str, title: str, category: Category, severity: Severity, scope: str = "container"
):
    """Decorator that registers a rule function in ``RULES``."""

    def decorator(func: Callable[..., list[Finding]]) -> Callable[..., list[Finding]]:
        RULES[rule_id] = RuleMeta(rule_id, title, category, severity, scope, func)
        return func

    return decorator


@dataclass
class RuleContext:
    """What a rule function can see besides the asset it is evaluating."""

    config: RulesConfig
    snapshot: InventorySnapshot

    def severity(self, rule_id: str, default: Severity | None = None) -> Severity:
        """Apply a configured severity override, else use the rule's default."""
        override = self.config.severity_overrides.get(rule_id)
        if override:
            return Severity(override)
        return default or RULES[rule_id].severity


# ---------------------------------------------------------------------------
# Small helpers used by several rules
# ---------------------------------------------------------------------------


def _ev(c: ContainerAsset, path: str, value: Any, note: str = "") -> Evidence:
    """Evidence read from a container's inspect document."""
    return Evidence(
        source="docker_inspect", resource=c.name, path=path, value=str(value), note=note
    )


def _c_finding(
    ctx: RuleContext,
    rule_id: str,
    c: ContainerAsset,
    *,
    evidence: list[Evidence],
    explanation: str,
    remediation: str,
    detail: str = "",
    severity: Severity | None = None,
    confidence: Confidence = Confidence.HIGH,
    title: str | None = None,
) -> Finding:
    """Build a container-scoped finding from the rule's registered metadata."""
    meta = RULES[rule_id]
    state_note = "" if c.running else f" (container is currently {c.state})"
    return make_finding(
        rule_id=rule_id,
        title=(title or meta.title) + state_note,
        resource_type="container",
        resource_name=c.name,
        resource_id=c.id,
        category=meta.category,
        severity=ctx.severity(rule_id, severity),
        confidence=confidence,
        evidence=evidence,
        explanation=explanation,
        remediation=remediation,
        detail=detail,
    )


def _normalise_host_path(path: str) -> str:
    """Docker Desktop for Mac reports bind sources as /host_mnt/Users/...; strip that."""
    return path.removeprefix("/host_mnt") or "/"


def _is_under(path: str, root: str) -> bool:
    """True if ``path`` equals ``root`` or is inside it. '/' only matches exactly."""
    if root == "/":
        return path == "/"
    return path == root or path.startswith(root.rstrip("/") + "/")


def _effective_user(c: ContainerAsset, snapshot: InventorySnapshot) -> tuple[str, str]:
    """Return (user, where-it-came-from). Docker falls back to the image's USER."""
    if c.user:
        return c.user, "Config.User"
    image = snapshot.image_by_id(c.image_id)
    if image and image.user:
        return image.user, "image Config.User"
    return "", "not set (defaults to root)"


def _has_opt(c: ContainerAsset, *needles: str) -> list[str]:
    """SecurityOpt entries containing any of ``needles`` (':' and '=' both used)."""
    hits = []
    for opt in c.security_opt:
        normalised = opt.replace(":", "=").lower()
        if any(n in normalised for n in needles):
            hits.append(opt)
    return hits


# ---------------------------------------------------------------------------
# Container: privileges & isolation
# ---------------------------------------------------------------------------


@rule("C001", "Container runs in privileged mode", Category.PRIVILEGE, Severity.CRITICAL)
def privileged_mode(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if not c.privileged:
        return []
    return [
        _c_finding(
            ctx,
            "C001",
            c,
            evidence=[_ev(c, "HostConfig.Privileged", True)],
            explanation=(
                "A privileged container gets all Linux capabilities, access to every host "
                "device and no seccomp/AppArmor confinement. Compromise of the process is "
                "effectively compromise of the Docker host - and of every other ICS "
                "component running on it."
            ),
            remediation=(
                "Remove `privileged: true`. Grant only the specific capabilities the "
                "workload needs with `cap_add`, and map individual devices with `devices:`."
            ),
        )
    ]


@rule("C002", "Container adds dangerous Linux capabilities", Category.PRIVILEGE, Severity.HIGH)
def dangerous_capabilities(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    dangerous = ctx.config.dangerous_capabilities
    hits = [cap for cap in c.cap_add if cap in dangerous]
    if not hits:
        return []
    # Severity = the most severe capability added.
    sev = Severity.max([Severity(dangerous[cap]) for cap in hits])
    notes = {
        "NET_ADMIN": "can reconfigure interfaces, routes and firewall rules",
        "NET_RAW": "can craft raw packets (spoofing, ARP poisoning on the ICS segment)",
        "SYS_ADMIN": "near-root; enables many container-escape techniques",
        "SYS_PTRACE": "can inspect/modify other processes",
        "SYS_MODULE": "can load kernel modules",
        "ALL": "every capability - equivalent to privileged",
    }
    return [
        _c_finding(
            ctx,
            "C002",
            c,
            severity=sev,
            detail=",".join(sorted(hits)),
            title=f"Container adds dangerous capabilities: {', '.join(sorted(hits))}",
            evidence=[_ev(c, "HostConfig.CapAdd", cap, notes.get(cap, "")) for cap in sorted(hits)],
            explanation=(
                "Added capabilities widen what a compromised process can do to the host "
                "kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to "
                "the process network allow traffic manipulation between PLCs and HMIs."
            ),
            remediation=(
                "Remove capabilities that are not strictly required. Start from "
                "`cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN "
                "is only used at start-up (e.g. to add routes), configure networking "
                "outside the container instead."
            ),
        )
    ]


@rule("C003", "Container runs as root", Category.PRIVILEGE, Severity.MEDIUM)
def runs_as_root(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    user, origin = _effective_user(c, ctx.snapshot)
    if user.split(":")[0] not in ("", "root", "0"):
        return []
    return [
        _c_finding(
            ctx,
            "C003",
            c,
            evidence=[_ev(c, "Config.User", user or "<empty>", origin)],
            explanation=(
                "The main process runs as UID 0. Combined with any added capability, "
                "writable mount or kernel bug, root inside the container makes escape and "
                "host compromise significantly easier."
            ),
            remediation=(
                'Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in '
                "compose) and fix file ownership so the service runs unprivileged. Consider "
                "user-namespace remapping (`userns-remap`) on the daemon."
            ),
        )
    ]


_NAMESPACES = [
    (
        "network_mode",
        "HostConfig.NetworkMode",
        "network",
        "shares the host network stack: it can bind any host port and sniff host traffic",
    ),
    ("pid_mode", "HostConfig.PidMode", "PID", "can see and signal every process on the host"),
    ("ipc_mode", "HostConfig.IpcMode", "IPC", "shares host shared memory / semaphores"),
    ("uts_mode", "HostConfig.UTSMode", "UTS", "can change the host's hostname"),
    ("userns_mode", "HostConfig.UsernsMode", "user", "opts out of user-namespace remapping"),
]


@rule("C004", "Container shares a host namespace", Category.ISOLATION, Severity.HIGH)
def host_namespaces(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    findings = []
    for attr, path, label, impact in _NAMESPACES:
        if getattr(c, attr) == "host":
            findings.append(
                _c_finding(
                    ctx,
                    "C004",
                    c,
                    detail=label,
                    title=f"Container shares the host {label} namespace",
                    evidence=[_ev(c, path, "host")],
                    explanation=f"The container {impact}. Namespace isolation is one of the "
                    "core container boundaries; sharing it removes that boundary.",
                    remediation=f"Remove `{path.split('.')[-1]}: host` (compose: "
                    f"`{attr.replace('_mode', '')}: host`) and use Docker networking / "
                    "explicit port publishing instead.",
                )
            )
    return findings


@rule(
    "C005", "Container disables a kernel security profile", Category.SECURITY_PROFILE, Severity.HIGH
)
def security_profile_disabled(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    hits = _has_opt(
        c, "seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"
    )
    if not hits:
        return []
    return [
        _c_finding(
            ctx,
            "C005",
            c,
            detail=",".join(hits),
            evidence=[_ev(c, "HostConfig.SecurityOpt", h) for h in hits],
            explanation=(
                "seccomp, AppArmor and SELinux labels restrict which kernel features a "
                "container can use. Disabling them exposes the full kernel attack surface."
            ),
            remediation="Remove the `*:unconfined` / `label:disable` security_opt entries; "
            "if a syscall is genuinely needed, write a custom seccomp profile that allows it.",
        )
    ]


@rule("C006", "no-new-privileges is not set", Category.SECURITY_PROFILE, Severity.LOW)
def no_new_privileges(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if _has_opt(c, "no-new-privileges"):
        enabled = [o for o in _has_opt(c, "no-new-privileges") if "false" not in o.lower()]
        if enabled:
            return []
    return [
        _c_finding(
            ctx,
            "C006",
            c,
            evidence=[_ev(c, "HostConfig.SecurityOpt", c.security_opt or "[]")],
            explanation=(
                "Without no-new-privileges, setuid/setgid binaries inside the container can "
                "raise a process's privileges."
            ),
            remediation='Add `security_opt: ["no-new-privileges:true"]`.',
        )
    ]


@rule("C007", "Root filesystem is writable", Category.FILESYSTEM, Severity.LOW)
def writable_rootfs(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if c.readonly_rootfs:
        return []
    return [
        _c_finding(
            ctx,
            "C007",
            c,
            evidence=[_ev(c, "HostConfig.ReadonlyRootfs", False)],
            explanation=(
                "A writable root filesystem lets an attacker persist tools or modify "
                "binaries/configuration (e.g. PLC logic or HMI screens) inside the container."
            ),
            remediation="Set `read_only: true` and mount `tmpfs` / named volumes only for "
            "the paths that must be writable.",
        )
    ]


@rule("C008", "Docker socket is mounted into the container", Category.FILESYSTEM, Severity.CRITICAL)
def docker_socket_mount(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    hits = [
        m
        for m in c.mounts
        if _normalise_host_path(m.source) in ctx.config.docker_socket_paths
        or m.source.endswith("docker.sock")
    ]
    if not hits:
        return []
    return [
        _c_finding(
            ctx,
            "C008",
            c,
            detail=",".join(m.source for m in hits),
            evidence=[
                _ev(
                    c,
                    "Mounts",
                    f"{m.source} -> {m.destination} ({'rw' if m.read_write else 'ro'})",
                    "even a read-only mount of the socket allows full API use",
                )
                for m in hits
            ],
            explanation=(
                "The Docker API socket grants full control of the Docker daemon: anyone who "
                "controls this container can start a privileged container that mounts the "
                "host filesystem, i.e. root on the host and control of every ICS component. "
                "Mounting it ':ro' does NOT help - it only makes the socket file read-only, "
                "not the API."
            ),
            remediation=(
                "Remove the socket mount. If the service needs Docker metadata (e.g. a "
                "version/status page), give it a filtered read-only proxy such as "
                "tecnativa/docker-socket-proxy with POST=0 and only the needed API sections."
            ),
        )
    ]


def _sensitive_match(src: str, config: RulesConfig) -> str | None:
    """Return why a bind-mount source is sensitive, or None if it is not.

    Three cases:
      1. system paths (/etc, /proc, ...): the path or anything below it;
      2. a home-directory root itself or a user's whole home (/Users, /Users/alice);
      3. credential directories inside a home (/Users/alice/.ssh, .../.aws, ...).
    Ordinary project/data directories inside a home directory are NOT sensitive.
    """
    for path in config.sensitive_host_paths:
        if _is_under(src, path):
            return path
    for root in config.home_directory_roots:
        if not _is_under(src, root):
            continue
        # parts after the root: ["alice", ".ssh", ...]
        rest = [p for p in src[len(root.rstrip("/")) :].split("/") if p]
        if len(rest) <= 1:
            return f"{root} (entire home directory)"
        inside_home = "/".join(rest[1:])
        for sub in config.sensitive_home_subpaths:
            if inside_home == sub or inside_home.startswith(sub.rstrip("/") + "/"):
                return f"~/{sub} (credentials)"
    return None


@rule("C009", "Sensitive host path is bind-mounted", Category.FILESYSTEM, Severity.HIGH)
def sensitive_bind_mounts(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    findings = []
    for m in c.mounts:
        if m.type != "bind":
            continue
        src = _normalise_host_path(m.source)
        if src in ctx.config.docker_socket_paths or src.endswith("docker.sock"):
            continue  # reported by C008
        match = _sensitive_match(src, ctx.config)
        if not match:
            continue
        sev = Severity.HIGH if m.read_write else Severity.MEDIUM
        findings.append(
            _c_finding(
                ctx,
                "C009",
                c,
                severity=sev,
                detail=src,
                title=f"Sensitive host path bind-mounted: {src}",
                evidence=[
                    _ev(
                        c,
                        "Mounts",
                        f"{m.source} -> {m.destination} ({'rw' if m.read_write else 'ro'})",
                        f"sensitive: {match}",
                    )
                ],
                explanation=(
                    "Host directories mounted into a container expose host configuration, "
                    "credentials or kernel interfaces; a writable mount lets the container "
                    "modify the host."
                ),
                remediation="Mount only the specific files needed, read-only (`:ro`), or use "
                "a named volume instead of a host path.",
            )
        )
    return findings


@rule("C010", "No capabilities are dropped", Category.PRIVILEGE, Severity.LOW)
def no_cap_drop(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if c.privileged or c.cap_drop:
        return []
    return [
        _c_finding(
            ctx,
            "C010",
            c,
            confidence=Confidence.MEDIUM,
            evidence=[_ev(c, "HostConfig.CapDrop", "null")],
            explanation=(
                "The container keeps Docker's full default capability set (incl. NET_RAW, "
                "CHOWN, SETUID...). Most services need none of these."
            ),
            remediation="Add `cap_drop: [ALL]` and re-add only required capabilities.",
        )
    ]


@rule("C011", "Host devices are mapped into the container", Category.PRIVILEGE, Severity.MEDIUM)
def host_devices(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if not c.devices:
        return []
    return [
        _c_finding(
            ctx,
            "C011",
            c,
            detail=",".join(c.devices),
            evidence=[_ev(c, "HostConfig.Devices", d) for d in c.devices],
            explanation="Direct device access bypasses container isolation for that device.",
            remediation="Remove device mappings that are not required; prefer read-only "
            "access via device cgroup rules (`r` only).",
        )
    ]


# ---------------------------------------------------------------------------
# Container: network exposure
# ---------------------------------------------------------------------------


@rule("N001", "Ports published on all host interfaces", Category.NETWORK_EXPOSURE, Severity.LOW)
def published_ports(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    exposed = [p for p in c.ports if p.all_interfaces and p.host_port]
    if not exposed:
        return []
    return [
        _c_finding(
            ctx,
            "N001",
            c,
            detail=",".join(f"{p.host_port}/{p.protocol}" for p in exposed),
            evidence=[
                _ev(
                    c,
                    "HostConfig.PortBindings",
                    f"{p.host_ip or '0.0.0.0'}:{p.host_port} -> {p.container_port}/{p.protocol}",
                )
                for p in exposed
            ],
            explanation=(
                "These ports are reachable from every network the Docker host is attached "
                "to. This is an EXPOSURE observation, not a vulnerability by itself: risk "
                "depends on the service behind the port (see image vulnerabilities and "
                "authentication). ICS management interfaces (HMI, PLC web UI, engineering "
                "tools) should not be reachable from untrusted networks."
            ),
            remediation=(
                "Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or "
                "remove the port mapping and reach the service via an internal network / "
                "jump host."
            ),
        )
    ]


@rule("N002", "Container bridges multiple networks", Category.NETWORK_SEGMENTATION, Severity.MEDIUM)
def multi_network(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if c.network_mode in ("host", "none") or len(c.networks) < 2:
        return []
    return [
        _c_finding(
            ctx,
            "N002",
            c,
            detail=",".join(c.networks),
            confidence=Confidence.MEDIUM,
            evidence=[
                _ev(c, f"NetworkSettings.Networks.{n}", c.ip_addresses.get(n, "attached"))
                for n in c.networks
            ],
            explanation=(
                "A container attached to several networks is a potential bridge between "
                "segmentation zones (e.g. DMZ <-> process network). If it is compromised, "
                "an attacker can pivot across zones that the network design intends to keep "
                "apart. Whether this is intended (a router/firewall) needs human review."
            ),
            remediation=(
                "Attach the container only to the networks it must serve. Route inter-zone "
                "traffic through a dedicated, hardened firewall container and keep "
                "management networks separate from ICS process networks."
            ),
        )
    ]


@rule(
    "N003",
    "IP forwarding enabled inside the container",
    Category.NETWORK_SEGMENTATION,
    Severity.MEDIUM,
)
def ip_forwarding(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    hits = {k: v for k, v in c.sysctls.items() if "forward" in k and v.strip() == "1"}
    if not hits:
        return []
    return [
        _c_finding(
            ctx,
            "N003",
            c,
            evidence=[_ev(c, f"HostConfig.Sysctls.{k}", v) for k, v in hits.items()],
            explanation=(
                "The container routes packets between its interfaces. Expected for a "
                "router/firewall container, but it makes this container a critical "
                "segmentation control: its rule set and hardening determine whether zones "
                "are actually isolated."
            ),
            remediation="Confirm this container is the intended router; harden and monitor "
            "it, restrict its management interface, and disable forwarding elsewhere.",
        )
    ]


@rule(
    "N004", "Container uses the default bridge network", Category.NETWORK_SEGMENTATION, Severity.LOW
)
def default_bridge(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if "bridge" not in c.networks:
        return []
    return [
        _c_finding(
            ctx,
            "N004",
            c,
            evidence=[_ev(c, "NetworkSettings.Networks", "bridge")],
            explanation=(
                "All containers on the default `bridge` network can reach each other, so "
                "unrelated workloads are not segmented."
            ),
            remediation="Place the container on a dedicated user-defined network.",
        )
    ]


@rule(
    "N005",
    "User-defined network allows external egress",
    Category.NETWORK_SEGMENTATION,
    Severity.INFO,
    scope="network",
)
def network_not_internal(n: NetworkAsset, ctx: RuleContext) -> list[Finding]:
    if n.name in ("bridge", "host", "none") or n.internal or n.driver in ("host", "null"):
        return []
    return [
        make_finding(
            rule_id="N005",
            title=f"Network '{n.name}' is not internal (has external egress)",
            resource_type="network",
            resource_name=n.name,
            resource_id=n.id,
            category=Category.NETWORK_SEGMENTATION,
            severity=ctx.severity("N005"),
            confidence=Confidence.HIGH,
            evidence=[
                Evidence(
                    source="docker_network", resource=n.name, path="Internal", value=str(n.internal)
                ),
                Evidence(source="docker_network", resource=n.name, path="Driver", value=n.driver),
                Evidence(
                    source="docker_network",
                    resource=n.name,
                    path="Containers",
                    value=", ".join(n.containers) or "none",
                ),
            ],
            explanation=(
                "Containers on this network can open outbound connections through the host. "
                "ICS process networks normally should not reach the internet."
            ),
            remediation="For process/control networks set `internal: true` and provide any "
            "required external access through an explicit, monitored gateway.",
        )
    ]


# ---------------------------------------------------------------------------
# Container: resources
# ---------------------------------------------------------------------------


@rule("R001", "Missing resource limits", Category.RESOURCES, Severity.LOW)
def resource_limits(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    missing = []
    evidence = []
    if not c.memory_limit:
        missing.append("memory")
        evidence.append(_ev(c, "HostConfig.Memory", 0, "0 = unlimited"))
    if not c.nano_cpus and not c.cpu_quota:
        missing.append("cpu")
        evidence.append(_ev(c, "HostConfig.NanoCpus", 0, "0 = unlimited"))
    if c.pids_limit in (None, 0, -1):
        missing.append("pids")
        evidence.append(_ev(c, "HostConfig.PidsLimit", c.pids_limit, "null/0/-1 = unlimited"))
    if not missing:
        return []
    return [
        _c_finding(
            ctx,
            "R001",
            c,
            detail=",".join(missing),
            title=f"Missing resource limits: {', '.join(missing)}",
            evidence=evidence,
            explanation=(
                "Without limits, one runaway or compromised container can exhaust host "
                "memory/CPU/PIDs and starve every other ICS component (availability is the "
                "top priority in OT environments)."
            ),
            remediation="Set `mem_limit`, `cpus` and `pids_limit` (compose) or "
            "`deploy.resources.limits` appropriate to each service.",
        )
    ]


@rule("R002", "No restart policy", Category.RESOURCES, Severity.INFO)
def restart_policy(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    if c.restart_policy not in ("", "no"):
        return []
    return [
        _c_finding(
            ctx,
            "R002",
            c,
            evidence=[_ev(c, "HostConfig.RestartPolicy.Name", c.restart_policy or "no")],
            explanation="The container will not be restarted automatically after a crash or "
            "host reboot, which may affect availability of the simulated process.",
            remediation="Use `restart: unless-stopped` for services that must stay available.",
        )
    ]


# ---------------------------------------------------------------------------
# Secrets hygiene
# ---------------------------------------------------------------------------


@rule("S001", "Credential-like environment variables", Category.SECRETS_HYGIENE, Severity.MEDIUM)
def secret_env_names(c: ContainerAsset, ctx: RuleContext) -> list[Finding]:
    patterns = [p.lower() for p in ctx.config.secret_env_name_patterns]
    hits = sorted(
        n for n in c.env_names if any(fnmatch.fnmatchcase(n.lower(), p) for p in patterns)
    )
    if not hits:
        return []
    return [
        _c_finding(
            ctx,
            "S001",
            c,
            detail=",".join(hits),
            confidence=Confidence.MEDIUM,
            title=f"Credential-like environment variables: {', '.join(hits)}",
            evidence=[_ev(c, "Config.Env", n, "variable name; value not reported") for n in hits],
            explanation=(
                "Secrets passed as environment variables are visible to anyone who can "
                "inspect the container (docker inspect, /proc/<pid>/environ) and often leak "
                "into logs and crash dumps. The name alone indicates a likely credential."
            ),
            remediation="Use Docker secrets / mounted secret files with restricted "
            "permissions, and rotate any credential that was exposed via the environment.",
        )
    ]


# ---------------------------------------------------------------------------
# Image hygiene
# ---------------------------------------------------------------------------


def _image_users(image: ImageAsset, snapshot: InventorySnapshot) -> list[str]:
    return sorted(c.name for c in snapshot.containers if c.image_id == image.id)


@rule("I001", "Image is not pinned to a version tag", Category.IMAGE_HYGIENE, Severity.LOW, "image")
def image_latest(image: ImageAsset, ctx: RuleContext) -> list[Finding]:
    floating = [t for t in image.tags if t.endswith(":latest")]
    if image.tags and not floating:
        return []
    value = ", ".join(floating) if floating else "<untagged>"
    return [
        make_finding(
            rule_id="I001",
            title=f"Image uses a floating tag: {value}",
            resource_type="image",
            resource_name=image.display_name,
            resource_id=image.id,
            category=Category.IMAGE_HYGIENE,
            severity=ctx.severity("I001"),
            evidence=[
                Evidence(
                    source="docker_image_inspect",
                    resource=image.display_name,
                    path="RepoTags",
                    value=value,
                ),
                Evidence(
                    source="docker_image_inspect",
                    resource=image.display_name,
                    path="used_by",
                    value=", ".join(_image_users(image, ctx.snapshot)),
                ),
            ],
            explanation=(
                "`latest`/untagged images change silently when rebuilt or re-pulled, so the "
                "deployed software (and its vulnerabilities) is not reproducible or auditable."
            ),
            remediation="Pin images to an explicit version tag and, ideally, an immutable "
            "digest (`image: repo/name:1.2.3@sha256:...`).",
        )
    ]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _container_in_scope(c: ContainerAsset, config: RulesConfig) -> bool:
    if any(fnmatch.fnmatchcase(c.name, p) for p in config.ignore_containers):
        return False
    return config.include_stopped_containers or c.running


def evaluate(snapshot: InventorySnapshot, config: RulesConfig) -> list[Finding]:
    """Run every enabled rule against the snapshot; return findings, most severe first."""
    ctx = RuleContext(config=config, snapshot=snapshot)
    containers = [c for c in snapshot.containers if _container_in_scope(c, config)]
    used_ids = {c.image_id for c in containers}
    used_images = [i for i in snapshot.images if i.id in used_ids]

    findings: list[Finding] = []
    for meta in RULES.values():
        if meta.rule_id in config.disabled_rules:
            continue
        targets: list[Any]
        if meta.scope == "container":
            targets = containers
        elif meta.scope == "network":
            targets = snapshot.networks
        elif meta.scope == "image":
            targets = used_images
        else:  # pragma: no cover - guarded by the decorator usage above
            continue
        for target in targets:
            findings.extend(meta.func(target, ctx))

    # De-duplicate by ID (defensive; IDs are deterministic) and sort.
    unique = {f.id: f for f in findings}
    return sorted(unique.values(), key=lambda f: f.sort_key())
