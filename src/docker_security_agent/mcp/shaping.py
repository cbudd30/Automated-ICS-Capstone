"""Result shaping: make tool results compact and readable for the LLM, losslessly.

Real numbers from docker-mcp-server against a 20-container host:
``container_list`` returns the *full* inspect document of every container,
about 158 KB of JSON. Sending that to a local model would blow its context
window. Trivy is worse: the HIGH+CRITICAL findings of the GRFICS images are
about 990 KB as one-entry-per-CVE JSON.

So, **for agent calls only**, results pass through ``shape_result``. The rule
(harness h2) is: reorganise, never summarise. Nothing that carries security
meaning is dropped or reworded; the full result is stored anyway
(mcp/evidence.py) and the agent can fetch it back by reference.

* ``*_inspect`` documents become one ``Path: value`` line per leaf field,
  using Docker's own field paths (``HostConfig.CapAdd: [NET_ADMIN, NET_RAW]``),
  so the agent's evidence names the exact Docker field it read. Only the
  internal identifiers in ``INSPECT_NOISE`` are removed.
* Trivy ``findings_list`` pages are grouped by package (package, version,
  type and path stated once, every CVE listed under it), exact duplicate
  findings are dropped, and the embedded "instructions for the assistant"
  ``meta`` block is removed: it is untrusted text, not scan data.
* list tools stay a one-line-per-resource summary (the agent calls
  ``*_inspect`` for details), rendered as one JSON object per line.
* anything still too long is cut at a line boundary with a marker that names
  the stored reference, never in the middle of an entry.

The application's own collector (inventory/collector.py) does NOT use shaping:
it needs the complete documents for the deterministic rules.
"""

from __future__ import annotations

import json
from typing import Any

# Recorded in run manifests: bump when the shaped form changes.
SHAPING_VERSION = "s2"

# Trivy's numeric severity scale (from trivy-mcp's finding_schema).
TRIVY_SEVERITY = {0: "UNKNOWN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
TRIVY_CATEGORY = {0: "vulnerability", 1: "misconfiguration", 2: "license", 3: "secret"}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Fields removed from inspect documents before the model sees them. The test is
# "is this noise to any security analyst looking at a container?", never "is
# this one of the fields the rules check?". Only internal identifiers pass that test; paths,
# timestamps, MAC addresses and both port views are kept. ``*`` matches one key.
INSPECT_NOISE: dict[str, str] = {
    "NetworkSettings.SandboxID": "Docker's internal ID of the network sandbox",
    "NetworkSettings.SandboxKey": "host path of the sandbox's network namespace handle",
    "NetworkSettings.Networks.*.EndpointID": "internal endpoint ID; the network is named by key",
    "NetworkSettings.Networks.*.NetworkID": "internal network ID; the network is named by key",
}
_NOISE_PATTERNS = [p.split(".") for p in INSPECT_NOISE]

# Trivy finding fields left out of the shaped text (still in the stored result).
TRIVY_NOISE: dict[str, str] = {
    "key": "trivy-mcp's internal per-row handle for findings_get; not a property of the CVE",
}

_INSPECT_TOOLS = {"container_inspect", "image_inspect", "network_inspect", "volume_inspect"}


def _short_id(value: str) -> str:
    return value.removeprefix("sha256:")[:12]


# ---------------------------------------------------------------------------
# Inspect documents -> "Path: value" lines
# ---------------------------------------------------------------------------


def _is_noise(segments: list[str]) -> bool:
    return any(
        len(p) == len(segments) and all(a in ("*", b) for a, b in zip(p, segments, strict=True))
        for p in _NOISE_PATTERNS
    )


def _scalar(value: Any, *, in_list: bool = False) -> str:
    """Render a scalar so that its type and value can be read back unambiguously."""
    if isinstance(value, str):
        quote = (
            value == ""
            or value != value.strip()
            or any(c in value for c in "\n\r\t")
            or (in_list and any(c in value for c in ",[]"))
        )
        if not quote:
            try:  # "true", "42", "null"... would read as another type
                json.loads(value)
                quote = True
            except ValueError:
                pass
        return json.dumps(value) if quote else value
    return json.dumps(value)


def _flatten(node: Any, segments: list[str], out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        if not node:
            out.append((".".join(segments), "{}"))
        for key, value in node.items():
            child = [*segments, str(key)]
            if not _is_noise(child):
                _flatten(value, child, out)
    elif isinstance(node, list):
        if all(not isinstance(v, dict | list) for v in node):
            items = ", ".join(_scalar(v, in_list=True) for v in node)
            out.append((".".join(segments), f"[{items}]"))
            return
        for i, value in enumerate(node):
            indexed = [*segments[:-1], f"{segments[-1]}[{i}]"] if segments else [f"[{i}]"]
            _flatten(value, indexed, out)
    else:
        out.append((".".join(segments), _scalar(node)))


def inspect_lines(doc: dict[str, Any]) -> list[str]:
    """Every leaf of an inspect document as ``Path: value`` (minus ``INSPECT_NOISE``)."""
    pairs: list[tuple[str, str]] = []
    _flatten(doc, [], pairs)
    return [f"{path}: {value}" for path, value in pairs]


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

# trivy-mcp's one-letter keys -> readable names. Unknown keys are passed through.
_TRIVY_KEYS = {
    "i": "key",
    "c": "category",
    "s": "severity",
    "an": "package",
    "av": "installed_version",
    "fv": "fixed_version",
    "fx": "has_fix",
    "at": "artifact_type",
    "ap": "artifact_path",
}


def trivy_finding_readable(f: dict[str, Any]) -> dict[str, Any]:
    """Translate trivy-mcp's compact keys into readable ones (all keys kept)."""
    out: dict[str, Any] = {}
    for key, value in f.items():
        name = _TRIVY_KEYS.get(key, key)
        if name == "severity":
            value = TRIVY_SEVERITY.get(value, value)
        elif name == "category":
            value = TRIVY_CATEGORY.get(value, value)
        out[name] = value
    return out


def _fix_text(f: dict[str, Any]) -> str:
    fixed, has_fix = f.get("fixed_version") or "", f.get("has_fix")
    if fixed and has_fix is not False:
        return f"fix {fixed}"
    if fixed:
        return f"fix {fixed} (has_fix=false)"
    return "no fix" if not has_fix else "fix available (version not given)"


_GROUP_KEYS = ("category", "artifact_type", "artifact_path", "package", "installed_version")
_LINE_KEYS = {"key", "id", "severity", "fixed_version", "has_fix", *_GROUP_KEYS}


def trivy_findings_text(page: dict[str, Any]) -> str:
    """One findings_list page, grouped by package, exact duplicates removed."""
    findings = [trivy_finding_readable(f) for f in page.get("findings") or []]
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        # Exact duplicate = identical in everything but trivy-mcp's per-row key.
        sig = json.dumps({k: v for k, v in f.items() if k not in TRIVY_NOISE}, sort_keys=True)
        if sig not in seen:
            seen.add(sig)
            unique.append(f)

    groups: dict[tuple, list[dict[str, Any]]] = {}
    for f in unique:
        groups.setdefault(tuple(f.get(k) for k in _GROUP_KEYS), []).append(f)

    def group_rank(item: tuple[tuple, list[dict[str, Any]]]) -> tuple:
        sevs = [str(f.get("severity")) for f in item[1]]
        best = min((_SEVERITY_ORDER.index(s) for s in sevs if s in _SEVERITY_ORDER), default=9)
        return (best, -len(item[1]), str(item[0][3]))

    counts: dict[str, int] = {}
    for f in unique:
        counts[str(f.get("severity"))] = counts.get(str(f.get("severity")), 0) + 1
    count_text = ", ".join(
        f"{s} {counts[s]}"
        for s in [*_SEVERITY_ORDER, *sorted(set(counts) - set(_SEVERITY_ORDER))]
        if s in counts
    )
    lines = [
        f"{len(unique)} findings in {len(groups)} packages on this page ({count_text})"
        + (
            f"; {len(findings) - len(unique)} exact duplicates removed"
            if len(unique) < len(findings)
            else ""
        )
    ]
    for (category, atype, apath, package, version), items in sorted(groups.items(), key=group_rank):
        where = ", ".join(str(x) for x in (atype, apath) if x)
        kind = "" if category in (None, "vulnerability") else f" [{category}]"
        lines.append(f"{package} {version}{kind} ({where})")
        for f in sorted(
            items,
            key=lambda f: (
                _SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in _SEVERITY_ORDER else 9,
                str(f.get("id")),
            ),
        ):
            extra = " ".join(
                f"{k}={json.dumps(v)}"
                for k, v in f.items()
                if k not in _LINE_KEYS and v not in (None, "")
            )
            lines.append(
                f"  {f.get('severity')} {f.get('id')} {_fix_text(f)}"
                + (f" {extra}" if extra else "")
            )
    token = page.get("next_token")
    if token:
        lines.append(
            f"next_token: {token}  (more findings: call findings_list again with this token)"
        )
    return "\n".join(lines)


def trivy_scan_text(item: dict[str, Any]) -> str:
    """scan_image returns {batch_id, counts: {artifact: {sev_num: n}}, meta: {...}}."""
    counts: dict[str, int] = {}
    for per_artifact in (item.get("counts") or {}).values():
        for sev, n in (per_artifact or {}).items():
            label = TRIVY_SEVERITY.get(int(sev), str(sev))
            counts[label] = counts.get(label, 0) + int(n)
    count_text = ", ".join(f"{s} {counts[s]}" for s in _SEVERITY_ORDER if s in counts)
    return "\n".join(
        [
            f"batch_id: {item.get('batch_id')}",
            f"target: {(item.get('meta') or {}).get('target')}",
            f"counts_by_severity: {count_text or 'none'}",
            "Call findings_list with this batchID to see individual vulnerabilities.",
        ]
    )


# ---------------------------------------------------------------------------
# List summaries
# ---------------------------------------------------------------------------


def _container_summary(item: dict[str, Any]) -> dict[str, Any]:
    """Compact one container (works for full inspect docs and sparse list entries)."""
    if "Names" in item:  # sparse /containers/json entry
        name = (item.get("Names") or ["?"])[0].lstrip("/")
        ports = [
            f"{p.get('IP', '')}:{p.get('PublicPort')}->{p.get('PrivatePort')}/{p.get('Type')}"
            for p in item.get("Ports") or []
            if p.get("PublicPort")
        ]
        networks = list(((item.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        return {
            "id": _short_id(item.get("Id", "")),
            "name": name,
            "image": item.get("Image"),
            "state": item.get("State"),
            "published_ports": ports,
            "networks": networks,
        }
    # Full inspect document.
    host_cfg = item.get("HostConfig") or {}
    ports = []
    for cport, bindings in (host_cfg.get("PortBindings") or {}).items():
        for b in bindings or []:
            ports.append(f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}->{cport}")
    return {
        "id": _short_id(item.get("Id", "")),
        "name": (item.get("Name") or "").lstrip("/"),
        "image": (item.get("Config") or {}).get("Image"),
        "state": (item.get("State") or {}).get("Status"),
        "published_ports": ports,
        "networks": list(((item.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
    }


def _image_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _short_id(item.get("Id", "")),
        "tags": item.get("RepoTags") or [],
        "created": item.get("Created"),
        "size_mb": round((item.get("Size") or 0) / 1_000_000, 1),
    }


def _network_summary(item: dict[str, Any]) -> dict[str, Any]:
    subnets = [c.get("Subnet") for c in ((item.get("IPAM") or {}).get("Config") or [])]
    return {
        "name": item.get("Name"),
        "id": _short_id(item.get("Id", "")),
        "driver": item.get("Driver"),
        "internal": item.get("Internal"),
        "subnets": [s for s in subnets if s],
    }


def _volume_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {"name": item.get("Name"), "driver": item.get("Driver")}


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def shape_result(tool: str, items: list[Any]) -> Any:
    """Return an LLM-friendly version of a tool result (list of parsed JSON items)."""
    dicts = [i for i in items if isinstance(i, dict)]
    if tool == "container_list":
        return [_container_summary(i) for i in dicts]
    if tool == "image_list":
        return [_image_summary(i) for i in dicts]
    if tool == "network_list":
        return [_network_summary(i) for i in dicts]
    if tool == "volume_list":
        return [_volume_summary(i) for i in dicts]
    if tool == "scan_image" and dicts:
        return trivy_scan_text(dicts[0])
    if tool == "findings_list" and dicts:
        return trivy_findings_text(dicts[0])
    if tool in _INSPECT_TOOLS and dicts:
        return "\n".join(line for d in dicts for line in inspect_lines(d))
    # Single item -> unwrap; otherwise return the list unchanged.
    return items[0] if len(items) == 1 else items


def to_text(value: Any, max_chars: int, *, ref: str | None = None) -> str:
    """Serialise for the model and enforce the size cap at a line boundary.

    Lists become one compact JSON object per line, so a cut never splits an
    entry. With ``ref`` (the stored full result) the marker tells the agent
    how to fetch the rest instead of repeating the call.
    """
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        text = "\n".join(json.dumps(v, separators=(",", ":")) for v in value)
    else:
        text = json.dumps(value, separators=(",", ":"))
    if len(text) <= max_chars:
        return text
    cut = text.rfind("\n", 0, max_chars + 1)
    if cut <= 0:  # a single line longer than the cap
        cut = max_chars
    rest = text[cut:].lstrip("\n")
    how = (
        f'The complete result is stored as {ref}: call evidence_get("{ref}", select=...) '
        "for the part you need instead of repeating this call."
        if ref
        else "Narrow the request, e.g. inspect a single resource."
    )
    return (
        text[:cut]
        + f"\n...[TRUNCATED: {len(rest)} more characters ({rest.count(chr(10)) + 1} lines) "
        f"omitted. {how}]"
    )
