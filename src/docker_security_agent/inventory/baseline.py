"""Named range baselines: the known state a cyber-range run must start from.

The reference framework requires the range to be reset to a known snapshot
before every experimental run. The reset itself changes Docker state, so it is
NOT done by this application (which only ever reads Docker through the
read-only proxy): ``deploy/grfics/range.sh`` performs it with the operator's
own Docker access. This module provides the read-only half:

* ``record_baseline`` - fingerprint the current inventory under a name
  (``docker-audit range record NAME``).
* ``verify``          - compare a fresh inventory with a baseline
  (``docker-audit range verify NAME``, and ``assess --range-baseline NAME``).

Why a fingerprint and not the snapshot ID
-----------------------------------------
Snapshot IDs include container and network IDs, and a reset recreates every
container and network, so a correctly reset range never reproduces its old
snapshot ID. The fingerprint is the snapshot with recreate-volatile fields
removed (IDs, creation times, IPs Docker assigns dynamically, compose's
``replace`` label) and images limited to those containers use. Everything
security-relevant - images by content ID, privileges, mounts, ports, networks,
labels including compose's config hash, volume set, container state - must match.

``since`` adds a freshness check: every container and volume must have been
created after the reset started. That catches a reset that skipped restoring
a volume (its old contents - e.g. a modified PLC program - would survive).
``project`` limits that check to one compose project (what range.sh resets):
other resources on the engine, such as the read-only proxy the verification
itself runs through, legitimately predate the reset. They are still compared
by the fingerprint.

Files live in ``<data_dir>/range-baselines/<NAME>/`` (git-ignored):
``baseline.json`` (written once) and ``verifications/<timestamp>.json``.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from docker_security_agent.schemas.assets import InventorySnapshot

BASELINE_DIRNAME = "range-baselines"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Labels Docker Compose changes on every recreate without any config change.
VOLATILE_LABELS = {"com.docker.compose.replace"}
PROJECT_LABEL = "com.docker.compose.project"


class RangeBaseline(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    recorded_at: datetime
    snapshot_id: str  # the inventory snapshot the baseline was taken from
    fingerprint_sha256: str
    fingerprint: dict[str, Any]


class RangeVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    baseline: str
    baseline_fingerprint_sha256: str
    snapshot_id: str
    verified_at: datetime
    since: datetime | None  # reset start time, when freshness was checked
    project: str | None = None  # compose project the freshness check covered (None = all)
    matches: bool
    differences: list[str]


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def fingerprint(snapshot: InventorySnapshot) -> dict[str, Any]:
    """Recreate-stable view of the snapshot, keyed by name for readable diffs."""
    data = snapshot.model_dump(
        mode="json",
        exclude={
            "containers": {"__all__": {"id", "raw", "created", "ip_addresses"}},
            "images": {"__all__": {"raw"}},
            "networks": {"__all__": {"id", "raw"}},
            "volumes": {"__all__": {"created"}},
        },
    )
    used = set(snapshot.used_image_ids())
    containers = {}
    for c in data["containers"]:
        c["labels"] = {k: v for k, v in c["labels"].items() if k not in VOLATILE_LABELS}
        containers[c["name"]] = c
    return {
        "docker": {"version": data["docker_version"], "platform": data["docker_platform"]},
        "containers": containers,
        "images": {i["id"]: i for i in data["images"] if i["id"] in used},
        "networks": {n["name"]: n for n in data["networks"]},
        "volumes": {v["name"]: v for v in data["volumes"]},
    }


def fingerprint_sha256(fp: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(fp, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def diff(expected: Any, actual: Any, path: str = "") -> list[str]:
    """Human-readable differences between two fingerprints (empty = identical)."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in sorted(set(expected) | set(actual)):
            sub = f"{path}.{key}" if path else str(key)
            if key not in actual:
                out.append(f"{sub}: missing")
            elif key not in expected:
                out.append(f"{sub}: unexpected")
            else:
                out += diff(expected[key], actual[key], sub)
        return out
    if expected != actual:
        return [f"{path}: expected {_short(expected)}, found {_short(actual)}"]
    return []


def _created_before(created: str, since: datetime) -> bool:
    """True if ``created`` is older than ``since``. Unknown times count as old."""
    try:
        when = datetime.fromisoformat(created)
    except ValueError:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when < since


def verify(
    baseline: RangeBaseline,
    snapshot: InventorySnapshot,
    since: datetime | None = None,
    project: str | None = None,
) -> RangeVerification:
    differences = [f"inventory incomplete: {e}" for e in snapshot.collection_errors]
    differences += diff(baseline.fingerprint, fingerprint(snapshot))
    if since is not None:

        def in_scope(labels: dict[str, str]) -> bool:
            return project is None or labels.get(PROJECT_LABEL) == project

        containers = [c for c in snapshot.containers if in_scope(c.labels)]
        volumes = [v for v in snapshot.volumes if in_scope(v.labels)]
        if project is not None and not containers:
            differences.append(f"no containers of compose project '{project}' found")
        differences += [
            f"containers.{c.name}: created {c.created or 'at an unknown time'}, before the reset"
            for c in containers
            if _created_before(c.created, since)
        ]
        differences += [
            f"volumes.{v.name}: created {v.created or 'at an unknown time'}, before the reset "
            "(contents were not restored)"
            for v in volumes
            if _created_before(v.created, since)
        ]
    return RangeVerification(
        baseline=baseline.name,
        baseline_fingerprint_sha256=baseline.fingerprint_sha256,
        snapshot_id=snapshot.snapshot_id,
        verified_at=datetime.now(UTC),
        since=since,
        project=project if since is not None else None,
        matches=not differences,
        differences=differences,
    )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _check_name(name: str) -> str:
    if not _NAME_RE.match(name):
        raise ValueError(
            f"Invalid baseline name '{name}': use letters, digits, '.', '_' or '-' "
            "(max 64 characters, starting with a letter or digit)"
        )
    return name


def baseline_dir(data_dir: Path, name: str) -> Path:
    return data_dir / BASELINE_DIRNAME / _check_name(name)


def record_baseline(data_dir: Path, name: str, snapshot: InventorySnapshot) -> RangeBaseline:
    """Save a new named baseline. Baselines are write-once: pick a new name to re-record."""
    if snapshot.collection_errors:
        raise ValueError(
            "Refusing to record a baseline from an incomplete inventory: "
            + "; ".join(snapshot.collection_errors)
        )
    fp = fingerprint(snapshot)
    baseline = RangeBaseline(
        name=name,
        recorded_at=datetime.now(UTC),
        snapshot_id=snapshot.snapshot_id,
        fingerprint_sha256=fingerprint_sha256(fp),
        fingerprint=fp,
    )
    d = baseline_dir(data_dir, name)
    d.mkdir(parents=True, exist_ok=True)
    try:
        with (d / "baseline.json").open("x") as fh:
            fh.write(baseline.model_dump_json(indent=2))
    except FileExistsError as exc:
        raise ValueError(f"Baseline '{name}' already exists; record under a new name") from exc
    return baseline


def load_baseline(data_dir: Path, name: str) -> RangeBaseline:
    path = baseline_dir(data_dir, name) / "baseline.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No range baseline named '{name}' (expected {path}). "
            "Create one with deploy/grfics/range.sh save NAME"
        )
    baseline = RangeBaseline.model_validate_json(path.read_text())
    if fingerprint_sha256(baseline.fingerprint) != baseline.fingerprint_sha256:
        raise ValueError(f"Range baseline '{name}' was modified after it was recorded")
    return baseline


def list_baselines(data_dir: Path) -> list[str]:
    root = data_dir / BASELINE_DIRNAME
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if (p / "baseline.json").exists())


def save_verification(data_dir: Path, result: RangeVerification) -> Path:
    d = baseline_dir(data_dir, result.baseline) / "verifications"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{result.verified_at:%Y%m%dT%H%M%S%fZ}.json"
    path.write_text(result.model_dump_json(indent=2))
    return path


def latest_reset(data_dir: Path, name: str) -> RangeVerification | None:
    """Most recent verification that checked freshness (i.e. followed a reset)."""
    d = baseline_dir(data_dir, name) / "verifications"
    if not d.is_dir():
        return None
    for path in sorted(d.glob("*.json"), reverse=True):
        v = RangeVerification.model_validate_json(path.read_text())
        if v.since is not None:
            return v
    return None
