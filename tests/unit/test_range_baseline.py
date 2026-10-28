"""Range baselines: recreate-stable fingerprint, verification, storage."""

from datetime import UTC, datetime

import pytest
from builders import build_snapshot

from docker_security_agent.inventory.baseline import (
    latest_reset,
    load_baseline,
    record_baseline,
    save_verification,
    verify,
)

RESET_AT = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)


def _recreated(snapshot, created="2026-10-16T10:05:00.123456789Z"):
    """What a correct reset looks like: new IDs, times and dynamic IPs; same config."""
    s = snapshot.model_copy(deep=True)
    for i, c in enumerate(s.containers):
        c.id = f"{i:064x}"
        c.created = created
        c.ip_addresses = {n: "10.9.9.9" for n in c.ip_addresses}
        c.labels["com.docker.compose.replace"] = "old-id"
    for n in s.networks:
        n.id = "f" * 64
    for v in s.volumes:
        v.created = created
    s.snapshot_id = s.compute_id()
    return s


def test_recreated_range_matches_although_snapshot_id_differs(settings, tmp_path):
    snap = build_snapshot(settings)
    baseline = record_baseline(tmp_path, "clean", snap)
    after = _recreated(snap)
    assert after.snapshot_id != snap.snapshot_id
    result = verify(baseline, after, since=RESET_AT)
    assert result.matches, result.differences


def test_verification_reports_real_changes(settings, tmp_path):
    snap = build_snapshot(settings)
    baseline = record_baseline(tmp_path, "clean", snap)
    after = _recreated(snap)
    plc = next(c for c in after.containers if c.name == "plc")
    plc.privileged = True
    plc.image_id = "sha256:" + "e" * 64
    after.volumes = [v for v in after.volumes if v.name != "plc_volume"]
    after.containers[0].state = "exited"
    diffs = verify(baseline, after).differences
    assert "containers.plc.privileged: expected false, found true" in diffs
    assert any(d.startswith("containers.plc.image_id:") for d in diffs)
    assert "volumes.plc_volume: missing" in diffs
    assert any(d.endswith('.state: expected "running", found "exited"') for d in diffs)


def test_freshness_catches_volume_not_restored(settings, tmp_path):
    snap = build_snapshot(settings)
    baseline = record_baseline(tmp_path, "clean", snap)
    after = _recreated(snap)
    stale = next(v for v in after.volumes if v.name == "plc_volume")
    stale.created = "2026-10-01T12:00:00Z"  # survived the reset
    result = verify(baseline, after, since=RESET_AT)
    assert not result.matches
    assert result.differences == [
        "volumes.plc_volume: created 2026-10-01T12:00:00Z, before the reset "
        "(contents were not restored)"
    ]
    assert verify(baseline, after).matches  # without --since only config is compared


def test_freshness_can_be_limited_to_the_reset_project(settings, tmp_path):
    # A reset recreates only the lab's compose project; the proxy and other
    # projects' volumes on the same engine stay as they were.
    snap = build_snapshot(settings)
    for v in snap.volumes:
        v.labels["com.docker.compose.project"] = "grficsv3"
    proxy = snap.containers[0].model_copy(
        update={"name": "docker-audit-socket-proxy", "labels": {}, "compose_project": None}
    )
    other = snap.volumes[0].model_copy(update={"name": "other_data", "labels": {}})
    snap.containers.append(proxy)
    snap.volumes.append(other)
    snap.snapshot_id = snap.compute_id()
    baseline = record_baseline(tmp_path, "clean", snap)

    after = _recreated(snap)
    old = "2026-10-01T12:00:00Z"
    next(c for c in after.containers if c.name == proxy.name).created = old
    next(v for v in after.volumes if v.name == "other_data").created = old

    assert len(verify(baseline, after, since=RESET_AT).differences) == 2
    result = verify(baseline, after, since=RESET_AT, project="grficsv3")
    assert result.matches, result.differences
    assert result.project == "grficsv3"

    stale = next(v for v in after.volumes if v.name == "plc_volume")
    stale.created = old  # a lab volume that was not restored is still caught
    assert verify(baseline, after, since=RESET_AT, project="grficsv3").differences == [
        f"volumes.plc_volume: created {old}, before the reset (contents were not restored)"
    ]
    assert verify(baseline, after, since=RESET_AT, project="nope").differences[0] == (
        "no containers of compose project 'nope' found"
    )


def test_incomplete_inventory_never_matches_or_records(settings, tmp_path):
    snap = build_snapshot(settings)
    baseline = record_baseline(tmp_path, "clean", snap)
    broken = snap.model_copy(update={"collection_errors": ["volume_list: timeout"]})
    assert not verify(baseline, broken).matches
    with pytest.raises(ValueError, match="incomplete"):
        record_baseline(tmp_path, "other", broken)


def test_storage_is_write_once_and_tamper_evident(settings, tmp_path):
    snap = build_snapshot(settings)
    record_baseline(tmp_path, "clean", snap)
    with pytest.raises(ValueError, match="already exists"):
        record_baseline(tmp_path, "clean", snap)
    with pytest.raises(ValueError, match="Invalid baseline name"):
        record_baseline(tmp_path, "../x", snap)
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path, "missing")

    path = tmp_path / "range-baselines" / "clean" / "baseline.json"
    path.write_text(path.read_text().replace('"running"', '"exited"', 1))
    with pytest.raises(ValueError, match="modified"):
        load_baseline(tmp_path, "clean")


def test_latest_reset_ignores_plain_checks(settings, tmp_path):
    snap = build_snapshot(settings)
    baseline = record_baseline(tmp_path, "clean", snap)
    assert latest_reset(tmp_path, "clean") is None
    save_verification(tmp_path, verify(baseline, _recreated(snap), since=RESET_AT))
    save_verification(tmp_path, verify(baseline, snap))  # later check, not a reset
    last = latest_reset(tmp_path, "clean")
    assert last.since == RESET_AT and last.matches
