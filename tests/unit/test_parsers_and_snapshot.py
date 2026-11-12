"""Parsing docker inspect documents and snapshot identity."""

import copy

import grfics
from builders import build_snapshot

from docker_security_agent.inventory.parsers import parse_container, parse_image


def test_parse_container_security_fields():
    doc = next(d for d in grfics.grfics_containers() if d["Name"] == "/router")
    c = parse_container(doc)
    assert c.name == "router"
    assert c.cap_add == ["NET_ADMIN", "NET_RAW"]
    assert c.sysctls == {"net.ipv4.ip_forward": "1"}
    assert set(c.networks) == {"a-grfics-admin", "b-ics-net", "c-dmz-net"}
    assert c.ip_addresses["b-ics-net"] == "192.168.95.200"
    assert c.ports[0].protocol == "udp" and c.ports[0].all_interfaces
    assert c.env_names == ["PATH", "FWUI_SECRET_KEY"]
    assert c.restart_policy == "unless-stopped"
    assert c.compose_service == "router"


def test_parse_container_handles_nulls():
    doc = grfics.container_doc("x", "img:1")
    doc["HostConfig"]["CapAdd"] = None
    doc["HostConfig"]["SecurityOpt"] = None
    doc["Mounts"] = None
    c = parse_container(doc)
    assert c.cap_add == [] and c.security_opt == [] and c.mounts == []


def test_cap_prefix_normalised():
    doc = grfics.container_doc("x", "img:1", cap_add=["CAP_SYS_ADMIN"])
    assert parse_container(doc).cap_add == ["SYS_ADMIN"]


def test_parse_image_digest_and_user():
    img = parse_image(grfics.image_doc("example/hardened:1.2.3", user="1000", digest=True))
    assert img.tags == ["example/hardened:1.2.3"]
    assert img.digest.startswith("example/hardened@sha256:")
    assert img.user == "1000"


def test_snapshot_membership_and_references(snapshot):
    ics = next(n for n in snapshot.networks if n.name == "b-ics-net")
    assert ics.containers == ["EWS", "plc", "router", "simulation"]
    refs = snapshot.image_references()
    assert "fortiphyd/grfics-plc:latest" in refs
    assert snapshot.used_image_ids()


def test_snapshot_id_is_stable_and_ignores_volatile_fields(settings, monkeypatch):
    a = build_snapshot(settings)
    b = build_snapshot(settings)
    assert a.snapshot_id == b.snapshot_id and a.snapshot_id.startswith("snap-")

    # Health-check timestamps / PIDs change constantly: same ID expected.
    original = grfics.grfics_containers

    def volatile():
        docs = original()
        for d in docs:
            d["State"]["Pid"] = 999
            d["State"]["Health"]["Log"][0]["Start"] = "2030-01-01T00:00:00Z"
        return docs

    monkeypatch.setattr(grfics, "grfics_containers", volatile)
    assert build_snapshot(settings).snapshot_id == a.snapshot_id

    # A real configuration change: different ID.
    def changed():
        docs = copy.deepcopy(volatile())
        docs[0]["HostConfig"]["Privileged"] = True
        return docs

    monkeypatch.setattr(grfics, "grfics_containers", changed)
    assert build_snapshot(settings).snapshot_id != a.snapshot_id


def test_credential_values_are_kept_in_the_snapshot(snapshot):
    """Harness h3: no redaction. Finding credentials is part of the lab, so the raw
    inspect documents keep environment values and labels exactly as Docker returns them."""
    dumped = snapshot.model_dump_json()
    for secret in (
        "Sup3rS3cret!",
        "some-long-secret-you-generate",
        "hunter2",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ):
        assert secret in dumped
    assert "<redacted>" not in dumped


def test_mount_and_port_order_does_not_change_snapshot_id(settings, monkeypatch):
    """Docker returns Mounts in a non-deterministic order (seen on Docker Desktop 4.88)."""
    first = build_snapshot(settings).snapshot_id
    original = grfics.grfics_containers

    def reordered():
        docs = original()
        for d in docs:
            d["Mounts"] = list(reversed(d["Mounts"]))
        return docs

    monkeypatch.setattr(grfics, "grfics_containers", reordered)
    assert build_snapshot(settings).snapshot_id == first
