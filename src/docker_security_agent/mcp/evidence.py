"""Evidence store: the full result of every agent tool call, keyed by a short reference.

Harness h2. The model only ever sees the *shaped* form of a tool result
(mcp/shaping.py), and older results are later replaced by one-line stubs
(agents/context_filter.py). This store is what keeps that safe:

* every successful agent tool call is stored **as it happens**, complete
  (not shaped), under the next reference ``E1``, ``E2``... The
  reference is the first thing on the result the model sees;
* the agent can read any stored result back with ``evidence_get``;
* a repeated call with identical arguments is answered with the reference
  instead of running the tool again (``find``);
* the agent's per-container sections live here too, so stubs can point at a
  written section.

Rows go to the ``tool_outputs`` / ``agent_sections`` tables of the assessment
database (memory/database.py), which makes the run reconstructable: exactly
what each tool returned, and what was sent to the model (``shaped_chars``).
Without a database path (tests) the store is in memory only.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from docker_security_agent.schemas.reports import ContainerSection


@dataclass
class StoredOutput:
    ref: str
    seq: int
    server: str
    tool: str
    arguments: dict[str, Any]
    items: list[Any]  # the full tool result, not shaped
    subject: str = ""  # what it is about: container / image name, scan target


def _canonical(server: str, tool: str, arguments: dict[str, Any]) -> str:
    return json.dumps([server, tool, arguments], sort_keys=True, separators=(",", ":"))


def _image_names(ref: str) -> set[str]:
    """``repo/name`` and ``repo/name:latest`` refer to the same image."""
    ref = ref.strip().lower()
    return {ref, ref.removesuffix(":latest")} if ref.endswith(":latest") else {ref, ref + ":latest"}


@dataclass
class EvidenceStore:
    run_id: str
    db_path: Path | str | None = None
    outputs: dict[str, StoredOutput] = field(default_factory=dict)
    sections: dict[str, ContainerSection] = field(default_factory=dict)
    _by_call: dict[str, str] = field(default_factory=dict)
    _conn: sqlite3.Connection | None = None

    def __post_init__(self) -> None:
        if self.db_path is not None:
            from docker_security_agent.memory.database import connect

            self._conn = connect(self.db_path)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ---- tool outputs ------------------------------------------------------

    def find(self, server: str, tool: str, arguments: dict[str, Any]) -> StoredOutput | None:
        """The stored result of an earlier call with exactly these arguments."""
        ref = self._by_call.get(_canonical(server, tool, arguments))
        return self.outputs.get(ref) if ref else None

    def add(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        items: list[Any],
    ) -> StoredOutput:
        seq = len(self.outputs) + 1
        stored = StoredOutput(
            ref=f"E{seq}",
            seq=seq,
            server=server,
            tool=tool,
            arguments=arguments,
            items=items,
            subject=self._subject(tool, arguments),
        )
        self.outputs[stored.ref] = stored
        self._by_call[_canonical(server, tool, arguments)] = stored.ref
        if self._conn is not None:
            self._conn.execute(
                """INSERT INTO tool_outputs (run_id, ref, seq, created_at, server, tool,
                       arguments_json, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.run_id,
                    stored.ref,
                    seq,
                    datetime.now(UTC).isoformat(),
                    server,
                    tool,
                    json.dumps(arguments, sort_keys=True),
                    json.dumps(items),
                ),
            )
            self._conn.commit()
        return stored

    def record_shaped_size(self, ref: str, chars: int) -> None:
        if self._conn is not None:
            self._conn.execute(
                "UPDATE tool_outputs SET shaped_chars = ? WHERE run_id = ? AND ref = ?",
                (chars, self.run_id, ref),
            )
            self._conn.commit()

    def get(self, ref: str) -> StoredOutput | None:
        return self.outputs.get(ref.strip().upper())

    def _subject(self, tool: str, arguments: dict[str, Any]) -> str:
        if tool in ("container_inspect", "image_inspect", "network_inspect", "volume_inspect"):
            return str(arguments.get("id_or_name") or arguments.get("name") or "")
        if tool == "scan_image":
            return str(arguments.get("target") or "")
        if tool == "findings_list":  # the image the batch was scanned from
            batch = arguments.get("batchID")
            for out in self.outputs.values():
                if out.tool == "scan_image" and any(
                    isinstance(i, dict) and i.get("batch_id") == batch for i in out.items
                ):
                    return out.subject
        return ""

    # ---- per-container sections -------------------------------------------

    def save_section(self, section: ContainerSection) -> None:
        name = section.resource_name.strip().lstrip("/")
        self.sections[name.lower()] = section
        if self._conn is not None:
            self._conn.execute(
                """INSERT INTO agent_sections (run_id, resource_name, updated_at, data_json)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(run_id, resource_name) DO UPDATE SET
                       updated_at = excluded.updated_at, data_json = excluded.data_json""",
                (self.run_id, name, datetime.now(UTC).isoformat(), section.model_dump_json()),
            )
            self._conn.commit()

    def _container_images(self) -> dict[str, set[str]]:
        """Container name -> image names, from the container_inspect results seen so far."""
        images: dict[str, set[str]] = {}
        for out in self.outputs.values():
            if out.tool != "container_inspect":
                continue
            for doc in out.items:
                if isinstance(doc, dict):
                    name = str(doc.get("Name") or out.subject).lstrip("/").lower()
                    image = str((doc.get("Config") or {}).get("Image") or "")
                    if image:
                        images.setdefault(name, set()).update(_image_names(image))
        return images

    def section_for(self, stored: StoredOutput) -> str | None:
        """Name of the written section that covers this result, if any."""
        subject = stored.subject.strip().lstrip("/").lower()
        if not subject:
            return None
        if subject in self.sections:
            return self.sections[subject].resource_name
        if stored.tool in ("scan_image", "findings_list", "image_inspect"):
            targets = _image_names(subject)
            for container, images in self._container_images().items():
                if container in self.sections and images & targets:
                    return self.sections[container].resource_name
        return None
