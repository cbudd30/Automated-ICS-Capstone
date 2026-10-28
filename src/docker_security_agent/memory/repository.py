"""Repository: the only code that reads/writes the assessment database.

Callers work with Pydantic objects (``InventorySnapshot``, ``Finding``, ...)
and never write SQL. Every method commits immediately, so a run that crashes
half-way still leaves a consistent, inspectable trail (status ``running`` or
``failed`` plus whatever was collected).

Historical data is clearly *historical*: every finding and scan is tied to the
run and snapshot it came from, and nothing here ever merges old findings into
a new run.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from docker_security_agent.memory.database import connect
from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.findings import Finding
from docker_security_agent.schemas.observations import (
    ImageScanResult,
    ToolCallRecord,
    VulnerabilityRecord,
)
from docker_security_agent.schemas.reports import AgentReport, Comparison, Report


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str)


class AssessmentRepository:
    def __init__(self, db_path: Path | str):
        self.db_path = db_path
        self.conn: sqlite3.Connection = connect(db_path)

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ runs

    def create_run(
        self,
        *,
        run_id: str,
        mode: str,
        objective: str,
        model_profile: str | None,
        model_provider: str | None,
        model_id: str | None,
        model_config: dict[str, Any] | None,
        prompt_version: str,
        session_id: str | None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO runs (run_id, started_at, status, mode, objective, model_profile,
                   model_provider, model_id, model_config_json, prompt_version, session_id)
               VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                _now(),
                mode,
                objective,
                model_profile,
                model_provider,
                model_id,
                _dumps(model_config or {}),
                prompt_version,
                session_id,
            ),
        )
        self.conn.commit()

    def update_run(self, run_id: str, **fields: Any) -> None:
        """Update arbitrary run columns; dict/list values are stored as JSON."""
        allowed = {
            "finished_at",
            "status",
            "snapshot_id",
            "agent_status",
            "mcp_servers_json",
            "docker_endpoint_json",
            "errors_json",
            "metrics_json",
            "report_json",
            "agent_report_json",
            "comparison_json",
        }
        cols, values = [], []
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"Cannot update column {key}")
            cols.append(f"{key} = ?")
            values.append(_dumps(value) if isinstance(value, dict | list) else value)
        self.conn.execute(f"UPDATE runs SET {', '.join(cols)} WHERE run_id = ?", (*values, run_id))
        self.conn.commit()

    def save_manifest(
        self, run_id: str, manifest_json: str, manifest_sha256: str, config_sha256: str
    ) -> None:
        """Attach the run manifest. Write-once: a second call raises ValueError."""
        cur = self.conn.execute(
            """UPDATE runs SET manifest_json = ?, manifest_sha256 = ?, config_sha256 = ?
               WHERE run_id = ? AND manifest_sha256 IS NULL""",
            (manifest_json, manifest_sha256, config_sha256, run_id),
        )
        if cur.rowcount != 1:
            raise ValueError(f"run {run_id} does not exist or already has a manifest")
        self.conn.commit()

    def load_manifest_json(self, run_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT manifest_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return row["manifest_json"] if row else None

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT run_id, started_at, finished_at, status, mode, model_profile, model_id,
                      snapshot_id, agent_status
               FROM runs ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def save_report(self, run_id: str, report: Report) -> None:
        self.update_run(run_id, report_json=report.model_dump_json())

    def save_agent_report(self, run_id: str, report: AgentReport) -> None:
        self.update_run(run_id, agent_report_json=report.model_dump_json())

    def save_comparison(self, run_id: str, comparison: Comparison) -> None:
        self.update_run(run_id, comparison_json=comparison.model_dump_json())

    def _stored(self, run_id: str, column: str) -> str | None:
        run = self.get_run(run_id)
        return run.get(column) if run else None

    def load_report(self, run_id: str) -> Report | None:
        text = self._stored(run_id, "report_json")
        return Report.model_validate_json(text) if text else None

    def load_agent_report(self, run_id: str) -> AgentReport | None:
        text = self._stored(run_id, "agent_report_json")
        return AgentReport.model_validate_json(text) if text else None

    def load_comparison(self, run_id: str) -> Comparison | None:
        text = self._stored(run_id, "comparison_json")
        return Comparison.model_validate_json(text) if text else None

    # -------------------------------------------------------------- snapshots

    def save_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Insert once; an identical snapshot (same ID) is not duplicated."""
        self.conn.execute(
            """INSERT OR IGNORE INTO snapshots (snapshot_id, captured_at, docker_version,
                   docker_platform, container_count, image_count, network_count,
                   volume_count, data_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot.snapshot_id,
                snapshot.captured_at.isoformat(),
                snapshot.docker_version,
                snapshot.docker_platform,
                len(snapshot.containers),
                len(snapshot.images),
                len(snapshot.networks),
                len(snapshot.volumes),
                snapshot.model_dump_json(),
            ),
        )
        self.conn.commit()

    def load_snapshot(self, snapshot_id: str) -> InventorySnapshot | None:
        row = self.conn.execute(
            "SELECT data_json FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        return InventorySnapshot.model_validate_json(row["data_json"]) if row else None

    def list_snapshots(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT snapshot_id, captured_at, docker_version, container_count, image_count,
                      network_count, volume_count
               FROM snapshots ORDER BY captured_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ scans

    def save_scan(self, run_id: str, snapshot_id: str, scan: ImageScanResult) -> int:
        cur = self.conn.execute(
            """INSERT INTO scans (run_id, snapshot_id, image_id, image_ref, digest, scanner,
                   scanner_version, status, error, scanned_at, duration_seconds, counts_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                snapshot_id,
                scan.image_id,
                scan.image_ref,
                scan.digest,
                scan.scanner,
                scan.scanner_version,
                scan.status,
                scan.error,
                scan.scanned_at.isoformat(),
                scan.duration_seconds,
                _dumps(scan.counts),
            ),
        )
        scan_id = cur.lastrowid
        self.conn.executemany(
            """INSERT INTO vulnerabilities (scan_id, vuln_id, package, installed_version,
                   fixed_version, has_fix, severity, artifact_type, target, finding_key)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id,
                    v.vuln_id,
                    v.package,
                    v.installed_version,
                    v.fixed_version,
                    int(v.has_fix),
                    v.severity,
                    v.artifact_type,
                    v.target,
                    v.finding_key,
                )
                for v in scan.vulnerabilities
            ],
        )
        self.conn.commit()
        assert scan_id is not None
        return scan_id

    def latest_scan_ids_for_snapshot(self, snapshot_id: str) -> list[int]:
        """IDs of the latest successful scan of each image for this snapshot.

        Snapshots are content-addressed, so several live runs can share one and
        each adds its own scans: "latest" changes over time. Runs record the IDs
        they used in their manifest so a re-run loads exactly the same scans.
        """
        rows = self.conn.execute(
            """SELECT scan_id, image_id FROM scans WHERE snapshot_id = ? AND status = 'ok'
               ORDER BY scanned_at DESC, scan_id DESC""",
            (snapshot_id,),
        ).fetchall()
        latest: dict[str, int] = {}
        for r in rows:
            latest.setdefault(r["image_id"], r["scan_id"])
        return sorted(latest.values())

    def load_scans_for_snapshot(self, snapshot_id: str) -> list[ImageScanResult]:
        """Latest successful scan of each image for this snapshot (for replay runs)."""
        return self.load_scans(self.latest_scan_ids_for_snapshot(snapshot_id))

    def load_scans(self, scan_ids: list[int]) -> list[ImageScanResult]:
        """Exactly these scans (any status). Raises KeyError if one is missing."""
        rows = [
            self.conn.execute("SELECT * FROM scans WHERE scan_id = ?", (i,)).fetchone()
            for i in scan_ids
        ]
        missing = [i for i, r in zip(scan_ids, rows, strict=True) if r is None]
        if missing:
            raise KeyError(f"scan(s) not found: {missing}")
        results = []
        for r in rows:
            vrows = self.conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ?", (r["scan_id"],)
            ).fetchall()
            results.append(
                ImageScanResult(
                    image_id=r["image_id"],
                    image_ref=r["image_ref"],
                    digest=r["digest"],
                    scanner=r["scanner"],
                    scanner_version=r["scanner_version"] or "",
                    status=r["status"],
                    error=r["error"],
                    scanned_at=datetime.fromisoformat(r["scanned_at"]),
                    duration_seconds=r["duration_seconds"] or 0.0,
                    counts=json.loads(r["counts_json"] or "{}"),
                    vulnerabilities=[
                        VulnerabilityRecord(
                            vuln_id=v["vuln_id"],
                            package=v["package"] or "",
                            installed_version=v["installed_version"] or "",
                            fixed_version=v["fixed_version"] or "",
                            has_fix=bool(v["has_fix"]),
                            severity=v["severity"] or "UNKNOWN",
                            artifact_type=v["artifact_type"] or "",
                            target=v["target"] or "",
                            finding_key=v["finding_key"] or "",
                        )
                        for v in vrows
                    ],
                )
            )
        return sorted(results, key=lambda s: s.image_id)

    # --------------------------------------------------------------- findings

    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO findings (run_id, finding_id, rule_id, title, resource_type,
                   resource_name, category, severity, confidence, status, source, data_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    run_id,
                    f.id,
                    f.rule_id,
                    f.title,
                    f.resource_type,
                    f.resource_name,
                    f.category.value,
                    f.severity.value,
                    f.confidence.value,
                    f.status.value,
                    f.source.value,
                    f.model_dump_json(),
                )
                for f in findings
            ],
        )
        self.conn.commit()

    def load_findings(self, run_id: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT data_json FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
        return [Finding.model_validate_json(r["data_json"]) for r in rows]

    # ------------------------------------------------------------- tool calls

    def save_tool_calls(self, run_id: str, records: list[ToolCallRecord]) -> None:
        self.conn.executemany(
            """INSERT INTO tool_calls (run_id, timestamp, phase, server, tool, arguments_json,
                   status, duration_ms, result_chars, redactions, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    run_id,
                    r.timestamp.isoformat(),
                    r.phase,
                    r.server,
                    r.tool,
                    _dumps(r.arguments),
                    r.status,
                    r.duration_ms,
                    r.result_chars,
                    r.redactions,
                    r.error,
                )
                for r in records
            ],
        )
        self.conn.commit()

    def load_tool_calls(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM tool_calls WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]
