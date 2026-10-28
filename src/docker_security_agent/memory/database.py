"""SQLite schema for the structured assessment store (``data/assessments.db``).

This is separate from the agent's conversation memory (sessions.py). It holds
the *facts* of every run so that results can be retrieved, compared across
models, and re-rendered later.

Tables
------
runs          one row per assessment run: model, prompt version, MCP versions,
              objective, snapshot used, status, errors, metrics, the three
              reports (deterministic, agent, comparison), and the run's
              immutable manifest + its hashes
snapshots     inventory snapshots (content-addressed by snapshot_id); shared
              by every run that used the same evidence
scans         one row per image scan (linked to the snapshot it belongs to)
vulnerabilities  every vulnerability Trivy reported for a scan
findings      every finding of a run (rule, scanner and agent), with evidence
tool_calls    audit trail of every MCP/function tool call in a run

Large/nested values (evidence lists, snapshot documents, metrics) are stored
as JSON text; everything you would filter on has its own column.

Nothing sensitive is stored: all tool results are redacted before they are
parsed into the objects that end up here.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id     TEXT PRIMARY KEY,
    captured_at     TEXT NOT NULL,
    docker_version  TEXT,
    docker_platform TEXT,
    container_count INTEGER,
    image_count     INTEGER,
    network_count   INTEGER,
    volume_count    INTEGER,
    data_json       TEXT NOT NULL          -- full InventorySnapshot (redacted)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,         -- running / completed / completed_with_errors / failed
    mode            TEXT NOT NULL,         -- live / replay / deterministic
                                           -- (replay: deterministic re-run on stored
                                           -- evidence; agent runs are always live)
    objective       TEXT NOT NULL,
    model_profile   TEXT,
    model_provider  TEXT,
    model_id        TEXT,
    model_config_json TEXT,
    prompt_version  TEXT,
    mcp_servers_json TEXT,                 -- servers, versions, approved tools
    docker_endpoint_json TEXT,             -- endpoint used + whether the read-only proxy
                                           -- was required and verified (live runs only)
    manifest_sha256 TEXT,                  -- immutable run manifest (see manifest.py);
    config_sha256   TEXT,                  -- written once, never updated
    manifest_json   TEXT,
    snapshot_id     TEXT REFERENCES snapshots(snapshot_id),
    session_id      TEXT,
    agent_status    TEXT,      -- ok/skipped/error/timeout/max_turns/invalid_output
    errors_json     TEXT,
    metrics_json    TEXT,
    report_json     TEXT,                  -- deterministic Report (`docker-audit report`)
    agent_report_json TEXT,                -- AgentReport (agent runs only)
    comparison_json TEXT                   -- Comparison: agent vs deterministic
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT REFERENCES runs(run_id),
    snapshot_id     TEXT REFERENCES snapshots(snapshot_id),
    image_id        TEXT NOT NULL,
    image_ref       TEXT NOT NULL,
    digest          TEXT,
    scanner         TEXT NOT NULL,
    scanner_version TEXT,
    status          TEXT NOT NULL,
    error           TEXT,
    scanned_at      TEXT NOT NULL,
    duration_seconds REAL,
    counts_json     TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    scan_id         INTEGER NOT NULL REFERENCES scans(scan_id),
    vuln_id         TEXT NOT NULL,
    package         TEXT,
    installed_version TEXT,
    fixed_version   TEXT,
    has_fix         INTEGER,
    severity        TEXT,
    artifact_type   TEXT,
    target          TEXT,
    finding_key     TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    finding_id      TEXT NOT NULL,
    rule_id         TEXT,
    title           TEXT,
    resource_type   TEXT,
    resource_name   TEXT,
    category        TEXT,
    severity        TEXT,
    confidence      TEXT,
    status          TEXT,
    source          TEXT,
    data_json       TEXT NOT NULL,         -- full Finding incl. evidence
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    timestamp       TEXT NOT NULL,
    phase           TEXT NOT NULL,         -- collector / agent
    server          TEXT,
    tool            TEXT,
    arguments_json  TEXT,                  -- redacted
    status          TEXT,
    duration_ms     INTEGER,
    result_chars    INTEGER,
    redactions      INTEGER,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_snapshot ON scans(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_run ON tool_calls(run_id);
"""


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open (and initialise if needed) the assessment database."""
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM schema_info").fetchone()[0] == 0:
        conn.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
    _migrate(conn)
    conn.commit()
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring a database created by an older version up to SCHEMA_VERSION."""
    # CREATE TABLE IF NOT EXISTS does not add columns to an existing table.
    added_run_columns = [
        "docker_endpoint_json",  # v2
        "manifest_sha256",  # v3
        "config_sha256",  # v3
        "manifest_json",  # v3
        "agent_report_json",  # v4
        "comparison_json",  # v4
    ]
    run_cols = {r["name"] for r in conn.execute("PRAGMA table_info(runs)")}
    for col in added_run_columns:
        if col not in run_cols:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {col} TEXT")
    conn.execute("UPDATE schema_info SET version = ?", (SCHEMA_VERSION,))
