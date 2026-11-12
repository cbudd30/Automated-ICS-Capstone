"""Records of what was observed during a run: tool calls and scanner results."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ToolCallRecord(BaseModel):
    """One MCP or function tool call, as stored in SQLite and counted in metrics.

    ``phase`` tells who made the call:
      * ``collector`` - the application itself (inventory / scans), deterministic;
      * ``agent``     - the LLM decided to call it.
    """

    timestamp: datetime
    phase: str
    server: str  # MCP server name, or "local" for function tools
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: str  # ok / error / blocked / budget_exhausted
    duration_ms: int = 0
    result_chars: int = 0
    error: str | None = None


class VulnerabilityRecord(BaseModel):
    """One vulnerability exactly as Trivy reported it (no LLM involvement)."""

    vuln_id: str  # CVE-.../GHSA-... as reported
    package: str
    installed_version: str = ""
    fixed_version: str = ""
    has_fix: bool = False
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN (Trivy's scale)
    artifact_type: str = ""  # e.g. "debian", "alpine", "node-pkg", "gobinary"
    target: str = ""  # Trivy's target/path string
    finding_key: str = ""  # trivy-mcp's deterministic finding identifier


class ImageScanResult(BaseModel):
    """Outcome of scanning one image with Trivy."""

    image_id: str
    image_ref: str  # the reference actually passed to Trivy
    digest: str | None = None  # immutable repo digest, when the image has one
    scanner: str = "trivy"
    scanner_version: str = ""
    status: str = "ok"  # ok / error / skipped
    error: str | None = None
    scanned_at: datetime
    duration_seconds: float = 0.0
    counts: dict[str, int] = Field(default_factory=dict)  # severity -> count
    vulnerabilities: list[VulnerabilityRecord] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.counts.values())
