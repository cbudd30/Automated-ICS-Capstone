"""Network scan models.

Two families live here:

1. ``NetworkScanResult``   - raw output from one nmap scan: open ports, detected
   services, ICS protocols found. Stored per snapshot so replay mode works
   without re-scanning.

2. ``NetworkAssessment``   - the structured output the NetworkAssessmentAgent
   must return: an OT-aware summary, prioritised exposure findings, and
   concrete remediation steps.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Raw scan observations
# ---------------------------------------------------------------------------


class PortRecord(BaseModel):
    """One open port on one host."""

    host: str
    port: int
    protocol: Literal["tcp", "udp"]
    state: str  # "open" | "open|filtered" | etc.
    service: str = ""  # e.g. "http", "s7comm", "modbus"
    product: str = ""  # e.g. "nginx", "Siemens S7 PLC"
    version: str = ""
    extra_info: str = ""
    # NSE script output keyed by script ID, e.g. {"modbus-discover": "Unit ID: 1"}
    scripts: dict[str, str] = Field(default_factory=dict)


class ICSProtocolHit(BaseModel):
    """An ICS/OT protocol detected by an NSE script."""

    host: str
    port: int
    protocol_name: str  # "modbus", "s7comm", "enip", "dnp3", "bacnet", "opcua"
    script_id: str       # the NSE script that produced this hit
    raw_output: str      # verbatim script output


class NetworkScanResult(BaseModel):
    """Results of one nmap scan against one Docker network or host range."""

    scan_id: int = 0           # set by the repository after persistence
    snapshot_id: str = ""
    target: str                # CIDR or hostname that was scanned
    scan_args: str = ""        # the nmap flags used (for auditability)
    scanner_version: str = ""
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0
    status: Literal["ok", "error", "skipped"] = "ok"
    error: str | None = None

    hosts_up: int = 0
    hosts_scanned: int = 0
    open_ports: list[PortRecord] = Field(default_factory=list)
    ics_hits: list[ICSProtocolHit] = Field(default_factory=list)

    # Summary counts by service category for the agent prompt
    counts: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Structured agent output
# ---------------------------------------------------------------------------


class ExposedService(BaseModel):
    """The agent's assessment of one exposed service."""

    host: str
    port: int
    protocol: str
    service_name: str
    rank: int = Field(description="1 = most urgent exposure")
    severity: Literal["critical", "high", "medium", "low", "info"]
    ot_rationale: str = Field(
        description="Why this exposure matters for OT/ICS availability and integrity"
    )
    evidence_refs: list[str] = Field(
        description="Port strings (e.g. '192.168.90.10:502/tcp') or NSE script IDs"
    )


class ICSExposure(BaseModel):
    """An ICS protocol directly reachable on the network."""

    host: str
    port: int
    protocol_name: str
    script_output: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    rationale: str


class NetworkAssessment(BaseModel):
    """Structured output of NetworkAssessmentAgent."""

    executive_summary: str = Field(
        description="3-6 sentences for a defender; OT availability and integrity first"
    )
    overall_risk: Literal["critical", "high", "medium", "low"]
    exposed_services: list[ExposedService] = Field(
        description="Top exposed services ranked by urgency (5-15 items)"
    )
    ics_exposures: list[ICSExposure] = Field(
        description="ICS/OT protocols detected on the network; empty if none found"
    )
    cross_agent_concerns: list[str] = Field(
        description=(
            "Findings that combine network exposure with Docker-layer risk "
            "(e.g. a privileged container also running Modbus). "
            "Reference Docker finding IDs where relevant."
        )
    )
    recommendations: list[str] = Field(
        description="Concrete, ordered remediation steps (firewall rules, compose settings, etc.)"
    )
    limitations: list[str] = Field(
        description="What could not be verified (e.g. UDP scans skipped, host unreachable)"
    )
