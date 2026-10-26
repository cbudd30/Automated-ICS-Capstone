"""Pydantic models for the NmapNetworkAgent (gc-nmap-mcp based).

These are intentionally separate from schemas/network.py (the subprocess-based
NetworkAssessmentAgent) so the two agents can be compared independently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Raw scan records (populated from gc-nmap-mcp tool output)
# ---------------------------------------------------------------------------


class NmapPort(BaseModel):
    """One open port returned by the nmap MCP server."""

    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    # NSE script output keyed by script id
    scripts: dict[str, str] = Field(default_factory=dict)


class NmapHost(BaseModel):
    """One scanned host and its open ports."""

    address: str
    hostname: str = ""
    state: str = "up"
    ports: list[NmapPort] = Field(default_factory=list)

    @property
    def ics_ports(self) -> list[NmapPort]:
        """Ports that match known ICS protocol numbers."""
        ICS = {102, 502, 4840, 9600, 20000, 44818, 47808, 1911, 2222, 18245}
        return [p for p in self.ports if p.port in ICS]


class NmapScan(BaseModel):
    """The result of one do-nmap tool call (one target / one set of flags)."""

    scan_id: str = ""
    target: str
    flags_used: str = ""
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0
    status: Literal["ok", "error", "empty"] = "ok"
    error: str | None = None
    hosts: list[NmapHost] = Field(default_factory=list)
    raw_output: str = ""  # full text from the MCP tool

    @property
    def all_ports(self) -> list[tuple[str, NmapPort]]:
        """Flat list of (host_address, port) pairs across all hosts."""
        return [(h.address, p) for h in self.hosts for p in h.ports]

    @property
    def ics_hits(self) -> list[tuple[str, NmapPort]]:
        """Flat list of (host_address, port) pairs for ICS protocol ports."""
        return [(h.address, p) for h in self.hosts for p in h.ics_ports]


# ---------------------------------------------------------------------------
# Structured agent output
# ---------------------------------------------------------------------------


class ExposedICSService(BaseModel):
    """One ICS protocol service the agent identified as exposed."""

    host: str
    port: int
    protocol_name: str  # e.g. "Modbus", "S7comm", "EtherNet/IP"
    risk_level: Literal["critical", "high", "medium", "low"]
    rationale: str
    recommended_action: str


class NetworkFinding(BaseModel):
    """A security finding produced by the NmapNetworkAgent."""

    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    host: str
    port: int | None = None
    evidence: str  # direct quote or reference from nmap output
    recommendation: str


class NmapNetworkAssessment(BaseModel):
    """Structured output from the NmapNetworkAgent."""

    executive_summary: str
    overall_risk: Literal["critical", "high", "medium", "low"]
    hosts_assessed: list[str]
    exposed_ics_services: list[ExposedICSService]
    findings: list[NetworkFinding]
    attack_surface_summary: str  # one paragraph: total exposure, worst combinations
    recommendations: list[str]
    limitations: list[str]
