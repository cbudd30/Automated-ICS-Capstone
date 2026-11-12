"""Finding and evidence models.

A *finding* is one security statement about one resource, for example
"container `simulation` mounts the Docker socket". Every finding carries:

* ``evidence``  - the exact observed values that support it (inspect field
                  path + value, or a Trivy record), so a human can verify it;
* ``status``    - ``confirmed`` when produced by a deterministic rule or the
                  scanner, ``potential`` when reported by the LLM;
* ``source``    - who produced it: ``rule``, ``scanner`` or ``agent``.

This separation is what lets the report say "these are facts" versus
"the model thinks this may matter, please review".
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting: critical=4 ... info=0."""
        return _SEVERITY_RANK[self]

    @classmethod
    def max(cls, values: list[Severity]) -> Severity:
        return max(values, key=lambda s: s.rank) if values else cls.INFO


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(StrEnum):
    HIGH = "high"  # objective fact read directly from Docker / scanner output
    MEDIUM = "medium"  # strong indicator, but context could change the conclusion
    LOW = "low"  # weak signal / heuristic


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"


class FindingSource(StrEnum):
    RULE = "rule"
    SCANNER = "scanner"
    AGENT = "agent"


class Category(StrEnum):
    PRIVILEGE = "privilege"
    ISOLATION = "isolation"
    SECURITY_PROFILE = "security-profile"
    FILESYSTEM = "filesystem"
    NETWORK_EXPOSURE = "network-exposure"
    NETWORK_SEGMENTATION = "network-segmentation"
    RESOURCES = "resources"
    SECRETS_HYGIENE = "secrets-hygiene"
    IMAGE_HYGIENE = "image-hygiene"
    IMAGE_VULNERABILITY = "image-vulnerability"
    OTHER = "other"


class Evidence(BaseModel):
    """One observed fact supporting a finding."""

    source: str  # "docker_inspect", "docker_image_inspect", "docker_network", "trivy", "agent"
    resource: str  # resource name the fact was read from
    path: str  # where in the source document, e.g. "HostConfig.Privileged"
    value: str  # observed value, stringified
    note: str = ""


class Finding(BaseModel):
    """One security finding (see module docstring)."""

    id: str  # stable: same rule + resource + detail -> same ID across runs
    rule_id: str  # e.g. "C001"; "AGENT" for model-proposed concerns
    title: str
    resource_type: str  # container / image / network / volume / environment
    resource_name: str
    resource_id: str = ""
    category: Category
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    source: FindingSource
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str
    remediation: str
    references: list[str] = Field(default_factory=list)

    def sort_key(self) -> tuple:
        """Sort by severity, then confidence, then name (most important first)."""
        conf_rank = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
        return (-self.severity.rank, -conf_rank[self.confidence], self.resource_name, self.id)
