"""Validate the LLM's structured output against the collected evidence.

The agent investigates with MCP tools only and reports its own findings. It
never sees the deterministic results, but its claims are still checked
against the evidence the application collected (inventory snapshot + Trivy
scans) before anything reaches a report. LLMs - especially small local ones -
can hallucinate CVE IDs, refer to containers that do not exist, or cite
fields that are not there:

* **Every finding** must
    - name a resource that exists in the inventory snapshot,
    - cite at least one verifiable piece of evidence: a field path present in
      that resource's inspect data, or a vulnerability ID that Trivy reported
      for that resource's image, and
    - not mention any CVE that Trivy did not report for that image.
  Findings that fail are kept in the agent report under "rejected" (for
  model comparison) but never treated as findings. Findings on assessment
  infrastructure excluded by configuration (the read-only proxy) are set
  aside as out of scope.
* **Observed values** are compared with the stored inspect data. A mismatch
  does not reject the finding (models paraphrase values), but lowers its
  confidence and is noted.
* **Free text** (summary, recommendations, limitations): CVE IDs that are not
  in the scanner output are replaced with ``[unverified CVE removed]``.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any

from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingSource,
    FindingStatus,
    Severity,
)
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import AgentAssessment, AgentFinding
from docker_security_agent.security.findings import finding_id

VULN_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)
_INDEX_RE = re.compile(r"\[(\d+)\]")


@dataclass
class ValidationOutcome:
    assessment: AgentAssessment  # with unverified CVEs scrubbed from free text
    findings: list[Finding] = field(default_factory=list)  # validated, agent's order
    rejected: list[Finding] = field(default_factory=list)
    out_of_scope: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _known_vuln_ids(scans: list[ImageScanResult]) -> set[str]:
    return {v.vuln_id.upper() for s in scans for v in s.vulnerabilities}


def _scrub_unknown_cves(text: str, known: set[str], notes: list[str], where: str) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group(0).upper() in known:
            return match.group(0)
        notes.append(f"{where}: removed {match.group(0)} (not present in scanner output)")
        return "[unverified CVE removed]"

    return VULN_ID_RE.sub(replace, text)


def _inspect_docs(snapshot: InventorySnapshot, resource_name: str) -> list[dict]:
    """Raw (redacted) inspect documents of every asset matching ``resource_name``.

    Matches the same names/IDs as ``InventorySnapshot.resource_names``.
    Volumes have no stored inspect document, so they never match.
    """
    name = resource_name.strip().lstrip("/").lower()
    docs = []
    for c in snapshot.containers:
        if name in {c.name.lower(), c.id.lower(), c.id[:12].lower()}:
            docs.append(c.raw)
    for i in snapshot.images:
        if name in {n.lower() for n in (i.id, i.display_name, *i.tags, *i.digests)}:
            docs.append(i.raw)
    for n in snapshot.networks:
        if name in {n.name.lower(), n.id.lower(), n.id[:12].lower()}:
            docs.append(n.raw)
    return docs


def image_ids_for(snapshot: InventorySnapshot, resource_name: str) -> set[str]:
    """Image IDs a resource name refers to: the image itself, or a container's image."""
    name = resource_name.strip().lstrip("/").lower()
    ids = {
        i.id
        for i in snapshot.images
        if name in {n.lower() for n in (i.id, i.display_name, *i.tags, *i.digests)}
        or name == i.id.removeprefix("sha256:")[:12].lower()
    }
    ids |= {
        c.image_id
        for c in snapshot.containers
        if name in {c.name.lower(), c.id.lower(), c.id[:12].lower()}
    }
    return ids


def _values_at(node: Any, parts: list[str]) -> list[Any]:
    """Every value found at the dotted path ``parts`` below ``node``."""
    if not parts:
        return [node]
    if isinstance(node, dict):
        # Keys may contain dots themselves (labels such as com.docker.compose.project,
        # network names), so try every split, longest key first.
        for n in range(len(parts), 0, -1):
            key = ".".join(parts[:n])
            if key in node:
                found = _values_at(node[key], parts[n:])
                if found:
                    return found
        return []
    if isinstance(node, list):
        if parts[0].isdigit():
            i = int(parts[0])
            return _values_at(node[i], parts[1:]) if i < len(node) else []
        # No index (e.g. Mounts.Source): collect the path from every element.
        return [v for item in node for v in _values_at(item, parts)]
    return []


def _split_path(path: str) -> list[str]:
    path = _INDEX_RE.sub(r".\1", path.strip()).lstrip(".")
    return path.split(".") if path else []


def inspect_values(doc: dict, path: str) -> list[Any]:
    """Values at dotted ``path`` (e.g. ``HostConfig.CapAdd``, ``Mounts[0].Source``)."""
    parts = _split_path(path)
    return _values_at(doc, parts) if parts else []


def inspect_path_exists(doc: dict, path: str) -> bool:
    """True if dotted ``path`` is present in the inspect document ``doc``."""
    parts = _split_path(path)
    return bool(parts) and bool(_values_at(doc, parts))


def _compact(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value)
    return re.sub(r"[\s\"'\[\]{}]", "", text).lower()


def value_matches(actual: list[Any], claimed: str) -> bool:
    """Loose check that the claimed value is what the inspect data holds.

    Containment either way after removing quotes, brackets and spaces, so
    ``NET_ADMIN`` matches ``["NET_ADMIN"]`` and ``true`` matches ``True``.
    An empty claim always matches.
    """
    want = _compact(claimed)
    if not want:
        return True
    for value in actual:
        have = _compact(value)
        if have in ("", "null", "none") and want in ("", "null", "none", "empty", "<empty>"):
            return True
        if have and (want in have or have in want):
            return True
    return False


def _to_finding(
    f: AgentFinding,
    *,
    status: FindingStatus,
    confidence: Confidence,
    evidence: list[Evidence],
    notes: list[str],
) -> Finding:
    return Finding(
        id=finding_id("AGENT", f.resource_name, f.title),
        rule_id="AGENT",
        title=f.title,
        resource_type="unknown",
        resource_name=f.resource_name.lstrip("/"),
        category=Category.OTHER,
        severity=Severity(f.severity),
        confidence=confidence,
        status=status,
        source=FindingSource.AGENT,
        evidence=evidence,
        explanation=f.explanation,
        remediation=f.remediation,
        references=sorted({v.strip().upper() for v in f.vulnerability_ids if v.strip()}),
        validation_notes=notes,
    )


def validate_agent_output(
    assessment: AgentAssessment,
    snapshot: InventorySnapshot,
    scans: list[ImageScanResult],
    ignored_containers: list[str] | None = None,
) -> ValidationOutcome:
    known_vulns = _known_vuln_ids(scans)
    vulns_by_image = {s.image_id: {v.vuln_id.upper() for v in s.vulnerabilities} for s in scans}
    resources = {r.lower() for r in snapshot.resource_names()}
    ignored = ignored_containers or []
    notes: list[str] = []

    # ---- free text: remove invented CVE IDs
    cleaned = assessment.model_copy(deep=True)
    cleaned.executive_summary = _scrub_unknown_cves(
        cleaned.executive_summary, known_vulns, notes, "executive_summary"
    )
    cleaned.recommendations = [
        _scrub_unknown_cves(r, known_vulns, notes, "recommendations")
        for r in cleaned.recommendations
    ]
    cleaned.limitations = [
        _scrub_unknown_cves(r, known_vulns, notes, "limitations") for r in cleaned.limitations
    ]

    outcome = ValidationOutcome(assessment=cleaned, notes=notes)
    seen: set[str] = set()

    for f in assessment.findings:
        name = f.resource_name.strip().lstrip("/")
        problems: list[str] = []
        finding_notes: list[str] = []

        if name.lower() not in resources:
            problems.append(f"resource '{f.resource_name}' not found in the inventory")

        # CVEs must be ones Trivy reported, and for this resource's image.
        image_vulns: set[str] = set()
        for image_id in image_ids_for(snapshot, name):
            image_vulns |= vulns_by_image.get(image_id, set())
        text = " ".join([f.title, f.explanation, f.remediation, *f.vulnerability_ids])
        cited = {m.upper() for m in VULN_ID_RE.findall(text)}
        unknown = sorted(cited - known_vulns)
        if unknown:
            problems.append(f"cites CVEs not in scanner output: {', '.join(unknown)}")
        elsewhere = sorted((cited & known_vulns) - image_vulns)
        if elsewhere:
            problems.append(
                f"cites CVEs Trivy reported for other images, not {name}: {', '.join(elsewhere)}"
            )
        valid_vulns = sorted(cited & image_vulns)

        # Field paths must exist on the named resource itself, not just look plausible.
        docs = _inspect_docs(snapshot, name)
        verified: list[Evidence] = []
        values_ok = True
        unverified: list[str] = []
        for e in f.evidence:
            values = [v for d in docs for v in inspect_values(d, e.field)]
            if not values:
                unverified.append(e.field)
                continue
            matches = value_matches(values, e.value)
            values_ok &= matches
            verified.append(
                Evidence(
                    source=f"agent:{e.tool}",
                    resource=name,
                    path=e.field.strip(),
                    value=e.value,
                    note="" if matches else "value differs from the inspect data",
                )
            )
        verified += [
            Evidence(source="agent:trivy", resource=name, path="vulnerability", value=v)
            for v in valid_vulns
        ]
        if not verified:
            problems.append("no verifiable evidence (no matching field or vulnerability ID)")
        if unverified:
            finding_notes.append(f"unverified fields ignored: {', '.join(unverified)}")
        if not values_ok:
            finding_notes.append("some observed values differ from the inspect data")

        key = finding_id("AGENT", name, f.title)
        if key in seen:
            notes.append(f"finding '{f.title}' on {name} reported twice; duplicate dropped")
            continue
        seen.add(key)

        if problems:
            outcome.rejected.append(
                _to_finding(
                    f,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    evidence=[
                        Evidence(
                            source=f"agent:{e.tool}", resource=name, path=e.field, value=e.value
                        )
                        for e in f.evidence
                    ],
                    notes=problems + finding_notes,
                )
            )
            notes.append(f"finding '{f.title}' rejected: {'; '.join(problems)}")
            continue

        finding = _to_finding(
            f,
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM if values_ok else Confidence.LOW,
            evidence=verified,
            notes=finding_notes,
        )
        if any(fnmatch.fnmatchcase(name, p) for p in ignored):
            finding.validation_notes.append("assessment infrastructure, excluded by configuration")
            outcome.out_of_scope.append(finding)
        else:
            outcome.findings.append(finding)

    return outcome
