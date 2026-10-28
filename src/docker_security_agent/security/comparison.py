"""Compare what the agent found with what the deterministic checks found.

The deterministic findings (rules + Trivy) are the answer key. The agent never
sees them; this module scores its validated findings against them afterwards.

Matching (by evidence, never by rule ID: the agent does not know the rules)
----------------------------------------------------------------------------
An agent finding covers a deterministic finding when both are about the same
resource and the agent cited the same Docker field the rule's evidence points
at:

* **Same resource.** The names match. For image findings (I001, V001) a
  container that runs the image also counts, because the agent may report a
  vulnerable image under the container it found it through.
* **Same field.** One field path is a prefix of the other, after removing
  list indexes and ignoring case: the agent's ``HostConfig.CapAdd[0]`` covers
  the rule's ``HostConfig.CapAdd``; the agent's ``NetworkSettings.Networks``
  covers the rule's ``NetworkSettings.Networks.grficsv3_b-ics-net``. A few
  equivalent fields count as the same (``FIELD_ALIASES``: ports can be read
  from ``HostConfig.PortBindings`` or ``NetworkSettings.Ports``, mounts from
  ``Mounts`` or ``HostConfig.Binds``).
* **Vulnerabilities (V001).** Covered when the agent reported at least one
  vulnerability ID that Trivy found in that image (scored per image).

Where two rules share a field, the agent's own words decide (``_TIE_BREAKS``):
a ``Mounts`` finding mentioning ``docker.sock`` is the socket mount (C008),
otherwise a sensitive bind mount (C009); ``SecurityOpt`` mentioning
``no-new-privileges`` is C006, mentioning seccomp/AppArmor/SELinux is C005;
``NetworkSettings.Networks`` mentioning the default ``bridge`` is N004,
otherwise multiple networks (N002).

One agent finding may cover several deterministic findings (e.g. "root with
NET_ADMIN" citing both ``Config.User`` and ``HostConfig.CapAdd``), and several
agent findings may cover the same one.

Scores
------
* recall = found / all deterministic findings;
* weighted recall weights each finding by its severity rank (critical 4,
  high 3, medium 2, low 1, info 0), so missing a Docker socket mount costs
  more than missing a restart policy;
* match rate = agent findings that cover at least one deterministic finding /
  all agent findings; the rest are either validated but outside the rules
  ("unmatched": possibly real issues the rules do not check, for human
  review) or rejected by validation.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.findings import Finding, Severity
from docker_security_agent.schemas.reports import (
    Comparison,
    ComparisonScores,
    FindingRef,
    MatchedFinding,
    ModelInfo,
    SeverityRecall,
)
from docker_security_agent.security.validation import ValidationOutcome, image_ids_for

# Fields that hold the same fact in different places of the inspect document.
FIELD_ALIASES: dict[str, set[str]] = {
    "hostconfig.portbindings": {"networksettings.ports", "config.exposedports"},
    "mounts": {"hostconfig.binds", "hostconfig.mounts"},
    "repotags": {"config.image", "image"},
}

# rule ID -> (words that confirm it, words that point at a rival rule on the same field)
_TIE_BREAKS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "C008": (("docker.sock", "docker socket"), ()),
    "C009": ((), ("docker.sock", "docker socket")),
    "C006": (("no-new-privileges", "no_new_privileges", "new privileges"), ()),
    "C005": (("seccomp", "apparmor", "selinux", "unconfined", "label="), ()),
    "N004": (("default bridge", "bridge network"), ()),
    "N002": ((), ("default bridge",)),
}
# Rules whose field is shared with a rival: they need a confirming word.
_NEEDS_CONFIRMATION = {"C005", "C006", "C008", "N004"}
# Evidence a rule attaches for context only; citing it does not mean finding the issue.
_CONTEXT_PATHS = {"I001": {"used_by"}, "N005": {"driver", "containers"}}

METHOD = [
    "The agent never saw the deterministic findings; they are used here as the answer key.",
    "An agent finding covers a deterministic finding when it names the same resource (for "
    "image findings, also a container running that image) and cites the same Docker field "
    "as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).",
    "Image vulnerabilities (V001) are scored per image: covered when the agent reported at "
    "least one vulnerability ID that Trivy found in that image.",
    "Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> "
    "socket mount C008, otherwise sensitive bind mount C009).",
    "Only validated agent findings can cover a deterministic finding; rejected ones never do.",
    "Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.",
]

_INDEX_RE = re.compile(r"\[\d+\]|\.\d+(?=\.|$)")


def _norm(path: str) -> str:
    return _INDEX_RE.sub("", path.strip().lstrip(".")).lower()


def _with_aliases(path: str) -> set[str]:
    out = {path}
    for base, aliases in FIELD_ALIASES.items():
        if path == base or path.startswith(base + "."):
            out |= aliases
        for alias in aliases:
            if path == alias or path.startswith(alias + "."):
                out.add(base)
    return out


def _paths_overlap(agent_path: str, rule_path: str) -> bool:
    for a in _with_aliases(_norm(agent_path)):
        for r in _with_aliases(_norm(rule_path)):
            if a == r or a.startswith(r + ".") or r.startswith(a + "."):
                return True
    return False


def _ref(f: Finding) -> FindingRef:
    return FindingRef(
        finding_id=f.id,
        rule_id=f.rule_id,
        title=f.title,
        resource_name=f.resource_name,
        severity=f.severity.value,
    )


def _same_resource(agent: Finding, det: Finding, snapshot: InventorySnapshot) -> bool:
    a = agent.resource_name.lower()
    if a == det.resource_name.lower():
        return True
    if det.resource_type == "image":
        return bool(det.resource_id) and det.resource_id in image_ids_for(snapshot, a)
    if det.resource_type == "container":
        c = snapshot.container_by_name(det.resource_name)
        return c is not None and a in {c.id.lower(), c.id[:12].lower()}
    return False


def _wording(agent: Finding) -> str:
    parts = [agent.title, agent.explanation, *(e.value for e in agent.evidence)]
    return " ".join(parts).lower()


def covers(agent: Finding, det: Finding, snapshot: InventorySnapshot) -> bool:
    """True if validated agent finding ``agent`` covers deterministic finding ``det``."""
    if not _same_resource(agent, det, snapshot):
        return False
    if det.rule_id == "V001":
        cited = {e.value.upper() for e in agent.evidence if e.path == "vulnerability"}
        return bool(cited)  # validation only keeps IDs Trivy found in this image
    context = _CONTEXT_PATHS.get(det.rule_id, set())
    rule_paths = [e.path for e in det.evidence if _norm(e.path) not in context]
    agent_paths = [e.path for e in agent.evidence if e.path != "vulnerability"]
    if not any(_paths_overlap(a, r) for a in agent_paths for r in rule_paths):
        return False
    confirm, rivals = _TIE_BREAKS.get(det.rule_id, ((), ()))
    words = _wording(agent)
    if rivals and any(w in words for w in rivals):
        return False
    if det.rule_id in _NEEDS_CONFIRMATION:
        return any(w in words for w in confirm)
    return True


def _rate(n: int, d: int) -> float:
    return round(n / d, 3) if d else 0.0


def compare(
    *,
    run_id: str,
    model: ModelInfo,
    agent_status: str,
    deterministic: list[Finding],
    validation: ValidationOutcome | None,
    snapshot: InventorySnapshot,
) -> Comparison:
    """Score the agent's validated findings against the deterministic findings."""
    agent = validation.findings if validation else []
    rejected = validation.rejected if validation else []
    out_of_scope = validation.out_of_scope if validation else []

    found: list[MatchedFinding] = []
    missed: list[FindingRef] = []
    used: set[str] = set()
    for det in sorted(deterministic, key=lambda f: f.sort_key()):
        hits = [a for a in agent if covers(a, det, snapshot)]
        if not hits:
            missed.append(_ref(det))
            continue
        used |= {a.id for a in hits}
        top = Severity.max([a.severity for a in hits])
        agreement = (
            "same"
            if top.rank == det.severity.rank
            else ("higher" if top.rank > det.severity.rank else "lower")
        )
        found.append(
            MatchedFinding(
                deterministic=_ref(det),
                agent_finding_ids=[a.id for a in hits],
                agent_severity=top.value,
                severity_agreement=agreement,
            )
        )

    by_severity = []
    for sev in Severity:
        total = sum(1 for f in deterministic if f.severity == sev)
        if total:
            hit = sum(1 for m in found if m.deterministic.severity == sev.value)
            by_severity.append(SeverityRecall(severity=sev.value, total=total, found=hit))

    weight_all = sum(f.severity.rank for f in deterministic)
    weight_found = sum(Severity(m.deterministic.severity).rank for m in found)
    unmatched = [a for a in agent if a.id not in used]
    agent_total = len(agent) + len(rejected)
    scores = ComparisonScores(
        deterministic_total=len(deterministic),
        found=len(found),
        missed=len(missed),
        recall=_rate(len(found), len(deterministic)),
        weighted_recall=_rate(weight_found, weight_all),
        by_severity=by_severity,
        agent_total=agent_total,
        agent_matched=len(agent) - len(unmatched),
        agent_unmatched=len(unmatched),
        agent_rejected=len(rejected),
        match_rate=_rate(len(agent) - len(unmatched), agent_total),
        rejection_rate=_rate(len(rejected), agent_total),
    )
    return Comparison(
        run_id=run_id,
        generated_at=datetime.now(UTC),
        model=model,
        agent_status=agent_status,
        snapshot_id=snapshot.snapshot_id,
        scores=scores,
        found=found,
        missed=missed,
        agent_unmatched=[_ref(a) for a in unmatched],
        agent_rejected=[_ref(a) for a in rejected],
        agent_out_of_scope=[_ref(a) for a in out_of_scope],
        method=METHOD,
    )
