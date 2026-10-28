"""The comparison report: ``comparison.json`` + ``comparison.md``.

Rendered from ``Comparison`` (security/comparison.py): scores, the
deterministic findings the agent found, the ones it MISSED, and the agent
findings that go beyond the rules or failed validation.
"""

from __future__ import annotations

from pathlib import Path

from docker_security_agent.reporting.generator import _table, write_files
from docker_security_agent.schemas.reports import Comparison, FindingRef

COMPARISON_REPORT = "comparison"


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def _refs_table(refs: list[FindingRef]) -> str:
    return _table(
        ["Severity", "Rule", "Finding", "Resource"],
        [[r.severity, r.rule_id, f"`{r.finding_id}` {r.title}", r.resource_name] for r in refs],
    )


def render_comparison_markdown(c: Comparison) -> str:
    s = c.scores
    md: list[str] = []
    md.append(f"# Agent vs Deterministic — `{c.run_id}`\n")
    md.append(
        f"**Model:** `{c.model.profile}` ({c.model.provider} / `{c.model.model}`) · "
        f"**Agent status:** {c.agent_status} · **Snapshot:** `{c.snapshot_id}` · "
        f"**Generated:** {c.generated_at:%Y-%m-%d %H:%M UTC}\n"
    )

    md.append("## 1. Scores\n")
    md.append(
        _table(
            ["Metric", "Value"],
            [
                [
                    "Deterministic findings found by the agent",
                    f"{s.found} of {s.deterministic_total} (recall {_pct(s.recall)})",
                ],
                ["Severity-weighted recall", _pct(s.weighted_recall)],
                ["Missed by the agent", str(s.missed)],
                [
                    "Agent findings that match a deterministic finding",
                    f"{s.agent_matched} of {s.agent_total} ({_pct(s.match_rate)})",
                ],
                ["Agent findings outside the rules (validated)", str(s.agent_unmatched)],
                [
                    "Agent findings rejected by validation",
                    f"{s.agent_rejected} ({_pct(s.rejection_rate)})",
                ],
            ],
        )
    )
    md.append("\n**Recall by severity:**\n")
    md.append(
        _table(
            ["Severity", "Found", "Total", "Recall"],
            [
                [b.severity, str(b.found), str(b.total), _pct(b.found / b.total)]
                for b in s.by_severity
            ],
        )
    )

    md.append(f"\n## 2. Missed by the agent ({len(c.missed)})\n")
    md.append(
        "Confirmed by the rules or Trivy, but the agent did not report them. Details and "
        "evidence: `deterministic_report.md`.\n"
    )
    md.append(_refs_table(c.missed))

    md.append(f"\n## 3. Found by the agent ({len(c.found)})\n")
    md.append(
        _table(
            ["Severity", "Rule", "Finding", "Resource", "Agent severity", "Agent finding(s)"],
            [
                [
                    m.deterministic.severity,
                    m.deterministic.rule_id,
                    m.deterministic.title,
                    m.deterministic.resource_name,
                    f"{m.agent_severity} ({m.severity_agreement})",
                    ", ".join(f"`{i}`" for i in m.agent_finding_ids),
                ]
                for m in c.found
            ],
        )
    )

    md.append(f"\n## 4. Agent findings outside the rules ({len(c.agent_unmatched)})\n")
    md.append(
        "Passed validation (real resource, real field) but match no deterministic finding: "
        "either an issue the rules do not check, or a weak/incorrect claim. Needs human "
        "review. Details: `agent_report.md`.\n"
    )
    md.append(_refs_table(c.agent_unmatched))

    md.append(f"\n## 5. Agent findings rejected by validation ({len(c.agent_rejected)})\n")
    md.append(_refs_table(c.agent_rejected))
    if c.agent_out_of_scope:
        md.append(
            f"\n_Out of scope (assessment infrastructure, not counted): "
            f"{len(c.agent_out_of_scope)}._\n"
        )

    md.append("\n## 6. How matching works\n")
    md.append("\n".join(f"- {line}" for line in c.method) + "\n")
    return "\n".join(md)


def write_comparison(comparison: Comparison, output_dir: Path) -> Path:
    """Write the comparison (.json + .md); return the .md path."""
    return write_files(
        output_dir,
        comparison.run_id,
        COMPARISON_REPORT,
        comparison.model_dump_json(indent=2),
        render_comparison_markdown(comparison),
    )
