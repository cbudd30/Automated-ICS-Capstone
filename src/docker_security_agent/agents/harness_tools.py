"""The agent's two harness tools (h2): ``evidence_get`` and ``record_container_section``.

Neither gives the agent anything new about the environment. ``evidence_get``
reads back results of the agent's *own* earlier tool calls (from the evidence
store, mcp/evidence.py); ``record_container_section`` writes the agent's own
structured analysis of one container. The deterministic findings stay out of
reach, so the agent's results remain its own.

Both are recorded in the tool-call audit trail (server ``harness``) and count
toward the agent's tool-call budget, so a fetch loop still ends.
"""

from __future__ import annotations

import re
from typing import Any

from agents import FunctionTool, function_tool

from docker_security_agent.mcp.evidence import EvidenceStore, StoredOutput
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.shaping import (
    inspect_lines,
    shape_result,
    to_text,
    trivy_finding_readable,
    trivy_findings_text,
)
from docker_security_agent.schemas.reports import AgentFinding, ContainerSection

HARNESS_SERVER = "harness"
EVIDENCE_GET = "evidence_get"
RECORD_SECTION = "record_container_section"

_INDEX_RE = re.compile(r"\[(\d+)\]")


def _norm_path(path: str) -> str:
    return _INDEX_RE.sub(r".\1", path.strip()).strip(".").lower()


def _select_lines(lines: list[str], select: str) -> list[str]:
    """Lines whose field path starts with ``select``; else whose path contains it."""
    want = _norm_path(select)
    paths = [_norm_path(line.split(": ", 1)[0]) for line in lines]
    picked = [
        ln for ln, p in zip(lines, paths, strict=True) if p == want or p.startswith(want + ".")
    ]
    return picked or [ln for ln, p in zip(lines, paths, strict=True) if want in p]


def _select_findings(page: dict[str, Any], select: str) -> dict[str, Any]:
    """Filter a findings_list page: ``package=NAME``, ``severity=LEVEL`` or an ID/text."""
    key, _, value = select.partition("=")
    key, value = key.strip().lower(), value.strip().lower()

    def keep(raw: dict[str, Any]) -> bool:
        f = trivy_finding_readable(raw)
        if value and key in ("package", "severity"):
            return str(f.get(key, "")).lower() == value
        return select.strip().lower() in " ".join(str(v) for v in f.values()).lower()

    return {**page, "findings": [f for f in page.get("findings") or [] if keep(f)]}


def render_stored(stored: StoredOutput, select: str = "") -> str:
    """A stored result in its shaped form, optionally narrowed by ``select``."""
    docs = [i for i in stored.items if isinstance(i, dict)]
    if stored.tool.endswith("_inspect") and docs:
        lines = [line for d in docs for line in inspect_lines(d)]
        return "\n".join(_select_lines(lines, select) if select else lines)
    if stored.tool == "findings_list" and docs:
        page = _select_findings(docs[0], select) if select else docs[0]
        return trivy_findings_text(page)
    shaped = shape_result(stored.tool, stored.items)
    text = to_text(shaped, 10**9)
    if select:
        text = "\n".join(line for line in text.splitlines() if select.lower() in line.lower())
    return text


def build_harness_tools(
    store: EvidenceStore, recorder: ToolCallRecorder, max_result_chars: int
) -> list[FunctionTool]:
    """Create the two harness tools bound to this run's evidence store.

    Both are ``async``: the SDK runs plain functions in a worker thread
    (``asyncio.to_thread``), and the store's SQLite connection may only be used
    by the thread that opened it (the event loop's).
    """

    @function_tool(name_override=EVIDENCE_GET)
    async def evidence_get(ref: str, select: str = "") -> str:
        """Read back a stored result of one of your earlier tool calls.

        Args:
            ref: The reference shown at the start of that result, e.g. "E7".
            select: Optional. For inspect results, a field path such as
                "HostConfig.CapAdd" or "Mounts"; for findings_list results,
                "package=openssl", "severity=CRITICAL" or a CVE ID. Empty = all.
        """
        args = {"ref": ref, "select": select}
        stored = store.get(ref)
        if stored is None:
            recorder.add(
                phase="agent",
                server=HARNESS_SERVER,
                tool=EVIDENCE_GET,
                arguments=args,
                status="error",
                error="unknown reference",
            )
            known = ", ".join(store.outputs) or "none yet"
            return f"No stored result {ref!r}. Known references: {known}."
        body = render_stored(stored, select)
        if select and not body.strip():
            body = f"Nothing in {stored.ref} matches select={select!r}."
        header = f"[{stored.ref}] {stored.tool} {stored.subject}".rstrip()
        if select:
            header += f" (select={select})"
        text = f"{header}\n" + to_text(
            body, max(max_result_chars - len(header) - 1, 1), ref=stored.ref
        )
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=EVIDENCE_GET,
            arguments=args,
            status="ok",
            result_chars=len(text),
        )
        return text

    @function_tool(name_override=RECORD_SECTION)
    async def record_container_section(
        resource_name: str,
        findings: list[AgentFinding],
        evidence_refs: list[str],
        notes: list[str],
    ) -> str:
        """Record your finished analysis of ONE container, right after analysing it.

        Write it while the container's tool results are still in your context.
        Calling it again for the same container replaces the earlier section.

        Args:
            resource_name: Exact container name.
            findings: Every issue on this container, each with tool/field/value
                evidence copied from the tool results (same format as the final
                assessment's findings).
            evidence_refs: References (E1, E2...) of the results you used.
            notes: What you could not verify for this container; [] if none.
        """
        section = ContainerSection(
            resource_name=resource_name, findings=findings, evidence_refs=evidence_refs, notes=notes
        )
        store.save_section(section)
        recorder.add(
            phase="agent",
            server=HARNESS_SERVER,
            tool=RECORD_SECTION,
            arguments={
                "resource_name": resource_name,
                "findings": len(findings),
                "evidence_refs": evidence_refs,
            },
            status="ok",
        )
        return (
            f"Section for {resource_name} recorded ({len(findings)} findings). Its tool results "
            "may now be shortened in your context; they stay available with evidence_get. "
            "Continue with the next container."
        )

    return [evidence_get, record_container_section]
