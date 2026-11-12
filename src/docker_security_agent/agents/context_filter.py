"""Context management before every model call (harness h2).

``RunConfig.call_model_input_filter`` runs immediately before each model
request and may change what is sent, not what is stored: the session still
holds every item in full. ``ContextFilter``:

* keeps the most recent ``keep_recent`` tool results in full;
* replaces each older one with a one-line stub that names its reference, so
  the agent can fetch it back with ``evidence_get``, and, when the agent has
  already written that container's section, says so;
* never shortens the harness tools' own results (``evidence_get`` output is
  what the agent fetched on purpose: shortening it would make it fetch again).

Correlation is by the reference at the start of each result (``[E7] ...``,
written by GuardedMCPServer), plus ``call_id`` to identify the tool, so the
stub always replaces the result it describes.

The filter is a pure function of its input: it stores nothing and its stubs
start with the same reference, so applying it again gives the same result.
The SDK's built-in ``ToolOutputTrimmer`` is not used because it keeps a
character preview instead of a reference to the full result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agents.run_config import CallModelData, ModelInputData

from docker_security_agent.agents.harness_tools import EVIDENCE_GET, RECORD_SECTION
from docker_security_agent.mcp.evidence import EvidenceStore

PROTECTED_TOOLS = frozenset({EVIDENCE_GET, RECORD_SECTION})
STUB_MARKER = "full result removed from context"
_REF_RE = re.compile(r"^\[(E\d+)\]")


def _output_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        return "".join(str(part.get("text", "")) for part in output if isinstance(part, dict))
    return ""


def stub_text(store: EvidenceStore, ref: str) -> str:
    stored = store.get(ref)
    if stored is None:
        return f'[{ref}] {STUB_MARKER}. Fetch it with evidence_get("{ref}").'
    what = f"{stored.tool} {stored.subject}".rstrip()
    section = store.section_for(stored)
    written = f" Your section for {section} is already recorded." if section else ""
    return (
        f"[{ref}] {what}: {STUB_MARKER} to save space.{written} "
        f'Fetch it with evidence_get("{ref}") (select=... for one part).'
    )


@dataclass
class ContextFilter:
    store: EvidenceStore
    keep_recent: int = 8

    def __call__(self, data: CallModelData[Any]) -> ModelInputData:
        items = data.model_data.input
        tool_of = {
            it.get("call_id"): it.get("name")
            for it in items
            if isinstance(it, dict) and it.get("type") == "function_call"
        }
        candidates: list[tuple[int, str]] = []
        for i, it in enumerate(items):
            if not (isinstance(it, dict) and it.get("type") == "function_call_output"):
                continue
            if tool_of.get(it.get("call_id")) in PROTECTED_TOOLS:
                continue
            match = _REF_RE.match(_output_text(it.get("output")))
            if match:
                candidates.append((i, match.group(1)))

        old = candidates[: max(len(candidates) - self.keep_recent, 0)]
        if not old:
            return data.model_data
        new_items = list(items)
        for i, ref in old:
            item = dict(items[i])
            stub = stub_text(self.store, ref)
            if isinstance(item.get("output"), list):
                item["output"] = [{"type": "input_text", "text": stub}]
            else:
                item["output"] = stub
            new_items[i] = item
        return ModelInputData(input=new_items, instructions=data.model_data.instructions)
