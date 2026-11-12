"""GuardedMCPServer: an MCP client with policy, shaping and recording.

The OpenAI Agents SDK talks to MCP servers through ``MCPServer`` objects. We
use the SDK's own ``MCPServerStdio`` (it launches the server as a subprocess
and speaks MCP over stdin/stdout) and subclass it to intercept ``call_tool``.

Every tool call goes through the same pipeline::

      caller (LLM via SDK, or our collector)
        |
        v
    [0] EvidenceStore.find      -> (agent, h2) exact repeat? answer with its reference
    [1] ToolPolicy.check        -> refuse unapproved tools / bad arguments
    [2] budget check            -> refuse when the agent is out of tool calls
    [3] MCPServerStdio.call_tool-> the real MCP request (stdio subprocess)
    [4] ToolCallRecorder.add    -> metrics + SQLite audit trail
    [5] EvidenceStore.add       -> (agent, h2) store the full result as E<n>
    [6] shape_result + to_text  -> (agent only) lossless compaction, cap at a line
                                   boundary, "[E<n>] tool subject" header
        |
        v
    result returned to the caller

Two entry points:

* ``call_tool(...)``  - what the SDK calls when the *LLM* uses a tool.
                        Returns an MCP ``CallToolResult`` with shaped text.
* ``collect(...)``    - what *our application code* calls (inventory, scans).
                        Returns the full, parsed JSON items.

Tool results are passed on unredacted (harness h3): finding credentials is part
of what this experimental lab assesses, so environment values, labels and any
secrets in them reach the model, the evidence store and the reports as-is.

The subprocess environment is minimal: the MCP SDK passes only a few safe
variables (PATH, HOME, ...) plus what we set here, so API keys in our own
environment (e.g. OPENAI_API_KEY) are NOT inherited by MCP servers.
"""

from __future__ import annotations

import json
import time
from typing import Any

from agents.mcp import MCPServerStdio, create_static_tool_filter
from mcp.types import CallToolResult, TextContent

from docker_security_agent.config import MCPServerConfig
from docker_security_agent.mcp.evidence import EvidenceStore
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.shaping import shape_result, to_text


class ToolCallFailed(Exception):
    """Raised by ``collect`` when a tool call is refused or fails."""


def _parse_content(result: CallToolResult) -> list[Any]:
    """Turn MCP text content blocks into Python objects.

    docker-mcp-server returns one text block per resource (each a JSON doc);
    trivy-mcp returns one JSON text block. Non-JSON text is kept as a string.
    """
    items: list[Any] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is None:
            continue  # images/resources are not expected from these servers
        try:
            items.append(json.loads(text))
        except json.JSONDecodeError:
            items.append(text)
    return items


class GuardedMCPServer(MCPServerStdio):
    """``MCPServerStdio`` + policy + shaping + recording."""

    def __init__(
        self,
        config: MCPServerConfig,
        *,
        docker_host: str,
        policy: ToolPolicy,
        recorder: ToolCallRecorder,
        max_result_chars: int,
    ):
        # The Docker endpoint (docker_host in mcp_servers.yaml) is injected here.
        env = {**config.env, "DOCKER_HOST": docker_host}
        super().__init__(
            params={"command": config.command, "args": config.args, "env": env},
            name=config.name,
            # The approved tool list never changes during a run.
            cache_tools_list=True,
            client_session_timeout_seconds=config.client_session_timeout_seconds,
            # [visibility filter] the LLM only ever sees approved tools.
            tool_filter=create_static_tool_filter(allowed_tool_names=config.allowed_tools),
        )
        self.config = config
        self.policy = policy
        self.recorder = recorder
        self.max_result_chars = max_result_chars
        # Set by the pipeline for the agent phase (harness h2); None = h1 behaviour.
        self.evidence: EvidenceStore | None = None

    # ------------------------------------------------------------------ SDK path

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Invoked by the Agents SDK when the LLM calls one of our tools.

        With an evidence store (harness h2): an exact repeat of an earlier call
        is answered with the earlier reference instead of being run again, and
        every result is stored in full before its shaped form, headed by its
        reference, goes to the model.
        """
        store = self.evidence
        if store is not None:
            logged_args = arguments or {}
            earlier = store.find(self.name, tool_name, logged_args)
            if earlier is not None:
                self.recorder.add(
                    phase="agent",
                    server=self.name,
                    tool=tool_name,
                    arguments=logged_args,
                    status="duplicate",
                    error=f"same arguments as {earlier.ref}",
                )
                return _text_result(duplicate_message(earlier.ref, tool_name), is_error=False)

        ok, payload = await self._guarded_call(tool_name, arguments, phase="agent", meta=meta)
        if not ok:
            return _text_result(str(payload), is_error=True)  # an error/refusal message
        if store is None:
            return _text_result(to_text(shape_result(tool_name, payload), self.max_result_chars))

        stored = store.add(self.name, tool_name, logged_args, payload)
        header = f"[{stored.ref}] {tool_name}" + (f" {stored.subject}" if stored.subject else "")
        body = to_text(
            shape_result(tool_name, payload),
            max(self.max_result_chars - len(header) - 1, 1),
            ref=stored.ref,
        )
        text = f"{header}\n{body}"
        store.record_shaped_size(stored.ref, len(text))
        return _text_result(text)

    # ------------------------------------------------------------ application path

    async def collect(self, tool_name: str, arguments: dict[str, Any] | None = None) -> list[Any]:
        """Call a tool for the application itself; return the full parsed JSON items.

        Raises ``ToolCallFailed`` on refusal or error so callers can record it.
        """
        ok, payload = await self._guarded_call(tool_name, arguments, phase="collector")
        if not ok:
            raise ToolCallFailed(str(payload))
        return payload

    # ------------------------------------------------------------- shared pipeline

    async def _guarded_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        phase: str,
        meta: dict[str, Any] | None = None,
    ) -> tuple[bool, Any]:
        """Run steps [1]-[4] (see module docstring). Returns (ok, items_or_message)."""
        logged_args = arguments or {}

        # [1] policy
        decision = self.policy.check(self.name, tool_name, arguments)
        if not decision.allowed:
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="blocked",
                error=decision.reason,
            )
            return False, f"Refused by policy: {decision.reason}"

        # [2] budget (agent calls only)
        if self.recorder.budget_exhausted(phase):
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="budget_exhausted",
            )
            return False, (
                "Tool-call budget exhausted. Do not call more tools; produce your final "
                "assessment now using the evidence you already have."
            )

        # [3] the real MCP call
        started = time.perf_counter()
        try:
            raw = await super().call_tool(tool_name, decision.arguments, meta)
        except Exception as exc:  # transport errors, MCP errors, timeouts
            message = f"{type(exc).__name__}: {exc}"
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="error",
                duration_ms=_ms(started),
                error=message,
            )
            return False, f"Tool error: {message}"

        items = _parse_content(raw)
        size = sum(len(json.dumps(i)) if not isinstance(i, str) else len(i) for i in items)

        if raw.is_error:
            message = " ".join(i if isinstance(i, str) else json.dumps(i) for i in items)[:2000]
            self.recorder.add(
                phase=phase,
                server=self.name,
                tool=tool_name,
                arguments=logged_args,
                status="error",
                duration_ms=_ms(started),
                result_chars=size,
                error=message,
            )
            return False, f"Tool error: {message}"

        # [4] record success ([5] storing and [6] shaping happen in call_tool, agent path)
        self.recorder.add(
            phase=phase,
            server=self.name,
            tool=tool_name,
            arguments=logged_args,
            status="ok",
            duration_ms=_ms(started),
            result_chars=size,
        )
        return True, items


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)


def duplicate_message(ref: str, tool: str) -> str:
    return (
        f"Not run again: {tool} was already called with exactly these arguments, and its "
        f"result is stored as {ref}. Use that result. If it is no longer in your context, "
        f'call evidence_get("{ref}") (optionally with select=...) instead of repeating the call.'
    )
