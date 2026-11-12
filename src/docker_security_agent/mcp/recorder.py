"""Tool-call recording and the agent's tool-call budget.

Every tool call - by the application or by the LLM - is appended here as a
``ToolCallRecord``. The records end up in SQLite (``tool_calls`` table) and in
the report's execution metrics, which is what makes runs with different models
comparable ("model A needed 12 tool calls, model B needed 31").

The recorder also enforces ``agent.limits.max_tool_calls``: once the agent has
used its budget, further calls are refused with a message telling the model
to finish its assessment.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from docker_security_agent.schemas.observations import ToolCallRecord


class ToolCallRecorder:
    def __init__(self, max_agent_calls: int):
        self.max_agent_calls = max_agent_calls
        self.records: list[ToolCallRecord] = []

    @property
    def agent_calls(self) -> int:
        """Agent calls that consumed budget (blocked/refused calls count too:
        a model that keeps calling forbidden tools should still run out)."""
        return sum(1 for r in self.records if r.phase == "agent")

    def budget_exhausted(self, phase: str) -> bool:
        return phase == "agent" and self.agent_calls >= self.max_agent_calls

    def add(
        self,
        *,
        phase: str,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None,
        status: str,
        duration_ms: int = 0,
        result_chars: int = 0,
        error: str | None = None,
    ) -> ToolCallRecord:
        record = ToolCallRecord(
            timestamp=datetime.now(UTC),
            phase=phase,
            server=server,
            tool=tool,
            arguments=arguments or {},
            status=status,
            duration_ms=duration_ms,
            result_chars=result_chars,
            error=error,
        )
        self.records.append(record)
        return record

    # ---- summaries for metrics ---------------------------------------------

    def counts_by_tool(self) -> dict[str, int]:
        return dict(Counter(f"{r.server}.{r.tool}" for r in self.records))

    def blocked(self) -> int:
        return sum(1 for r in self.records if r.status in ("blocked", "budget_exhausted"))
