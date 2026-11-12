"""Tool access policy: which MCP tools may be called, and with which arguments.

There are two places tools are filtered:

1. **Visibility** - ``GuardedMCPServer`` passes ``allowed_tools`` to the SDK's
   ``create_static_tool_filter`` so the LLM never even *sees* unapproved tools.
2. **Call time** - ``ToolPolicy.check`` (this module) is consulted again on
   every call. This matters because a model can hallucinate a tool name, and
   because the application itself also calls tools (inventory collection).

Since harness h4 there is no read-only proxy: the MCP servers have full Docker
access, so this policy is what keeps the agent to its approved tools. The
containment boundary is the agent's container plus Docker Desktop sharing no
Mac folders (docs/running-the-agent.md).

Argument rules (configured in mcp_servers.yaml -> argument_policy):

* ``scan_image`` may only target images that exist in the current inventory
  snapshot, so the agent cannot make Trivy pull arbitrary images from the
  internet. Scan types are limited (no ``secret`` scanning, which would return
  secret values) and the output format is forced to JSON.
* ``findings_list`` may only request the allowed categories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from docker_security_agent.config import MCPConfig


@dataclass
class PolicyDecision:
    """Result of a policy check."""

    allowed: bool
    reason: str = ""
    # Arguments after normalisation (e.g. forced outputFormat). Use these,
    # not the original arguments, when calling the tool.
    arguments: dict[str, Any] = field(default_factory=dict)


class ToolPolicy:
    """Allow-list + argument validation for every MCP tool call."""

    def __init__(self, mcp_config: MCPConfig):
        # server name -> set of approved tool names
        self._allowed: dict[str, set[str]] = {
            s.name: set(s.allowed_tools) for s in mcp_config.servers.values() if s.enabled
        }
        self._scan = mcp_config.argument_policy.scan_image
        # Filled by set_scan_targets() once the inventory is known.
        self._scan_targets: set[str] | None = None

    # ---- configuration ----------------------------------------------------

    def set_scan_targets(self, image_references: set[str]) -> None:
        """Tell the policy which image references exist (from the snapshot)."""
        self._scan_targets = set(image_references)

    def allowed_tools(self, server: str) -> list[str]:
        return sorted(self._allowed.get(server, set()))

    def is_tool_allowed(self, server: str, tool: str) -> bool:
        return tool in self._allowed.get(server, set())

    # ---- the check --------------------------------------------------------

    def check(self, server: str, tool: str, arguments: dict[str, Any] | None) -> PolicyDecision:
        """Decide whether ``server.tool(arguments)`` may run."""
        args = dict(arguments or {})

        if not self.is_tool_allowed(server, tool):
            return PolicyDecision(
                False, f"Tool '{tool}' on server '{server}' is not in the approved tool list."
            )

        if tool == "scan_image":
            return self._check_scan_image(args)
        if tool == "findings_list":
            return self._check_findings_list(args)
        return PolicyDecision(True, arguments=args)

    def _check_scan_image(self, args: dict[str, Any]) -> PolicyDecision:
        target = str(args.get("target", "")).strip()
        if not target:
            return PolicyDecision(False, "scan_image requires a 'target' image reference.")

        if self._scan.restrict_targets_to_inventory:
            if self._scan_targets is None:
                return PolicyDecision(
                    False, "No inventory snapshot loaded; image scans are not permitted yet."
                )
            if target not in self._scan_targets:
                return PolicyDecision(
                    False,
                    f"Image '{target}' is not in the current Docker inventory. Only local "
                    "images listed by image_list/container_inspect may be scanned.",
                )

        # Keep only approved scan types; default to the first approved one.
        requested = args.get("scanType") or []
        if isinstance(requested, str):
            requested = [requested]
        scan_types = [t for t in requested if t in self._scan.allowed_scan_types]
        args["scanType"] = scan_types or self._scan.allowed_scan_types[:1]
        args["targetType"] = "image"
        args["outputFormat"] = self._scan.forced_output_format
        args["target"] = target
        return PolicyDecision(True, arguments=args)

    def _check_findings_list(self, args: dict[str, Any]) -> PolicyDecision:
        if not args.get("batchID"):
            return PolicyDecision(False, "findings_list requires 'batchID' from scan_image.")
        categories = args.get("categories") or []
        if isinstance(categories, str):
            categories = [categories]
        allowed = [c for c in categories if c in self._scan.allowed_scan_types]
        args["categories"] = allowed or self._scan.allowed_scan_types[:1]
        args.setdefault("minSeverity", "UNKNOWN")
        return PolicyDecision(True, arguments=args)
