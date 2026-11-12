"""MCP integration layer: guarded MCP clients, tool policy, result shaping.

NOTE: this package is named `mcp` *inside* `docker_security_agent`, so always
import it as `docker_security_agent.mcp...`. The third-party MCP SDK is the
top-level `mcp` package and is imported as plain `mcp` (absolute imports).
"""
