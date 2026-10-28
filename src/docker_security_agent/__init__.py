"""Defensive Docker security assessment agent.

High-level map of the package (read in this order to understand the flow):

    config.py               Load YAML config + .env into typed Pydantic settings.
    cli.py                  `docker-audit` command-line interface (Typer).
    pipeline.py             One assessment run, end to end (the "main" workflow).

    mcp/                    Everything between the app and the MCP servers:
        policy.py             which tools / arguments are allowed (allow-list).
        redaction.py          scrub secrets out of tool results.
        shaping.py            shrink big tool results before the LLM sees them.
        recorder.py           log every tool call (for metrics + SQLite).
        servers.py            GuardedMCPServer = MCP client + policy + redaction.
        registry.py           build servers from config, health checks, setup.

    inventory/              Turn raw `docker inspect` JSON into typed assets.
    security/               Deterministic rules, Trivy parsing, scan orchestration,
                            validation of the LLM's output, and the agent-vs-rules
                            comparison.
    llm/                    Model factory (OpenAI / Ollama / vLLM) + capability checks.
    agents/                 The single DockerSecurityAssessmentAgent.
    memory/                 SQLite: agent sessions + structured assessment store.
    reporting/              agent, deterministic and comparison reports (.json + .md).
    schemas/                Pydantic data models shared by all of the above.
"""

__version__ = "0.1.0"

# Bumped whenever the agent's instructions or first message change, so runs
# with different prompts can be told apart when comparing models.
#   v1 - findings listed in the first message; generic "verify" workflow
#   v2 - summary-only first message; explicit evidence-gathering workflow;
#        assessment-infrastructure containers labelled in evidence tools
#   v3 - evidence tools take optional arguments and return real error messages;
#        no example finding ID in the output schema
#   v4 - MCP tools only (no evidence tools, no deterministic findings); the first
#        message is the objective + out-of-scope containers; the agent reports its
#        own findings with tool/field/value evidence
PROMPT_VERSION = "v4"
