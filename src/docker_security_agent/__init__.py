"""Defensive Docker security assessment agent.

High-level map of the package (read in this order to understand the flow):

    config.py               Load YAML config + .env into typed Pydantic settings.
    cli.py                  `docker-audit` command-line interface (Typer).
    pipeline.py             One assessment run, end to end (the "main" workflow).

    mcp/                    Everything between the app and the MCP servers:
        policy.py             which tools / arguments are allowed (allow-list).
        shaping.py            shrink big tool results before the LLM sees them.
        recorder.py           log every tool call (for metrics + SQLite).
        servers.py            GuardedMCPServer = MCP client + policy + shaping.
        registry.py           build servers from config, health checks, setup.

    inventory/              Turn raw `docker inspect` JSON into typed assets.
    security/               Deterministic rules, Trivy parsing, scan orchestration.
    llm/                    Model factory (OpenAI / Ollama / vLLM) + capability checks.
    agents/                 The single DockerSecurityAssessmentAgent.
    memory/                 SQLite: agent sessions + structured assessment store.
    reporting/              agent and deterministic reports (.json + .md).
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
#   v5 - coverage: inspect every container and scan every image on a checklist
#        before finishing; one finding per affected container
#   v6 - (with harness h2) one container at a time, recording each container's
#        section right after analysing it; tool results carry references (E7)
#        and can be fetched back; final findings only for what no section covers
#   v7 - (with harness h3) the rule about "<redacted>" values is gone: tool results
#        are no longer redacted
#   v8 - (with harness h4) the out-of-scope note names the agent's own container
#        (no read-only proxy any more)
#   v9 - the agent documents issues only: no remediation per finding and no
#        recommendations list (analysts decide fixes); step 4's combinations are
#        examples, not an exhaustive list: also report weaknesses known from training;
#        no fixed tool-call estimate per container (budget raised in agent.yaml)
PROMPT_VERSION = "v9"

# Bumped whenever the harness around the agent changes what the model sees or
# can do, independently of the prompt text. Recorded in every run manifest.
#   h1 - full shaped tool results stay in context for the whole run; results cut
#        mid-text at max_tool_result_chars
#   h2 - lossless shaping (inspect -> "Path: value" lines, Trivy grouped by package,
#        exact duplicates removed, cut at line boundaries); every full result stored
#        (tool_outputs) under a reference + evidence_get; per-container sections
#        (record_container_section) merged into the assessment; older results
#        replaced by reference stubs before each model call (keep the last N);
#        exact repeat calls answered with the earlier reference
#   h3 - no redaction: tool results (environment values, labels, credentials) reach
#        the model, the evidence store, the database and the reports unmodified
#   h4 - no read-only proxy: the tools have full Docker access. Containment instead:
#        the agent runs in a container and Docker Desktop shares no Mac folders
HARNESS_VERSION = "h4"
