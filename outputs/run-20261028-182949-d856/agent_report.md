# Agent Security Assessment — `run-20261028-182949-d856`

**Agent status:** error · **Overall risk (agent):** n/a · **Generated:** 2026-10-28 18:42 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v5 · **Snapshot:** `snap-9b3a3ad7a5fe1631`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. Every finding below passed evidence validation and still needs human review. What it missed is in `comparison.md`.

## 1. Summary

The agent produced no valid assessment (status: error). See errors below.

Findings: 0 () · rejected: 0 · out of scope: 0


## 2. Findings

_None._


## 3. Rejected findings (failed evidence validation)

_None._


## 4. Recommendations

_None._


## 5. Limitations (stated by the agent)

_None._


**Errors / notes during the run:**

- agent: BadRequestError: Error code: 400 - {'error': {'message': "This model's maximum context length is 131072 tokens. However, your prompt contains at least 131073 input tokens, which exceeds this limit even without any output tokens. Please reduce the length of the input prompt. (parameter=input_tokens, value=131073)", 'type': 'BadRequestError', 'param': 'input_tokens', 'code': 400}}


## 6. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 781.8s / 0.99s / 22.09s / 758.01s |
| Tool calls (total / by agent / blocked) | 489 / 36 / 1 |
| Values redacted | 444 |
| Model requests | 0 |
| Tokens (in / out / total) | n/a / n/a / n/a |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_list`×2, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `trivy.findings_list`×458, `trivy.scan_image`×16, `trivy.trivy_version`×1
