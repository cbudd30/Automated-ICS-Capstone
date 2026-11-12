# Docker Security Assessment Agent for ICS Environments

An agentic AI framework that helps **cyber defenders** assess the security posture of
containerized industrial control system (ICS) environments. A single AI agent
(`DockerSecurityAssessmentAgent`, built on the OpenAI Agents SDK) inspects authorized
Docker resources through **read-only MCP tools**, decides by itself what to inspect and
scan, and reports the risks it finds for an OT context. Independently, **deterministic
security rules** and **Trivy image scans** assess the same environment. The agent never
sees their results. Every run
produces evidence-backed **JSON and Markdown reports**: what the agent found, and what the
deterministic checks found. The two are independent: nothing scores one against the other.

The first target environment is [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3), a
Docker-based OT/ICS security lab that simulates a chemical plant. The tool is not tied to
GRFICS: it assesses whatever runs on the Docker engine it is pointed at.

> **This is a defensive auditing tool.** It only reads Docker metadata and scanner results.
> It does not perform exploitation, active network scanning, credential attacks, privilege
> escalation, lateral movement, container-escape testing, PLC communication, or any
> modification of the environment. These limits are enforced technically (see
> [Security boundaries](#6-security-boundaries)), not only by the prompt.

---

## Table of contents

1. [Project status](#1-project-status)
2. [Quick start](#2-quick-start)
3. [Setup instructions (step by step)](#3-setup-instructions-step-by-step)
4. [How it works](#4-how-it-works)
5. [Architecture](#5-architecture)
6. [Security boundaries](#6-security-boundaries)
7. [MCP integrations](#7-mcp-integrations)
8. [LLM providers](#8-llm-providers)
9. [Deterministic security rules](#9-deterministic-security-rules)
10. [Findings, evidence and reports](#10-findings-evidence-and-reports)
11. [Persistence and model-comparison reproducibility](#11-persistence-and-model-comparison-reproducibility)
12. [CLI reference](#12-cli-reference)
13. [Code tour: where to start reading](#13-code-tour-where-to-start-reading)
14. [Testing](#14-testing)
15. [Running GRFICSv3 on macOS](#15-running-grficsv3-on-macos)
16. [Known limitations](#16-known-limitations)
17. [Troubleshooting](#17-troubleshooting)
18. [Recommended next milestone](#18-recommended-next-milestone)

---

## 1. Project status

> **Since 2026-11-09 (harness h4) there is no read-only Docker proxy.** The agent runs in
> its own container with full Docker access, Docker Desktop shares no Mac folders, and the
> lab is rebuilt from the `clean-v2` baseline. How to run it, what contains it and how to
> recover: [`docs/running-the-agent.md`](docs/running-the-agent.md), sections "Every
> experiment" and "Containment and recovery". Parts of this README below that describe the
> proxy, `require_proxy` or `clean-v1`, and the verification results in section 14,
> describe the setup before that date.

Milestone 1 is implemented. Every command in this README was run on the development
machine (macOS 15, Apple Silicon, Docker Desktop 4.88 / Engine 29.7.2, Ollama 0.40.1).

| Phase | What | Status |
|---|---|---|
| 1 | GRFICSv3 review, MCP research, architecture ([`docs/mcp-selection.md`](docs/mcp-selection.md)) | Done |
| 2 | uv project, config loading, CLI, tests | Done |
| 3 | MCP integration: registry, allow-list policy, result shaping (redaction removed in h3, read-only proxy removed in h4) | Done, verified live |
| 4 | Model factory: OpenAI, Ollama, vLLM; capability checks | Done. Ollama verified live; OpenAI and vLLM verified with unit tests and mocked HTTP (no API key or vLLM server was available) |
| 5 | Deterministic rules (20 configuration rules + V001 scanner rule), Trivy integration, findings and evidence schemas | Done, verified live |
| 6 | Single agent with autonomous tool selection | Done, verified live with `qwen3:14b` |
| 7 | SQLite sessions and assessment store; JSON and Markdown reports | Done |
| 8 | Automated tests, controlled live assessment, read-only verification | Done (see [Testing](#14-testing)) |
| 9 | Agent discovers issues on its own (MCP tools only, prompt v4); three reports per run; agent scored against the deterministic findings | Done, verified with the automated tests (scripted model + fake MCP servers). **Not yet run live**: the live results in [Testing](#14-testing) are from prompt v3 |

---

## 2. Quick start

The agent runs in its own container (harness h4). For the full procedure, including the
GPU VM, see [`docs/running-the-agent.md`](docs/running-the-agent.md):

```bash
uv sync                                       # host tools: range.sh, model checks
cp .env.example .env                          # API keys / endpoints
deploy/agent/build.sh                         # build the agent image
deploy/agent/run.sh setup                     # Trivy DB in the agent's volume
deploy/agent/run.sh doctor                    # everything green?
deploy/grfics/range.sh reset clean-v2         # lab at its known starting state
caffeinate -i deploy/agent/run.sh assess --model local-vllm --range-baseline clean-v2
```

The reports are written to `outputs/<RUN_ID>/`: `agent_report.md` and
`deterministic_report.md` (each with a `.json` twin).

---

## 3. Setup instructions (step by step)

### 3.1 Prerequisites

| Requirement | Why | Install / check |
|---|---|---|
| macOS (or Linux) | development platform | — |
| **Docker Desktop** (running) | the environment being assessed | https://docs.docker.com/desktop/ · check: `docker info` |
| **uv** | Python 3.12, virtualenv, dependencies; also launches docker-mcp-server via `uvx` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` · check: `uv --version` |
| **Trivy** | image vulnerability scanner used by the trivy-mcp server | `brew install trivy` · check: `trivy --version` |
| Ollama *(optional)* | local models | https://ollama.com · check: `ollama list` |
| OpenAI API key *(optional)* | frontier model | put `OPENAI_API_KEY` in `.env` |
| vLLM server *(optional)* | self-hosted models | see [8.3](#83-vllm) |

You do **not** need to install Python yourself (uv downloads 3.12 into `.venv`) or install
any MCP server manually:

- **docker-mcp-server** is started on demand with `uvx docker-mcp-server==2.2.7`, which
  downloads the pinned version into uv's cache on first use.
- **trivy-mcp** is a Trivy *plugin*. `docker-audit setup` (and `assess`, when the plugin is
  missing) runs `trivy plugin install mcp@v0.0.20` automatically. Only the `trivy` binary
  itself is a manual prerequisite.

### 3.2 Install the project

```bash
git clone <this repository>
cd Automated-ICS-Exploitation-Capstone
uv sync            # creates .venv with Python 3.12 and installs exact versions from uv.lock
```

> If your shell has another virtualenv activated, uv prints a warning that `VIRTUAL_ENV`
> does not match and ignores it. That is expected; run `deactivate` to silence it.

### 3.3 Configure secrets and endpoints (optional)

```bash
cp .env.example .env
```

Edit `.env` only for what you use: `OPENAI_API_KEY` / `OPENAI_MODEL` for OpenAI,
`VLLM_BASE_URL` / `VLLM_MODEL` / `VLLM_API_KEY` for vLLM, and `OLLAMA_BASE_URL` if Ollama
is not on `localhost:11434`. `.env` is git-ignored. Its values are read from the
environment only and are never written to reports, SQLite or logs.

### 3.4 Docker access and containment

There is no read-only proxy since harness h4: the MCP servers use the Docker socket
(`docker_host: unix:///var/run/docker.sock` in `config/mcp_servers.yaml`) with full
access. Containment comes from running the agent in its container and from Docker Desktop
sharing no Mac folders; see "Containment and recovery" in
[`docs/running-the-agent.md`](docs/running-the-agent.md).

### 3.5 One-time setup: Trivy plugin and vulnerability database

```bash
uv run docker-audit setup
```

This installs the trivy-mcp plugin if it is missing and downloads Trivy's vulnerability
database (about 120 MB). The download is required because trivy-mcp always runs Trivy
with `--skip-update`.

### 3.6 Prepare a local model (Ollama)

```bash
uv run docker-audit models --provider ollama        # installed models + tool support + context
```

Two things matter:

1. **Tool calling.** The agent loop needs a model whose Ollama capabilities include
   `tools`. For example, `qwen3:14b` and `gpt-oss` have it, while `dolphin3:latest`
   reports only `completion` and is refused with a clear error.
2. **Context window.** Through its OpenAI-compatible API, Ollama runs every model with a
   **4,096-token** context unless the model sets `num_ctx`, and it ignores per-request
   overrides. The agent's prompt and tool schemas would be silently truncated. Create a
   larger-context variant once; it reuses the same weights, so nothing is downloaded:

   ```bash
   uv run docker-audit models --provider ollama --create-variant qwen3:14b --num-ctx 32768
   # -> creates "qwen3:14b-ctx32k" (used by the local-qwen profile). Remove with: ollama rm qwen3:14b-ctx32k
   ```

### 3.7 Verify everything

```bash
uv run docker-audit doctor          # config, Docker, MCP servers, Trivy DB, default model
uv run docker-audit mcp check       # starts both MCP servers, compares tools with the allow-list
uv run docker-audit models          # every model profile with capability status
```

Expected `mcp check` output (abridged):

```text
✓ docker (docker_inspection): 77 tools registered, 11 exposed to the agent
✓ trivy (image_scanner): 6 tools registered, 4 exposed to the agent
```

### 3.8 Run assessments

```bash
uv run docker-audit inventory                       # read-only inventory snapshot (no LLM)
uv run docker-audit assess --no-agent               # rules + Trivy only (no LLM)
uv run docker-audit assess --model local-qwen       # full assessment with the agent
uv run docker-audit runs                            # list runs
uv run docker-audit report --run-id <RUN_ID>        # view a stored report
```

### 3.9 (Optional) Deploy GRFICSv3 as the target

See [Running GRFICSv3 on macOS](#15-running-grficsv3-on-macos). The assessment tool works
the same way against any Docker environment. During development it was run against a
locally running ICS range (20 containers, 38 images, 8 networks).

### 3.10 Run the agent in its Docker container

This is now the standard way to run the agent (harness h4). `deploy/agent/compose.yml`
mounts no Mac folder: config is built into the image, the agent reaches Docker through the
socket, and `deploy/agent/run.sh` copies each run's `outputs/<RUN_ID>/` and databases
(`data/container/`) back to the Mac with `docker cp`. Steps: see
[`docs/running-the-agent.md`](docs/running-the-agent.md).

---

## 4. How it works

One `docker-audit assess` run (`src/docker_security_agent/pipeline.py`):

```text
0. preflight      model capability check; Docker reachable ONLY via the read-only proxy;
                  trivy-mcp plugin + Trivy DB present (installed if missing)
1. record run     SQLite `runs` row (status=running)
2. deterministic  the APPLICATION (not the LLM) collects evidence:
                    a) inventory snapshot via docker-mcp-server (5 read-only tool calls)
                    b) 20 deterministic rules -> confirmed findings
                    c) Trivy scan of every image in use via trivy-mcp -> confirmed V001 findings
                  This is the answer key. The agent never sees it.
3. agent          DockerSecurityAssessmentAgent gets ONLY the objective (and which
                  containers are out of scope) and the approved MCP tools. It DECIDES
                  which containers, networks and images to inspect and which images to
                  scan, and returns its own findings, each with the tool, field and value
                  it is based on (AgentAssessment)
4. persist        findings, scans, tool calls, metrics, the two reports -> SQLite
5. reports        outputs/<RUN_ID>/agent_report.{json,md}, deterministic_report.{json,md}
                  (the agent's findings are reported as it gave them, unchecked)
```

**Why step 2 runs first.** The agent's guard rails need the inventory: the tool policy
only lets Trivy scan images that exist. The agent itself gets nothing from it: no summary,
no finding counts, no stored scans. It has to discover the environment with its tools,
which is what makes its tool use and its findings comparable across models.

**Division of labor.** Deterministic code decides *what is objectively true*: rule
matches, scanner output, schema validity and evidence linkage. The agent shows *what an
LLM can discover on its own* and how it explains and prioritizes it for an OT
environment. The two reports are read side by side; there is no automatic scoring. If the
agent fails (timeout, bad output, weak tool calling), the deterministic report is still
produced.

**Three modes:**

| Mode | Command | Docker access | LLM | Reports |
|---|---|---|---|---|
| live | `assess --model X` | yes (read-only) | yes | agent, deterministic |
| deterministic | `assess --no-agent` | yes (read-only) | no | deterministic |
Every run collects fresh evidence from the live lab (replay of stored evidence was removed
on 2026-11-09). To compare models fairly, reset the range to the same baseline before each
live run (see
[Resetting the range](#resetting-the-range-between-runs)).

---

## 5. Architecture

```text
                     User / CLI (docker-audit, Typer)
                                 |
                                 v
         Experiment configuration (config/*.yaml + .env, Pydantic-validated)
                                 |
                                 v
                    pipeline.run_assessment  (one run)
       +-------------------------+------------------------------+
       |                         |                              |
       v                         v                              v
  Model factory          MCP layer (mcp/)                 SQLite memory (memory/)
  llm/factory.py         GuardedMCPServer =                 - SDK SQLiteSession
   - OpenAI  (Responses)   MCPServerStdio                     (agent conversations)
   - Ollama  (ChatCompl.)  + ToolPolicy (allow-list,        - AssessmentRepository
   - vLLM    (ChatCompl.)    argument rules)                  (runs, snapshots, scans,
  llm/capabilities.py      + (no redaction since h3)          vulns, findings,
   (tools / context /      + shaping (compact results)        tool_calls)
    structured output)     + ToolCallRecorder (audit)
       |                   + leak guardrail (SDK)
       |                         |
       |              +----------+-----------+
       |              v                      v
       |     docker-mcp-server 2.2.7    trivy-mcp 0.0.20
       |     (uvx, READONLY=1,          (Trivy plugin,
       |      11 tools approved)         4 tools approved)
       |              |                      |
       |              +----------+-----------+
       |                         v
       |         docker-socket-proxy (GET/HEAD only, 127.0.0.1:2375)
       |                         v
       |                Docker Engine -> GRFICSv3 / ICS containers
       v
  DockerSecurityAssessmentAgent (agents/security_assessment.py, OpenAI Agents SDK)
     tools = the approved MCP tools ONLY (no access to the deterministic results)
                                 |
                                 v
   security/ rules.py · vulnerability_parser.py · scanner.py   (deterministic findings)
                                 |
                                 v
   reporting/ agent_report.py · generator.py
              -> agent_report · deterministic_report (.json + .md)
```

The application runs on the macOS host in a project-specific `.venv`. It never runs inside
GRFICS's Kali container, never joins the GRFICS networks, and does not scan networks.

---

## 6. Security boundaries

Docker daemon access can amount to root on the host, even when a tool only *intends* to
read. Since harness h4 the agent deliberately has that access; layers 1 and 4 below were
removed, and containment (the agent's container plus no Docker Desktop file sharing)
keeps it inside Docker. The table records all four original layers:

| # | Layer | Mechanism | Verified |
|---|---|---|---|
| 1 | **API boundary (removed in harness h4)** | Was `docker-socket-proxy`: `POST=0`; only CONTAINERS/IMAGES/NETWORKS/VOLUMES/INFO/VERSION enabled; bound to 127.0.0.1. MCP servers get `DOCKER_HOST=tcp://127.0.0.1:2375` and never the socket. | `POST .../exec`, `POST .../stop` and `GET /secrets` → **403**. During assessments the proxy log shows only GET/HEAD. |
| 2 | **Server mode** | `DOCKER_MCP_SERVER_READONLY=1` unregisters mutating tools. | 77 tools remain, including `secret_inspect`, `swarm_join_tokens`, `container_archive_get`. **Read-only mode is not enough on its own.** |
| 3 | **Tool allow-list** | `allowed_tools` in `config/mcp_servers.yaml`, applied to *visibility* (SDK `create_static_tool_filter`) and again at *call time* (`ToolPolicy`). Trivy `scan_image` may only target images in the current inventory, `secret` scanning is stripped, and output is forced to JSON. | `mcp check`: 11 of 77 Docker tools and 4 of 6 Trivy tools are exposed. Integration tests call `container_exec` and `scan_filesystem` directly and they are refused before reaching the server. |
| 4 | **Redaction (removed in harness h3)** | Tool results are no longer scrubbed: finding credentials is part of this experimental lab, so environment values, labels and secrets reach the model, SQLite and the reports as Docker returns them. | `tests/integration`: credential values are present in what the agent sees and in the snapshot. |

Other controls:

- **Minimal subprocess environment.** The MCP SDK passes only a few safe variables
  (`PATH`, `HOME`, ...) to MCP servers, so `OPENAI_API_KEY` and similar are not inherited.
- **Tool output is data, not instructions.** The agent's instructions say so, and
  trivy-mcp's `meta` block (which contains instructions addressed to the assistant) is
  removed before results reach the model.
- **Limits.** `max_turns` (30), `max_tool_calls` (40) and a wall-clock timeout (1200 s)
  are configurable in `config/agent.yaml`.
- **The range reset is outside the boundary on purpose.** `deploy/grfics/range.sh` changes
  the lab, so it uses the operator's own Docker access and is never available to the agent.
  docker-audit only *verifies* resets.
- **Containment instead of a proxy (harness h4).** The agent runs in a container that mounts
  no Mac folder, and Docker Desktop shares no Mac folders (`mounts denied`), so its full
  Docker access stays inside Docker. Every live run records the Docker endpoint it used
  (`runs.docker_endpoint_json`). See "Containment and recovery" in the runbook.
- **Tracing is off by default.** The SDK would otherwise upload traces, including Docker
  metadata, to OpenAI even when a local model is used.
- **Read-only verification.** The end-to-end tests compare a fingerprint of all
  containers (with state), images, networks and volumes before and after a run, and
  assert that no new non-GET request appears in the proxy log.

---

## 7. MCP integrations

Full evaluation and live verification results: [`docs/mcp-selection.md`](docs/mcp-selection.md).

| Purpose | Selected | Approved tools |
|---|---|---|
| Docker inspection | [docker-mcp-server](https://pypi.org/project/docker-mcp-server/) 2.2.7 (L337-org, MIT), via `uvx`, `DOCKER_MCP_SERVER_READONLY=1` | `container_list`, `container_inspect`, `image_list`, `image_inspect`, `image_history`, `network_list`, `network_inspect`, `volume_list`, `volume_inspect`, `system_info`, `system_version` |
| Image vulnerabilities | [trivy-mcp](https://github.com/aquasecurity/trivy-mcp) 0.0.20 (Aqua Security, Trivy plugin) | `scan_image`, `findings_list`, `findings_get`, `trivy_version` |
| Rejected | `mcp-server-docker` (ckreiling) | has no read-only mode; exposes run/remove/build |
| Deferred | Docker MCP Toolkit / Gateway | catalog and gateway only; provides no inventory tools itself |

**No custom MCP server was built.** The only MCP-adjacent code is the thin wrapper
(`GuardedMCPServer`) that adds policy, shaping and recording around the SDK's
own `MCPServerStdio`. To enable or disable a server or tool, edit
`config/mcp_servers.yaml`; the agent code does not change.

---

## 8. LLM providers

The model factory (`llm/factory.py`) is the only code that knows about providers. The
agent receives an SDK `Model` and `ModelSettings`, so switching models is a config change.

| Provider | SDK class | Profiles in `config/models.yaml` |
|---|---|---|
| OpenAI | `OpenAIResponsesModel` | `openai-primary` (model from `OPENAI_MODEL`) |
| Ollama | `OpenAIChatCompletionsModel` + `AsyncOpenAI(base_url=…/v1)` | `local-qwen` (`qwen3:14b-ctx32k`), `local-gpt-oss`, `local-dolphin` |
| vLLM | `OpenAIChatCompletionsModel` + `AsyncOpenAI(base_url=…/v1)` | `local-vllm` |

### 8.1 Adding a model
Add a profile to `config/models.yaml`:

```yaml
profiles:
  my-llama:
    provider: ollama
    model: "llama3.1:8b-ctx32k"       # any installed Ollama model with tools capability
    base_url: "${OLLAMA_BASE_URL:-http://localhost:11434/v1}"
    temperature: 0.2
    timeout_seconds: 600
    structured_output: prompted       # or native
```

then run `uv run docker-audit assess --model my-llama`.

### 8.2 Structured output modes
- `native`: the provider enforces the `AgentAssessment` JSON schema (OpenAI default).
- `prompted`: the schema is described in the instructions and the application parses the
  JSON itself, tolerating `<think>` blocks and code fences. This is the default for local
  models, which often handle tool calls and enforced schemas together poorly.

### 8.3 vLLM
Start vLLM with tool calling enabled, for example:

```bash
vllm serve Qwen/Qwen3-14B --enable-auto-tool-choice --tool-call-parser hermes --max-model-len 32768
```

Set `VLLM_BASE_URL` / `VLLM_MODEL` in `.env`. vLLM cannot report whether tool calling is
enabled, so run `uv run docker-audit models --provider vllm --probe`, which sends a tiny
test tool call and a JSON-schema request.

### 8.4 Capability checks
`docker-audit models` / `doctor` check, per provider:
- **Ollama:** the model is installed (`/api/tags`), has the `tools` capability
  (`/api/show`), and its context window is large enough.
- **vLLM:** the endpoint is reachable and the model is served (`/v1/models`); `--probe`
  tests tool calls and structured output.
- **OpenAI:** the API key is present; `--probe` checks that the model ID is accessible.

---

## 9. Deterministic security rules

The logic is in `security/rules.py`. Toggles, severities and match lists are in
`config/security_rules.yaml`. Every finding carries the exact `docker inspect` field
path and observed value as evidence.

| ID | Rule | Default severity |
|---|---|---|
| C001 | Privileged mode | critical |
| C002 | Dangerous capabilities added (per-capability severity: SYS_ADMIN critical, NET_ADMIN/NET_RAW medium, ...) | high (max of caps) |
| C003 | Runs as root (container or image USER) | medium |
| C004 | Host namespace shared (network / PID / IPC / UTS / user) | high |
| C005 | seccomp / AppArmor / SELinux disabled | high |
| C006 | `no-new-privileges` not set | low |
| C007 | Writable root filesystem | low |
| C008 | **Docker socket mounted** | critical |
| C009 | Sensitive host path bind-mounted (system paths, whole home dirs, `~/.ssh`, `~/.aws`, ...; rw = high, ro = medium) | high |
| C010 | No capabilities dropped | low |
| C011 | Host devices mapped | medium |
| N001 | Ports published on all interfaces (exposure observation, **not** a vulnerability) | low |
| N002 | Container bridges multiple networks (segmentation) | medium |
| N003 | IP forwarding enabled in container | medium |
| N004 | Uses the default `bridge` network | low |
| N005 | User-defined network is not `internal` | info |
| R001 | Missing memory / CPU / PID limits | low |
| R002 | No restart policy | info |
| S001 | Credential-like environment variable *names* (values never read) | medium |
| I001 | Image on a floating tag (`latest` / untagged) | low |
| V001 | Image has known vulnerabilities (from Trivy; severity = highest CVE) | per scan |

Stopped containers are analyzed too (they can be restarted) and labelled as such. The
audit's own socket proxy is excluded through `ignore_containers`.

**Expected GRFICSv3 results**, taken from its `docker-compose.yml` and reproduced by the
fixture-based tests: C008 on `simulation` (Docker socket); C002 NET_ADMIN on every
service, plus NET_RAW on `router`; N003 and N002 on `router` (it forwards between the
admin, ICS and DMZ networks); S001 on `router` (`FWUI_SECRET_KEY`); C003 root everywhere;
N001 for all UI ports; R001 everywhere.

---

## 10. Findings, evidence and reports

Each finding (`schemas/findings.py`) has: a stable `id` (same rule, resource and detail
give the same ID across runs and models), `resource`, `category`, `severity`,
`confidence`, `evidence[]` (source, resource, path, value), `explanation`, `remediation`,
`status` and `source`:

| status | source | meaning |
|---|---|---|
| `confirmed` | `rule` / `scanner` | an objective fact from Docker metadata or Trivy |
| `potential` | `agent` | a finding the agent reported, as it gave it (not checked against the data); needs human review |

**Agent findings.** The agent returns each finding with `resource_name`, `severity`,
`evidence` (the tool it used, the field path such as `HostConfig.Privileged`, and the value
it saw), `vulnerability_ids` (CVE/GHSA IDs for image vulnerabilities), `explanation` and
`remediation` (`AgentAssessment` in `schemas/reports.py`). These are reported as the agent
gave them: nothing checks that the resource, field or CVE is real (the validator was
removed on 2026-11-09), so every agent finding has confidence `low` and needs human review.

**The two reports** (`outputs/<RUN_ID>/`):

| File | Contents |
|---|---|
| `agent_report.md` / `.json` | Only what the agent found: summary, its overall risk, its findings with evidence (unchecked), recommendations, its stated limitations, metrics |
| `deterministic_report.md` / `.json` | No AI: 1 summary · 2 environment overview · 3 container inventory · 4 image inventory · 5 network configuration · 6 prioritized findings · 7 misconfigurations · 8 known image vulnerabilities · 9 remediation · 10 limitations · 11 execution metrics |

A sample report from an earlier version (one combined `report.md`, before the agent was
separated from the deterministic results) is in [`docs/sample-report/`](docs/sample-report/).

---

## 11. Persistence and model-comparison reproducibility

| Store | File | Contents |
|---|---|---|
| Agent sessions | `data/agent_sessions.db` | OpenAI Agents SDK `SQLiteSession` (conversation history). Each run gets a new session by default; `--session NAME` continues a named one. |
| Assessment store | `data/assessments.db` | `runs` (model provider, ID and config, prompt version, MCP server versions, objective, snapshot, status, errors, metrics, the deterministic report, the agent report), `snapshots`, `scans`, `vulnerabilities`, `findings` (rule, scanner and agent), `tool_calls` |

**Comparing models on the same environment:** reset the range before each run, so every
model starts from the same verified state and is scored against the same answer key.

```bash
export GRFICS_DIR=~/path/to/GRFICSv3
deploy/grfics/range.sh reset clean-v1
uv run docker-audit assess --model local-qwen     --range-baseline clean-v1
deploy/grfics/range.sh reset clean-v1
uv run docker-audit assess --model local-gpt-oss  --range-baseline clean-v1
uv run docker-audit runs
uv run docker-audit report --run-id run-XXXX      # agent report (default); --kind deterministic
```

Snapshot IDs are content hashes of the security-relevant data. Volatile fields such as
PIDs and health-check timestamps are excluded, so an unchanged environment produces the
same ID. Each run records the prompt version (`PROMPT_VERSION` in
`src/docker_security_agent/__init__.py`), tool calls (name, arguments, duration,
status), token usage, timings and completion status. Historical
findings are always tied to their run and snapshot and are never presented as current
state.

**Run manifests (immutable experiment configuration).** Once a run's evidence is known,
it freezes a manifest (`src/docker_security_agent/manifest.py`) and writes it to
`outputs/<RUN_ID>/manifest.json`. The file is created once and made read-only, and it is
stored in the `runs` row with two hashes, both shown in the report:

| Hash | Covers | Meaning |
|---|---|---|
| `manifest_sha256` | the whole manifest | this exact run record (tamper evidence) |
| `config_sha256` | the `experiment` block only | the experimental configuration: equal hashes = same configuration |

The `experiment` block holds the scenario (`scenario_id` in `config/experiment.yaml`),
the objective, the range baseline the run started from (see
[Resetting the range](#resetting-the-range-between-runs)), the pinned evidence (snapshot ID **and the exact scan IDs**), the prompt
bundle (version + hash of the instructions), the schema versions, the model and sampling
parameters for each role, the agent limits, the rule configuration and the logging flags.
The rest of the manifest records the run ID and time, the framework commit (with a flag
for uncommitted changes), and how the evidence was gathered (MCP servers, Docker
endpoint, scan settings).

The manifest is a record only: runs can no longer be re-run from it (`--manifest` and
`--allow-drift` were removed on 2026-11-09). Group agent runs for comparison by range
baseline, prompt version and model.

---

## 12. CLI reference

| Command | Purpose |
|---|---|
| `docker-audit doctor [--probe]` | Validate config, Docker, MCP servers, Trivy DB and default model |
| `docker-audit setup [--skip-db]` | Install the trivy-mcp plugin; download/refresh the Trivy DB |
| `docker-audit models [--provider openai\|ollama\|vllm] [--probe]` | Model profiles with capability status; `--provider ollama` lists installed models |
| `docker-audit models --provider ollama --create-variant MODEL [--num-ctx N]` | Create a larger-context Ollama variant |
| `docker-audit mcp check` | Start each MCP server; registered vs. exposed vs. missing tools |
| `docker-audit mcp tools` | Exactly the tools (and descriptions) the agent sees |
| `docker-audit inventory [--json] [--no-save]` | Read-only inventory snapshot |
| `docker-audit assess [--model P] [--no-agent] [--no-scan] [--session NAME] [--objective TEXT] [--skip-model-check]` | Run an assessment on the live lab |
| `docker-audit assess ... --range-baseline NAME` | Abort unless the live range matches baseline NAME; recorded in the manifest |
| `docker-audit range record NAME` / `range verify NAME [--since ISO [--project P]]` / `range list` | Record or verify a named range baseline (read-only) |
| `deploy/grfics/range.sh save NAME` / `reset NAME` / `list` | Operator script: archive the lab as a baseline / reset the lab to it (changes the lab) |
| `docker-audit runs [--limit N]` | List runs |
| `docker-audit report --run-id ID [--kind agent\|deterministic] [--format md\|json\|path] [--raw]` | Show a stored report (default: the agent report) |

---

## 13. Code tour: where to start reading

Every module starts with a docstring explaining its role. A suggested reading order:

1. `src/docker_security_agent/__init__.py`: package map and prompt version.
2. `pipeline.py`: the whole workflow, top to bottom.
3. `mcp/servers.py`: `GuardedMCPServer`, the security-critical wrapper (policy,
   shaping, recording).
4. `mcp/policy.py`, `mcp/shaping.py`, `mcp/registry.py`.
5. `inventory/collector.py` and `inventory/parsers.py`: Docker JSON to typed assets.
6. `security/rules.py`: the 20 rules (each a small, documented function).
7. `security/scanner.py` and `security/vulnerability_parser.py`: Trivy via MCP.
8. `agents/security_assessment.py`: instructions, first message, agent construction (MCP
   tools only), run limits.
9. `reporting/agent_report.py`, `reporting/generator.py`,
    `memory/repository.py`, `llm/factory.py`, `llm/capabilities.py`, `cli.py`.

```text
.
├── config/                 models · agent · mcp_servers · security_rules · experiment (.yaml)
├── deploy/
│   └── grfics/docker-compose.macos.yml  GRFICSv3 macvlan -> bridge override
├── docs/  mcp-selection.md · sample-report/
├── src/docker_security_agent/
│   ├── cli.py · config.py · pipeline.py
│   ├── agents/security_assessment.py
│   ├── llm/        factory.py · capabilities.py
│   ├── mcp/        servers.py · policy.py · shaping.py · recorder.py · registry.py
│   ├── inventory/  collector.py · parsers.py
│   ├── security/   rules.py · findings.py · scanner.py · vulnerability_parser.py
│   ├── memory/     database.py · repository.py · sessions.py
│   ├── schemas/    assets.py · findings.py · observations.py · reports.py
│   └── reporting/  generator.py
└── tests/
    ├── unit/ · integration/ · e2e/
    └── fixtures/   grfics.py (GRFICS-like Docker JSON) · fake_mcp_server.py · builders.py
```

---

## 14. Testing

```bash
uv run pytest                      # unit + integration (default; no Docker, no LLM, no API)
uv run pytest -m e2e               # + live Docker/proxy/Trivy end-to-end
uv run pytest -m "e2e and llm"     # + live agent run with the default model
```

| Level | Files | What it covers | Needs |
|---|---|---|---|
| Unit (78) | `tests/unit/` | config validation; env expansion; policy (allow-list, scan targets, argument normalization); shaping (compaction, trivy `meta` removed, truncation); parsers; stable snapshot IDs; all rules against GRFICS-like fixtures (incl. a hardened container with **zero** findings); Trivy parsing and pagination; comparison (field and prefix matching, aliases, wording tie-breaks, image findings via containers, rejected findings never count, scores); SQLite repository; the two reports and their Markdown sections; model factory; Ollama/vLLM/OpenAI capability checks (mocked HTTP); prompted-JSON parsing; snapshot IDs independent of Docker's mount ordering | nothing |
| Integration (11) | `tests/integration/` | real MCP subprocesses (fake docker/trivy servers): hidden and refused dangerous tools, unredacted results over MCP, collection, scan pagination, graceful server failure; **real SDK agent loop** with the SDK's `ScriptedModel` (MCP-only tools, a first message without inventory or findings, session persistence, tool budget, max turns, invalid output); full pipeline live-with-fakes producing both reports, an agent scan outside the answer key refused, failed agent still producing reports, live re-run of an agent manifest | Python only |
| End-to-end (2) | `tests/e2e/` | full assessment against the real Docker host; Docker state fingerprint unchanged; no write request reached the proxy; live agent run | Docker + proxy + Trivy (+ Ollama for `llm`) |

The mocked tests use the OpenAI Agents SDK's own test double
(`agents.testing.ScriptedModel`), so the real SDK loop runs without an LLM.

**Results from the development machine (2026-10-08):**

| Suite | Result |
|---|---|
| `uv run pytest` (unit + integration) | **89 passed** in about 5 s |
| `uv run pytest -m "e2e and not llm"` | **1 passed**: full deterministic assessment of the live host; Docker state and proxy write-count unchanged |
| `uv run pytest -m "e2e and llm"` | **1 passed** in 6 min 38 s: live agent run with `qwen3:14b-ctx32k`, agent status `ok`, read-only verified |
| Not executed | OpenAI and vLLM live runs (no API key or vLLM server on the machine). Both are covered by unit tests with mocked HTTP and use the same SDK code path as Ollama. |

The live agent results above used prompt v3, in which the agent was given the
deterministic findings. Prompt v4 (MCP tools only, scored against those findings) has
been verified with the automated tests only.

**Containerized agent (2026-10-20, Docker Desktop 4.88.1 / Engine 29.7.2):**

| Check | Result |
|---|---|
| `docker compose ... run --rm test` (unit + integration in the image, no network) | **123 passed**, 2 deselected (same as `uv run pytest` on the host) |
| `doctor --probe` in the container | all checks OK: proxy `filtered=True`, both MCP servers, Trivy DB, `local-qwen` via `host.docker.internal` (tool-call probe OK) |
| `mcp check` in the container | identical to the host: docker 77 registered / 11 exposed, trivy 6 / 4 |
| ToolPolicy live in the container | `secret_inspect`, `container_archive_get` refused; `scan_image` outside the inventory refused; `secret`/`misconfig` scan types rewritten to `vuln`; proxy answered 403 to `POST /containers/plc/stop`, `/containers/create`, `/exec/x/start`, `GET /secrets` |
| `assess --no-agent`, host vs container, same Trivy DB | all 162 rule findings identical; 19/20 image scans identical. Differences: the container run also scans its own image `docker-audit-agent:latest` (one extra V001), see Known limitations |
| `assess --model local-qwen` in the container | completed, agent status `ok`, 412 s, 0 blocked tool calls, 0 rejected claims |
| Persistence | runs, reports and manifests written by one container are listed by a new container and by the host (`docker-audit runs`) |

---

## 15. Running GRFICSv3 on macOS

GRFICSv3 defines `b-ics-net` and `c-dmz-net` as **macvlan** networks on `eth0`, which Docker
Desktop for Mac does not support. GRFICS is not modified. Choose one option:

**Option B (recommended for this milestone): compose override.**
[`deploy/grfics/docker-compose.macos.yml`](deploy/grfics/docker-compose.macos.yml)
redefines the two networks as bridges with the **same subnets and gateways**, so all of
GRFICS's static IPs still work. The merge was validated with `docker compose config`.

```bash
git clone https://github.com/Fortiphyd/GRFICSv3 ~/GRFICSv3
cd ~/GRFICSv3
docker compose -f docker-compose.yml \
  -f /path/to/this/repo/deploy/grfics/docker-compose.macos.yml pull
docker compose -f docker-compose.yml \
  -f /path/to/this/repo/deploy/grfics/docker-compose.macos.yml up -d
cd /path/to/this/repo && uv run docker-audit assess --model local-qwen
```

Trade-off: bridge networks are reachable from the Docker host, so segmentation is weaker
than with macvlan. The report shows the driver actually deployed (`bridge`), so findings
always describe what is really running.

**Option A (highest fidelity): Linux VM.** Run GRFICSv3 unmodified inside UTM, Colima/Lima
or an OrbStack Linux machine. Run the socket proxy against that VM's Docker engine and set
`DOCKER_AUDIT_DOCKER_HOST` to it. Nothing else changes.

### Resetting the range between runs

Confirmatory runs must start from the same known lab state (framework §3, coding guide
§25). [`deploy/grfics/range.sh`](deploy/grfics/range.sh) restores GRFICS to a **named
baseline**:

```bash
# once, on a freshly deployed, healthy lab: archive volumes + record the fingerprint
deploy/grfics/range.sh save clean-v1

# before every run: recreate containers/networks, restore volumes, verify
deploy/grfics/range.sh reset clean-v1
uv run docker-audit assess --model local-qwen --range-baseline clean-v1
```

- `save` stops the project, archives every named volume (PLC program and state, HMI
  database, ...) with checksums, restarts it, and runs `docker-audit range record`.
- `reset` checks the archive checksums, runs `docker compose down --volumes`, recreates and
  restores each volume, starts the lab from **local** images (no pull, no build), waits for
  health checks, then runs `docker-audit range verify NAME --since <reset start> --project <project>`.
- **Verification** compares a fresh read-only inventory with the baseline's fingerprint:
  images by content ID, privileges, mounts, ports, networks, compose labels (including the
  config hash), volumes and container state. Container IDs, creation times and dynamic IPs
  are ignored, because a reset always changes them. `--since` also requires every container
  and volume to be newer than the reset, which catches a volume that was not restored.
  `--project` limits that freshness check to the reset compose project. Other resources on
  the engine, such as the proxy the check runs through, predate the reset by design and are
  still compared by the fingerprint.
- `assess --range-baseline NAME` repeats the comparison before scanning and **aborts** on
  any difference. The run manifest records the baseline (`experiment.range_baseline`) and the
  check (`acquisition.range_check`, including the last verified reset).

Baselines and archives live in `data/range-baselines/NAME/` (git-ignored) and are
write-once. Environment variables (`GRFICS_DIR`, `GRFICS_PROJECT`, ...) are documented at
the top of the script. Fingerprints cover the whole Docker engine, so run the lab on an
engine dedicated to it: unrelated containers show up as differences.

> GRFICSv3 itself was **not** deployed during development (it pulls several GB of images
> and runs an attacker container). The pipeline was validated live against another
> running ICS range, and GRFICS's configuration is covered by fixture-based tests.

---

## 16. Known limitations

- **Metadata only.** No runtime behavior, network traffic or in-container files are
  analyzed, and no active scanning is done (by design).
- **Exploitability is not tested.** Trivy matches package versions against its database.
  A CVE is reported as present, not as reachable.
- **Trivy OS coverage.** Some distributions are not supported (e.g. Kali, used by
  GRFICS's attacker container). Such images return zero findings and are reported as
  "not assessed" rather than clean.
- **No redaction (since harness h3).** Credential values in environment variables and
  labels reach the model, the SQLite databases and the reports unmodified, because
  finding credentials is part of this experimental lab. Treat `data/` and `outputs/`
  as sensitive.
- **Small local models make mistakes.** Observed in live runs with `qwen3:14b`:
  - attaching a correct rationale to the wrong finding ID, and flagging the audit's own
    proxy. (Prompt v3; since v4 the agent ranks nothing it did not find itself, and
    ignored infrastructure is named as out of scope in its first message.)
  - omitting an argument, getting the SDK's generic "An error occurred... try again"
    message, retrying blindly, then **inventing finding IDs**. In one case it copied the
    example ID from the schema description. Validation dropped every invented ID and the
    report fell back to the deterministic ranking. The root causes were fixed (prompt
    v3): optional tool arguments now have defaults, tool errors show the expected
    parameters, and the schema contains no example IDs.

  Different runs of the same model can behave differently. Compare models over several
  runs on the same snapshot rather than a single run.
- **Ollama context.** Through `/v1` Ollama uses `num_ctx` from the model (default 4096).
  A larger-context variant is required (see 3.6).
- **docker-mcp-server maturity.** It is a small community project, and on 2026-10-08 its
  GitHub default branch contained only a README. It is pinned to the reviewed PyPI
  version, and the proxy remains the real boundary.
- **trivy-mcp** has had no commit since December 2025 and always uses `--skip-update`. It
  is pinned; the fallback would be a small adapter around `trivy image --format json`.
- **Prompt injection.** Labels or container names could contain hostile text. The agent
  is told to treat tool output as data, and it has no write capability, so the worst case
  is a misleading report. Agent findings are not validated, so invented facts can also
  appear in it.
- **macOS Option B networking** differs from upstream GRFICS (see section 15).
- **Containerized agent** (section 3.10):
  - The agent's own container is ignored by the rules, but its image is in use while it
    runs, so with `scan.scope: used` Trivy scans `docker-audit-agent:latest` too (one
    extra V001 finding compared with a host run). This is the same treatment the proxy
    image already gets. Range baselines recorded from the host do not include the agent
    container either, so run `range verify` / `--range-baseline` from the host.
  - `deploy/grfics/range.sh` (the reset tool) needs write access to Docker and stays on
    the host; the e2e tests (`-m e2e`) use the host `docker` CLI and also run on the host.
  - The root filesystem is writable (uv needs a cache lock); Trivy's Java DB is not
    downloaded by `setup` (see 3.10 step 3).

---

## 17. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker_host ... does not look like the read-only socket proxy` | `docker compose -f deploy/socket-proxy/compose.yml up -d` |
| `Model 'X' does not support tool calling` | Pick a model with `Tools = yes` in `docker-audit models --provider ollama` |
| `Context window 4096 < 16384` warning | `docker-audit models --provider ollama --create-variant <model>` and use the variant |
| `--skip-db-update cannot be specified on the first run` | `uv run docker-audit setup` (downloads the Trivy DB) |
| First `mcp check` is slow | `uvx` downloads docker-mcp-server on first use (once) |
| `VIRTUAL_ENV ... does not match` warning | Harmless; another venv is active. Run `deactivate`. |
| Container: `network docker-audit-mgmt declared as external, but could not be found` | Start (or recreate) the proxy first: `docker compose -f deploy/socket-proxy/compose.yml up -d` |
| Container: `Cannot reach Docker proxy at http://docker-audit-socket-proxy:2375` | The proxy was started from an older compose file without the `docker-audit-mgmt` network; run the `up -d` above again |
| Container: model check cannot reach Ollama | `curl http://localhost:11434/api/tags` on the Mac; Ollama must be running. For a non-default address set `AGENT_OLLAMA_BASE_URL` |
| Container: `scan <image>: Tool error: MCPError: failed to scan project` on a Java image | Trivy Java DB missing: `docker compose -f deploy/agent/compose.yml run --rm --entrypoint trivy agent image --download-java-db-only` |
| Agent status `invalid_output` | The model's final answer was not valid JSON. Try `structured_output: native` or a stronger model. |

---

## 18. Recommended next milestone

**Milestone 2: model-comparison harness and pre-deployment analysis**

1. A `docker-audit compare --runs a,b,c` command that tabulates per-run results (findings,
   rejections, tool calls, tokens, latency) across models and prompt versions.
2. Static analysis of `docker-compose.yml` before deployment, so GRFICS can be assessed
   without running it (same rules, a different collector).
3. Mapping findings to the CIS Docker Benchmark and to MITRE ATT&CK for ICS techniques.
4. SBOM export (Trivy CycloneDX) and SBOM-based re-scanning without image access.
5. An optional GRFICS deployment in a Linux VM (Option A) for high-fidelity network
   findings.

---

## License and acknowledgements

- GRFICSv3 by Fortiphyd Logic (GPLv3), used only as an assessment target and not vendored.
- Trivy and trivy-mcp by Aqua Security; docker-mcp-server by L337-org;
  docker-socket-proxy by Tecnativa; OpenAI Agents SDK by OpenAI. These are used as
  dependencies under their own licenses (see each project).
