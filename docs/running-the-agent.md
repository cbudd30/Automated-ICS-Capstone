# Running the agent in the GRFICS environment

Step-by-step runbook for one experiment, from setting up the GPU VM to reading
the results: start the model on the VM, reset the GRFICSv3 lab to the clean
baseline, run the agent, and read what it found and missed. For background on
each step see the README (sections 3, 4, 10, 15) and
`docs/grfics-integration-notes.md`.

Where things run:

```text
Mac (repository root)                          FAIR Lab GPU VM (ai-user@10.100.60.83)
├─ docker-audit (agent + deterministic checks)  └─ vLLM serving Qwen/Qwen3-32B
├─ Docker Desktop: GRFICS lab, socket proxy        on 4x NVIDIA RTX A6000 (48 GB each)
└─ localhost:8000 ══════ SSH tunnel ══════════▶   localhost:8000
```

Only the model runs on the VM. The agent, Docker, GRFICS and the MCP tools stay
on the Mac. Each model turn sends the agent's conversation (including the Docker
data its tools returned) through the tunnel to the VM.

Paths on the Mac assume this layout:

```text
~/SeniorYear/Capstone/
├── Automated-ICS-Capstone/   this repository
└── GRFICSv3/                 GRFICSv3 checkout (images already pulled)
```

## What a run does

1. The deterministic checks (20 rules + Trivy) assess the lab. This is the
   answer key; the agent never sees it.
2. The agent (`DockerSecurityAssessmentAgent`, prompt v4) gets only the
   objective and the read-only MCP tools. It decides what to inspect and scan,
   and reports its own findings.
3. Its findings are validated against the real Docker data and compared with
   the answer key.
4. Three reports are written to `outputs/<RUN_ID>/`: `agent_report.md`,
   `deterministic_report.md` and `comparison.md` (each with a `.json` twin).

`docker-audit assess` does all four in one command (step 9 below). It does
**not** start or reset GRFICS: that is step 7, `range.sh reset`.

## One-time setup: GPU VM

You must be on SKYNET WiFi, or on the VPN, to reach the VM.

### A. Log in and change the password

```bash
ssh ai-user@10.100.60.83
passwd                         # replace the default password you were given
```

### B. Verify the GPUs

```bash
cat ~/README.txt               # run the verification script it describes
nvidia-smi --query-gpu=name,memory.total --format=csv
```

Expected: 4 lines like `NVIDIA RTX A6000, 49140 MiB`. If fewer GPUs are
listed, ask the lab admin before going on: `--tensor-parallel-size 4` in step 2
needs all four.

### C. Install vLLM

```bash
python3 -m venv ~/vllm
source ~/vllm/bin/activate
pip install --upgrade pip
pip install vllm
```

### D. Choose an API key

Pick a secret string. It goes on the `vllm serve` command line (step 2) and in
the Mac's `.env` (one-time setup E). Do not commit it or paste it into chat.

The first `vllm serve` downloads Qwen3-32B (about 65 GB) to
`~/.cache/huggingface`; later starts take a minute or two.

## One-time setup: Mac

Skip anything already done on this machine.

| What | Command | Check |
|---|---|---|
| Python environment | `uv sync` | `ls .venv/bin/docker-audit` |
| Trivy plugin + vulnerability DB | `uv run docker-audit setup` | `doctor` shows the Trivy DB as OK |
| Trivy Java DB (needed for Java images such as Caldera) | `trivy image --download-java-db-only` | no `failed to scan project` errors in step 9 |
| GRFICS images | in `GRFICSv3/`: `docker compose -f docker-compose.yml -f ../Automated-ICS-Capstone/deploy/grfics/docker-compose.macos.yml pull` | `docker images \| grep fortiphyd` shows 7 images |
| Clean baseline | `deploy/grfics/range.sh save clean-v1` (lab running and healthy, nothing changed yet) | `data/range-baselines/clean-v1/` exists |
| vLLM settings | `cp .env.example .env`, then set the three lines below | `grep VLLM_ .env` |

`clean-v1` already exists on this machine (saved 2026-10-20). Baselines are
write-once: to record a new one, use a new name (`clean-v2`).

The vLLM lines in `.env` (git-ignored; edit `.env`, never `.env.example`):

```text
VLLM_BASE_URL=http://localhost:8000/v1
VLLM_MODEL=Qwen/Qwen3-32B
VLLM_API_KEY=<the secret from VM step D>
```

`VLLM_MODEL` must match the model name in `vllm serve` exactly. These values
feed the `local-vllm` profile in `config/models.yaml`.

## Every experiment

### 1. Start Docker Desktop

Open Docker Desktop on the Mac and wait until it is running.

### 2. Start vLLM on the VM

```bash
ssh ai-user@10.100.60.83
tmux new -s vllm                # or `tmux attach -t vllm` if it is still running
source ~/vllm/bin/activate

vllm serve Qwen/Qwen3-32B \
  --tensor-parallel-size 4 \
  --max-model-len 32768 \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --reasoning-parser qwen3 \
  --api-key <your-secret>
```

- `--tensor-parallel-size 4` splits the model across the four GPUs.
- `--max-model-len 32768` is the agent's context window (32k tokens).
- `--enable-auto-tool-choice --tool-call-parser hermes` turns on tool calling;
  without them the agent cannot use its tools.
- `--reasoning-parser qwen3` separates Qwen3's thinking from its answer.

Wait for `Application startup complete`. Then detach with `Ctrl-b` `d` (the
server keeps running) and `exit` the SSH session. `nvidia-smi` on the VM now
shows roughly 40+ GB used on each GPU: vLLM reserves about 90% of each GPU's
memory up front.

### 3. Open the SSH tunnel (Mac)

In a separate Mac terminal, and leave it open for the whole experiment:

```bash
ssh -N -L 8000:localhost:8000 ai-user@10.100.60.83
```

It prints nothing while it works. If it closes, the agent loses the model
mid-run.

### 4. Prepare the shell (Mac)

```bash
cd ~/SeniorYear/Capstone/Automated-ICS-Capstone
deactivate 2>/dev/null                            # leave any other project's venv
export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3  # range.sh defaults to ~/GRFICSv3
```

Do this in every new terminal.

### 5. Check the model through the tunnel

```bash
uv run docker-audit models --provider vllm --probe
```

The `local-vllm` row (model `Qwen/Qwen3-32B`) must show **Usable** `OK`,
**Tools** `yes`, and `tool-call probe succeeded` in Notes.

**Structured** `no` with `structured-output probe failed: Expecting value: line
1 column 1 (char 0)` is expected and harmless: the probe allows only 256 output tokens and Qwen3 spends
them all thinking. Real runs have no such cap, and `local-vllm` uses
`structured_output: prompted`, which does not depend on this probe.

### 6. Start the read-only Docker API proxy

```bash
docker compose -f deploy/socket-proxy/compose.yml up -d
```

It must be running before the reset: it was running when `clean-v1` was
recorded, and the reset's verification reads Docker through it.

### 7. Reset GRFICS to the clean baseline

```bash
deploy/grfics/range.sh reset clean-v1
```

It removes the lab, restores its volumes, starts it from local images and
verifies it. It must end with:

```text
Range matches baseline clean-v1 (... grficsv3's containers and volumes recreated by the reset)
```

If it reports differences instead, stop and see [Troubleshooting](#troubleshooting).

### 8. Preflight check

```bash
uv run docker-audit doctor --probe
```

Configuration, the proxy (`filtered=True`), both MCP servers and the Trivy DB
must be OK. `doctor` checks the *default* model (`default_model: local-qwen` in
`config/experiment.yaml`), which runs on the Mac's Ollama; if Ollama is not
running that row fails, and it can be ignored for vLLM runs: step 5 already
checked `local-vllm`.

### 9. Run the assessment

```bash
uv run docker-audit assess --model local-vllm --range-baseline clean-v1
```

- `--model local-vllm` uses Qwen3-32B on the VM through the tunnel.
- `--range-baseline clean-v1` makes the run abort if the lab differs from the
  baseline, and records the baseline in the run's manifest. Always pass it for
  runs you will report: without it the manifest has no range check.
- The deterministic part (inventory, rules, Trivy) takes about 1-3 minutes.
  The agent phase took about 3 minutes in the first vLLM run; its limits are
  60 turns, 100 tool calls and 3600 seconds (`config/agent.yaml`).
- The command ends with a summary like:

```text
Run run-YYYYMMDD-HHMMSS-xxxx: completed — deterministic risk CRITICAL
Deterministic findings: critical 7, high 1, medium 25, low 42, info 10
Agent (ok): N findings, M rejected · agent risk ...
Comparison: found X/85 deterministic findings (recall ..%, weighted ..%) · missed ...
Deterministic report: outputs/run-.../deterministic_report.md
Agent report:         outputs/run-.../agent_report.md
Comparison:           outputs/run-.../comparison.md
```

The run ID is the start time in UTC plus a random 4-character tag, e.g.
`run-20261026-193926-59c2` = 2026-10-26 19:39:26 UTC.

To watch what the agent is doing while it runs:

```bash
docker logs -f docker-audit-socket-proxy                    # Mac: each Docker query it makes
ssh ai-user@10.100.60.83 -t tmux attach -t vllm             # VM: vLLM log, one line per model request
```

Detach from the vLLM log with `Ctrl-b` `d`; do not press `Ctrl-c` there, that
stops the server.

### 10. Read the results

```bash
RUN=$(ls -t outputs | head -1)
open outputs/$RUN/comparison.md          # start here: found, missed, scores
open outputs/$RUN/agent_report.md        # what the agent reported, with evidence
open outputs/$RUN/deterministic_report.md
```

Or from the database, for any run:

```bash
uv run docker-audit runs
uv run docker-audit report --run-id <RUN_ID>                       # comparison
uv run docker-audit report --run-id <RUN_ID> --kind agent
uv run docker-audit report --run-id <RUN_ID> --kind deterministic
```

What to look at in `comparison.md`:

| Section | Meaning |
|---|---|
| Scores | recall = deterministic findings the agent found / all of them; weighted recall counts critical 4, high 3, medium 2, low 1, info 0 |
| Missed by the agent | confirmed issues the agent did not report |
| Found by the agent | matched issues, with the agent's severity vs the rule's |
| Outside the rules | validated agent findings no rule covers: review by hand |
| Rejected | agent claims that failed validation (invented resource, field or CVE) |

### 11. See every tool call the agent made

```bash
sqlite3 -header -column data/assessments.db "
  select timestamp, server, tool, status, duration_ms, arguments_json
  from tool_calls
  where run_id = (select run_id from runs order by rowid desc limit 1) and phase = 'agent'
  order by id"
```

`status` is `ok`, `error`, `blocked` (refused by the tool policy) or
`budget_exhausted`. The full conversation is in `data/agent_sessions.db`.

### 12. Compare another model (optional)

Reset before every run, so each model starts from the same lab and is scored
against the same answer key:

```bash
deploy/grfics/range.sh reset clean-v1
uv run docker-audit assess --model local-qwen --range-baseline clean-v1
```

- Ollama profiles (`local-qwen`, `local-gpt-oss`) run on the Mac: start the
  Ollama app first, and create the 32k-context variant once with
  `uv run docker-audit models --provider ollama --create-variant qwen3:14b`.
- Another model on the VM: stop vLLM (step 13), start `vllm serve` with the
  new model name, and set `VLLM_MODEL` in `.env` to the same name.
- `openai-primary` needs `OPENAI_API_KEY` in `.env`.

### 13. Shut down

On the Mac:

```bash
docker compose -f $GRFICS_DIR/docker-compose.yml \
  -f deploy/grfics/docker-compose.macos.yml -p grficsv3 stop
docker compose -f deploy/socket-proxy/compose.yml stop
```

Close the tunnel with `Ctrl-c` in its terminal (step 3).

On the VM, stop vLLM so the GPUs are free for others:

```bash
ssh ai-user@10.100.60.83 -t tmux attach -t vllm    # then Ctrl-c, then `exit`
```

Nothing is deleted. The next experiment starts again at step 1; the reset in
step 7 brings the lab back to `clean-v1`.

## Rules during the experiment period

Each of these changes the lab or its images, and makes later runs fail the
baseline check or stop being comparable:

- Do not run `docker compose pull`, or `up` without `--pull never`, in `GRFICSv3/`.
- Do not run `docker image prune`, `docker system prune`, or Docker Desktop's
  "Clean / Purge data".
- Do not rebuild GRFICS images.
- Do not delete any Docker volume, including the kept `ics_range_*` and
  `bloodhound_*` volumes: the baseline fingerprint covers all of them.
- Do not start other labs (`ics_range`, BloodHound) on this Docker engine.
- Keep the same model, `vllm serve` flags and `--max-model-len` for every run
  you will compare. Changing them changes the model's behaviour.

## Running the agent in a container instead

Same steps 1-7, then:

```bash
deploy/agent/build.sh                                  # first time, and after code changes
A="docker compose -f deploy/agent/compose.yml run --rm"
$A agent setup                                         # first time: Trivy DB in its volume
$A --entrypoint trivy agent image --download-java-db-only
$A agent doctor --probe
$A agent assess --model local-vllm
```

The container reads the same `.env`, and reaches the tunnel at
`host.docker.internal:8000` (`AGENT_VLLM_BASE_URL` in
`deploy/agent/compose.yml`), so step 3 must be running.

Leave out `--range-baseline` in the container: the agent's own container is
on the engine during the run, so the baseline check would report it as a
difference. Reports still land in `outputs/` and `data/` on the Mac.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ssh: connect to host 10.100.60.83 ... timed out` | Join SKYNET WiFi or connect the VPN |
| `bind [127.0.0.1]:8000: Address already in use` when opening the tunnel | A tunnel is already open, or another app uses port 8000: `lsof -i :8000` |
| `vLLM endpoint not reachable at http://localhost:8000/v1` | The tunnel (step 3) is closed, or vLLM is not running on the VM (step 2) |
| `vLLM rejected the API key` | `VLLM_API_KEY` in `.env` differs from `--api-key` on `vllm serve` |
| `Model 'Qwen/Qwen3-32B' is not served` | `VLLM_MODEL` in `.env` differs from the name given to `vllm serve` |
| Tool-call probe fails | `vllm serve` was started without `--enable-auto-tool-choice --tool-call-parser hermes` |
| `vllm serve` fails with `CUDA out of memory` | Add `--gpu-memory-utilization 0.85`, or check `nvidia-smi` for another process using the GPUs |
| `vllm serve` fails because fewer than 4 GPUs are visible | Check `nvidia-smi`; ask the lab admin, or lower `--tensor-parallel-size` to the number of GPUs |
| `python3 -m venv` fails on the VM | The venv package is missing; ask the lab admin to install `python3-venv` |
| `No docker-compose.yml in GRFICS_DIR=/Users/.../GRFICSv3` | `export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3` (step 4) |
| Reset ends with `Range does NOT match baseline clean-v1` | Read the listed differences. A changed image ID: the images changed; save a new baseline (`clean-v2`). An unexpected container: stop the other project (`docker compose -p <project> down`). |
| `Cannot reach Docker proxy` / doctor fails on the proxy | Step 6: `docker compose -f deploy/socket-proxy/compose.yml up -d` |
| `--snapshot replays stored evidence for --no-agent runs only` | The agent needs live Docker. Reset the lab and run live (steps 7 and 9). |
| `VIRTUAL_ENV ... does not match` warning, or `Failed to spawn` | `deactivate` (step 4), then retry |
| Model check fails / cannot reach Ollama (Ollama profiles only) | Start Ollama; `curl http://localhost:11434/api/tags` must answer |
| Scan fails with `failed to scan project` | `trivy image --download-java-db-only`, then rerun step 9 |
| Agent status `timeout` or `max_turns` | The model ran out of time or turns: every finding shows as missed. Raise the limits in `config/agent.yaml` (recorded in the manifest), or try a faster model. |
| Agent status `invalid_output` | The model's final answer was not valid JSON. Try `structured_output: native` in its profile or a stronger model. |
