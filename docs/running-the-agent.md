# Running the agent in the GRFICS environment

Step-by-step runbook for one experiment, from setting up the GPU VM to reading
the results: start the model on the VM, reset the GRFICSv3 lab to the clean
baseline, run the agent, and read what it found and missed. For background on
each step see the README (sections 3, 4, 10, 15) and
`docs/grfics-integration-notes.md`.

Where things run:

```text
Mac (repository root)                          FAIR Lab GPU VM (ai-user@10.100.60.83)
└─ Docker Desktop (shares NO Mac folders)       └─ vLLM serving Qwen/Qwen3-32B, 131k context
   ├─ agent container: docker-audit + its MCP      (YaRN), on 4x NVIDIA RTX A6000 (48 GB each)
   │  tools, FULL Docker access
   └─ GRFICS lab
localhost:8000 ══════ SSH tunnel ═══════════════▶ localhost:8000
```

Only the model runs on the VM. The agent and its MCP tools run in a container on
the Mac's Docker, next to GRFICS. Each model turn sends the agent's conversation
(including the Docker data its tools returned) through the tunnel to the VM.

The agent has **full Docker access** (there is no read-only proxy since
2026-11-09), so it could change or delete anything in Docker. Two walls keep it
from reaching the Mac itself, and the lab can always be rebuilt: see
[Containment and recovery](#containment-and-recovery).

Paths on the Mac assume this layout:

```text
~/SeniorYear/Capstone/
├── Automated-ICS-Capstone/   this repository
└── GRFICSv3/                 GRFICSv3 checkout (images already pulled)
```

## What a run does

1. The deterministic checks (20 rules + Trivy) assess the lab, with no AI. The
   agent never sees their results.
2. The agent (`DockerSecurityAssessmentAgent`, prompt v9, harness h4) gets only the
   objective and its approved MCP tools. It decides what to inspect and scan,
   and reports its own findings.
3. Its findings are reported exactly as the agent gave them. Nothing checks them
   against the real Docker data, so review them by hand.
4. Two independent reports are written to `outputs/<RUN_ID>/`:
   `deterministic_report.md` and `agent_report.md` (each with a `.json` twin).
   Nothing scores the agent against the deterministic findings.

`deploy/agent/run.sh assess` does all four in one command (step 9 below). It does
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
the Mac's `.env` (see "One-time setup: Mac"). Do not commit it or paste it into chat.

### E. Download Qwen3-32B and create the 131k-context model folder

Qwen3-32B natively handles 32,768 tokens (40,960 at most). Covering every GRFICS
container needs more, so the agent runs it at 131,072 tokens with **YaRN**, the
context extension Qwen documents for Qwen3. In vLLM 0.32.0 the command-line
flags for this (`--rope-scaling`, `--hf-overrides`) do not work; the working
method is a model folder whose `config.json` turns YaRN on. The weights are
linked from the Hugging Face cache, so nothing is copied.

Download the weights once (about 65 GB, to `~/.cache/huggingface`):

```bash
source ~/vllm/bin/activate
hf download Qwen/Qwen3-32B          # or: huggingface-cli download Qwen/Qwen3-32B
```

Then create the folder (run once; safe to run again):

```bash
SNAP=$(ls -d ~/.cache/huggingface/hub/models--Qwen--Qwen3-32B/snapshots/*/ | head -1)
DST=~/models/Qwen3-32B-yarn; mkdir -p "$DST"
for f in "$SNAP"*; do ln -sf "$(readlink -f "$f")" "$DST/$(basename "$f")"; done
rm -f "$DST/config.json"
python3 - <<'EOF'
import glob, json, os
snap = sorted(glob.glob(os.path.expanduser("~/.cache/huggingface/hub/models--Qwen--Qwen3-32B/snapshots/*/")))[0]
cfg = json.load(open(snap + "config.json"))
yarn = {"rope_type": "yarn", "factor": 4.0, "original_max_position_embeddings": 32768}
cfg.update(rope_scaling=yarn, rope_parameters={**yarn, "rope_theta": cfg.get("rope_theta", 1000000)},
           max_position_embeddings=131072)
json.dump(cfg, open(os.path.expanduser("~/models/Qwen3-32B-yarn/config.json"), "w"), indent=2)
print({k: cfg[k] for k in ("max_position_embeddings", "rope_scaling")})
EOF
ls -l "$DST" | head          # weights are links (->) into the cache; config.json is a real file
```

Raising `max_position_embeddings` removes vLLM's own length check, so a server
that starts does not prove YaRN is active. Step 5 checks it.

## One-time setup: Mac

Skip anything already done on this machine.

| What | Command | Check |
|---|---|---|
| Python environment (for `range.sh` and the step 5 check) | `uv sync` | `ls .venv/bin/docker-audit` |
| Docker Desktop shares no Mac folders | See [Containment and recovery](#containment-and-recovery) | the mount test there says `mounts denied` |
| Agent image | `deploy/agent/build.sh` (again after any change to `src/` or `config/`: config is built into the image) | `docker images \| grep docker-audit-agent` |
| Trivy DB in the agent's volume | `deploy/agent/run.sh setup` | `deploy/agent/run.sh doctor` shows the Trivy DB as OK |
| Trivy Java DB (needed for Java images such as Caldera) | `docker compose -f deploy/agent/compose.yml run --rm --entrypoint trivy agent image --download-java-db-only` | no `failed to scan project` errors in step 9 |
| GRFICS images | in `GRFICSv3/`: `docker compose -f docker-compose.yml -f ../Automated-ICS-Capstone/deploy/grfics/docker-compose.macos.yml pull` | `docker images \| grep fortiphyd` shows 7 images |
| Clean baseline | `deploy/grfics/range.sh save clean-v2` (lab running and healthy, nothing changed yet) | `data/range-baselines/clean-v2/` exists |
| vLLM settings | `cp .env.example .env`, then set the three lines below | `grep VLLM_ .env` |

`clean-v2` already exists on this machine (saved 2026-11-09, after the read-only
proxy was removed; `clean-v1` still lists the proxy and no longer matches).
Baselines are write-once: to record a new one, use a new name (`clean-v3`).

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

vllm serve ~/models/Qwen3-32B-yarn \
  --served-model-name Qwen/Qwen3-32B \
  --host 127.0.0.1 --port 8000 \
  --tensor-parallel-size 4 \
  --max-model-len 131072 \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --reasoning-parser qwen3 \
  --api-key <your-secret>
```

- `~/models/Qwen3-32B-yarn` is the YaRN folder from one-time setup E. Serving
  `Qwen/Qwen3-32B` directly gives the old 32k setup, which is too small for the
  agent to cover every container.
- `--served-model-name Qwen/Qwen3-32B` keeps the name `.env` and the
  `local-vllm` profile expect. Both setups report this name, so the context
  length is not visible in the model name: step 5 checks it.
- `--host 127.0.0.1` keeps the server reachable only through the SSH tunnel,
  not from the SKYNET network.
- `--tensor-parallel-size 4` splits the model across the four GPUs.
- `--max-model-len 131072` is the agent's context window (131k tokens).
- `--enable-auto-tool-choice --tool-call-parser hermes` turns on tool calling;
  without them the agent cannot use its tools.
- `--reasoning-parser qwen3` separates Qwen3's thinking from its answer.

Loading takes a few minutes (longer while another large download writes to the
same disk). Wait for `Application startup complete`. Then detach with `Ctrl-b`
`d` (the server keeps running) and `exit` the SSH session. `nvidia-smi` on the
VM now shows roughly 40+ GB used on each GPU: vLLM reserves about 90% of each
GPU's memory up front.

### 3. Open the SSH tunnel (Mac)

In a separate Mac terminal, and leave it open for the whole experiment:

```bash
ssh -N -o ServerAliveInterval=30 -L 8000:localhost:8000 ai-user@10.100.60.83
```

It prints nothing while it works. If it closes, the agent loses the model
mid-run. `ServerAliveInterval=30` keeps an idle tunnel from being dropped.

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

Then check that the server is the 131k one:

```bash
set -a; . ./.env; set +a
curl -s -H "Authorization: Bearer $VLLM_API_KEY" http://localhost:8000/v1/models \
  | python3 -c 'import json,sys; [print(m["id"], m.get("root"), m.get("max_model_len")) for m in json.load(sys.stdin)["data"]]'
```

Expected: `Qwen/Qwen3-32B /home/ai-user/models/Qwen3-32B-yarn 131072`. If it shows
`Qwen/Qwen3-32B 32768`, the server was started the old way: restart it as in
step 2.

The first time after creating the YaRN folder (or after changing vLLM), also
check that YaRN really works past the native limit. This hides a code at the
start of a ~55k-token prompt; the model must return it exactly:

```bash
set -a; . ./.env; set +a
python3 - <<'EOF'
import json, os, random, urllib.request
random.seed(11)
words = "valve pump sensor relay setpoint pressure tank flow reactor alarm operator console network switch firewall".split()
prompt = ("Remember this: the secret code is AMBER-FALCON-3058.\n\n"
          + " ".join(random.choice(words) for _ in range(52000))
          + "\n\nQuestion: what is the secret code stated at the very beginning? Reply with the code only.")
req = urllib.request.Request("http://localhost:8000/v1/chat/completions",
    data=json.dumps({"model": "Qwen/Qwen3-32B", "max_tokens": 2048, "temperature": 0,
                     "messages": [{"role": "user", "content": prompt}]}).encode(),
    headers={"Authorization": "Bearer " + os.environ["VLLM_API_KEY"], "Content-Type": "application/json"})
r = json.load(urllib.request.urlopen(req, timeout=900))
print("prompt_tokens:", r["usage"]["prompt_tokens"], "| answer:", r["choices"][0]["message"]["content"].strip())
EOF
```

Expected: `prompt_tokens: 55547 | answer: AMBER-FALCON-3058` (verified on
2026-10-28). Garbage instead of the code means YaRN is not active: do not run
the agent on this server.

### 6. Rebuild the agent image (only after code or config changes)

```bash
deploy/agent/build.sh
```

The agent's container has `config/` and the code built in (it mounts nothing
from the Mac), so changes to `src/` or `config/` only take effect after a rebuild.

### 7. Reset GRFICS to the clean baseline

```bash
deploy/grfics/range.sh reset clean-v2
```

It removes the lab, restores its volumes (streamed through Docker from
`data/range-baselines/clean-v2/volumes/` on the Mac), starts it from local images
and verifies it. It must end with:

```text
Range matches baseline clean-v2 (... grficsv3's containers and volumes recreated by the reset)
```

If it reports differences instead, stop and see [Troubleshooting](#troubleshooting).

### 8. Preflight check

```bash
deploy/agent/run.sh doctor --probe
```

Configuration, Docker, both MCP servers and the Trivy DB must be OK. `doctor` checks the *default* model (`default_model: local-qwen` in
`config/experiment.yaml`), which runs on the Mac's Ollama; if Ollama is not
running that row fails, and it can be ignored for vLLM runs: step 5 already
checked `local-vllm`.

### 9. Run the assessment

```bash
caffeinate -i deploy/agent/run.sh assess --model local-vllm --range-baseline clean-v2
```

- `deploy/agent/run.sh` runs `docker-audit` in the agent container and, when it
  ends, copies `outputs/<RUN_ID>/` and the databases (to `data/container/`) back
  to the Mac with `docker cp`.

- `caffeinate -i` keeps the Mac from sleeping while the command runs. Sleep
  drops the SSH tunnel and the run fails with `APIConnectionError`. It does not
  prevent sleep when the lid is closed: keep the lid open.
- `--model local-vllm` uses Qwen3-32B on the VM through the tunnel.
- `--range-baseline clean-v2` makes the run abort if the lab differs from the
  baseline, and records the baseline in the run's manifest. Always pass it for
  runs you will report: without it the manifest has no range check.
- The deterministic part (inventory, rules, Trivy) takes about 1-3 minutes.
  The agent phase took about 3 minutes in the first vLLM run; its limits are
  150 turns, 200 tool calls and 7200 seconds (`config/agent.yaml`).
- The command ends with a summary like:

```text
Run run-YYYYMMDD-HHMMSS-xxxx: completed — deterministic risk CRITICAL
Deterministic findings: critical 7, high 1, medium 25, low 42, info 10
Agent (ok): N findings · agent risk ...
Deterministic report: outputs/run-.../deterministic_report.md
Agent report:         outputs/run-.../agent_report.md
```

The run ID is the start time in UTC plus a random 4-character tag, e.g.
`run-20261026-193926-59c2` = 2026-10-26 19:39:26 UTC.

To watch what the agent is doing while it runs:

```bash
docker ps --filter name=docker-audit-agent-run              # Mac: the running agent container
ssh ai-user@10.100.60.83 -t tmux attach -t vllm             # VM: vLLM log, one line per model request
```

Detach from the vLLM log with `Ctrl-b` `d`; do not press `Ctrl-c` there, that
stops the server.

### 10. Read the results

```bash
RUN=$(ls -t outputs | head -1)
open outputs/$RUN/agent_report.md        # what the agent reported, with evidence
open outputs/$RUN/deterministic_report.md  # what the rules and Trivy found, no AI
```

Or from the database, for any run (`docker-audit` here runs in the container and
reads the container's own copy of the database):

```bash
deploy/agent/run.sh runs
deploy/agent/run.sh report --run-id <RUN_ID>                        # agent report
deploy/agent/run.sh report --run-id <RUN_ID> --kind deterministic
```

`agent_report.md` lists the agent's findings exactly as it reported them; they are
not checked against the collected data, so an invented container or a CVE from the
wrong image would appear as a finding. Runs before 2026-11-09 also have a
`comparison.md` (scores against the deterministic findings) and a "Rejected findings"
section (claims that failed validation); both have since been removed.

### 11. See every tool call the agent made

```bash
sqlite3 -header -column data/container/assessments.db "
  select timestamp, server, tool, status, duration_ms, arguments_json
  from tool_calls
  where run_id = (select run_id from runs order by rowid desc limit 1) and phase = 'agent'
  order by id"
```

`status` is `ok`, `error`, `blocked` (refused by the tool policy) or
`budget_exhausted`. The full conversation is in `data/container/agent_sessions.db`.
(`data/assessments.db` holds the runs made directly on the Mac before 2026-11-09.)

### 12. Compare another model (optional)

Reset before every run, so each model assesses the same lab:

```bash
deploy/grfics/range.sh reset clean-v2
caffeinate -i deploy/agent/run.sh assess --model local-qwen --range-baseline clean-v2
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
```

Close the tunnel with `Ctrl-c` in its terminal (step 3).

On the VM, stop vLLM so the GPUs are free for others:

```bash
ssh ai-user@10.100.60.83 -t tmux attach -t vllm    # then Ctrl-c, then `exit`
```

Nothing is deleted. The next experiment starts again at step 1; the reset in
step 7 brings the lab back to `clean-v2`.

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
  you will compare. Changing them changes the model's behaviour. The 32k and the
  131k (YaRN) server report the same model name, so note which one each run used.

## Containment and recovery

The agent's tools have full Docker access, on purpose (more tools may be added
later). Two walls keep everything it does inside Docker:

| Wall | What it does | How it is set up |
|---|---|---|
| 1. Docker shares no Mac folders | No container, however privileged, can mount your home folder, `/Users`, `/tmp`, `/Volumes`... | Docker Desktop → Settings → Resources → File sharing lists only the empty folder `~/.docker-share-empty` (set in `~/Library/Group Containers/group.com.docker/settings-store.json`, key `FilesharingDirectories`). An empty list does not work: Docker Desktop then falls back to its defaults on the next start. |
| 2. The agent runs in a container | Its MCP tools run inside that container, so they cannot read `~/.ssh`, `.env` or any other Mac file. | `deploy/agent/compose.yml`: no Mac folder is mounted; config is built into the image; results leave through `docker cp` (`deploy/agent/run.sh`). |

Check wall 1 after any Docker Desktop update or settings change. Every line must
say `mounts denied`, except the empty share:

```bash
for dir in "$HOME" /Users /tmp /Volumes "$HOME/.docker-share-empty"; do
  printf '%-40s -> ' "$dir"; docker run --rm -v "$dir":/x:ro alpine:3.20 true 2>&1 | head -1
done
```

What the walls do **not** cover: the network. Containers can still connect to
services on the Mac (`host.docker.internal`), the local network, and the VPN or
SKYNET when connected.

Recovery, worst case first:

| What broke | Recovery |
|---|---|
| The lab (containers, volumes, plant state) | `deploy/grfics/range.sh reset clean-v2`. The baselines and their volume archives are on the Mac, out of the agent's reach. |
| Docker itself (unknown images, networks, containers, anything left behind) | Docker Desktop → Troubleshoot → *Reset to factory defaults*; then set file sharing again (wall 1), pull the GRFICS images, `deploy/agent/build.sh`, `deploy/agent/run.sh setup`, and `range.sh reset clean-v2`. |
| The agent's results in Docker | Each run's reports and databases are copied to the Mac when it ends; reports are also pushed to GitHub. |
| Undo wall 1 | Restore the backup next to the settings file (`settings-store.json.backup-before-no-filesharing-*`) while Docker Desktop is quit. |

Not recoverable: anything the agent sends out over the network.

Running `uv run docker-audit assess ...` directly on the Mac still works, but then
the tools run on the Mac with your user's access: wall 2 is gone. Use
`deploy/agent/run.sh` for real runs.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ssh: connect to host 10.100.60.83 ... timed out` | Join SKYNET WiFi or connect the VPN |
| `bind [127.0.0.1]:8000: Address already in use` when opening the tunnel | A tunnel is already open, or another app uses port 8000: `lsof -i :8000` |
| `vLLM endpoint not reachable at http://localhost:8000/v1` | The tunnel (step 3) is closed, or vLLM is not running on the VM (step 2) |
| `vLLM rejected the API key` | `VLLM_API_KEY` in `.env` differs from `--api-key` on `vllm serve` |
| `Model 'Qwen/Qwen3-32B' is not served` | `VLLM_MODEL` in `.env` differs from the name given to `vllm serve` |
| Tool-call probe fails | `vllm serve` was started without `--enable-auto-tool-choice --tool-call-parser hermes` |
| `vllm: error: unrecognized arguments: --rope-scaling ...` | That flag was removed in recent vLLM. Use the YaRN model folder (one-time setup E) and serve it as in step 2 |
| `vllm serve` fails: `max_model_len (131072) is greater than the derived max_model_len (40960...)` | You served `Qwen/Qwen3-32B` directly. Serve `~/models/Qwen3-32B-yarn` (step 2). Do not use `VLLM_ALLOW_LONG_MAX_MODEL_LEN=1`: it removes the check without turning YaRN on |
| Step 5 shows `max_model_len 32768`, or a run fails with `maximum context length is 32768 tokens` | The server was started the old way. Restart it as in step 2 |
| Agent fails with `APIConnectionError: Connection error.` and 0 model requests | The Mac slept or the tunnel dropped. Reopen the tunnel (step 3); run with `caffeinate -i` and the lid open (step 9) |
| `vllm serve` fails with `CUDA out of memory` | Add `--gpu-memory-utilization 0.85`, or check `nvidia-smi` for another process using the GPUs |
| `vllm serve` fails because fewer than 4 GPUs are visible | Check `nvidia-smi`; ask the lab admin, or lower `--tensor-parallel-size` to the number of GPUs |
| `python3 -m venv` fails on the VM | The venv package is missing; ask the lab admin to install `python3-venv` |
| `No docker-compose.yml in GRFICS_DIR=/Users/.../GRFICSv3` | `export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3` (step 4) |
| Reset ends with `Range does NOT match baseline clean-v2` | Read the listed differences. A changed image ID: the images changed; save a new baseline (`clean-v3`). An unexpected container: stop the other project (`docker compose -p <project> down`). |
| `Range does NOT match baseline clean-v1` listing `docker-audit-socket-proxy` | Expected: `clean-v1` was recorded with the read-only proxy, which was removed. Use `clean-v2`. |
| `Cannot reach Docker at ...` | Start Docker Desktop and wait until `docker info` answers |
| `mounts denied` | Expected for Mac folders (wall 1). Something tried to mount a Mac folder; use Docker volumes or `docker cp` instead |
| Docker Desktop restarts with all mounts allowed again | `FilesharingDirectories` became empty or `null`: set it back to `~/.docker-share-empty` (wall 1) |
| `VIRTUAL_ENV ... does not match` warning, or `Failed to spawn` | `deactivate` (step 4), then retry |
| Model check fails / cannot reach Ollama (Ollama profiles only) | Start Ollama; `curl http://localhost:11434/api/tags` must answer |
| Scan fails with `failed to scan project` | `trivy image --download-java-db-only`, then rerun step 9 |
| Agent status `timeout` or `max_turns` | The model ran out of time or turns: every finding shows as missed. Raise the limits in `config/agent.yaml` (recorded in the manifest), or try a faster model. |
| Agent status `invalid_output` | The model's final answer was not valid JSON. Try `structured_output: native` in its profile or a stronger model. |
