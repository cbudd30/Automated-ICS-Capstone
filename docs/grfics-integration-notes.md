# GRFICSv3 integration notes

Working notes from setting up the containerized agent and the GRFICSv3 range
(2026-10-20). The README is the reference; this file records what was done on
this machine, what was decided, and why.

## 1. Where things stand

| Item | State |
|---|---|
| Agent containerization | Committed and pushed as `bddd5a5` ("Containerize the agent (Dockerfile + Compose)"). See README §3.10. |
| Host test suite | 123 passed, 2 deselected (`.venv/bin/python -m pytest -q`) |
| GRFICSv3 checkout | `~/SeniorYear/Capstone/GRFICSv3` (sibling of this repo), upstream commit `37bdf10` |
| GRFICS images | Pulled once from Docker Hub (`fortiphyd/*:latest`, native arm64) |
| GRFICS lab | Running and healthy with the macOS override (7 services, no `siem` profile) |
| Range baseline | `clean-v1` saved (details in section 4) |
| Other labs on the engine | `ics_range` and `bloodhound` taken down with `docker compose down` (volumes and images kept) |

## 2. How the agent relates to GRFICS

The agent does not need to join GRFICS's networks to assess it. It works only
from Docker metadata (containers, images, networks, mounts, capabilities),
read through the read-only socket proxy, plus Trivy scans of the images. Any
lab running on the same Docker engine is visible to it.

Joining GRFICS networks (`deploy/agent/compose.grfics.example.yml`) is only
for a later phase that needs network-level access. It is not used now.

```text
Mac
 ├─ Ollama  localhost:11434 ............ LLM (never in a container)
 └─ Docker Desktop engine
     ├─ GRFICS lab (simulation, plc, EWS, HMI, kali, router, caldera)
     ├─ docker-audit-socket-proxy ...... GET/HEAD only, 403 for writes
     └─ agent (host .venv, or the docker-audit-agent container)
          ├─ docker-mcp-server  (stdio) ──► proxy ──► Docker API
          └─ trivy mcp          (stdio) ──► proxy ──► image contents
```

## 3. Clearing the engine before the baseline

A baseline fingerprints the whole Docker engine, including stopped
containers. The `ics_range` lab (from `ICS-Exploitation-Capstone-2026`) also
had a container named `plc`, which would have blocked GRFICS from starting.

Done:

```bash
docker compose -p ics_range down --remove-orphans
docker compose -p bloodhound down --remove-orphans
```

- Removed: those projects' containers and networks.
- Kept: their 11 named volumes and their images.
- To bring them back: `docker compose up -d` in `ICS-Exploitation-Capstone-2026`,
  or in `~/Library/Application Support/bloodhound` for BloodHound.

A full delete (`down -v --rmi all`) was considered and not used. It would also
delete volume data (OpenPLC program, FUXA screens, Shuffle workflows, and
BloodHound's 541 MB graph DB, which cannot be recreated) and images
(`ics_range-*` can be rebuilt from that repo; the BloodHound images can be
pulled again).

## 4. The `clean-v1` baseline

Created with:

```bash
cd ~/SeniorYear/Capstone/GRFICSv3
OVR=../Automated-ICS-Capstone/deploy/grfics/docker-compose.macos.yml
docker compose -f docker-compose.yml -f $OVR pull
docker compose -f docker-compose.yml -f $OVR up -d --pull never

cd ../Automated-ICS-Capstone
export GRFICS_DIR=~/SeniorYear/Capstone/GRFICSv3
DOCKER_AUDIT="$PWD/.venv/bin/docker-audit" deploy/grfics/range.sh save clean-v1
```

`DOCKER_AUDIT` points straight at the venv's binary because a `VIRTUAL_ENV`
from another project was active in the shell, which breaks `uv run`.

Result:

| Field | Value |
|---|---|
| Fingerprint | `ace1974091c5` |
| Snapshot | `snap-128c413894057962` |
| Containers | 8 (7 GRFICS services + `docker-audit-socket-proxy`) |
| Volumes in fingerprint | 22 (every volume on the engine, not only GRFICS's) |
| Archived volumes | `plc_volume`, `router_config`, `scadalts_db` |
| Location | `data/range-baselines/clean-v1/` (git-ignored, write-once) |

Image IDs at baseline time:

| Image | ID | Size |
|---|---|---|
| `fortiphyd/grfics-simulation` | `ed3517811da2` | 1.54 GB |
| `fortiphyd/grfics-plc` | `7397c8440578` | 1.47 GB |
| `fortiphyd/grfics-workstation` | `0e9f4e94459b` | 5.46 GB |
| `fortiphyd/grfics-scadalts` | `83f3f576e769` | 1.96 GB |
| `fortiphyd/grfics-attacker` | `6cd239bfad70` | 6.67 GB |
| `fortiphyd/grfics-router` | `9b9a167e5c78` | 341 MB |
| `fortiphyd/grfics-caldera` | `a7a3edc9ef16` | 7.36 GB |

## 5. What `range.sh` does

`deploy/grfics/range.sh` is a host-side operator script. It is the only part
of the project that changes the lab, so it is deliberately not part of the
agent. It uses normal Docker access and never goes through the proxy.

**`save NAME`**

1. Refuses if `NAME` exists (write-once) or the lab is not running.
2. Stops the lab so volume data is consistent.
3. Archives each GRFICS volume to `<vol>.tar.gz` with a throwaway
   `alpine:3.20` container (no network, volume mounted read-only). It also
   saves the volume's labels.
4. Writes `SHA256SUMS`.
5. Restarts the lab and waits until every service is running and healthy.
6. Runs `docker-audit range record NAME` (read-only, through the proxy).

**`reset NAME`**

1. Checks the archives against `SHA256SUMS`.
2. Records the start time from the Docker engine's clock.
3. Runs `docker compose down --volumes --remove-orphans`. This is destructive
   to the lab's current state, by design.
4. Recreates each volume with its labels and unpacks its archive.
5. Starts the lab from local images only (`--no-build --pull never`) and
   waits for health.
6. Runs `docker-audit range verify NAME --since <start> --project <project>`.
   It compares against the fingerprint, ignoring container IDs, creation times
   and dynamic IPs, and requires every GRFICS container and volume to be newer
   than the reset. Other resources on the engine (the proxy, other projects'
   volumes) predate the reset by design; until 2026-10-26 the check covered
   them too, so every reset failed with "created ..., before the reset".

**`list`** shows baselines and their last verified reset.

## 6. Why volumes are saved but images are not

| Where state lives | Changes during a run? | How reset handles it |
|---|---|---|
| Image | No (read-only) | Not saved; containers are recreated from the same local image |
| Container's writable layer | Yes | Discarded by `down` / `up` |
| Named volumes | Yes, and they survive `down` | Archived and restored |

Images are verified by content ID instead. If an image changes, `range verify`
fails. A reset cannot repair a changed or missing image, though.

**Decision: option 1, discipline.** Do not change images during the
experiment period. The alternatives were archiving images with `docker save`
(several GB per baseline) or pinning images by digest in the macOS override.

## 7. Rules during the experiment period

Do:

- Before every run: `deploy/grfics/range.sh reset clean-v1`.
- Assess with `--range-baseline clean-v1`. The run aborts on any drift.
- Run baseline-gated assessments from the host. The containerized agent adds
  its own container to the engine, which the baseline does not include.

Do not:

- `docker compose pull`, or `up` without `--pull never`, in the GRFICS folder.
  The images are `:latest`, so a new pull can bring different images.
- `docker image prune`, `docker system prune`, or Docker Desktop "Clean / Purge data".
- Rebuild GRFICS images.
- Delete any volume on the engine, including the kept `ics_range_*` and
  `bloodhound_*` volumes. All 22 are in the fingerprint.
- Start other labs (`ics_range`, BloodHound) on this engine.

If verify reports a change: pull again, save a new baseline (`clean-v2`), and
record which runs used which baseline. Each run's `manifest.json` already
records it.

## 8. Running assessments and finding the output

```bash
deploy/grfics/range.sh reset clean-v1                    # needs GRFICS_DIR set
uv run docker-audit inventory                            # sees the GRFICS containers?
uv run docker-audit assess --no-agent --range-baseline clean-v1        # rules + Trivy only
uv run docker-audit assess --model local-qwen --range-baseline clean-v1
uv run docker-audit runs
```

The first run scans every GRFICS image with Trivy, which takes several
minutes. Later runs reuse the cache.

Output (on the Mac, in this repo):

| Path | Contents |
|---|---|
| `outputs/run-<date>-<time>-<id>/agent_report.md` | What the agent found by itself (since prompt v4) |
| `outputs/run-.../deterministic_report.md` | What the rules and Trivy found (no AI) |
| `outputs/run-.../comparison.md` | What the agent found and **missed**, with scores |
| `outputs/run-.../*.json` | The same three reports, machine-readable |
| `outputs/run-.../manifest.json` | Read-only run configuration, evidence and baseline |
| `data/assessments.db` | SQLite: runs, snapshots, scans, findings, tool calls |
| `data/agent_sessions.db` | LLM conversation history |

How to evaluate:

Since prompt v4 (2026-10-26) the agent gets only the MCP tools and the
objective. It never sees the deterministic findings; they are the answer key.

- **Start with `comparison.md`.** Recall (how many deterministic findings the
  agent found), severity-weighted recall, and the list of what it **missed**.
- **Finding `status`.** `confirmed` = rule or scanner fact. `potential` = an
  agent finding that passed evidence validation; review it by hand. `rejected`
  = an agent claim that failed validation. The rejection rate is a useful metric.
- **"Outside the rules"** in the comparison: validated agent findings that match
  no rule. Either something the rules do not check, or a weak claim. Review them.
- **Compare models** by resetting the range before each live run
  (`range.sh reset clean-v1`, then `assess --model <profile> --range-baseline
  clean-v1`). Agent runs cannot be replayed on a stored snapshot any more.
- **Metrics section** of `agent_report.md` has timing, tokens, tool calls and
  blocked calls.

## 9. How the agent chooses and reaches the model

1. **Profile.** `--model X` selects profile `X` from `config/models.yaml`.
   Without the flag, `default_model` in `config/experiment.yaml` is used
   (`local-qwen`). See `config.py:268-269`.
2. **Provider.** The profile's `provider:` field picks the client in
   `llm/factory.py:60-90`:
   - `openai`: `AsyncOpenAI` with `OPENAI_API_KEY`, using the Responses API.
   - `ollama` / `vllm`: `AsyncOpenAI(base_url=..., api_key="not-needed")`,
     using Chat Completions. Both serve the same OpenAI-compatible `/v1` API.
3. **The OpenAI Agents SDK always runs.** It drives the tool loop, MCP and
   sessions. The provider only decides which model server it talks to.

Ollama address:

- On the Mac: `${OLLAMA_BASE_URL:-http://localhost:11434/v1}`.
- In the container: `deploy/agent/compose.yml` sets
  `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`.

`local-qwen` = `qwen3:14b-ctx32k` (installed). No `.env` is needed for Ollama.
A `.env` (copied from `.env.example`) is only needed for OpenAI or vLLM keys,
or a non-default Ollama address.

## 10. Known caveats

- These are the first live GRFICS runs. During development GRFICS was only
  covered by fixture tests.
- On macOS the GRFICS networks are bridges, not macvlan, so segmentation is
  weaker than upstream. Reports show `bridge`, which is what actually runs.
- GRFICS starts a Kali attacker container and Caldera by default. The agent
  only reads them.
- The containerized agent scans its own image as well, giving one extra V001
  finding compared with a host run.
