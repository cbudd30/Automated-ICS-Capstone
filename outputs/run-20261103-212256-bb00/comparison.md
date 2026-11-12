# Agent vs Deterministic — `run-20261103-212256-bb00`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** ok · **Snapshot:** `snap-69b1cd146a835f16` · **Generated:** 2026-11-03 21:54 UTC

## 1. Scores

| Metric | Value |
|---|---|
| Deterministic findings found by the agent | 28 of 85 (recall 33%) |
| Severity-weighted recall | 50% |
| Missed by the agent | 57 |
| Agent findings that match a deterministic finding | 29 of 31 (94%) |
| Agent findings outside the rules (validated) | 0 |
| Agent findings rejected by validation | 2 (6%) |


**Recall by severity:**

| Severity | Found | Total | Recall |
|---|---|---|---|
| critical | 6 | 7 | 86% |
| high | 0 | 1 | 0% |
| medium | 15 | 25 | 60% |
| low | 7 | 42 | 17% |
| info | 0 | 10 | 0% |


## 2. Missed by the agent (57)

Confirmed by the rules or Trivy, but the agent did not report them. Details and evidence: `deterministic_report.md`.

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | V001 | `F-V001-e3f7e95629` Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN) | fortiphyd/grfics-simulation:latest |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-642bd54116` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C002 | `F-C002-9ff6db8b5a` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C002 | `F-C002-ecef44d8e3` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C002 | `F-C002-ef79f33e97` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | N003 | `F-N003-409c4fff4c` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-970a6099c7` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | S001 | `F-S001-dc0c2ecdaa` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | S001 | `F-S001-85dfcdcc99` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | S001 | `F-S001-979d5fd5cb` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | S001 | `F-S001-9c458a959a` Credential-like environment variables: FWUI_SECRET_KEY | router |
| low | C006 | `F-C006-5a289c7891` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-a4de23187f` Root filesystem is writable | EWS |
| low | N001 | `F-N001-0cb1f0c910` Ports published on all host interfaces | EWS |
| low | C006 | `F-C006-b076e34997` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-3f1e5940e2` Root filesystem is writable | HMI |
| low | N001 | `F-N001-5968db9717` Ports published on all host interfaces | HMI |
| low | C006 | `F-C006-66db46f4e3` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-77df33b14f` Root filesystem is writable | caldera |
| low | N001 | `F-N001-4b14ce61f0` Ports published on all host interfaces | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-09d9f01cdf` no-new-privileges is not set | kali |
| low | C007 | `F-C007-9029918cfd` Root filesystem is writable | kali |
| low | N001 | `F-N001-12cc6aed28` Ports published on all host interfaces | kali |
| low | C006 | `F-C006-72739a1f27` no-new-privileges is not set | plc |
| low | C007 | `F-C007-2d308aa79b` Root filesystem is writable | plc |
| low | N001 | `F-N001-c27d4bf5e2` Ports published on all host interfaces | plc |
| low | C006 | `F-C006-e846a64ec8` no-new-privileges is not set | router |
| low | C007 | `F-C007-a89aad83b5` Root filesystem is writable | router |
| low | N001 | `F-N001-5fdc7031ff` Ports published on all host interfaces | router |
| low | C006 | `F-C006-c8b070474f` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-d7b458e71c` Root filesystem is writable | simulation |
| low | N001 | `F-N001-57c5a7e154` Ports published on all host interfaces | simulation |
| low | C010 | `F-C010-cd66171efc` No capabilities are dropped | EWS |
| low | C010 | `F-C010-f80bc24b82` No capabilities are dropped | HMI |
| low | C010 | `F-C010-93acfc6e11` No capabilities are dropped | caldera |
| low | C010 | `F-C010-478cb8bdd8` No capabilities are dropped | kali |
| low | C010 | `F-C010-3493a0efe5` No capabilities are dropped | plc |
| low | C010 | `F-C010-e8e822fceb` No capabilities are dropped | router |
| low | C010 | `F-C010-9f3563e9e6` No capabilities are dropped | simulation |
| info | R002 | `F-R002-7f7a4734d7` No restart policy | EWS |
| info | R002 | `F-R002-7f37a0a528` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-b68a76204d` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-68f6ca4cdc` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-86d69aa763` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-f8f5e58aa4` No restart policy | kali |
| info | R002 | `F-R002-38545afecd` No restart policy | plc |
| info | R002 | `F-R002-1a797a3d20` No restart policy | simulation |


## 3. Found by the agent (28)

| Severity | Rule | Finding | Resource | Agent severity | Agent finding(s) |
|---|---|---|---|---|---|
| critical | V001 | Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN) | fortiphyd/grfics-caldera:latest | critical (same) | `F-AGENT-ea8297eb0a` |
| critical | V001 | Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN) | fortiphyd/grfics-plc:latest | critical (same) | `F-AGENT-5dbf735580` |
| critical | V001 | Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN) | fortiphyd/grfics-router:latest | critical (same) | `F-AGENT-889445787d` |
| critical | V001 | Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW) | fortiphyd/grfics-scadalts:latest | critical (same) | `F-AGENT-8e831c39b5` |
| critical | V001 | Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN) | fortiphyd/grfics-workstation:latest | critical (same) | `F-AGENT-9f9707fa6d` |
| critical | C008 | Docker socket is mounted into the container | simulation | critical (same) | `F-AGENT-64c9b49ecd`, `F-AGENT-844939d47c` |
| medium | C003 | Container runs as root | EWS | high (higher) | `F-AGENT-115d61a533` |
| medium | C003 | Container runs as root | HMI | high (higher) | `F-AGENT-9e92389a35` |
| medium | C003 | Container runs as root | caldera | high (higher) | `F-AGENT-c911bed87f` |
| medium | C003 | Container runs as root | kali | high (higher) | `F-AGENT-06e8c4c933` |
| medium | C003 | Container runs as root | plc | high (higher) | `F-AGENT-5dbd79bde1` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router | critical (higher) | `F-AGENT-b34ca67d67` |
| medium | C003 | Container runs as root | router | high (higher) | `F-AGENT-a151ce978c` |
| medium | C003 | Container runs as root | simulation | high (higher) | `F-AGENT-074cc5cc68` |
| medium | N002 | Container bridges multiple networks | EWS | critical (higher) | `F-AGENT-a35139491a` |
| medium | N002 | Container bridges multiple networks | HMI | critical (higher) | `F-AGENT-be6b45227a` |
| medium | N002 | Container bridges multiple networks | caldera | critical (higher) | `F-AGENT-2545e4e51f` |
| medium | N002 | Container bridges multiple networks | kali | critical (higher) | `F-AGENT-742c8e37c2` |
| medium | N002 | Container bridges multiple networks | plc | critical (higher) | `F-AGENT-8dbc3c9b4a` |
| medium | N002 | Container bridges multiple networks | router | high (higher) | `F-AGENT-5a35e3b0d7` |
| medium | N002 | Container bridges multiple networks | simulation | critical (higher) | `F-AGENT-aa02774d6b` |
| low | R001 | Missing resource limits: memory, cpu, pids | EWS | medium (higher) | `F-AGENT-622ea665f5` |
| low | R001 | Missing resource limits: memory, cpu, pids | HMI | medium (higher) | `F-AGENT-621d9a03e1` |
| low | R001 | Missing resource limits: memory, cpu, pids | caldera | medium (higher) | `F-AGENT-7af47036d6` |
| low | R001 | Missing resource limits: memory, cpu, pids | kali | medium (higher) | `F-AGENT-e4f6817362` |
| low | R001 | Missing resource limits: memory, cpu, pids | plc | medium (higher) | `F-AGENT-b8dd4700f5` |
| low | R001 | Missing resource limits: memory, cpu, pids | router | medium (higher) | `F-AGENT-77817704e1` |
| low | R001 | Missing resource limits: memory, cpu, pids | simulation | medium (higher) | `F-AGENT-ff798e191b` |


## 4. Agent findings outside the rules (0)

Passed validation (real resource, real field) but match no deterministic finding: either an issue the rules do not check, or a weak/incorrect claim. Needs human review. Details: `agent_report.md`.

_None._


## 5. Agent findings rejected by validation (2)

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | AGENT | `F-AGENT-4bfeb9dff7` Image Vulnerabilities | simulation |
| critical | AGENT | `F-AGENT-e1d6fde913` Multi-Network Bridging | grficsv3_a-grfics-admin |


## 6. How matching works

- The agent never saw the deterministic findings; they are used here as the answer key.
- An agent finding covers a deterministic finding when it names the same resource (for image findings, also a container running that image) and cites the same Docker field as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).
- Image vulnerabilities (V001) are scored per image: covered when the agent reported at least one vulnerability ID that Trivy found in that image.
- Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> socket mount C008, otherwise sensitive bind mount C009).
- Only validated agent findings can cover a deterministic finding; rejected ones never do.
- Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.
