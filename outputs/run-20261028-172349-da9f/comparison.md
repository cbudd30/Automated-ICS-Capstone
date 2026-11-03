# Agent vs Deterministic — `run-20261028-172349-da9f`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** error · **Snapshot:** `snap-fb281edbac80d479` · **Generated:** 2026-10-28 18:26 UTC

## 1. Scores

| Metric | Value |
|---|---|
| Deterministic findings found by the agent | 0 of 85 (recall 0%) |
| Severity-weighted recall | 0% |
| Missed by the agent | 85 |
| Agent findings that match a deterministic finding | 0 of 0 (0%) |
| Agent findings outside the rules (validated) | 0 |
| Agent findings rejected by validation | 0 (0%) |


**Recall by severity:**

| Severity | Found | Total | Recall |
|---|---|---|---|
| critical | 0 | 7 | 0% |
| high | 0 | 1 | 0% |
| medium | 0 | 25 | 0% |
| low | 0 | 42 | 0% |
| info | 0 | 10 | 0% |


## 2. Missed by the agent (85)

Confirmed by the rules or Trivy, but the agent did not report them. Details and evidence: `deterministic_report.md`.

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | V001 | `F-V001-ec328b84bb` Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN) | fortiphyd/grfics-caldera:latest |
| critical | V001 | `F-V001-5c7f29bdf3` Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN) | fortiphyd/grfics-plc:latest |
| critical | V001 | `F-V001-c66c18dcb1` Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN) | fortiphyd/grfics-router:latest |
| critical | V001 | `F-V001-885cc6c80e` Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW) | fortiphyd/grfics-scadalts:latest |
| critical | V001 | `F-V001-e3f7e95629` Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN) | fortiphyd/grfics-simulation:latest |
| critical | V001 | `F-V001-9e8f54fed8` Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN) | fortiphyd/grfics-workstation:latest |
| critical | C008 | `F-C008-db5445b949` Docker socket is mounted into the container | simulation |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-8cbab193f3` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C003 | `F-C003-b7d4bad03d` Container runs as root | EWS |
| medium | C002 | `F-C002-9589c994db` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C003 | `F-C003-8ddee4631b` Container runs as root | HMI |
| medium | C003 | `F-C003-13872ec4bb` Container runs as root | caldera |
| medium | C002 | `F-C002-638943531c` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C003 | `F-C003-d82936c959` Container runs as root | kali |
| medium | C002 | `F-C002-a3f42d87c6` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | C003 | `F-C003-66ac282e7d` Container runs as root | plc |
| medium | C002 | `F-C002-2218f2f6fc` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| medium | C003 | `F-C003-20ecff9a62` Container runs as root | router |
| medium | N003 | `F-N003-a41c691406` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-98c172cba2` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | C003 | `F-C003-ce89bce6c0` Container runs as root | simulation |
| medium | N002 | `F-N002-7b7838a78d` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-48d798b680` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-7004d6dc0e` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-4c449375d8` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-f9320e7a1e` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-f0d9dec86f` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-47ec083a92` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-ab0fc90ff6` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-fc5db6bab0` Container bridges multiple networks | router |
| medium | S001 | `F-S001-242a3e9a4d` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-963f6ca6f8` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-04e6854a0c` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-6aed282f94` Root filesystem is writable | EWS |
| low | N001 | `F-N001-bea58d0388` Ports published on all host interfaces | EWS |
| low | R001 | `F-R001-d1941a4bef` Missing resource limits: memory, cpu, pids | EWS |
| low | C006 | `F-C006-5383408607` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-193231a99d` Root filesystem is writable | HMI |
| low | N001 | `F-N001-7c51a8bf40` Ports published on all host interfaces | HMI |
| low | R001 | `F-R001-7f8b1552b4` Missing resource limits: memory, cpu, pids | HMI |
| low | C006 | `F-C006-a433803a7a` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-24efd9ce18` Root filesystem is writable | caldera |
| low | N001 | `F-N001-d33e17c077` Ports published on all host interfaces | caldera |
| low | R001 | `F-R001-6f58560137` Missing resource limits: memory, cpu, pids | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-508e636444` no-new-privileges is not set | kali |
| low | C007 | `F-C007-fc7160e1b5` Root filesystem is writable | kali |
| low | N001 | `F-N001-8e7be549ab` Ports published on all host interfaces | kali |
| low | R001 | `F-R001-37c12e084d` Missing resource limits: memory, cpu, pids | kali |
| low | C006 | `F-C006-4d99ba1ca0` no-new-privileges is not set | plc |
| low | C007 | `F-C007-72fefa606f` Root filesystem is writable | plc |
| low | N001 | `F-N001-7041a23a68` Ports published on all host interfaces | plc |
| low | R001 | `F-R001-bb1822ae36` Missing resource limits: memory, cpu, pids | plc |
| low | C006 | `F-C006-c546431193` no-new-privileges is not set | router |
| low | C007 | `F-C007-031101d92d` Root filesystem is writable | router |
| low | N001 | `F-N001-a88ebcfda5` Ports published on all host interfaces | router |
| low | R001 | `F-R001-a235f50a23` Missing resource limits: memory, cpu, pids | router |
| low | C006 | `F-C006-98e3ed7b30` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-b974989ada` Root filesystem is writable | simulation |
| low | N001 | `F-N001-182357c504` Ports published on all host interfaces | simulation |
| low | R001 | `F-R001-b3a7419788` Missing resource limits: memory, cpu, pids | simulation |
| low | C010 | `F-C010-a9f7b5f95b` No capabilities are dropped | EWS |
| low | C010 | `F-C010-739fdd9d83` No capabilities are dropped | HMI |
| low | C010 | `F-C010-4c7c63c6e1` No capabilities are dropped | caldera |
| low | C010 | `F-C010-7a81618007` No capabilities are dropped | kali |
| low | C010 | `F-C010-bff8338e7b` No capabilities are dropped | plc |
| low | C010 | `F-C010-efcbcd0751` No capabilities are dropped | router |
| low | C010 | `F-C010-1778bc4287` No capabilities are dropped | simulation |
| info | R002 | `F-R002-bca8fdce45` No restart policy | EWS |
| info | R002 | `F-R002-2cfb363633` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-3078206449` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-ca192e5ddf` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-b1a0003873` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-0101e462c0` No restart policy | kali |
| info | R002 | `F-R002-03c270159f` No restart policy | plc |
| info | R002 | `F-R002-aa2eb7f720` No restart policy | simulation |


## 3. Found by the agent (0)

_None._


## 4. Agent findings outside the rules (0)

Passed validation (real resource, real field) but match no deterministic finding: either an issue the rules do not check, or a weak/incorrect claim. Needs human review. Details: `agent_report.md`.

_None._


## 5. Agent findings rejected by validation (0)

_None._


## 6. How matching works

- The agent never saw the deterministic findings; they are used here as the answer key.
- An agent finding covers a deterministic finding when it names the same resource (for image findings, also a container running that image) and cites the same Docker field as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).
- Image vulnerabilities (V001) are scored per image: covered when the agent reported at least one vulnerability ID that Trivy found in that image.
- Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> socket mount C008, otherwise sensitive bind mount C009).
- Only validated agent findings can cover a deterministic finding; rejected ones never do.
- Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.
