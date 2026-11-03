# Agent vs Deterministic — `run-20261028-165254-bc20`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** error · **Snapshot:** `snap-f15452669668365a` · **Generated:** 2026-10-28 16:57 UTC

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
| critical | C008 | `F-C008-68fe4c7f4f` Docker socket is mounted into the container | simulation |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-53feed5895` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C003 | `F-C003-3487b8591a` Container runs as root | EWS |
| medium | C002 | `F-C002-037b08e810` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C003 | `F-C003-c9e52521d1` Container runs as root | HMI |
| medium | C003 | `F-C003-820281404a` Container runs as root | caldera |
| medium | C002 | `F-C002-d6baa40e78` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C003 | `F-C003-f4ec27c5ae` Container runs as root | kali |
| medium | C002 | `F-C002-286ec51f66` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | C003 | `F-C003-48817d75f3` Container runs as root | plc |
| medium | C002 | `F-C002-0987895434` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| medium | C003 | `F-C003-6068191ec5` Container runs as root | router |
| medium | N003 | `F-N003-e3fa2e8ec8` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-4e095e1c8d` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | C003 | `F-C003-6c2192b5b7` Container runs as root | simulation |
| medium | N002 | `F-N002-4db643e2d1` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-66b0f979f3` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-198cac17b8` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-62bb5f6658` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-bc320aad5f` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-5e9938e52a` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-232f0e1c1c` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-33813c9433` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-dd4f3c0f9d` Container bridges multiple networks | router |
| medium | S001 | `F-S001-4c6bac58b2` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-b224fc9598` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-8fa6ce9ceb` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-35449f172f` Root filesystem is writable | EWS |
| low | N001 | `F-N001-f65e9784b2` Ports published on all host interfaces | EWS |
| low | R001 | `F-R001-2d4dcdfda0` Missing resource limits: memory, cpu, pids | EWS |
| low | C006 | `F-C006-780203f722` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-bad2334e29` Root filesystem is writable | HMI |
| low | N001 | `F-N001-2a4cb7bc45` Ports published on all host interfaces | HMI |
| low | R001 | `F-R001-dda211013b` Missing resource limits: memory, cpu, pids | HMI |
| low | C006 | `F-C006-630f1484bd` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-ac6ad29443` Root filesystem is writable | caldera |
| low | N001 | `F-N001-f64a314cc7` Ports published on all host interfaces | caldera |
| low | R001 | `F-R001-4b2ca13da0` Missing resource limits: memory, cpu, pids | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-fe6e76f949` no-new-privileges is not set | kali |
| low | C007 | `F-C007-996e872a74` Root filesystem is writable | kali |
| low | N001 | `F-N001-c69c9ac216` Ports published on all host interfaces | kali |
| low | R001 | `F-R001-b67834c1ce` Missing resource limits: memory, cpu, pids | kali |
| low | C006 | `F-C006-329b6e5395` no-new-privileges is not set | plc |
| low | C007 | `F-C007-256019f237` Root filesystem is writable | plc |
| low | N001 | `F-N001-9d1303f518` Ports published on all host interfaces | plc |
| low | R001 | `F-R001-b090775fa2` Missing resource limits: memory, cpu, pids | plc |
| low | C006 | `F-C006-fb97b968f6` no-new-privileges is not set | router |
| low | C007 | `F-C007-8cee1f4829` Root filesystem is writable | router |
| low | N001 | `F-N001-eaec2938a2` Ports published on all host interfaces | router |
| low | R001 | `F-R001-d1ae950716` Missing resource limits: memory, cpu, pids | router |
| low | C006 | `F-C006-96d45214d1` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-d434e2d984` Root filesystem is writable | simulation |
| low | N001 | `F-N001-3785262898` Ports published on all host interfaces | simulation |
| low | R001 | `F-R001-9f23d75cea` Missing resource limits: memory, cpu, pids | simulation |
| low | C010 | `F-C010-1c9ee998ab` No capabilities are dropped | EWS |
| low | C010 | `F-C010-64eeeccefc` No capabilities are dropped | HMI |
| low | C010 | `F-C010-77f32c42d3` No capabilities are dropped | caldera |
| low | C010 | `F-C010-e0a6b07dae` No capabilities are dropped | kali |
| low | C010 | `F-C010-d5ab8cc44c` No capabilities are dropped | plc |
| low | C010 | `F-C010-971af83363` No capabilities are dropped | router |
| low | C010 | `F-C010-1dc2cfa6fb` No capabilities are dropped | simulation |
| info | R002 | `F-R002-c900ecc4fd` No restart policy | EWS |
| info | R002 | `F-R002-d6c47abd42` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-d6ffe19a8a` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-d30407ee28` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-f8063ba02e` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-68ddaa52aa` No restart policy | kali |
| info | R002 | `F-R002-494b9f2dd4` No restart policy | plc |
| info | R002 | `F-R002-32f1c46679` No restart policy | simulation |


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
