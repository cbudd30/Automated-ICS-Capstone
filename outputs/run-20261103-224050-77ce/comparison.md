# Agent vs Deterministic — `run-20261103-224050-77ce`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** ok · **Snapshot:** `snap-f373af1bdb7c1c22` · **Generated:** 2026-11-03 22:49 UTC

## 1. Scores

| Metric | Value |
|---|---|
| Deterministic findings found by the agent | 0 of 85 (recall 0%) |
| Severity-weighted recall | 0% |
| Missed by the agent | 85 |
| Agent findings that match a deterministic finding | 0 of 4 (0%) |
| Agent findings outside the rules (validated) | 0 |
| Agent findings rejected by validation | 4 (100%) |


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
| critical | C008 | `F-C008-6e299e2c38` Docker socket is mounted into the container | simulation |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-972b27c257` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C003 | `F-C003-614794561d` Container runs as root | EWS |
| medium | C002 | `F-C002-142607511a` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C003 | `F-C003-f08f0be745` Container runs as root | HMI |
| medium | C003 | `F-C003-b170ff99fc` Container runs as root | caldera |
| medium | C002 | `F-C002-725f36dbd5` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C003 | `F-C003-f6e561d64d` Container runs as root | kali |
| medium | C002 | `F-C002-888aecdfba` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | C003 | `F-C003-4c4902359f` Container runs as root | plc |
| medium | C002 | `F-C002-e674733314` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| medium | C003 | `F-C003-124c10f8ba` Container runs as root | router |
| medium | N003 | `F-N003-11b2afc166` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-8c0989ecfa` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | C003 | `F-C003-d1ca7006aa` Container runs as root | simulation |
| medium | N002 | `F-N002-f1dadde77e` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-337f8a2a73` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-e60b8a7de1` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-a7f0135730` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-8cdb036ebc` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-3c16fa7a1b` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-61f806d0bb` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-37cf676829` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-904332a3f7` Container bridges multiple networks | router |
| medium | S001 | `F-S001-9518137eb8` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-79aa83880b` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-1104feea9c` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-b7490ac45b` Root filesystem is writable | EWS |
| low | N001 | `F-N001-48193958f7` Ports published on all host interfaces | EWS |
| low | R001 | `F-R001-23ad18bb33` Missing resource limits: memory, cpu, pids | EWS |
| low | C006 | `F-C006-8f9d5a1f7a` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-0ea8c834cb` Root filesystem is writable | HMI |
| low | N001 | `F-N001-9dfd5d373a` Ports published on all host interfaces | HMI |
| low | R001 | `F-R001-3fb8680d13` Missing resource limits: memory, cpu, pids | HMI |
| low | C006 | `F-C006-d77e7886cd` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-ac1e8f5aa6` Root filesystem is writable | caldera |
| low | N001 | `F-N001-ca619437be` Ports published on all host interfaces | caldera |
| low | R001 | `F-R001-6049acacae` Missing resource limits: memory, cpu, pids | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-dacf762030` no-new-privileges is not set | kali |
| low | C007 | `F-C007-699695c066` Root filesystem is writable | kali |
| low | N001 | `F-N001-c7b4bcd09d` Ports published on all host interfaces | kali |
| low | R001 | `F-R001-5bda9123ff` Missing resource limits: memory, cpu, pids | kali |
| low | C006 | `F-C006-ee370b9965` no-new-privileges is not set | plc |
| low | C007 | `F-C007-c396f63b6e` Root filesystem is writable | plc |
| low | N001 | `F-N001-da94b296f7` Ports published on all host interfaces | plc |
| low | R001 | `F-R001-0a4333f6ae` Missing resource limits: memory, cpu, pids | plc |
| low | C006 | `F-C006-641b2e51cb` no-new-privileges is not set | router |
| low | C007 | `F-C007-7c41eb0fa7` Root filesystem is writable | router |
| low | N001 | `F-N001-1f4cb535c8` Ports published on all host interfaces | router |
| low | R001 | `F-R001-62e67b1a9c` Missing resource limits: memory, cpu, pids | router |
| low | C006 | `F-C006-4fd5fb1b90` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-bde4930b75` Root filesystem is writable | simulation |
| low | N001 | `F-N001-fcb8448755` Ports published on all host interfaces | simulation |
| low | R001 | `F-R001-3fc90baf34` Missing resource limits: memory, cpu, pids | simulation |
| low | C010 | `F-C010-8d4127840b` No capabilities are dropped | EWS |
| low | C010 | `F-C010-e341973f13` No capabilities are dropped | HMI |
| low | C010 | `F-C010-990a8b9df9` No capabilities are dropped | caldera |
| low | C010 | `F-C010-5abb7e02ff` No capabilities are dropped | kali |
| low | C010 | `F-C010-121aa10c09` No capabilities are dropped | plc |
| low | C010 | `F-C010-5936bed522` No capabilities are dropped | router |
| low | C010 | `F-C010-a58d4d719a` No capabilities are dropped | simulation |
| info | R002 | `F-R002-99c4be6402` No restart policy | EWS |
| info | R002 | `F-R002-1f44e87255` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-78a8c1528b` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-dc3d2f0d13` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-62d9609d9d` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-0524e4562c` No restart policy | kali |
| info | R002 | `F-R002-77b2a7d3d6` No restart policy | plc |
| info | R002 | `F-R002-1b35894e1d` No restart policy | simulation |


## 3. Found by the agent (0)

_None._


## 4. Agent findings outside the rules (0)

Passed validation (real resource, real field) but match no deterministic finding: either an issue the rules do not check, or a weak/incorrect claim. Needs human review. Details: `agent_report.md`.

_None._


## 5. Agent findings rejected by validation (4)

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| high | AGENT | `F-AGENT-c0cc97d95b` High-severity image vulnerabilities | ics-simulator |
| high | AGENT | `F-AGENT-1faf9d986d` High-severity image vulnerabilities | opcua-server |
| high | AGENT | `F-AGENT-cfdc4e7bae` Unpatched Java libraries in ICS containers | ics-simulator |
| critical | AGENT | `F-AGENT-72f1e48bee` High-risk web server components in OPC UA service | opcua-server |


## 6. How matching works

- The agent never saw the deterministic findings; they are used here as the answer key.
- An agent finding covers a deterministic finding when it names the same resource (for image findings, also a container running that image) and cites the same Docker field as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).
- Image vulnerabilities (V001) are scored per image: covered when the agent reported at least one vulnerability ID that Trivy found in that image.
- Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> socket mount C008, otherwise sensitive bind mount C009).
- Only validated agent findings can cover a deterministic finding; rejected ones never do.
- Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.
