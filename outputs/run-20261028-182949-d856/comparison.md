# Agent vs Deterministic — `run-20261028-182949-d856`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** error · **Snapshot:** `snap-9b3a3ad7a5fe1631` · **Generated:** 2026-10-28 18:42 UTC

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
| critical | C008 | `F-C008-e28fcee7e7` Docker socket is mounted into the container | simulation |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-3f72b98b24` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C003 | `F-C003-1148fac8d8` Container runs as root | EWS |
| medium | C002 | `F-C002-5ccf4fae24` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C003 | `F-C003-b07c36fac1` Container runs as root | HMI |
| medium | C003 | `F-C003-294b529fdc` Container runs as root | caldera |
| medium | C002 | `F-C002-ef2a81682f` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C003 | `F-C003-cf7897f0d8` Container runs as root | kali |
| medium | C002 | `F-C002-116d497111` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | C003 | `F-C003-18e91b1739` Container runs as root | plc |
| medium | C002 | `F-C002-233bf393d6` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| medium | C003 | `F-C003-c5d93ea4b0` Container runs as root | router |
| medium | N003 | `F-N003-3eb43354fa` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-7d433bbe88` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | C003 | `F-C003-9b3333ad46` Container runs as root | simulation |
| medium | N002 | `F-N002-ee2ff4d33d` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-f5b386fa18` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-a9ba10ffdb` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-aa9473743c` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-25651cb7e6` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-bda984b6ef` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-6309982903` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-ddb43c5903` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-968507efd3` Container bridges multiple networks | router |
| medium | S001 | `F-S001-aab7f638e3` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-a76c282ed4` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-b51b12aafa` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-792c68f60e` Root filesystem is writable | EWS |
| low | N001 | `F-N001-91ac9caedc` Ports published on all host interfaces | EWS |
| low | R001 | `F-R001-fed16234d6` Missing resource limits: memory, cpu, pids | EWS |
| low | C006 | `F-C006-3ac4d642ae` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-dbcf4ca4fb` Root filesystem is writable | HMI |
| low | N001 | `F-N001-3439d18210` Ports published on all host interfaces | HMI |
| low | R001 | `F-R001-facac27728` Missing resource limits: memory, cpu, pids | HMI |
| low | C006 | `F-C006-eb67045425` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-b6acb8ae18` Root filesystem is writable | caldera |
| low | N001 | `F-N001-c41076fb49` Ports published on all host interfaces | caldera |
| low | R001 | `F-R001-d03d448e5a` Missing resource limits: memory, cpu, pids | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-28a557d52a` no-new-privileges is not set | kali |
| low | C007 | `F-C007-7b14c3541f` Root filesystem is writable | kali |
| low | N001 | `F-N001-82672a6fee` Ports published on all host interfaces | kali |
| low | R001 | `F-R001-60046a084b` Missing resource limits: memory, cpu, pids | kali |
| low | C006 | `F-C006-c84c236e66` no-new-privileges is not set | plc |
| low | C007 | `F-C007-bfa67fd6c7` Root filesystem is writable | plc |
| low | N001 | `F-N001-b21d50835d` Ports published on all host interfaces | plc |
| low | R001 | `F-R001-49f443bf24` Missing resource limits: memory, cpu, pids | plc |
| low | C006 | `F-C006-4823ff4941` no-new-privileges is not set | router |
| low | C007 | `F-C007-186349a0ff` Root filesystem is writable | router |
| low | N001 | `F-N001-b0b7bc8299` Ports published on all host interfaces | router |
| low | R001 | `F-R001-844f7788b7` Missing resource limits: memory, cpu, pids | router |
| low | C006 | `F-C006-33603630ab` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-6c485d3443` Root filesystem is writable | simulation |
| low | N001 | `F-N001-a66bafe8d0` Ports published on all host interfaces | simulation |
| low | R001 | `F-R001-1c0aa23ac1` Missing resource limits: memory, cpu, pids | simulation |
| low | C010 | `F-C010-181706a20e` No capabilities are dropped | EWS |
| low | C010 | `F-C010-d7c75b6449` No capabilities are dropped | HMI |
| low | C010 | `F-C010-22e8d6518d` No capabilities are dropped | caldera |
| low | C010 | `F-C010-716b899fd4` No capabilities are dropped | kali |
| low | C010 | `F-C010-6b77bc20c7` No capabilities are dropped | plc |
| low | C010 | `F-C010-eac6857fd0` No capabilities are dropped | router |
| low | C010 | `F-C010-5cf6d7c8ee` No capabilities are dropped | simulation |
| info | R002 | `F-R002-c0689fffd3` No restart policy | EWS |
| info | R002 | `F-R002-fccc88f7c1` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-86ba7de000` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-07e0405563` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-290cff6b58` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-e196c3a9d4` No restart policy | kali |
| info | R002 | `F-R002-3ec0d3a8b9` No restart policy | plc |
| info | R002 | `F-R002-b86343f8bb` No restart policy | simulation |


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
