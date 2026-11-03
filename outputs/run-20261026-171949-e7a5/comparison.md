# Agent vs Deterministic — `run-20261026-171949-e7a5`

**Model:** `local-qwen` (ollama / `qwen3:14b-ctx32k`) · **Agent status:** ok · **Snapshot:** `snap-42ec19bd1e402794` · **Generated:** 2026-10-26 18:31 UTC

## 1. Scores

| Metric | Value |
|---|---|
| Deterministic findings found by the agent | 1 of 85 (recall 1%) |
| Severity-weighted recall | 3% |
| Missed by the agent | 84 |
| Agent findings that match a deterministic finding | 1 of 3 (33%) |
| Agent findings outside the rules (validated) | 0 |
| Agent findings rejected by validation | 2 (67%) |


**Recall by severity:**

| Severity | Found | Total | Recall |
|---|---|---|---|
| critical | 1 | 7 | 14% |
| high | 0 | 1 | 0% |
| medium | 0 | 25 | 0% |
| low | 0 | 42 | 0% |
| info | 0 | 10 | 0% |


## 2. Missed by the agent (84)

Confirmed by the rules or Trivy, but the agent did not report them. Details and evidence: `deterministic_report.md`.

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | V001 | `F-V001-ec328b84bb` Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN) | fortiphyd/grfics-caldera:latest |
| critical | V001 | `F-V001-5c7f29bdf3` Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN) | fortiphyd/grfics-plc:latest |
| critical | V001 | `F-V001-885cc6c80e` Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW) | fortiphyd/grfics-scadalts:latest |
| critical | V001 | `F-V001-e3f7e95629` Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN) | fortiphyd/grfics-simulation:latest |
| critical | V001 | `F-V001-9e8f54fed8` Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN) | fortiphyd/grfics-workstation:latest |
| critical | C008 | `F-C008-8156eaec96` Docker socket is mounted into the container | simulation |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C002 | `F-C002-383abc283c` Container adds dangerous capabilities: NET_ADMIN | EWS |
| medium | C003 | `F-C003-255ad39f7d` Container runs as root | EWS |
| medium | C002 | `F-C002-3bf07d0e81` Container adds dangerous capabilities: NET_ADMIN | HMI |
| medium | C003 | `F-C003-9b67810909` Container runs as root | HMI |
| medium | C003 | `F-C003-91987dbd22` Container runs as root | caldera |
| medium | C002 | `F-C002-11ce7daa2d` Container adds dangerous capabilities: NET_ADMIN | kali |
| medium | C003 | `F-C003-205593608c` Container runs as root | kali |
| medium | C002 | `F-C002-a9137c7b7f` Container adds dangerous capabilities: NET_ADMIN | plc |
| medium | C003 | `F-C003-e1e6ceccb1` Container runs as root | plc |
| medium | C002 | `F-C002-541155100b` Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router |
| medium | C003 | `F-C003-8946ab56f6` Container runs as root | router |
| medium | N003 | `F-N003-d06c0ca54d` IP forwarding enabled inside the container | router |
| medium | C002 | `F-C002-6aafad366c` Container adds dangerous capabilities: NET_ADMIN | simulation |
| medium | C003 | `F-C003-1cd093f70a` Container runs as root | simulation |
| medium | N002 | `F-N002-09a743e881` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-0329c4a990` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-7609984e56` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-f4fda064dc` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-8470cef167` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-2aa37c4a27` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-e8d4932f0d` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-3ec8fa3c85` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-fff053fbd3` Container bridges multiple networks | router |
| medium | S001 | `F-S001-87a0fb071c` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-8e11f9cb59` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-cc312f426a` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-686c0fdf88` Root filesystem is writable | EWS |
| low | N001 | `F-N001-43f484d9a9` Ports published on all host interfaces | EWS |
| low | R001 | `F-R001-a2b8b31f01` Missing resource limits: memory, cpu, pids | EWS |
| low | C006 | `F-C006-5530a164e2` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-7d97762995` Root filesystem is writable | HMI |
| low | N001 | `F-N001-6726443bcf` Ports published on all host interfaces | HMI |
| low | R001 | `F-R001-a343b03efb` Missing resource limits: memory, cpu, pids | HMI |
| low | C006 | `F-C006-c6e5ed8856` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-ee0d4d1391` Root filesystem is writable | caldera |
| low | N001 | `F-N001-9597c1b196` Ports published on all host interfaces | caldera |
| low | R001 | `F-R001-8246b9b5d1` Missing resource limits: memory, cpu, pids | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-3fdea5a984` no-new-privileges is not set | kali |
| low | C007 | `F-C007-f0697f802e` Root filesystem is writable | kali |
| low | N001 | `F-N001-f0794d34af` Ports published on all host interfaces | kali |
| low | R001 | `F-R001-4eb797ec63` Missing resource limits: memory, cpu, pids | kali |
| low | C006 | `F-C006-b4244521ae` no-new-privileges is not set | plc |
| low | C007 | `F-C007-6e50cf6b1b` Root filesystem is writable | plc |
| low | N001 | `F-N001-d97a4f8c87` Ports published on all host interfaces | plc |
| low | R001 | `F-R001-a972f47047` Missing resource limits: memory, cpu, pids | plc |
| low | C006 | `F-C006-5b03095036` no-new-privileges is not set | router |
| low | C007 | `F-C007-94bb11ca8e` Root filesystem is writable | router |
| low | N001 | `F-N001-bcdd21cb20` Ports published on all host interfaces | router |
| low | R001 | `F-R001-09ec4a69c5` Missing resource limits: memory, cpu, pids | router |
| low | C006 | `F-C006-5c0796e3b7` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-30bd0cb15c` Root filesystem is writable | simulation |
| low | N001 | `F-N001-97c8980cd6` Ports published on all host interfaces | simulation |
| low | R001 | `F-R001-2d99a39101` Missing resource limits: memory, cpu, pids | simulation |
| low | C010 | `F-C010-59d33f6786` No capabilities are dropped | EWS |
| low | C010 | `F-C010-a2d45cde25` No capabilities are dropped | HMI |
| low | C010 | `F-C010-a1957449c3` No capabilities are dropped | caldera |
| low | C010 | `F-C010-47cccf2f8c` No capabilities are dropped | kali |
| low | C010 | `F-C010-86d0bd0af1` No capabilities are dropped | plc |
| low | C010 | `F-C010-fee0f76e97` No capabilities are dropped | router |
| low | C010 | `F-C010-dea410a966` No capabilities are dropped | simulation |
| info | R002 | `F-R002-5288503991` No restart policy | EWS |
| info | R002 | `F-R002-6a49906a89` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-521c538eca` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-afbb443d90` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-9b287ac708` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-3387678041` No restart policy | kali |
| info | R002 | `F-R002-f804afbc82` No restart policy | plc |
| info | R002 | `F-R002-412014737c` No restart policy | simulation |


## 3. Found by the agent (1)

| Severity | Rule | Finding | Resource | Agent severity | Agent finding(s) |
|---|---|---|---|---|---|
| critical | V001 | Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN) | fortiphyd/grfics-router:latest | critical (same) | `F-AGENT-b35c1c2a3d` |


## 4. Agent findings outside the rules (0)

Passed validation (real resource, real field) but match no deterministic finding: either an issue the rules do not check, or a weak/incorrect claim. Needs human review. Details: `agent_report.md`.

_None._


## 5. Agent findings rejected by validation (2)

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| high | AGENT | `F-AGENT-7ba3e902d2` ICS Network Containers Lack Resource Limits | grficsv3_b-ics-net |
| high | AGENT | `F-AGENT-9190252eb5` Published Ports on ICS Network Containers | HMI (fortiphyd/grfics-scadalts:latest) |


## 6. How matching works

- The agent never saw the deterministic findings; they are used here as the answer key.
- An agent finding covers a deterministic finding when it names the same resource (for image findings, also a container running that image) and cites the same Docker field as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).
- Image vulnerabilities (V001) are scored per image: covered when the agent reported at least one vulnerability ID that Trivy found in that image.
- Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> socket mount C008, otherwise sensitive bind mount C009).
- Only validated agent findings can cover a deterministic finding; rejected ones never do.
- Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.
