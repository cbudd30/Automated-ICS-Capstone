# Agent vs Deterministic — `run-20261103-225702-e4b9`

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Agent status:** ok · **Snapshot:** `snap-17690ac30597eb8d` · **Generated:** 2026-11-03 23:18 UTC

## 1. Scores

| Metric | Value |
|---|---|
| Deterministic findings found by the agent | 29 of 85 (recall 34%) |
| Severity-weighted recall | 46% |
| Missed by the agent | 56 |
| Agent findings that match a deterministic finding | 25 of 29 (86%) |
| Agent findings outside the rules (validated) | 0 |
| Agent findings rejected by validation | 4 (14%) |


**Recall by severity:**

| Severity | Found | Total | Recall |
|---|---|---|---|
| critical | 5 | 7 | 71% |
| high | 0 | 1 | 0% |
| medium | 12 | 25 | 48% |
| low | 12 | 42 | 29% |
| info | 0 | 10 | 0% |


## 2. Missed by the agent (56)

Confirmed by the rules or Trivy, but the agent did not report them. Details and evidence: `deterministic_report.md`.

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | V001 | `F-V001-5c7f29bdf3` Image has known vulnerabilities (55 CRITICAL, 1544 HIGH, 6197 MEDIUM, 2083 LOW, 121 UNKNOWN) | fortiphyd/grfics-plc:latest |
| critical | V001 | `F-V001-9e8f54fed8` Image has known vulnerabilities (36 CRITICAL, 704 HIGH, 2175 MEDIUM, 1218 LOW, 8 UNKNOWN) | fortiphyd/grfics-workstation:latest |
| high | V001 | `F-V001-2b857d3575` Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW) | tecnativa/docker-socket-proxy:v0.5.0 |
| medium | C003 | `F-C003-30b0663436` Container runs as root | router |
| medium | N003 | `F-N003-d193a2a313` IP forwarding enabled inside the container | router |
| medium | N002 | `F-N002-964ce77801` Container bridges multiple networks | EWS |
| medium | S001 | `F-S001-4281f12603` Credential-like environment variables: VNC_PASSWORD | EWS |
| medium | N002 | `F-N002-0b7cfb45e1` Container bridges multiple networks | HMI |
| medium | S001 | `F-S001-02d0245b2f` Credential-like environment variables: MYSQL_PASSWORD, MYSQL_ROOT_PASSWORD, TOMCAT_PASSWORD | HMI |
| medium | N002 | `F-N002-be42172b33` Container bridges multiple networks | caldera |
| medium | N002 | `F-N002-a795e15932` Container bridges multiple networks | kali |
| medium | S001 | `F-S001-3d55983e0c` Credential-like environment variables: VNC_PASSWORD | kali |
| medium | N002 | `F-N002-2f42fda941` Container bridges multiple networks | plc |
| medium | N002 | `F-N002-81e8c08941` Container bridges multiple networks | router |
| medium | S001 | `F-S001-9dccac986d` Credential-like environment variables: FWUI_SECRET_KEY | router |
| medium | N002 | `F-N002-21d0f049ef` Container bridges multiple networks | simulation |
| low | C006 | `F-C006-8f41cb1277` no-new-privileges is not set | EWS |
| low | C007 | `F-C007-5d82bab299` Root filesystem is writable | EWS |
| low | N001 | `F-N001-cf817cd692` Ports published on all host interfaces | EWS |
| low | C006 | `F-C006-50f2144e4b` no-new-privileges is not set | HMI |
| low | C007 | `F-C007-eca6c595cf` Root filesystem is writable | HMI |
| low | C006 | `F-C006-3f2f6a90de` no-new-privileges is not set | caldera |
| low | C007 | `F-C007-e2ffa58d2c` Root filesystem is writable | caldera |
| low | I001 | `F-I001-8c6d0e8428` Image uses a floating tag: fortiphyd/grfics-attacker:latest | fortiphyd/grfics-attacker:latest |
| low | I001 | `F-I001-4caef92d21` Image uses a floating tag: fortiphyd/grfics-caldera:latest | fortiphyd/grfics-caldera:latest |
| low | I001 | `F-I001-bdb1b41685` Image uses a floating tag: fortiphyd/grfics-plc:latest | fortiphyd/grfics-plc:latest |
| low | I001 | `F-I001-88b5ab583a` Image uses a floating tag: fortiphyd/grfics-router:latest | fortiphyd/grfics-router:latest |
| low | I001 | `F-I001-bb96196ac9` Image uses a floating tag: fortiphyd/grfics-scadalts:latest | fortiphyd/grfics-scadalts:latest |
| low | I001 | `F-I001-7eb90dfea9` Image uses a floating tag: fortiphyd/grfics-simulation:latest | fortiphyd/grfics-simulation:latest |
| low | I001 | `F-I001-21a668129f` Image uses a floating tag: fortiphyd/grfics-workstation:latest | fortiphyd/grfics-workstation:latest |
| low | C006 | `F-C006-eb3cca5285` no-new-privileges is not set | kali |
| low | C007 | `F-C007-7f26343bcd` Root filesystem is writable | kali |
| low | C006 | `F-C006-1a24118819` no-new-privileges is not set | plc |
| low | C007 | `F-C007-c26e33faf2` Root filesystem is writable | plc |
| low | N001 | `F-N001-a907a359ef` Ports published on all host interfaces | plc |
| low | C006 | `F-C006-9b6611f8f4` no-new-privileges is not set | router |
| low | C007 | `F-C007-44512c52da` Root filesystem is writable | router |
| low | C006 | `F-C006-18bee3c9d8` no-new-privileges is not set | simulation |
| low | C007 | `F-C007-4c9222ff87` Root filesystem is writable | simulation |
| low | C010 | `F-C010-593bf7be53` No capabilities are dropped | EWS |
| low | C010 | `F-C010-11cce86996` No capabilities are dropped | HMI |
| low | C010 | `F-C010-879c799c68` No capabilities are dropped | caldera |
| low | C010 | `F-C010-abc0e2a83c` No capabilities are dropped | kali |
| low | C010 | `F-C010-e1b81732ee` No capabilities are dropped | plc |
| low | C010 | `F-C010-731b4c381b` No capabilities are dropped | router |
| low | C010 | `F-C010-a9e711ed80` No capabilities are dropped | simulation |
| info | R002 | `F-R002-ef00ba556b` No restart policy | EWS |
| info | R002 | `F-R002-787e7b0bfd` No restart policy | HMI |
| info | N005 | `F-N005-39eae3dfcd` Network 'docker-audit-agent_default' is not internal (has external egress) | docker-audit-agent_default |
| info | N005 | `F-N005-bb9759638d` Network 'docker-audit-proxy_default' is not internal (has external egress) | docker-audit-proxy_default |
| info | N005 | `F-N005-847d1eb8ad` Network 'grficsv3_a-grfics-admin' is not internal (has external egress) | grficsv3_a-grfics-admin |
| info | N005 | `F-N005-03974092ac` Network 'grficsv3_b-ics-net' is not internal (has external egress) | grficsv3_b-ics-net |
| info | N005 | `F-N005-b92597b3c2` Network 'grficsv3_c-dmz-net' is not internal (has external egress) | grficsv3_c-dmz-net |
| info | R002 | `F-R002-bba4932b61` No restart policy | kali |
| info | R002 | `F-R002-398ce635fd` No restart policy | plc |
| info | R002 | `F-R002-098663dfc9` No restart policy | simulation |


## 3. Found by the agent (29)

| Severity | Rule | Finding | Resource | Agent severity | Agent finding(s) |
|---|---|---|---|---|---|
| critical | V001 | Image has known vulnerabilities (85 CRITICAL, 1319 HIGH, 2796 MEDIUM, 1247 LOW, 187 UNKNOWN) | fortiphyd/grfics-caldera:latest | critical (same) | `F-AGENT-94cfa11769` |
| critical | V001 | Image has known vulnerabilities (5 CRITICAL, 190 HIGH, 354 MEDIUM, 247 LOW, 2 UNKNOWN) | fortiphyd/grfics-router:latest | critical (same) | `F-AGENT-8e162ad996` |
| critical | V001 | Image has known vulnerabilities (47 CRITICAL, 92 HIGH, 146 MEDIUM, 55 LOW) | fortiphyd/grfics-scadalts:latest | critical (same) | `F-AGENT-317afdd2d3` |
| critical | V001 | Image has known vulnerabilities (7 CRITICAL, 157 HIGH, 246 MEDIUM, 278 LOW, 8 UNKNOWN) | fortiphyd/grfics-simulation:latest | critical (same) | `F-AGENT-bf3ee86cc9` |
| critical | C008 | Docker socket is mounted into the container | simulation | critical (same) | `F-AGENT-64c9b49ecd` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN | EWS | high (higher) | `F-AGENT-18a40307cb` |
| medium | C003 | Container runs as root | EWS | high (higher) | `F-AGENT-2cda102cd8` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN | HMI | high (higher) | `F-AGENT-b0a282b9d9` |
| medium | C003 | Container runs as root | HMI | high (higher) | `F-AGENT-01a6c3ac51` |
| medium | C003 | Container runs as root | caldera | high (higher) | `F-AGENT-e51514926e` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN | kali | high (higher) | `F-AGENT-fb22dc96a2` |
| medium | C003 | Container runs as root | kali | high (higher) | `F-AGENT-875a0eb5ad` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN | plc | high (higher) | `F-AGENT-8eb56f9fdf` |
| medium | C003 | Container runs as root | plc | high (higher) | `F-AGENT-3766c3fa93` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN, NET_RAW | router | high (higher) | `F-AGENT-4ba3fea9a8` |
| medium | C002 | Container adds dangerous capabilities: NET_ADMIN | simulation | high (higher) | `F-AGENT-27ce9af58c` |
| medium | C003 | Container runs as root | simulation | high (higher) | `F-AGENT-652b63be13` |
| low | R001 | Missing resource limits: memory, cpu, pids | EWS | medium (higher) | `F-AGENT-622ea665f5` |
| low | N001 | Ports published on all host interfaces | HMI | critical (higher) | `F-AGENT-317afdd2d3` |
| low | R001 | Missing resource limits: memory, cpu, pids | HMI | medium (higher) | `F-AGENT-621d9a03e1` |
| low | N001 | Ports published on all host interfaces | caldera | critical (higher) | `F-AGENT-94cfa11769` |
| low | R001 | Missing resource limits: memory, cpu, pids | caldera | medium (higher) | `F-AGENT-7af47036d6` |
| low | N001 | Ports published on all host interfaces | kali | critical (higher) | `F-AGENT-8358ccfce1` |
| low | R001 | Missing resource limits: memory, cpu, pids | kali | medium (higher) | `F-AGENT-e4f6817362` |
| low | R001 | Missing resource limits: memory, cpu, pids | plc | medium (higher) | `F-AGENT-b8dd4700f5` |
| low | N001 | Ports published on all host interfaces | router | critical (higher) | `F-AGENT-8e162ad996` |
| low | R001 | Missing resource limits: memory, cpu, pids | router | medium (higher) | `F-AGENT-77817704e1` |
| low | N001 | Ports published on all host interfaces | simulation | critical (higher) | `F-AGENT-bf3ee86cc9` |
| low | R001 | Missing resource limits: memory, cpu, pids | simulation | medium (higher) | `F-AGENT-ff798e191b` |


## 4. Agent findings outside the rules (0)

Passed validation (real resource, real field) but match no deterministic finding: either an issue the rules do not check, or a weak/incorrect claim. Needs human review. Details: `agent_report.md`.

_None._


## 5. Agent findings rejected by validation (4)

| Severity | Rule | Finding | Resource |
|---|---|---|---|
| critical | AGENT | `F-AGENT-694a5642de` Exposed VNC Service with Vulnerable Image | EWS |
| critical | AGENT | `F-AGENT-fa8f407984` Exposed PLC Web Interface with Vulnerable Image | plc |
| critical | AGENT | `F-AGENT-82e573114c` ICS Network Bridging to DMZ | grficsv3_c-dmz-net |
| high | AGENT | `F-AGENT-29e096932b` Attacker Tools in DMZ Network | grficsv3_c-dmz-net |


## 6. How matching works

- The agent never saw the deterministic findings; they are used here as the answer key.
- An agent finding covers a deterministic finding when it names the same resource (for image findings, also a container running that image) and cites the same Docker field as the rule's evidence (prefix match, list indexes ignored, equivalent fields accepted).
- Image vulnerabilities (V001) are scored per image: covered when the agent reported at least one vulnerability ID that Trivy found in that image.
- Where two rules use the same field, the agent's wording decides (e.g. 'docker.sock' -> socket mount C008, otherwise sensitive bind mount C009).
- Only validated agent findings can cover a deterministic finding; rejected ones never do.
- Weighted recall weights findings by severity: critical 4, high 3, medium 2, low 1, info 0.
