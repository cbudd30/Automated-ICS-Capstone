# Docker Security Assessment — `run-20261009-030302-f940`

**Status:** completed · **Overall risk:** CRITICAL (determined by agent) · **Generated:** 2026-10-09 03:09 UTC

**Model:** `local-qwen` (ollama / `qwen3:14b-ctx32k`) · **Prompt:** v3 · **Snapshot:** `snap-33c9249587920935`

## 1. Assessment summary

The Docker environment hosting the ICS lab has critical vulnerabilities in multiple images used by exposed services, including the Docker socket mounted in a container. High-severity issues in images like 'ics_range-hmi:latest' and 'ics_range-wazuh-manager:latest' pose immediate risks to availability and integrity. The 'shuffle-backend' container's access to the Docker socket is a critical misconfiguration requiring urgent remediation.

**Objective:** Assess the security posture of the Docker environment hosting a containerized industrial control system (ICS) lab. Identify container misconfigurations, risky network exposure, missing resource limits, and known image vulnerabilities. Prioritise risks by their impact on an OT environment and give concrete, evidence-based remediation for defenders.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 17 | 2 | 30 | 104 | 9 |


## 2. Docker environment overview

- Docker engine: 29.7.2 (Docker Desktop 4.88.1 (237512))
- Snapshot captured: 2026-10-09 03:03:03 UTC
- Containers: 20 (13 running) · Images: 38 · Networks: 8 · Volumes: 18
- Images with known vulnerabilities: 19 · Total vulnerabilities: CRITICAL 118, HIGH 2473, MEDIUM 7060, LOW 3014, UNKNOWN 108


## 3. Container inventory

| Container | Image | State | User | Privileged | Networks | Published ports | Findings |
|---|---|---|---|---|---|---|---|
| admin-ui | ics_range-admin-ui | exited | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:8080->80/tcp | 6 |
| attacker | ics_range-attacker | exited | (default: root) | no | ics_range_ics_net | - | 7 |
| bloodhound-app-db-1 | docker.io/library/postgres:18 | exited | (default: root) | no | bloodhound_default | - | 7 |
| bloodhound-bloodhound-1 | docker.io/specterops/bloodhound:latest | exited | 0 | no | bloodhound_default | 127.0.0.1:8080->8080/tcp | 6 |
| bloodhound-graph-db-1 | docker.io/library/neo4j:4.4 | exited | (default: root) | no | bloodhound_default | 127.0.0.1:7474->7474/tcp, 127.0.0.1:7687->7687/tcp | 6 |
| controller | ics_range-controller | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:9000->9000/tcp | 7 |
| docker-audit-socket-proxy | tecnativa/docker-socket-proxy:v0.5.0 | running | root | no | docker-audit-proxy_default | 127.0.0.1:2375->2375/tcp | 0 |
| elasticsearch | ics_range-elasticsearch | running | 1000:0 | no | ics_range_mgmt_net | 0.0.0.0:9200->9200/tcp | 6 |
| engineer-workstation | ics_range-engineer-workstation | running | (default: root) | no | ics_range_ics_net | - | 5 |
| filebeat | ics_range-filebeat | running | root | no | ics_range_mgmt_net, ics_range_mon_net | - | 7 |
| hmi | ics_range-hmi | running | (default: root) | no | ics_range_ics_net | 0.0.0.0:1881->1881/tcp | 6 |
| kibana | ics_range-kibana | running | 1000 | no | ics_range_mgmt_net | 0.0.0.0:5601->5601/tcp | 6 |
| plc | ics_range-plc | exited | (default: root) | no | ics_range_ics_net | 0.0.0.0:8081->8080/tcp | 6 |
| process-simulator | ics_range-process-simulator | running | (default: root) | no | ics_range_ics_net | - | 5 |
| rsyslog | ics_range-rsyslog | running | (default: root) | no | ics_range_ics_net, ics_range_mon_net | 0.0.0.0:514->514/udp | 7 |
| shuffle-backend | ics_range-shuffle-backend | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:5001->5001/tcp | 8 |
| shuffle-database | ics_range-shuffle-database | running | 1000 | no | ics_range_mgmt_net | 0.0.0.0:9201->9200/tcp | 6 |
| shuffle-frontend | ics_range-shuffle-frontend | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:3444->443/tcp, 0.0.0.0:3443->80/tcp | 6 |
| wazuh-manager | ics_range-wazuh-manager | running | (default: root) | no | ics_range_mgmt_net, ics_range_mon_net | 0.0.0.0:1514->1514/tcp, 0.0.0.0:1515->1515/tcp, 0.0.0.0:55000->55000/tcp | 8 |
| zeek | ics_range-zeek | exited | (default: root) | no |  | - | 6 |


## 4. Image inventory

| Image | ID | Digest | Size (MB) | Used by | Scan | Vulnerabilities |
|---|---|---|---|---|---|---|
| ics_range-shuffle-backend:latest | 024f628d085d | ics_range-shuffle-backend@sha256:024f628 | 50.2 | shuffle-backend | ok | C:2, H:56, M:50, L:55, U:3 |
| ics_range-rsyslog:latest | 0302a5b18fce | ics_range-rsyslog@sha256:0302a5b18fce184 | 28.9 | rsyslog | ok | C:4, H:59, M:104, L:80, U:6 |
| tecnativa/docker-socket-proxy:v0.5.0 | 1f5038b54f06 | tecnativa/docker-socket-proxy@sha256:1f5 | 20.6 | docker-audit-socket-proxy | ok | H:6, M:10, L:13 |
| specterops/bloodhound:latest | 24dba2ba69f7 | specterops/bloodhound@sha256:24dba2ba69f | 64.0 | bloodhound-bloodhound-1 | ok | M:2, U:2 |
| ics_range-filebeat:latest | 337151eeb27c | ics_range-filebeat@sha256:337151eeb27c9e | 121.1 | filebeat | ok | H:11, M:4, L:4, U:2 |
| ics_range-elasticsearch:latest | 40f5b4211ca4 | ics_range-elasticsearch@sha256:40f5b4211 | 758.8 | elasticsearch | ok | C:1, H:53, M:170, L:85 |
| postgres:18 | 4ef4dbc939d6 | postgres@sha256:4ef4dbc939d61acea5771265 | 161.1 | bloodhound-app-db-1 | ok | C:14, H:114, M:199, L:159, U:9 |
| ics_range-admin-ui:latest | 4f94459af729 | ics_range-admin-ui@sha256:4f94459af729b3 | 21.8 | admin-ui | ok | C:2, H:43, M:74, L:42 |
| ics_range-kibana:latest | 5c91c8a5d96d | ics_range-kibana@sha256:5c91c8a5d96dd63e | 591.6 | kibana | ok | C:4, H:74, M:278, L:121 |
| neo4j:4.4 | 69187cd5fded | neo4j@sha256:69187cd5fdedbef00e9280c5c94 | 328.2 | bloodhound-graph-db-1 | ok | C:7, H:199, M:2030, L:417, U:7 |
| ics_range-zeek:latest | 6cc2573de09d | ics_range-zeek@sha256:6cc2573de09d567198 | 161.7 | zeek | ok | C:24, H:275, M:487, L:254, U:8 |
| ics_range-wazuh-manager:latest | 80318ef9d90c | ics_range-wazuh-manager@sha256:80318ef9d | 613.7 | wazuh-manager | ok | C:9, H:391, M:290, L:30, U:3 |
| ics_range-controller:latest | 84f96e8b30a1 | ics_range-controller@sha256:84f96e8b30a1 | 52.9 | controller | ok | C:3, H:63, M:109, L:70, U:3 |
| ics_range-engineer-workstation:latest | 8f2c81d5c916 | ics_range-engineer-workstation@sha256:8f | 70.4 | engineer-workstation | ok | C:3, H:139, M:180, L:132, U:3 |
| ics_range-hmi:latest | a36495afdbd3 | ics_range-hmi@sha256:a36495afdbd36c8900e | 208.4 | hmi | ok | C:15, H:157, M:239, L:146, U:4 |
| ics_range-plc:latest | a7232d788f58 | ics_range-plc@sha256:a7232d788f587afb33e | 382.5 | plc | ok | C:15, H:287, M:2212, L:1085, U:10 |
| ics_range-shuffle-database:latest | c56c86838e5d | ics_range-shuffle-database@sha256:c56c86 | 755.0 | shuffle-database | ok | C:3, H:291, M:194, L:14 |
| ics_range-shuffle-frontend:latest | f6647d037418 | ics_range-shuffle-frontend@sha256:f6647d | 77.8 | shuffle-frontend | ok | C:9, H:194, M:323, L:238, U:45 |
| ics_range-attacker:latest | fde9f564fa08 | ics_range-attacker@sha256:fde9f564fa0884 | 94.2 | attacker | ok | - |
| ics_range-process-simulator:latest | fe1a3d545268 | ics_range-process-simulator@sha256:fe1a3 | 50.6 | process-simulator | ok | C:3, H:61, M:105, L:69, U:3 |


## 5. Network configuration

| Network | Driver | Internal | Subnets | Containers |
|---|---|---|---|---|
| bloodhound_default | bridge | no | 172.18.0.0/16 | bloodhound-app-db-1, bloodhound-bloodhound-1, bloodhound-graph-db-1 |
| bridge | bridge | no | 172.17.0.0/16 | - |
| docker-audit-proxy_default | bridge | no | 172.19.0.0/16 | docker-audit-socket-proxy |
| host | host | no | - | - |
| ics_range_ics_net | bridge | no | 172.30.0.0/24 | attacker, engineer-workstation, hmi, plc, process-simulator, rsyslog |
| ics_range_mgmt_net | bridge | no | 172.20.0.0/24 | admin-ui, controller, elasticsearch, filebeat, kibana, shuffle-backend, shuffle-database, shuffle-frontend, wazuh-manager |
| ics_range_mon_net | bridge | no | 172.40.0.0/24 | filebeat, rsyslog, wazuh-manager |
| none | null | no | - | - |


## 6. Prioritized findings

| # | Severity | Finding | Resource | Rationale | Ranked by |
|---|---|---|---|---|---|
| 1 | critical | `F-C008-aa76ffcc14` Docker socket is mounted into the container | shuffle-backend | The Docker socket mount in 'shuffle-backend' allows container escape, which could compromise the entire host and ICS processes. This is a top priority in OT environments where integrity of control systems is critical. | agent |
| 2 | critical | `F-V001-94b6486bc4` Image has known vulnerabilities (15 CRITICAL, 157 HIGH, 239 MEDIUM, 146 LOW, 4 UNKNOWN) | ics_range-hmi:latest | The 'ics_range-hmi:latest' image has 15 critical vulnerabilities, which could be exploited through the HMI interface to disrupt or manipulate industrial processes. | agent |
| 3 | critical | `F-V001-dd7a72a84a` Image has known vulnerabilities (9 CRITICAL, 391 HIGH, 290 MEDIUM, 30 LOW, 3 UNKNOWN) | ics_range-wazuh-manager:latest | The 'ics_range-wazuh-manager:latest' image has 9 critical vulnerabilities, risking the integrity of the security monitoring system itself and potentially allowing attackers to bypass detection. | agent |
| 4 | critical | `F-V001-5ca0a0bb7f` Image has known vulnerabilities (3 CRITICAL, 291 HIGH, 194 MEDIUM, 14 LOW) | ics_range-shuffle-database:latest | The 'ics_range-shuffle-database:latest' image has 3 critical vulnerabilities, which could be exploited to compromise data integrity in the shuffle backend service. | agent |
| 5 | critical | `F-V001-27f4668167` Image has known vulnerabilities (9 CRITICAL, 194 HIGH, 323 MEDIUM, 238 LOW, 45 UNKNOWN) | ics_range-shuffle-frontend:latest | The 'ics_range-shuffle-frontend:latest' image has 9 critical vulnerabilities, posing a risk to the frontend service that may interact directly with operators or external systems. | agent |


## 7. Security misconfigurations (143)

Confirmed by deterministic rules. Each finding lists the exact Docker field that supports it.

#### 🔴 `F-C008-aa76ffcc14` — Docker socket is mounted into the container

- **Resource:** container `shuffle-backend`
- **Category:** filesystem · **Severity:** critical · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/var/run/docker.sock -> /var/run/docker.sock (rw)` — even a read-only mount of the socket allows full API use

**Why it matters:** The Docker API socket grants full control of the Docker daemon: anyone who controls this container can start a privileged container that mounts the host filesystem, i.e. root on the host and control of every ICS component. Mounting it ':ro' does NOT help - it only makes the socket file read-only, not the API.

**Remediation:** Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.

#### 🟡 `F-C003-3032d28750` — Container runs as root (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-18d934064b` — Container adds dangerous capabilities: NET_ADMIN, NET_RAW (container is currently exited)

- **Resource:** container `attacker`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules
  - `HostConfig.CapAdd` = `NET_RAW` — can craft raw packets (spoofing, ARP poisoning on the ICS segment)

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-1d9919974b` — Container runs as root (container is currently exited)

- **Resource:** container `attacker`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-3406b77fe2` — Container runs as root (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-971948e431` — Container runs as root (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `0` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-282affb892` — Container runs as root (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-6dd8825555` — Container runs as root

- **Resource:** container `controller`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-6edba355a8` — Container runs as root

- **Resource:** container `engineer-workstation`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-1d060cdccc` — Container runs as root

- **Resource:** container `filebeat`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `root` — Config.User

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-6230e3194c` — Container runs as root

- **Resource:** container `hmi`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-0b8bcbf820` — Container runs as root (container is currently exited)

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-01c0ec354f` — Container runs as root

- **Resource:** container `process-simulator`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-e954a1ca37` — Container runs as root

- **Resource:** container `rsyslog`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-088d38c92b` — Container runs as root

- **Resource:** container `shuffle-backend`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-bfb8ab387d` — Container runs as root

- **Resource:** container `shuffle-frontend`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C003-47292c8130` — Container runs as root

- **Resource:** container `wazuh-manager`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-C002-45568bf496` — Container adds dangerous capabilities: NET_ADMIN, NET_RAW (container is currently exited)

- **Resource:** container `zeek`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapAdd` = `NET_ADMIN` — can reconfigure interfaces, routes and firewall rules
  - `HostConfig.CapAdd` = `NET_RAW` — can craft raw packets (spoofing, ARP poisoning on the ICS segment)

**Why it matters:** Added capabilities widen what a compromised process can do to the host kernel and network. In an OT lab, NET_ADMIN/NET_RAW on hosts attached to the process network allow traffic manipulation between PLCs and HMIs.

**Remediation:** Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.

#### 🟡 `F-C003-692b9b29e4` — Container runs as root (container is currently exited)

- **Resource:** container `zeek`
- **Category:** privilege · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.User` = `<empty>` — not set (defaults to root)

**Why it matters:** The main process runs as UID 0. Combined with any added capability, writable mount or kernel bug, root inside the container makes escape and host compromise significantly easier.

**Remediation:** Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.

#### 🟡 `F-S001-06251a5d02` — Credential-like environment variables: POSTGRES_PASSWORD (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `POSTGRES_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-S001-c70ad7ead2` — Credential-like environment variables: ELASTIC_PASSWORD, WAZUH_API_PASSWORD

- **Resource:** container `controller`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `ELASTIC_PASSWORD=<redacted>` — value not collected
  - `Config.Env` = `WAZUH_API_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-S001-4874ed41f7` — Credential-like environment variables: ELASTIC_PASSWORD

- **Resource:** container `elasticsearch`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `ELASTIC_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-3939cc295e` — Container bridges multiple networks

- **Resource:** container `filebeat`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.ics_range_mgmt_net` = `172.20.0.6`
  - `NetworkSettings.Networks.ics_range_mon_net` = `172.40.0.3`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-d5ae86b363` — Credential-like environment variables: ELASTIC_PASSWORD

- **Resource:** container `filebeat`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `ELASTIC_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-S001-8c018ac59f` — Credential-like environment variables: ELASTICSEARCH_PASSWORD

- **Resource:** container `kibana`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `ELASTICSEARCH_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-13d8aa9de4` — Container bridges multiple networks

- **Resource:** container `rsyslog`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.ics_range_ics_net` = `172.30.0.2`
  - `NetworkSettings.Networks.ics_range_mon_net` = `172.40.0.2`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-a09ef50c69` — Credential-like environment variables: SHUFFLE_OPENSEARCH_PASSWORD

- **Resource:** container `shuffle-backend`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `SHUFFLE_OPENSEARCH_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-S001-4cce5125b4` — Credential-like environment variables: OPENSEARCH_INITIAL_ADMIN_PASSWORD

- **Resource:** container `shuffle-database`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `OPENSEARCH_INITIAL_ADMIN_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🟡 `F-N002-5cf0c5b4bc` — Container bridges multiple networks

- **Resource:** container `wazuh-manager`
- **Category:** network-segmentation · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `NetworkSettings.Networks.ics_range_mgmt_net` = `172.20.0.9`
  - `NetworkSettings.Networks.ics_range_mon_net` = `172.40.0.4`

**Why it matters:** A container attached to several networks is a potential bridge between segmentation zones (e.g. DMZ <-> process network). If it is compromised, an attacker can pivot across zones that the network design intends to keep apart. Whether this is intended (a router/firewall) needs human review.

**Remediation:** Attach the container only to the networks it must serve. Route inter-zone traffic through a dedicated, hardened firewall container and keep management networks separate from ICS process networks.

#### 🟡 `F-S001-fea6cd8b32` — Credential-like environment variables: WAZUH_API_PASSWORD

- **Resource:** container `wazuh-manager`
- **Category:** secrets-hygiene · **Severity:** medium · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `Config.Env` = `WAZUH_API_PASSWORD=<redacted>` — value not collected

**Why it matters:** Secrets passed as environment variables are visible to anyone who can inspect the container (docker inspect, /proc/<pid>/environ) and often leak into logs and crash dumps. Values were redacted and not analysed; the name alone indicates a likely credential.

**Remediation:** Use Docker secrets / mounted secret files with restricted permissions, and rotate any credential that was exposed via the environment.

#### 🔵 `F-C006-cbf006365a` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-ad633d8b03` — Root filesystem is writable (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-e98ab6881b` — Ports published on all host interfaces (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8080 -> 80/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-e8a692f5ee` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-42f4287651` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `attacker`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-3d5a8c0207` — Root filesystem is writable (container is currently exited)

- **Resource:** container `attacker`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-b1a716fb7a` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `attacker`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-211134a118` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-e41b539f45` — Root filesystem is writable (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-1f572fd814` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-02a2ea7f0e` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-e4bbd37805` — Root filesystem is writable (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-85d80570dd` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-33d0e35384` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-47c5b86457` — Root filesystem is writable (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-34f7cac205` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-6ad3cdf472` — no-new-privileges is not set

- **Resource:** container `controller`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-90472efe5f` — Root filesystem is writable

- **Resource:** container `controller`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-a268566db2` — Ports published on all host interfaces

- **Resource:** container `controller`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:9000 -> 9000/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-68e73b4e9a` — Missing resource limits: memory, cpu, pids

- **Resource:** container `controller`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-dee77ed32e` — no-new-privileges is not set

- **Resource:** container `elasticsearch`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-c240413502` — Root filesystem is writable

- **Resource:** container `elasticsearch`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-926513e270` — Ports published on all host interfaces

- **Resource:** container `elasticsearch`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:9200 -> 9200/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-a7970ff518` — Missing resource limits: memory, cpu, pids

- **Resource:** container `elasticsearch`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-6f141153b5` — no-new-privileges is not set

- **Resource:** container `engineer-workstation`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-d3dc473110` — Root filesystem is writable

- **Resource:** container `engineer-workstation`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-7a17b2de16` — Missing resource limits: memory, cpu, pids

- **Resource:** container `engineer-workstation`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-40c8f5ba4e` — no-new-privileges is not set

- **Resource:** container `filebeat`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-3431a074d8` — Root filesystem is writable

- **Resource:** container `filebeat`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-2c51818f77` — Missing resource limits: memory, cpu, pids

- **Resource:** container `filebeat`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-21aac74daf` — no-new-privileges is not set

- **Resource:** container `hmi`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-553e42ff9e` — Root filesystem is writable

- **Resource:** container `hmi`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-4b1f5d74d1` — Ports published on all host interfaces

- **Resource:** container `hmi`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:1881 -> 1881/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-c5720f5325` — Missing resource limits: memory, cpu, pids

- **Resource:** container `hmi`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-I001-63c217254f` — Image uses a floating tag: ics_range-admin-ui:latest

- **Resource:** image `ics_range-admin-ui:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-admin-ui:latest`
  - `used_by` = `admin-ui`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-61b9f54db0` — Image uses a floating tag: ics_range-attacker:latest

- **Resource:** image `ics_range-attacker:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-attacker:latest`
  - `used_by` = `attacker`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-f7e52d2a3d` — Image uses a floating tag: ics_range-controller:latest

- **Resource:** image `ics_range-controller:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-controller:latest`
  - `used_by` = `controller`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-073dc7781c` — Image uses a floating tag: ics_range-elasticsearch:latest

- **Resource:** image `ics_range-elasticsearch:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-elasticsearch:latest`
  - `used_by` = `elasticsearch`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-a643eb0cdb` — Image uses a floating tag: ics_range-engineer-workstation:latest

- **Resource:** image `ics_range-engineer-workstation:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-engineer-workstation:latest`
  - `used_by` = `engineer-workstation`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-9f910fe827` — Image uses a floating tag: ics_range-filebeat:latest

- **Resource:** image `ics_range-filebeat:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-filebeat:latest`
  - `used_by` = `filebeat`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-10c70dcfd7` — Image uses a floating tag: ics_range-hmi:latest

- **Resource:** image `ics_range-hmi:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-hmi:latest`
  - `used_by` = `hmi`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-16f02ee0cb` — Image uses a floating tag: ics_range-kibana:latest

- **Resource:** image `ics_range-kibana:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-kibana:latest`
  - `used_by` = `kibana`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-ed6d388827` — Image uses a floating tag: ics_range-plc:latest

- **Resource:** image `ics_range-plc:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-plc:latest`
  - `used_by` = `plc`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-bd67ef3f83` — Image uses a floating tag: ics_range-process-simulator:latest

- **Resource:** image `ics_range-process-simulator:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-process-simulator:latest`
  - `used_by` = `process-simulator`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-c829fbf6c2` — Image uses a floating tag: ics_range-rsyslog:latest

- **Resource:** image `ics_range-rsyslog:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-rsyslog:latest`
  - `used_by` = `rsyslog`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-f2af552afd` — Image uses a floating tag: ics_range-shuffle-backend:latest

- **Resource:** image `ics_range-shuffle-backend:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-shuffle-backend:latest`
  - `used_by` = `shuffle-backend`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-2fffe3f9e0` — Image uses a floating tag: ics_range-shuffle-database:latest

- **Resource:** image `ics_range-shuffle-database:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-shuffle-database:latest`
  - `used_by` = `shuffle-database`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-a59661891d` — Image uses a floating tag: ics_range-shuffle-frontend:latest

- **Resource:** image `ics_range-shuffle-frontend:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-shuffle-frontend:latest`
  - `used_by` = `shuffle-frontend`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-2a86c94003` — Image uses a floating tag: ics_range-wazuh-manager:latest

- **Resource:** image `ics_range-wazuh-manager:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-wazuh-manager:latest`
  - `used_by` = `wazuh-manager`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-I001-7a8ab8f364` — Image uses a floating tag: ics_range-zeek:latest

- **Resource:** image `ics_range-zeek:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `ics_range-zeek:latest`
  - `used_by` = `zeek`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-C006-5def7f35f2` — no-new-privileges is not set

- **Resource:** container `kibana`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-ec31c4421d` — Root filesystem is writable

- **Resource:** container `kibana`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-dc6fe31980` — Ports published on all host interfaces

- **Resource:** container `kibana`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:5601 -> 5601/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-80c2d379c3` — Missing resource limits: memory, cpu, pids

- **Resource:** container `kibana`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-62a3ca97e0` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `plc`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-f8bc497e87` — Root filesystem is writable (container is currently exited)

- **Resource:** container `plc`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-ff0999154d` — Ports published on all host interfaces (container is currently exited)

- **Resource:** container `plc`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:8081 -> 8080/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-53351ac22d` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `plc`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-753bbba0a4` — no-new-privileges is not set

- **Resource:** container `process-simulator`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-f800a52d56` — Root filesystem is writable

- **Resource:** container `process-simulator`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-8b95f0dd66` — Missing resource limits: memory, cpu, pids

- **Resource:** container `process-simulator`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-acd2de219f` — no-new-privileges is not set

- **Resource:** container `rsyslog`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-69f3f1a50c` — Root filesystem is writable

- **Resource:** container `rsyslog`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-cba812cb32` — Ports published on all host interfaces

- **Resource:** container `rsyslog`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:514 -> 514/udp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-f753a3dd05` — Missing resource limits: memory, cpu, pids

- **Resource:** container `rsyslog`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-9f2c0b0706` — no-new-privileges is not set

- **Resource:** container `shuffle-backend`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-95148a7eca` — Root filesystem is writable

- **Resource:** container `shuffle-backend`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-9190b72f61` — Ports published on all host interfaces

- **Resource:** container `shuffle-backend`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:5001 -> 5001/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-ee755f3d8a` — Missing resource limits: memory, cpu, pids

- **Resource:** container `shuffle-backend`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-ea69c0dd9a` — no-new-privileges is not set

- **Resource:** container `shuffle-database`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-f26f117f90` — Root filesystem is writable

- **Resource:** container `shuffle-database`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-4890ed6c9d` — Ports published on all host interfaces

- **Resource:** container `shuffle-database`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:9201 -> 9200/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-81e3b9874d` — Missing resource limits: memory, cpu, pids

- **Resource:** container `shuffle-database`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-eb26f99693` — no-new-privileges is not set

- **Resource:** container `shuffle-frontend`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-ba72356ae1` — Root filesystem is writable

- **Resource:** container `shuffle-frontend`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-166b1e3225` — Ports published on all host interfaces

- **Resource:** container `shuffle-frontend`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:3444 -> 443/tcp`
  - `HostConfig.PortBindings` = `0.0.0.0:3443 -> 80/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-8094a63812` — Missing resource limits: memory, cpu, pids

- **Resource:** container `shuffle-frontend`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-I001-fcd63f7b43` — Image uses a floating tag: specterops/bloodhound:latest

- **Resource:** image `specterops/bloodhound:latest`
- **Category:** image-hygiene · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `RepoTags` = `specterops/bloodhound:latest`
  - `used_by` = `bloodhound-bloodhound-1`

**Why it matters:** `latest`/untagged images change silently when rebuilt or re-pulled, so the deployed software (and its vulnerabilities) is not reproducible or auditable.

**Remediation:** Pin images to an explicit version tag and, ideally, an immutable digest (`image: repo/name:1.2.3@sha256:...`).

#### 🔵 `F-C006-4b40023d51` — no-new-privileges is not set

- **Resource:** container `wazuh-manager`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-267d3e3312` — Root filesystem is writable

- **Resource:** container `wazuh-manager`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-N001-efb996dd35` — Ports published on all host interfaces

- **Resource:** container `wazuh-manager`
- **Category:** network-exposure · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.PortBindings` = `0.0.0.0:1514 -> 1514/tcp`
  - `HostConfig.PortBindings` = `0.0.0.0:1515 -> 1515/tcp`
  - `HostConfig.PortBindings` = `0.0.0.0:55000 -> 55000/tcp`

**Why it matters:** These ports are reachable from every network the Docker host is attached to. This is an EXPOSURE observation, not a vulnerability by itself: risk depends on the service behind the port (see image vulnerabilities and authentication). ICS management interfaces (HMI, PLC web UI, engineering tools) should not be reachable from untrusted networks.

**Remediation:** Bind to loopback or a management interface (`127.0.0.1:8080:8080`) or remove the port mapping and reach the service via an internal network / jump host.

#### 🔵 `F-R001-9d4e58df47` — Missing resource limits: memory, cpu, pids

- **Resource:** container `wazuh-manager`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C006-3893201423` — no-new-privileges is not set (container is currently exited)

- **Resource:** container `zeek`
- **Category:** security-profile · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.SecurityOpt` = `[]`

**Why it matters:** Without no-new-privileges, setuid/setgid binaries inside the container can raise a process's privileges.

**Remediation:** Add `security_opt: ["no-new-privileges:true"]`.

#### 🔵 `F-C007-22216d381e` — Root filesystem is writable (container is currently exited)

- **Resource:** container `zeek`
- **Category:** filesystem · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.ReadonlyRootfs` = `False`

**Why it matters:** A writable root filesystem lets an attacker persist tools or modify binaries/configuration (e.g. PLC logic or HMI screens) inside the container.

**Remediation:** Set `read_only: true` and mount `tmpfs` / named volumes only for the paths that must be writable.

#### 🔵 `F-R001-010e916dc5` — Missing resource limits: memory, cpu, pids (container is currently exited)

- **Resource:** container `zeek`
- **Category:** resources · **Severity:** low · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.Memory` = `0` — 0 = unlimited
  - `HostConfig.NanoCpus` = `0` — 0 = unlimited
  - `HostConfig.PidsLimit` = `None` — null/0/-1 = unlimited

**Why it matters:** Without limits, one runaway or compromised container can exhaust host memory/CPU/PIDs and starve every other ICS component (availability is the top priority in OT environments).

**Remediation:** Set `mem_limit`, `cpus` and `pids_limit` (compose) or `deploy.resources.limits` appropriate to each service.

#### 🔵 `F-C010-5a7849391d` — No capabilities are dropped (container is currently exited)

- **Resource:** container `admin-ui`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-618c649db8` — No capabilities are dropped (container is currently exited)

- **Resource:** container `attacker`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-5f73c0fc09` — No capabilities are dropped (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-2408bd1d2d` — No capabilities are dropped (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-fe8af0bf13` — No capabilities are dropped (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-8c66d7578b` — No capabilities are dropped

- **Resource:** container `controller`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-86b4c6bfba` — No capabilities are dropped

- **Resource:** container `elasticsearch`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-3dd636ac61` — No capabilities are dropped

- **Resource:** container `engineer-workstation`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-cbbeb9bfa7` — No capabilities are dropped

- **Resource:** container `filebeat`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-e61a060f09` — No capabilities are dropped

- **Resource:** container `hmi`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-0fe1e10b98` — No capabilities are dropped

- **Resource:** container `kibana`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-ce7bfca57a` — No capabilities are dropped (container is currently exited)

- **Resource:** container `plc`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-c343bb42c1` — No capabilities are dropped

- **Resource:** container `process-simulator`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-7780684778` — No capabilities are dropped

- **Resource:** container `rsyslog`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-503e7457f6` — No capabilities are dropped

- **Resource:** container `shuffle-backend`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-b0c72853e2` — No capabilities are dropped

- **Resource:** container `shuffle-database`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-448808f682` — No capabilities are dropped

- **Resource:** container `shuffle-frontend`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-b19b1c8d40` — No capabilities are dropped

- **Resource:** container `wazuh-manager`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### 🔵 `F-C010-e5866d6f1b` — No capabilities are dropped (container is currently exited)

- **Resource:** container `zeek`
- **Category:** privilege · **Severity:** low · **Confidence:** medium · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.CapDrop` = `null`

**Why it matters:** The container keeps Docker's full default capability set (incl. NET_RAW, CHOWN, SETUID...). Most services need none of these.

**Remediation:** Add `cap_drop: [ALL]` and re-add only required capabilities.

#### ⚪ `F-R002-384c1d4c7d` — No restart policy (container is currently exited)

- **Resource:** container `attacker`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-2989e831ef` — No restart policy (container is currently exited)

- **Resource:** container `bloodhound-app-db-1`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-5dfbdaa4fc` — No restart policy (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-R002-f693d3fab3` — No restart policy (container is currently exited)

- **Resource:** container `bloodhound-graph-db-1`
- **Category:** resources · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `HostConfig.RestartPolicy.Name` = `no`

**Why it matters:** The container will not be restarted automatically after a crash or host reboot, which may affect availability of the simulated process.

**Remediation:** Use `restart: unless-stopped` for services that must stay available.

#### ⚪ `F-N005-b4b1281129` — Network 'bloodhound_default' is not internal (has external egress)

- **Resource:** network `bloodhound_default`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `bloodhound-app-db-1, bloodhound-bloodhound-1, bloodhound-graph-db-1`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-bb9759638d` — Network 'docker-audit-proxy_default' is not internal (has external egress)

- **Resource:** network `docker-audit-proxy_default`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `docker-audit-socket-proxy`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-34b521faf5` — Network 'ics_range_ics_net' is not internal (has external egress)

- **Resource:** network `ics_range_ics_net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `attacker, engineer-workstation, hmi, plc, process-simulator, rsyslog`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-72f67946cf` — Network 'ics_range_mgmt_net' is not internal (has external egress)

- **Resource:** network `ics_range_mgmt_net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `admin-ui, controller, elasticsearch, filebeat, kibana, shuffle-backend, shuffle-database, shuffle-frontend, wazuh-manager`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.

#### ⚪ `F-N005-4a750ccc73` — Network 'ics_range_mon_net' is not internal (has external egress)

- **Resource:** network `ics_range_mon_net`
- **Category:** network-segmentation · **Severity:** info · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Internal` = `False`
  - `Driver` = `bridge`
  - `Containers` = `filebeat, rsyslog, wazuh-manager`

**Why it matters:** Containers on this network can open outbound connections through the host. ICS process networks normally should not reach the internet.

**Remediation:** For process/control networks set `internal: true` and provide any required external access through an explicit, monitored gateway.


## 8. Known image vulnerabilities

Reported by Trivy; CVE IDs, severities and versions are copied verbatim from the scanner.

### ics_range-shuffle-backend:latest

Digest: `ics_range-shuffle-backend@sha256:024f628d085d77cbb08f9416ef2aa9808b350acd483e898fae0d281cd57d6831` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 2, HIGH 56, MEDIUM 50, LOW 55, UNKNOWN 3

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-31789 | CRITICAL | libcrypto3 | 3.5.4-r0 | 3.5.6-r0 |
| CVE-2026-31789 | CRITICAL | libssl3 | 3.5.4-r0 | 3.5.6-r0 |
| CVE-2025-15467 | HIGH | libssl3 | 3.5.4-r0 | 3.5.5-r0 |
| CVE-2025-15467 | HIGH | libcrypto3 | 3.5.4-r0 | 3.5.5-r0 |
| CVE-2025-69421 | HIGH | libssl3 | 3.5.4-r0 | 3.5.5-r0 |
| CVE-2025-69421 | HIGH | libcrypto3 | 3.5.4-r0 | 3.5.5-r0 |
| CVE-2026-14456 | HIGH | libssl3 | 3.5.4-r0 | 3.5.8-r0 |
| CVE-2026-14456 | HIGH | libcrypto3 | 3.5.4-r0 | 3.5.8-r0 |
| CVE-2026-17106 | HIGH | github.com/moby/go-archive | v0.1.0 | 0.3.0 |
| CVE-2026-22184 | HIGH | zlib | 1.3.1-r2 | 1.3.2-r0 |

### ics_range-rsyslog:latest

Digest: `ics_range-rsyslog@sha256:0302a5b18fce184ad967e0036f403af1c559bfa93fb9be03902829e90957976b` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 4, HIGH 59, MEDIUM 104, LOW 80, UNKNOWN 6

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2023-45853 | CRITICAL | zlib1g | 1:1.2.13.dfsg-1 | - |
| CVE-2026-103111 | HIGH | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u2 |
| CVE-2026-42497 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-48962 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-57432 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-57433 | HIGH | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 |
| CVE-2026-86145 | HIGH | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u1 |

### tecnativa/docker-socket-proxy:v0.5.0

Digest: `tecnativa/docker-socket-proxy@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459` · Scanner: Trivy v0.68.2 · Counts: HIGH 6, MEDIUM 10, LOW 13

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-103111 | HIGH | pcre2 | 10.47-r1 | 10.49-r0 |
| CVE-2026-14456 | HIGH | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 |
| CVE-2026-14456 | HIGH | libssl3 | 3.5.7-r0 | 3.5.8-r0 |
| CVE-2026-86145 | HIGH | pcre2 | 10.47-r1 | 10.48-r0 |
| CVE-2026-89157 | HIGH | pcre2 | 10.47-r1 | 10.48-r0 |
| CVE-2026-89161 | HIGH | pcre2 | 10.47-r1 | 10.48-r0 |
| CVE-2026-18798 | MEDIUM | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 |
| CVE-2026-18798 | MEDIUM | libssl3 | 3.5.7-r0 | 3.5.8-r0 |
| CVE-2026-63072 | MEDIUM | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 |
| CVE-2026-63072 | MEDIUM | libssl3 | 3.5.7-r0 | 3.5.8-r0 |

### specterops/bloodhound:latest

Digest: `specterops/bloodhound@sha256:24dba2ba69f7fcc06c407f6503df2879487df492f8b62b33ec8ef2a6a97e4b4d` · Scanner: Trivy v0.68.2 · Counts: MEDIUM 2, UNKNOWN 2

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-56855 | MEDIUM | golang.org/x/crypto | v0.55.0 | 0.56.0 |
| CVE-2026-78662 | MEDIUM | golang.org/x/crypto | v0.55.0 | 0.56.0 |
| DLA-4792-1 | UNKNOWN | tzdata | 2026b-0+deb12u1 | 2026c-0+deb12u1 |
| GO-2026-5932 | UNKNOWN | golang.org/x/crypto | v0.55.0 | - |

### ics_range-filebeat:latest

Digest: `ics_range-filebeat@sha256:337151eeb27c9eebd04737a285e8fb005aaa3ab7d8739af42933d30a98d1b50d` · Scanner: Trivy v0.68.2 · Counts: HIGH 11, MEDIUM 4, LOW 4, UNKNOWN 2

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-33818 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-39821 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-46600 | HIGH | stdlib | v1.26.5 | 1.26.6, 1.27.0-rc.3 |
| CVE-2026-56853 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-56854 | HIGH | golang.org/x/crypto | v0.54.0 | 0.55.0 |
| CVE-2026-56858 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-56859 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-56860 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-56862 | HIGH | stdlib | v1.26.5 | 1.25.13, 1.26.6, 1.27.0-rc.3 |
| CVE-2026-84304 | HIGH | google.golang.org/grpc | v1.82.1 | 1.83.1 |

### ics_range-elasticsearch:latest

Digest: `ics_range-elasticsearch@sha256:40f5b4211ca48258cd14fc8c56f64b1e843d206b3b31e9f572eb1ebb5423c736` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 1, HIGH 53, MEDIUM 170, LOW 85

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-75595 | CRITICAL | io.netty:netty-handler | 4.1.135.Final | 4.2.17.Final, 4.1.137.Final |
| CVE-2026-0799 | HIGH | libpcap | 14:1.10.0-4.el9 | 14:1.10.0-4.el9_8.1 |
| CVE-2026-106451 | HIGH | at.yawk.lz4:lz4-java | 1.11.1 | 1.11.4 |
| CVE-2026-11822 | HIGH | sqlite-libs | 3.34.1-10.el9_8 | 3.34.1-11.el9_8 |
| CVE-2026-11824 | HIGH | sqlite-libs | 3.34.1-10.el9_8 | 3.34.1-11.el9_8 |
| CVE-2026-14456 | HIGH | openssl-libs | 1:3.5.5-6.el9_8 | 1:3.5.8-1.el9_8 |
| CVE-2026-54512 | HIGH | com.fasterxml.jackson.core:jackson-databind | 2.19.2 | 2.18.8, 3.1.4, 2.21.4 |
| CVE-2026-54513 | HIGH | com.fasterxml.jackson.core:jackson-databind | 2.19.2 | 2.18.8, 2.21.4, 3.1.4 |
| CVE-2026-55831 | HIGH | io.netty:netty-codec-http | 4.1.135.Final | 4.2.16.Final, 4.1.136.Final |
| CVE-2026-55833 | HIGH | io.netty:netty-codec-http | 4.1.135.Final | 4.2.16.Final, 4.1.136.Final |

### postgres:18

Digest: `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 14, HIGH 114, MEDIUM 199, LOW 159, UNKNOWN 9

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2025-68121 | CRITICAL | stdlib | v1.24.6 | 1.24.13, 1.25.7, 1.26.0-rc.3 |
| CVE-2026-13221 | CRITICAL | perl-modules-5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | perl | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | libperl5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | libperl5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-modules-5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | libperl5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |

### ics_range-admin-ui:latest

Digest: `ics_range-admin-ui@sha256:4f94459af729b3ec171e3c1780fe5bb4d075101507a0956123af5b80dc59867a` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 2, HIGH 43, MEDIUM 74, LOW 42

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-31789 | CRITICAL | libcrypto3 | 3.3.3-r0 | 3.3.7-r0 |
| CVE-2026-31789 | CRITICAL | libssl3 | 3.3.3-r0 | 3.3.7-r0 |
| CVE-2025-15467 | HIGH | libcrypto3 | 3.3.3-r0 | 3.3.6-r0 |
| CVE-2025-15467 | HIGH | libssl3 | 3.3.3-r0 | 3.3.6-r0 |
| CVE-2025-32414 | HIGH | libxml2 | 2.13.4-r5 | 2.13.4-r6 |
| CVE-2025-32415 | HIGH | libxml2 | 2.13.4-r5 | 2.13.4-r6 |
| CVE-2025-49794 | HIGH | libxml2 | 2.13.4-r5 | 2.13.9-r0 |
| CVE-2025-49795 | HIGH | libxml2 | 2.13.4-r5 | 2.13.9-r0 |
| CVE-2025-49796 | HIGH | libxml2 | 2.13.4-r5 | 2.13.9-r0 |
| CVE-2025-59375 | HIGH | libexpat | 2.7.0-r0 | 2.7.2-r0 |

### ics_range-kibana:latest

Digest: `ics_range-kibana@sha256:5c91c8a5d96dd63e90178e1511beebfe5226497664d7e14f7e4dc421b69537a2` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 4, HIGH 74, MEDIUM 278, LOW 121

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-102992 | CRITICAL | piscina | 5.2.0 | 5.3.2, 4.9.4, 6.0.0-rc.5 |
| CVE-2026-106445 | CRITICAL | handlebars | 4.7.9 | 4.7.10 |
| CVE-2026-106446 | CRITICAL | handlebars | 4.7.9 | 4.7.10 |
| CVE-2026-90711 | CRITICAL | proxy-addr | 2.0.7 | 2.0.8 |
| CVE-2026-101898 | HIGH | axios | 1.19.0 | 1.20.0 |
| CVE-2026-101901 | HIGH | axios | 1.19.0 | 1.20.0 |
| CVE-2026-101903 | HIGH | axios | 1.19.0 | 1.20.0 |
| CVE-2026-101905 | HIGH | axios | 1.19.0 | 1.20.0 |
| CVE-2026-101906 | HIGH | axios | 1.19.0 | 1.20.0 |
| CVE-2026-101907 | HIGH | axios | 1.19.0 | 1.20.0 |

### neo4j:4.4

Digest: `neo4j@sha256:69187cd5fdedbef00e9280c5c9461eadebf210350fca7803bc7349dd7c3ba853` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 7, HIGH 199, MEDIUM 2030, LOW 417, UNKNOWN 7

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2025-14813 | CRITICAL | org.bouncycastle:bcprov-jdk18on | 1.78 | 1.80.2, 1.81.1, 1.84 |
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-75595 | CRITICAL | io.netty:netty-handler | 4.1.127.Final | 4.2.17.Final, 4.1.137.Final |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8763 | CRITICAL | org.bouncycastle:bcprov-jdk18on | 1.78 | 1.85 |
| CVE-2026-43185 | CRITICAL | linux-libc-dev | 6.12.107-1 | - |
| CVE-2025-22104 | HIGH | linux-libc-dev | 6.12.107-1 | 6.12.111-1 |
| CVE-2025-38206 | HIGH | linux-libc-dev | 6.12.107-1 | 6.12.111-1 |
| CVE-2026-10050 | HIGH | org.eclipse.jetty:jetty-security | 9.4.57.v20241219 | 9.4.63, 10.0.31, 11.0.31, 12.0.36, 12.1.10 |

### ics_range-zeek:latest

Digest: `ics_range-zeek@sha256:6cc2573de09d56719884aecb2a7113d02a606d20d196040fb0918be0a75a6b0c` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 24, HIGH 275, MEDIUM 487, LOW 254, UNKNOWN 8

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | libperl5.36 | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |
| CVE-2026-13221 | CRITICAL | perl-modules-5.36 | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |
| CVE-2026-13221 | CRITICAL | perl | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |
| CVE-2026-13221 | CRITICAL | perl-base | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |
| CVE-2026-31789 | CRITICAL | libssl3 | 3.0.15-1~deb12u1 | 3.0.19-1~deb12u2 |
| CVE-2026-31789 | CRITICAL | openssl | 3.0.15-1~deb12u1 | 3.0.19-1~deb12u2 |
| CVE-2026-33845 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u3 | 3.7.9-2+deb12u7 |
| CVE-2026-42010 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u3 | 3.7.9-2+deb12u7 |
| CVE-2026-42496 | CRITICAL | perl-modules-5.36 | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |
| CVE-2026-42496 | CRITICAL | perl | 5.36.0-7+deb12u1 | 5.36.0-7+deb12u4 |

### ics_range-wazuh-manager:latest

Digest: `ics_range-wazuh-manager@sha256:80318ef9d90c5eb48e9d49b62a2f09288ffa60acdeee97dc080bd868f3f6a595` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 9, HIGH 391, MEDIUM 290, LOW 30, UNKNOWN 3

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2022-23806 | CRITICAL | stdlib | v1.14.12 | 1.16.14, 1.17.7 |
| CVE-2023-24538 | CRITICAL | stdlib | v1.14.12 | 1.19.8, 1.20.3 |
| CVE-2023-24540 | CRITICAL | stdlib | v1.14.12 | 1.19.9, 1.20.4 |
| CVE-2024-24790 | CRITICAL | stdlib | v1.14.12 | 1.21.11, 1.22.4 |
| CVE-2025-43859 | CRITICAL | h11 | 0.14.0 | 0.16.0 |
| CVE-2025-68121 | CRITICAL | stdlib | v1.14.12 | 1.24.13, 1.25.7, 1.26.0-rc.3 |
| CVE-2026-102268 | CRITICAL | PyJWT | 2.8.0 | 2.14.0 |
| CVE-2026-33186 | CRITICAL | google.golang.org/grpc | v1.29.1 | 1.79.3 |
| CVE-2026-63374 | CRITICAL | anyio | 4.1.0 | 4.14.2 |
| CVE-2020-14040 | HIGH | golang.org/x/text | v0.3.2 | 0.3.3 |

### ics_range-controller:latest

Digest: `ics_range-controller@sha256:84f96e8b30a1c7c8ee0e57ed7a9fc86f4c0285e933db14eb2a663823f44d63a2` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 3, HIGH 63, MEDIUM 109, LOW 70, UNKNOWN 3

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-103111 | HIGH | libpcre2-8-0 | 10.46-1~deb13u1 | 10.46-1~deb13u3 |
| CVE-2026-11822 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-11824 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-41992 | HIGH | gzip | 1.13-1 | 1.13-1+deb13u1 |
| CVE-2026-42497 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-48962 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-57432 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |

### ics_range-engineer-workstation:latest

Digest: `ics_range-engineer-workstation@sha256:8f2c81d5c91626bc0c242de4ddef29533dc92993b88e8853ccf6916c264dded8` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 3, HIGH 139, MEDIUM 180, LOW 132, UNKNOWN 3

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-103111 | HIGH | libpcre2-8-0 | 10.46-1~deb13u1 | 10.46-1~deb13u3 |
| CVE-2026-11822 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-11824 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-41992 | HIGH | gzip | 1.13-1 | 1.13-1+deb13u1 |
| CVE-2026-42497 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-48962 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-57432 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |

### ics_range-hmi:latest

Digest: `ics_range-hmi@sha256:a36495afdbd36c8900eb6d15794d51e8154a50f3122fd321cdc06bd7e8f51ef0` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 15, HIGH 157, MEDIUM 239, LOW 146, UNKNOWN 4

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.36.0-7+deb12u2 | 5.36.0-7+deb12u4 |
| CVE-2026-33845 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u4 | 3.7.9-2+deb12u7 |
| CVE-2026-42010 | CRITICAL | libgnutls30 | 3.7.9-2+deb12u4 | 3.7.9-2+deb12u7 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.36.0-7+deb12u2 | 5.36.0-7+deb12u4 |
| CVE-2026-59873 | CRITICAL | tar | 6.2.1 | 7.5.19 |
| CVE-2026-59873 | CRITICAL | tar | 7.5.11 | 7.5.19 |
| CVE-2026-59873 | CRITICAL | tar | 7.5.15 | 7.5.19 |
| CVE-2026-77413 | CRITICAL | jsonata | 2.0.6 | 1.8.8, 2.2.0 |
| CVE-2026-77414 | CRITICAL | jsonata | 2.0.6 | 2.2.1, 1.8.8 |
| CVE-2026-77415 | CRITICAL | jsonata | 2.0.6 | 2.2.1, 1.8.8 |

### ics_range-plc:latest

Digest: `ics_range-plc@sha256:a7232d788f587afb33e81ced3b9861aa53f57c9634d0d4728933bcaf39006de3` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 15, HIGH 287, MEDIUM 2212, LOW 1085, UNKNOWN 10

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-102268 | CRITICAL | PyJWT | 2.13.0 | 2.14.0 |
| CVE-2026-13221 | CRITICAL | libperl5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | perl | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | perl-modules-5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | libperl5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-modules-5.40 | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |

### ics_range-shuffle-database:latest

Digest: `ics_range-shuffle-database@sha256:c56c86838e5df3333973e5efbb753ecb853007a5854cec8ebc0c7bbf4688f450` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 3, HIGH 291, MEDIUM 194, LOW 14

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-75595 | CRITICAL | io.netty:netty-handler | 4.1.121.Final | 4.2.17.Final, 4.1.137.Final |
| CVE-2026-75595 | CRITICAL | io.netty:netty-handler | 4.1.118.Final | 4.2.17.Final, 4.1.137.Final |
| CVE-2026-8763 | CRITICAL | org.bouncycastle:bc-fips | 2.0.0 | 1.0.2.7, 2.0.2, 2.1.3 |
| CVE-2025-11468 | HIGH | python3-libs | 3.9.23-1.amzn2023.0.2 | 3.9.25-1.amzn2023.0.4 |
| CVE-2025-11468 | HIGH | python3 | 3.9.23-1.amzn2023.0.2 | 3.9.25-1.amzn2023.0.4 |
| CVE-2025-12183 | HIGH | org.lz4:lz4-java | 1.8.0 | 1.8.1 |
| CVE-2025-13151 | HIGH | libtasn1 | 4.19.0-1.amzn2023.0.5 | 4.19.0-1.amzn2023.0.6 |
| CVE-2025-13462 | HIGH | python3 | 3.9.23-1.amzn2023.0.2 | 3.9.25-1.amzn2023.0.7 |
| CVE-2025-13462 | HIGH | python3-libs | 3.9.23-1.amzn2023.0.2 | 3.9.25-1.amzn2023.0.7 |
| CVE-2025-13601 | HIGH | glib2 | 2.82.2-766.amzn2023 | 2.82.2-767.amzn2023 |

### ics_range-shuffle-frontend:latest

Digest: `ics_range-shuffle-frontend@sha256:f6647d03741890435575dd6adaabb95a97aae318a963ea0cb2be094c24964de5` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 9, HIGH 194, MEDIUM 323, LOW 238, UNKNOWN 45

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-31789 | CRITICAL | libssl3t64 | 3.5.4-1~deb13u1 | 3.5.5-1~deb13u2 |
| CVE-2026-31789 | CRITICAL | openssl-provider-legacy | 3.5.4-1~deb13u1 | 3.5.5-1~deb13u2 |
| CVE-2026-31789 | CRITICAL | openssl | 3.5.4-1~deb13u1 | 3.5.5-1~deb13u2 |
| CVE-2026-33845 | CRITICAL | libgnutls30t64 | 3.8.9-3 | 3.8.9-3+deb13u4 |
| CVE-2026-42010 | CRITICAL | libgnutls30t64 | 3.8.9-3 | 3.8.9-3+deb13u4 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-6653 | CRITICAL | libxml2 | 2.12.7+dfsg+really2.9.14-2.1+deb13u2 | - |
| CVE-2025-15467 | HIGH | openssl | 3.5.4-1~deb13u1 | 3.5.4-1~deb13u2 |

### ics_range-attacker:latest

Digest: `ics_range-attacker@sha256:fde9f564fa0884ce3dae86ef348c93a5d81f80fcdc690a1004034829e4f6ec0a` · Scanner: Trivy v0.68.2 · Counts: 

_None._

### ics_range-process-simulator:latest

Digest: `ics_range-process-simulator@sha256:fe1a3d545268adaa7d85ef04f124363f375240c56e9f3320a935a24e139f3dd1` · Scanner: Trivy v0.68.2 · Counts: CRITICAL 3, HIGH 61, MEDIUM 105, LOW 69, UNKNOWN 3

| ID | Severity | Package | Installed | Fixed |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-42496 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-8376 | CRITICAL | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-103111 | HIGH | libpcre2-8-0 | 10.46-1~deb13u1 | 10.46-1~deb13u3 |
| CVE-2026-11822 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-11824 | HIGH | libsqlite3-0 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| CVE-2026-41992 | HIGH | gzip | 1.13-1 | 1.13-1+deb13u1 |
| CVE-2026-42497 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-48962 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |
| CVE-2026-57432 | HIGH | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 |

#### 🔴 `F-V001-6b055d3bf2` — Image has known vulnerabilities (2 CRITICAL, 43 HIGH, 74 MEDIUM, 42 LOW)

- **Resource:** image `ics_range-admin-ui:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `2 CRITICAL, 43 HIGH, 74 MEDIUM, 42 LOW` — scanner trivy v0.68.2
  - `alpine/libcrypto3` = `CVE-2026-31789 CRITICAL installed=3.3.3-r0 fixed=3.3.7-r0`
  - `alpine/libssl3` = `CVE-2026-31789 CRITICAL installed=3.3.3-r0 fixed=3.3.7-r0`
  - `alpine/libcrypto3` = `CVE-2025-15467 HIGH installed=3.3.3-r0 fixed=3.3.6-r0`
  - `alpine/libssl3` = `CVE-2025-15467 HIGH installed=3.3.3-r0 fixed=3.3.6-r0`
  - `alpine/libxml2` = `CVE-2025-32414 HIGH installed=2.13.4-r5 fixed=2.13.4-r6`

**Why it matters:** Trivy matched 161 known vulnerabilities in packages of this image (161 have a fixed version available). Image used by: admin-ui. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2025-15467, https://avd.aquasec.com/nvd/cve-2025-15467, https://avd.aquasec.com/nvd/cve-2025-32414

#### 🔴 `F-V001-8e5ada8413` — Image has known vulnerabilities (3 CRITICAL, 63 HIGH, 109 MEDIUM, 70 LOW, 3 UNKNOWN)

- **Resource:** image `ics_range-controller:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `3 CRITICAL, 63 HIGH, 109 MEDIUM, 70 LOW, 3 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/libpcre2-8-0` = `CVE-2026-103111 HIGH installed=10.46-1~deb13u1 fixed=10.46-1~deb13u3`
  - `debian/libsqlite3-0` = `CVE-2026-11822 HIGH installed=3.46.1-7+deb13u1 fixed=3.46.1-7+deb13u2`

**Why it matters:** Trivy matched 248 known vulnerabilities in packages of this image (84 have a fixed version available). Image used by: controller. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-8376, https://avd.aquasec.com/nvd/cve-2026-103111, https://avd.aquasec.com/nvd/cve-2026-11822

#### 🔴 `F-V001-c33db87e8c` — Image has known vulnerabilities (1 CRITICAL, 53 HIGH, 170 MEDIUM, 85 LOW)

- **Resource:** image `ics_range-elasticsearch:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `1 CRITICAL, 53 HIGH, 170 MEDIUM, 85 LOW` — scanner trivy v0.68.2
  - `jar/io.netty:netty-handler` = `CVE-2026-75595 CRITICAL installed=4.1.135.Final fixed=4.2.17.Final, 4.1.137.Final`
  - `redhat/libpcap` = `CVE-2026-0799 HIGH installed=14:1.10.0-4.el9 fixed=14:1.10.0-4.el9_8.1`
  - `jar/at.yawk.lz4:lz4-java` = `CVE-2026-106451 HIGH installed=1.11.1 fixed=1.11.4`
  - `redhat/sqlite-libs` = `CVE-2026-11822 HIGH installed=3.34.1-10.el9_8 fixed=3.34.1-11.el9_8`
  - `redhat/sqlite-libs` = `CVE-2026-11824 HIGH installed=3.34.1-10.el9_8 fixed=3.34.1-11.el9_8`

**Why it matters:** Trivy matched 309 known vulnerabilities in packages of this image (93 have a fixed version available). Image used by: elasticsearch. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-75595, https://avd.aquasec.com/nvd/cve-2026-0799, https://avd.aquasec.com/nvd/cve-2026-106451, https://avd.aquasec.com/nvd/cve-2026-11822, https://avd.aquasec.com/nvd/cve-2026-11824

#### 🔴 `F-V001-87999330be` — Image has known vulnerabilities (3 CRITICAL, 139 HIGH, 180 MEDIUM, 132 LOW, 3 UNKNOWN)

- **Resource:** image `ics_range-engineer-workstation:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `3 CRITICAL, 139 HIGH, 180 MEDIUM, 132 LOW, 3 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/libpcre2-8-0` = `CVE-2026-103111 HIGH installed=10.46-1~deb13u1 fixed=10.46-1~deb13u3`
  - `debian/libsqlite3-0` = `CVE-2026-11822 HIGH installed=3.46.1-7+deb13u1 fixed=3.46.1-7+deb13u2`

**Why it matters:** Trivy matched 457 known vulnerabilities in packages of this image (83 have a fixed version available). Image used by: engineer-workstation. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-8376, https://avd.aquasec.com/nvd/cve-2026-103111, https://avd.aquasec.com/nvd/cve-2026-11822

#### 🔴 `F-V001-94b6486bc4` — Image has known vulnerabilities (15 CRITICAL, 157 HIGH, 239 MEDIUM, 146 LOW, 4 UNKNOWN)

- **Resource:** image `ics_range-hmi:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `15 CRITICAL, 157 HIGH, 239 MEDIUM, 146 LOW, 4 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u2 fixed=5.36.0-7+deb12u4`
  - `debian/libgnutls30` = `CVE-2026-33845 CRITICAL installed=3.7.9-2+deb12u4 fixed=3.7.9-2+deb12u7`
  - `debian/libgnutls30` = `CVE-2026-42010 CRITICAL installed=3.7.9-2+deb12u4 fixed=3.7.9-2+deb12u7`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.36.0-7+deb12u2 fixed=5.36.0-7+deb12u4`
  - `node-pkg/tar` = `CVE-2026-59873 CRITICAL installed=6.2.1 fixed=7.5.19`

**Why it matters:** Trivy matched 561 known vulnerabilities in packages of this image (252 have a fixed version available). Image used by: hmi. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-33845, https://avd.aquasec.com/nvd/cve-2026-42010, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-59873

#### 🔴 `F-V001-718d10ca7d` — Image has known vulnerabilities (4 CRITICAL, 74 HIGH, 278 MEDIUM, 121 LOW)

- **Resource:** image `ics_range-kibana:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `4 CRITICAL, 74 HIGH, 278 MEDIUM, 121 LOW` — scanner trivy v0.68.2
  - `node-pkg/piscina` = `CVE-2026-102992 CRITICAL installed=5.2.0 fixed=5.3.2, 4.9.4, 6.0.0-rc.5`
  - `node-pkg/handlebars` = `CVE-2026-106445 CRITICAL installed=4.7.9 fixed=4.7.10`
  - `node-pkg/handlebars` = `CVE-2026-106446 CRITICAL installed=4.7.9 fixed=4.7.10`
  - `node-pkg/proxy-addr` = `CVE-2026-90711 CRITICAL installed=2.0.7 fixed=2.0.8`
  - `node-pkg/axios` = `CVE-2026-101898 HIGH installed=1.19.0 fixed=1.20.0`

**Why it matters:** Trivy matched 477 known vulnerabilities in packages of this image (139 have a fixed version available). Image used by: kibana. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-102992, https://avd.aquasec.com/nvd/cve-2026-106445, https://avd.aquasec.com/nvd/cve-2026-106446, https://avd.aquasec.com/nvd/cve-2026-90711, https://avd.aquasec.com/nvd/cve-2026-101898

#### 🔴 `F-V001-afcdfdf4a5` — Image has known vulnerabilities (15 CRITICAL, 287 HIGH, 2212 MEDIUM, 1085 LOW, 10 UNKNOWN)

- **Resource:** image `ics_range-plc:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `15 CRITICAL, 287 HIGH, 2212 MEDIUM, 1085 LOW, 10 UNKNOWN` — scanner trivy v0.68.2
  - `python-pkg/PyJWT` = `CVE-2026-102268 CRITICAL installed=2.13.0 fixed=2.14.0`
  - `debian/libperl5.40` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-modules-5.40` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`

**Why it matters:** Trivy matched 3609 known vulnerabilities in packages of this image (1567 have a fixed version available). Image used by: plc. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-102268, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221

#### 🔴 `F-V001-b029a0c528` — Image has known vulnerabilities (3 CRITICAL, 61 HIGH, 105 MEDIUM, 69 LOW, 3 UNKNOWN)

- **Resource:** image `ics_range-process-simulator:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `3 CRITICAL, 61 HIGH, 105 MEDIUM, 69 LOW, 3 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/libpcre2-8-0` = `CVE-2026-103111 HIGH installed=10.46-1~deb13u1 fixed=10.46-1~deb13u3`
  - `debian/libsqlite3-0` = `CVE-2026-11822 HIGH installed=3.46.1-7+deb13u1 fixed=3.46.1-7+deb13u2`

**Why it matters:** Trivy matched 241 known vulnerabilities in packages of this image (77 have a fixed version available). Image used by: process-simulator. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-8376, https://avd.aquasec.com/nvd/cve-2026-103111, https://avd.aquasec.com/nvd/cve-2026-11822

#### 🔴 `F-V001-e7b4b02ee1` — Image has known vulnerabilities (4 CRITICAL, 59 HIGH, 104 MEDIUM, 80 LOW, 6 UNKNOWN)

- **Resource:** image `ics_range-rsyslog:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `4 CRITICAL, 59 HIGH, 104 MEDIUM, 80 LOW, 6 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.36.0-7+deb12u3 fixed=5.36.0-7+deb12u4`
  - `debian/zlib1g` = `CVE-2023-45853 CRITICAL installed=1:1.2.13.dfsg-1 fixed=none`
  - `debian/libpcre2-8-0` = `CVE-2026-103111 HIGH installed=10.42-1 fixed=10.42-1+deb12u2`

**Why it matters:** Trivy matched 253 known vulnerabilities in packages of this image (23 have a fixed version available). Image used by: rsyslog. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-8376, https://avd.aquasec.com/nvd/cve-2023-45853, https://avd.aquasec.com/nvd/cve-2026-103111

#### 🔴 `F-V001-1a3c631a8f` — Image has known vulnerabilities (2 CRITICAL, 56 HIGH, 50 MEDIUM, 55 LOW, 3 UNKNOWN)

- **Resource:** image `ics_range-shuffle-backend:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `2 CRITICAL, 56 HIGH, 50 MEDIUM, 55 LOW, 3 UNKNOWN` — scanner trivy v0.68.2
  - `alpine/libcrypto3` = `CVE-2026-31789 CRITICAL installed=3.5.4-r0 fixed=3.5.6-r0`
  - `alpine/libssl3` = `CVE-2026-31789 CRITICAL installed=3.5.4-r0 fixed=3.5.6-r0`
  - `alpine/libssl3` = `CVE-2025-15467 HIGH installed=3.5.4-r0 fixed=3.5.5-r0`
  - `alpine/libcrypto3` = `CVE-2025-15467 HIGH installed=3.5.4-r0 fixed=3.5.5-r0`
  - `alpine/libssl3` = `CVE-2025-69421 HIGH installed=3.5.4-r0 fixed=3.5.5-r0`

**Why it matters:** Trivy matched 166 known vulnerabilities in packages of this image (162 have a fixed version available). Image used by: shuffle-backend. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2025-15467, https://avd.aquasec.com/nvd/cve-2025-15467, https://avd.aquasec.com/nvd/cve-2025-69421

#### 🔴 `F-V001-5ca0a0bb7f` — Image has known vulnerabilities (3 CRITICAL, 291 HIGH, 194 MEDIUM, 14 LOW)

- **Resource:** image `ics_range-shuffle-database:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `3 CRITICAL, 291 HIGH, 194 MEDIUM, 14 LOW` — scanner trivy v0.68.2
  - `jar/io.netty:netty-handler` = `CVE-2026-75595 CRITICAL installed=4.1.121.Final fixed=4.2.17.Final, 4.1.137.Final`
  - `jar/io.netty:netty-handler` = `CVE-2026-75595 CRITICAL installed=4.1.118.Final fixed=4.2.17.Final, 4.1.137.Final`
  - `jar/org.bouncycastle:bc-fips` = `CVE-2026-8763 CRITICAL installed=2.0.0 fixed=1.0.2.7, 2.0.2, 2.1.3`
  - `amazon/python3-libs` = `CVE-2025-11468 HIGH installed=3.9.23-1.amzn2023.0.2 fixed=3.9.25-1.amzn2023.0.4`
  - `amazon/python3` = `CVE-2025-11468 HIGH installed=3.9.23-1.amzn2023.0.2 fixed=3.9.25-1.amzn2023.0.4`

**Why it matters:** Trivy matched 502 known vulnerabilities in packages of this image (494 have a fixed version available). Image used by: shuffle-database. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-75595, https://avd.aquasec.com/nvd/cve-2026-75595, https://avd.aquasec.com/nvd/cve-2026-8763, https://avd.aquasec.com/nvd/cve-2025-11468, https://avd.aquasec.com/nvd/cve-2025-11468

#### 🔴 `F-V001-27f4668167` — Image has known vulnerabilities (9 CRITICAL, 194 HIGH, 323 MEDIUM, 238 LOW, 45 UNKNOWN)

- **Resource:** image `ics_range-shuffle-frontend:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `9 CRITICAL, 194 HIGH, 323 MEDIUM, 238 LOW, 45 UNKNOWN` — scanner trivy v0.68.2
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/libssl3t64` = `CVE-2026-31789 CRITICAL installed=3.5.4-1~deb13u1 fixed=3.5.5-1~deb13u2`
  - `debian/openssl-provider-legacy` = `CVE-2026-31789 CRITICAL installed=3.5.4-1~deb13u1 fixed=3.5.5-1~deb13u2`
  - `debian/openssl` = `CVE-2026-31789 CRITICAL installed=3.5.4-1~deb13u1 fixed=3.5.5-1~deb13u2`
  - `debian/libgnutls30t64` = `CVE-2026-33845 CRITICAL installed=3.8.9-3 fixed=3.8.9-3+deb13u4`

**Why it matters:** Trivy matched 809 known vulnerabilities in packages of this image (493 have a fixed version available). Image used by: shuffle-frontend. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-31789, https://avd.aquasec.com/nvd/cve-2026-33845

#### 🔴 `F-V001-dd7a72a84a` — Image has known vulnerabilities (9 CRITICAL, 391 HIGH, 290 MEDIUM, 30 LOW, 3 UNKNOWN)

- **Resource:** image `ics_range-wazuh-manager:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `9 CRITICAL, 391 HIGH, 290 MEDIUM, 30 LOW, 3 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/stdlib` = `CVE-2022-23806 CRITICAL installed=v1.14.12 fixed=1.16.14, 1.17.7`
  - `gobinary/stdlib` = `CVE-2023-24538 CRITICAL installed=v1.14.12 fixed=1.19.8, 1.20.3`
  - `gobinary/stdlib` = `CVE-2023-24540 CRITICAL installed=v1.14.12 fixed=1.19.9, 1.20.4`
  - `gobinary/stdlib` = `CVE-2024-24790 CRITICAL installed=v1.14.12 fixed=1.21.11, 1.22.4`
  - `python-pkg/h11` = `CVE-2025-43859 CRITICAL installed=0.14.0 fixed=0.16.0`

**Why it matters:** Trivy matched 723 known vulnerabilities in packages of this image (723 have a fixed version available). Image used by: wazuh-manager. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2022-23806, https://avd.aquasec.com/nvd/cve-2023-24538, https://avd.aquasec.com/nvd/cve-2023-24540, https://avd.aquasec.com/nvd/cve-2024-24790, https://avd.aquasec.com/nvd/cve-2025-43859

#### 🔴 `F-V001-a376c3dd66` — Image has known vulnerabilities (24 CRITICAL, 275 HIGH, 487 MEDIUM, 254 LOW, 8 UNKNOWN)

- **Resource:** image `ics_range-zeek:latest`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `24 CRITICAL, 275 HIGH, 487 MEDIUM, 254 LOW, 8 UNKNOWN` — scanner trivy v0.68.2
  - `debian/libperl5.36` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u1 fixed=5.36.0-7+deb12u4`
  - `debian/perl-modules-5.36` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u1 fixed=5.36.0-7+deb12u4`
  - `debian/perl` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u1 fixed=5.36.0-7+deb12u4`
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.36.0-7+deb12u1 fixed=5.36.0-7+deb12u4`
  - `debian/libssl3` = `CVE-2026-31789 CRITICAL installed=3.0.15-1~deb12u1 fixed=3.0.19-1~deb12u2`

**Why it matters:** Trivy matched 1048 known vulnerabilities in packages of this image (572 have a fixed version available). Image used by: zeek. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-31789

#### 🔴 `F-V001-abe3ebffc3` — Image has known vulnerabilities (7 CRITICAL, 199 HIGH, 2030 MEDIUM, 417 LOW, 7 UNKNOWN)

- **Resource:** image `neo4j:4.4`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `7 CRITICAL, 199 HIGH, 2030 MEDIUM, 417 LOW, 7 UNKNOWN` — scanner trivy v0.68.2
  - `jar/org.bouncycastle:bcprov-jdk18on` = `CVE-2025-14813 CRITICAL installed=1.78 fixed=1.80.2, 1.81.1, 1.84`
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-42496 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `jar/io.netty:netty-handler` = `CVE-2026-75595 CRITICAL installed=4.1.127.Final fixed=4.2.17.Final, 4.1.137.Final`
  - `debian/perl-base` = `CVE-2026-8376 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`

**Why it matters:** Trivy matched 2660 known vulnerabilities in packages of this image (1452 have a fixed version available). Image used by: bloodhound-graph-db-1. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2025-14813, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-42496, https://avd.aquasec.com/nvd/cve-2026-75595, https://avd.aquasec.com/nvd/cve-2026-8376

#### 🔴 `F-V001-d996987928` — Image has known vulnerabilities (14 CRITICAL, 114 HIGH, 199 MEDIUM, 159 LOW, 9 UNKNOWN)

- **Resource:** image `postgres:18`
- **Category:** image-vulnerability · **Severity:** critical · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `14 CRITICAL, 114 HIGH, 199 MEDIUM, 159 LOW, 9 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/stdlib` = `CVE-2025-68121 CRITICAL installed=v1.24.6 fixed=1.24.13, 1.25.7, 1.26.0-rc.3`
  - `debian/perl-modules-5.40` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/perl-base` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`
  - `debian/libperl5.40` = `CVE-2026-13221 CRITICAL installed=5.40.1-6 fixed=5.40.1-6+deb13u1`

**Why it matters:** Trivy matched 495 known vulnerabilities in packages of this image (196 have a fixed version available). Image used by: bloodhound-app-db-1. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2025-68121, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221, https://avd.aquasec.com/nvd/cve-2026-13221

#### 🟠 `F-V001-a2d3aeb860` — Image has known vulnerabilities (11 HIGH, 4 MEDIUM, 4 LOW, 2 UNKNOWN)

- **Resource:** image `ics_range-filebeat:latest`
- **Category:** image-vulnerability · **Severity:** high · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `11 HIGH, 4 MEDIUM, 4 LOW, 2 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/stdlib` = `CVE-2026-33818 HIGH installed=v1.26.5 fixed=1.25.13, 1.26.6, 1.27.0-rc.3`
  - `gobinary/stdlib` = `CVE-2026-39821 HIGH installed=v1.26.5 fixed=1.25.13, 1.26.6, 1.27.0-rc.3`
  - `gobinary/stdlib` = `CVE-2026-46600 HIGH installed=v1.26.5 fixed=1.26.6, 1.27.0-rc.3`
  - `gobinary/stdlib` = `CVE-2026-56853 HIGH installed=v1.26.5 fixed=1.25.13, 1.26.6, 1.27.0-rc.3`
  - `gobinary/golang.org/x/crypto` = `CVE-2026-56854 HIGH installed=v0.54.0 fixed=0.55.0`

**Why it matters:** Trivy matched 21 known vulnerabilities in packages of this image (20 have a fixed version available). Image used by: filebeat. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-33818, https://avd.aquasec.com/nvd/cve-2026-39821, https://avd.aquasec.com/nvd/cve-2026-46600, https://avd.aquasec.com/nvd/cve-2026-56853, https://avd.aquasec.com/nvd/cve-2026-56854

#### 🟠 `F-V001-2b857d3575` — Image has known vulnerabilities (6 HIGH, 10 MEDIUM, 13 LOW)

- **Resource:** image `tecnativa/docker-socket-proxy:v0.5.0`
- **Category:** image-vulnerability · **Severity:** high · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `6 HIGH, 10 MEDIUM, 13 LOW` — scanner trivy v0.68.2
  - `alpine/pcre2` = `CVE-2026-103111 HIGH installed=10.47-r1 fixed=10.49-r0`
  - `alpine/libcrypto3` = `CVE-2026-14456 HIGH installed=3.5.7-r0 fixed=3.5.8-r0`
  - `alpine/libssl3` = `CVE-2026-14456 HIGH installed=3.5.7-r0 fixed=3.5.8-r0`
  - `alpine/pcre2` = `CVE-2026-86145 HIGH installed=10.47-r1 fixed=10.48-r0`
  - `alpine/pcre2` = `CVE-2026-89157 HIGH installed=10.47-r1 fixed=10.48-r0`

**Why it matters:** Trivy matched 29 known vulnerabilities in packages of this image (29 have a fixed version available). Image used by: docker-audit-socket-proxy. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-103111, https://avd.aquasec.com/nvd/cve-2026-14456, https://avd.aquasec.com/nvd/cve-2026-14456, https://avd.aquasec.com/nvd/cve-2026-86145, https://avd.aquasec.com/nvd/cve-2026-89157

#### 🟡 `F-V001-0da58304e8` — Image has known vulnerabilities (2 MEDIUM, 2 UNKNOWN)

- **Resource:** image `specterops/bloodhound:latest`
- **Category:** image-vulnerability · **Severity:** medium · **Confidence:** high · **Status:** confirmed (scanner)
- **Evidence:**
  - `counts` = `2 MEDIUM, 2 UNKNOWN` — scanner trivy v0.68.2
  - `gobinary/golang.org/x/crypto` = `CVE-2026-56855 MEDIUM installed=v0.55.0 fixed=0.56.0`
  - `gobinary/golang.org/x/crypto` = `CVE-2026-78662 MEDIUM installed=v0.55.0 fixed=0.56.0`
  - `debian/tzdata` = `DLA-4792-1 UNKNOWN installed=2026b-0+deb12u1 fixed=2026c-0+deb12u1`
  - `gobinary/golang.org/x/crypto` = `GO-2026-5932 UNKNOWN installed=v0.55.0 fixed=none`

**Why it matters:** Trivy matched 4 known vulnerabilities in packages of this image (3 have a fixed version available). Image used by: bloodhound-bloodhound-1. Exploitability depends on whether the vulnerable package is reachable from an exposed service.

**Remediation:** Rebuild the image on an updated base image and upgrade the listed packages to their fixed versions; prioritise CRITICAL/HIGH findings in images whose ports are published.

**References:** https://avd.aquasec.com/nvd/cve-2026-56855, https://avd.aquasec.com/nvd/cve-2026-78662


## 9. Potential concerns (AI-proposed, needs human review)

#### 🟠 `F-AGENT-7f1ad7dcad` — Missing Resource Limits on Exposed Containers

- **Resource:** unknown `ics_range-elasticsearch:latest`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `evidence_ref` = `F-V001-c33db87e8c`

**Why it matters:** Elasticsearch is exposed but lacks memory/CPU limits, which could lead to resource exhaustion and denial of service in an OT environment.

**Remediation:** Add resource limits in Docker Compose or runtime constraints.

#### 🟡 `F-AGENT-cae35fab23` — Unrestricted Network Access

- **Resource:** unknown `ics_range-process-simulator:latest`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `evidence_ref` = `F-V001-b029a0c528`

**Why it matters:** The process simulator may be bridging networks without proper segmentation, increasing attack surface.

**Remediation:** Restrict to only necessary networks using Docker network policies.


## 10. Remediation recommendations

1. Immediately remove the Docker socket mount from 'shuffle-backend' by modifying its Dockerfile or runtime configuration.
2. Update all vulnerable images (e.g., 'ics_range-hmi:latest', 'ics_range-wazuh-manager:latest') to versions with fixed CVEs.
3. Implement resource limits for Elasticsearch and other critical services to prevent DoS.
4. Isolate the 'ics_range-process-simulator:latest' container to a dedicated network with strict access controls.
5. Scan all remaining images with Trivy to identify and remediate additional vulnerabilities.


## 11. Limitations and unknowns

- Metadata-only assessment: no runtime behaviour, network traffic or in-container files were inspected, and no active scanning was performed.
- Image vulnerabilities come from Trivy's database at scan time; exploitability depends on whether the vulnerable code is reachable, which was not tested.
- Secret values were redacted before analysis; credential findings are based on variable names and patterns only.
- Findings reflect the Docker state at the snapshot time only; historical runs are not evidence of current state.
- Only 19 of 162 findings are shown; lower-severity issues may exist but are not prioritized here.
- Network topology details (e.g., bridge configurations) are not available to fully assess segmentation risks.
- Trivy reported zero vulnerabilities for: ics_range-attacker:latest. This can mean the image is clean OR that Trivy does not support the image's OS/package manager (e.g. Kali Linux); treat these as 'not assessed' until verified.


## 12. Model and execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 382.7s / 0.71s / 21.13s / 359.05s |
| Tool calls (total / by agent / blocked) | 303 / 1 / 0 |
| Values redacted | 227 |
| Model requests | 2 |
| Tokens (in / out / total) | 16185 / 2236 / 18421 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_list`×1, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `local.get_rule_findings`×1, `trivy.findings_list`×276, `trivy.scan_image`×20, `trivy.trivy_version`×1
