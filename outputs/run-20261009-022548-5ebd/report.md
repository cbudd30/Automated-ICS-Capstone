# Docker Security Assessment — `run-20261009-022548-5ebd`

**Status:** completed · **Overall risk:** CRITICAL (determined by deterministic) · **Generated:** 2026-10-09 02:25 UTC

**Model:** none (deterministic run) · **Snapshot:** `snap-dd56d3f4bcdf4759`

## 1. Assessment summary

AI analysis unavailable (agent status: skipped). Deterministic checks produced 151 findings (1 critical, 5 high, 32 medium). See prioritised findings and remediation below.

**Objective:** Assess the security posture of the Docker environment hosting a containerized industrial control system (ICS) lab. Identify container misconfigurations, risky network exposure, missing resource limits, and known image vulnerabilities. Prioritise risks by their impact on an OT environment and give concrete, evidence-based remediation for defenders.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 1 | 5 | 32 | 104 | 9 |


## 2. Docker environment overview

- Docker engine: 29.7.2 (Docker Desktop 4.88.1 (237512))
- Snapshot captured: 2026-10-09 02:25:48 UTC
- Containers: 20 (13 running) · Images: 38 · Networks: 8 · Volumes: 18
- Images with known vulnerabilities: 0 · Total vulnerabilities: 


## 3. Container inventory

| Container | Image | State | User | Privileged | Networks | Published ports | Findings |
|---|---|---|---|---|---|---|---|
| admin-ui | ics_range-admin-ui | exited | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:8080->80/tcp | 6 |
| attacker | ics_range-attacker | exited | (default: root) | no | ics_range_ics_net | - | 7 |
| bloodhound-app-db-1 | docker.io/library/postgres:18 | exited | (default: root) | no | bloodhound_default | - | 7 |
| bloodhound-bloodhound-1 | docker.io/specterops/bloodhound:latest | exited | 0 | no | bloodhound_default | 127.0.0.1:8080->8080/tcp | 7 |
| bloodhound-graph-db-1 | docker.io/library/neo4j:4.4 | exited | (default: root) | no | bloodhound_default | 127.0.0.1:7474->7474/tcp, 127.0.0.1:7687->7687/tcp | 6 |
| controller | ics_range-controller | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:9000->9000/tcp | 8 |
| docker-audit-socket-proxy | tecnativa/docker-socket-proxy:v0.5.0 | running | root | no | docker-audit-proxy_default | 127.0.0.1:2375->2375/tcp | 0 |
| elasticsearch | ics_range-elasticsearch | running | 1000:0 | no | ics_range_mgmt_net | 0.0.0.0:9200->9200/tcp | 7 |
| engineer-workstation | ics_range-engineer-workstation | running | (default: root) | no | ics_range_ics_net | - | 5 |
| filebeat | ics_range-filebeat | running | root | no | ics_range_mgmt_net, ics_range_mon_net | - | 9 |
| hmi | ics_range-hmi | running | (default: root) | no | ics_range_ics_net | 0.0.0.0:1881->1881/tcp | 6 |
| kibana | ics_range-kibana | running | 1000 | no | ics_range_mgmt_net | 0.0.0.0:5601->5601/tcp | 6 |
| plc | ics_range-plc | exited | (default: root) | no | ics_range_ics_net | 0.0.0.0:8081->8080/tcp | 6 |
| process-simulator | ics_range-process-simulator | running | (default: root) | no | ics_range_ics_net | - | 5 |
| rsyslog | ics_range-rsyslog | running | (default: root) | no | ics_range_ics_net, ics_range_mon_net | 0.0.0.0:514->514/udp | 8 |
| shuffle-backend | ics_range-shuffle-backend | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:5001->5001/tcp | 8 |
| shuffle-database | ics_range-shuffle-database | running | 1000 | no | ics_range_mgmt_net | 0.0.0.0:9201->9200/tcp | 6 |
| shuffle-frontend | ics_range-shuffle-frontend | running | (default: root) | no | ics_range_mgmt_net | 0.0.0.0:3444->443/tcp, 0.0.0.0:3443->80/tcp | 6 |
| wazuh-manager | ics_range-wazuh-manager | running | (default: root) | no | ics_range_mgmt_net, ics_range_mon_net | 0.0.0.0:1514->1514/tcp, 0.0.0.0:1515->1515/tcp, 0.0.0.0:55000->55000/tcp | 9 |
| zeek | ics_range-zeek | exited | (default: root) | no |  | - | 7 |


## 4. Image inventory

| Image | ID | Digest | Size (MB) | Used by | Scan | Vulnerabilities |
|---|---|---|---|---|---|---|
| ics_range-shuffle-backend:latest | 024f628d085d | ics_range-shuffle-backend@sha256:024f628 | 50.2 | shuffle-backend | not scanned | - |
| ics_range-rsyslog:latest | 0302a5b18fce | ics_range-rsyslog@sha256:0302a5b18fce184 | 28.9 | rsyslog | not scanned | - |
| tecnativa/docker-socket-proxy:v0.5.0 | 1f5038b54f06 | tecnativa/docker-socket-proxy@sha256:1f5 | 20.6 | docker-audit-socket-proxy | not scanned | - |
| specterops/bloodhound:latest | 24dba2ba69f7 | specterops/bloodhound@sha256:24dba2ba69f | 64.0 | bloodhound-bloodhound-1 | not scanned | - |
| ics_range-filebeat:latest | 337151eeb27c | ics_range-filebeat@sha256:337151eeb27c9e | 121.1 | filebeat | not scanned | - |
| ics_range-elasticsearch:latest | 40f5b4211ca4 | ics_range-elasticsearch@sha256:40f5b4211 | 758.8 | elasticsearch | not scanned | - |
| postgres:18 | 4ef4dbc939d6 | postgres@sha256:4ef4dbc939d61acea5771265 | 161.1 | bloodhound-app-db-1 | not scanned | - |
| ics_range-admin-ui:latest | 4f94459af729 | ics_range-admin-ui@sha256:4f94459af729b3 | 21.8 | admin-ui | not scanned | - |
| ics_range-kibana:latest | 5c91c8a5d96d | ics_range-kibana@sha256:5c91c8a5d96dd63e | 591.6 | kibana | not scanned | - |
| neo4j:4.4 | 69187cd5fded | neo4j@sha256:69187cd5fdedbef00e9280c5c94 | 328.2 | bloodhound-graph-db-1 | not scanned | - |
| ics_range-zeek:latest | 6cc2573de09d | ics_range-zeek@sha256:6cc2573de09d567198 | 161.7 | zeek | not scanned | - |
| ics_range-wazuh-manager:latest | 80318ef9d90c | ics_range-wazuh-manager@sha256:80318ef9d | 613.7 | wazuh-manager | not scanned | - |
| ics_range-controller:latest | 84f96e8b30a1 | ics_range-controller@sha256:84f96e8b30a1 | 52.9 | controller | not scanned | - |
| ics_range-engineer-workstation:latest | 8f2c81d5c916 | ics_range-engineer-workstation@sha256:8f | 70.4 | engineer-workstation | not scanned | - |
| ics_range-hmi:latest | a36495afdbd3 | ics_range-hmi@sha256:a36495afdbd36c8900e | 208.4 | hmi | not scanned | - |
| ics_range-plc:latest | a7232d788f58 | ics_range-plc@sha256:a7232d788f587afb33e | 382.5 | plc | not scanned | - |
| ics_range-shuffle-database:latest | c56c86838e5d | ics_range-shuffle-database@sha256:c56c86 | 755.0 | shuffle-database | not scanned | - |
| ics_range-shuffle-frontend:latest | f6647d037418 | ics_range-shuffle-frontend@sha256:f6647d | 77.8 | shuffle-frontend | not scanned | - |
| ics_range-attacker:latest | fde9f564fa08 | ics_range-attacker@sha256:fde9f564fa0884 | 94.2 | attacker | not scanned | - |
| ics_range-process-simulator:latest | fe1a3d545268 | ics_range-process-simulator@sha256:fe1a3 | 50.6 | process-simulator | not scanned | - |


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
| 1 | critical | `F-C008-aa76ffcc14` Docker socket is mounted into the container | shuffle-backend | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 2 | high | `F-C009-976dd4d231` Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/results | controller | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 3 | high | `F-C009-8a0baa3f27` Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/siem | elasticsearch | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 4 | high | `F-C009-4b9789d92d` Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/rsyslog | rsyslog | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 5 | high | `F-C009-24c025e5c4` Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/wazuh | wazuh-manager | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 6 | high | `F-C009-389f84fbca` Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap (container is currently exited) | zeek | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 7 | medium | `F-C003-3032d28750` Container runs as root (container is currently exited) | admin-ui | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 8 | medium | `F-C002-18d934064b` Container adds dangerous capabilities: NET_ADMIN, NET_RAW (container is currently exited) | attacker | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 9 | medium | `F-C003-1d9919974b` Container runs as root (container is currently exited) | attacker | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 10 | medium | `F-C003-3406b77fe2` Container runs as root (container is currently exited) | bloodhound-app-db-1 | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 11 | medium | `F-C003-971948e431` Container runs as root (container is currently exited) | bloodhound-bloodhound-1 | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 12 | medium | `F-C009-a57b691e21` Sensitive host path bind-mounted: /Users/mohamed_metwally/Library/Application Support/bloodhound/bloodhound.config.json (container is currently exited) | bloodhound-bloodhound-1 | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 13 | medium | `F-C003-282affb892` Container runs as root (container is currently exited) | bloodhound-graph-db-1 | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 14 | medium | `F-C003-6dd8825555` Container runs as root | controller | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |
| 15 | medium | `F-C003-6edba355a8` Container runs as root | engineer-workstation | Ordered by severity and confidence (no valid agent prioritisation available). | deterministic |


## 7. Security misconfigurations (151)

Confirmed by deterministic rules. Each finding lists the exact Docker field that supports it.

#### 🔴 `F-C008-aa76ffcc14` — Docker socket is mounted into the container

- **Resource:** container `shuffle-backend`
- **Category:** filesystem · **Severity:** critical · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/var/run/docker.sock -> /var/run/docker.sock (rw)` — even a read-only mount of the socket allows full API use

**Why it matters:** The Docker API socket grants full control of the Docker daemon: anyone who controls this container can start a privileged container that mounts the host filesystem, i.e. root on the host and control of every ICS component. Mounting it ':ro' does NOT help - it only makes the socket file read-only, not the API.

**Remediation:** Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.

#### 🟠 `F-C009-976dd4d231` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/results

- **Resource:** container `controller`
- **Category:** filesystem · **Severity:** high · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/results -> /data/results (rw)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

#### 🟠 `F-C009-8a0baa3f27` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/siem

- **Resource:** container `elasticsearch`
- **Category:** filesystem · **Severity:** high · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/siem -> /usr/share/elasticsearch/data (rw)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

#### 🟠 `F-C009-4b9789d92d` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/rsyslog

- **Resource:** container `rsyslog`
- **Category:** filesystem · **Severity:** high · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/rsyslog -> /var/log/rsyslog (rw)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

#### 🟠 `F-C009-24c025e5c4` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/wazuh

- **Resource:** container `wazuh-manager`
- **Category:** filesystem · **Severity:** high · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/host_mnt/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/wazuh -> /var/ossec/logs (rw)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

#### 🟠 `F-C009-389f84fbca` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap (container is currently exited)

- **Resource:** container `zeek`
- **Category:** filesystem · **Severity:** high · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap -> /zeek/logs (rw)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

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

#### 🟡 `F-C009-a57b691e21` — Sensitive host path bind-mounted: /Users/mohamed_metwally/Library/Application Support/bloodhound/bloodhound.config.json (container is currently exited)

- **Resource:** container `bloodhound-bloodhound-1`
- **Category:** filesystem · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/Library/Application Support/bloodhound/bloodhound.config.json -> /bloodhound.config.json (ro)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

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

#### 🟡 `F-C009-3418863a79` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap

- **Resource:** container `filebeat`
- **Category:** filesystem · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap -> /data/pcap (ro)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

#### 🟡 `F-C009-822b8443f4` — Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs

- **Resource:** container `filebeat`
- **Category:** filesystem · **Severity:** medium · **Confidence:** high · **Status:** confirmed (rule)
- **Evidence:**
  - `Mounts` = `/Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs -> /data/logs (ro)` — under /Users

**Why it matters:** Host directories mounted into a container expose host configuration, credentials or kernel interfaces; a writable mount lets the container modify the host.

**Remediation:** Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.

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


## 9. Potential concerns (AI-proposed, needs human review)

_None._


## 10. Remediation recommendations

1. Docker socket is mounted into the container: Remove the socket mount. If the service needs Docker metadata (e.g. a version/status page), give it a filtered read-only proxy such as tecnativa/docker-socket-proxy with POST=0 and only the needed API sections.
2. Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/results: Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.
3. Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/siem: Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.
4. Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/rsyslog: Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.
5. Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/logs/wazuh: Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.
6. Sensitive host path bind-mounted: /Users/mohamed_metwally/SeniorYear/Capstone/ICS-Exploitation-Capstone-2026/data/pcap (container is currently exited): Mount only the specific files needed, read-only (`:ro`), or use a named volume instead of a host path.
7. Container runs as root (container is currently exited): Add a non-root `USER` to the Dockerfile (or `user: "1000:1000"` in compose) and fix file ownership so the service runs unprivileged. Consider user-namespace remapping (`userns-remap`) on the daemon.
8. Container adds dangerous capabilities: NET_ADMIN, NET_RAW (container is currently exited): Remove capabilities that are not strictly required. Start from `cap_drop: [ALL]` and add back only what the service needs; if NET_ADMIN is only used at start-up (e.g. to add routes), configure networking outside the container instead.


## 11. Limitations and unknowns

- Metadata-only assessment: no runtime behaviour, network traffic or in-container files were inspected, and no active scanning was performed.
- Image vulnerabilities come from Trivy's database at scan time; exploitability depends on whether the vulnerable code is reachable, which was not tested.
- Secret values were redacted before analysis; credential findings are based on variable names and patterns only.
- Findings reflect the Docker state at the snapshot time only; historical runs are not evidence of current state.


## 12. Model and execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 1.15s / 0.69s / 0.0s / 0.0s |
| Tool calls (total / by agent / blocked) | 5 / 0 / 0 |
| Values redacted | 227 |
| Model requests | 0 |
| Tokens (in / out / total) | n/a / n/a / n/a |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |


**Tool calls by name:** `docker.container_list`×1, `docker.image_list`×1, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1
