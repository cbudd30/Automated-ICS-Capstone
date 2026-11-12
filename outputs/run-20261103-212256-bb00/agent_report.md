# Agent Security Assessment — `run-20261103-212256-bb00`

**Agent status:** ok · **Overall risk (agent):** CRITICAL · **Generated:** 2026-11-03 21:54 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v6 · **Snapshot:** `snap-69b1cd146a835f16`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. Every finding below passed evidence validation and still needs human review. What it missed is in `comparison.md`.

## 1. Summary

The Docker environment hosting the ICS lab has critical security gaps. Five containers (router, caldera, HMI, simulation, plc) run with elevated privileges (CAP_NET_ADMIN, root user) and expose sensitive networks (admin/ICS/DMZ). Image vulnerabilities are rampant: 195 in router, 1404 in caldera, 168 in HMI, 1600 in simulation, and 1599 in plc. The simulation and EWS containers have Docker socket mounts, enabling host-level control. Resource limits are missing across all containers, risking availability. Immediate remediation is required to prevent lateral movement and process disruption.

Findings: 29 (critical 14, high 8, medium 7) · rejected: 2 · out of scope: 0


## 2. Findings

#### 🔴 `F-AGENT-b34ca67d67` — Elevated Capabilities

- **Resource:** unknown `router`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`

**Why it matters:** CAP_NET_ADMIN and CAP_NET_RAW allow full network control and raw socket access, which could enable an attacker to manipulate routing tables or perform network-based attacks on the ICS network.

**Remediation:** Remove unnecessary capabilities by setting CapDrop instead of CapAdd in Docker Compose or CLI.

#### 🟠 `F-AGENT-5a35e3b0d7` — Multiple Network Exposure

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_b-ics-net, grficsv3_c-dmz-net` — value differs from the inspect data

**Why it matters:** The container bridges admin, ICS, and DMZ networks, creating a potential attack vector between network segments. ICS networks should be isolated from DMZ to prevent lateral movement.

**Remediation:** Use network segmentation with dedicated networks for each service and avoid multi-network containers.

**Validation:** some observed values differ from the inspect data

#### 🔴 `F-AGENT-889445787d` — Image Vulnerabilities

- **Resource:** unknown `router`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `vulnerability` = `CVE-2023-2953`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2026-100236`
  - `vulnerability` = `CVE-2026-11822`
  - `vulnerability` = `CVE-2026-12064`
  - `vulnerability` = `CVE-2026-13221`
  - `vulnerability` = `CVE-2026-16742`
  - `vulnerability` = `CVE-2026-42496`
  - `vulnerability` = `CVE-2026-42497`
  - `vulnerability` = `CVE-2026-53613`
  - `vulnerability` = `CVE-2026-54369`
  - `vulnerability` = `CVE-2026-6276`
  - `vulnerability` = `CVE-2026-7210`
  - `vulnerability` = `CVE-2026-76642`
  - `vulnerability` = `CVE-2026-77214`
  - `vulnerability` = `CVE-2026-78409`
  - `vulnerability` = `CVE-2026-78410`
  - `vulnerability` = `CVE-2026-8286`
  - `vulnerability` = `CVE-2026-8376`
  - `vulnerability` = `CVE-2026-8458`
  - `vulnerability` = `CVE-2026-86562`
  - `vulnerability` = `CVE-2026-86563`
  - `vulnerability` = `CVE-2026-86565`
  - `vulnerability` = `CVE-2026-86567`
  - `vulnerability` = `CVE-2026-86848`
  - `vulnerability` = `CVE-2026-8927`
  - `vulnerability` = `CVE-2026-9538`

**Why it matters:** The container image contains 195 high/critical vulnerabilities in core packages like perl, OpenSSL, and network utilities. Exploitation could lead to privilege escalation or network disruption in the ICS environment.

**Remediation:** Rebuild the image with updated packages or switch to a hardened base image. Apply network restrictions to limit exposure.

**Validation:** unverified fields ignored: batchID

**References:** CVE-2023-2953, CVE-2023-45853, CVE-2026-100236, CVE-2026-11822, CVE-2026-12064, CVE-2026-13221, CVE-2026-16742, CVE-2026-42496, CVE-2026-42497, CVE-2026-53613, CVE-2026-54369, CVE-2026-6276, CVE-2026-7210, CVE-2026-76642, CVE-2026-77214, CVE-2026-78409, CVE-2026-78410, CVE-2026-8286, CVE-2026-8376, CVE-2026-8458, CVE-2026-86562, CVE-2026-86563, CVE-2026-86565, CVE-2026-86567, CVE-2026-86848, CVE-2026-8927, CVE-2026-9538

#### 🟠 `F-AGENT-a151ce978c` — Root Privileges

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `''`

**Why it matters:** Running as root increases risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🟡 `F-AGENT-77817704e1` — Missing Resource Limits

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-ea8297eb0a` — Image Vulnerabilities

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `vulnerability` = `CVE-2022-23806`
  - `vulnerability` = `CVE-2023-24538`
  - `vulnerability` = `CVE-2023-24540`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2024-24790`
  - `vulnerability` = `CVE-2025-68121`
  - `vulnerability` = `CVE-2025-7458`
  - `vulnerability` = `CVE-2026-78667`
  - `vulnerability` = `CVE-2026-78669`

**Why it matters:** The container image contains 85 critical and 1319 high-severity vulnerabilities in core packages like golang, OpenSSL, and SQLite. Caldera is an attack framework; a compromised instance could exploit these to gain host-level access or disrupt the ICS network.

**Remediation:** Rebuild the image with updated packages or switch to a hardened base image. Remove the container from the admin network and restrict access to the DMZ network only.

**Validation:** unverified fields ignored: batchID

**References:** CVE-2022-23806, CVE-2023-24538, CVE-2023-24540, CVE-2023-45853, CVE-2024-24790, CVE-2025-68121, CVE-2025-7458, CVE-2026-78667, CVE-2026-78669

#### 🟠 `F-AGENT-c911bed87f` — Root Privileges

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `''`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🔴 `F-AGENT-2545e4e51f` — Network Exposure

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_c-dmz-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and DMZ networks. Caldera is an attack framework; its presence on the admin network could allow lateral movement to other critical ICS services.

**Remediation:** Isolate Caldera to the DMZ network only. Use network policies to restrict communication between networks.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-7af47036d6` — Missing Resource Limits

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-8e831c39b5` — Image Vulnerabilities

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `vulnerability` = `CVE-2017-15095`
  - `vulnerability` = `CVE-2017-17485`
  - `vulnerability` = `CVE-2017-7525`
  - `vulnerability` = `CVE-2018-11307`
  - `vulnerability` = `CVE-2018-14718`
  - `vulnerability` = `CVE-2018-14719`
  - `vulnerability` = `CVE-2018-14720`
  - `vulnerability` = `CVE-2018-14721`
  - `vulnerability` = `CVE-2018-19360`
  - `vulnerability` = `CVE-2018-19361`
  - `vulnerability` = `CVE-2018-19362`
  - `vulnerability` = `CVE-2018-7489`
  - `vulnerability` = `CVE-2019-14379`
  - `vulnerability` = `CVE-2019-14540`
  - `vulnerability` = `CVE-2019-16335`
  - `vulnerability` = `CVE-2019-16942`
  - `vulnerability` = `CVE-2019-16943`
  - `vulnerability` = `CVE-2019-17267`
  - `vulnerability` = `CVE-2019-17531`
  - `vulnerability` = `CVE-2019-20330`
  - `vulnerability` = `CVE-2020-35491`
  - `vulnerability` = `CVE-2020-36179`
  - `vulnerability` = `CVE-2020-8840`
  - `vulnerability` = `CVE-2020-9547`
  - `vulnerability` = `CVE-2020-9548`
  - `vulnerability` = `CVE-2022-22965`
  - `vulnerability` = `CVE-2022-22978`
  - `vulnerability` = `CVE-2022-23305`
  - `vulnerability` = `CVE-2022-23307`
  - `vulnerability` = `CVE-2026-22732`
  - `vulnerability` = `CVE-2026-34487`
  - `vulnerability` = `CVE-2026-41845`
  - `vulnerability` = `CVE-2026-43512`
  - `vulnerability` = `CVE-2026-43515`
  - `vulnerability` = `CVE-2026-44487`
  - `vulnerability` = `CVE-2026-45623`
  - `vulnerability` = `CVE-2026-47884`
  - `vulnerability` = `CVE-2026-54466`
  - `vulnerability` = `CVE-2026-65182`
  - `vulnerability` = `CVE-2026-65905`
  - `vulnerability` = `CVE-2026-68525`
  - `vulnerability` = `CVE-2026-69219`
  - `vulnerability` = `CVE-2026-91777`

**Why it matters:** The container image contains 86 critical and 159 high-severity vulnerabilities in Java libraries (e.g., Jackson, Tomcat, Spring) and Node.js packages. HMI systems are critical for operator interaction; a compromised HMI could allow attackers to manipulate process data or disrupt operations.

**Remediation:** Rebuild the image with updated libraries (e.g., Tomcat 9.0.118, Spring 5.2.20) and remove unnecessary capabilities like CAP_NET_ADMIN. Isolate the HMI to the admin network only.

**Validation:** unverified fields ignored: batchID

**References:** CVE-2017-15095, CVE-2017-17485, CVE-2017-7525, CVE-2018-11307, CVE-2018-14718, CVE-2018-14719, CVE-2018-14720, CVE-2018-14721, CVE-2018-19360, CVE-2018-19361, CVE-2018-19362, CVE-2018-7489, CVE-2019-14379, CVE-2019-14540, CVE-2019-16335, CVE-2019-16942, CVE-2019-16943, CVE-2019-17267, CVE-2019-17531, CVE-2019-20330, CVE-2020-35491, CVE-2020-36179, CVE-2020-8840, CVE-2020-9547, CVE-2020-9548, CVE-2022-22965, CVE-2022-22978, CVE-2022-23305, CVE-2022-23307, CVE-2026-22732, CVE-2026-34487, CVE-2026-41845, CVE-2026-43512, CVE-2026-43515, CVE-2026-44487, CVE-2026-45623, CVE-2026-47884, CVE-2026-54466, CVE-2026-65182, CVE-2026-65905, CVE-2026-68525, CVE-2026-69219, CVE-2026-91777

#### 🟠 `F-AGENT-9e92389a35` — Root Privileges

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `''`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🔴 `F-AGENT-be6b45227a` — Network Exposure

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_c-dmz-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and DMZ networks. HMI systems should be isolated to the admin network to prevent lateral movement from the DMZ.

**Remediation:** Remove the container from the DMZ network and ensure it's only on the admin network. Use network policies to restrict access.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-621d9a03e1` — Missing Resource Limits

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-742c8e37c2` — Network Exposure

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_c-dmz-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and DMZ networks. Kali Linux is a penetration testing tool; its presence on the admin network could allow lateral movement to other critical ICS services.

**Remediation:** Isolate Kali to the DMZ network only. Use network policies to restrict communication between networks.

**Validation:** some observed values differ from the inspect data

#### 🟠 `F-AGENT-06e8c4c933` — Root Privileges

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🟡 `F-AGENT-e4f6817362` — Missing Resource Limits

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-9f9707fa6d` — Image Vulnerabilities

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `vulnerability` = `CVE-2023-49569`
  - `vulnerability` = `CVE-2023-53867`
  - `vulnerability` = `CVE-2024-24790`
  - `vulnerability` = `CVE-2024-50286`
  - `vulnerability` = `CVE-2025-21613`
  - `vulnerability` = `CVE-2025-37777`
  - `vulnerability` = `CVE-2025-68121`
  - `vulnerability` = `CVE-2026-24049`
  - `vulnerability` = `CVE-2026-25681`
  - `vulnerability` = `CVE-2026-27136`
  - `vulnerability` = `CVE-2026-33186`
  - `vulnerability` = `CVE-2026-39828`
  - `vulnerability` = `CVE-2026-39830`
  - `vulnerability` = `CVE-2026-39831`
  - `vulnerability` = `CVE-2026-41066`
  - `vulnerability` = `CVE-2026-46597`
  - `vulnerability` = `CVE-2026-63825`
  - `vulnerability` = `CVE-2026-63940`
  - `vulnerability` = `CVE-2026-68426`
  - `vulnerability` = `CVE-2026-72399`
  - `vulnerability` = `CVE-2026-74345`
  - `vulnerability` = `CVE-2026-78669`
  - `vulnerability` = `CVE-2026-84445`
  - `vulnerability` = `CVE-2026-89530`
  - `vulnerability` = `CVE-2026-89652`
  - `vulnerability` = `CVE-2026-89659`
  - `vulnerability` = `CVE-2026-89708`
  - `vulnerability` = `CVE-2026-90037`
  - `vulnerability` = `CVE-2026-90162`
  - `vulnerability` = `CVE-2026-93221`
  - `vulnerability` = `CVE-2026-98365`

**Why it matters:** The container image contains 36 critical and 704 high-severity vulnerabilities in core packages like Linux kernel, Go, and Python. EWS is a critical component for operator workstations; a compromised EWS could allow attackers to execute arbitrary code or disrupt ICS operations.

**Remediation:** Rebuild the image with updated packages (e.g., Linux kernel 5.15.0-198.208+, Go 1.21.11+, Python 3.11.10+). Remove CAP_NET_ADMIN and isolate the container to the admin network only.

**Validation:** unverified fields ignored: batchID

**References:** CVE-2023-49569, CVE-2023-53867, CVE-2024-24790, CVE-2024-50286, CVE-2025-21613, CVE-2025-37777, CVE-2025-68121, CVE-2026-24049, CVE-2026-25681, CVE-2026-27136, CVE-2026-33186, CVE-2026-39828, CVE-2026-39830, CVE-2026-39831, CVE-2026-41066, CVE-2026-46597, CVE-2026-63825, CVE-2026-63940, CVE-2026-68426, CVE-2026-72399, CVE-2026-74345, CVE-2026-78669, CVE-2026-84445, CVE-2026-89530, CVE-2026-89652, CVE-2026-89659, CVE-2026-89708, CVE-2026-90037, CVE-2026-90162, CVE-2026-93221, CVE-2026-98365

#### 🟠 `F-AGENT-115d61a533` — Root Privileges

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🔴 `F-AGENT-a35139491a` — Network Exposure

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_b-ics-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and ICS networks. EWS workstations should be isolated to the admin network to prevent lateral movement to the ICS network.

**Remediation:** Remove the container from the ICS network and ensure it's only on the admin network. Use network policies to restrict access.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-622ea665f5` — Missing Resource Limits

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-64c9b49ecd` — Docker Socket Mount

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Source` = `/var/run/docker.sock`

**Why it matters:** Mounting the Docker socket allows the container to control the Docker host and manage other containers, creating a high-risk attack vector if compromised.

**Remediation:** Remove the Docker socket mount from the container configuration.

#### 🟠 `F-AGENT-074cc5cc68` — Root Privileges

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `''`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🔴 `F-AGENT-aa02774d6b` — Network Exposure

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_b-ics-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and ICS networks. Simulation containers should be isolated to the ICS network to prevent lateral movement to admin services.

**Remediation:** Remove the container from the admin network and ensure it's only on the ICS network. Use network policies to restrict communication.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-ff798e191b` — Missing Resource Limits

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-5dbf735580` — Image Vulnerabilities

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `vulnerability` = `CVE-2021-29921`
  - `vulnerability` = `CVE-2022-37454`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2024-47685`
  - `vulnerability` = `CVE-2024-56171`
  - `vulnerability` = `CVE-2026-13221`
  - `vulnerability` = `CVE-2026-23112`
  - `vulnerability` = `CVE-2026-33845`
  - `vulnerability` = `CVE-2026-40356`
  - `vulnerability` = `CVE-2026-42010`
  - `vulnerability` = `CVE-2026-42496`
  - `vulnerability` = `CVE-2026-43037`
  - `vulnerability` = `CVE-2026-54369`
  - `vulnerability` = `CVE-2026-6653`
  - `vulnerability` = `CVE-2026-68123`
  - `vulnerability` = `CVE-2026-68140`
  - `vulnerability` = `CVE-2026-74583`
  - `vulnerability` = `CVE-2026-8376`
  - `vulnerability` = `CVE-2026-89638`
  - `vulnerability` = `CVE-2026-89708`
  - `vulnerability` = `CVE-2026-90003`
  - `vulnerability` = `CVE-2026-90037`
  - `vulnerability` = `CVE-2026-93221`
  - `vulnerability` = `CVE-2026-98084`

**Why it matters:** The container image contains 55 critical and 1544 high-severity vulnerabilities in core packages like Linux kernel, OpenSSL, and Python. PLCs control physical processes; a compromised PLC could cause operational disruptions or safety incidents.

**Remediation:** Rebuild the image with updated packages (e.g., Linux kernel 5.10.257+, OpenSSL 3.0.19+, Python 3.9.2+). Remove CAP_NET_ADMIN and isolate the container to the ICS network only.

**Validation:** unverified fields ignored: batchID

**References:** CVE-2021-29921, CVE-2022-37454, CVE-2023-45853, CVE-2024-47685, CVE-2024-56171, CVE-2026-13221, CVE-2026-23112, CVE-2026-33845, CVE-2026-40356, CVE-2026-42010, CVE-2026-42496, CVE-2026-43037, CVE-2026-54369, CVE-2026-6653, CVE-2026-68123, CVE-2026-68140, CVE-2026-74583, CVE-2026-8376, CVE-2026-89638, CVE-2026-89708, CVE-2026-90003, CVE-2026-90037, CVE-2026-93221, CVE-2026-98084

#### 🟠 `F-AGENT-5dbd79bde1` — Root Privileges

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `''`

**Why it matters:** Running as root increases the risk of privilege escalation if any vulnerabilities exist in the container's software stack.

**Remediation:** Set a non-root user in Docker Compose or Dockerfile using the 'user' directive.

#### 🔴 `F-AGENT-8dbc3c9b4a` — Network Exposure

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** critical · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Networks` = `grficsv3_a-grfics-admin, grficsv3_b-ics-net` — value differs from the inspect data

**Why it matters:** The container is on both admin and ICS networks. PLCs should be isolated to the ICS network to prevent lateral movement from admin services.

**Remediation:** Remove the container from the admin network and ensure it's only on the ICS network. Use network policies to restrict access.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-b8dd4700f5` — Missing Resource Limits

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CpuShares` = `0`
  - `HostConfig.Memory` = `0`

**Why it matters:** Unbounded CPU and memory usage could allow resource exhaustion attacks against the ICS network.

**Remediation:** Add CPU and memory limits in Docker Compose or CLI with --memory and --cpu-shares.

#### 🔴 `F-AGENT-844939d47c` — Docker Socket Mounts

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Source` = `/var/run/docker.sock`
  - `Mounts[0].Source` = `/var/run/docker.sock`

**Why it matters:** Mounting the Docker socket in simulation and EWS containers grants full host control. A compromised container could manipulate other containers or the host OS.

**Remediation:** Remove Docker socket mounts from all containers. Use Docker API access controls or dedicated monitoring tools instead of direct socket access.


## 3. Rejected findings (failed evidence validation)

- **Image Vulnerabilities** (`simulation`): cites CVEs Trivy reported for other images, not simulation: CVE-2026-23449, CVE-2026-25681, CVE-2026-43049, CVE-2026-53375, CVE-2026-63819, CVE-2026-64394, CVE-2026-64557, CVE-2026-72110, CVE-2026-72338, CVE-2026-72380, CVE-2026-74506, CVE-2026-74510, CVE-2026-78669, CVE-2026-80837, CVE-2026-80864, CVE-2026-80883, CVE-2026-89537, CVE-2026-90104, CVE-2026-90321, CVE-2026-90392, CVE-2026-93787, CVE-2026-93796, CVE-2026-97530, CVE-2026-98104, CVE-2026-98107, CVE-2026-98260, CVE-2026-98332; unverified fields ignored: batchID
- **Multi-Network Bridging** (`grficsv3_a-grfics-admin`): no verifiable evidence (no matching field or vulnerability ID); unverified fields ignored: NetworkSettings.Networks, NetworkSettings.Networks, NetworkSettings.Networks


## 4. Recommendations

1. Isolate ICS containers to dedicated networks with no cross-segment communication (admin/ICS/DMZ separation).
2. Remove CAP_NET_ADMIN and other unnecessary capabilities from all containers.
3. Set non-root users in Docker Compose files (user directive) for all containers.
4. Add CPU and memory limits to all containers to prevent resource exhaustion.
5. Rebuild all images with updated packages (e.g., OpenSSL 3.0.19+, Python 3.11.10+).
6. Remove Docker socket mounts from simulation and EWS containers.


## 5. Limitations (stated by the agent)

- docker-audit-socket-proxy container was excluded as per user instructions.
- Some vulnerabilities (e.g., CVE-2026-84782) have no available fixes in the scanned images.
- Image rebuilds may require source access for non-ICS components like caldera and kali.


**Errors / notes during the run:**

- validation: finding 'Image Vulnerabilities' rejected: cites CVEs Trivy reported for other images, not simulation: CVE-2026-23449, CVE-2026-25681, CVE-2026-43049, CVE-2026-53375, CVE-2026-63819, CVE-2026-64394, CVE-2026-64557, CVE-2026-72110, CVE-2026-72338, CVE-2026-72380, CVE-2026-74506, CVE-2026-74510, CVE-2026-78669, CVE-2026-80837, CVE-2026-80864, CVE-2026-80883, CVE-2026-89537, CVE-2026-90104, CVE-2026-90321, CVE-2026-90392, CVE-2026-93787, CVE-2026-93796, CVE-2026-97530, CVE-2026-98104, CVE-2026-98107, CVE-2026-98260, CVE-2026-98332
- validation: finding 'Multi-Network Bridging' rejected: no verifiable evidence (no matching field or vulnerability ID)


## 6. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 1922.93s / 0.91s / 21.5s / 1899.96s |
| Tool calls (total / by agent / blocked) | 492 / 39 / 1 |
| Values redacted | 467 |
| Model requests | 40 |
| Tokens (in / out / total) | 1468798 / 31007 / 1499805 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×3, `docker.image_inspect`×7, `docker.image_list`×2, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×7, `trivy.findings_list`×446, `trivy.scan_image`×16, `trivy.trivy_version`×1
