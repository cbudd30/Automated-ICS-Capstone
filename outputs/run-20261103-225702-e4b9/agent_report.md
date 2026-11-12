# Agent Security Assessment — `run-20261103-225702-e4b9`

**Agent status:** ok · **Overall risk (agent):** CRITICAL · **Generated:** 2026-11-03 23:18 UTC

**Model:** `local-vllm` (vllm / `Qwen/Qwen3-32B`) · **Prompt:** v6 · **Snapshot:** `snap-17690ac30597eb8d`

> What the agent found by itself with read-only MCP tools. It did not see the deterministic findings. Every finding below passed evidence validation and still needs human review. What it missed is in `comparison.md`.

## 1. Summary

The Docker environment for the ICS lab exhibits multiple critical security weaknesses. Seven containers have exposed services with high-severity image vulnerabilities (e.g., WireGuard, VNC, web interfaces) that could be exploited to compromise ICS components. Elevated capabilities (CAP_NET_ADMIN) in five containers enable network manipulation, while four containers run as root with no resource limits, increasing availability risks. Attacker tools (Caldera, Kali) are co-located with ICS components in the DMZ network, creating lateral movement pathways. Immediate remediation is required to prevent remote exploitation of critical infrastructure.

Findings: 25 (critical 6, high 12, medium 7) · rejected: 4 · out of scope: 0


## 2. Findings

#### 🟠 `F-AGENT-4ba3fea9a8` — Elevated Network Capabilities

- **Resource:** unknown `router`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN, CAP_NET_RAW]`

**Why it matters:** CAP_NET_ADMIN and CAP_NET_RAW allow manipulation of network interfaces and raw socket access, increasing risk of network-based attacks on ICS systems.

**Remediation:** Remove CapAdd or replace with least-privilege capabilities. Use AppArmor/SELinux profiles to restrict network operations.

#### 🔴 `F-AGENT-8e162ad996` — Exposed ICS Network Services

- **Resource:** unknown `router`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.51820/udp` = `[{'HostIp': '0.0.0.0', 'HostPort': '51820'}, {'HostIp': '::', 'HostPort': '51820'}]`
  - `vulnerability` = `CVE-2023-2953`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2025-7458`
  - `vulnerability` = `CVE-2026-100236`
  - `vulnerability` = `CVE-2026-11940`
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
  - `vulnerability` = `CVE-2026-78408`
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

**Why it matters:** Published port 51820/udp (WireGuard) with 5 critical and 190+ high vulnerabilities in the image could allow remote exploitation of ICS network infrastructure.

**Remediation:** Remove unnecessary port exposure. Update image to patched version if available. Isolate ICS network from DMZ with network segmentation.

**References:** CVE-2023-2953, CVE-2023-45853, CVE-2025-7458, CVE-2026-100236, CVE-2026-11940, CVE-2026-13221, CVE-2026-16742, CVE-2026-42496, CVE-2026-42497, CVE-2026-53613, CVE-2026-54369, CVE-2026-6276, CVE-2026-7210, CVE-2026-76642, CVE-2026-77214, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410, CVE-2026-8286, CVE-2026-8376, CVE-2026-8458, CVE-2026-86562, CVE-2026-86563, CVE-2026-86565, CVE-2026-86567, CVE-2026-86848, CVE-2026-8927, CVE-2026-9538

#### 🟡 `F-AGENT-77817704e1` — Missing Resource Limits

- **Resource:** unknown `router`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks disrupting ICS network routing functions.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 512m, cpu_shares: 512

#### 🟠 `F-AGENT-18a40307cb` — Elevated Network Capabilities

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** CAP_NET_ADMIN allows network interface manipulation, increasing risk of ICS network disruption or eavesdropping.

**Remediation:** Remove CapAdd unless explicitly required. Use network policies to restrict traffic.

#### 🟠 `F-AGENT-2cda102cd8` — Running as Root User

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Root privileges in ICS workstations increase risk of privilege escalation to critical systems.

**Remediation:** Run container as non-root user. Set user: 'engineer' in Docker Compose.

#### 🟡 `F-AGENT-622ea665f5` — Missing Resource Limits

- **Resource:** unknown `EWS`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks disrupting ICS workstations.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 1g, cpu_shares: 512

#### 🔴 `F-AGENT-64c9b49ecd` — Docker Socket Mount

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Mounts[0].Source` = `/var/run/docker.sock`

**Why it matters:** Mounting the Docker socket allows container to control the Docker daemon, enabling container escape and arbitrary container creation.

**Remediation:** Remove the Docker socket mount unless absolutely required. Use Docker-in-Docker (dind) or other secure alternatives if needed.

#### 🟠 `F-AGENT-27ce9af58c` — Elevated Network Capabilities

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** CAP_NET_ADMIN allows network interface manipulation, increasing risk of ICS network disruption or eavesdropping.

**Remediation:** Remove CapAdd unless explicitly required. Use AppArmor/SELinux profiles to restrict network operations.

#### 🔴 `F-AGENT-bf3ee86cc9` — Exposed Web Service with Vulnerable Image

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.80/tcp` = `[{'HostIp': '0.0.0.0', 'HostPort': '80'}, {'HostIp': '::', 'HostPort': '80'}]`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2025-15467`
  - `vulnerability` = `CVE-2025-68973`
  - `vulnerability` = `CVE-2025-69720`
  - `vulnerability` = `CVE-2025-7458`
  - `vulnerability` = `CVE-2026-0799`
  - `vulnerability` = `CVE-2026-11940`
  - `vulnerability` = `CVE-2026-12064`
  - `vulnerability` = `CVE-2026-15176`
  - `vulnerability` = `CVE-2026-16742`
  - `vulnerability` = `CVE-2026-28388`
  - `vulnerability` = `CVE-2026-28389`
  - `vulnerability` = `CVE-2026-31789`
  - `vulnerability` = `CVE-2026-33845`
  - `vulnerability` = `CVE-2026-40355`
  - `vulnerability` = `CVE-2026-40356`
  - `vulnerability` = `CVE-2026-42009`
  - `vulnerability` = `CVE-2026-42010`
  - `vulnerability` = `CVE-2026-45447`
  - `vulnerability` = `CVE-2026-53613`
  - `vulnerability` = `CVE-2026-54369`
  - `vulnerability` = `CVE-2026-56153`
  - `vulnerability` = `CVE-2026-6276`
  - `vulnerability` = `CVE-2026-63292`
  - `vulnerability` = `CVE-2026-63686`
  - `vulnerability` = `CVE-2026-63718`
  - `vulnerability` = `CVE-2026-6653`
  - `vulnerability` = `CVE-2026-7210`
  - `vulnerability` = `CVE-2026-76642`
  - `vulnerability` = `CVE-2026-78408`
  - `vulnerability` = `CVE-2026-78409`
  - `vulnerability` = `CVE-2026-78410`
  - `vulnerability` = `CVE-2026-8286`
  - `vulnerability` = `CVE-2026-84782`
  - `vulnerability` = `CVE-2026-86138`
  - `vulnerability` = `CVE-2026-86142`
  - `vulnerability` = `CVE-2026-86143`
  - `vulnerability` = `CVE-2026-86144`
  - `vulnerability` = `CVE-2026-8927`
  - `vulnerability` = `CVE-2026-93479`
  - `vulnerability` = `CVE-2026-9538`
  - `vulnerability` = `CVE-2026-97205`
  - `vulnerability` = `CVE-2026-97687`
  - `vulnerability` = `CVE-2026-97689`

**Why it matters:** Published port 80/tcp (web service) with 7 critical and 157 high-severity vulnerabilities in the image could allow remote exploitation of ICS simulation components.

**Remediation:** Remove unnecessary port exposure. Update image to patched version if available. Add reverse proxy with authentication.

**References:** CVE-2023-45853, CVE-2025-15467, CVE-2025-68973, CVE-2025-69720, CVE-2025-7458, CVE-2026-0799, CVE-2026-11940, CVE-2026-12064, CVE-2026-15176, CVE-2026-16742, CVE-2026-28388, CVE-2026-28389, CVE-2026-31789, CVE-2026-33845, CVE-2026-40355, CVE-2026-40356, CVE-2026-42009, CVE-2026-42010, CVE-2026-45447, CVE-2026-53613, CVE-2026-54369, CVE-2026-56153, CVE-2026-6276, CVE-2026-63292, CVE-2026-63686, CVE-2026-63718, CVE-2026-6653, CVE-2026-7210, CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410, CVE-2026-8286, CVE-2026-84782, CVE-2026-86138, CVE-2026-86142, CVE-2026-86143, CVE-2026-86144, CVE-2026-8927, CVE-2026-93479, CVE-2026-9538, CVE-2026-97205, CVE-2026-97687, CVE-2026-97689

#### 🟠 `F-AGENT-652b63be13` — Running as Root User

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root` — value differs from the inspect data

**Why it matters:** Root privileges in ICS simulation containers increase risk of privilege escalation to critical systems.

**Remediation:** Run container as non-root user. Set user: 'ics_user' in Docker Compose.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-ff798e191b` — Missing Resource Limits

- **Resource:** unknown `simulation`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks disrupting ICS simulation services.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 1g, cpu_shares: 512

#### 🟠 `F-AGENT-8eb56f9fdf` — Elevated Network Capabilities

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** CAP_NET_ADMIN allows network interface manipulation, increasing risk of ICS network disruption or eavesdropping.

**Remediation:** Remove CapAdd unless explicitly required. Use AppArmor/SELinux profiles to restrict network operations.

#### 🟠 `F-AGENT-3766c3fa93` — Running as Root User

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root` — value differs from the inspect data

**Why it matters:** Root privileges in ICS PLC containers increase risk of privilege escalation to critical systems.

**Remediation:** Run container as non-root user. Set user: 'plc_user' in Docker Compose.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-b8dd4700f5` — Missing Resource Limits

- **Resource:** unknown `plc`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks disrupting ICS control logic.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 512m, cpu_shares: 512

#### 🔴 `F-AGENT-94cfa11769` — Exposed C2 Framework with Vulnerable Image

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.8888/tcp` = `[{'HostIp': '0.0.0.0', 'HostPort': '8888'}, {'HostIp': '::', 'HostPort': '8888'}]`
  - `vulnerability` = `CVE-2022-23806`
  - `vulnerability` = `CVE-2023-24538`
  - `vulnerability` = `CVE-2023-24540`
  - `vulnerability` = `CVE-2023-45853`
  - `vulnerability` = `CVE-2024-24790`
  - `vulnerability` = `CVE-2025-68121`
  - `vulnerability` = `CVE-2025-7458`

**Why it matters:** Published port 8888/tcp (Caldera C2 interface) with 85 critical and 1319 high-severity vulnerabilities in the image could allow remote exploitation of ICS attack simulation capabilities.

**Remediation:** Remove unnecessary port exposure. Update image to patched version if available. Add reverse proxy with authentication.

**References:** CVE-2022-23806, CVE-2023-24538, CVE-2023-24540, CVE-2023-45853, CVE-2024-24790, CVE-2025-68121, CVE-2025-7458

#### 🟠 `F-AGENT-e51514926e` — Running as Root User

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root` — value differs from the inspect data

**Why it matters:** Root privileges in C2 framework containers increase risk of privilege escalation to ICS systems during red team exercises.

**Remediation:** Run container as non-root user. Set user: 'caldera_user' in Docker Compose.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-7af47036d6` — Missing Resource Limits

- **Resource:** unknown `caldera`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks during active red team operations.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 1g, cpu_shares: 512

#### 🟠 `F-AGENT-fb22dc96a2` — Elevated Network Capabilities

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** CAP_NET_ADMIN allows network interface manipulation, increasing risk of ICS network disruption or eavesdropping.

**Remediation:** Remove CapAdd unless explicitly required. Use AppArmor/SELinux profiles to restrict network operations.

#### 🔴 `F-AGENT-8358ccfce1` — Exposed Attacker Tools with Vulnerable Image

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.6080/tcp` = `[{'HostIp': '0.0.0.0', 'HostPort': '6088'}, {'HostIp': '::', 'HostPort': '6088'}]`

**Why it matters:** Published port 6080/tcp (VNC) with no known vulnerabilities in the image, but as an attacker container, this could be used to exploit other ICS components.

**Remediation:** Remove unnecessary port exposure. Isolate attacker container in dedicated network segment.

#### 🟠 `F-AGENT-875a0eb5ad` — Running as Root User

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root`

**Why it matters:** Root privileges in attacker containers increase risk of privilege escalation to ICS systems.

**Remediation:** Run container as non-root user. Set user: 'kali_user' in Docker Compose.

#### 🟡 `F-AGENT-e4f6817362` — Missing Resource Limits

- **Resource:** unknown `kali`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks during red team operations.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 1g, cpu_shares: 512

#### 🟠 `F-AGENT-b0a282b9d9` — Elevated Network Capabilities

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.CapAdd` = `[CAP_NET_ADMIN]`

**Why it matters:** CAP_NET_ADMIN allows network interface manipulation, increasing risk of ICS network disruption or eavesdropping.

**Remediation:** Remove CapAdd unless explicitly required. Use AppArmor/SELinux profiles to restrict network operations.

#### 🔴 `F-AGENT-317afdd2d3` — Exposed HMI Web Interface with Vulnerable Image

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** critical · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `NetworkSettings.Ports.8080/tcp` = `[{'HostIp': '0.0.0.0', 'HostPort': '6081'}, {'HostIp': '::', 'HostPort': '6081'}]`
  - `vulnerability` = `CVE-2016-1000031`
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
  - `vulnerability` = `CVE-2018-8088`
  - `vulnerability` = `CVE-2019-14379`
  - `vulnerability` = `CVE-2019-14540`
  - `vulnerability` = `CVE-2019-16335`
  - `vulnerability` = `CVE-2019-16942`
  - `vulnerability` = `CVE-2019-16943`
  - `vulnerability` = `CVE-2019-17267`
  - `vulnerability` = `CVE-2019-17531`
  - `vulnerability` = `CVE-2019-20330`
  - `vulnerability` = `CVE-2020-8840`
  - `vulnerability` = `CVE-2020-9547`
  - `vulnerability` = `CVE-2020-9548`
  - `vulnerability` = `CVE-2022-22965`
  - `vulnerability` = `CVE-2022-22978`
  - `vulnerability` = `CVE-2022-23305`
  - `vulnerability` = `CVE-2022-23307`
  - `vulnerability` = `CVE-2022-46337`
  - `vulnerability` = `CVE-2023-40743`
  - `vulnerability` = `CVE-2026-22732`
  - `vulnerability` = `CVE-2026-29145`
  - `vulnerability` = `CVE-2026-34487`
  - `vulnerability` = `CVE-2026-41293`
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
  - `vulnerability` = `CVE-2026-84939`

**Why it matters:** Published port 8080/tcp (HMI web interface) with 86 critical and 159 high-severity vulnerabilities in the image could allow remote exploitation of ICS human-machine interface systems.

**Remediation:** Remove unnecessary port exposure. Update image to patched version if available. Add reverse proxy with authentication.

**References:** CVE-2016-1000031, CVE-2017-15095, CVE-2017-17485, CVE-2017-7525, CVE-2018-11307, CVE-2018-14718, CVE-2018-14719, CVE-2018-14720, CVE-2018-14721, CVE-2018-19360, CVE-2018-19361, CVE-2018-19362, CVE-2018-7489, CVE-2018-8088, CVE-2019-14379, CVE-2019-14540, CVE-2019-16335, CVE-2019-16942, CVE-2019-16943, CVE-2019-17267, CVE-2019-17531, CVE-2019-20330, CVE-2020-8840, CVE-2020-9547, CVE-2020-9548, CVE-2022-22965, CVE-2022-22978, CVE-2022-23305, CVE-2022-23307, CVE-2022-46337, CVE-2023-40743, CVE-2026-22732, CVE-2026-29145, CVE-2026-34487, CVE-2026-41293, CVE-2026-41845, CVE-2026-43512, CVE-2026-43515, CVE-2026-44487, CVE-2026-45623, CVE-2026-47884, CVE-2026-54466, CVE-2026-65182, CVE-2026-65905, CVE-2026-68525, CVE-2026-69219, CVE-2026-84939

#### 🟠 `F-AGENT-01a6c3ac51` — Running as Root User

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** high · **Confidence:** low · **Status:** potential (agent)
- **Evidence:**
  - `Config.User` = `root` — value differs from the inspect data

**Why it matters:** Root privileges in HMI containers increase risk of privilege escalation to ICS systems.

**Remediation:** Run container as non-root user. Set user: 'hmi_user' in Docker Compose.

**Validation:** some observed values differ from the inspect data

#### 🟡 `F-AGENT-621d9a03e1` — Missing Resource Limits

- **Resource:** unknown `HMI`
- **Category:** other · **Severity:** medium · **Confidence:** medium · **Status:** potential (agent)
- **Evidence:**
  - `HostConfig.Memory` = `0`
  - `HostConfig.CpuShares` = `0`

**Why it matters:** Unlimited CPU and memory access could allow resource exhaustion attacks disrupting ICS interface operations.

**Remediation:** Set memory and CPU limits in Docker Compose. Example: mem_limit: 1g, cpu_shares: 512


## 3. Rejected findings (failed evidence validation)

- **Exposed VNC Service with Vulnerable Image** (`EWS`): cites CVEs Trivy reported for other images, not EWS: CVE-2026-77214
- **Exposed PLC Web Interface with Vulnerable Image** (`plc`): cites CVEs Trivy reported for other images, not plc: CVE-2024-24790, CVE-2025-15467, CVE-2025-68121, CVE-2025-7458, CVE-2026-25681, CVE-2026-27136, CVE-2026-31789, CVE-2026-33186, CVE-2026-33811, CVE-2026-33814, CVE-2026-39821, CVE-2026-39822, CVE-2026-39828, CVE-2026-39830, CVE-2026-39831, CVE-2026-39836, CVE-2026-56859, CVE-2026-78669, CVE-2026-84445
- **ICS Network Bridging to DMZ** (`grficsv3_c-dmz-net`): no verifiable evidence (no matching field or vulnerability ID); unverified fields ignored: Containers.cba2c488717af6448d81034a09129be82a54bbb912f3f332a5abb731b8cff7b4.IPv4Address
- **Attacker Tools in DMZ Network** (`grficsv3_c-dmz-net`): no verifiable evidence (no matching field or vulnerability ID); unverified fields ignored: Containers.14d047f6fd94a6e96c6d94e9cf700ce23ba0cf4e7a053bfbaa0ba5792989b549.Name, Containers.177d6da7db5366f529de6517fff3420ae9db254ea22d077be65f438a4d75293b.Name


## 4. Recommendations

1. Remove all unnecessary port exposures (e.g., 51820/udp, 6080/tcp, 8080/tcp) to limit attack surface
2. Update all container images to patched versions (e.g., fortiphyd/grfics-router, grfics-scadalts) or rebuild with updated dependencies
3. Replace elevated capabilities (CAP_NET_ADMIN) with AppArmor/SELinux profiles for least-privilege access
4. Set memory and CPU limits for all containers (e.g., mem_limit: 1g, cpu_shares: 512) to prevent resource exhaustion
5. Run containers as non-root users (e.g., user: 'ics_user') to reduce privilege escalation risks
6. Isolate attacker tools (Caldera, Kali) in a dedicated network with no access to ICS components


## 5. Limitations (stated by the agent)

- Cannot verify stopped containers or historical configurations
- Some vulnerabilities have no available fixes (e.g., CVE-2022-23305 in log4j)
- Network segmentation policies cannot be verified without inspecting firewall rules


**Errors / notes during the run:**

- validation: finding 'Exposed VNC Service with Vulnerable Image' rejected: cites CVEs Trivy reported for other images, not EWS: CVE-2026-77214
- validation: finding 'Exposed PLC Web Interface with Vulnerable Image' rejected: cites CVEs Trivy reported for other images, not plc: CVE-2024-24790, CVE-2025-15467, CVE-2025-68121, CVE-2025-7458, CVE-2026-25681, CVE-2026-27136, CVE-2026-31789, CVE-2026-33186, CVE-2026-33811, CVE-2026-33814, CVE-2026-39821, CVE-2026-39822, CVE-2026-39828, CVE-2026-39830, CVE-2026-39831, CVE-2026-39836, CVE-2026-56859, CVE-2026-78669, CVE-2026-84445
- validation: finding 'ICS Network Bridging to DMZ' rejected: no verifiable evidence (no matching field or vulnerability ID)
- validation: finding 'Attacker Tools in DMZ Network' rejected: no verifiable evidence (no matching field or vulnerability ID)
- validation: finding 'ICS Network Bridging to DMZ' on grficsv3_c-dmz-net reported twice; duplicate dropped
- validation: finding 'Attacker Tools in DMZ Network' on grficsv3_c-dmz-net reported twice; duplicate dropped


## 6. Execution metrics

| Metric | Value |
|---|---|
| Duration (total / collect / scan / agent) | 1299.91s / 1.05s / 24.68s / 1273.44s |
| Tool calls (total / by agent / blocked) | 493 / 40 / 0 |
| Values redacted | 313 |
| Model requests | 41 |
| Tokens (in / out / total) | 1511556 / 29449 / 1541005 |


**MCP servers:**

| Server | Role | Version | Connected | Approved tools |
|---|---|---|---|---|
| docker | docker_inspection | docker-mcp-server==2.2.7 | yes | container_list, container_inspect, image_list, image_inspect, image_history, network_list, network_inspect, volume_list, volume_inspect, system_info, system_version |
| trivy | image_scanner | v0.68.2 | yes | scan_image, findings_list, findings_get, trivy_version |


**Tool calls by name:** `docker.container_inspect`×7, `docker.container_list`×2, `docker.image_inspect`×7, `docker.image_list`×1, `docker.network_inspect`×3, `docker.network_list`×1, `docker.system_version`×1, `docker.volume_list`×1, `harness.record_container_section`×8, `trivy.findings_list`×446, `trivy.scan_image`×15, `trivy.trivy_version`×1
