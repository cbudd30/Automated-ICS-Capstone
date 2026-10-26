"""Deterministic network scanning with nmap.

Mirrors scanner.py (Trivy) in structure: one function scans one target and
returns a ``NetworkScanResult``; a higher-level function iterates over all
Docker network subnets discovered in the inventory snapshot.

Design decisions
----------------
* **ICS-safe by default** - only TCP connect scans (-sT) are used so no root
  privilege is required and SYN/FIN/XMAS probes that can crash PLCs are never
  sent. UDP is opt-in and only for specific ICS ports.
* **Target restriction** - only subnets present in the inventory snapshot are
  scanned. Arbitrary targets cannot be injected.
* **NSE scripts** - a curated allowlist of safe, read-only ICS discovery
  scripts is run after the port scan. Exploit/dos/intrusive categories are
  never used.
* **XML output** - nmap's -oX flag produces machine-readable output; we parse
  it with the stdlib xml.etree module (no extra dependencies).
* **Reproducibility** - results are stored in SQLite so replay mode can re-use
  them without rescanning (same pattern as ImageScanResult).

ICS ports scanned by default (see ICS_PORTS below):
  502   Modbus TCP
  102   Siemens S7comm (ISO-TSAP)
  44818 EtherNet/IP
  47808 BACnet/IP
  20000 DNP3
  4840  OPC UA
  1911  Niagara Fox
  9600  OMRON FINS
"""

from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.network import (
    ICSProtocolHit,
    NetworkScanResult,
    PortRecord,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NMAP_BINARY = "nmap"

# ICS/OT protocol ports (TCP unless noted). Only these are scanned by default
# so we don't hammer the lab with a full port sweep.
ICS_PORTS: list[int] = [
    102,    # Siemens S7comm (ISO-TSAP)
    502,    # Modbus TCP
    4840,   # OPC UA
    9600,   # OMRON FINS
    20000,  # DNP3
    44818,  # EtherNet/IP / CIP
    47808,  # BACnet/IP
    1911,   # Niagara Fox
    2222,   # EtherNet/IP (alt)
    18245,  # GE SRTP
]

# Common IT service ports also checked (exposure matters for network segmentation)
IT_PORTS: list[int] = [
    21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888,
]

# NSE scripts that are safe to run on ICS networks (read-only discovery only)
ICS_NSE_SCRIPTS = [
    "modbus-discover",
    "s7-info",
    "enip-info",
    "dnp3-info",
    "bacnet-info",
    "opcua-node-info",
]

# Map from NSE script ID to human-readable protocol name
SCRIPT_TO_PROTOCOL: dict[str, str] = {
    "modbus-discover": "modbus",
    "s7-info":         "s7comm",
    "enip-info":       "enip",
    "dnp3-info":       "dnp3",
    "bacnet-info":     "bacnet",
    "opcua-node-info": "opcua",
}

# Nmap timing template: T2 (polite) to avoid overwhelming ICS devices.
# T3 (normal) is used for IT-only subnets.
ICS_TIMING = "T2"
IT_TIMING  = "T3"

# Hard cap on how many hosts we will scan in one call (safety valve)
MAX_HOSTS_PER_SCAN = 256


# ---------------------------------------------------------------------------
# nmap availability check
# ---------------------------------------------------------------------------


def nmap_available() -> bool:
    """Return True if nmap is on PATH."""
    return shutil.which(NMAP_BINARY) is not None


def nmap_version() -> str:
    """Return the nmap version string, or '' if nmap is not installed."""
    if not nmap_available():
        return ""
    try:
        proc = subprocess.run(
            [NMAP_BINARY, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # First line: "Nmap 7.94 ( https://nmap.org )"
        return proc.stdout.splitlines()[0] if proc.stdout else ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def _parse_scripts(elem: ET.Element) -> dict[str, str]:
    """Extract NSE script output from a <port> or <host> element."""
    return {
        script.get("id", ""): script.get("output", "")
        for script in elem.findall("script")
    }


def _parse_port(host_addr: str, port_elem: ET.Element) -> PortRecord | None:
    """Parse one <port> element into a PortRecord. Returns None if not open."""
    state_elem = port_elem.find("state")
    if state_elem is None:
        return None
    state = state_elem.get("state", "")
    if "open" not in state:
        return None

    protocol = port_elem.get("protocol", "tcp")
    portid   = int(port_elem.get("portid", "0"))

    service_elem = port_elem.find("service")
    service  = ""
    product  = ""
    version  = ""
    extra    = ""
    if service_elem is not None:
        service = service_elem.get("name", "")
        product = service_elem.get("product", "")
        version = service_elem.get("version", "")
        extra   = service_elem.get("extrainfo", "")

    scripts = _parse_scripts(port_elem)

    return PortRecord(
        host=host_addr,
        port=portid,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        extra_info=extra,
        scripts=scripts,
    )


def _extract_ics_hits(port: PortRecord) -> list[ICSProtocolHit]:
    """Turn NSE script output on a port into ICSProtocolHit records."""
    hits: list[ICSProtocolHit] = []
    for script_id, output in port.scripts.items():
        if script_id in SCRIPT_TO_PROTOCOL and output.strip():
            hits.append(
                ICSProtocolHit(
                    host=port.host,
                    port=port.port,
                    protocol_name=SCRIPT_TO_PROTOCOL[script_id],
                    script_id=script_id,
                    raw_output=output.strip(),
                )
            )
    return hits


def parse_nmap_xml(xml_text: str, target: str, scan_args: str) -> NetworkScanResult:
    """Parse nmap XML output into a NetworkScanResult."""
    result = NetworkScanResult(
        target=target,
        scan_args=scan_args,
        scanned_at=datetime.now(UTC),
    )
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result.status = "error"
        result.error  = f"XML parse error: {exc}"
        return result

    # Scanner version from the <nmaprun> element
    result.scanner_version = root.get("version", "")

    hosts_up = 0
    hosts_scanned = 0
    open_ports: list[PortRecord] = []
    ics_hits:   list[ICSProtocolHit] = []

    for host_elem in root.findall("host"):
        hosts_scanned += 1
        status_elem = host_elem.find("status")
        if status_elem is not None and status_elem.get("state") == "up":
            hosts_up += 1

        # Determine host address (prefer IPv4)
        addr = ""
        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr_elem.get("addr", "")
                break

        ports_elem = host_elem.find("ports")
        if ports_elem is None or not addr:
            continue

        for port_elem in ports_elem.findall("port"):
            port = _parse_port(addr, port_elem)
            if port is None:
                continue
            open_ports.append(port)
            ics_hits.extend(_extract_ics_hits(port))

    result.hosts_up      = hosts_up
    result.hosts_scanned = hosts_scanned
    result.open_ports    = open_ports
    result.ics_hits      = ics_hits

    # Summary counts
    by_service: dict[str, int] = {}
    for p in open_ports:
        key = p.service or f"port/{p.port}"
        by_service[key] = by_service.get(key, 0) + 1
    result.counts = {
        "hosts_up":    hosts_up,
        "open_ports":  len(open_ports),
        "ics_protocols_detected": len(ics_hits),
        "by_service":  by_service,
    }
    return result


# ---------------------------------------------------------------------------
# Running nmap
# ---------------------------------------------------------------------------


def _build_nmap_args(
    target: str,
    *,
    ports: list[int],
    timing: str,
    run_scripts: bool,
    output_file: str,
) -> list[str]:
    """Construct the nmap command. TCP connect scan only (-sT, no root needed)."""
    port_str = ",".join(str(p) for p in sorted(set(ports)))
    args = [
        NMAP_BINARY,
        "-sT",            # TCP connect scan (no root required, ICS-safe)
        "-sV",            # service/version detection
        "--version-intensity", "2",   # low intensity - gentler on ICS devices
        f"-{timing}",     # timing template
        "-p", port_str,
        "--open",         # only report open ports
        "-oX", output_file,
    ]
    if run_scripts:
        script_list = ",".join(ICS_NSE_SCRIPTS)
        args += ["--script", script_list]
    args.append(target)
    return args


def scan_target(
    target: str,
    *,
    ports: list[int] | None = None,
    timing: str = ICS_TIMING,
    run_scripts: bool = True,
    timeout_seconds: float = 300.0,
    tmp_dir: str | None = None,
) -> NetworkScanResult:
    """Run nmap against ``target`` and return a ``NetworkScanResult``.

    Args:
        target:          CIDR or hostname (e.g. "172.20.0.0/24").
        ports:           Port list; defaults to ICS_PORTS + IT_PORTS.
        timing:          nmap timing template name, e.g. "T2".
        run_scripts:     Whether to run ICS NSE scripts after the port scan.
        timeout_seconds: Hard wall-clock limit for the nmap subprocess.
        tmp_dir:         Directory for the temporary XML output file.
    """
    if not nmap_available():
        return NetworkScanResult(
            target=target,
            status="error",
            error="nmap is not installed or not on PATH",
        )

    scan_ports = ports if ports is not None else (ICS_PORTS + IT_PORTS)
    started    = time.perf_counter()

    # Write nmap output to a temp file so we can parse it even if stdout is noisy
    tmp_path = Path(tmp_dir or "/tmp") / f"nmap_scan_{int(started)}.xml"
    nmap_args = _build_nmap_args(
        target,
        ports=scan_ports,
        timing=timing,
        run_scripts=run_scripts,
        output_file=str(tmp_path),
    )
    scan_args_str = " ".join(nmap_args[1:])  # strip binary name for logging

    try:
        proc = subprocess.run(
            nmap_args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if proc.returncode != 0:
            return NetworkScanResult(
                target=target,
                scan_args=scan_args_str,
                status="error",
                error=f"nmap exited with code {proc.returncode}: {proc.stderr.strip()[:500]}",
                duration_seconds=round(time.perf_counter() - started, 2),
            )

        xml_text = tmp_path.read_text(encoding="utf-8") if tmp_path.exists() else ""
        if not xml_text:
            return NetworkScanResult(
                target=target,
                scan_args=scan_args_str,
                status="error",
                error="nmap produced no XML output",
                duration_seconds=round(time.perf_counter() - started, 2),
            )

        result = parse_nmap_xml(xml_text, target=target, scan_args=scan_args_str)
        result.duration_seconds = round(time.perf_counter() - started, 2)
        return result

    except subprocess.TimeoutExpired:
        return NetworkScanResult(
            target=target,
            scan_args=scan_args_str,
            status="error",
            error=f"nmap scan timed out after {timeout_seconds:.0f}s",
            duration_seconds=round(time.perf_counter() - started, 2),
        )
    except Exception as exc:
        return NetworkScanResult(
            target=target,
            scan_args=scan_args_str,
            status="error",
            error=f"{type(exc).__name__}: {exc}",
            duration_seconds=round(time.perf_counter() - started, 2),
        )
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Scanning all Docker network subnets
# ---------------------------------------------------------------------------


def subnets_from_snapshot(snapshot: InventorySnapshot) -> list[str]:
    """Return all non-default-bridge subnets from the inventory snapshot."""
    subnets: list[str] = []
    for net in snapshot.networks:
        # Skip the default bridge (usually 172.17.0.0/16) - it's Docker-internal
        if net.name == "bridge":
            continue
        for subnet in net.subnets:
            # Safety: only scan /24 or smaller to respect MAX_HOSTS_PER_SCAN
            # Larger subnets would need to be split; skip them with a warning.
            prefix = int(subnet.split("/")[-1]) if "/" in subnet else 32
            if prefix >= 24:
                subnets.append(subnet)
    return subnets


def scan_network_subnets(
    snapshot: InventorySnapshot,
    *,
    timeout_per_subnet_seconds: float = 300.0,
    progress: object = None,
) -> list[NetworkScanResult]:
    """Scan every non-bridge Docker subnet found in the inventory snapshot.

    ``progress(i, n, subnet)`` is called before each scan if provided.
    Returns one ``NetworkScanResult`` per subnet (including error results).
    """
    scanner_ver = nmap_version()
    subnets     = subnets_from_snapshot(snapshot)
    results: list[NetworkScanResult] = []

    for idx, subnet in enumerate(subnets, start=1):
        if progress:
            progress(idx, len(subnets), subnet)
        result = scan_target(
            subnet,
            timeout_seconds=timeout_per_subnet_seconds,
        )
        result.snapshot_id      = snapshot.snapshot_id
        result.scanner_version  = result.scanner_version or scanner_ver
        results.append(result)

    return results
