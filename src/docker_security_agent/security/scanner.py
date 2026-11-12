"""Deterministic image scanning through the trivy-mcp server.

The application scans images itself (instead of hoping the LLM remembers to)
for two reasons:

* **Completeness** - every report contains vulnerability data for every
  in-scope image, regardless of how capable the model is.
* **Traceability** - results are stored per run and snapshot, so every
  report's vulnerability data can be traced back to the scan that produced it.

Flow per image:  scan_image -> batch_id -> findings_list (paginate) -> records.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from docker_security_agent.config import ScanConfig
from docker_security_agent.mcp.servers import GuardedMCPServer, ToolCallFailed
from docker_security_agent.schemas.assets import ImageAsset, InventorySnapshot
from docker_security_agent.schemas.observations import ImageScanResult, VulnerabilityRecord
from docker_security_agent.security.vulnerability_parser import (
    count_by_severity,
    parse_findings_page,
    parse_scan_summary,
)

# Safety valve against a server that keeps returning a next_token forever.
MAX_PAGES = 200


def select_images(snapshot: InventorySnapshot, scan_cfg: ScanConfig) -> list[ImageAsset]:
    """Images to scan: those used by containers (default) or all local images."""
    if scan_cfg.scope == "all":
        images = list(snapshot.images)
    else:
        used = set(snapshot.used_image_ids())
        images = [i for i in snapshot.images if i.id in used]
    if scan_cfg.max_images > 0:
        images = images[: scan_cfg.max_images]
    return images


def scan_target(image: ImageAsset) -> str:
    """Reference passed to Trivy: a tag if the image has one, else its ID."""
    return image.tags[0] if image.tags else image.id


async def trivy_version(trivy: GuardedMCPServer) -> str:
    try:
        items = await trivy.collect("trivy_version", {})
    except ToolCallFailed:
        return ""
    first = items[0] if items else ""
    return first if isinstance(first, str) else str(first)


async def scan_image(
    trivy: GuardedMCPServer,
    image: ImageAsset,
    scan_cfg: ScanConfig,
    scanner_version: str,
) -> ImageScanResult:
    """Scan one image and collect every vulnerability (all pages)."""
    started = time.perf_counter()
    target = scan_target(image)
    result = ImageScanResult(
        image_id=image.id,
        image_ref=target,
        digest=image.digest,
        scanner_version=scanner_version,
        scanned_at=datetime.now(UTC),
    )
    try:
        summary_items = await trivy.collect(
            "scan_image",
            {
                "target": target,
                "targetType": "image",
                "scanType": ["vuln"],
                "severities": scan_cfg.severities,
                "outputFormat": "json",
                "fixedOnly": False,
            },
        )
        summary: dict[str, Any] = next((i for i in summary_items if isinstance(i, dict)), {})
        batch_id, summary_counts = parse_scan_summary(summary)
        if not batch_id:
            raise ToolCallFailed(f"scan_image returned no batch_id: {str(summary)[:300]}")

        vulns: dict[str, VulnerabilityRecord] = {}
        token: str | None = None
        for _ in range(MAX_PAGES):
            args: dict[str, Any] = {
                "batchID": batch_id,
                "categories": ["vuln"],
                "minSeverity": "UNKNOWN",
                "limit": scan_cfg.page_size,
            }
            if token:
                args["token"] = token
            page_items = await trivy.collect("findings_list", args)
            page = next((i for i in page_items if isinstance(i, dict)), {})
            records, token = parse_findings_page(page)
            for r in records:
                # Same CVE can appear for several packages; key on the finding key.
                vulns[r.finding_key or f"{r.vuln_id}|{r.package}|{r.target}"] = r
            if not token:
                break

        result.vulnerabilities = list(vulns.values())
        result.counts = count_by_severity(result.vulnerabilities)
        # Cross-check: the scan summary and the paged findings should agree.
        if sum(summary_counts.values()) != len(result.vulnerabilities):
            result.error = (
                f"note: summary reported {sum(summary_counts.values())} findings, "
                f"{len(result.vulnerabilities)} retrieved"
            )
    except ToolCallFailed as exc:
        result.status = "error"
        result.error = str(exc)[:1000]
    result.duration_seconds = round(time.perf_counter() - started, 2)
    return result


async def scan_images(
    trivy: GuardedMCPServer,
    snapshot: InventorySnapshot,
    scan_cfg: ScanConfig,
    progress: Any = None,
) -> list[ImageScanResult]:
    """Scan all in-scope images sequentially. ``progress(i, n, name)`` is optional."""
    version = await trivy_version(trivy)
    images = select_images(snapshot, scan_cfg)
    results = []
    for idx, image in enumerate(images, start=1):
        if progress:
            progress(idx, len(images), image.display_name)
        results.append(await scan_image(trivy, image, scan_cfg, version))
    return results
