"""One assessment run, end to end.

``run_assessment`` is what ``docker-audit assess`` calls. Reading it top to
bottom gives the whole workflow:

    0. preflight      validate the model profile (capability check) and,
                      for live runs, that Docker is reached via the read-only
                      proxy; install the Trivy plugin / DB if needed
    1. record run     create the `runs` row (status=running)
    2. deterministic  LIVE:   connect MCP servers -> collect inventory snapshot
       evidence               -> run deterministic rules -> scan images
                      REPLAY: load a stored snapshot + its stored scans
                              (no Docker access at all; --no-agent only)
    2b. manifest      freeze the immutable run manifest (config + pinned
                      evidence) -> outputs/<run_id>/manifest.json + SQLite
                      (with --range-baseline: the live range must first match
                      the named baseline, else the run aborts before scanning)
    3. agent          run DockerSecurityAssessmentAgent with the MCP tools
                      ONLY. It never sees step 2's results: it discovers the
                      environment itself and reports its own findings
    4. validate       check the agent's findings against step 2's evidence
    5. compare        agent findings vs deterministic findings (answer key):
                      found / missed / outside the rules / rejected + scores
    6. persist        findings, scans, tool calls, metrics, reports -> SQLite
    7. reports        outputs/<run_id>/deterministic_report.{json,md} always;
                      agent_report.{json,md} + comparison.{json,md} with an agent

Step 2 runs first because the agent's guard rails need it: the tool policy
only lets Trivy scan images in the inventory, and validation checks the
agent's claims against it. The agent itself gets none of it.

Modes
-----
* ``live``          - default; collects fresh evidence from Docker and runs
                      the agent.
* ``deterministic`` - ``--no-agent``; rules + scanner only, no LLM.
* ``replay``        - ``--no-agent --snapshot ID``; re-runs the rules on stored
                      evidence. Agent runs cannot be replayed (the agent needs
                      live MCP tools); compare models by resetting the range
                      (deploy/grfics/range.sh) before each live run instead.
"""

from __future__ import annotations

import fnmatch
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from agents import set_tracing_disabled

from docker_security_agent import PROMPT_VERSION
from docker_security_agent.agents.security_assessment import (
    AgentRunOutcome,
    build_agent,
    build_input,
    run_agent,
)
from docker_security_agent.config import ConfigError, Settings
from docker_security_agent.inventory.baseline import (
    RangeBaseline,
    latest_reset,
    load_baseline,
    save_verification,
)
from docker_security_agent.inventory.baseline import verify as verify_range
from docker_security_agent.inventory.collector import collect_snapshot
from docker_security_agent.llm.capabilities import check_profile
from docker_security_agent.llm.factory import ModelBundle, build_model
from docker_security_agent.manifest import (
    RangeCheck,
    RangeRef,
    ReplayOf,
    RunManifest,
    apply_manifest,
    build_manifest,
    drift,
    manifest_document,
    parse_manifest_document,
    write_manifest,
)
from docker_security_agent.mcp.policy import ToolPolicy
from docker_security_agent.mcp.recorder import ToolCallRecorder
from docker_security_agent.mcp.redaction import Redactor
from docker_security_agent.mcp.registry import (
    build_servers,
    check_docker_endpoint,
    connect,
    download_trivy_db,
    ensure_server_setup,
    trivy_db_status,
)
from docker_security_agent.mcp.servers import GuardedMCPServer
from docker_security_agent.memory.repository import AssessmentRepository
from docker_security_agent.memory.sessions import open_session
from docker_security_agent.reporting.agent_report import build_agent_report, write_agent_report
from docker_security_agent.reporting.comparison_report import write_comparison
from docker_security_agent.reporting.generator import build_report, write_report
from docker_security_agent.schemas.assets import InventorySnapshot
from docker_security_agent.schemas.observations import ImageScanResult
from docker_security_agent.schemas.reports import (
    AgentReport,
    Comparison,
    DockerEndpointInfo,
    MCPServerInfo,
    ModelInfo,
    Report,
    RunMetrics,
)
from docker_security_agent.security import rules
from docker_security_agent.security.comparison import compare
from docker_security_agent.security.scanner import scan_images, trivy_version
from docker_security_agent.security.validation import ValidationOutcome, validate_agent_output
from docker_security_agent.security.vulnerability_parser import vulnerability_findings


class AssessmentAborted(Exception):
    """Preflight or evidence collection failed in a way that makes the run pointless."""


@dataclass
class AssessOptions:
    model_profile: str | None = None  # None -> experiment.default_model
    snapshot_id: str | None = None  # replay mode (deterministic runs only)
    use_agent: bool = True
    scan: bool | None = None  # None -> experiment.scan.enabled
    session_name: str | None = None
    objective: str | None = None
    skip_model_check: bool = False
    progress: Callable[[str], None] | None = None
    # Security warnings that must stand out (falls back to ``progress``).
    warn: Callable[[str], None] | None = None
    # Replay exactly these stored scans (from a manifest) instead of the latest.
    scan_ids: list[int] | None = None
    replay_of: ReplayOf | None = None  # set when re-running from a manifest
    # Live: verify the range matches this named baseline before scanning (else abort).
    range_baseline: str | None = None
    range_ref: RangeRef | None = None  # replay: the baseline recorded in the manifest
    notes: list[str] = field(default_factory=list)  # recorded in the run's errors


@dataclass
class _ManifestHolder:
    manifest: RunManifest | None = None
    path: Path | None = None
    range_ref: RangeRef | None = None
    range_check: RangeCheck | None = None


@dataclass
class AssessResult:
    run_id: str
    status: str
    report: Report  # deterministic report
    md_path: Path  # deterministic_report.md
    manifest_path: Path | None
    agent_report: AgentReport | None = None
    agent_md_path: Path | None = None
    comparison: Comparison | None = None
    comparison_md_path: Path | None = None


def new_run_id() -> str:
    return f"run-{datetime.now(UTC):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


def _say(opts: AssessOptions, message: str) -> None:
    if opts.progress:
        opts.progress(message)


def _warn(opts: AssessOptions, message: str) -> None:
    if opts.warn:
        opts.warn(message)
    else:
        _say(opts, message)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


async def _prepare_model(settings: Settings, opts: AssessOptions) -> ModelBundle | None:
    if not opts.use_agent:
        return None
    profile = settings.get_profile(opts.model_profile)
    if not opts.skip_model_check:
        _say(opts, f"Checking model profile '{profile.name}' ({profile.provider}/{profile.model})")
        report = await check_profile(profile)
        if not report.ok:
            raise ConfigError(
                f"Model profile '{profile.name}' is not usable:\n  - "
                + "\n  - ".join(report.errors or ["unknown problem"])
            )
    return build_model(profile)


def _preflight_live(
    settings: Settings, opts: AssessOptions, scanning: bool
) -> tuple[list[str], DockerEndpointInfo]:
    """Check the Docker proxy and Trivy setup.

    Returns non-fatal warnings and the endpoint provenance recorded for the run.
    """
    warnings: list[str] = []
    endpoint = check_docker_endpoint(settings)
    if not endpoint.ok:
        raise AssessmentAborted(
            "Docker endpoint check failed:\n  - " + "\n  - ".join(endpoint.problems)
        )
    info = DockerEndpointInfo(
        docker_host=endpoint.docker_host,
        require_proxy=settings.mcp.require_proxy,
        proxy_verified=endpoint.filtered,
        docker_version=endpoint.docker_version,
    )
    if endpoint.filtered:
        _say(
            opts,
            f"Docker {endpoint.docker_version} reachable via read-only proxy "
            f"{settings.mcp.docker_host}",
        )
    if info.unenforced_warning:
        warnings.append(info.unenforced_warning)
        _warn(opts, info.unenforced_warning)

    scanner_cfg = settings.mcp.server_for_role("image_scanner")
    if scanning and scanner_cfg:
        setup = ensure_server_setup(scanner_cfg, install=True)
        if setup.installed_now:
            _say(opts, f"Installed MCP server '{setup.server}' ({setup.message})")
        if not setup.ready:
            warnings.append(f"Image scanning disabled: {setup.server}: {setup.message}")
        elif not trivy_db_status():
            _say(opts, "Downloading Trivy vulnerability database (first run, ~120 MB)...")
            ok, msg = download_trivy_db()
            if not ok:
                warnings.append(f"Trivy DB download failed, scans may fail: {msg}")
    return warnings, info


# ---------------------------------------------------------------------------
# Re-running from a manifest
# ---------------------------------------------------------------------------


def load_manifest(settings: Settings, source: str) -> RunManifest:
    """Load a manifest from a file path or a run ID, verifying it was not altered."""
    path = Path(source)
    repo = AssessmentRepository(settings.assessment_db_path)
    try:
        if path.is_file():
            manifest = parse_manifest_document(path.read_text(), str(path))
        else:
            text = repo.load_manifest_json(source)
            if not text:
                raise ConfigError(
                    f"'{source}' is neither a manifest file nor a run with a manifest"
                )
            manifest = parse_manifest_document(text, f"run {source}")
        # A file must also match what the database recorded for that run, if we have it.
        stored = repo.get_run(manifest.run_id)
        if stored and stored.get("manifest_sha256") not in (None, manifest.manifest_sha256()):
            raise ConfigError(
                f"Manifest for {manifest.run_id} does not match the hash stored in the "
                "database when the run was made."
            )
    finally:
        repo.close()
    return manifest


def options_from_manifest(
    settings: Settings, source: str, *, allow_drift: bool = False
) -> tuple[Settings, AssessOptions]:
    """Settings + options that re-run a manifest's configuration.

    A deterministic manifest is replayed: same snapshot, same scan IDs, no Docker
    access. An agent manifest is re-run LIVE (the agent needs MCP tools), and must
    match the original's range baseline when it had one. Raises ConfigError if the
    prompt or schemas changed since (unless ``allow_drift``).
    """
    manifest = load_manifest(settings, source)
    blocking, info = drift(manifest, settings.project_root)
    if blocking and not allow_drift:
        raise ConfigError(
            "Cannot reproduce this manifest with the current code:\n  - "
            + "\n  - ".join(blocking)
            + "\nUse --allow-drift to run anyway (recorded in the run)."
        )
    new_settings, profile_name = apply_manifest(settings, manifest)
    exp = manifest.experiment
    notes = [f"re-run of {manifest.run_id}: {d}" for d in blocking + info]
    if exp.agent is not None and exp.agent.named_session:
        notes.append(
            f"re-run of {manifest.run_id}: the original continued a named session; "
            "the re-run starts a fresh one"
        )
    live = profile_name is not None
    if live and exp.range_baseline is None:
        notes.append(
            f"re-run of {manifest.run_id}: the original was not checked against a range "
            "baseline, so the live environment may differ"
        )
    opts = AssessOptions(
        range_ref=None if live else exp.range_baseline,
        range_baseline=exp.range_baseline.name if live and exp.range_baseline else None,
        model_profile=profile_name,
        snapshot_id=None if live else exp.evidence.snapshot_id,
        scan_ids=None if live else list(exp.evidence.scan_ids),
        use_agent=live,
        objective=exp.objective,
        replay_of=ReplayOf(run_id=manifest.run_id, manifest_sha256=manifest.manifest_sha256()),
        notes=notes,
    )
    return new_settings, opts


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_assessment(settings: Settings, opts: AssessOptions) -> AssessResult:
    # The SDK would otherwise try to upload traces to OpenAI (see agent.yaml).
    set_tracing_disabled(not settings.agent.tracing_enabled)

    replay = opts.snapshot_id is not None
    if replay and opts.use_agent:
        raise ConfigError(
            "--snapshot replays stored evidence for --no-agent runs only: the agent "
            "investigates live Docker with MCP tools. Reset the range "
            "(deploy/grfics/range.sh reset NAME) and run live with --range-baseline NAME."
        )
    scanning = (settings.experiment.scan.enabled if opts.scan is None else opts.scan) and not replay
    mode = "replay" if replay else ("live" if opts.use_agent else "deterministic")
    objective = (opts.objective or settings.experiment.objective).strip()

    # 0. preflight (before anything is recorded, so config mistakes leave no junk rows)
    baseline: RangeBaseline | None = None
    if opts.range_baseline:
        if replay:
            raise ConfigError("--range-baseline checks a live range; it cannot be used to replay")
        try:
            baseline = load_baseline(settings.data_dir, opts.range_baseline)
        except (FileNotFoundError, ValueError) as exc:
            raise ConfigError(str(exc)) from exc
    bundle = await _prepare_model(settings, opts)
    warnings, endpoint = ([], None) if replay else _preflight_live(settings, opts, scanning)

    # 1. record the run
    run_id = new_run_id()
    repo = AssessmentRepository(settings.assessment_db_path)
    profile = bundle.profile if bundle else None
    session_id = opts.session_name or run_id
    repo.create_run(
        run_id=run_id,
        mode=mode,
        objective=objective,
        model_profile=profile.name if profile else None,
        model_provider=profile.provider if profile else None,
        model_id=profile.model if profile else None,
        model_config=profile.public_dict() if profile else None,
        prompt_version=PROMPT_VERSION,
        session_id=session_id if bundle else None,
    )
    if endpoint is not None:
        # Recorded up front so even a run that fails later keeps its provenance.
        repo.update_run(run_id, docker_endpoint_json=endpoint.model_dump())
    _say(opts, f"Run {run_id} started ({mode} mode)")

    started_at = datetime.now(UTC)
    t_start = time.perf_counter()
    recorder = ToolCallRecorder(settings.agent.limits.max_tool_calls)
    policy = ToolPolicy(settings.mcp)
    redactor = Redactor(settings.mcp.redaction)
    metrics = RunMetrics(started_at=started_at)
    errors = list(warnings) + opts.notes
    server_infos: list[MCPServerInfo] = []
    frozen = _ManifestHolder(range_ref=opts.range_ref)

    def check_range(snapshot: InventorySnapshot) -> None:
        """Abort unless the live range matches the requested baseline."""
        if baseline is None:
            return
        result = verify_range(baseline, snapshot)
        save_verification(settings.data_dir, result)
        if not result.matches:
            shown = result.differences[:15]
            more = len(result.differences) - len(shown)
            raise AssessmentAborted(
                f"The range does not match baseline '{baseline.name}' "
                f"({len(result.differences)} difference(s)):\n  - "
                + "\n  - ".join(shown)
                + (f"\n  ... and {more} more" if more > 0 else "")
                + f"\nReset it first: deploy/grfics/range.sh reset {baseline.name}"
            )
        last = latest_reset(settings.data_dir, baseline.name)
        frozen.range_ref = RangeRef(
            name=baseline.name,
            fingerprint_sha256=baseline.fingerprint_sha256,
            baseline_snapshot_id=baseline.snapshot_id,
        )
        frozen.range_check = RangeCheck(
            verified_at=result.verified_at,
            last_reset_at=last.since if last else None,
            last_reset_matched=last.matches if last else None,
        )
        _say(opts, f"Range matches baseline '{baseline.name}'")

    def freeze_manifest(snapshot_id: str, scan_ids: list[int]) -> None:
        """Write the immutable run manifest once the evidence is pinned."""
        manifest = build_manifest(
            settings=settings,
            run_id=run_id,
            mode=mode,
            objective=objective,
            profile=profile,
            named_session=bundle is not None and opts.session_name is not None,
            snapshot_id=snapshot_id,
            scan_ids=scan_ids,
            docker_endpoint=endpoint,
            replay_of=opts.replay_of,
            range_baseline=frozen.range_ref,
            range_check=frozen.range_check,
        )
        frozen.path = write_manifest(manifest, settings.output_dir)
        doc = manifest_document(manifest)
        repo.save_manifest(
            run_id,
            manifest_json=json.dumps(doc, sort_keys=True),
            manifest_sha256=doc["manifest_sha256"],
            config_sha256=doc["config_sha256"],
        )
        frozen.manifest = manifest
        _say(opts, f"Manifest {doc['manifest_sha256'][:12]} (config {doc['config_sha256'][:12]})")

    try:
        if replay:
            snapshot, scans, findings, outcome = await _replay_phase(
                settings, opts, repo, run_id, freeze_manifest
            )
        else:
            snapshot, scans, findings, outcome, server_infos = await _live_phase(
                settings,
                opts,
                repo,
                bundle,
                recorder,
                policy,
                redactor,
                objective,
                run_id,
                session_id,
                scanning,
                metrics,
                errors,
                freeze_manifest,
                check_range,
            )

        # 4. validate the agent's findings against the deterministic evidence
        validation: ValidationOutcome | None = None
        agent_status = "skipped"
        if outcome is not None:
            agent_status = outcome.status
            if outcome.error:
                errors.append(f"agent: {outcome.error}")
            if outcome.assessment is not None:
                validation = validate_agent_output(
                    outcome.assessment,
                    snapshot,
                    scans,
                    ignored_containers=settings.rules.ignore_containers,
                )
            metrics.model_requests = outcome.usage.get("requests", 0)
            metrics.input_tokens = outcome.usage.get("input_tokens")
            metrics.output_tokens = outcome.usage.get("output_tokens")
            metrics.total_tokens = outcome.usage.get("total_tokens")
            metrics.agent_seconds = outcome.duration_seconds

        # 6. persist findings + tool calls + metrics
        all_findings = list(findings)
        if validation:
            all_findings += validation.findings + validation.rejected + validation.out_of_scope
        repo.save_findings(run_id, all_findings)
        repo.save_tool_calls(run_id, recorder.records)

        metrics.finished_at = datetime.now(UTC)
        metrics.duration_seconds = round(time.perf_counter() - t_start, 2)
        metrics.tool_calls_total = len(recorder.records)
        metrics.tool_calls_agent = recorder.agent_calls
        metrics.tool_calls_blocked = recorder.blocked()
        metrics.tool_calls_by_name = recorder.counts_by_tool()
        metrics.redactions = recorder.total_redactions()

        agent_failed = outcome is not None and outcome.status != "ok"
        status = (
            "completed_with_errors" if (agent_failed or snapshot.collection_errors) else "completed"
        )
        model_info = (
            ModelInfo(
                profile=profile.name,
                provider=profile.provider,
                model=profile.model,
                settings=profile.public_dict(),
            )
            if profile
            else None
        )

        # 7a. deterministic report (always)
        report = build_report(
            run_id=run_id,
            status=status,
            objective=objective,
            model=model_info,
            prompt_version=PROMPT_VERSION,
            mcp_servers=server_infos,
            docker_endpoint=endpoint,
            manifest_sha256=frozen.manifest.manifest_sha256() if frozen.manifest else None,
            config_sha256=frozen.manifest.config_sha256() if frozen.manifest else None,
            snapshot=snapshot,
            findings=findings,
            scans=scans,
            errors=errors,
            metrics=metrics,
        )
        md_path = write_report(report, settings.output_dir)
        repo.save_report(run_id, report)
        result = AssessResult(run_id, status, report, md_path, frozen.path)

        # 5 + 7b. agent report and comparison (agent runs only)
        if outcome is not None and model_info is not None:
            result.agent_report = build_agent_report(
                run_id=run_id,
                model=model_info,
                prompt_version=PROMPT_VERSION,
                agent_status=agent_status,
                snapshot_id=snapshot.snapshot_id,
                validation=validation,
                errors=[e for e in errors if e.startswith("agent:")],
                metrics=metrics,
            )
            result.agent_md_path = write_agent_report(
                result.agent_report, server_infos, settings.output_dir
            )
            repo.save_agent_report(run_id, result.agent_report)
            result.comparison = compare(
                run_id=run_id,
                model=model_info,
                agent_status=agent_status,
                deterministic=findings,
                validation=validation,
                snapshot=snapshot,
            )
            result.comparison_md_path = write_comparison(result.comparison, settings.output_dir)
            repo.save_comparison(run_id, result.comparison)

        repo.update_run(
            run_id,
            finished_at=datetime.now(UTC).isoformat(),
            status=status,
            agent_status=agent_status,
            errors_json=errors,
            metrics_json=metrics.model_dump(mode="json"),
            mcp_servers_json=[s.model_dump() for s in server_infos],
        )
        return result
    except BaseException as exc:
        # Leave an honest trail in SQLite, then re-raise for the CLI to show.
        repo.save_tool_calls(run_id, recorder.records)
        repo.update_run(
            run_id,
            finished_at=datetime.now(UTC).isoformat(),
            status="failed",
            errors_json=errors + [f"{type(exc).__name__}: {exc}"],
        )
        raise
    finally:
        repo.close()


# ---------------------------------------------------------------------------
# Live phase: MCP servers connected for collection, scanning and the agent
# ---------------------------------------------------------------------------


async def _live_phase(
    settings,
    opts,
    repo,
    bundle,
    recorder,
    policy,
    redactor,
    objective,
    run_id,
    session_id,
    scanning,
    metrics,
    errors,
    freeze_manifest,
    check_range,
):
    roles = {"docker_inspection"} | ({"image_scanner"} if scanning or bundle else set())
    servers = build_servers(settings, policy, redactor, recorder, roles=roles)
    _say(opts, "Starting MCP servers: " + ", ".join(s.name for s in servers))

    async with connect(servers) as manager:
        active: list[GuardedMCPServer] = list(manager.active_servers)  # type: ignore[arg-type]
        by_role = {s.config.role: s for s in active}
        infos = []
        for s in servers:
            err = manager.errors.get(s)
            infos.append(
                MCPServerInfo(
                    name=s.name,
                    role=s.config.role,
                    command=" ".join([s.config.command, *s.config.args]),
                    approved_tools=s.config.allowed_tools,
                    connected=s in active,
                    error=f"{type(err).__name__}: {err}" if err else None,
                )
            )
            if err:
                errors.append(f"MCP server '{s.name}' failed to start: {err}")

        docker = by_role.get("docker_inspection")
        if docker is None:
            raise AssessmentAborted(
                "The Docker inspection MCP server is not available; cannot collect evidence."
            )

        # 2a. inventory
        t0 = time.perf_counter()
        _say(opts, "Collecting Docker inventory (read-only)...")
        snapshot = await collect_snapshot(docker)
        repo.save_snapshot(snapshot)
        repo.update_run(run_id, snapshot_id=snapshot.snapshot_id)
        check_range(snapshot)
        policy.set_scan_targets(snapshot.image_references())
        metrics.collection_seconds = round(time.perf_counter() - t0, 2)
        _say(
            opts,
            f"Snapshot {snapshot.snapshot_id}: {len(snapshot.containers)} containers, "
            f"{len(snapshot.images)} images, {len(snapshot.networks)} networks",
        )
        errors.extend(f"inventory: {e}" for e in snapshot.collection_errors)

        # 2b. deterministic rules
        findings = rules.evaluate(snapshot, settings.rules)
        _say(opts, f"Deterministic rules produced {len(findings)} findings")

        # 2c. image scans
        scans: list[ImageScanResult] = []
        scan_ids: list[int] = []
        trivy = by_role.get("image_scanner")
        if scanning and trivy is not None:
            t0 = time.perf_counter()
            scans = await scan_images(
                trivy,
                snapshot,
                settings.experiment.scan,
                progress=lambda i, n, name: _say(opts, f"Scanning image {i}/{n}: {name}"),
            )
            for scan in scans:
                scan_ids.append(repo.save_scan(run_id, snapshot.snapshot_id, scan))
                if scan.status != "ok":
                    errors.append(f"scan {scan.image_ref}: {scan.error}")
            metrics.scan_seconds = round(time.perf_counter() - t0, 2)
            findings = findings + vulnerability_findings(
                scans, snapshot, settings.rules.vulnerability_min_severity
            )
            findings.sort(key=lambda f: f.sort_key())
            # The agent may scan exactly the images the answer key covers.
            policy.set_scan_targets(_image_refs(snapshot, {s.image_id for s in scans}))
        elif scanning:
            errors.append("Image scanning requested but the Trivy MCP server is unavailable.")

        # record server versions now that we can ask
        for info in infos:
            if info.role == "docker_inspection":
                info.version = next((a for a in docker.config.args if "==" in a), "")
            elif info.role == "image_scanner" and trivy is not None:
                info.version = scans[0].scanner_version if scans else await trivy_version(trivy)

        freeze_manifest(snapshot.snapshot_id, scan_ids)

        # 3. agent (MCP servers still connected; it gets nothing from step 2)
        outcome = None
        if bundle is not None:
            outcome = await _agent_phase(
                settings, opts, bundle, recorder, active, snapshot, objective, run_id, session_id
            )
    return snapshot, scans, findings, outcome, infos


def _image_refs(snapshot: InventorySnapshot, image_ids: set[str]) -> set[str]:
    """Every reference (ID, short ID, tag, digest) of the given images."""
    refs: set[str] = set()
    for img in snapshot.images:
        if img.id in image_ids:
            short = img.id.removeprefix("sha256:")
            refs |= {img.id, short, short[:12], *img.tags, *img.digests}
    return refs


# ---------------------------------------------------------------------------
# Replay phase: stored evidence only, no Docker access
# ---------------------------------------------------------------------------


async def _replay_phase(settings, opts, repo, run_id, freeze_manifest):
    snapshot = repo.load_snapshot(opts.snapshot_id)
    if snapshot is None:
        raise AssessmentAborted(
            f"Snapshot '{opts.snapshot_id}' not found. List snapshots with: docker-audit snapshots"
        )
    repo.update_run(run_id, snapshot_id=snapshot.snapshot_id)
    scan_ids = (
        opts.scan_ids
        if opts.scan_ids is not None
        else repo.latest_scan_ids_for_snapshot(snapshot.snapshot_id)
    )
    try:
        scans = repo.load_scans(scan_ids)
    except KeyError as exc:
        raise AssessmentAborted(f"Pinned evidence is missing from the database: {exc}") from exc
    freeze_manifest(snapshot.snapshot_id, scan_ids)
    _say(opts, f"Replaying snapshot {snapshot.snapshot_id} with {len(scans)} stored scans")
    findings = rules.evaluate(snapshot, settings.rules) + vulnerability_findings(
        scans, snapshot, settings.rules.vulnerability_min_severity
    )
    findings.sort(key=lambda f: f.sort_key())
    return snapshot, scans, findings, None


# ---------------------------------------------------------------------------
# Agent phase
# ---------------------------------------------------------------------------


async def _agent_phase(
    settings: Settings,
    opts: AssessOptions,
    bundle: ModelBundle,
    recorder: ToolCallRecorder,
    mcp_servers: list[GuardedMCPServer],
    snapshot: InventorySnapshot,
    objective: str,
    run_id: str,
    session_id: str,
) -> AgentRunOutcome:
    # Only the names of excluded infrastructure (e.g. the read-only proxy) are
    # passed on, so the agent does not report the assessment tooling itself.
    out_of_scope = [
        c.name
        for c in snapshot.containers
        if any(fnmatch.fnmatchcase(c.name, p) for p in settings.rules.ignore_containers)
    ]
    agent = build_agent(bundle, mcp_servers=mcp_servers)
    limits = settings.agent.limits
    _say(
        opts,
        f"Running {agent.name} with {bundle.profile.name}, MCP tools only "
        f"(max {limits.max_turns} turns, {limits.max_tool_calls} tool calls, "
        f"{limits.max_duration_seconds:.0f}s)...",
    )
    outcome = await run_agent(
        agent,
        build_input(objective, out_of_scope),
        max_turns=limits.max_turns,
        timeout_seconds=limits.max_duration_seconds,
        session=open_session(session_id, settings.session_db_path),
        tracing_enabled=settings.agent.tracing_enabled,
        run_id=run_id,
    )
    _say(
        opts,
        f"Agent finished: {outcome.status} in {outcome.duration_seconds}s "
        f"({recorder.agent_calls} tool calls)",
    )
    return outcome
