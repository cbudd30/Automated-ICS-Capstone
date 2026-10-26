"""``docker-audit`` command-line interface (Typer + Rich).

Commands
--------
  doctor               validate config, Docker proxy, MCP servers, Trivy DB, default model
  setup                one-time setup: install trivy-mcp plugin, download Trivy DB
  models               list model profiles and their capability status
  models --provider ollama   discover installed Ollama models (+ tool support)
  mcp check            start each MCP server, compare its tools with the allow-list
  mcp tools            show the tools the agent will actually see
  inventory            collect and print a Docker inventory snapshot (read-only)
  assess               run a full assessment (see pipeline.py)
  runs                 list previous runs
  snapshots            list stored inventory snapshots (for --snapshot replay)
  report --run-id ID   print a stored report (markdown or JSON)

Every command loads configuration first; config errors are shown as a clean
message instead of a traceback.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from docker_security_agent.config import ConfigError, Settings, load_settings

app = typer.Typer(
    help="Defensive, read-only Docker security assessment agent for ICS environments.",
    no_args_is_help=True,
    add_completion=False,
)
mcp_app = typer.Typer(help="Inspect the approved MCP servers and tools.", no_args_is_help=True)
app.add_typer(mcp_app, name="mcp")
range_app = typer.Typer(
    help="Named range baselines: record and verify (read-only). The reset itself is "
    "deploy/grfics/range.sh.",
    no_args_is_help=True,
)
app.add_typer(range_app, name="range")

console = Console()


def _settings() -> Settings:
    try:
        return load_settings()
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _ok(flag: bool) -> str:
    return "[green]OK[/green]" if flag else "[red]FAIL[/red]"


# ---------------------------------------------------------------------------
# doctor / setup
# ---------------------------------------------------------------------------


@app.command()
def doctor(
    probe: Annotated[bool, typer.Option(help="Also send tiny test requests to the model")] = False,
) -> None:
    """Validate configuration and every dependency, without changing anything."""
    from docker_security_agent.llm.capabilities import check_profile
    from docker_security_agent.mcp.registry import (
        check_docker_endpoint,
        ensure_server_setup,
        trivy_db_status,
    )

    settings = _settings()
    problems = 0
    table = Table(title="docker-audit doctor", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details", overflow="fold")

    table.add_row(
        "Configuration", _ok(True), f"{settings.config_dir} ({len(settings.models)} model profiles)"
    )

    ep = check_docker_endpoint(settings)
    table.add_row(
        "Docker via read-only proxy",
        _ok(ep.ok),
        f"{ep.docker_host} docker={ep.docker_version or '?'} "
        f"filtered={ep.filtered}" + ("; " + "; ".join(ep.problems) if ep.problems else ""),
    )
    problems += not ep.ok

    for cfg in settings.mcp.enabled_servers():
        st = ensure_server_setup(cfg, install=False)
        table.add_row(
            f"MCP server '{cfg.name}'",
            _ok(st.ready),
            f"{cfg.command} {' '.join(cfg.args)} — {st.message}",
        )
        problems += not st.ready

    db = trivy_db_status()
    table.add_row(
        "Trivy vulnerability DB",
        _ok(bool(db)),
        f"trivy {db.get('trivy_version', '?')}, updated {db.get('UpdatedAt', '?')}"
        if db
        else "not downloaded — run `docker-audit setup`",
    )
    problems += not db

    profile = settings.get_profile(None)
    rep = asyncio.run(check_profile(profile, probe=probe))
    table.add_row(
        f"Default model '{profile.name}'",
        _ok(rep.ok),
        "; ".join(rep.errors + rep.warnings + rep.details),
    )
    problems += not rep.ok

    for path in (settings.data_dir, settings.output_dir):
        path.mkdir(parents=True, exist_ok=True)
    table.add_row(
        "Data / output directories", _ok(True), f"{settings.data_dir} , {settings.output_dir}"
    )

    console.print(table)
    if problems:
        console.print(f"[yellow]{problems} problem(s) found.[/yellow]")
        raise typer.Exit(1)
    console.print("[green]All checks passed.[/green]")


@app.command()
def setup(
    skip_db: Annotated[bool, typer.Option(help="Do not download the Trivy DB")] = False,
) -> None:
    """One-time setup: install MCP server plugins (trivy-mcp) and the Trivy DB."""
    from docker_security_agent.mcp.registry import (
        check_docker_endpoint,
        download_trivy_db,
        ensure_server_setup,
        trivy_db_status,
    )

    settings = _settings()
    for cfg in settings.mcp.enabled_servers():
        st = ensure_server_setup(cfg, install=True)
        console.print(f"MCP server [bold]{cfg.name}[/bold]: {_ok(st.ready)} {st.message}")

    if not skip_db:
        if trivy_db_status():
            console.print("Trivy DB: [green]present[/green] (refreshing)")
        with console.status("Downloading Trivy vulnerability DB..."):
            ok, msg = download_trivy_db()
        console.print(f"Trivy DB download: {_ok(ok)} {msg if not ok else ''}")

    ep = check_docker_endpoint(settings)
    if not ep.ok:
        console.print(
            "[yellow]Docker read-only proxy not detected.[/yellow] Start it with:\n"
            "  docker compose -f deploy/socket-proxy/compose.yml up -d"
        )
    else:
        console.print(f"Docker read-only proxy: [green]OK[/green] ({ep.docker_host})")


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


@app.command()
def models(
    provider: Annotated[str | None, typer.Option(help="ollama: list installed models")] = None,
    probe: Annotated[bool, typer.Option(help="Send tiny test requests (tools/JSON)")] = False,
    create_variant: Annotated[
        str | None,
        typer.Option(help="Ollama: create a larger-context variant of this installed model"),
    ] = None,
    num_ctx: Annotated[int, typer.Option(help="Context size for --create-variant")] = 32768,
) -> None:
    """List configured model profiles, or discover installed Ollama models."""
    from docker_security_agent.llm.capabilities import (
        OLLAMA_DEFAULT_CONTEXT,
        check_profile,
        create_ollama_context_variant,
        list_ollama_models,
    )

    settings = _settings()

    if provider == "ollama":
        base = next(
            (p.base_url for p in settings.models.values() if p.provider == "ollama" and p.base_url),
            "http://localhost:11434/v1",
        )
        if create_variant:
            # Explicit, user-requested change to the local Ollama model list.
            name = asyncio.run(create_ollama_context_variant(base, create_variant, num_ctx))
            console.print(
                f"Created Ollama model [bold]{name}[/bold] (num_ctx={num_ctx}, same weights as "
                f"{create_variant}). Use it as `model:` in config/models.yaml. "
                f"Remove with: ollama rm {name}"
            )
            return
        try:
            found = asyncio.run(list_ollama_models(base))
        except Exception as exc:
            console.print(f"[red]Could not reach Ollama at {base}:[/red] {exc}")
            raise typer.Exit(1) from exc
        table = Table(title=f"Installed Ollama models ({base})")
        for col in (
            "Model",
            "Size",
            "Family",
            "Params",
            "Quant",
            "Tools",
            "Context",
            "Capabilities",
        ):
            table.add_column(col)
        for m in found:
            table.add_row(
                m.name,
                f"{m.size_gb} GB",
                m.family,
                m.parameter_size,
                m.quantization,
                "[green]yes[/green]" if m.supports_tools else "[red]no[/red]",
                str(m.num_ctx) if m.num_ctx else f"{OLLAMA_DEFAULT_CONTEXT} (default)",
                ", ".join(m.capabilities),
            )
        console.print(table)
        console.print("Add a profile in config/models.yaml to use a model (provider: ollama).")
        return

    if provider and provider not in ("openai", "vllm"):
        console.print(f"[red]Unknown provider '{provider}'[/red]")
        raise typer.Exit(2)

    async def _check_all():
        selected = [p for p in settings.models.values() if not provider or p.provider == provider]
        return await asyncio.gather(*(check_profile(p, probe=probe) for p in selected))

    reports = asyncio.run(_check_all())
    table = Table(title="Model profiles")
    for col in ("Profile", "Provider", "Model", "Usable", "Tools", "Structured", "Notes"):
        table.add_column(col, overflow="fold")
    tri = {True: "yes", False: "[red]no[/red]", None: "unknown"}
    for r in reports:
        default = " (default)" if r.profile == settings.experiment.default_model else ""
        table.add_row(
            r.profile + default,
            r.provider,
            r.model,
            _ok(r.ok),
            tri[r.supports_tools],
            tri[r.supports_structured_output],
            "; ".join(r.errors + [f"[yellow]{w}[/yellow]" for w in r.warnings] + r.details),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# mcp check / tools
# ---------------------------------------------------------------------------


def _guarded_servers(settings: Settings, roles=None):
    from docker_security_agent.mcp.policy import ToolPolicy
    from docker_security_agent.mcp.recorder import ToolCallRecorder
    from docker_security_agent.mcp.redaction import Redactor
    from docker_security_agent.mcp.registry import build_servers

    recorder = ToolCallRecorder(settings.agent.limits.max_tool_calls)
    return build_servers(
        settings, ToolPolicy(settings.mcp), Redactor(settings.mcp.redaction), recorder, roles=roles
    ), recorder


def _collect_snapshot(settings: Settings):
    """Read-only inventory via the proxy + Docker MCP server. Returns (snapshot, recorder)."""
    from docker_security_agent.inventory.collector import collect_snapshot
    from docker_security_agent.mcp.registry import check_docker_endpoint, connect

    ep = check_docker_endpoint(settings)
    if not ep.ok:
        console.print("[red]" + "\n".join(ep.problems) + "[/red]")
        raise typer.Exit(1)
    servers, recorder = _guarded_servers(settings, roles={"docker_inspection"})

    async def _run():
        async with connect(servers) as manager:
            if not manager.active_servers:
                raise RuntimeError(f"Docker MCP server failed: {list(manager.errors.values())}")
            return await collect_snapshot(manager.active_servers[0])

    with console.status("Collecting inventory via MCP..."):
        return asyncio.run(_run()), recorder


@mcp_app.command("check")
def mcp_check() -> None:
    """Start each MCP server, list its tools and compare them with the allow-list."""
    from docker_security_agent.mcp.registry import connect, inspect_server_tools

    settings = _settings()
    servers, _ = _guarded_servers(settings)

    async def _run():
        async with connect(servers) as manager:
            results = []
            for s in servers:
                if s in manager.active_servers:
                    results.append((s, await inspect_server_tools(s), None))
                else:
                    results.append((s, None, manager.errors.get(s)))
            return results

    with console.status("Starting MCP servers..."):
        results = asyncio.run(_run())
    failed = 0
    for server, inv, err in results:
        if inv is None:
            failed += 1
            console.print(f"[red]✗ {server.name}[/red]: failed to start: {err}")
            continue
        hidden = sorted(set(inv.available) - set(inv.exposed))
        console.print(
            f"[green]✓ {server.name}[/green] ({server.config.role}): "
            f"{len(inv.available)} tools registered, {len(inv.exposed)} exposed "
            "to the agent"
        )
        console.print(f"   exposed : {', '.join(inv.exposed)}")
        if inv.missing:
            failed += 1
            console.print(
                f"   [red]missing (approved but not offered): {', '.join(inv.missing)}[/red]"
            )
        if inv.schema_problems:
            failed += 1
            console.print(f"   [red]schema problems: {'; '.join(inv.schema_problems)}[/red]")
        console.print(
            f"   hidden  : {len(hidden)} tools ({', '.join(hidden[:12])}"
            f"{', ...' if len(hidden) > 12 else ''})"
        )
    raise typer.Exit(1 if failed else 0)


@mcp_app.command("tools")
def mcp_tools() -> None:
    """Show exactly the tools (and descriptions) the agent will see."""
    from docker_security_agent.mcp.registry import connect

    settings = _settings()
    servers, _ = _guarded_servers(settings)

    async def _run():
        async with connect(servers) as manager:
            out = []
            for s in manager.active_servers:
                # list_tools() on the SDK object applies the allow-list filter,
                # exactly as the agent sees it.
                out.append((s.name, await s.list_tools(None, None)))
            return out, {s.name: str(e) for s, e in manager.errors.items()}

    with console.status("Starting MCP servers..."):
        listed, errors = asyncio.run(_run())
    table = Table(title="Approved MCP tools visible to the agent")
    for col in ("Server", "Tool", "Description"):
        table.add_column(col, overflow="fold")
    for server, tools in listed:
        for t in tools:
            table.add_row(server, t.name, (t.description or "").strip().split("\n")[0][:110])
    console.print(table)
    for name, err in errors.items():
        console.print(f"[red]{name} unavailable:[/red] {err}")
    console.print(
        "Plus local evidence tools: get_inventory_overview, get_rule_findings, "
        "get_container_details, get_image_vulnerabilities"
    )


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


@app.command()
def inventory(
    as_json: Annotated[bool, typer.Option("--json", help="Print the snapshot as JSON")] = False,
    save: Annotated[bool, typer.Option(help="Store the snapshot in SQLite")] = True,
) -> None:
    """Collect a read-only Docker inventory snapshot and print it."""
    from docker_security_agent.memory.repository import AssessmentRepository

    settings = _settings()
    snap, recorder = _collect_snapshot(settings)
    if save:
        repo = AssessmentRepository(settings.assessment_db_path)
        repo.save_snapshot(snap)
        repo.close()

    if as_json:
        sys.stdout.write(
            snap.model_dump_json(
                indent=2,
                exclude={
                    "containers": {"__all__": {"raw"}},
                    "images": {"__all__": {"raw"}},
                    "networks": {"__all__": {"raw"}},
                },
            )
        )
        return

    console.print(
        f"Snapshot [bold]{snap.snapshot_id}[/bold] — Docker {snap.docker_version} "
        f"({snap.docker_platform}); {snap.redactions} values redacted"
    )
    t = Table(title=f"Containers ({len(snap.containers)})")
    for col in ("Name", "State", "Image", "User", "Priv", "CapAdd", "Ports", "Networks"):
        t.add_column(col, overflow="fold")
    for c in snap.containers:
        t.add_row(
            c.name,
            c.state,
            c.image_ref,
            c.user or "(root)",
            "yes" if c.privileged else "",
            ",".join(c.cap_add),
            ", ".join(f"{p.host_ip or '*'}:{p.host_port}->{p.container_port}" for p in c.ports),
            ", ".join(c.networks),
        )
    console.print(t)
    t = Table(title=f"Networks ({len(snap.networks)})")
    for col in ("Name", "Driver", "Internal", "Subnets", "Containers"):
        t.add_column(col, overflow="fold")
    for n in snap.networks:
        t.add_row(n.name, n.driver, str(n.internal), ", ".join(n.subnets), ", ".join(n.containers))
    console.print(t)
    console.print(
        f"Images: {len(snap.images)} ({len(snap.used_image_ids())} in use) · "
        f"Volumes: {len(snap.volumes)}"
    )
    if snap.collection_errors:
        console.print("[yellow]Collection errors:[/yellow] " + "; ".join(snap.collection_errors))
    console.print(
        f"Tool calls: {len(recorder.records)} "
        f"({', '.join(f'{k}×{v}' for k, v in recorder.counts_by_tool().items())})"
    )


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------


def _security_warning(message: str) -> None:
    console.print(
        Panel(message, title="SECURITY WARNING", border_style="bold red", style="bold red")
    )


@app.command()
def assess(
    model: Annotated[str | None, typer.Option(help="Model profile from config/models.yaml")] = None,
    snapshot: Annotated[str | None, typer.Option(help="Replay a stored snapshot ID")] = None,
    no_agent: Annotated[bool, typer.Option("--no-agent", help="Rules + scanner only")] = False,
    no_scan: Annotated[bool, typer.Option("--no-scan", help="Skip Trivy image scans")] = False,
    session: Annotated[str | None, typer.Option(help="Continue a named agent session")] = None,
    objective: Annotated[str | None, typer.Option(help="Override the objective")] = None,
    skip_model_check: Annotated[bool, typer.Option(help="Skip capability preflight")] = False,
    manifest: Annotated[
        str | None,
        typer.Option(
            help="Re-run a manifest (file path or run ID) on its pinned evidence. "
            "Cannot be combined with --model/--snapshot/--no-agent/--session/--objective."
        ),
    ] = None,
    allow_drift: Annotated[
        bool, typer.Option(help="With --manifest: run even if the prompt or schemas changed")
    ] = False,
    range_baseline: Annotated[
        str | None,
        typer.Option(
            help="Live runs: abort unless the range matches this named baseline "
            "(see `docker-audit range`)"
        ),
    ] = None,
) -> None:
    """Run a full defensive assessment and write outputs/<RUN_ID>/report.{json,md}."""
    from docker_security_agent.pipeline import (
        AssessmentAborted,
        AssessOptions,
        options_from_manifest,
        run_assessment,
    )

    settings = _settings()
    try:
        if manifest:
            if any([model, snapshot, no_agent, session, objective, range_baseline]):
                raise ConfigError(
                    "--manifest fixes the whole configuration; drop "
                    "--model/--snapshot/--no-agent/--session/--objective/--range-baseline"
                )
            settings, opts = options_from_manifest(settings, manifest, allow_drift=allow_drift)
            opts.skip_model_check = skip_model_check
        else:
            opts = AssessOptions(
                model_profile=model,
                snapshot_id=snapshot,
                use_agent=not no_agent,
                scan=False if no_scan else None,
                session_name=session,
                objective=objective,
                skip_model_check=skip_model_check,
                range_baseline=range_baseline,
            )
        opts.progress = lambda msg: console.print(f"[dim]•[/dim] {msg}")
        opts.warn = _security_warning
        result = asyncio.run(run_assessment(settings, opts))
    except (ConfigError, AssessmentAborted) as exc:
        console.print(f"[red]Assessment not started/aborted:[/red] {exc}")
        raise typer.Exit(1) from exc

    s = result.report.summary
    console.print()
    console.print(
        f"[bold]Run {result.run_id}[/bold]: {result.status} — overall risk "
        f"[bold]{s.overall_risk.upper()}[/bold] ({s.risk_source})"
    )
    console.print("Findings: " + ", ".join(f"{k} {v}" for k, v in s.findings_by_severity.items()))
    console.print(
        f"Potential concerns: {len(result.report.potential_concerns)} · rejected "
        f"agent claims: {len(result.report.rejected_agent_claims)}"
    )
    console.print(f"Report: {result.md_path}\n        {result.json_path}")
    if result.manifest_path:
        console.print(
            f"Manifest: {result.manifest_path}\n          sha256 {result.report.manifest_sha256}"
            f"\n          config {result.report.config_sha256}"
        )
    endpoint = result.report.docker_endpoint
    if endpoint and endpoint.unenforced_warning:
        _security_warning(endpoint.unenforced_warning)
    if result.report.errors:
        console.print("[yellow]Notes:[/yellow]")
        for e in result.report.errors[:10]:
            console.print(f"  - {e[:300]}")


# ---------------------------------------------------------------------------
# range baselines
# ---------------------------------------------------------------------------


@range_app.command("record")
def range_record(name: Annotated[str, typer.Argument(help="New baseline name")]) -> None:
    """Fingerprint the current (read-only) inventory as named baseline NAME."""
    from docker_security_agent.inventory.baseline import record_baseline
    from docker_security_agent.memory.repository import AssessmentRepository

    settings = _settings()
    snap, _ = _collect_snapshot(settings)
    try:
        baseline = record_baseline(settings.data_dir, name, snap)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    repo = AssessmentRepository(settings.assessment_db_path)
    repo.save_snapshot(snap)
    repo.close()
    console.print(
        f"Recorded baseline [bold]{name}[/bold]: {len(snap.containers)} containers, "
        f"{len(snap.volumes)} volumes · fingerprint {baseline.fingerprint_sha256[:12]} · "
        f"snapshot {snap.snapshot_id}"
    )


@range_app.command("verify")
def range_verify(
    name: Annotated[str, typer.Argument(help="Baseline name")],
    since: Annotated[
        str | None,
        typer.Option(help="ISO time the reset started: every container and volume must be newer"),
    ] = None,
) -> None:
    """Check that the live range matches baseline NAME (exit code 1 if not)."""
    from datetime import UTC, datetime

    from docker_security_agent.inventory.baseline import load_baseline, save_verification, verify

    settings = _settings()
    try:
        baseline = load_baseline(settings.data_dir, name)
        since_dt = datetime.fromisoformat(since) if since else None
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    if since_dt is not None and since_dt.tzinfo is None:
        since_dt = since_dt.replace(tzinfo=UTC)
    snap, _ = _collect_snapshot(settings)
    result = verify(baseline, snap, since=since_dt)
    path = save_verification(settings.data_dir, result)
    if result.matches:
        console.print(
            f"[green]Range matches baseline {name}[/green] (snapshot {snap.snapshot_id}"
            + (", all containers and volumes recreated by the reset" if since_dt else "")
            + f") · {path}"
        )
        return
    console.print(f"[red]Range does NOT match baseline {name}:[/red]")
    for d in result.differences:
        console.print(f"  - {d}")
    console.print(f"Recorded: {path}")
    raise typer.Exit(1)


@range_app.command("list")
def range_list() -> None:
    """List recorded range baselines and their latest verified reset."""
    from docker_security_agent.inventory.baseline import (
        latest_reset,
        list_baselines,
        load_baseline,
    )

    settings = _settings()
    t = Table(title="Range baselines")
    for col in ("Name", "Recorded", "Containers", "Fingerprint", "Last reset", "Matched"):
        t.add_column(col)
    for name in list_baselines(settings.data_dir):
        b = load_baseline(settings.data_dir, name)
        last = latest_reset(settings.data_dir, name)
        t.add_row(
            name,
            f"{b.recorded_at:%Y-%m-%d %H:%M}",
            str(len(b.fingerprint["containers"])),
            b.fingerprint_sha256[:12],
            f"{last.since:%Y-%m-%d %H:%M}" if last and last.since else "-",
            ("yes" if last.matches else "[red]no[/red]") if last else "-",
        )
    console.print(t)


# ---------------------------------------------------------------------------
# runs / snapshots / report
# ---------------------------------------------------------------------------


@app.command()
def runs(limit: int = 20) -> None:
    """List previous assessment runs (most recent first)."""
    from docker_security_agent.memory.repository import AssessmentRepository

    settings = _settings()
    repo = AssessmentRepository(settings.assessment_db_path)
    rows = repo.list_runs(limit)
    repo.close()
    t = Table(title="Assessment runs")
    t.add_column("Run ID", no_wrap=True)
    for col in ("Started", "Status", "Mode", "Model", "Agent", "Snapshot"):
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(
            r["run_id"],
            (r["started_at"] or "")[:19],
            r["status"],
            r["mode"],
            f"{r['model_profile'] or '-'} ({r['model_id'] or '-'})",
            r["agent_status"] or "-",
            r["snapshot_id"] or "-",
        )
    console.print(t)


@app.command()
def snapshots(limit: int = 20) -> None:
    """List stored inventory snapshots (use with `assess --snapshot`)."""
    from docker_security_agent.memory.repository import AssessmentRepository

    settings = _settings()
    repo = AssessmentRepository(settings.assessment_db_path)
    rows = repo.list_snapshots(limit)
    repo.close()
    t = Table(title="Inventory snapshots")
    t.add_column("Snapshot ID", no_wrap=True)
    for col in ("Captured", "Docker", "Containers", "Images", "Networks"):
        t.add_column(col)
    for r in rows:
        t.add_row(
            r["snapshot_id"],
            r["captured_at"][:19],
            r["docker_version"] or "",
            str(r["container_count"]),
            str(r["image_count"]),
            str(r["network_count"]),
        )
    console.print(t)


@app.command()
def report(
    run_id: Annotated[str, typer.Option("--run-id", help="Run ID from `docker-audit runs`")],
    fmt: Annotated[str, typer.Option("--format", help="md | json | path")] = "md",
    raw: Annotated[bool, typer.Option(help="Print markdown source instead of rendering")] = False,
) -> None:
    """Print a stored report (re-rendered from the JSON stored in SQLite)."""
    from docker_security_agent.memory.repository import AssessmentRepository
    from docker_security_agent.reporting.generator import render_markdown

    settings = _settings()
    repo = AssessmentRepository(settings.assessment_db_path)
    stored = repo.load_report(run_id)
    run = repo.get_run(run_id)
    repo.close()
    if stored is None:
        msg = "run not found" if run is None else f"run has no report (status: {run['status']})"
        console.print(f"[red]{run_id}: {msg}[/red]")
        raise typer.Exit(1)
    if fmt == "json":
        sys.stdout.write(stored.model_dump_json(indent=2))
    elif fmt == "path":
        console.print(str(settings.output_dir / run_id))
    else:
        md = render_markdown(stored)
        if raw:
            sys.stdout.write(md)
        else:
            console.print(Markdown(md))


@app.command(name="nmap-scan")
def nmap_scan(
    targets: Annotated[
        list[str],
        typer.Option("--target", "-t", help="IP, CIDR, or hostname to scan (repeatable)."),
    ],
    model: Annotated[
        str | None,
        typer.Option("--model", "-m", help="Model profile name (see config/models.yaml)."),
    ] = None,
    objective: Annotated[
        str,
        typer.Option("--objective", help="Custom assessment objective."),
    ] = "",
    max_turns: Annotated[int, typer.Option("--max-turns")] = 20,
    timeout: Annotated[float, typer.Option("--timeout", help="Wall-clock limit in seconds.")] = 600.0,
    output_json: Annotated[
        str | None, typer.Option("--output", "-o", help="Write JSON result to this file.")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run the standalone NmapNetworkAgent against one or more targets.

    Uses the gc-nmap-mcp MCP server (do-nmap tool). Requires nmap installed
    and NMAP_PATH set (defaults to /usr/bin/nmap).

    Examples
    --------
      docker-audit nmap-scan --target 192.168.95.0/24
      docker-audit nmap-scan -t 10.0.0.1 -t 10.0.0.2 --model gpt-4o
    """
    import uuid
    from docker_security_agent.agents.nmap_network_agent import (
        build_nmap_agent,
        build_nmap_input,
        run_nmap_agent,
    )
    from docker_security_agent.llm.factory import ModelBundle
    from docker_security_agent.mcp.policy import ToolPolicy
    from docker_security_agent.mcp.recorder import ToolCallRecorder
    from docker_security_agent.mcp.redaction import Redactor
    from docker_security_agent.mcp.registry import build_servers, connect

    if not targets:
        console.print("[red]Error:[/red] at least one --target is required.")
        raise typer.Exit(1)

    settings = _settings()
    profile = settings.get_profile(model)

    if "nmap" not in settings.mcp.servers or not settings.mcp.servers["nmap"].enabled:
        console.print(
            "[red]Error:[/red] nmap MCP server is not configured or is disabled.\n"
            "Check the 'nmap' entry in config/mcp_servers.yaml."
        )
        raise typer.Exit(1)

    run_id = str(uuid.uuid4())[:8]
    console.print(
        Panel(
            f"[bold]NmapNetworkAgent[/bold]  run={run_id}  model={profile.model}\n"
            f"Targets: {', '.join(targets)}",
            title="docker-audit nmap-scan",
        )
    )

    async def _run() -> None:
        policy = ToolPolicy(settings.mcp)
        redactor = Redactor(settings.mcp.redaction)
        recorder = ToolCallRecorder(max_calls=max_turns * 3)

        servers = build_servers(
            settings, policy, redactor, recorder, roles={"network_scanner"}
        )
        if not servers:
            console.print("[red]Error:[/red] No network_scanner MCP servers are active.")
            raise typer.Exit(1)

        async with connect(servers) as mgr:
            active = list(mgr.active_servers)
            if not active:
                console.print(
                    "[red]Error:[/red] nmap MCP server failed to start.\n"
                    "Is nmap installed? Is NMAP_PATH set correctly?"
                )
                raise typer.Exit(1)

            bundle = ModelBundle.from_profile(profile)
            agent = build_nmap_agent(bundle, mcp_servers=active)
            user_input = build_nmap_input(targets, objective=objective)
            if verbose:
                console.print("[dim]--- agent input ---[/dim]")
                console.print(user_input)
                console.print("[dim]---[/dim]")
            outcome = await run_nmap_agent(
                agent,
                user_input,
                max_turns=max_turns,
                timeout_seconds=timeout,
                run_id=run_id,
            )

        if outcome.status != "ok":
            console.print(f"[red]Agent finished with status={outcome.status}[/red]")
            if outcome.error:
                console.print(f"[yellow]{outcome.error}[/yellow]")
            raise typer.Exit(1)

        assessment = outcome.assessment
        console.print()
        console.print(Panel(assessment.executive_summary, title="Executive Summary"))
        console.print(f"[bold]Overall risk:[/bold] {assessment.overall_risk.upper()}")
        console.print()

        if assessment.exposed_ics_services:
            t = Table(title=f"Exposed ICS Services ({len(assessment.exposed_ics_services)})")
            for col in ("Host", "Port", "Protocol", "Risk", "Rationale"):
                t.add_column(col, no_wrap=col in ("Host", "Port", "Risk"))
            for svc in assessment.exposed_ics_services:
                t.add_row(
                    svc.host,
                    str(svc.port),
                    svc.protocol_name,
                    svc.risk_level.upper(),
                    svc.rationale[:80],
                )
            console.print(t)
        else:
            console.print("[green]No exposed ICS services found.[/green]")

        if assessment.findings:
            t2 = Table(title=f"Findings ({len(assessment.findings)})")
            for col in ("Severity", "Host", "Port", "Title"):
                t2.add_column(col, no_wrap=col in ("Severity", "Host", "Port"))
            for f in assessment.findings:
                t2.add_row(
                    f.severity.upper(),
                    f.host,
                    str(f.port) if f.port else "",
                    f.title,
                )
            console.print(t2)

        if assessment.recommendations:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, rec in enumerate(assessment.recommendations, 1):
                console.print(f"  {i}. {rec}")

        console.print(
            f"\n[dim]Finished in {outcome.duration_seconds:.1f}s  |  "
            f"tokens: {outcome.usage.get('total_tokens', 'n/a')}[/dim]"
        )

        if output_json:
            import pathlib
            out = pathlib.Path(output_json)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(assessment.model_dump_json(indent=2))
            console.print(f"[green]JSON written to {output_json}[/green]")

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    app()
