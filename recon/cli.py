"""Typer CLI for Night Scout.

The CLI is intentionally thin.  Composition and runtime behavior live in
`recon.runtime`, which keeps the same application usable from tests, Python
code, and a future packaged executable.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Any

import typer

from recon import __version__
from recon.core.events import ScopeState
from recon.exporters.jsonl import ExportMode
from recon.policy.request_identity import RequestIdentityPolicy
from recon.policy.scope import ScopeAssetKind, ScopeEngine, ScopeSubject
from recon.policy.seeds import effective_scope_rules
from recon.runtime import (
    RuntimeMobileArtifactInput,
    RuntimeProgress,
    build_runtime,
    doctor_from_files,
    load_runtime_configuration,
    runtime_database_config,
)
from recon.storage.database import Database
from recon.storage.schema import upgrade_database
from recon.storage.workspace import WorkspaceRepository
from recon.surface.models import SurfaceGraphFilter
from recon.surface.rebuild import SurfaceGraphRebuilder
from recon.tooling import (
    ToolInstallProgress,
    ToolInstallResult,
    assert_supported_platform,
    install_tools,
    load_tools_manifest,
    managed_bin_dir,
    probe_all_tools,
)
from recon.userenv import (
    add_confirmed_domain_scope,
    initialize_user_environment,
    is_default_user_pipeline,
    preferred_pipeline_path,
    refresh_user_wordlist_resources,
    user_paths,
)
from recon.workers.mobile import MobileArtifactKind
from scripts.wordlists_sync import build_local_manifest
from scripts.wordlists_sync import main as wordlists_sync_main

_SCOPE_WORKSPACE_HELP = "Scope YAML override; target_id selects its isolated workspace."

app = typer.Typer(
    name="nightscout",
    help="Recursive, scope-aware attack-surface intelligence with isolated target workspaces.",
    no_args_is_help=True,
    add_completion=False,
)


tools_app = typer.Typer(
    name="tools",
    help="Install and verify managed external tools on Debian/Kali.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(tools_app, name="tools")

wordlists_app = typer.Typer(
    name="wordlists",
    help="Manage public wordlist corpora in the per-user Night Scout workspace.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(wordlists_app, name="wordlists")

workspace_app = typer.Typer(
    name="workspace",
    help="Inspect or explicitly adopt isolated target workspaces.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(workspace_app, name="workspace")

review_app = typer.Typer(
    name="review",
    help="Inspect and resolve tasks paused for human review.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(review_app, name="review")

graph_app = typer.Typer(
    name="graph",
    help="Build and maintain the canonical attack-surface graph.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(graph_app, name="graph")


def _resolve_pipeline(value: Path | None) -> Path:
    return value.expanduser().resolve() if value is not None else preferred_pipeline_path()


def _graph_export_command(
    *,
    pipeline: Path,
    scope: Path | None,
    format: str,
) -> str:
    args = [
        "nightscout",
        "export",
        "--pipeline",
        str(pipeline),
    ]
    if scope is not None:
        args.extend(("--scope", str(scope.expanduser().resolve())))
    args.extend(("--format", format))
    return shlex.join(args)


def _render_result_commands(*, pipeline: Path, scope: Path | None) -> None:
    html_command = _graph_export_command(
        pipeline=pipeline,
        scope=scope,
        format="html",
    )
    graph_json_command = _graph_export_command(
        pipeline=pipeline,
        scope=scope,
        format="graph-json",
    )
    tree_json_command = _graph_export_command(
        pipeline=pipeline,
        scope=scope,
        format="tree-json",
    )

    typer.echo("view results:")
    typer.echo(f"  graph_html=\"$({html_command})\"")
    typer.echo('  xdg-open "$graph_html"')
    typer.echo(f"  {graph_json_command}")
    typer.echo(f"  {tree_json_command}")


def _request_identity_from_cli(
    values: list[str] | None,
    *,
    command: str,
) -> RequestIdentityPolicy:
    try:
        return RequestIdentityPolicy.from_cli_header_lines(values or ())
    except ValueError as exc:
        typer.echo(f"{command} failed: invalid --identity-header: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Night Scout {__version__}")
        raise typer.Exit()


def _render_tool_progress(item: ToolInstallProgress) -> None:
    typer.echo(
        f"  [tool {item.index}/{item.total}] {item.tool_id}: {item.phase.value} - {item.detail}"
    )


def _render_run_progress(item: RuntimeProgress) -> None:
    parts = [
        "recon:",
        f"run={item.run_id}",
        f"phase={item.phase}",
        f"step={item.step}/{item.max_steps}",
    ]
    if item.outcome is not None:
        parts.append(f"outcome={item.outcome.value}")
    if item.worker:
        parts.append(f"worker={item.worker}")
    if item.action:
        parts.append(f"action={item.action}")
    if item.queue_status is not None:
        parts.append(f"queue={item.queue_status.value}")
    if item.running:
        parts.append(f"running={item.running}")
    if item.slot_id is not None:
        parts.append(f"slot={item.slot_id}")
    if item.wait_seconds is not None:
        parts.append(f"wait={item.wait_seconds:.1f}s")
    if item.run_status:
        parts.append(f"status={item.run_status}")
    if item.reason:
        reason = " ".join(item.reason.split())
        parts.append(f"reason={reason[:240]}")
    typer.echo(" ".join(parts), err=True)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show Night Scout version and exit.",
    ),
) -> None:
    del version


@app.command("setup")
def setup_command(
    skip_tools: bool = typer.Option(
        False,
        "--skip-tools",
        help="Initialize user config/workspace base without installing companion tools.",
    ),
    skip_wordlists: bool = typer.Option(
        False,
        "--skip-wordlists",
        help="Keep only the bundled baseline corpus; do not sync default public wordlists.",
    ),
    include_optional_tools: bool = typer.Option(
        False,
        "--optional-tools",
        help="Also install optional mobile-analysis tools.",
    ),
    update_tools: bool = typer.Option(
        False,
        "--update-tools",
        help="Update already installed managed tools.",
    ),
    allow_unverified: bool = typer.Option(
        False,
        "--allow-unverified",
        help="Allow an upstream tool asset without a verifiable SHA-256.",
    ),
) -> None:
    """Initialize the per-user Night Scout environment on Debian/Kali."""

    try:
        typer.echo("[setup 1/5] Checking supported platform...")
        platform_info = assert_supported_platform()
        typer.echo(f"  {platform_info.pretty_name} / {platform_info.architecture}: supported")

        typer.echo("[setup 2/5] Preparing per-user config and workspace base...")
        paths = initialize_user_environment()
        typer.echo(f"  config:    {paths.config_root}")
        typer.echo(f"  workspace base: {paths.data_root}")

        typer.echo("[setup 3/5] Preparing wordlists...")
        if skip_wordlists:
            build_local_manifest(
                paths.data_root,
                base_manifest_path=paths.wordlists_root / "manifest.yaml",
                lock_path=paths.wordlists_lock,
                output_path=paths.wordlists_manifest,
            )
            typer.echo("  public wordlist sync skipped; bundled baseline is ready")
        else:
            typer.echo("  syncing the default public corpus; this needs network access")
            code = wordlists_sync_main(["--root", str(paths.data_root), "sync"])
            if code:
                raise RuntimeError(f"default wordlist sync failed with exit code {code}")
            typer.echo("  default public corpus synchronized")

        results: tuple[ToolInstallResult, ...] = ()
        typer.echo("[setup 4/5] Preparing companion tools...")
        if skip_tools:
            typer.echo("  skipped by request")
        else:
            typer.echo(
                "  first setup can take several minutes: Night Scout tries trusted "
                "Debian/Kali APT packages first, then upstream fallback when needed"
            )
            typer.echo("  APT/PDTM/pipx output is shown live, so long downloads are visible below")
            results = install_tools(
                include_optional=include_optional_tools,
                update=update_tools,
                allow_unverified=allow_unverified,
                install_prerequisites=True,
                progress=_render_tool_progress,
            )

        typer.echo("[setup 5/5] Running final health checks...")
        report = None
        if not skip_tools:
            report = doctor_from_files(pipeline_path=paths.pipeline_path)
            typer.echo(f"  doctor:    {'healthy' if report.healthy else 'required checks failed'}")
            if not report.healthy:
                for check in report.checks:
                    if check.required and not check.ok:
                        typer.echo(f"  FAIL {check.name}: {check.detail}", err=True)
                raise typer.Exit(code=1)
        else:
            typer.echo("  tool-dependent doctor checks deferred because --skip-tools was used")
    except KeyboardInterrupt:
        typer.echo(
            "setup interrupted; completed wordlists/tools remain in the user workspace "
            "and a later setup will verify/reuse them",
            err=True,
        )
        raise typer.Exit(code=130) from None
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"setup failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo("")
    typer.echo(
        f"Night Scout setup complete: {platform_info.pretty_name} / {platform_info.architecture}"
    )
    typer.echo(f"config:    {paths.config_root}")
    typer.echo(f"workspace base: {paths.data_root}")
    typer.echo(f"cache:     {paths.cache_root}")
    typer.echo(
        "wordlists: bundled baseline corpus ready"
        if skip_wordlists
        else "wordlists: default public corpus synchronized"
    )

    for result in results:
        marker = "SKIP" if result.skipped else "OK"
        typer.echo(f"[{marker:4}] tool:{result.tool_id}: {result.detail}")

    typer.echo("")
    typer.echo("Scope starts fail-closed.")
    typer.echo("For a real bug-bounty program, create a scope YAML and run:")
    typer.echo("  nightscout run --scope program.yaml")
    typer.echo("")
    typer.echo("For a one-domain quick start:")
    typer.echo("  nightscout run example.com")


@app.command("doctor")
def doctor_command(
    pipeline: Path | None = typer.Option(
        None,
        "--pipeline",
        "-p",
        help="Pipeline YAML file. Defaults to the per-user config after setup.",
    ),
    scope: Path | None = typer.Option(
        None,
        "--scope",
        "-s",
        help="Scope YAML override. Otherwise pipeline scope_file is used.",
    ),
    identity_headers: list[str] = typer.Option(
        None,
        "--identity-header",
        help="Required target HTTP header as 'Name: value'; repeat for multiple headers.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Validate configuration and external tool availability without scanning."""

    pipeline = _resolve_pipeline(pipeline)
    request_identity = _request_identity_from_cli(identity_headers, command="doctor")
    report = doctor_from_files(
        pipeline_path=pipeline,
        scope_path=scope,
        request_identity=request_identity,
    )

    if json_output:
        typer.echo(
            json.dumps(
                report.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"pipeline: {report.pipeline_path}")
        if report.scope_path:
            typer.echo(f"scope:    {report.scope_path}")
        typer.echo("")
        for check in report.checks:
            marker = "OK" if check.ok else ("WARN" if not check.required else "FAIL")
            typer.echo(f"[{marker:4}] {check.name}: {check.detail}")
        typer.echo("")
        typer.echo("healthy" if report.healthy else "required checks failed")

    if not report.healthy:
        raise typer.Exit(code=1)


@app.command("run")
def run_command(
    targets: list[str] | None = typer.Argument(
        None,
        help=(
            "Optional root-domain seeds. Provide several domains, or omit them "
            "to derive the domain frontier from --scope / configured scope."
        ),
    ),
    pipeline: Path | None = typer.Option(
        None,
        "--pipeline",
        "-p",
        help="Pipeline YAML file. Defaults to the per-user config after setup.",
    ),
    scope: Path | None = typer.Option(
        None,
        "--scope",
        "-s",
        help=_SCOPE_WORKSPACE_HELP,
    ),
    max_steps: int | None = typer.Option(
        None,
        "--max-steps",
        min=1,
        help="Maximum lifecycle executions before returning control.",
    ),
    mobile_artifact: Path | None = typer.Option(
        None,
        "--mobile-artifact",
        help="Local APK/IPA to add to this run; requires --mobile-app-id.",
    ),
    mobile_app_id: str | None = typer.Option(
        None,
        "--mobile-app-id",
        help="Scoped Android package ID or iOS bundle ID; requires --mobile-artifact.",
    ),
    mobile_source_url: str | None = typer.Option(
        None,
        "--mobile-source-url",
        help="Store/listing provenance only; Night Scout never fetches this URL.",
    ),
    mobile_kind: MobileArtifactKind | None = typer.Option(
        None,
        "--mobile-kind",
        case_sensitive=False,
        help="Artifact kind when it cannot be inferred from .apk or .ipa.",
    ),
    identity_headers: list[str] = typer.Option(
        None,
        "--identity-header",
        help="Required target HTTP header as 'Name: value'; repeat for multiple headers.",
    ),
    authorize_exact: bool = typer.Option(
        False,
        "--authorize-exact",
        help="Explicitly add this exact domain to the default local IN_SCOPE policy.",
    ),
    authorize_subdomains: bool = typer.Option(
        False,
        "--authorize-subdomains",
        help="Explicitly add the exact domain and *.domain to the default local scope.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit final run summary as JSON.",
    ),
    progress: bool = typer.Option(
        True,
        "--progress/--no-progress",
        help="Emit live lifecycle state to stderr while recon is running.",
    ),
) -> None:
    """Run one program frontier from domain and optional local mobile seeds."""

    pipeline = _resolve_pipeline(pipeline)
    normalized_targets = tuple(targets or ())
    request_identity = _request_identity_from_cli(identity_headers, command="run")
    if (mobile_artifact is None) != (mobile_app_id is None):
        typer.echo(
            "run failed: --mobile-artifact and --mobile-app-id must be provided together",
            err=True,
        )
        raise typer.Exit(code=2)
    if mobile_app_id is not None and not mobile_app_id.strip():
        typer.echo("run failed: --mobile-app-id must not be blank", err=True)
        raise typer.Exit(code=2)
    if mobile_artifact is None and (mobile_source_url is not None or mobile_kind is not None):
        typer.echo(
            "run failed: --mobile-source-url and --mobile-kind require --mobile-artifact",
            err=True,
        )
        raise typer.Exit(code=2)

    mobile_input = None
    if mobile_artifact is not None and mobile_app_id is not None:
        # Preserve the final path component so the storage boundary can reject
        # a symlink instead of receiving its already-resolved target.
        mobile_input = RuntimeMobileArtifactInput(
            artifact_path=mobile_artifact.expanduser().absolute(),
            app_id=mobile_app_id,
            source_url=mobile_source_url,
            kind=mobile_kind,
        )
    _prepare_default_scope_for_run(
        targets=normalized_targets,
        pipeline=pipeline,
        scope=scope,
        authorize_exact=authorize_exact,
        authorize_subdomains=authorize_subdomains,
    )

    async def _run() -> dict[str, Any]:
        runtime = await build_runtime(
            pipeline_path=pipeline,
            scope_path=scope,
            request_identity=request_identity,
        )
        try:
            if mobile_input is None:
                summary = await runtime.run_domains(
                    normalized_targets,
                    max_steps=max_steps,
                    progress=_render_run_progress if progress else None,
                )
            else:
                summary = await runtime.run_domains(
                    normalized_targets,
                    mobile_artifact=mobile_input,
                    max_steps=max_steps,
                    progress=_render_run_progress if progress else None,
                )
            return summary.model_dump(mode="json")
        finally:
            await runtime.close()

    try:
        summary = asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("interrupted", err=True)
        raise typer.Exit(code=130) from None
    except asyncio.CancelledError:
        typer.echo("interrupted", err=True)
        raise typer.Exit(code=130) from None
    except Exception as exc:
        typer.echo(f"run failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        if summary.get("status") == "FAILED":
            raise typer.Exit(code=1)
        return

    typer.echo(f"run_id:      {summary['run_id']}")
    typer.echo(f"status:      {summary['status']}")
    typer.echo(f"seeds:       {len(summary['seeds'])}")
    for seed in summary["seeds"]:
        typer.echo(f"  {seed['target']}  scope={seed['scope_state']}  mode={seed['mode']}")
        if seed.get("artifact_ref"):
            typer.echo(
                "    "
                f"artifact={seed['artifact_ref']} kind={seed['artifact_kind']} "
                f"sha256={seed['artifact_sha256']} size={seed['artifact_size_bytes']} bytes"
            )
    typer.echo(f"steps:       {summary['steps']}")
    typer.echo(f"events:      {summary['event_count']}")
    typer.echo(f"assets:      {summary['asset_count']}")
    typer.echo(f"open review: {summary['open_review_cases']}")
    if summary.get("genome_fingerprint"):
        typer.echo(f"genome:      {summary['genome_fingerprint']}")

    outcomes = summary.get("outcomes", {})
    if outcomes:
        typer.echo("outcomes:")
        for name, count in sorted(outcomes.items()):
            typer.echo(f"  {name}: {count}")

    task_counts = summary.get("task_counts", {})
    if task_counts:
        typer.echo("tasks:")
        for name, count in sorted(task_counts.items()):
            typer.echo(f"  {name}: {count}")

    attempt_counts = summary.get("attempt_counts", {})
    if attempt_counts:
        typer.echo("attempts:")
        for name, count in sorted(attempt_counts.items()):
            typer.echo(f"  {name}: {count}")

    warnings = summary.get("warnings", [])
    if warnings:
        typer.echo("warnings:")
        for warning in warnings:
            typer.echo(f"  - {warning}")

    _render_result_commands(pipeline=pipeline, scope=scope)

    if summary.get("status") == "FAILED":
        raise typer.Exit(code=1)


@app.command("status")
def status_command(
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(
        None,
        "--scope",
        "-s",
        help=_SCOPE_WORKSPACE_HELP,
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show persistent workspace/frontier status."""

    pipeline = _resolve_pipeline(pipeline)

    async def _status() -> dict[str, Any]:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            status = await runtime.status()
            return status.model_dump(mode="json")
        finally:
            await runtime.close()

    try:
        status = asyncio.run(_status())
    except Exception as exc:
        typer.echo(f"status failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True))
        return

    typer.echo(f"target:       {status['target_id']}")
    typer.echo(f"workspace:    {status['workspace_root']}")
    typer.echo(f"database:     {status['database_path']}")
    typer.echo(f"events:       {status['event_count']}")
    typer.echo(f"assets:       {status['asset_count']}")
    typer.echo(f"open reviews: {status['open_review_cases']}")
    typer.echo(f"dispatcher:   {status['dispatcher_state']}")
    typer.echo(f"waiting rate: {status['waiting_rate']}")
    typer.echo(
        "event queue:  "
        f"{status['event_queue_depth']}/{status['event_queue_capacity']} "
        f"(high {status['event_queue_high_watermark']}, "
        f"avg write {status['event_publish_avg_ms']:.2f} ms)"
    )
    if status["sqlite_busy_count"]:
        typer.echo(f"sqlite busy:  {status['sqlite_busy_count']}")

    if status.get("running_by_worker"):
        typer.echo("running by worker:")
        for name, count in sorted(status["running_by_worker"].items()):
            typer.echo(f"  {name}: {count}")

    if status.get("run_counts"):
        typer.echo("runs:")
        for name, count in sorted(status["run_counts"].items()):
            typer.echo(f"  {name}: {count}")

    if status.get("task_counts"):
        typer.echo("tasks:")
        for name, count in sorted(status["task_counts"].items()):
            typer.echo(f"  {name}: {count}")

    if status.get("attempt_counts"):
        typer.echo("attempts:")
        for name, count in sorted(status["attempt_counts"].items()):
            typer.echo(f"  {name}: {count}")

    for warning in status.get("warnings", []):
        typer.echo(f"warning: {warning}")


@workspace_app.command("adopt")
def workspace_adopt_command(
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(
        None,
        "--scope",
        "-s",
        help="Scope whose target_id will become the workspace owner.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Confirm ownership assignment for an unattributed legacy workspace.",
    ),
) -> None:
    """Explicitly bind a populated, unattributed legacy workspace to one target."""

    if not yes:
        typer.echo(
            "workspace adoption requires --yes after inspecting the selected scope and data",
            err=True,
        )
        raise typer.Exit(code=2)

    pipeline = _resolve_pipeline(pipeline)

    async def _adopt() -> tuple[str, str]:
        configuration = load_runtime_configuration(
            pipeline_path=pipeline,
            scope_path=scope,
        )
        database_config = runtime_database_config(configuration)
        await asyncio.to_thread(upgrade_database, database_config.path)
        database = Database(database_config)
        try:
            binding = await WorkspaceRepository(database).bind_or_validate(
                configuration.scope.target_id,
                allow_unattributed_adoption=True,
            )
            return binding.target_id, str(database.config.path)
        finally:
            await database.dispose()

    try:
        target_id, database_path = asyncio.run(_adopt())
    except Exception as exc:
        typer.echo(f"workspace adopt failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"workspace bound to target: {target_id}")
    typer.echo(f"database: {database_path}")


@app.command("explain")
def explain_command(
    query: str = typer.Argument(
        ...,
        help="Event ID or exact persisted Event value.",
    ),
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
    max_depth: int = typer.Option(8, "--max-depth", min=1, max=64),
) -> None:
    """Show event, provenance path, routed tasks and scheduler decisions."""

    pipeline = _resolve_pipeline(pipeline)

    async def _explain() -> dict[str, Any] | None:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            return await runtime.explain(query, max_depth=max_depth)
        finally:
            await runtime.close()

    try:
        result = asyncio.run(_explain())
    except Exception as exc:
        typer.echo(f"explain failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if result is None:
        typer.echo("no matching persisted event", err=True)
        raise typer.Exit(code=1)

    typer.echo(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


@review_app.command("list")
def review_list_command(
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List open review cases without exposing raw sensitive evidence."""
    pipeline = _resolve_pipeline(pipeline)

    async def _list() -> list[dict[str, Any]]:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            cases = await runtime.list_review_cases()
            return [case.model_dump(mode="json") for case in cases]
        finally:
            await runtime.close()

    try:
        cases = asyncio.run(_list())
    except Exception as exc:
        typer.echo(f"review list failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(cases, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if not cases:
        typer.echo("no open review cases")
        return
    for item in cases:
        categories = ",".join(item["categories"])
        typer.echo(
            f"{item['case_id']}  task={item['task_id']}  "
            f"worker={item['worker']}:{item['action']}  categories={categories}"
        )
        for summary in item["summaries"]:
            typer.echo(f"  {summary}")


@review_app.command("show")
def review_show_command(
    case_id: str = typer.Argument(...),
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
) -> None:
    """Show one review case and its paused task."""
    pipeline = _resolve_pipeline(pipeline)

    async def _show() -> dict[str, Any] | None:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            return await runtime.review_case_details(case_id)
        finally:
            await runtime.close()

    try:
        result = asyncio.run(_show())
    except Exception as exc:
        typer.echo(f"review show failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if result is None:
        typer.echo(f"unknown review case: {case_id}", err=True)
        raise typer.Exit(code=1)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


def _resolve_review_from_cli(
    *,
    case_id: str,
    approve: bool,
    reason: str | None,
    pipeline: Path | None,
    scope: Path | None,
) -> None:
    resolved_pipeline = _resolve_pipeline(pipeline)

    async def _resolve() -> dict[str, Any]:
        runtime = await build_runtime(
            pipeline_path=resolved_pipeline,
            scope_path=scope,
        )
        try:
            case = (
                await runtime.approve_review_case(case_id, reason=reason)
                if approve
                else await runtime.reject_review_case(case_id, reason=reason)
            )
            return case.model_dump(mode="json")
        finally:
            await runtime.close()

    action = "approve" if approve else "reject"
    try:
        result = asyncio.run(_resolve())
    except Exception as exc:
        typer.echo(f"review {action} failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"{result['case_id']}: {result['state']}")


@review_app.command("approve")
def review_approve_command(
    case_id: str = typer.Argument(...),
    reason: str | None = typer.Option(None, "--reason"),
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
) -> None:
    """Approve and release exactly one paused task."""
    _resolve_review_from_cli(
        case_id=case_id,
        approve=True,
        reason=reason,
        pipeline=pipeline,
        scope=scope,
    )


@review_app.command("reject")
def review_reject_command(
    case_id: str = typer.Argument(...),
    reason: str | None = typer.Option(None, "--reason"),
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
) -> None:
    """Reject and permanently block exactly one paused task."""
    _resolve_review_from_cli(
        case_id=case_id,
        approve=False,
        reason=reason,
        pipeline=pipeline,
        scope=scope,
    )


@app.command("export")
def export_command(
    format: str = typer.Option(
        "all",
        "--format",
        "-f",
        help="jsonl, text, csv, graph-json, tree-json, html, or all.",
    ),
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Override destination. Only valid for one selected format.",
    ),
    sensitive: bool = typer.Option(
        False,
        "--sensitive",
        help="Include protected raw sensitive evidence in a separate export surface.",
    ),
    confirm_sensitive: bool = typer.Option(
        False,
        "--confirm-sensitive",
        help="Required second opt-in for --sensitive.",
    ),
    confirmed_only: bool = typer.Option(False, "--confirmed-only"),
    include_hypotheses: bool = typer.Option(True, "--include-hypotheses/--no-hypotheses"),
    include_historical: bool = typer.Option(True, "--include-historical/--no-historical"),
    include_out_of_scope: bool = typer.Option(False, "--include-out-of-scope"),
    include_intelligence: bool = typer.Option(False, "--include-intelligence"),
    include_provenance: bool = typer.Option(False, "--include-provenance"),
    root: str | None = typer.Option(None, "--root"),
    max_depth: int | None = typer.Option(None, "--max-depth", min=0, max=128),
    min_confidence: float = typer.Option(0.0, "--min-confidence", min=0.0, max=1.0),
    max_nodes: int = typer.Option(100_000, "--max-nodes", min=1, max=1_000_000),
    max_edges: int = typer.Option(250_000, "--max-edges", min=1, max=2_000_000),
) -> None:
    """Export persisted findings in SAFE or explicitly confirmed sensitive mode."""

    pipeline = _resolve_pipeline(pipeline)
    normalized_format = format.strip().lower()
    graph_formats = {"graph-json", "tree-json", "html"}
    supported_formats = {"jsonl", "text", "csv", *graph_formats}
    if normalized_format not in {*supported_formats, "all"}:
        raise typer.BadParameter(
            "--format must be jsonl, text, csv, graph-json, tree-json, html, or all"
        )

    if normalized_format == "all" and output is not None:
        raise typer.BadParameter("--output can only be used with one explicit format")

    if sensitive and not confirm_sensitive:
        typer.echo(
            "sensitive export requires both --sensitive and --confirm-sensitive",
            err=True,
        )
        raise typer.Exit(code=2)

    mode = ExportMode.SENSITIVE_EVIDENCE if sensitive else ExportMode.SAFE
    formats = (
        (
            "jsonl",
            "text",
            "csv",
            "graph-json",
            "tree-json",
            "html",
        )
        if normalized_format == "all"
        else (normalized_format,)
    )
    graph_filter = SurfaceGraphFilter(
        confirmed_only=confirmed_only,
        include_hypotheses=include_hypotheses,
        include_historical=include_historical,
        include_out_of_scope=include_out_of_scope,
        include_intelligence=include_intelligence,
        include_provenance=include_provenance,
        root=root,
        max_depth=max_depth,
        min_confidence=min_confidence,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )

    async def _export() -> list[str]:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            paths: list[str] = []
            for item in formats:
                section = getattr(
                    runtime.configuration.pipeline.exports,
                    item.replace("-", "_"),
                )
                if normalized_format == "all" and not section.enabled:
                    continue
                written = await runtime.export(
                    format=item,
                    mode=mode,
                    confirm_sensitive=confirm_sensitive,
                    output=output if len(formats) == 1 else None,
                    graph_filter=graph_filter if item in graph_formats else None,
                )
                paths.extend(str(path) for path in written)
            return paths
        finally:
            await runtime.close()

    try:
        paths = asyncio.run(_export())
    except Exception as exc:
        typer.echo(f"export failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for path in paths:
        typer.echo(path)


@graph_app.command("rebuild")
def graph_rebuild_command(
    pipeline: Path | None = typer.Option(None, "--pipeline", "-p"),
    scope: Path | None = typer.Option(None, "--scope", "-s", help=_SCOPE_WORKSPACE_HELP),
    dry_run: bool = typer.Option(False, "--dry-run"),
    batch_size: int = typer.Option(500, "--batch-size", min=1, max=10_000),
) -> None:
    """Rebuild semantic relationships offline without target traffic."""

    pipeline = _resolve_pipeline(pipeline)

    async def _rebuild() -> dict[str, Any]:
        runtime = await build_runtime(pipeline_path=pipeline, scope_path=scope)
        try:
            report = await SurfaceGraphRebuilder(runtime.database).rebuild(
                dry_run=dry_run,
                batch_size=batch_size,
            )
            return report.model_dump(mode="json")
        finally:
            await runtime.close()

    try:
        report = asyncio.run(_rebuild())
    except Exception as exc:
        typer.echo(f"graph rebuild failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


def _wordlists_cli(argv: list[str]) -> None:
    paths = user_paths()
    refresh_user_wordlist_resources(paths)
    code = wordlists_sync_main(["--root", str(paths.data_root), *argv])
    if code:
        raise typer.Exit(code=code)


@wordlists_app.command("list")
def wordlists_list_command() -> None:
    """Show configured public wordlist sources and local install state."""

    _wordlists_cli(["list"])


@wordlists_app.command("verify")
def wordlists_verify_command() -> None:
    """Verify synchronized corpora against the local SHA-256 lock."""

    _wordlists_cli(["verify"])


@wordlists_app.command("sync")
def wordlists_sync_command(
    source_ids: list[str] = typer.Option(
        None,
        "--source",
        help="Exact source ID; repeat to sync selected sources.",
    ),
    all_sources: bool = typer.Option(
        False,
        "--all",
        help="Also sync large/optional public corpora.",
    ),
) -> None:
    """Explicitly download/update public wordlists and regenerate the local manifest."""

    argv = ["sync"]
    for source_id in source_ids or ():
        argv.extend(["--source", source_id])
    if all_sources:
        argv.append("--all")
    _wordlists_cli(argv)


def _prepare_default_scope_for_run(
    *,
    targets: tuple[str, ...] = (),
    target: str | None = None,
    pipeline: Path,
    scope: Path | None,
    authorize_exact: bool,
    authorize_subdomains: bool,
) -> None:
    """Offer explicit first-run authorization only for managed local targets."""

    if target is not None:
        if targets:
            raise ValueError("use either target or targets, not both")
        targets = (target,)

    if not targets or scope is not None or not is_default_user_pipeline(pipeline):
        return

    try:
        cfg = load_runtime_configuration(pipeline_path=pipeline, scope_path=None)
        engine = ScopeEngine(list(effective_scope_rules(cfg.scope.rules)))
    except Exception as exc:
        typer.echo(f"scope preflight failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for target in targets:
        try:
            subject = ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=target)
            decision = engine.evaluate(subject)
        except Exception as exc:
            typer.echo(
                f"scope preflight failed for {target!r}: {type(exc).__name__}: {exc}", err=True
            )
            raise typer.Exit(code=2) from exc

        if decision.state in {ScopeState.IN_SCOPE, ScopeState.PASSIVE_ONLY}:
            continue

        if decision.state is not ScopeState.UNKNOWN:
            typer.echo(
                f"target {subject.value} is {decision.state.value} in {cfg.scope_path}; "
                "Night Scout will not override an existing scope classification",
                err=True,
            )
            raise typer.Exit(code=2)

        include_subdomains = authorize_subdomains
        authorize = authorize_exact or authorize_subdomains

        if not authorize:
            if not sys.stdin.isatty():
                typer.echo(
                    f"target {subject.value} has no explicit scope rule. For non-interactive "
                    "use, pass --authorize-exact or --authorize-subdomains, or provide --scope.",
                    err=True,
                )
                raise typer.Exit(code=2)
            authorize = typer.confirm(
                f"Confirm that exact domain {subject.value} is authorized for active testing?",
                default=False,
            )
            if not authorize:
                typer.echo("scope not changed; run cancelled", err=True)
                raise typer.Exit(code=2)
            include_subdomains = typer.confirm(
                f"Also confirm that all subdomains *.{subject.value} are authorized?",
                default=False,
            )

        add_confirmed_domain_scope(
            subject.value,
            include_subdomains=include_subdomains,
            scope_path=cfg.scope_path,
        )
        typer.echo(
            f"scope updated: {subject.value}"
            + (f" and *.{subject.value}" if include_subdomains else "")
        )
        # Refresh the in-memory preflight engine so subsequent explicit seeds in
        # the same command see the rules we just persisted.
        cfg = load_runtime_configuration(pipeline_path=pipeline, scope_path=None)
        engine = ScopeEngine(list(effective_scope_rules(cfg.scope.rules)))


@tools_app.command("list")
def tools_list_command(
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List the supported managed specialist tools."""

    try:
        platform_info = assert_supported_platform()
        manifest = load_tools_manifest()
    except Exception as exc:
        typer.echo(f"tools list failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    rows = []
    for spec in manifest.tools:
        apt_spec = spec.apt.get(platform_info.os_id)
        install_path = (
            f"apt:{apt_spec.package} -> fallback:{spec.strategy.value}"
            if apt_spec is not None
            else f"upstream:{spec.strategy.value}"
        )
        rows.append(
            {
                "tool_id": spec.tool_id,
                "binary": spec.binary,
                "requirement": spec.requirement.value,
                "strategy": spec.strategy.value,
                "apt_package": apt_spec.package if apt_spec is not None else None,
                "apt_binary": apt_spec.binary if apt_spec is not None else None,
                "install_path": install_path,
                "workers": list(spec.workers),
                "description": spec.description,
            }
        )
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "platform": platform_info.model_dump(mode="json"),
                    "managed_bin": str(managed_bin_dir(manifest)),
                    "tools": rows,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return

    typer.echo(f"platform:    {platform_info.pretty_name} / {platform_info.architecture}")
    typer.echo(f"managed bin: {managed_bin_dir(manifest)}")
    typer.echo("")
    for row in rows:
        typer.echo(
            f"{row['tool_id']:<14} {row['requirement']:<8} "
            f"{row['install_path']:<36} {row['description']}"
        )


@tools_app.command("verify")
def tools_verify_command(
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Verify installed tool identities/versions without scanning."""

    try:
        assert_supported_platform()
        manifest = load_tools_manifest()
        statuses = probe_all_tools(manifest)
    except Exception as exc:
        typer.echo(f"tools verify failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(
            json.dumps(
                [status.model_dump(mode="json") for status in statuses],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for status in statuses:
            marker = (
                "OK"
                if status.installed and status.identity_ok
                else ("WARN" if not status.required else "FAIL")
            )
            typer.echo(f"[{marker:4}] {status.tool_id}: {status.detail}")

    failed = any(
        status.required and not (status.installed and status.identity_ok) for status in statuses
    )
    if failed:
        raise typer.Exit(code=1)


@tools_app.command("install")
def tools_install_command(
    tool_ids: list[str] = typer.Argument(
        None,
        help="Optional tool IDs. Without IDs installs required runtime tools.",
    ),
    include_optional: bool = typer.Option(
        False,
        "--optional",
        help="Also install optional mobile-analysis tools.",
    ),
    all_tools: bool = typer.Option(
        False,
        "--all",
        help="Install every manifest tool.",
    ),
    update: bool = typer.Option(False, "--update", help="Update already installed tools."),
    install_prerequisites: bool = typer.Option(
        False,
        "--install-prerequisites",
        help="Allow apt-get (and sudo when needed) for fallback prerequisites such as Java/pipx.",
    ),
    allow_unverified: bool = typer.Option(
        False,
        "--allow-unverified",
        help="Permit a GitHub asset lacking an upstream SHA-256 digest/checksum.",
    ),
) -> None:
    """Install companion tools using distro APT first, then verified upstream fallback."""

    typer.echo(
        "Installing/verifying companion tools (APT-first, upstream fallback). "
        "Network downloads may take several minutes; live installer output follows."
    )
    try:
        results = install_tools(
            requested=tuple(tool_ids or ()),
            include_optional=include_optional,
            all_tools=all_tools,
            update=update,
            allow_unverified=allow_unverified,
            install_prerequisites=install_prerequisites,
            progress=_render_tool_progress,
        )
    except KeyboardInterrupt:
        typer.echo("tools install interrupted; rerun to verify/resume", err=True)
        raise typer.Exit(code=130) from None
    except Exception as exc:
        typer.echo(f"tools install failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for result in results:
        marker = "SKIP" if result.skipped else "OK"
        typer.echo(f"[{marker:4}] {result.tool_id}: {result.detail}")


if __name__ == "__main__":
    app()
