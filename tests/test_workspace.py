from __future__ import annotations

import shutil
import sqlite3

import pytest
import yaml
from typer.testing import CliRunner

from recon.cli import app
from recon.core.events import Event, EventType
from recon.runtime import NightScoutRuntime, load_runtime_configuration, runtime_database_config
from recon.storage.database import Database, EventRepository, RunRepository
from recon.storage.schema import upgrade_database
from recon.storage.workspace import (
    WorkspaceRepository,
    WorkspaceTargetMismatchError,
    WorkspaceUnboundError,
    workspace_directory_name,
)


def _write_target_configs(tmp_path, project_root):
    root = tmp_path / "project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")

    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text(encoding="utf-8")
    )
    pipeline["scope_file"] = "configs/corp.yaml"
    pipeline["storage"]["database"]["path"] = "nightscout.sqlite3"
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    base_scope = yaml.safe_load(
        (project_root / "configs" / "scope.example.yaml").read_text(encoding="utf-8")
    )
    corp_scope = root / "configs" / "corp.yaml"
    other_scope = root / "configs" / "other.yaml"
    base_scope["target_id"] = "corp"
    corp_scope.write_text(yaml.safe_dump(base_scope, sort_keys=False), encoding="utf-8")
    base_scope["target_id"] = "another-company"
    other_scope.write_text(yaml.safe_dump(base_scope, sort_keys=False), encoding="utf-8")

    return root, pipeline_path, corp_scope, other_scope


def test_target_id_selects_an_isolated_workspace(tmp_path, project_root) -> None:
    root, pipeline_path, corp_scope, other_scope = _write_target_configs(
        tmp_path,
        project_root,
    )

    corp = load_runtime_configuration(pipeline_path=pipeline_path, scope_path=corp_scope)
    other = load_runtime_configuration(pipeline_path=pipeline_path, scope_path=other_scope)

    assert corp.workspace_root == root / "workspaces" / "corp"
    assert other.workspace_root == root / "workspaces" / "another-company"
    assert runtime_database_config(corp).path != runtime_database_config(other).path


@pytest.mark.asyncio
async def test_runtime_rejects_reusing_an_explicit_workspace_for_another_target(
    monkeypatch,
    tmp_path,
    project_root,
) -> None:
    _, pipeline_path, corp_scope, other_scope = _write_target_configs(tmp_path, project_root)
    monkeypatch.setenv("NIGHTSCOUT_WORKSPACE_ROOT", str(tmp_path / "shared-workspace"))

    runtime = await NightScoutRuntime.build(
        pipeline_path=pipeline_path,
        scope_path=corp_scope,
    )
    await runtime.close()

    with pytest.raises(WorkspaceTargetMismatchError, match="belongs to target 'corp'"):
        await NightScoutRuntime.build(
            pipeline_path=pipeline_path,
            scope_path=other_scope,
        )


def test_unsafe_target_id_has_a_stable_safe_directory_name() -> None:
    first = workspace_directory_name("Компания Corp / Production")
    second = workspace_directory_name("Компания Corp / Production")

    assert first == second
    assert first.startswith("target-")
    assert "/" not in first


def test_workspace_adopt_cli_binds_an_unattributed_flat_database(
    tmp_path,
    project_root,
) -> None:
    root, pipeline_path, corp_scope, _ = _write_target_configs(tmp_path, project_root)
    path = root / "nightscout.sqlite3"
    upgrade_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO recon_runs(run_id,status,started_at,metadata_json) VALUES(?,?,?,?)",
            (
                "run_unattributed",
                "RUNNING",
                "2026-08-20T10:00:00.000000+00:00",
                "{}",
            ),
        )
        connection.commit()

    result = CliRunner().invoke(
        app,
        [
            "workspace",
            "adopt",
            "--pipeline",
            str(pipeline_path),
            "--scope",
            str(corp_scope),
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert "workspace bound to target: corp" in result.stdout
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT target_id FROM workspace_metadata WHERE singleton_id=1"
        ).fetchone() == ("corp",)
        assert connection.execute(
            "SELECT target_id FROM recon_runs WHERE run_id='run_unattributed'"
        ).fetchone() == ("corp",)


@pytest.mark.asyncio
async def test_workspace_binding_rejects_a_different_scope_target(tmp_path) -> None:
    path = tmp_path / "workspace.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        repository = WorkspaceRepository(database)
        created = await repository.bind_or_validate("corp")
        existing = await repository.bind_or_validate("corp")

        assert created.created is True
        assert existing.created is False
        with pytest.raises(WorkspaceTargetMismatchError, match="belongs to target 'corp'"):
            await repository.bind_or_validate("another-company")
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_populated_unattributed_workspace_requires_explicit_adoption(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        await EventRepository(database).ingest(
            Event(type=EventType.ROOT_DOMAIN, value="corp.example", source="fixture")
        )
        repository = WorkspaceRepository(database)

        with pytest.raises(WorkspaceUnboundError, match="workspace adopt"):
            await repository.bind_or_validate("corp")

        adopted = await repository.bind_or_validate(
            "corp",
            allow_unattributed_adoption=True,
        )
        assert adopted.target_id == "corp"
        assert adopted.created is True
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_legacy_run_history_is_adopted_only_for_matching_target(tmp_path) -> None:
    path = tmp_path / "legacy-history.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        runs = RunRepository(database)
        await runs.start(target_id="corp")

        repository = WorkspaceRepository(database)
        binding = await repository.bind_or_validate("corp")
        assert binding.adopted_from_history is True
    finally:
        await database.dispose()
