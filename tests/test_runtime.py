from __future__ import annotations

import shutil

import pytest
import yaml

from recon.core.queue import TaskStatus
from recon.runtime import build_runtime
from recon.storage.schema import current_revision, head_revision


@pytest.mark.asyncio
async def test_recursive_local_runtime_survives_migration_bootstrap(tmp_path, project_root):
    root = tmp_path / "project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(project_root / "configs" / "scope.example.yaml", root / "configs" / "scope.example.yaml")

    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.example.yaml"
    pipeline["storage"]["database"]["path"] = "workspace.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"] = {
        "max_steps": 20,
        "project_vocabulary": False,
        "vulnerability_enrichment": False,
        "snapshot_capture": False,
        "snapshot_diff_on_write": False,
        "build_genome_on_finish": False,
    }
    pipeline["routing"]["enabled_rule_ids"] = [
        "permutations.root.targeted",
        "permutations.root.exploration",
    ]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True
    pipeline["workers"]["permutations"]["config"]["max_candidates"] = 3

    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        summary = await runtime.run_domain("example.com", max_steps=10)
        assert summary.event_count >= 1
        tasks = await runtime.task_store.all()
        assert tasks
        assert all(task.status in {TaskStatus.SUCCEEDED, TaskStatus.BLOCKED, TaskStatus.REVIEW} for task in tasks)
        assert any(task.status is TaskStatus.SUCCEEDED for task in tasks)
    finally:
        await runtime.close()

    database_path = root / "workspace.sqlite3"
    assert current_revision(database_path) == head_revision(database_path)
