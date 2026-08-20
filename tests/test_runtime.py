from __future__ import annotations

import shutil

import pytest
import yaml
from sqlalchemy import select

from recon.core.events import Event, EventType
from recon.core.lifecycle import LifecycleOutcome
from recon.core.queue import Task, TaskStatus
from recon.policy.review_gate import ReviewCategory, ReviewSignal
from recon.runtime import build_runtime
from recon.storage.models import EventObservationRecord, TaskRecord
from recon.storage.schema import current_revision, head_revision


@pytest.mark.asyncio
async def test_recursive_local_runtime_survives_migration_bootstrap(tmp_path, project_root):
    root = tmp_path / "project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )

    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
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


@pytest.mark.asyncio
async def test_program_restriction_review_can_be_listed_approved_and_executed(
    tmp_path,
    project_root,
):
    root = tmp_path / "review-project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text()
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "review.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"] = {
        "max_steps": 1,
        "project_vocabulary": False,
        "vulnerability_enrichment": False,
        "snapshot_capture": False,
        "snapshot_diff_on_write": False,
        "build_genome_on_finish": False,
    }
    pipeline["routing"]["enabled_rule_ids"] = ["permutations.root.targeted"]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True
    pipeline["workers"]["permutations"]["config"]["max_candidates"] = 1
    pipeline["restrictions"] = {
        "enabled": True,
        "rules": [
            {
                "rule_id": "manual-permutations",
                "outcome": "REVIEW",
                "workers": ["permutations"],
                "reason": "operator approval required",
            }
        ],
    }
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        summary = await runtime.run_domain("example.com", max_steps=1)
        assert summary.outcomes == {LifecycleOutcome.REVIEW.value: 1}
        cases = await runtime.list_review_cases()
        assert len(cases) == 1
        assert "manual-permutations" in cases[0].summaries[0]

        approved = await runtime.approve_review_case(
            cases[0].case_id,
            reason="authorized fixture",
        )
        assert approved.state.value == "APPROVED"
        result = await runtime.lifecycle.run_once()
        assert result.outcome is LifecycleOutcome.SUCCEEDED
        task = await runtime.queue.get(cases[0].task_id)
        assert task is not None and task.status is TaskStatus.SUCCEEDED

        event = Event(
            type=EventType.DNS_NAME,
            value="rejected.example.com",
            source="test",
        )
        await runtime.events.ingest(event)
        rejected_task = Task(
            worker="permutations",
            action="generate_targeted",
            input_event_id=event.event_id,
            input_identity_key=event.identity_key,
        )
        assert await runtime.queue.enqueue(rejected_task)
        await runtime.queue.send_to_review(
            rejected_task.task_id,
            reason="manual fixture",
        )
        rejected_case = await runtime.review_store.open_or_get(
            task=rejected_task,
            signals=(
                ReviewSignal(
                    category=ReviewCategory.POLICY_AMBIGUITY,
                    summary="reject fixture",
                ),
            ),
        )
        rejected = await runtime.reject_review_case(
            rejected_case.case_id,
            reason="not authorized",
        )
        assert rejected.state.value == "BLOCKED"
        blocked_task = await runtime.queue.get(rejected_task.task_id)
        assert blocked_task is not None and blocked_task.status is TaskStatus.BLOCKED
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_scope_review_always_creates_approvable_review_case(
    tmp_path,
    project_root,
):
    root = tmp_path / "scope-review-project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text()
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "scope-review.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["routing"]["enabled_rule_ids"] = []
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        event = Event(
            type=EventType.DNS_NAME,
            value="outside-scope.invalid",
            source="test",
        )
        await runtime.events.ingest(event)
        task = Task(
            worker="dns",
            action="resolve",
            input_event_id=event.event_id,
            input_identity_key=event.identity_key,
        )
        assert await runtime.queue.enqueue(task)

        result = await runtime.lifecycle.run_once()
        cases = await runtime.list_review_cases()

        assert result.outcome is LifecycleOutcome.REVIEW
        assert len(cases) == 1
        assert cases[0].task_id == task.task_id
        assert cases[0].categories == (ReviewCategory.SCOPE_AMBIGUITY,)

        await runtime.approve_review_case(cases[0].case_id, reason="fixture")
        resumed = await runtime.lifecycle.run_once()
        assert resumed.outcome is not LifecycleOutcome.REVIEW
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_disabled_exploration_removes_routes_and_blocks_old_frontier(
    tmp_path,
    project_root,
):
    root = tmp_path / "disabled-exploration"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text()
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "disabled.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["exploration"]["enabled"] = False
    pipeline["routing"]["enabled_rule_ids"] = [
        "permutations.root.exploration"
    ]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        assert runtime.router.get("permutations.root.exploration") is None

        event = Event(
            type=EventType.ROOT_DOMAIN,
            value="example.com",
            source="test",
        )
        await runtime.events.ingest(event)
        old_task = Task(
            worker="permutations",
            action="generate_exploration",
            input_event_id=event.event_id,
            route_rule_id="permutations.root.exploration",
        )
        assert await runtime.queue.enqueue(old_task)
        result = await runtime.lifecycle.run_once()
        assert result.outcome is LifecycleOutcome.BLOCKED
        assert "exploration is disabled" in (result.reason or "")
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_runtime_search_tier_controls_worker_candidate_limit(
    tmp_path,
    project_root,
):
    root = tmp_path / "tiered-exploration"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    shutil.copytree(project_root / "wordlists", root / "wordlists")
    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text()
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "tiered.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["exploration"].update(
        {"enabled": True, "initial_tier": "MICRO", "maximum_tier": "MICRO"}
    )
    pipeline["routing"]["enabled_rule_ids"] = [
        "permutations.root.exploration"
    ]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True
    pipeline["workers"]["permutations"]["config"].update(
        {"tier": "EXHAUSTIVE", "max_candidates": 300}
    )
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        summary = await runtime.run_domain("example.com", max_steps=1)
        assert summary.outcomes == {LifecycleOutcome.SUCCEEDED.value: 1}
        async with runtime.database.session() as session:
            rows = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).where(
                            EventObservationRecord.source.like("permutations:%")
                        )
                    )
                ).all()
            )
        assert rows
        assert len(rows) <= 50
        assert all(row.metadata_json["candidate_tier"] == "MICRO" for row in rows)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_persistent_frontier_keeps_origin_and_attributes_resume_to_new_run(
    tmp_path,
    project_root,
):
    root = tmp_path / "resumed-frontier"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    shutil.copytree(project_root / "wordlists", root / "wordlists")
    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text()
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "resume.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "resume_frontier": True,
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["routing"]["enabled_rule_ids"] = [
        "permutations.root.targeted",
        "permutations.root.exploration",
    ]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True
    pipeline["workers"]["permutations"]["config"]["max_candidates"] = 2
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        first = await runtime.run_domain("example.com", max_steps=1)
        async with runtime.database.session() as session:
            old_pending = await session.scalar(
                select(TaskRecord).where(
                    TaskRecord.run_id == first.run_id,
                    TaskRecord.status == TaskStatus.PENDING.value,
                )
            )
        assert old_pending is not None
        old_task_id = old_pending.task_id
        async with runtime.database.transaction(immediate=True) as session:
            prioritized = await session.get(TaskRecord, old_task_id)
            assert prioritized is not None
            prioritized.priority = 100.0

        second = await runtime.run_domain("example.com", max_steps=1)
        assert second.run_id != first.run_id
        assert second.task_counts == {"PENDING": 1, "SUCCEEDED": 1}

        async with runtime.database.session() as session:
            resumed = await session.get(TaskRecord, old_task_id)
        assert resumed is not None
        assert resumed.run_id == first.run_id
        assert resumed.execution_run_id == second.run_id

        global_status = await runtime.status()
        assert global_status.event_count > second.event_count
        assert sum(global_status.task_counts.values()) > sum(
            second.task_counts.values()
        )
    finally:
        await runtime.close()
