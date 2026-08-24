from __future__ import annotations

import asyncio
import shutil
import time
from datetime import timedelta

import pytest
import yaml
from sqlalchemy import select

from recon.core.events import Event, EventType
from recon.core.lifecycle import DispatchTicket, LifecycleOutcome, LifecycleResult
from recon.core.queue import Task, TaskStatus, utc_now
from recon.core.scheduler import (
    ScheduleDecision,
    SchedulingSignals,
)
from recon.policy.review_gate import ReviewCategory, ReviewSignal
from recon.runtime import RuntimeProgress, build_runtime
from recon.storage.models import EventObservationRecord, TaskRecord
from recon.storage.schema import current_revision, head_revision


@pytest.mark.asyncio
async def test_runtime_dispatcher_runs_twenty_independent_tasks_at_four_way_parallelism(
    tmp_path,
    project_root,
) -> None:
    root = tmp_path / "parallel-project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "parallel.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["runtime"]["parallelism"].update(
        {"execution_concurrency": 4, "worker_limits": {}}
    )
    pipeline["routing"]["enabled_rule_ids"] = []
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    class TimedLifecycle:
        def __init__(self) -> None:
            self.remaining = 20
            self.active = 0
            self.max_active = 0

        async def admit_batch(self, *, limit, **kwargs):
            del kwargs
            count = min(limit, self.remaining)
            self.remaining -= count
            if count == 0:
                return [LifecycleResult(outcome=LifecycleOutcome.IDLE)]
            tickets = []
            for index in range(count):
                now = utc_now()
                task = Task(
                    worker="fixture",
                    action="sleep",
                    input_event_id=f"evt_{self.remaining}_{index}",
                    status=TaskStatus.RUNNING,
                    attempts=1,
                    started_at=now,
                    lease_expires_at=now + timedelta(minutes=1),
                    claim_token=f"claim-{self.remaining}-{index}",
                )
                schedule = ScheduleDecision(
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    input_event_id=task.input_event_id,
                    score=0.0,
                    breakdown={
                        "route_priority": 0.0,
                        "confidence": 0.0,
                        "novelty": 0.0,
                        "expected_yield": 0.0,
                        "information_gain": 0.0,
                        "age_boost": 0.0,
                        "cost_penalty": 0.0,
                        "retry_penalty": 0.0,
                        "total": 0.0,
                    },
                    signals=SchedulingSignals(),
                    evaluated_at=now,
                )
                tickets.append(DispatchTicket(task=task, schedule=schedule))
            return tickets

        async def execute_claimed(self, ticket):
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            try:
                await asyncio.sleep(0.05)
            finally:
                self.active -= 1
            return LifecycleResult(
                outcome=LifecycleOutcome.SUCCEEDED,
                task_id=ticket.task.task_id,
                worker=ticket.task.worker,
                action=ticket.task.action,
                queue_status=TaskStatus.SUCCEEDED,
                claimed=True,
                execution_attempt=1,
            )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    lifecycle = TimedLifecycle()
    runtime.lifecycle = lifecycle  # type: ignore[assignment]
    try:
        started = time.perf_counter()
        summary = await runtime.run_domain("example.com", max_steps=20)
        elapsed = time.perf_counter() - started
        assert summary.steps == 20
        assert summary.outcomes == {"SUCCEEDED": 20}
        assert lifecycle.max_active == 4
        assert elapsed < 0.65  # Serial fixture time is at least 1.0 second.
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_runtime_treats_capacity_deferral_as_silent_backpressure(
    tmp_path,
    project_root,
) -> None:
    root = tmp_path / "backpressure-project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "backpressure.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["runtime"]["parallelism"].update(
        {"execution_concurrency": 2, "worker_limits": {}}
    )
    pipeline["routing"]["enabled_rule_ids"] = []
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    class BackpressureLifecycle:
        def __init__(self) -> None:
            self.admit_calls = 0
            self.executing = False
            self.admitted_while_executing = False

        async def admit_batch(self, *, limit, **kwargs):
            del limit, kwargs
            self.admit_calls += 1
            self.admitted_while_executing |= self.executing
            if self.admit_calls > 1:
                return [LifecycleResult(outcome=LifecycleOutcome.IDLE)]
            now = utc_now()
            task = Task(
                worker="fixture",
                action="sleep",
                input_event_id="evt_backpressure",
                status=TaskStatus.RUNNING,
                attempts=1,
                started_at=now,
                lease_expires_at=now + timedelta(minutes=1),
                claim_token="claim-backpressure",
            )
            schedule = ScheduleDecision(
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                input_event_id=task.input_event_id,
                score=0.0,
                breakdown={
                    "route_priority": 0.0,
                    "confidence": 0.0,
                    "novelty": 0.0,
                    "expected_yield": 0.0,
                    "information_gain": 0.0,
                    "age_boost": 0.0,
                    "cost_penalty": 0.0,
                    "retry_penalty": 0.0,
                    "total": 0.0,
                },
                signals=SchedulingSignals(),
                evaluated_at=now,
            )
            return [
                DispatchTicket(task=task, schedule=schedule),
                LifecycleResult(
                    outcome=LifecycleOutcome.DEFERRED,
                    reason="soft execution capacity exhausted",
                    backpressure=True,
                ),
            ]

        async def execute_claimed(self, ticket):
            self.executing = True
            try:
                await asyncio.sleep(0.02)
            finally:
                self.executing = False
            return LifecycleResult(
                outcome=LifecycleOutcome.SUCCEEDED,
                task_id=ticket.task.task_id,
                worker=ticket.task.worker,
                action=ticket.task.action,
                queue_status=TaskStatus.SUCCEEDED,
                claimed=True,
                execution_attempt=1,
            )

    runtime = await build_runtime(pipeline_path=pipeline_path)
    lifecycle = BackpressureLifecycle()
    runtime.lifecycle = lifecycle  # type: ignore[assignment]
    progress: list[RuntimeProgress] = []
    try:
        summary = await runtime.run_domain(
            "example.com",
            max_steps=2,
            progress=progress.append,
        )
        assert summary.outcomes == {"IDLE": 1, "SUCCEEDED": 1}
        assert lifecycle.admit_calls == 2
        assert lifecycle.admitted_while_executing is False
        assert all(item.outcome is not LifecycleOutcome.DEFERRED for item in progress)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_concurrent_event_publish_has_bounded_single_writer_without_loss(
    tmp_path,
    project_root,
) -> None:
    root = tmp_path / "publish-project"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "publish.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["runtime"]["parallelism"].update(
        {"execution_concurrency": 4, "event_queue_capacity": 4}
    )
    pipeline["routing"]["enabled_rule_ids"] = []
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    runtime = await build_runtime(pipeline_path=pipeline_path)
    try:
        writes = await asyncio.gather(
            *(
                runtime.event_bus.publish(
                    Event(
                        type=EventType.ARTIFACT,
                        value=f"artifact-{index}",
                        source="parallel-fixture",
                    )
                )
                for index in range(30)
            )
        )
        status = await runtime.status()
        assert all(writes)
        assert status.event_count == 30
        assert status.asset_count == 30
        assert status.event_queue_capacity == 4
        assert status.event_queue_high_watermark >= 4
        assert status.event_queue_depth == 0
        assert status.sqlite_busy_count == 0
    finally:
        await runtime.close()


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
        assert summary.attempt_counts.get(LifecycleOutcome.SUCCEEDED.value, 0) >= 1
        tasks = await runtime.task_store.all()
        assert tasks
        assert all(
            task.status in {TaskStatus.SUCCEEDED, TaskStatus.BLOCKED, TaskStatus.REVIEW}
            for task in tasks
        )
        assert any(task.status is TaskStatus.SUCCEEDED for task in tasks)
    finally:
        await runtime.close()

    database_path = root / "workspaces" / "example-program" / "workspace.sqlite3"
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
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
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
        assert summary.attempt_counts == {LifecycleOutcome.REVIEW.value: 1}
        assert summary.status == "PAUSED"
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
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
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
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "disabled.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["exploration"]["enabled"] = False
    pipeline["routing"]["enabled_rule_ids"] = ["permutations.root.exploration"]
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
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
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
    pipeline["routing"]["enabled_rule_ids"] = ["permutations.root.exploration"]
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
        updates: list[RuntimeProgress] = []
        summary = await runtime.run_domain(
            "example.com",
            max_steps=1,
            progress=updates.append,
        )
        assert summary.outcomes == {LifecycleOutcome.SUCCEEDED.value: 1}
        assert any(item.phase == "EXECUTING" and item.worker == "permutations" for item in updates)
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
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
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
        assert sum(global_status.task_counts.values()) > sum(second.task_counts.values())
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_resume_frontier_false_rejects_hidden_active_frontier(
    tmp_path,
    project_root,
):
    root = tmp_path / "isolated-frontier"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    shutil.copytree(project_root / "wordlists", root / "wordlists")
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "isolated.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "resume_frontier": False,
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
        assert first.status == "PAUSED"
        assert any(not task.is_terminal for task in await runtime.task_store.all())

        with pytest.raises(RuntimeError, match="requires an empty active frontier"):
            await runtime.run_domain("example.com", max_steps=1)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_runtime_waits_for_short_deferred_frontier(
    tmp_path,
    project_root,
    monkeypatch,
):
    root = tmp_path / "deferred-wait"
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        root / "configs" / "scope.yaml",
    )
    shutil.copytree(project_root / "wordlists", root / "wordlists")
    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "deferred.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "max_deferred_wait_seconds": 1,
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["routing"]["enabled_rule_ids"] = []
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    class FakeLifecycle:
        def __init__(self) -> None:
            self.results = iter(
                (
                    LifecycleResult(outcome=LifecycleOutcome.RETRY),
                    LifecycleResult(outcome=LifecycleOutcome.IDLE),
                    LifecycleResult(outcome=LifecycleOutcome.SUCCEEDED),
                    LifecycleResult(outcome=LifecycleOutcome.IDLE),
                )
            )
            self.calls = 0

        async def run_once(self, *, on_claimed=None) -> LifecycleResult:
            del on_claimed
            self.calls += 1
            return next(self.results)

    runtime = await build_runtime(pipeline_path=pipeline_path)
    fake_lifecycle = FakeLifecycle()
    next_ready_values = iter((utc_now() + timedelta(milliseconds=10), None))

    async def fake_next_ready_at():
        return next(next_ready_values)

    monkeypatch.setattr(runtime, "lifecycle", fake_lifecycle)
    monkeypatch.setattr(runtime.task_store, "next_ready_at", fake_next_ready_at)
    updates: list[RuntimeProgress] = []
    try:
        summary = await runtime.run_domain(
            "example.com",
            max_steps=3,
            progress=updates.append,
        )
        assert fake_lifecycle.calls == 4
        assert summary.status == "SUCCEEDED"
        assert summary.stopped_idle is True
        assert summary.outcomes == {"IDLE": 1, "RETRY": 1, "SUCCEEDED": 1}
        assert any(item.phase == "WAITING" for item in updates)

        class LongDeferredLifecycle:
            def __init__(self) -> None:
                self.results = iter(
                    (
                        LifecycleResult(outcome=LifecycleOutcome.RETRY),
                        LifecycleResult(outcome=LifecycleOutcome.IDLE),
                    )
                )

            async def run_once(self, *, on_claimed=None) -> LifecycleResult:
                del on_claimed
                return next(self.results)

        async def long_deferred_ready_at():
            return utc_now() + timedelta(seconds=5)

        monkeypatch.setattr(runtime, "lifecycle", LongDeferredLifecycle())
        monkeypatch.setattr(
            runtime.task_store,
            "next_ready_at",
            long_deferred_ready_at,
        )
        paused = await runtime.run_domain("example.com", max_steps=3)
        assert paused.status == "PAUSED"
        assert paused.paused_deferred is True
        assert paused.next_resume_at is not None

        class FailedLifecycle:
            def __init__(self) -> None:
                self.results = iter(
                    (
                        LifecycleResult(outcome=LifecycleOutcome.FAILED),
                        LifecycleResult(outcome=LifecycleOutcome.IDLE),
                    )
                )

            async def run_once(self, *, on_claimed=None) -> LifecycleResult:
                del on_claimed
                return next(self.results)

        monkeypatch.setattr(runtime, "lifecycle", FailedLifecycle())
        failed = await runtime.run_domain("example.com", max_steps=3)
        assert failed.status == "FAILED"
        assert failed.outcomes[LifecycleOutcome.FAILED.value] == 1
    finally:
        await runtime.close()
