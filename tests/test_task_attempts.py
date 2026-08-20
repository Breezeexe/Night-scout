from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from recon.core.budgets import BudgetManager, InMemoryBudgetStore
from recon.core.events import Event, EventType
from recon.core.lifecycle import (
    GateDecision,
    GateOutcome,
    Lifecycle,
    LifecycleOutcome,
)
from recon.core.queue import Task, TaskQueue, TaskStatus
from recon.core.scheduler import Scheduler
from recon.storage.database import (
    Database,
    EventRepository,
    RunRepository,
    SQLiteTaskStore,
    TaskAttemptRepository,
)
from recon.storage.models import TaskAttemptRecord, TaskRecord
from recon.storage.schema import upgrade_database


class _ReviewBeforeClaimGate:
    async def evaluate(self, task, schedule) -> GateDecision:
        return GateDecision(
            outcome=GateOutcome.REVIEW,
            reason="operator review",
            review_case_id="case_fixture",
        )


class _UnusedExecutor:
    async def execute(self, task):
        raise AssertionError("reviewed task must not reach executor")


class _RunAttemptObserver:
    def __init__(self, repository: TaskAttemptRepository, run_id: str) -> None:
        self._repository = repository
        self._run_id = run_id

    async def start(self, task, schedule) -> str:
        del schedule
        return await self._repository.start(run_id=self._run_id, task=task)

    async def finish(self, attempt_id, result) -> None:
        await self._repository.finish(
            attempt_id,
            outcome=result.outcome.value,
            queue_status=(result.queue_status.value if result.queue_status is not None else None),
            reason=result.reason,
            reservation_id=result.reservation_id,
            claimed=result.claimed,
            execution_attempt=result.execution_attempt,
        )


@pytest.mark.asyncio
async def test_resumed_preclaim_review_is_attributed_to_current_run(tmp_path) -> None:
    path = tmp_path / "attempts.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        runs = RunRepository(database)
        old_run_id = await runs.start()
        event = Event(
            type=EventType.ROOT_DOMAIN,
            value="example.com",
            source="fixture",
        )
        await EventRepository(database).ingest(event)
        store = SQLiteTaskStore(database, resume_frontier=True)
        store.set_run_id(old_run_id)
        task = Task(
            worker="probe",
            action="review",
            input_event_id=event.event_id,
        )
        assert await store.put(task)
        await runs.finish(old_run_id, status="PAUSED")

        current_run_id = await runs.start()
        store.set_run_id(current_run_id)
        attempts = TaskAttemptRepository(database)
        lifecycle = Lifecycle(
            queue=TaskQueue(store),
            scheduler=Scheduler(TaskQueue(store)),
            budgets=BudgetManager(InMemoryBudgetStore()),
            gates=(_ReviewBeforeClaimGate(),),
            executor=_UnusedExecutor(),
            attempt_observer=_RunAttemptObserver(attempts, current_run_id),
        )

        result = await lifecycle.run_once()

        assert result.outcome is LifecycleOutcome.REVIEW
        assert result.claimed is False
        assert result.execution_attempt is None
        assert await attempts.counts(run_id=current_run_id) == {"REVIEW": 1}

        async with database.session() as session:
            attempt = await session.scalar(select(TaskAttemptRecord))
            persisted_task = await session.get(TaskRecord, task.task_id)
        assert attempt is not None
        assert attempt.run_id == current_run_id
        assert attempt.task_id == task.task_id
        assert attempt.outcome == "REVIEW"
        assert attempt.queue_status == TaskStatus.REVIEW.value
        assert attempt.claimed is False
        assert attempt.finished_at is not None
        assert persisted_task is not None
        assert persisted_task.run_id == old_run_id
        assert persisted_task.execution_run_id is None

        from recon.runtime import NightScoutRuntime

        status = await NightScoutRuntime.status(
            SimpleNamespace(
                database=database,
                task_store=store,
                warnings=[],
            ),
            run_id=current_run_id,
        )
        assert status.task_counts == {TaskStatus.REVIEW.value: 1}
        assert status.attempt_counts == {LifecycleOutcome.REVIEW.value: 1}
    finally:
        await database.dispose()
