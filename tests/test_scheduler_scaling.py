from __future__ import annotations

from datetime import timedelta

import pytest

from recon.core.events import Event, EventType
from recon.core.queue import InMemoryTaskStore, Task, TaskQueue, utc_now
from recon.core.scheduler import SchedulerConfig, SchedulingSignals
from recon.runtime import RecordingScheduler
from recon.storage.database import Database, EventRepository, SQLiteTaskStore
from recon.storage.schema import upgrade_database


class _Signals:
    def __init__(self) -> None:
        self.calls = 0

    async def signals_for(self, task: Task) -> SchedulingSignals:
        self.calls += 1
        return SchedulingSignals()


class _ValuableSignals:
    async def signals_for(self, task: Task) -> SchedulingSignals:
        if task.task_id == "valuable":
            return SchedulingSignals(
                confidence=1.0,
                novelty=1.0,
                expected_yield=1.0,
                information_gain=1.0,
                estimated_cost=0.1,
            )
        return SchedulingSignals(
            confidence=0.0,
            novelty=0.0,
            expected_yield=0.0,
            information_gain=0.0,
            estimated_cost=10.0,
        )


class _DecisionSink:
    def __init__(self) -> None:
        self.batches: list[tuple[object, ...]] = []
        self.selected: str | None = None

    async def record_schedules(
        self,
        decisions: list[object],
        *,
        selected_task_id: str,
    ) -> tuple[str, ...]:
        self.batches.append(tuple(decisions))
        self.selected = selected_task_id
        return ()


@pytest.mark.asyncio
async def test_scheduler_scores_bounded_shortlist_and_records_one_batch():
    queue = TaskQueue(InMemoryTaskStore())
    await queue.enqueue_many(
        Task(worker="fixture", action="scan", input_event_id=f"evt_{index}")
        for index in range(300)
    )
    signals = _Signals()
    sink = _DecisionSink()
    scheduler = RecordingScheduler(
        queue,
        signal_provider=signals,
        config=SchedulerConfig(candidate_limit=None),
        decisions=sink,  # type: ignore[arg-type]
    )

    selected = await scheduler.select_next()

    assert selected is not None
    assert signals.calls == 256
    assert len(sink.batches) == 1
    assert len(sink.batches[0]) == 256
    assert sink.selected == selected.task_id


@pytest.mark.asyncio
async def test_scheduler_shortlist_includes_old_low_priority_work():
    queue = TaskQueue(InMemoryTaskStore())
    valuable = Task(
        task_id="valuable",
        worker="fixture",
        action="scan",
        input_event_id="evt_valuable",
        priority=0.0,
        created_at=utc_now() - timedelta(days=1),
    )
    assert await queue.enqueue(valuable)
    await queue.enqueue_many(
        Task(
            task_id=f"high-{index:03d}",
            worker="fixture",
            action="scan",
            input_event_id=f"evt_{index}",
            priority=1.0,
        )
        for index in range(300)
    )
    sink = _DecisionSink()
    scheduler = RecordingScheduler(
        queue,
        signal_provider=_ValuableSignals(),
        config=SchedulerConfig(candidate_limit=256),
        decisions=sink,  # type: ignore[arg-type]
    )

    selected = await scheduler.select_next()

    assert selected is not None
    assert selected.task_id == "valuable"
    assert len(sink.batches[0]) == 256


@pytest.mark.asyncio
async def test_sqlite_scheduler_shortlist_includes_old_low_priority_work(tmp_path):
    path = tmp_path / "fair-shortlist.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(
            type=EventType.ROOT_DOMAIN,
            value="example.com",
            source="test",
        )
        await EventRepository(database).ingest(event)
        queue = TaskQueue(SQLiteTaskStore(database))
        assert await queue.enqueue(
            Task(
                task_id="valuable",
                worker="fixture",
                action="valuable",
                input_event_id=event.event_id,
                priority=0.0,
                created_at=utc_now() - timedelta(days=1),
            )
        )
        await queue.enqueue_many(
            Task(
                task_id=f"high-{index:03d}",
                worker="fixture",
                action=f"scan-{index}",
                input_event_id=event.event_id,
                priority=1.0,
            )
            for index in range(300)
        )
        sink = _DecisionSink()
        scheduler = RecordingScheduler(
            queue,
            signal_provider=_ValuableSignals(),
            config=SchedulerConfig(candidate_limit=256),
            decisions=sink,  # type: ignore[arg-type]
        )

        selected = await scheduler.select_next()

        assert selected is not None
        assert selected.task_id == "valuable"
        assert len(sink.batches[0]) == 256
    finally:
        await database.dispose()
