from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from recon.core.budgets import (
    BudgetCaps,
    BudgetDecision,
    BudgetManager,
    BudgetOutcome,
    BudgetProfile,
    BudgetReservation,
    InMemoryBudgetStore,
)
from recon.core.lifecycle import (
    DispatchTicket,
    GateDecision,
    GateOutcome,
    Lifecycle,
    LifecycleOutcome,
    LifecycleResult,
    WorkerExecutionResult,
    WorkerOutcome,
)
from recon.core.queue import InMemoryTaskStore, Task, TaskQueue, TaskStatus, utc_now
from recon.core.scheduler import Scheduler


class _AllowGate:
    async def evaluate(self, task, schedule) -> GateDecision:
        return GateDecision(outcome=GateOutcome.ALLOW)


class _FailingHeartbeatBudgets:
    def __init__(self) -> None:
        self.committed = False

    async def reserve(self, task, **kwargs) -> BudgetDecision:
        now = utc_now()
        reservation = BudgetReservation(
            task_id=task.task_id,
            items=(),
            created_at=now,
            expires_at=now + timedelta(minutes=1),
        )
        return BudgetDecision(
            outcome=BudgetOutcome.ALLOW,
            task_id=task.task_id,
            reservation=reservation,
        )

    async def renew(self, reservation_id, **kwargs):
        raise RuntimeError("simulated heartbeat storage outage")

    async def commit(self, reservation_id):
        self.committed = True

    async def release(self, reservation_id):
        return None

    async def reap_expired(self):
        return []


class _CancellableExecutor:
    def __init__(self) -> None:
        self.cancelled = False

    async def execute(self, task):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _SelfCancellingExecutor:
    async def execute(self, task):
        del task
        raise asyncio.CancelledError


class _AllowBudgets(_FailingHeartbeatBudgets):
    async def renew(self, reservation_id, **kwargs):
        return None


class _ParallelExecutor:
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0

    async def execute(self, task):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.04)
            return WorkerExecutionResult(outcome=WorkerOutcome.SUCCEEDED)
        finally:
            self.active -= 1


class _RecordingAttemptObserver:
    def __init__(self) -> None:
        self.started: list[str] = []

    async def start(self, task, schedule):
        del schedule
        self.started.append(task.task_id)
        return f"attempt-{task.task_id}"

    async def finish(self, attempt_id, result):
        del attempt_id, result


@pytest.mark.asyncio
async def test_heartbeat_failure_cancels_worker_and_requeues_task() -> None:
    store = InMemoryTaskStore()
    queue = TaskQueue(store)
    task = Task(worker="probe", action="scan", input_event_id="evt_1")
    assert await queue.enqueue(task)

    budgets = _FailingHeartbeatBudgets()
    executor = _CancellableExecutor()
    lifecycle = Lifecycle(
        queue=queue,
        scheduler=Scheduler(queue),
        budgets=budgets,
        gates=(_AllowGate(),),
        executor=executor,
        task_lease_for=timedelta(milliseconds=100),
        heartbeat_interval=timedelta(milliseconds=10),
    )

    result = await asyncio.wait_for(lifecycle.run_once(), timeout=1)
    current = await queue.get(task.task_id)

    assert result.outcome is LifecycleOutcome.RETRY
    assert result.claimed is True
    assert result.execution_attempt == 1
    assert result.queue_status is TaskStatus.DEFERRED
    assert current is not None and current.status is TaskStatus.DEFERRED
    assert current.claim_token is None
    assert executor.cancelled is True
    assert budgets.committed is True
    assert "budget heartbeat failed" in (result.reason or "")


@pytest.mark.asyncio
async def test_operator_cancellation_immediately_requeues_claimed_task() -> None:
    queue = TaskQueue(InMemoryTaskStore())
    task = Task(worker="probe", action="scan", input_event_id="evt_cancel")
    assert await queue.enqueue(task)
    budgets = _AllowBudgets()
    executor = _CancellableExecutor()
    lifecycle = Lifecycle(
        queue=queue,
        scheduler=Scheduler(queue),
        budgets=budgets,
        gates=(_AllowGate(),),
        executor=executor,
    )

    execution = asyncio.create_task(lifecycle.run_once())
    for _ in range(100):
        current = await queue.get(task.task_id)
        if current is not None and current.status is TaskStatus.RUNNING:
            break
        await asyncio.sleep(0.001)
    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    current = await queue.get(task.task_id)
    assert current is not None and current.status is TaskStatus.DEFERRED
    assert current.claim_token is None
    assert current.last_error == "execution cancelled by operator"
    assert executor.cancelled is True
    assert budgets.committed is True


@pytest.mark.asyncio
async def test_worker_self_cancellation_is_contained_as_retry() -> None:
    queue = TaskQueue(InMemoryTaskStore())
    task = Task(worker="probe", action="scan", input_event_id="evt_self_cancel")
    assert await queue.enqueue(task)
    lifecycle = Lifecycle(
        queue=queue,
        scheduler=Scheduler(queue),
        budgets=_AllowBudgets(),
        gates=(_AllowGate(),),
        executor=_SelfCancellingExecutor(),
    )

    result = await lifecycle.run_once()

    current = await queue.get(task.task_id)
    assert result.outcome is LifecycleOutcome.RETRY
    assert result.reason == "worker execution cancelled unexpectedly"
    assert current is not None and current.status is TaskStatus.DEFERRED
    assert current.last_error == "worker execution cancelled unexpectedly"


@pytest.mark.asyncio
async def test_batch_admission_executes_tasks_in_parallel_with_worker_capacity() -> None:
    queue = TaskQueue(InMemoryTaskStore())
    await queue.enqueue_many(
        Task(worker="probe", action="scan", input_event_id=f"evt_{index}")
        for index in range(4)
    )
    executor = _ParallelExecutor()
    lifecycle = Lifecycle(
        queue=queue,
        scheduler=Scheduler(queue),
        budgets=_AllowBudgets(),
        gates=(_AllowGate(),),
        executor=executor,
    )

    admitted = await lifecycle.admit_batch(
        limit=4,
        worker_capacities={"probe": 3},
    )
    tickets = [item for item in admitted if not isinstance(item, LifecycleResult)]
    assert len(tickets) == 3
    results = await asyncio.gather(*(lifecycle.execute_claimed(item) for item in tickets))

    assert executor.max_active == 3
    assert all(result.outcome is LifecycleOutcome.SUCCEEDED for result in results)


@pytest.mark.asyncio
async def test_budget_capacity_backpressure_is_not_recorded_as_execution_attempt() -> None:
    queue = TaskQueue(InMemoryTaskStore())
    first_task = Task(worker="probe", action="one", input_event_id="evt_one")
    second_task = Task(worker="probe", action="two", input_event_id="evt_two")
    assert await queue.enqueue(first_task)
    assert await queue.enqueue(second_task)
    attempts = _RecordingAttemptObserver()
    lifecycle = Lifecycle(
        queue=queue,
        scheduler=Scheduler(queue),
        budgets=BudgetManager(
            InMemoryBudgetStore(),
            profile=BudgetProfile(
                soft_global_limits=BudgetCaps(concurrent_tasks=1),
                exploration_reserve_fraction=0.0,
            ),
        ),
        gates=(_AllowGate(),),
        executor=_ParallelExecutor(),
        attempt_observer=attempts,
    )

    first = await lifecycle.admit_next()
    second = await lifecycle.admit_next()

    assert isinstance(first, DispatchTicket)
    assert isinstance(second, LifecycleResult)
    assert second.outcome is LifecycleOutcome.DEFERRED
    assert second.backpressure is True
    assert second.claimed is False
    assert attempts.started == [first.task.task_id]
