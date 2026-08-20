from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from recon.core.budgets import BudgetDecision, BudgetOutcome, BudgetReservation
from recon.core.lifecycle import (
    GateDecision,
    GateOutcome,
    Lifecycle,
    LifecycleOutcome,
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
