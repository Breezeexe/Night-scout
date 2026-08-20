from __future__ import annotations

import pytest

from recon.core.budgets import (
    BudgetCaps,
    BudgetManager,
    BudgetOutcome,
    BudgetProfile,
    InMemoryBudgetStore,
)
from recon.core.queue import Task


@pytest.mark.asyncio
async def test_committed_soft_budget_exhaustion_is_terminal() -> None:
    store = InMemoryBudgetStore()
    manager = BudgetManager(
        store,
        profile=BudgetProfile(
            soft_global_limits=BudgetCaps(tasks=1),
            exploration_reserve_fraction=0.0,
        ),
    )
    first_task = Task(worker="probe", action="one", input_event_id="evt_1")
    second_task = Task(worker="probe", action="two", input_event_id="evt_2")

    first = await manager.reserve(first_task)
    assert first.outcome is BudgetOutcome.ALLOW
    assert first.reservation is not None
    await manager.commit(first.reservation.reservation_id)

    exhausted = await manager.reserve(second_task)

    assert exhausted.outcome is BudgetOutcome.DENY
    assert exhausted.retry_after_seconds is None
    assert "soft exploration budget exhausted" in (exhausted.reason or "")


@pytest.mark.asyncio
async def test_soft_capacity_exhaustion_remains_temporary() -> None:
    store = InMemoryBudgetStore()
    manager = BudgetManager(
        store,
        profile=BudgetProfile(
            soft_global_limits=BudgetCaps(concurrent_tasks=1),
            exploration_reserve_fraction=0.0,
        ),
    )
    first = await manager.reserve(Task(worker="probe", action="one", input_event_id="evt_1"))
    assert first.reservation is not None

    capacity = await manager.reserve(Task(worker="probe", action="two", input_event_id="evt_2"))

    assert capacity.outcome is BudgetOutcome.DEFER
    assert capacity.retry_after_seconds is not None
