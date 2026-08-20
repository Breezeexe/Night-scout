from __future__ import annotations

from datetime import timedelta

import pytest

from recon.core.budgets import (
    BudgetCheck,
    BudgetClass,
    BudgetMetric,
    BudgetReservation,
    BudgetReservationItem,
    utc_now as budget_now,
)
from recon.policy.rate_limit import RateBucketCheck, RateLimitOutcome, utc_now as rate_now
from recon.core.events import Event, EventType
from recon.core.queue import Task
from recon.storage.database import Database, EventRepository, SQLiteBudgetStore, SQLiteRateLimitStore, SQLiteTaskStore
from recon.storage.schema import upgrade_database


@pytest.mark.asyncio
async def test_budget_parent_is_flushed_before_fk_items(tmp_path):
    path = tmp_path / "budget.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(type=EventType.ROOT_DOMAIN, value="example.com", source="test")
        await EventRepository(database).ingest(event)
        await SQLiteTaskStore(database).put(Task(worker="fixture", action="budget", input_event_id=event.event_id, task_id="task-budget"))
        store = SQLiteBudgetStore(database)
        created = budget_now()
        reservation = BudgetReservation(
            task_id="task-budget",
            items=(
                BudgetReservationItem(
                    bucket_key="global",
                    metric=BudgetMetric.REQUESTS,
                    budget_class=BudgetClass.SOFT,
                    amount=1.0,
                ),
            ),
            created_at=created,
            expires_at=created + timedelta(minutes=1),
        )
        allowed, violations = await store.try_reserve(
            reservation=reservation,
            checks=(
                BudgetCheck(
                    bucket_key="global",
                    metric=BudgetMetric.REQUESTS,
                    budget_class=BudgetClass.SOFT,
                    requested=1.0,
                    configured_limit=10.0,
                    effective_limit=10.0,
                ),
            ),
        )
        assert allowed is True
        assert violations == ()
        loaded = await store.get_reservation(reservation.reservation_id)
        assert loaded is not None and len(loaded.items) == 1
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_rate_lease_parent_is_flushed_before_fk_items(tmp_path):
    path = tmp_path / "rate.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(type=EventType.ROOT_DOMAIN, value="example.com", source="test")
        await EventRepository(database).ingest(event)
        await SQLiteTaskStore(database).put(Task(worker="fixture", action="rate", input_event_id=event.event_id, task_id="task-rate"))
        store = SQLiteRateLimitStore(database)
        decision = await store.try_acquire(
            task_id="task-rate",
            checks=(
                RateBucketCheck(
                    rule_id="host",
                    bucket_key="host:example.com",
                    requests=1.0,
                    concurrency=1,
                    requests_per_second=5.0,
                    burst=5.0,
                    max_concurrency=2,
                ),
            ),
            lease_for=timedelta(minutes=1),
            now=rate_now(),
        )
        assert decision.outcome is RateLimitOutcome.ALLOW
        assert decision.lease is not None
        loaded = await store.get_lease(decision.lease.lease_id)
        assert loaded is not None and len(loaded.items) == 1
    finally:
        await database.dispose()
