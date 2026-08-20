from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from recon.core.budgets import (
    BudgetCheck,
    BudgetClass,
    BudgetMetric,
    BudgetReservation,
    BudgetReservationItem,
)
from recon.core.budgets import (
    utc_now as budget_now,
)
from recon.core.events import Event, EventType
from recon.core.queue import Task, TaskQueue, TaskStatus
from recon.core.router import Router, RouteRule, RoutingContext
from recon.policy.rate_limit import RateBucketCheck, RateLimitOutcome
from recon.policy.rate_limit import utc_now as rate_now
from recon.storage.database import (
    Database,
    EventRepository,
    SQLiteBudgetStore,
    SQLiteRateLimitStore,
    SQLiteTaskStore,
)
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


@pytest.mark.asyncio
async def test_semantic_task_dedupe_survives_repeated_observation_and_completion(tmp_path):
    path = tmp_path / "dedupe.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        events = EventRepository(database)
        store = SQLiteTaskStore(database)
        queue = TaskQueue(store)
        router = Router(
            [
                RouteRule(
                    rule_id="dns.resolve",
                    accepts=frozenset({EventType.DNS_NAME}),
                    worker="dns",
                    action="resolve",
                )
            ]
        )
        first = Event(type=EventType.DNS_NAME, value="api.example.com", source="one")
        repeated = Event(type=EventType.DNS_NAME, value="api.example.com", source="two")
        await events.ingest(first)
        await events.ingest(repeated)

        first_task = router.expand(first, context=RoutingContext())[0]
        repeated_task = router.expand(repeated, context=RoutingContext())[0]
        assert first_task.dedupe_key == repeated_task.dedupe_key
        assert await queue.enqueue(first_task) is True
        assert await queue.enqueue(repeated_task) is False

        claimed = await queue.claim(first_task.task_id)
        assert claimed.claim_token is not None
        await queue.succeed(
            first_task.task_id,
            claim_token=claimed.claim_token,
        )
        third = Event(type=EventType.DNS_NAME, value="api.example.com", source="three")
        await events.ingest(third)
        assert await queue.enqueue(router.expand(third, context=RoutingContext())[0]) is False
        assert len(await store.all()) == 1
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_sqlite_task_claim_is_atomic_across_queue_instances(tmp_path):
    path = tmp_path / "atomic-claim.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(type=EventType.ROOT_DOMAIN, value="example.com", source="test")
        await EventRepository(database).ingest(event)
        task = Task(
            worker="fixture",
            action="atomic-claim",
            input_event_id=event.event_id,
        )
        assert await SQLiteTaskStore(database).put(task) is True

        queues = (
            TaskQueue(SQLiteTaskStore(database)),
            TaskQueue(SQLiteTaskStore(database)),
        )

        async def attempt(queue: TaskQueue):
            try:
                return await queue.claim(task.task_id)
            except ValueError:
                return None

        claims = await asyncio.gather(*(attempt(queue) for queue in queues))

        successful = [claim for claim in claims if claim is not None]
        assert len(successful) == 1
        assert successful[0].status is TaskStatus.RUNNING
        persisted = await SQLiteTaskStore(database).get(task.task_id)
        assert persisted is not None
        assert persisted.attempts == 1
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_stale_worker_cannot_finalize_reclaimed_task(tmp_path):
    path = tmp_path / "claim-fencing.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(type=EventType.ROOT_DOMAIN, value="example.com", source="test")
        await EventRepository(database).ingest(event)
        task = Task(
            worker="fixture",
            action="claim-fencing",
            input_event_id=event.event_id,
            max_attempts=3,
        )
        store_a = SQLiteTaskStore(database)
        store_b = SQLiteTaskStore(database)
        queue_a = TaskQueue(store_a)
        queue_b = TaskQueue(store_b)
        assert await store_a.put(task) is True

        first = await queue_a.claim(task.task_id, lease_for=timedelta(milliseconds=1))
        assert first.claim_token is not None
        await asyncio.sleep(0.01)
        assert len(await queue_b.recover_expired_leases()) == 1
        second = await queue_b.claim(task.task_id)
        assert second.claim_token is not None
        assert second.claim_token != first.claim_token

        with pytest.raises(ValueError, match="claim token is stale"):
            await queue_a.succeed(task.task_id, claim_token=first.claim_token)

        persisted = await store_b.get(task.task_id)
        assert persisted is not None
        assert persisted.status is TaskStatus.RUNNING
        assert persisted.claim_token == second.claim_token
        await queue_b.succeed(task.task_id, claim_token=second.claim_token)
    finally:
        await database.dispose()
