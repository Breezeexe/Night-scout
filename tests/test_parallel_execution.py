from __future__ import annotations

import asyncio

import pytest

from recon.core.queue import Task
from recon.policy.rate_limit import (
    InMemoryRateLimitStore,
    RateLimitContext,
    RateLimitDemand,
    RateLimiter,
    RateLimitOutcome,
    RateLimitProfile,
    RateLimitRule,
)


@pytest.mark.asyncio
async def test_await_acquire_wakes_on_release_and_cleans_wait_metrics() -> None:
    limiter = RateLimiter(
        InMemoryRateLimitStore(),
        profile=RateLimitProfile(
            default_retry_after_seconds=10,
            rules=(
                RateLimitRule(
                    rule_id="host-exclusive",
                    resource_pattern="host:example.com",
                    max_concurrency=1,
                ),
            ),
        ),
    )
    context = RateLimitContext(resource_keys=frozenset({"host:example.com"}))
    demand = RateLimitDemand(requests=0, concurrency=1)
    first = await limiter.acquire(
        Task(worker="crawler", action="crawl", input_event_id="evt_1"),
        context=context,
        demand=demand,
    )
    assert first.lease is not None

    waiter = asyncio.create_task(
        limiter.await_acquire(
            Task(worker="http", action="probe", input_event_id="evt_2"),
            context=context,
            demand=demand,
        )
    )
    for _ in range(100):
        if limiter.waiting_by_worker:
            break
        await asyncio.sleep(0.001)
    assert limiter.waiting_by_worker == {"http": 1}

    await limiter.release(first.lease.lease_id)
    second = await asyncio.wait_for(waiter, timeout=0.2)
    assert second.outcome is RateLimitOutcome.ALLOW
    assert second.lease is not None
    assert limiter.waiting_by_worker == {}
    await limiter.release(second.lease.lease_id)


@pytest.mark.asyncio
async def test_await_acquire_is_cancelable_without_waiter_leak() -> None:
    limiter = RateLimiter(
        InMemoryRateLimitStore(),
        profile=RateLimitProfile(
            rules=(
                RateLimitRule(
                    rule_id="one-at-a-time",
                    max_concurrency=1,
                ),
            ),
        ),
    )
    context = RateLimitContext(resource_keys=frozenset({"host:example.com"}))
    demand = RateLimitDemand(requests=0, concurrency=1)
    owner = await limiter.acquire(
        Task(worker="dns", action="resolve", input_event_id="evt_owner"),
        context=context,
        demand=demand,
    )
    assert owner.lease is not None
    waiter = asyncio.create_task(
        limiter.await_acquire(
            Task(worker="dns", action="resolve", input_event_id="evt_wait"),
            context=context,
            demand=demand,
        )
    )
    for _ in range(100):
        if limiter.waiting_by_worker:
            break
        await asyncio.sleep(0.001)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert limiter.waiting_by_worker == {}
    await limiter.release(owner.lease.lease_id)
