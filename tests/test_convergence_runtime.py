from __future__ import annotations

from datetime import timedelta

import pytest

from recon.core.budgets import BudgetLane
from recon.core.events import Event, EventType
from recon.core.lifecycle import GateOutcome
from recon.core.queue import Task, utc_now
from recon.intelligence.convergence import (
    BranchBudgetState,
    ConvergenceAction,
    ConvergenceController,
    ConvergenceState,
    InMemoryConvergenceStateStore,
    SearchTier,
)
from recon.intelligence.yield_model import (
    BranchYieldTrend,
    YieldAggregate,
    YieldEstimate,
    YieldQuery,
    target_key_for_event,
)
from recon.runtime import RuntimeConvergenceGate


class _Events:
    def __init__(self, *events: Event) -> None:
        self._events = {event.event_id: event for event in events}

    async def get_event(self, event_id: str) -> Event | None:
        return self._events.get(event_id)


class _ProductiveYieldModel:
    async def branch_trend(self, **_: object) -> BranchYieldTrend:
        return BranchYieldTrend(
            branch_id="branch",
            recent_executions=8,
            previous_executions=8,
            recent_hit_rate=0.5,
            previous_hit_rate=0.3,
            recent_assets_per_execution=0.5,
            previous_assets_per_execution=0.3,
            recent_novel_assets_per_execution=0.5,
            previous_novel_assets_per_execution=0.2,
            marginal_yield_delta=0.2,
            convergence_signal=0.0,
            low_marginal_yield=False,
            reason="productive fixture",
        )

    async def estimate(self, query: YieldQuery) -> YieldEstimate:
        return YieldEstimate(
            query=query,
            aggregate=YieldAggregate(),
            posterior_hit_rate=0.8,
            discovery_score=0.8,
            novelty_score=0.8,
            execution_reliability=1.0,
            expected_yield=0.9,
            uncertainty=0.5,
            estimated_cost=1.0,
            effective_sample_size=8.0,
        )


class _EmptyBudgetInspector:
    async def state_for(
        self,
        *,
        branch_id: str,
        lane: BudgetLane,
        branch_soft_multiplier: float,
    ) -> BranchBudgetState:
        return BranchBudgetState(
            branch_id=branch_id,
            lane=lane,
            exploration_reserve_fraction=0.1,
            branch_soft_multiplier=branch_soft_multiplier,
        )


@pytest.mark.asyncio
async def test_convergence_state_blocks_dispatch_and_maximum_tier_caps_growth():
    seed = Event(type=EventType.ROOT_DOMAIN, value="example.com", source="test")
    target_key = target_key_for_event(seed)
    store = InMemoryConvergenceStateStore()

    await store.put(
        ConvergenceState(
            target_key=target_key,
            branch_id=seed.event_id,
            lane=BudgetLane.NORMAL,
            tier=SearchTier.SMALL,
            productive_streak=1,
        )
    )
    controller = ConvergenceController(
        yield_model=_ProductiveYieldModel(),  # type: ignore[arg-type]
        budget_inspector=_EmptyBudgetInspector(),  # type: ignore[arg-type]
        state_store=store,
        maximum_tier=SearchTier.SMALL,
    )
    decision = await controller.evaluate(
        seed_event=seed,
        branch_id=seed.event_id,
        lane=BudgetLane.NORMAL,
        current_tier=SearchTier.SMALL,
    )
    assert decision.action is ConvergenceAction.CONTINUE
    assert decision.recommended_tier is SearchTier.SMALL

    task = Task(
        worker="dns",
        action="resolve",
        input_event_id=seed.event_id,
        branch_id=seed.event_id,
    )
    gate = RuntimeConvergenceGate(events=_Events(seed), state_store=store)  # type: ignore[arg-type]
    await store.put(
        decision.state_after.model_copy(
            update={"cooldown_until": utc_now() + timedelta(minutes=5)}
        )
    )
    gate_decision = await gate.evaluate(task, None)  # type: ignore[arg-type]
    assert gate_decision.outcome is GateOutcome.DEFER
    assert (gate_decision.retry_after_seconds or 0) > 0

    state = await store.get(
        target_key=target_key,
        branch_id=seed.event_id,
        lane=BudgetLane.NORMAL,
    )
    assert state is not None
    await store.put(state.model_copy(update={"closed": True}))
    gate_decision = await gate.evaluate(task, None)  # type: ignore[arg-type]
    assert gate_decision.outcome is GateOutcome.BLOCK
    assert "closed" in (gate_decision.reason or "")
