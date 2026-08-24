"""Task ranking for Night Scout.

The scheduler ranks candidate tasks but does not authorize or execute them.

Its responsibility is deliberately narrow:

    "Among tasks that are currently ready, which one appears most valuable
    to evaluate next?"

The future lifecycle layer will take a ScheduleDecision and then perform the
mandatory execution gates:

    scope -> policy -> budget -> review -> queue.claim() -> worker

Keeping those concerns separate prevents the scheduler from accidentally
becoming an authorization bypass.

Dynamic signals such as confidence, novelty, expected yield, information gain,
and worker cost are supplied through a SchedulingSignalProvider. This keeps the
scheduler independent from the future storage and intelligence modules.
"""

from __future__ import annotations

import asyncio
import math
from collections import Counter, defaultdict, deque
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.queue import Task, TaskQueue


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


class SchedulingSignals(BaseModel):
    """Dynamic intelligence inputs used to rank one task.

    The future intelligence/storage layer can calculate these values from the
    input Event, Target Genome, worker statistics, historical yield, and other
    persisted observations.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    novelty: float = Field(default=0.5, ge=0.0, le=1.0)
    expected_yield: float = Field(default=0.5, ge=0.0, le=1.0)
    information_gain: float = Field(default=0.5, ge=0.0, le=1.0)

    estimated_cost: float = Field(default=1.0, gt=0.0)


class SchedulingSignalProvider(Protocol):
    """Contract for obtaining dynamic scheduling intelligence."""

    async def signals_for(self, task: Task) -> SchedulingSignals:
        """Return scheduling signals for a task."""
        ...


class DefaultSchedulingSignalProvider:
    """Neutral signal provider used before intelligence modules exist."""

    async def signals_for(self, task: Task) -> SchedulingSignals:
        """Return neutral defaults without external dependencies."""
        return SchedulingSignals()


class SchedulerConfig(BaseModel):
    """Weights and operational limits for scheduler ranking."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    route_priority_weight: float = 1.0

    confidence_weight: float = 3.0
    novelty_weight: float = 4.0
    expected_yield_weight: float = 3.0
    information_gain_weight: float = 3.0

    cost_weight: float = 2.0
    retry_penalty_weight: float = 1.0

    age_boost_per_minute: float = Field(default=0.01, ge=0.0)
    max_age_boost: float = Field(default=3.0, ge=0.0)

    candidate_limit: int = Field(default=256, ge=1, le=10_000)
    signal_concurrency: int = Field(default=32, ge=1)

    @field_validator("candidate_limit", mode="before")
    @classmethod
    def bounded_default_candidate_limit(cls, value: object) -> object:
        # Older generated pipeline files used YAML null to mean unbounded.
        # Treat it as the safe bounded default instead of retaining O(n)
        # scoring on every scheduler iteration.
        return 256 if value is None else value


class ScoreBreakdown(BaseModel):
    """Explainable components of one scheduling score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    route_priority: float

    confidence: float
    novelty: float
    expected_yield: float
    information_gain: float

    age_boost: float

    cost_penalty: float
    retry_penalty: float

    total: float


class ScheduleDecision(BaseModel):
    """Serializable ranking decision for one task.

    The storage layer may later persist these decisions so `nightscout explain`
    can show why a task was prioritized at a specific point in time.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    worker: str
    action: str
    input_event_id: str
    branch_id: str | None = None

    score: float
    breakdown: ScoreBreakdown
    signals: SchedulingSignals

    evaluated_at: datetime

    route_rule_id: str | None = None
    routing_reason: str | None = None


class Scheduler:
    """Rank ready tasks using static route priority and dynamic intelligence."""

    def __init__(
        self,
        queue: TaskQueue,
        *,
        signal_provider: SchedulingSignalProvider | None = None,
        config: SchedulerConfig | None = None,
    ) -> None:
        self._queue = queue
        self._signal_provider = signal_provider or DefaultSchedulingSignalProvider()
        self._config = config or SchedulerConfig()

    async def rank_ready(self) -> list[ScheduleDecision]:
        """Return all currently considered tasks ordered by scheduler value.

        No task lifecycle state is modified by this method.
        """
        tasks = await self._queue.ready(
            limit=self._config.candidate_limit,
            fair=True,
        )

        if not tasks:
            return []

        evaluated_at = utc_now()
        decisions = await self._score_tasks(tasks, evaluated_at=evaluated_at)

        decisions.sort(
            key=lambda decision: self._decision_sort_key(
                decision,
                task_by_id={task.task_id: task for task in tasks},
            )
        )

        return decisions

    async def select_next(
        self,
        *,
        excluded_workers: frozenset[str] | None = None,
    ) -> ScheduleDecision | None:
        """Return the highest-ranked ready task without claiming it."""
        ranked = await self.rank_ready()
        excluded = excluded_workers or frozenset()
        return next(
            (decision for decision in ranked if decision.worker not in excluded),
            None,
        )

    async def select_batch(
        self,
        *,
        limit: int,
        excluded_workers: frozenset[str] | None = None,
        worker_capacities: Mapping[str, int] | None = None,
    ) -> list[ScheduleDecision]:
        """Return a ranked dispatch batch after scoring the frontier once.

        ``worker_capacities`` contains the number of currently free execution
        slots for workers with an explicit per-worker limit. Workers omitted
        from the mapping may consume any remaining global slot.
        """
        if limit < 1:
            return []

        ranked = await self.rank_ready()
        return self._select_ranked_batch(
            ranked,
            limit=limit,
            excluded_workers=excluded_workers,
            worker_capacities=worker_capacities,
        )

    @staticmethod
    def _select_ranked_batch(
        ranked: list[ScheduleDecision],
        *,
        limit: int,
        excluded_workers: frozenset[str] | None,
        worker_capacities: Mapping[str, int] | None,
    ) -> list[ScheduleDecision]:
        """Take ranked work in fair worker rounds without losing local order."""
        excluded = excluded_workers or frozenset()
        capacities = worker_capacities or {}
        worker_order: list[str] = []
        queues: dict[str, deque[ScheduleDecision]] = defaultdict(deque)
        for decision in ranked:
            if decision.worker in excluded:
                continue
            if decision.worker not in queues:
                worker_order.append(decision.worker)
            queues[decision.worker].append(decision)

        selected: list[ScheduleDecision] = []
        selected_by_worker: Counter[str] = Counter()
        while len(selected) < limit:
            progressed = False
            for worker in worker_order:
                capacity = capacities.get(worker)
                if capacity is not None and selected_by_worker[worker] >= capacity:
                    continue
                if not queues[worker]:
                    continue
                selected.append(queues[worker].popleft())
                selected_by_worker[worker] += 1
                progressed = True
                if len(selected) >= limit:
                    break
            if not progressed:
                break
        return selected

    async def explain_task(self, task: Task) -> ScheduleDecision:
        """Score one task without requiring it to be present in the queue.

        This is useful for tests, diagnostics, and the future explain command.
        """
        evaluated_at = utc_now()
        signals = await self._signal_provider.signals_for(task)
        return self._build_decision(
            task,
            signals=signals,
            evaluated_at=evaluated_at,
        )

    async def _score_tasks(
        self,
        tasks: list[Task],
        *,
        evaluated_at: datetime,
    ) -> list[ScheduleDecision]:
        semaphore = asyncio.Semaphore(self._config.signal_concurrency)

        async def score_one(task: Task) -> ScheduleDecision:
            async with semaphore:
                signals = await self._signal_provider.signals_for(task)

            return self._build_decision(
                task,
                signals=signals,
                evaluated_at=evaluated_at,
            )

        return list(await asyncio.gather(*(score_one(task) for task in tasks)))

    def _build_decision(
        self,
        task: Task,
        *,
        signals: SchedulingSignals,
        evaluated_at: datetime,
    ) -> ScheduleDecision:
        age_minutes = max(
            (evaluated_at - task.created_at).total_seconds() / 60.0,
            0.0,
        )

        age_boost = min(
            age_minutes * self._config.age_boost_per_minute,
            self._config.max_age_boost,
        )

        route_priority_component = (
            task.priority * self._config.route_priority_weight
        )
        confidence_component = (
            signals.confidence * self._config.confidence_weight
        )
        novelty_component = (
            signals.novelty * self._config.novelty_weight
        )
        yield_component = (
            signals.expected_yield * self._config.expected_yield_weight
        )
        information_gain_component = (
            signals.information_gain * self._config.information_gain_weight
        )

        # log1p keeps high-cost workers meaningfully penalized without letting
        # one very large cost value dominate all other intelligence signals.
        cost_penalty = (
            math.log1p(signals.estimated_cost) * self._config.cost_weight
        )

        retry_penalty = (
            task.attempts * self._config.retry_penalty_weight
        )

        total = (
            route_priority_component
            + confidence_component
            + novelty_component
            + yield_component
            + information_gain_component
            + age_boost
            - cost_penalty
            - retry_penalty
        )

        breakdown = ScoreBreakdown(
            route_priority=route_priority_component,
            confidence=confidence_component,
            novelty=novelty_component,
            expected_yield=yield_component,
            information_gain=information_gain_component,
            age_boost=age_boost,
            cost_penalty=cost_penalty,
            retry_penalty=retry_penalty,
            total=total,
        )

        return ScheduleDecision(
            task_id=task.task_id,
            worker=task.worker,
            action=task.action,
            input_event_id=task.input_event_id,
            branch_id=task.branch_id,
            score=total,
            breakdown=breakdown,
            signals=signals,
            evaluated_at=evaluated_at,
            route_rule_id=task.route_rule_id,
            routing_reason=task.routing_reason,
        )

    @staticmethod
    def _decision_sort_key(
        decision: ScheduleDecision,
        *,
        task_by_id: dict[str, Task],
    ) -> tuple[float, float, datetime, datetime, str]:
        """Return deterministic ordering for equally scored decisions."""
        task = task_by_id[decision.task_id]

        return (
            -decision.score,
            -task.priority,
            task.available_at,
            task.created_at,
            task.task_id,
        )
