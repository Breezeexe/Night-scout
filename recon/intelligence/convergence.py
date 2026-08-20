"""Controlled convergence policy for Night Scout reconnaissance branches.

`yield_model.py` answers:
    "Is this branch still producing useful discoveries?"

`budgets.py` answers:
    "Is more exploration allowed?"

This module combines those signals into an explainable *recommendation* for the
orchestrator:

    CONTINUE
    ADVANCE_TIER
    COOLDOWN
    CLOSE

It does not execute workers, mutate the task queue, reserve budget, or override
scope/policy gates.

Protected exploration
---------------------
Night Scout's BudgetManager already protects an exploration reserve:

    BudgetLane.NORMAL
        sees soft_limit * (1 - exploration_reserve_fraction)

    BudgetLane.EXPLORATION
        sees the full soft limit

Convergence preserves that contract. A low-yield EXPLORATION branch may enter
COOLDOWN, but it is not permanently CLOSED merely because its recent yield is
low. This prevents target learning from starving long-tail discovery.

A branch is automatically CLOSED only when:
- a hard branch budget is fully exhausted; or
- a NORMAL branch has reached EXHAUSTIVE tier and repeatedly demonstrates
  low marginal yield with low information gain.

Even then, this module only returns the decision. The orchestrator owns the
actual branch state transition.

Tier progression
----------------
Productive branches can advance through:

    MICRO -> SMALL -> MEDIUM -> LARGE -> EXHAUSTIVE

The controller advances at most one tier per evaluation. It never jumps from
MICRO directly to EXHAUSTIVE.

Sparse histories do not look like zero yield. High uncertainty means high
information value, so a branch with too little evidence normally CONTINUEs.

Budget integration
------------------
`BranchBudgetInspector` reads the existing `BudgetStore` and `BudgetProfile`.
It reproduces the *same effective branch soft-limit semantics* as
BudgetManager, including exploration reserve and a productive
`branch_soft_multiplier`.

The controller may recommend a branch soft multiplier >= 1 for productive
branches. This is compatible with `BudgetContext.branch_soft_multiplier`;
convergence never uses a multiplier below 1 to "punish" a branch.

`budget_context_for_decision(...)` converts a decision into the BudgetContext
that the orchestrator can pass to its existing BudgetManager.

Persistence boundary
--------------------
Convergence state (tier, streaks, cooldown count, close flag) is behind the
small `ConvergenceStateStore` protocol. An in-memory implementation is included
for bootstrap/tests. A future SQLite adapter can persist this state without
changing the controller.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.budgets import (
    BudgetClass,
    BudgetContext,
    BudgetLane,
    BudgetMetric,
    BudgetProfile,
    BudgetStore,
)
from recon.core.events import Event
from recon.intelligence.yield_model import (
    BranchYieldTrend,
    YieldEstimate,
    YieldModel,
    YieldQuery,
    target_key_for_event,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ConvergenceAction(StrEnum):
    """Recommendation returned to the branch/orchestration layer."""

    CONTINUE = "CONTINUE"
    ADVANCE_TIER = "ADVANCE_TIER"
    COOLDOWN = "COOLDOWN"
    CLOSE = "CLOSE"


class SearchTier(StrEnum):
    """Generic search-intensity tier shared conceptually by intelligence lanes."""

    MICRO = "MICRO"
    SMALL = "SMALL"
    MEDIUM = "MEDIUM"
    LARGE = "LARGE"
    EXHAUSTIVE = "EXHAUSTIVE"

    @property
    def next_tier(self) -> "SearchTier":
        order = (
            SearchTier.MICRO,
            SearchTier.SMALL,
            SearchTier.MEDIUM,
            SearchTier.LARGE,
            SearchTier.EXHAUSTIVE,
        )

        index = order.index(self)

        if index >= len(order) - 1:
            return self

        return order[index + 1]

    @property
    def is_exhaustive(self) -> bool:
        return self is SearchTier.EXHAUSTIVE

    @property
    def rank(self) -> int:
        return (
            SearchTier.MICRO,
            SearchTier.SMALL,
            SearchTier.MEDIUM,
            SearchTier.LARGE,
            SearchTier.EXHAUSTIVE,
        ).index(self)


class BudgetMetricPressure(BaseModel):
    """One observed branch budget bucket/metric pressure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric: BudgetMetric
    budget_class: BudgetClass

    configured_limit: float = Field(ge=0.0)
    effective_limit: float = Field(ge=0.0)

    committed: float = Field(ge=0.0)
    reserved: float = Field(ge=0.0)

    utilization: float = Field(ge=0.0)

    @property
    def total_used(self) -> float:
        return self.committed + self.reserved

    @property
    def exhausted(self) -> bool:
        return self.utilization >= 1.0 - 1e-9


class BranchBudgetState(BaseModel):
    """Read-only snapshot of branch-level soft/hard budget pressure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    branch_id: str
    lane: BudgetLane

    exploration_reserve_fraction: float = Field(
        ge=0.0,
        lt=1.0,
    )

    branch_soft_multiplier: float = Field(
        default=1.0,
        ge=1.0,
    )

    soft: tuple[BudgetMetricPressure, ...] = ()
    hard: tuple[BudgetMetricPressure, ...] = ()

    @field_validator("branch_id")
    @classmethod
    def branch_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("branch_id must not be blank")

        return normalized

    @property
    def soft_pressure(self) -> float:
        if not self.soft:
            return 0.0

        return max(
            item.utilization
            for item in self.soft
        )

    @property
    def hard_pressure(self) -> float:
        if not self.hard:
            return 0.0

        return max(
            item.utilization
            for item in self.hard
        )

    @property
    def soft_exhausted(self) -> bool:
        return any(
            item.exhausted
            for item in self.soft
        )

    @property
    def hard_exhausted(self) -> bool:
        return any(
            item.exhausted
            for item in self.hard
        )

    @property
    def limiting_soft_metric(self) -> BudgetMetric | None:
        if not self.soft:
            return None

        return max(
            self.soft,
            key=lambda item: (
                item.utilization,
                item.metric.value,
            ),
        ).metric

    @property
    def limiting_hard_metric(self) -> BudgetMetric | None:
        if not self.hard:
            return None

        return max(
            self.hard,
            key=lambda item: (
                item.utilization,
                item.metric.value,
            ),
        ).metric


class BranchBudgetInspector:
    """Read branch budget usage using BudgetManager-compatible semantics."""

    def __init__(
        self,
        store: BudgetStore,
        *,
        profile: BudgetProfile,
    ) -> None:
        self._store = store
        self._profile = profile

    @property
    def profile(self) -> BudgetProfile:
        return self._profile

    async def state_for(
        self,
        *,
        branch_id: str,
        lane: BudgetLane,
        branch_soft_multiplier: float = 1.0,
    ) -> BranchBudgetState:
        if branch_soft_multiplier < 1.0:
            raise ValueError(
                "branch_soft_multiplier must be >= 1"
            )

        bucket_key = (
            "branch:"
            + branch_id.strip()
        )

        if bucket_key == "branch:":
            raise ValueError(
                "branch_id must not be blank"
            )

        soft = await self._pressures_for_caps(
            bucket_key=bucket_key,
            budget_class=BudgetClass.SOFT,
            lane=lane,
            multiplier=branch_soft_multiplier,
        )

        hard = await self._pressures_for_caps(
            bucket_key=bucket_key,
            budget_class=BudgetClass.HARD,
            lane=lane,
            multiplier=1.0,
        )

        return BranchBudgetState(
            branch_id=branch_id,
            lane=lane,
            exploration_reserve_fraction=(
                self._profile.exploration_reserve_fraction
            ),
            branch_soft_multiplier=(
                branch_soft_multiplier
            ),
            soft=soft,
            hard=hard,
        )

    async def _pressures_for_caps(
        self,
        *,
        bucket_key: str,
        budget_class: BudgetClass,
        lane: BudgetLane,
        multiplier: float,
    ) -> tuple[
        BudgetMetricPressure,
        ...
    ]:
        caps = (
            self._profile.soft_branch_limits
            if budget_class is BudgetClass.SOFT
            else self._profile.hard_branch_limits
        )

        configured = (
            caps.as_metric_limits()
        )

        if not configured:
            return ()

        result: list[
            BudgetMetricPressure
        ] = []

        for metric, limit in sorted(
            configured.items(),
            key=lambda item: (
                item[0].value
            ),
        ):
            usage = await self._store.usage(
                bucket_key=bucket_key,
                metric=metric,
                budget_class=budget_class,
            )

            configured_limit = (
                limit
                * multiplier
            )

            effective_limit = (
                configured_limit
            )

            if (
                budget_class
                is BudgetClass.SOFT
                and lane
                is BudgetLane.NORMAL
            ):
                effective_limit *= (
                    1.0
                    - self._profile.exploration_reserve_fraction
                )

            total = usage.total

            if effective_limit <= 0.0:
                # A zero limit leaves no room for a future positive demand.
                utilization = 1.0
            else:
                utilization = (
                    total
                    / effective_limit
                )

            result.append(
                BudgetMetricPressure(
                    metric=metric,
                    budget_class=budget_class,
                    configured_limit=(
                        configured_limit
                    ),
                    effective_limit=(
                        effective_limit
                    ),
                    committed=usage.committed,
                    reserved=usage.reserved,
                    utilization=max(
                        0.0,
                        utilization,
                    ),
                )
            )

        return tuple(result)


class ConvergenceState(BaseModel):
    """Persistent controller state for one branch/lane."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str | None = None
    branch_id: str
    lane: BudgetLane

    tier: SearchTier

    branch_soft_multiplier: float = Field(default=1.0, ge=1.0)

    evaluations: int = Field(default=0, ge=0)

    low_yield_streak: int = Field(default=0, ge=0)
    productive_streak: int = Field(default=0, ge=0)

    cooldown_count: int = Field(default=0, ge=0)
    cooldown_until: datetime | None = None

    closed: bool = False

    last_action: ConvergenceAction | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("target_key")
    @classmethod
    def normalize_optional_target(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip().lower()
        return normalized or None

    @field_validator("branch_id")
    @classmethod
    def branch_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "branch_id must not be blank"
            )

        return normalized

    @field_validator(
        "cooldown_until",
        "updated_at",
    )
    @classmethod
    def aware_timestamp(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if (
            value is not None
            and (
                value.tzinfo is None
                or value.utcoffset() is None
            )
        ):
            raise ValueError(
                "convergence timestamps must be timezone-aware"
            )

        return value


class ConvergenceStateStore(Protocol):
    """Persistence boundary for branch convergence state."""

    async def get(
        self,
        *,
        target_key: str | None,
        branch_id: str,
        lane: BudgetLane,
    ) -> ConvergenceState | None:
        ...

    async def put(
        self,
        state: ConvergenceState,
    ) -> None:
        ...


class InMemoryConvergenceStateStore:
    """Concurrency-safe bootstrap convergence store."""

    def __init__(self) -> None:
        self._states: dict[
            tuple[
                str | None,
                str,
                BudgetLane,
            ],
            ConvergenceState,
        ] = {}

        self._lock = asyncio.Lock()

    async def get(
        self,
        *,
        target_key: str | None,
        branch_id: str,
        lane: BudgetLane,
    ) -> ConvergenceState | None:
        key = (
            (
                target_key.lower()
                if target_key
                is not None
                else None
            ),
            branch_id,
            lane,
        )

        async with self._lock:
            state = self._states.get(
                key
            )

            return (
                state.model_copy(
                    deep=True
                )
                if state
                is not None
                else None
            )

    async def put(
        self,
        state: ConvergenceState,
    ) -> None:
        key = (
            state.target_key,
            state.branch_id,
            state.lane,
        )

        async with self._lock:
            self._states[
                key
            ] = state.model_copy(
                deep=True
            )


class ConvergenceConfig(BaseModel):
    """Decision thresholds and cooldown/tier behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum_recent_executions: int = Field(
        default=8,
        ge=1,
        le=10_000,
    )

    productive_hit_rate: float = Field(
        default=0.12,
        ge=0.0,
        le=1.0,
    )

    productive_novel_assets_per_execution: float = Field(
        default=0.10,
        ge=0.0,
    )

    advance_expected_yield: float = Field(
        default=0.58,
        ge=0.0,
        le=1.0,
    )

    advance_productive_streak: int = Field(
        default=2,
        ge=1,
        le=100,
    )

    advance_max_soft_pressure: float = Field(
        default=0.80,
        ge=0.0,
    )

    low_yield_convergence_signal: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
    )

    low_information_gain: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
    )

    cooldown_low_yield_streak: int = Field(
        default=2,
        ge=1,
        le=100,
    )

    close_low_yield_streak: int = Field(
        default=4,
        ge=1,
        le=100,
    )

    cooldown_base_seconds: float = Field(
        default=15 * 60,
        gt=0.0,
    )

    cooldown_max_seconds: float = Field(
        default=24 * 60 * 60,
        gt=0.0,
    )

    productive_soft_multiplier_max: float = Field(
        default=2.0,
        ge=1.0,
        le=100.0,
    )

    productive_soft_multiplier_threshold: float = Field(
        default=0.62,
        ge=0.0,
        le=1.0,
    )

    hard_pressure_close_threshold: float = Field(
        default=1.0,
        gt=0.0,
    )

    soft_pressure_cooldown_threshold: float = Field(
        default=1.0,
        gt=0.0,
    )

    @model_validator(mode="after")
    def valid_thresholds(
        self,
    ) -> "ConvergenceConfig":
        if (
            self.close_low_yield_streak
            < self.cooldown_low_yield_streak
        ):
            raise ValueError(
                "close_low_yield_streak cannot be below cooldown streak"
            )

        if (
            self.cooldown_max_seconds
            < self.cooldown_base_seconds
        ):
            raise ValueError(
                "cooldown_max_seconds cannot be below cooldown_base_seconds"
            )

        return self


class ConvergenceDecision(BaseModel):
    """Explainable controller recommendation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str | None = None
    branch_id: str
    lane: BudgetLane

    protected_exploration: bool

    action: ConvergenceAction

    current_tier: SearchTier
    recommended_tier: SearchTier

    recommended_branch_soft_multiplier: float = Field(
        default=1.0,
        ge=1.0,
    )

    cooldown_until: datetime | None = None

    expected_yield: float = Field(
        ge=0.0,
        le=1.0,
    )

    information_gain: float = Field(
        ge=0.0,
        le=1.0,
    )

    convergence_signal: float = Field(
        ge=0.0,
        le=1.0,
    )

    trend: BranchYieldTrend
    yield_estimate: YieldEstimate

    budget: BranchBudgetState

    reasons: tuple[str, ...]

    state_before: ConvergenceState
    state_after: ConvergenceState

    evaluated_at: datetime

    @field_validator(
        "cooldown_until",
        "evaluated_at",
    )
    @classmethod
    def aware_timestamp(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if (
            value is not None
            and (
                value.tzinfo is None
                or value.utcoffset() is None
            )
        ):
            raise ValueError(
                "decision timestamps must be timezone-aware"
            )

        return value

    @property
    def should_dispatch(self) -> bool:
        return self.action in {
            ConvergenceAction.CONTINUE,
            ConvergenceAction.ADVANCE_TIER,
        }

    @property
    def should_pause(self) -> bool:
        return self.action is ConvergenceAction.COOLDOWN

    @property
    def should_close(self) -> bool:
        return self.action is ConvergenceAction.CLOSE


class ConvergenceController:
    """Combine yield trend, uncertainty, and budget pressure."""

    def __init__(
        self,
        *,
        yield_model: YieldModel,
        budget_inspector: BranchBudgetInspector,
        state_store: ConvergenceStateStore,
        config: ConvergenceConfig | None = None,
        maximum_tier: SearchTier | str = SearchTier.EXHAUSTIVE,
    ) -> None:
        self._yield_model = (
            yield_model
        )

        self._budget_inspector = (
            budget_inspector
        )

        self._state_store = (
            state_store
        )

        self._config = (
            config
            or ConvergenceConfig()
        )
        self._maximum_tier = normalize_search_tier(maximum_tier)

    async def evaluate(
        self,
        *,
        seed_event: Event,
        branch_id: str,
        lane: BudgetLane,
        current_tier: SearchTier | str,
        now: datetime | None = None,
    ) -> ConvergenceDecision:
        """Evaluate one branch without executing or reserving work."""

        evaluated_at = (
            now
            or utc_now()
        )

        if (
            evaluated_at.tzinfo is None
            or evaluated_at.utcoffset()
            is None
        ):
            raise ValueError(
                "convergence evaluation time must be timezone-aware"
            )

        tier = normalize_search_tier(
            current_tier
        )
        if tier.rank > self._maximum_tier.rank:
            raise ValueError(
                f"current tier {tier.value} exceeds configured maximum tier "
                f"{self._maximum_tier.value}"
            )

        target_key = (
            target_key_for_event(
                seed_event
            )
        )

        prior = await self._state_store.get(
            target_key=target_key,
            branch_id=branch_id,
            lane=lane,
        )

        if prior is None:
            prior = ConvergenceState(
                target_key=target_key,
                branch_id=branch_id,
                lane=lane,
                tier=tier,
                updated_at=evaluated_at,
            )

        elif (
            prior.tier
            is not tier
            and not prior.closed
        ):
            # The orchestrator is authoritative for the currently active tier.
            # Synchronize instead of silently evaluating stale state.
            prior = prior.model_copy(
                update={
                    "tier": tier,
                }
            )

        trend, estimate = await asyncio.gather(
            self._yield_model.branch_trend(
                branch_id=branch_id,
                target_key=target_key,
            ),
            self._yield_model.estimate(
                YieldQuery(
                    target_key=target_key,
                    branch_id=branch_id,
                )
            ),
        )

        budget = await self._budget_inspector.state_for(
            branch_id=branch_id,
            lane=lane,
            branch_soft_multiplier=(
                prior.branch_soft_multiplier
            ),
        )

        decision = self._decide(
            prior=prior,
            trend=trend,
            estimate=estimate,
            budget=budget,
            evaluated_at=evaluated_at,
        )

        await self._state_store.put(
            decision.state_after
        )

        return decision

    def _decide(
        self,
        *,
        prior: ConvergenceState,
        trend: BranchYieldTrend,
        estimate: YieldEstimate,
        budget: BranchBudgetState,
        evaluated_at: datetime,
    ) -> ConvergenceDecision:
        lane = prior.lane
        tier = prior.tier

        protected_exploration = (
            lane
            is BudgetLane.EXPLORATION
        )

        reasons: list[str] = []

        information_gain = (
            estimate.uncertainty
        )

        multiplier = (
            productive_soft_multiplier(
                expected_yield=(
                    estimate.expected_yield
                ),
                config=self._config,
            )
        )

        if prior.closed:
            after = prior.model_copy(
                update={
                    "branch_soft_multiplier": 1.0,
                    "last_action": (
                        ConvergenceAction.CLOSE
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.CLOSE
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=None,
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=(
                    "branch is already closed",
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        # HARD budget is non-negotiable and must override an existing
        # cooldown. BudgetManager would deny future cumulative work anyway, so
        # convergence should not keep a branch merely "temporarily paused".
        if (
            budget.hard_pressure
            >= (
                self._config.hard_pressure_close_threshold
            )
        ):
            reasons.append(
                "hard branch budget is exhausted; future positive demand "
                "cannot be authorized"
            )

            after = prior.model_copy(
                update={
                    "evaluations": (
                        prior.evaluations
                        + 1
                    ),
                    "branch_soft_multiplier": 1.0,
                    "closed": True,
                    "cooldown_until": None,
                    "last_action": (
                        ConvergenceAction.CLOSE
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.CLOSE
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=None,
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        if (
            prior.cooldown_until
            is not None
            and evaluated_at
            < prior.cooldown_until
        ):
            reasons.append(
                "existing cooldown has not expired"
            )

            if protected_exploration:
                reasons.append(
                    "exploration reserve remains protected during cooldown"
                )

            after = prior.model_copy(
                update={
                    "branch_soft_multiplier": 1.0,
                    "last_action": (
                        ConvergenceAction.COOLDOWN
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.COOLDOWN
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=(
                    prior.cooldown_until
                ),
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        evaluations = (
            prior.evaluations
            + 1
        )

        history_ready = (
            trend.recent_executions
            >= self._config.minimum_recent_executions
        )

        productive = bool(
            history_ready
            and (
                trend.recent_hit_rate
                >= self._config.productive_hit_rate
                or trend.recent_novel_assets_per_execution
                >= (
                    self._config.productive_novel_assets_per_execution
                )
            )
            and estimate.expected_yield
            >= self._config.advance_expected_yield
        )

        low_yield = bool(
            history_ready
            and (
                trend.low_marginal_yield
                or (
                    trend.convergence_signal
                    >= (
                        self._config.low_yield_convergence_signal
                    )
                    and information_gain
                    <= self._config.low_information_gain
                )
            )
        )

        low_yield_streak = (
            prior.low_yield_streak
            + 1
            if low_yield
            else 0
        )

        productive_streak = (
            prior.productive_streak
            + 1
            if productive
            else 0
        )

        if (
            budget.soft_pressure
            >= (
                self._config.soft_pressure_cooldown_threshold
            )
        ):
            reasons.append(
                "effective soft branch budget is exhausted; preserve "
                "frontier and allow budget policy to defer further work"
            )

            if protected_exploration:
                reasons.append(
                    "exploration lane used the full protected soft allowance; "
                    "cooldown is temporary rather than permanent close"
                )

            cooldown_until = (
                evaluated_at
                + cooldown_duration(
                    prior.cooldown_count
                    + 1,
                    config=self._config,
                )
            )

            after = prior.model_copy(
                update={
                    "evaluations": evaluations,
                    "low_yield_streak": (
                        low_yield_streak
                    ),
                    "productive_streak": (
                        productive_streak
                    ),
                    "cooldown_count": (
                        prior.cooldown_count
                        + 1
                    ),
                    "cooldown_until": (
                        cooldown_until
                    ),
                    "branch_soft_multiplier": 1.0,
                    "last_action": (
                        ConvergenceAction.COOLDOWN
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.COOLDOWN
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=(
                    cooldown_until
                ),
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        if not history_ready:
            reasons.append(
                "insufficient recent history; continue bounded work to reduce "
                "uncertainty instead of treating sparse evidence as zero yield"
            )

            after = prior.model_copy(
                update={
                    "evaluations": evaluations,
                    "low_yield_streak": 0,
                    "productive_streak": 0,
                    "cooldown_until": None,
                    "branch_soft_multiplier": 1.0,
                    "last_action": (
                        ConvergenceAction.CONTINUE
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.CONTINUE
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=None,
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        if (
            productive
            and productive_streak
            >= (
                self._config.advance_productive_streak
            )
            and tier.rank < self._maximum_tier.rank
            and budget.soft_pressure
            < (
                self._config.advance_max_soft_pressure
            )
        ):
            next_tier = (
                tier.next_tier
            )

            reasons.extend(
                (
                    "recent branch yield remains productive",
                    (
                        "advance exactly one tier while remaining below "
                        "the configured soft-budget pressure threshold"
                    ),
                )
            )

            after = prior.model_copy(
                update={
                    "evaluations": evaluations,
                    "tier": next_tier,
                    "low_yield_streak": 0,
                    "productive_streak": 0,
                    "cooldown_until": None,
                    "branch_soft_multiplier": multiplier,
                    "last_action": (
                        ConvergenceAction.ADVANCE_TIER
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.ADVANCE_TIER
                ),
                recommended_tier=(
                    next_tier
                ),
                multiplier=multiplier,
                cooldown_until=None,
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        if (
            low_yield
            and low_yield_streak
            >= (
                self._config.cooldown_low_yield_streak
            )
        ):
            if (
                not protected_exploration
                and tier.is_exhaustive
                and low_yield_streak
                >= (
                    self._config.close_low_yield_streak
                )
                and information_gain
                <= self._config.low_information_gain
            ):
                reasons.extend(
                    (
                        "normal lane is already at EXHAUSTIVE tier",
                        "repeated low marginal yield persists",
                        "remaining information gain is low",
                    )
                )

                after = prior.model_copy(
                    update={
                        "evaluations": evaluations,
                        "low_yield_streak": (
                            low_yield_streak
                        ),
                        "productive_streak": 0,
                        "closed": True,
                        "cooldown_until": None,
                        "last_action": (
                            ConvergenceAction.CLOSE
                        ),
                        "updated_at": (
                            evaluated_at
                        ),
                    }
                )

                return self._decision(
                    prior=prior,
                    after=after,
                    action=(
                        ConvergenceAction.CLOSE
                    ),
                    recommended_tier=tier,
                    multiplier=1.0,
                    cooldown_until=None,
                    trend=trend,
                    estimate=estimate,
                    budget=budget,
                    reasons=tuple(
                        reasons
                    ),
                    protected_exploration=(
                        protected_exploration
                    ),
                    evaluated_at=evaluated_at,
                )

            reasons.append(
                "recent marginal yield is repeatedly low; pause the branch "
                "instead of continuously spending budget"
            )

            if protected_exploration:
                reasons.append(
                    "exploration lane is not permanently closed by low yield; "
                    "the protected lane will be eligible again after cooldown"
                )

            cooldown_until = (
                evaluated_at
                + cooldown_duration(
                    prior.cooldown_count
                    + 1,
                    config=self._config,
                )
            )

            after = prior.model_copy(
                update={
                    "evaluations": evaluations,
                    "low_yield_streak": (
                        low_yield_streak
                    ),
                    "productive_streak": 0,
                    "cooldown_count": (
                        prior.cooldown_count
                        + 1
                    ),
                    "cooldown_until": (
                        cooldown_until
                    ),
                    "branch_soft_multiplier": 1.0,
                    "last_action": (
                        ConvergenceAction.COOLDOWN
                    ),
                    "updated_at": (
                        evaluated_at
                    ),
                }
            )

            return self._decision(
                prior=prior,
                after=after,
                action=(
                    ConvergenceAction.COOLDOWN
                ),
                recommended_tier=tier,
                multiplier=1.0,
                cooldown_until=(
                    cooldown_until
                ),
                trend=trend,
                estimate=estimate,
                budget=budget,
                reasons=tuple(
                    reasons
                ),
                protected_exploration=(
                    protected_exploration
                ),
                evaluated_at=evaluated_at,
            )

        if productive:
            reasons.append(
                "branch is productive but has not yet satisfied the "
                "consecutive-evaluation threshold for tier advancement"
            )

        elif low_yield:
            reasons.append(
                "low-yield signal is present but has not persisted long "
                "enough for cooldown"
            )

        else:
            reasons.append(
                "branch remains within acceptable marginal-yield bounds"
            )

        after = prior.model_copy(
            update={
                "evaluations": evaluations,
                "low_yield_streak": (
                    low_yield_streak
                ),
                "productive_streak": (
                    productive_streak
                ),
                "cooldown_until": None,
                "branch_soft_multiplier": (
                    multiplier
                    if productive
                    else 1.0
                ),
                "last_action": (
                    ConvergenceAction.CONTINUE
                ),
                "updated_at": (
                    evaluated_at
                ),
            }
        )

        return self._decision(
            prior=prior,
            after=after,
            action=(
                ConvergenceAction.CONTINUE
            ),
            recommended_tier=tier,
            multiplier=(
                multiplier
                if productive
                else 1.0
            ),
            cooldown_until=None,
            trend=trend,
            estimate=estimate,
            budget=budget,
            reasons=tuple(
                reasons
            ),
            protected_exploration=(
                protected_exploration
            ),
            evaluated_at=evaluated_at,
        )

    @staticmethod
    def _decision(
        *,
        prior: ConvergenceState,
        after: ConvergenceState,
        action: ConvergenceAction,
        recommended_tier: SearchTier,
        multiplier: float,
        cooldown_until: datetime | None,
        trend: BranchYieldTrend,
        estimate: YieldEstimate,
        budget: BranchBudgetState,
        reasons: Sequence[str],
        protected_exploration: bool,
        evaluated_at: datetime,
    ) -> ConvergenceDecision:
        return ConvergenceDecision(
            target_key=prior.target_key,
            branch_id=prior.branch_id,
            lane=prior.lane,
            protected_exploration=(
                protected_exploration
            ),
            action=action,
            current_tier=prior.tier,
            recommended_tier=(
                recommended_tier
            ),
            recommended_branch_soft_multiplier=max(
                1.0,
                multiplier,
            ),
            cooldown_until=(
                cooldown_until
            ),
            expected_yield=(
                estimate.expected_yield
            ),
            information_gain=(
                estimate.uncertainty
            ),
            convergence_signal=(
                trend.convergence_signal
            ),
            trend=trend,
            yield_estimate=estimate,
            budget=budget,
            reasons=tuple(
                reason
                for reason in reasons
                if reason
            ),
            state_before=prior,
            state_after=after,
            evaluated_at=evaluated_at,
        )


def normalize_search_tier(
    value: SearchTier | str,
) -> SearchTier:
    if isinstance(
        value,
        SearchTier,
    ):
        return value

    normalized = (
        str(
            value
        )
        .strip()
        .upper()
    )

    return SearchTier(
        normalized
    )


def productive_soft_multiplier(
    *,
    expected_yield: float,
    config: ConvergenceConfig,
) -> float:
    """Recommend extra branch soft budget only for clearly productive yield."""

    if (
        expected_yield
        < config.productive_soft_multiplier_threshold
        or config.productive_soft_multiplier_max
        <= 1.0
    ):
        return 1.0

    denominator = max(
        1e-9,
        1.0
        - config.productive_soft_multiplier_threshold,
    )

    progress = (
        expected_yield
        - config.productive_soft_multiplier_threshold
    ) / denominator

    return min(
        config.productive_soft_multiplier_max,
        1.0
        + clamp01(
            progress
        )
        * (
            config.productive_soft_multiplier_max
            - 1.0
        ),
    )


def cooldown_duration(
    cooldown_number: int,
    *,
    config: ConvergenceConfig,
) -> timedelta:
    """Exponential bounded cooldown."""

    ordinal = max(
        1,
        cooldown_number,
    )

    seconds = (
        config.cooldown_base_seconds
        * (
            2
            ** min(
                ordinal
                - 1,
                20,
            )
        )
    )

    seconds = min(
        seconds,
        config.cooldown_max_seconds,
    )

    return timedelta(
        seconds=seconds
    )


def budget_context_for_decision(
    decision: ConvergenceDecision,
    *,
    base: BudgetContext | None = None,
) -> BudgetContext:
    """Create BudgetContext consistent with a convergence recommendation."""

    context = (
        base
        or BudgetContext()
    )

    return context.model_copy(
        update={
            "lane": (
                decision.lane
            ),
            "branch_soft_multiplier": (
                decision.recommended_branch_soft_multiplier
            ),
        }
    )


def clamp01(
    value: float,
) -> float:
    return min(
        1.0,
        max(
            0.0,
            float(
                value
            ),
        ),
    )
