"""Explainable discovery-yield intelligence for Night Scout.

This module measures *recon productivity*, not vulnerability severity.

It answers questions such as:

- Which worker/action is still producing new assets?
- Which branch is approaching diminishing returns?
- Which public/target vocabulary token has actually produced confirmations?
- Which learned naming pattern is productive?
- Which route/source deserves more scheduler attention?
- How uncertain is the current estimate, and therefore how much information
  could another bounded experiment provide?

The model intentionally separates execution success from discovery yield:

    worker process SUCCEEDED + 0 new assets
        != productive discovery

and:

    worker process RETRY + partial persisted discoveries
        can still have positive yield

This matters because Night Scout workers stream/publish deduplicable partial
results before a retryable backend failure.

Integration contracts
---------------------
No existing module needs to depend on this file.

Scheduler:
    YieldSchedulingSignalProvider
        implements core.scheduler.SchedulingSignalProvider

Wordlist corpus:
    WordlistYieldFeedbackAdapter
        implements intelligence.wordlists.YieldFeedbackProvider

Pattern engine:
    PatternYieldFeedbackAdapter
        implements intelligence.patterns.PatternFeedbackProvider

Persistence:
    YieldStore
        is the storage boundary

An in-memory implementation is provided for tests/bootstrap. A future SQLite
adapter can implement the same protocol transactionally.

Atomic observation model
------------------------
One YieldObservation normally represents one completed/partial worker execution
or one explicitly aggregated batch.

It carries task-level metrics:

    attempted_units
    successful_hits
    new_assets
    novel_assets
    requests
    runtime
    cost

and exact per-token / per-pattern credit:

    TokenYieldCredit
    PatternYieldCredit

This avoids ambiguous inference when a single worker batch tested many
candidate words. For example, a pairwise permutation can explicitly credit both
input tokens without trying to reconstruct attribution from hostname strings.

Statistical model
-----------------
Hit probability uses an explainable Beta-Binomial posterior. Sparse histories
therefore shrink toward a configurable prior instead of becoming 0% or 100%
after one observation.

Expected yield combines:

    posterior hit probability
    discoveries per attempted unit
    novelty fraction
    execution reliability

All components remain bounded in [0, 1].

Task scheduling uses a hierarchical blend of:
    target
    worker
    worker+action
    route
    branch
    input source

Specific contexts receive more weight as evidence accumulates. Sparse contexts
also produce a higher information-gain signal so protected exploration does not
vanish simply because it has little historical data.

Convergence
-----------
`branch_trend(...)` compares recent and previous execution windows. It only
emits an explainable low-marginal-yield signal; it does not close a branch or
override policy/budgets. A later convergence controller can consume it.
"""

from __future__ import annotations

import asyncio
import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from enum import StrEnum
from statistics import pstdev
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event
from recon.core.queue import Task
from recon.core.scheduler import SchedulingSignals
from recon.intelligence.patterns import PatternFeedback
from recon.intelligence.wordlists import (
    CorpusCategory,
    YieldFeedback,
    canonical_token_key,
    infer_seed_domain,
    normalize_token_for_category,
)


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""

    return datetime.now(timezone.utc)


def new_yield_observation_id() -> str:
    return f"yld_{uuid4().hex}"


class YieldExecutionOutcome(StrEnum):
    """Execution result independent from discovery productivity."""

    SUCCEEDED = "SUCCEEDED"
    RETRY = "RETRY"
    FAILED = "FAILED"


class TokenYieldCredit(BaseModel):
    """Exact historical credit for one corpus token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    category: CorpusCategory

    attempted_hypotheses: int = Field(default=1, ge=0)
    successful_hits: int = Field(default=0, ge=0)

    new_assets: int = Field(default=0, ge=0)
    novel_assets: int = Field(default=0, ge=0)

    source_ids: frozenset[str] = Field(default_factory=frozenset)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("token")
    @classmethod
    def token_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("token must not be blank")

        return normalized

    @field_validator("source_ids")
    @classmethod
    def normalize_sources(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in values
            if value.strip()
        )

    @model_validator(mode="after")
    def valid_counts(
        self,
    ) -> "TokenYieldCredit":
        if self.successful_hits > self.attempted_hypotheses:
            raise ValueError(
                "token successful_hits cannot exceed attempted_hypotheses"
            )

        if self.novel_assets > self.new_assets:
            raise ValueError(
                "token novel_assets cannot exceed new_assets"
            )

        normalized = normalize_token_for_category(
            self.token,
            category=self.category,
        )

        if normalized is None:
            raise ValueError(
                "token is invalid for its corpus category"
            )

        return self


class PatternYieldCredit(BaseModel):
    """Exact historical credit for one learned naming pattern."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str

    attempted_hypotheses: int = Field(default=1, ge=0)
    successful_hits: int = Field(default=0, ge=0)

    new_assets: int = Field(default=0, ge=0)
    novel_assets: int = Field(default=0, ge=0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pattern_id")
    @classmethod
    def pattern_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("pattern_id must not be blank")

        return normalized

    @model_validator(mode="after")
    def valid_counts(
        self,
    ) -> "PatternYieldCredit":
        if self.successful_hits > self.attempted_hypotheses:
            raise ValueError(
                "pattern successful_hits cannot exceed attempted_hypotheses"
            )

        if self.novel_assets > self.new_assets:
            raise ValueError(
                "pattern novel_assets cannot exceed new_assets"
            )

        return self


class YieldObservation(BaseModel):
    """One explainable productivity observation.

    `attempted_units` is the number of logical candidate opportunities tested by
    this observation. For a one-request enrichment worker it may be 1. For a
    bounded permutation/parameter batch it may be the number of candidates.

    `successful_hits` means productive candidate hits/confirmations, not process
    exit success.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(
        default_factory=new_yield_observation_id
    )

    observed_at: datetime = Field(default_factory=utc_now)

    run_id: str | None = None
    task_id: str | None = None
    input_event_id: str | None = None

    target_key: str | None = None
    branch_id: str | None = None

    worker: str
    action: str

    route_rule_id: str | None = None
    input_source: str | None = None

    source_ids: frozenset[str] = Field(default_factory=frozenset)

    execution_outcome: YieldExecutionOutcome = (
        YieldExecutionOutcome.SUCCEEDED
    )

    attempted_units: int = Field(default=1, ge=0)
    successful_hits: int = Field(default=0, ge=0)

    new_assets: int = Field(default=0, ge=0)
    novel_assets: int = Field(default=0, ge=0)

    new_domains: int = Field(default=0, ge=0)
    new_urls: int = Field(default=0, ge=0)
    new_endpoints: int = Field(default=0, ge=0)
    new_vocabulary_tokens: int = Field(default=0, ge=0)
    new_patterns: int = Field(default=0, ge=0)

    request_count: float = Field(default=0.0, ge=0.0)
    runtime_seconds: float = Field(default=0.0, ge=0.0)

    # Abstract scheduler cost units. Workers may choose to map expensive
    # external API calls / CPU / subprocess batches into this value.
    cost_units: float = Field(default=1.0, gt=0.0)

    token_credits: tuple[TokenYieldCredit, ...] = ()
    pattern_credits: tuple[PatternYieldCredit, ...] = ()

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "observation_id",
        "worker",
        "action",
    )
    @classmethod
    def required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized

    @field_validator(
        "run_id",
        "task_id",
        "input_event_id",
        "target_key",
        "branch_id",
        "route_rule_id",
        "input_source",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @field_validator("source_ids")
    @classmethod
    def normalize_source_ids(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in values
            if value.strip()
        )

    @field_validator("observed_at")
    @classmethod
    def timestamp_is_aware(
        cls,
        value: datetime,
    ) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "observed_at must be timezone-aware"
            )

        return value

    @model_validator(mode="after")
    def count_invariants(
        self,
    ) -> "YieldObservation":
        if self.successful_hits > self.attempted_units:
            raise ValueError(
                "successful_hits cannot exceed attempted_units"
            )

        if self.novel_assets > self.new_assets:
            raise ValueError(
                "novel_assets cannot exceed new_assets"
            )

        return self


class YieldQuery(BaseModel):
    """Filter used by the persistence boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str | None = None
    branch_id: str | None = None

    worker: str | None = None
    action: str | None = None

    route_rule_id: str | None = None
    input_source: str | None = None

    source_id: str | None = None

    token: str | None = None
    token_category: CorpusCategory | None = None

    pattern_id: str | None = None

    since: datetime | None = None
    until: datetime | None = None

    limit: int | None = Field(default=None, ge=1)

    newest_first: bool = False

    @field_validator(
        "target_key",
        "branch_id",
        "worker",
        "action",
        "route_rule_id",
        "input_source",
        "source_id",
        "token",
        "pattern_id",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @field_validator("since", "until")
    @classmethod
    def timestamps_are_aware(
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
                "yield query timestamps must be timezone-aware"
            )

        return value

    @model_validator(mode="after")
    def valid_window(
        self,
    ) -> "YieldQuery":
        if (
            self.since is not None
            and self.until is not None
            and self.since > self.until
        ):
            raise ValueError(
                "yield query since cannot be after until"
            )

        if (
            self.token_category is not None
            and self.token is None
        ):
            raise ValueError(
                "token_category requires token"
            )

        return self


class YieldAggregate(BaseModel):
    """Sufficient statistics for an explainable yield estimate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observations: int = Field(default=0, ge=0)
    executions: int = Field(default=0, ge=0)

    execution_succeeded: int = Field(default=0, ge=0)
    execution_retry: int = Field(default=0, ge=0)
    execution_failed: int = Field(default=0, ge=0)

    attempted_units: int = Field(default=0, ge=0)
    successful_hits: int = Field(default=0, ge=0)

    new_assets: int = Field(default=0, ge=0)
    novel_assets: int = Field(default=0, ge=0)

    new_domains: int = Field(default=0, ge=0)
    new_urls: int = Field(default=0, ge=0)
    new_endpoints: int = Field(default=0, ge=0)
    new_vocabulary_tokens: int = Field(default=0, ge=0)
    new_patterns: int = Field(default=0, ge=0)

    request_count: float = Field(default=0.0, ge=0.0)
    runtime_seconds: float = Field(default=0.0, ge=0.0)
    cost_units: float = Field(default=0.0, ge=0.0)

    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None

    @field_validator(
        "first_observed_at",
        "last_observed_at",
    )
    @classmethod
    def timestamps_are_aware(
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
                "aggregate timestamps must be timezone-aware"
            )

        return value

    @property
    def execution_success_rate(
        self,
    ) -> float:
        if self.executions <= 0:
            return 0.0

        return (
            self.execution_succeeded
            / self.executions
        )

    @property
    def raw_hit_rate(
        self,
    ) -> float:
        if self.attempted_units <= 0:
            return 0.0

        return (
            self.successful_hits
            / self.attempted_units
        )

    @property
    def discoveries_per_attempt(
        self,
    ) -> float:
        if self.attempted_units <= 0:
            return 0.0

        return (
            self.new_assets
            / self.attempted_units
        )

    @property
    def novelty_fraction(
        self,
    ) -> float:
        if self.new_assets <= 0:
            return 0.0

        return (
            self.novel_assets
            / self.new_assets
        )

    @property
    def mean_cost_units(
        self,
    ) -> float | None:
        if self.executions <= 0:
            return None

        return (
            self.cost_units
            / self.executions
        )

    @property
    def mean_runtime_seconds(
        self,
    ) -> float | None:
        if self.executions <= 0:
            return None

        return (
            self.runtime_seconds
            / self.executions
        )

    @property
    def mean_requests(
        self,
    ) -> float | None:
        if self.executions <= 0:
            return None

        return (
            self.request_count
            / self.executions
        )


class YieldEstimate(BaseModel):
    """Normalized [0,1] productivity estimate plus cost/uncertainty."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    query: YieldQuery
    aggregate: YieldAggregate

    posterior_hit_rate: float = Field(ge=0.0, le=1.0)
    discovery_score: float = Field(ge=0.0, le=1.0)
    novelty_score: float = Field(ge=0.0, le=1.0)
    execution_reliability: float = Field(ge=0.0, le=1.0)

    expected_yield: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)

    estimated_cost: float = Field(gt=0.0)

    effective_sample_size: float = Field(ge=0.0)


class TaskYieldComponent(BaseModel):
    """One hierarchical component used in a task estimate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    base_weight: float = Field(gt=0.0)

    reliability: float = Field(ge=0.0, le=1.0)
    applied_weight: float = Field(ge=0.0)

    estimate: YieldEstimate

    @field_validator("name")
    @classmethod
    def name_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("component name must not be blank")

        return normalized


class TaskYieldEstimate(BaseModel):
    """Hierarchically blended task estimate used by scheduler."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str

    target_key: str | None = None

    expected_yield: float = Field(ge=0.0, le=1.0)
    information_gain: float = Field(ge=0.0, le=1.0)
    estimated_cost: float = Field(gt=0.0)

    component_disagreement: float = Field(ge=0.0, le=1.0)

    components: tuple[TaskYieldComponent, ...]


class BranchYieldTrend(BaseModel):
    """Recent-vs-previous marginal yield diagnostic."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str | None = None
    branch_id: str

    recent_executions: int = Field(ge=0)
    previous_executions: int = Field(ge=0)

    recent_hit_rate: float = Field(ge=0.0, le=1.0)
    previous_hit_rate: float = Field(ge=0.0, le=1.0)

    recent_assets_per_execution: float = Field(ge=0.0)
    previous_assets_per_execution: float = Field(ge=0.0)

    recent_novel_assets_per_execution: float = Field(ge=0.0)
    previous_novel_assets_per_execution: float = Field(ge=0.0)

    marginal_yield_delta: float

    convergence_signal: float = Field(ge=0.0, le=1.0)
    low_marginal_yield: bool

    reason: str


class YieldStore(Protocol):
    """Persistence boundary for raw yield observations."""

    async def append(
        self,
        observation: YieldObservation,
    ) -> bool:
        """Insert an observation; return False for duplicate observation_id."""

        ...

    async def query(
        self,
        query: YieldQuery,
    ) -> Sequence[YieldObservation]:
        """Return matching observations."""

        ...

    async def aggregate(
        self,
        query: YieldQuery,
    ) -> YieldAggregate:
        """Return sufficient statistics for matching observations."""

        ...


class InMemoryYieldStore:
    """Concurrency-safe bootstrap implementation of YieldStore."""

    def __init__(self) -> None:
        self._observations: dict[
            str,
            YieldObservation,
        ] = {}

        self._lock = asyncio.Lock()

    async def append(
        self,
        observation: YieldObservation,
    ) -> bool:
        async with self._lock:
            if (
                observation.observation_id
                in self._observations
            ):
                return False

            self._observations[
                observation.observation_id
            ] = observation.model_copy(
                deep=True
            )

            return True

    async def query(
        self,
        query: YieldQuery,
    ) -> Sequence[YieldObservation]:
        async with self._lock:
            matches = [
                observation.model_copy(
                    deep=True
                )
                for observation
                in self._observations.values()
                if observation_matches_query(
                    observation,
                    query,
                )
            ]

        matches.sort(
            key=lambda observation: (
                observation.observed_at,
                observation.observation_id,
            ),
            reverse=query.newest_first,
        )

        if query.limit is not None:
            matches = matches[
                : query.limit
            ]

        return tuple(matches)

    async def aggregate(
        self,
        query: YieldQuery,
    ) -> YieldAggregate:
        observations = await self.query(
            query.model_copy(
                update={
                    "limit": None,
                }
            )
        )

        return aggregate_observations_for_query(
            observations,
            query=query,
        )


class YieldEventProvider(Protocol):
    """Load input Events for scheduler context."""

    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class YieldModelConfig(BaseModel):
    """Statistical priors, blend weights, and convergence thresholds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Neutral prior mean = alpha / (alpha + beta).
    hit_prior_alpha: float = Field(default=1.0, gt=0.0)
    hit_prior_beta: float = Field(default=1.0, gt=0.0)

    execution_prior_alpha: float = Field(default=4.0, gt=0.0)
    execution_prior_beta: float = Field(default=1.0, gt=0.0)

    novelty_prior_alpha: float = Field(default=1.0, gt=0.0)
    novelty_prior_beta: float = Field(default=1.0, gt=0.0)

    discovery_saturation_per_attempt: float = Field(
        default=1.0,
        gt=0.0,
    )

    hit_weight: float = Field(default=0.50, ge=0.0)
    discovery_weight: float = Field(default=0.25, ge=0.0)
    novelty_weight: float = Field(default=0.15, ge=0.0)
    reliability_weight: float = Field(default=0.10, ge=0.0)

    default_cost_units: float = Field(default=1.0, gt=0.0)

    # Hierarchical task blend.
    prior_component_weight: float = Field(default=1.0, gt=0.0)

    target_weight: float = Field(default=0.75, gt=0.0)
    worker_weight: float = Field(default=1.0, gt=0.0)
    worker_action_weight: float = Field(default=2.5, gt=0.0)
    route_weight: float = Field(default=1.5, gt=0.0)
    branch_weight: float = Field(default=1.5, gt=0.0)
    input_source_weight: float = Field(default=1.0, gt=0.0)

    reliability_half_life: float = Field(default=12.0, gt=0.0)

    # Information gain.
    uncertainty_weight: float = Field(default=0.75, ge=0.0)
    disagreement_weight: float = Field(default=0.25, ge=0.0)

    # Branch convergence diagnostic.
    trend_window_executions: int = Field(default=20, ge=2, le=10_000)
    trend_min_recent_executions: int = Field(default=8, ge=2, le=10_000)

    low_hit_rate_threshold: float = Field(
        default=0.08,
        ge=0.0,
        le=1.0,
    )

    low_assets_per_execution_threshold: float = Field(
        default=0.10,
        ge=0.0,
    )

    low_novel_assets_per_execution_threshold: float = Field(
        default=0.05,
        ge=0.0,
    )

    @model_validator(mode="after")
    def valid_weights(
        self,
    ) -> "YieldModelConfig":
        total = (
            self.hit_weight
            + self.discovery_weight
            + self.novelty_weight
            + self.reliability_weight
        )

        if total <= 0.0:
            raise ValueError(
                "at least one expected-yield component weight is required"
            )

        information_total = (
            self.uncertainty_weight
            + self.disagreement_weight
        )

        if information_total <= 0.0:
            raise ValueError(
                "information gain weights cannot both be zero"
            )

        if (
            self.trend_min_recent_executions
            > self.trend_window_executions
        ):
            raise ValueError(
                "trend_min_recent_executions cannot exceed trend window"
            )

        return self

    @property
    def prior_hit_mean(
        self,
    ) -> float:
        return (
            self.hit_prior_alpha
            / (
                self.hit_prior_alpha
                + self.hit_prior_beta
            )
        )


class YieldModel:
    """Explainable productivity estimator."""

    def __init__(
        self,
        store: YieldStore,
        *,
        config: YieldModelConfig | None = None,
    ) -> None:
        self._store = store
        self._config = (
            config
            or YieldModelConfig()
        )

    @property
    def store(
        self,
    ) -> YieldStore:
        return self._store

    @property
    def config(
        self,
    ) -> YieldModelConfig:
        return self._config

    async def estimate(
        self,
        query: YieldQuery,
    ) -> YieldEstimate:
        aggregate = await self._store.aggregate(
            query
        )

        return estimate_from_aggregate(
            query,
            aggregate,
            config=self._config,
        )

    async def estimate_for_worker(
        self,
        *,
        target_key: str | None,
        worker: str,
        action: str | None = None,
    ) -> YieldEstimate:
        return await self.estimate(
            YieldQuery(
                target_key=target_key,
                worker=worker,
                action=action,
            )
        )

    async def estimate_for_source(
        self,
        *,
        target_key: str | None,
        source_id: str,
    ) -> YieldEstimate:
        return await self.estimate(
            YieldQuery(
                target_key=target_key,
                source_id=source_id,
            )
        )

    async def estimate_for_token(
        self,
        *,
        target_key: str | None,
        token: str,
        category: CorpusCategory,
    ) -> YieldEstimate:
        return await self.estimate(
            YieldQuery(
                target_key=target_key,
                token=token,
                token_category=category,
            )
        )

    async def estimate_for_pattern(
        self,
        *,
        target_key: str | None,
        pattern_id: str,
    ) -> YieldEstimate:
        return await self.estimate(
            YieldQuery(
                target_key=target_key,
                pattern_id=pattern_id,
            )
        )

    async def task_estimate(
        self,
        task: Task,
        *,
        input_event: Event | None,
    ) -> TaskYieldEstimate:
        target_key = (
            target_key_for_event(
                input_event
            )
            if input_event is not None
            else None
        )

        input_source = (
            input_event.source
            if input_event is not None
            else None
        )

        component_specs: list[
            tuple[
                str,
                float,
                YieldQuery,
            ]
        ] = []

        if target_key is not None:
            component_specs.append(
                (
                    "target",
                    self._config.target_weight,
                    YieldQuery(
                        target_key=target_key,
                    ),
                )
            )

        component_specs.extend(
            (
                (
                    "worker",
                    self._config.worker_weight,
                    YieldQuery(
                        target_key=target_key,
                        worker=task.worker,
                    ),
                ),
                (
                    "worker_action",
                    self._config.worker_action_weight,
                    YieldQuery(
                        target_key=target_key,
                        worker=task.worker,
                        action=task.action,
                    ),
                ),
            )
        )

        if task.route_rule_id is not None:
            component_specs.append(
                (
                    "route",
                    self._config.route_weight,
                    YieldQuery(
                        target_key=target_key,
                        route_rule_id=(
                            task.route_rule_id
                        ),
                    ),
                )
            )

        if task.branch_id is not None:
            component_specs.append(
                (
                    "branch",
                    self._config.branch_weight,
                    YieldQuery(
                        target_key=target_key,
                        branch_id=(
                            task.branch_id
                        ),
                    ),
                )
            )

        if input_source is not None:
            component_specs.append(
                (
                    "input_source",
                    self._config.input_source_weight,
                    YieldQuery(
                        target_key=target_key,
                        input_source=input_source,
                    ),
                )
            )

        estimates = await asyncio.gather(
            *(
                self.estimate(
                    query
                )
                for (
                    _name,
                    _weight,
                    query,
                )
                in component_specs
            )
        )

        components: list[
            TaskYieldComponent
        ] = []

        for (
            (
                name,
                base_weight,
                _query,
            ),
            estimate,
        ) in zip(
            component_specs,
            estimates,
            strict=True,
        ):
            reliability = component_reliability(
                estimate.aggregate,
                half_life=(
                    self._config.reliability_half_life
                ),
            )

            applied = (
                base_weight
                * reliability
            )

            components.append(
                TaskYieldComponent(
                    name=name,
                    base_weight=base_weight,
                    reliability=reliability,
                    applied_weight=applied,
                    estimate=estimate,
                )
            )

        expected_numerator = (
            self._config.prior_hit_mean
            * self._config.prior_component_weight
        )

        expected_denominator = (
            self._config.prior_component_weight
        )

        cost_numerator = (
            self._config.default_cost_units
            * self._config.prior_component_weight
        )

        cost_denominator = (
            self._config.prior_component_weight
        )

        uncertainty_numerator = (
            1.0
            * self._config.prior_component_weight
        )

        uncertainty_denominator = (
            self._config.prior_component_weight
        )

        weighted_component_yields: list[float] = []

        for component in components:
            if component.applied_weight <= 0.0:
                continue

            estimate = component.estimate
            weight = component.applied_weight

            expected_numerator += (
                estimate.expected_yield
                * weight
            )

            expected_denominator += (
                weight
            )

            cost_numerator += (
                estimate.estimated_cost
                * weight
            )

            cost_denominator += (
                weight
            )

            uncertainty_numerator += (
                estimate.uncertainty
                * weight
            )

            uncertainty_denominator += (
                weight
            )

            weighted_component_yields.append(
                estimate.expected_yield
            )

        expected_yield = (
            expected_numerator
            / expected_denominator
        )

        estimated_cost = (
            cost_numerator
            / cost_denominator
        )

        uncertainty = (
            uncertainty_numerator
            / uncertainty_denominator
        )

        disagreement = normalized_disagreement(
            weighted_component_yields
        )

        information_total = (
            self._config.uncertainty_weight
            + self._config.disagreement_weight
        )

        information_gain = (
            (
                uncertainty
                * self._config.uncertainty_weight
                + disagreement
                * self._config.disagreement_weight
            )
            / information_total
        )

        return TaskYieldEstimate(
            task_id=task.task_id,
            target_key=target_key,
            expected_yield=clamp01(
                expected_yield
            ),
            information_gain=clamp01(
                information_gain
            ),
            estimated_cost=max(
                estimated_cost,
                1e-9,
            ),
            component_disagreement=(
                disagreement
            ),
            components=tuple(
                components
            ),
        )

    async def branch_trend(
        self,
        *,
        branch_id: str,
        target_key: str | None = None,
    ) -> BranchYieldTrend:
        """Compare recent/previous execution windows.

        This is diagnostic only. It never closes a branch.
        """

        query = YieldQuery(
            target_key=target_key,
            branch_id=branch_id,
            newest_first=True,
            limit=(
                self._config.trend_window_executions
                * 2
            ),
        )

        observations = tuple(
            await self._store.query(
                query
            )
        )

        window = (
            self._config.trend_window_executions
        )

        recent = observations[
            :window
        ]

        previous = observations[
            window:
            window * 2
        ]

        recent_metrics = (
            marginal_window_metrics(
                recent
            )
        )

        previous_metrics = (
            marginal_window_metrics(
                previous
            )
        )

        recent_yield = (
            recent_metrics[
                "assets_per_execution"
            ]
            + recent_metrics[
                "novel_assets_per_execution"
            ]
        )

        previous_yield = (
            previous_metrics[
                "assets_per_execution"
            ]
            + previous_metrics[
                "novel_assets_per_execution"
            ]
        )

        delta = (
            recent_yield
            - previous_yield
        )

        enough_recent = (
            len(recent)
            >= self._config.trend_min_recent_executions
        )

        low_hit = (
            recent_metrics[
                "hit_rate"
            ]
            <= self._config.low_hit_rate_threshold
        )

        low_assets = (
            recent_metrics[
                "assets_per_execution"
            ]
            <= (
                self._config.low_assets_per_execution_threshold
            )
        )

        low_novel = (
            recent_metrics[
                "novel_assets_per_execution"
            ]
            <= (
                self._config.low_novel_assets_per_execution_threshold
            )
        )

        not_improving = (
            not previous
            or delta <= 0.0
        )

        low_marginal = bool(
            enough_recent
            and low_hit
            and low_assets
            and low_novel
            and not_improving
        )

        if not enough_recent:
            convergence_signal = 0.0
            reason = (
                "insufficient recent execution history"
            )

        else:
            hit_pressure = (
                1.0
                - min(
                    1.0,
                    recent_metrics[
                        "hit_rate"
                    ]
                    / max(
                        self._config.low_hit_rate_threshold,
                        1e-9,
                    ),
                )
            )

            asset_pressure = (
                1.0
                - min(
                    1.0,
                    recent_metrics[
                        "assets_per_execution"
                    ]
                    / max(
                        self._config.low_assets_per_execution_threshold,
                        1e-9,
                    ),
                )
            )

            novel_pressure = (
                1.0
                - min(
                    1.0,
                    recent_metrics[
                        "novel_assets_per_execution"
                    ]
                    / max(
                        self._config.low_novel_assets_per_execution_threshold,
                        1e-9,
                    ),
                )
            )

            decline_pressure = (
                clamp01(
                    -delta
                    / max(
                        abs(
                            previous_yield
                        ),
                        1.0,
                    )
                )
                if previous
                else 0.0
            )

            convergence_signal = (
                hit_pressure
                * 0.35
                + asset_pressure
                * 0.30
                + novel_pressure
                * 0.25
                + decline_pressure
                * 0.10
            )

            if low_marginal:
                reason = (
                    "recent branch executions show low hit rate, low new "
                    "asset yield, low novelty, and no improvement"
                )
            else:
                reason = (
                    "branch still has productive or insufficiently converged "
                    "recent yield"
                )

        return BranchYieldTrend(
            target_key=target_key,
            branch_id=branch_id,
            recent_executions=len(
                recent
            ),
            previous_executions=len(
                previous
            ),
            recent_hit_rate=(
                recent_metrics[
                    "hit_rate"
                ]
            ),
            previous_hit_rate=(
                previous_metrics[
                    "hit_rate"
                ]
            ),
            recent_assets_per_execution=(
                recent_metrics[
                    "assets_per_execution"
                ]
            ),
            previous_assets_per_execution=(
                previous_metrics[
                    "assets_per_execution"
                ]
            ),
            recent_novel_assets_per_execution=(
                recent_metrics[
                    "novel_assets_per_execution"
                ]
            ),
            previous_novel_assets_per_execution=(
                previous_metrics[
                    "novel_assets_per_execution"
                ]
            ),
            marginal_yield_delta=(
                delta
            ),
            convergence_signal=(
                clamp01(
                    convergence_signal
                )
            ),
            low_marginal_yield=(
                low_marginal
            ),
            reason=reason,
        )


class YieldSchedulingSignalProvider:
    """Scheduler adapter backed by YieldModel."""

    def __init__(
        self,
        *,
        model: YieldModel,
        events: YieldEventProvider,
    ) -> None:
        self._model = model
        self._events = events

    async def signals_for(
        self,
        task: Task,
    ) -> SchedulingSignals:
        event = await self._events.get_event(
            task.input_event_id
        )

        estimate = await self._model.task_estimate(
            task,
            input_event=event,
        )

        return SchedulingSignals(
            confidence=(
                event.confidence
                if event is not None
                else 0.5
            ),
            novelty=(
                event.novelty
                if event is not None
                else 0.5
            ),
            expected_yield=(
                estimate.expected_yield
            ),
            information_gain=(
                estimate.information_gain
            ),
            estimated_cost=(
                estimate.estimated_cost
            ),
        )


class WordlistYieldFeedbackAdapter:
    """Adapt raw yield history to wordlists.YieldFeedbackProvider."""

    def __init__(
        self,
        store: YieldStore,
    ) -> None:
        self._store = store

    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[
        YieldFeedback
    ]:
        target_key = target_key_for_event(
            seed_event
        )

        observations = await self._store.query(
            YieldQuery(
                target_key=target_key,
            )
        )

        attempts: Counter[
            tuple[
                CorpusCategory,
                str,
            ]
        ] = Counter()

        hits: Counter[
            tuple[
                CorpusCategory,
                str,
            ]
        ] = Counter()

        sources: dict[
            tuple[
                CorpusCategory,
                str,
            ],
            set[str],
        ] = defaultdict(set)

        observation_ids: dict[
            tuple[
                CorpusCategory,
                str,
            ],
            list[str],
        ] = defaultdict(list)

        for observation in observations:
            for credit in observation.token_credits:
                normalized = normalize_token_for_category(
                    credit.token,
                    category=credit.category,
                )

                if normalized is None:
                    continue

                key = (
                    credit.category,
                    canonical_token_key(
                        normalized,
                        category=credit.category,
                    ),
                )

                attempts[
                    key
                ] += (
                    credit.attempted_hypotheses
                )

                hits[
                    key
                ] += (
                    credit.successful_hits
                )

                sources[
                    key
                ].update(
                    credit.source_ids
                )

                if (
                    len(
                        observation_ids[
                            key
                        ]
                    )
                    < 64
                ):
                    observation_ids[
                        key
                    ].append(
                        observation.observation_id
                    )

        result: list[
            YieldFeedback
        ] = []

        for (
            category,
            canonical_token,
        ) in sorted(
            attempts,
            key=lambda item: (
                item[0].value,
                item[1],
            ),
        ):
            result.append(
                YieldFeedback(
                    token=canonical_token,
                    category=category,
                    attempted_hypotheses=(
                        attempts[
                            (
                                category,
                                canonical_token,
                            )
                        ]
                    ),
                    successful_hits=(
                        hits[
                            (
                                category,
                                canonical_token,
                            )
                        ]
                    ),
                    metadata={
                        "source_ids": sorted(
                            sources[
                                (
                                    category,
                                    canonical_token,
                                )
                            ]
                        ),
                        "yield_observation_ids": (
                            observation_ids[
                                (
                                    category,
                                    canonical_token,
                                )
                            ]
                        ),
                        "target_key": target_key,
                    },
                )
            )

        return tuple(result)


class PatternYieldFeedbackAdapter:
    """Adapt raw yield history to patterns.PatternFeedbackProvider."""

    def __init__(
        self,
        store: YieldStore,
    ) -> None:
        self._store = store

    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[
        PatternFeedback
    ]:
        target_key = target_key_for_event(
            seed_event
        )

        observations = await self._store.query(
            YieldQuery(
                target_key=target_key,
            )
        )

        attempts: Counter[str] = Counter()
        hits: Counter[str] = Counter()

        observation_ids: dict[
            str,
            list[str],
        ] = defaultdict(list)

        for observation in observations:
            for credit in observation.pattern_credits:
                attempts[
                    credit.pattern_id
                ] += (
                    credit.attempted_hypotheses
                )

                hits[
                    credit.pattern_id
                ] += (
                    credit.successful_hits
                )

                if (
                    len(
                        observation_ids[
                            credit.pattern_id
                        ]
                    )
                    < 64
                ):
                    observation_ids[
                        credit.pattern_id
                    ].append(
                        observation.observation_id
                    )

        return tuple(
            PatternFeedback(
                pattern_id=pattern_id,
                attempted_hypotheses=(
                    attempts[
                        pattern_id
                    ]
                ),
                successful_hits=(
                    hits[
                        pattern_id
                    ]
                ),
                metadata={
                    "yield_observation_ids": (
                        observation_ids[
                            pattern_id
                        ]
                    ),
                    "target_key": target_key,
                },
            )
            for pattern_id
            in sorted(
                attempts
            )
        )


def yield_observation_from_task(
    task: Task,
    *,
    input_event: Event | None,
    execution_outcome: YieldExecutionOutcome,
    attempted_units: int = 1,
    successful_hits: int = 0,
    new_assets: int = 0,
    novel_assets: int = 0,
    new_domains: int = 0,
    new_urls: int = 0,
    new_endpoints: int = 0,
    new_vocabulary_tokens: int = 0,
    new_patterns: int = 0,
    request_count: float = 0.0,
    runtime_seconds: float = 0.0,
    cost_units: float = 1.0,
    source_ids: Sequence[str] = (),
    token_credits: Sequence[TokenYieldCredit] = (),
    pattern_credits: Sequence[PatternYieldCredit] = (),
    run_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> YieldObservation:
    """Build a normalized observation from an executed Task.

    The caller supplies discovery deltas after storage/dedupe so `new_assets`
    means genuinely new canonical assets rather than raw tool output lines.
    """

    return YieldObservation(
        run_id=run_id,
        task_id=task.task_id,
        input_event_id=task.input_event_id,
        target_key=(
            target_key_for_event(
                input_event
            )
            if input_event is not None
            else None
        ),
        branch_id=task.branch_id,
        worker=task.worker,
        action=task.action,
        route_rule_id=task.route_rule_id,
        input_source=(
            input_event.source
            if input_event is not None
            else None
        ),
        source_ids=frozenset(
            source_ids
        ),
        execution_outcome=(
            execution_outcome
        ),
        attempted_units=(
            attempted_units
        ),
        successful_hits=(
            successful_hits
        ),
        new_assets=new_assets,
        novel_assets=novel_assets,
        new_domains=new_domains,
        new_urls=new_urls,
        new_endpoints=new_endpoints,
        new_vocabulary_tokens=(
            new_vocabulary_tokens
        ),
        new_patterns=new_patterns,
        request_count=request_count,
        runtime_seconds=(
            runtime_seconds
        ),
        cost_units=cost_units,
        token_credits=tuple(
            token_credits
        ),
        pattern_credits=tuple(
            pattern_credits
        ),
        metadata=(
            dict(
                metadata
                or {}
            )
        ),
    )


def target_key_for_event(
    event: Event,
) -> str | None:
    """Return conservative target identity used for yield isolation.

    Explicit metadata wins. Without it, host-level context is preferred over
    guessing a registrable organizational root.
    """

    for key in (
        "target_key",
        "seed_domain",
    ):
        raw = event.metadata.get(
            key
        )

        if isinstance(
            raw,
            str,
        ):
            normalized = (
                raw.strip()
                .lower()
            )

            if normalized:
                return normalized

    inferred = infer_seed_domain(
        event
    )

    return (
        inferred.lower()
        if inferred is not None
        else None
    )


def observation_matches_query(
    observation: YieldObservation,
    query: YieldQuery,
) -> bool:
    if (
        query.target_key is not None
        and observation.target_key
        != query.target_key
    ):
        return False

    if (
        query.branch_id is not None
        and observation.branch_id
        != query.branch_id
    ):
        return False

    if (
        query.worker is not None
        and observation.worker
        != query.worker
    ):
        return False

    if (
        query.action is not None
        and observation.action
        != query.action
    ):
        return False

    if (
        query.route_rule_id is not None
        and observation.route_rule_id
        != query.route_rule_id
    ):
        return False

    if (
        query.input_source is not None
        and observation.input_source
        != query.input_source
    ):
        return False

    if (
        query.source_id is not None
        and query.source_id
        not in observation.source_ids
    ):
        return False

    if (
        query.since is not None
        and observation.observed_at
        < query.since
    ):
        return False

    if (
        query.until is not None
        and observation.observed_at
        > query.until
    ):
        return False

    if query.token is not None:
        assert (
            query.token_category
            is not None
        )

        expected_key = canonical_token_key(
            query.token,
            category=query.token_category,
        )

        found = False

        for credit in observation.token_credits:
            if (
                credit.category
                is not query.token_category
            ):
                continue

            credit_key = canonical_token_key(
                credit.token,
                category=credit.category,
            )

            if credit_key == expected_key:
                found = True
                break

        if not found:
            return False

    if (
        query.pattern_id is not None
        and not any(
            credit.pattern_id
            == query.pattern_id
            for credit
            in observation.pattern_credits
        )
    ):
        return False

    return True


def aggregate_observations_for_query(
    observations: Sequence[
        YieldObservation
    ],
    *,
    query: YieldQuery,
) -> YieldAggregate:
    """Aggregate observations with exact token/pattern credit semantics.

    General worker/source/branch queries use full task-level metrics. A token
    or pattern query instead uses its explicit credit counts and apportions
    shared request/runtime/cost by the fraction of attempted units attributed
    to that credit. This prevents one word in a 1,000-candidate batch from
    inheriting the whole batch as its own history.
    """

    if query.token is None and query.pattern_id is None:
        return aggregate_observations(
            observations
        )

    if not observations:
        return YieldAggregate()

    attempted_units = 0
    successful_hits = 0
    new_assets = 0
    novel_assets = 0

    request_count = 0.0
    runtime_seconds = 0.0
    cost_units = 0.0

    timestamps: list[datetime] = []
    outcome_counts: Counter[YieldExecutionOutcome] = Counter()

    for observation in observations:
        matching_attempts = 0
        matching_hits = 0
        matching_new_assets = 0
        matching_novel_assets = 0

        if query.token is not None:
            assert query.token_category is not None

            expected_key = canonical_token_key(
                query.token,
                category=query.token_category,
            )

            for credit in observation.token_credits:
                if credit.category is not query.token_category:
                    continue

                if canonical_token_key(
                    credit.token,
                    category=credit.category,
                ) != expected_key:
                    continue

                matching_attempts += credit.attempted_hypotheses
                matching_hits += credit.successful_hits
                matching_new_assets += credit.new_assets
                matching_novel_assets += credit.novel_assets

        elif query.pattern_id is not None:
            for credit in observation.pattern_credits:
                if credit.pattern_id != query.pattern_id:
                    continue

                matching_attempts += credit.attempted_hypotheses
                matching_hits += credit.successful_hits
                matching_new_assets += credit.new_assets
                matching_novel_assets += credit.novel_assets

        if matching_attempts <= 0 and matching_hits <= 0:
            continue

        attempted_units += matching_attempts
        successful_hits += matching_hits
        new_assets += matching_new_assets
        novel_assets += matching_novel_assets

        denominator = max(
            1,
            observation.attempted_units,
        )

        fraction = min(
            1.0,
            matching_attempts
            / denominator,
        )

        request_count += observation.request_count * fraction
        runtime_seconds += observation.runtime_seconds * fraction
        cost_units += observation.cost_units * fraction

        timestamps.append(
            observation.observed_at
        )

        outcome_counts[
            observation.execution_outcome
        ] += 1

    if not timestamps:
        return YieldAggregate()

    executions = len(
        timestamps
    )

    return YieldAggregate(
        observations=executions,
        executions=executions,
        execution_succeeded=(
            outcome_counts[
                YieldExecutionOutcome.SUCCEEDED
            ]
        ),
        execution_retry=(
            outcome_counts[
                YieldExecutionOutcome.RETRY
            ]
        ),
        execution_failed=(
            outcome_counts[
                YieldExecutionOutcome.FAILED
            ]
        ),
        attempted_units=attempted_units,
        successful_hits=successful_hits,
        new_assets=new_assets,
        novel_assets=novel_assets,
        request_count=request_count,
        runtime_seconds=runtime_seconds,
        cost_units=cost_units,
        first_observed_at=min(
            timestamps
        ),
        last_observed_at=max(
            timestamps
        ),
    )


def aggregate_observations(
    observations: Sequence[
        YieldObservation
    ],
) -> YieldAggregate:
    if not observations:
        return YieldAggregate()

    outcome_counts = Counter(
        observation.execution_outcome
        for observation
        in observations
    )

    timestamps = [
        observation.observed_at
        for observation
        in observations
    ]

    return YieldAggregate(
        observations=len(
            observations
        ),
        executions=len(
            observations
        ),
        execution_succeeded=(
            outcome_counts[
                YieldExecutionOutcome.SUCCEEDED
            ]
        ),
        execution_retry=(
            outcome_counts[
                YieldExecutionOutcome.RETRY
            ]
        ),
        execution_failed=(
            outcome_counts[
                YieldExecutionOutcome.FAILED
            ]
        ),
        attempted_units=sum(
            observation.attempted_units
            for observation
            in observations
        ),
        successful_hits=sum(
            observation.successful_hits
            for observation
            in observations
        ),
        new_assets=sum(
            observation.new_assets
            for observation
            in observations
        ),
        novel_assets=sum(
            observation.novel_assets
            for observation
            in observations
        ),
        new_domains=sum(
            observation.new_domains
            for observation
            in observations
        ),
        new_urls=sum(
            observation.new_urls
            for observation
            in observations
        ),
        new_endpoints=sum(
            observation.new_endpoints
            for observation
            in observations
        ),
        new_vocabulary_tokens=sum(
            observation.new_vocabulary_tokens
            for observation
            in observations
        ),
        new_patterns=sum(
            observation.new_patterns
            for observation
            in observations
        ),
        request_count=sum(
            observation.request_count
            for observation
            in observations
        ),
        runtime_seconds=sum(
            observation.runtime_seconds
            for observation
            in observations
        ),
        cost_units=sum(
            observation.cost_units
            for observation
            in observations
        ),
        first_observed_at=min(
            timestamps
        ),
        last_observed_at=max(
            timestamps
        ),
    )


def estimate_from_aggregate(
    query: YieldQuery,
    aggregate: YieldAggregate,
    *,
    config: YieldModelConfig,
) -> YieldEstimate:
    """Convert sufficient statistics into normalized scheduler intelligence."""

    posterior_hit = beta_posterior_mean(
        successes=(
            aggregate.successful_hits
        ),
        failures=max(
            0,
            aggregate.attempted_units
            - aggregate.successful_hits,
        ),
        alpha=config.hit_prior_alpha,
        beta=config.hit_prior_beta,
    )

    if aggregate.attempted_units > 0:
        discoveries_per_attempt = (
            aggregate.new_assets
            / aggregate.attempted_units
        )
    else:
        discoveries_per_attempt = 0.0

    discovery_score = (
        1.0
        - math.exp(
            -discoveries_per_attempt
            / config.discovery_saturation_per_attempt
        )
    )

    novelty_score = beta_posterior_mean(
        successes=(
            aggregate.novel_assets
        ),
        failures=max(
            0,
            aggregate.new_assets
            - aggregate.novel_assets,
        ),
        alpha=(
            config.novelty_prior_alpha
        ),
        beta=(
            config.novelty_prior_beta
        ),
    )

    execution_reliability = (
        beta_posterior_mean(
            successes=(
                aggregate.execution_succeeded
            ),
            failures=(
                aggregate.execution_retry
                + aggregate.execution_failed
            ),
            alpha=(
                config.execution_prior_alpha
            ),
            beta=(
                config.execution_prior_beta
            ),
        )
    )

    total_weight = (
        config.hit_weight
        + config.discovery_weight
        + config.novelty_weight
        + config.reliability_weight
    )

    expected_yield = (
        posterior_hit
        * config.hit_weight
        + discovery_score
        * config.discovery_weight
        + novelty_score
        * config.novelty_weight
        + execution_reliability
        * config.reliability_weight
    ) / total_weight

    sample_size = float(
        max(
            aggregate.attempted_units,
            aggregate.executions,
        )
    )

    # Sparse contexts are intentionally uncertain. This creates scheduler
    # information gain rather than permanently deprioritizing unexplored lanes.
    uncertainty = (
        1.0
        / math.sqrt(
            sample_size
            + 1.0
        )
    )

    estimated_cost = (
        aggregate.mean_cost_units
        if aggregate.mean_cost_units
        is not None
        else config.default_cost_units
    )

    return YieldEstimate(
        query=query,
        aggregate=aggregate,
        posterior_hit_rate=(
            clamp01(
                posterior_hit
            )
        ),
        discovery_score=(
            clamp01(
                discovery_score
            )
        ),
        novelty_score=(
            clamp01(
                novelty_score
            )
        ),
        execution_reliability=(
            clamp01(
                execution_reliability
            )
        ),
        expected_yield=(
            clamp01(
                expected_yield
            )
        ),
        uncertainty=(
            clamp01(
                uncertainty
            )
        ),
        estimated_cost=max(
            float(
                estimated_cost
            ),
            1e-9,
        ),
        effective_sample_size=(
            sample_size
        ),
    )


def beta_posterior_mean(
    *,
    successes: int | float,
    failures: int | float,
    alpha: float,
    beta: float,
) -> float:
    denominator = (
        successes
        + failures
        + alpha
        + beta
    )

    if denominator <= 0.0:
        raise ValueError(
            "invalid Beta posterior denominator"
        )

    return (
        successes
        + alpha
    ) / denominator


def component_reliability(
    aggregate: YieldAggregate,
    *,
    half_life: float,
) -> float:
    """Smoothly raise context weight as evidence accumulates."""

    evidence = float(
        max(
            aggregate.attempted_units,
            aggregate.executions,
        )
    )

    if evidence <= 0.0:
        return 0.0

    return (
        evidence
        / (
            evidence
            + half_life
        )
    )


def normalized_disagreement(
    values: Sequence[float],
) -> float:
    """Map component dispersion into [0,1]."""

    if len(values) < 2:
        return 0.0

    # Values lie in [0,1]. Population standard deviation cannot exceed 0.5.
    return clamp01(
        pstdev(
            values
        )
        / 0.5
    )


def marginal_window_metrics(
    observations: Sequence[
        YieldObservation
    ],
) -> dict[str, float]:
    if not observations:
        return {
            "hit_rate": 0.0,
            "assets_per_execution": 0.0,
            "novel_assets_per_execution": 0.0,
        }

    attempted = sum(
        observation.attempted_units
        for observation
        in observations
    )

    hits = sum(
        observation.successful_hits
        for observation
        in observations
    )

    executions = len(
        observations
    )

    assets = sum(
        observation.new_assets
        for observation
        in observations
    )

    novel = sum(
        observation.novel_assets
        for observation
        in observations
    )

    return {
        "hit_rate": (
            hits / attempted
            if attempted > 0
            else 0.0
        ),
        "assets_per_execution": (
            assets / executions
        ),
        "novel_assets_per_execution": (
            novel / executions
        ),
    }


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