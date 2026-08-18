"""Bounded DNS permutation generation for Night Scout.

This worker turns vocabulary into hypotheses, not network traffic.

It never resolves a candidate. Every generated hostname is published as a
DNS_NAME Event with scope=UNKNOWN and must pass the normal scope/policy/rate
pipeline before workers/dns.py may query it.

The most important design rule is that Target Genome is NOT the only source of
candidates. Generation is split into two independently budgeted task actions:

    generate_targeted
        Target-specific vocabulary and learned naming patterns.

    generate_exploration
        Global-corpus words that have not yet been seen on this target.

`PermutationBudgetPlanner` maps the second action to
BudgetLane.EXPLORATION. That means the exploration reserve implemented in
core/budgets.py is real, not just a comment inside this worker: productive
Target Genome branches cannot consume all of the long-tail discovery budget.

An exploration cursor rotates through the global corpus so repeated runs do
not always retry the same first N popular words. The in-memory cursor here is
for tests/bootstrap; a later intelligence/wordlists.py storage adapter should
persist the same protocol across restarts.

Generation methods
------------------
For a ROOT_DOMAIN:
    word.example.com
    word1-word2.example.com      (bounded top-target-word pairwise)

For a confirmed DNS_NAME:
    word.api.example.com         (nested child)
    word-api.example.com         (sibling prefix mutation)
    api-word.example.com         (sibling suffix mutation)

Future intelligence/patterns.py can inject explicit learned hostname
hypotheses without coupling this worker to the pattern engine.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
from collections.abc import Sequence
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.budgets import BudgetContext, BudgetDemand, BudgetLane
from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import (
    BudgetPlan,
    WorkerExecutionResult,
    WorkerOutcome,
)
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule
from recon.core.scheduler import ScheduleDecision
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "permutations"

ACTION_GENERATE_TARGETED = "generate_targeted"
ACTION_GENERATE_EXPLORATION = "generate_exploration"

_LABEL_SANITIZE_RE = re.compile(r"[^a-z0-9-]+")
_SEPARATOR_RE = re.compile(r"[_\s]+")
_HYPHEN_RE = re.compile(r"-+")


class CandidateLane(StrEnum):
    """Independent candidate-budget lanes."""

    TARGETED = "TARGETED"
    EXPLORATION = "EXPLORATION"


class CandidateTier(StrEnum):
    """Operational wordlist/candidate size tier."""

    MICRO = "MICRO"
    SMALL = "SMALL"
    MEDIUM = "MEDIUM"
    LARGE = "LARGE"
    EXHAUSTIVE = "EXHAUSTIVE"


DEFAULT_TIER_LIMITS: dict[CandidateTier, int] = {
    CandidateTier.MICRO: 250,
    CandidateTier.SMALL: 2_000,
    CandidateTier.MEDIUM: 10_000,
    CandidateTier.LARGE: 50_000,
    CandidateTier.EXHAUSTIVE: 250_000,
}


class PermutationMethod(StrEnum):
    """Explainable candidate-generation methods."""

    DIRECT_CHILD = "DIRECT_CHILD"
    NESTED_CHILD = "NESTED_CHILD"

    PREFIX_LEFT_LABEL = "PREFIX_LEFT_LABEL"
    SUFFIX_LEFT_LABEL = "SUFFIX_LEFT_LABEL"

    PAIRWISE_HYPHEN = "PAIRWISE_HYPHEN"
    LEARNED_PATTERN = "LEARNED_PATTERN"


class PermutationWord(BaseModel):
    """One deduplicated word with global and target-specific provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str

    global_sources: frozenset[str] = Field(default_factory=frozenset)
    target_sources: frozenset[str] = Field(default_factory=frozenset)

    global_score: float = Field(default=0.0, ge=0.0)
    global_rank: int | None = Field(default=None, ge=1)

    target_frequency: int = Field(default=0, ge=0)
    target_source_diversity: int = Field(default=0, ge=0)
    target_relevance: float = Field(default=0.0, ge=0.0)

    successful_hits: int = Field(default=0, ge=0)
    attempted_hypotheses: int = Field(default=0, ge=0)

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    # Explicit DNS-safe variants may be supplied by the future vocabulary
    # engine. If omitted, this worker creates at most two conservative variants.
    labels: tuple[str, ...] = ()

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("token")
    @classmethod
    def token_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("word token must not be blank")
        return normalized

    @field_validator("global_sources", "target_sources")
    @classmethod
    def normalize_sources(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )

    @field_validator("labels")
    @classmethod
    def normalize_labels(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        result: list[str] = []

        for value in values:
            label = normalize_candidate_label(value)
            if label is not None and label not in result:
                result.append(label)

        return tuple(result)

    @property
    def lane(self) -> CandidateLane:
        """A word is targeted only when the current target supplied evidence."""
        if (
            self.target_frequency > 0
            or self.target_source_diversity > 0
            or self.target_relevance > 0.0
            or bool(self.target_sources)
        ):
            return CandidateLane.TARGETED

        return CandidateLane.EXPLORATION

    @property
    def yield_ratio(self) -> float:
        if self.attempted_hypotheses <= 0:
            return 0.0

        return self.successful_hits / self.attempted_hypotheses

    @property
    def ranking_score(self) -> float:
        """Explainable discovery-priority score, not vulnerability severity."""
        rank_bonus = (
            1.0 / math.log2(self.global_rank + 1)
            if self.global_rank is not None
            else 0.0
        )

        return (
            self.target_relevance * 4.0
            + math.log1p(self.target_frequency) * 1.5
            + self.target_source_diversity * 1.0
            + len(self.target_sources) * 0.5
            + self.yield_ratio * 3.0
            + self.global_score
            + rank_bonus
            + self.confidence * 0.25
        )

    def label_variants(self) -> tuple[str, ...]:
        if self.labels:
            return self.labels

        return token_to_candidate_labels(self.token)


class LearnedHostnameHypothesis(BaseModel):
    """Explicit target pattern hypothesis from future patterns.py."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str

    score: float = 0.0
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    source_event_ids: tuple[str, ...] = ()
    source_pattern: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @field_validator("source_event_ids")
    @classmethod
    def normalize_event_ids(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    value.strip()
                    for value in values
                    if value.strip()
                }
            )
        )

    @field_validator("source_pattern")
    @classmethod
    def normalize_pattern(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.strip() or None


class PermutationCandidate(BaseModel):
    """One generated hostname hypothesis before Event publication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str

    lane: CandidateLane
    method: PermutationMethod

    score: float
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    word_tokens: tuple[str, ...] = ()

    source_event_ids: tuple[str, ...] = ()
    source_pattern: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)


class WordCorpusProvider(Protocol):
    """Boundary implemented later by intelligence/wordlists.py."""

    async def words_for(
        self,
        seed_event: Event,
    ) -> Sequence[PermutationWord]:
        """Return global + target-aware deduplicated corpus entries."""
        ...


class LearnedHypothesisProvider(Protocol):
    """Boundary implemented later by intelligence/patterns.py."""

    async def hypotheses_for(
        self,
        seed_event: Event,
    ) -> Sequence[LearnedHostnameHypothesis]:
        ...


class ExplorationCursorStore(Protocol):
    """Rotate through long-tail exploration words."""

    async def claim_window(
        self,
        *,
        namespace: str,
        pool_size: int,
        window_size: int,
    ) -> tuple[int, ...]:
        ...


class InputEventProvider(Protocol):
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class StaticWordCorpus:
    """Deterministic provider for tests/bootstrap."""

    def __init__(
        self,
        words: Sequence[PermutationWord],
    ) -> None:
        self._words = tuple(words)

    async def words_for(
        self,
        seed_event: Event,
    ) -> Sequence[PermutationWord]:
        del seed_event
        return self._words


class NoLearnedHypotheses:
    """Placeholder until intelligence/patterns.py exists."""

    async def hypotheses_for(
        self,
        seed_event: Event,
    ) -> Sequence[LearnedHostnameHypothesis]:
        del seed_event
        return ()


class InMemoryExplorationCursorStore:
    """Concurrency-safe rotating cursor.

    A persistent implementation should later store the same namespace/offset
    state in SQLite so long-tail progress survives restart.
    """

    def __init__(self) -> None:
        self._offsets: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def claim_window(
        self,
        *,
        namespace: str,
        pool_size: int,
        window_size: int,
    ) -> tuple[int, ...]:
        if pool_size < 0:
            raise ValueError("pool_size cannot be negative")
        if window_size < 0:
            raise ValueError("window_size cannot be negative")

        if pool_size == 0 or window_size == 0:
            return ()

        count = min(pool_size, window_size)

        async with self._lock:
            start = self._offsets.get(namespace, 0) % pool_size

            indexes = tuple(
                (start + offset) % pool_size
                for offset in range(count)
            )

            self._offsets[namespace] = (
                start + count
            ) % pool_size

            return indexes


class PermutationsConfig(BaseModel):
    """Bounded generation configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: CandidateTier = CandidateTier.SMALL

    # Optional explicit override of the selected tier.
    max_candidates: int | None = Field(default=None, ge=1)

    # This is a protected minimum share, not a relevance score.
    exploration_fraction: float = Field(
        default=0.20,
        gt=0.0,
        lt=1.0,
    )
    minimum_exploration_candidates: int = Field(
        default=25,
        ge=1,
    )

    pairwise_top_words: int = Field(
        default=24,
        ge=0,
        le=500,
    )
    pairwise_enabled: bool = True

    nested_children: bool = True
    sibling_mutations: bool = True

    candidate_confidence_floor: float = Field(
        default=0.25,
        ge=0.0,
        le=1.0,
    )
    candidate_confidence_ceiling: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
    )

    @model_validator(mode="after")
    def validate_bounds(self) -> PermutationsConfig:
        if (
            self.candidate_confidence_floor
            > self.candidate_confidence_ceiling
        ):
            raise ValueError(
                "candidate_confidence_floor cannot exceed ceiling"
            )

        return self

    @property
    def effective_max_candidates(self) -> int:
        return (
            self.max_candidates
            if self.max_candidates is not None
            else DEFAULT_TIER_LIMITS[self.tier]
        )

    @property
    def exploration_candidate_limit(self) -> int:
        total = self.effective_max_candidates

        reserved = max(
            self.minimum_exploration_candidates,
            math.ceil(total * self.exploration_fraction),
        )

        # For tiny explicitly-overridden batches, exploration still gets a
        # non-zero slot.
        return min(reserved, total)

    @property
    def targeted_candidate_limit(self) -> int:
        return max(
            self.effective_max_candidates
            - self.exploration_candidate_limit,
            0,
        )


class PermutationBudgetPlanner:
    """Map permutation task actions onto BudgetManager lanes.

    This is the key integration that protects long-tail exploration from
    Target Genome budget starvation.
    """

    def __init__(
        self,
        config: PermutationsConfig | None = None,
    ) -> None:
        self._config = config or PermutationsConfig()

    async def plan(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> BudgetPlan:
        if task.worker != WORKER_NAME:
            raise ValueError(
                "PermutationBudgetPlanner received a non-permutations task"
            )

        if task.action == ACTION_GENERATE_TARGETED:
            candidate_limit = (
                self._config.targeted_candidate_limit
            )
            lane = BudgetLane.NORMAL

        elif task.action == ACTION_GENERATE_EXPLORATION:
            candidate_limit = (
                self._config.exploration_candidate_limit
            )
            lane = BudgetLane.EXPLORATION

        else:
            raise ValueError(
                f"unknown permutations action: {task.action}"
            )

        return BudgetPlan(
            demand=BudgetDemand(
                tasks=1.0,
                cost=schedule.signals.estimated_cost,
                candidates=float(candidate_limit),
                # Pure local generation: no network request/concurrency demand.
                requests=0.0,
                concurrent_tasks=1.0,
            ),
            context=BudgetContext(
                lane=lane,
            ),
        )


class PermutationsWorker:
    """Generate targeted or exploration DNS hypotheses."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        words: WordCorpusProvider,
        exploration_cursors: ExplorationCursorStore,
        learned: LearnedHypothesisProvider | None = None,
        config: PermutationsConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._words = words
        self._exploration_cursors = exploration_cursors
        self._learned = learned or NoLearnedHypotheses()
        self._config = config or PermutationsConfig()

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "permutations worker may only execute claimed RUNNING "
                    f"tasks, got {task.status.value}"
                ),
            )

        if task.worker != self.name:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    f"task worker mismatch: expected {self.name}, "
                    f"got {task.worker}"
                ),
            )

        lane = _lane_for_action(task.action)
        if lane is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "unsupported permutations action: "
                    f"{task.action}"
                ),
            )

        seed_event = await self._events.get_event(
            task.input_event_id
        )
        if seed_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        if seed_event.type not in {
            EventType.ROOT_DOMAIN,
            EventType.DNS_NAME,
        }:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "permutations requires ROOT_DOMAIN or DNS_NAME input, "
                    f"got {seed_event.type.value}"
                ),
            )

        try:
            seed = normalize_dns_name(seed_event.value)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"invalid seed domain: {exc}",
            )

        corpus = await self._words.words_for(seed_event)

        if lane is CandidateLane.TARGETED:
            learned = await self._learned.hypotheses_for(
                seed_event
            )
        else:
            learned = ()

        candidates = await self.generate_candidates(
            seed_event=seed_event,
            seed=seed,
            corpus=corpus,
            learned=learned,
            lane=lane,
        )

        for candidate in candidates:
            event = Event(
                type=EventType.DNS_NAME,
                value=candidate.hostname,
                source=(
                    f"permutations:{candidate.method.value.lower()}:"
                    f"{candidate.lane.value.lower()}"
                ),
                parent_event_id=seed_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=candidate.confidence,
                novelty=_candidate_novelty(candidate),
                depth=seed_event.depth + 1,
                tags={
                    "permutation",
                    "hypothesis",
                    "dns-candidate",
                    f"lane:{candidate.lane.value.lower()}",
                    f"tier:{self._config.tier.value.lower()}",
                    f"method:{candidate.method.value.lower()}",
                },
                metadata={
                    "hypothesis": True,
                    "requires_dns_confirmation": True,
                    "candidate_lane": candidate.lane.value,
                    "candidate_tier": self._config.tier.value,
                    "generation_method": candidate.method.value,
                    "generation_score": candidate.score,
                    "word_tokens": list(candidate.word_tokens),
                    "source_event_ids": list(
                        candidate.source_event_ids
                    ),
                    "source_pattern": candidate.source_pattern,
                    "seed_domain": seed,
                    **candidate.metadata,
                },
            )

            await self._publisher.publish(event)

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def generate_candidates(
        self,
        *,
        seed_event: Event,
        seed: str,
        corpus: Sequence[PermutationWord],
        learned: Sequence[LearnedHostnameHypothesis],
        lane: CandidateLane,
    ) -> tuple[PermutationCandidate, ...]:
        """Generate one independently-budgeted lane."""
        words = _dedupe_words(corpus)

        if lane is CandidateLane.TARGETED:
            targeted_words = sorted(
                (
                    word
                    for word in words
                    if word.lane is CandidateLane.TARGETED
                ),
                key=_targeted_word_sort_key,
            )

            limit = self._config.targeted_candidate_limit

            word_candidates = self._generate_word_candidates(
                seed_event=seed_event,
                seed=seed,
                words=targeted_words,
                lane=CandidateLane.TARGETED,
                limit=limit,
            )

            learned_candidates = self._generate_learned_candidates(
                seed_event=seed_event,
                seed=seed,
                hypotheses=learned,
            )

            return _rank_and_dedupe_candidates(
                (*learned_candidates, *word_candidates)
            )[:limit]

        exploration_words = sorted(
            (
                word
                for word in words
                if word.lane is CandidateLane.EXPLORATION
            ),
            key=_exploration_word_sort_key,
        )

        limit = self._config.exploration_candidate_limit

        if not exploration_words or limit <= 0:
            return ()

        # A word may produce more than one label/mutation, so the cursor window
        # can be smaller than the final candidate limit. We deliberately claim
        # up to `limit` distinct words; unused capacity is simply not invented.
        indexes = await self._exploration_cursors.claim_window(
            namespace=_exploration_namespace(
                seed=seed,
                tier=self._config.tier,
            ),
            pool_size=len(exploration_words),
            window_size=min(
                len(exploration_words),
                limit,
            ),
        )

        rotating_words = [
            exploration_words[index]
            for index in indexes
        ]

        return self._generate_word_candidates(
            seed_event=seed_event,
            seed=seed,
            words=rotating_words,
            lane=CandidateLane.EXPLORATION,
            limit=limit,
        )

    def _generate_word_candidates(
        self,
        *,
        seed_event: Event,
        seed: str,
        words: Sequence[PermutationWord],
        lane: CandidateLane,
        limit: int,
    ) -> tuple[PermutationCandidate, ...]:
        if limit <= 0:
            return ()

        generated: list[PermutationCandidate] = []

        for word in words:
            for label in word.label_variants():
                if len(generated) >= limit:
                    break

                direct = _direct_word_candidate(
                    seed_event=seed_event,
                    seed=seed,
                    word=word,
                    label=label,
                    lane=lane,
                    config=self._config,
                )

                if direct is not None:
                    generated.append(direct)

                if len(generated) >= limit:
                    break

                if (
                    seed_event.type is EventType.DNS_NAME
                    and self._config.sibling_mutations
                ):
                    for sibling in _sibling_candidates(
                        seed=seed,
                        word=word,
                        label=label,
                        lane=lane,
                        config=self._config,
                    ):
                        if len(generated) >= limit:
                            break

                        generated.append(sibling)

            if len(generated) >= limit:
                break

        if (
            seed_event.type is EventType.ROOT_DOMAIN
            and lane is CandidateLane.TARGETED
            and self._config.pairwise_enabled
            and self._config.pairwise_top_words > 1
            and len(generated) < limit
        ):
            generated.extend(
                _pairwise_candidates(
                    seed=seed,
                    words=words[
                        : self._config.pairwise_top_words
                    ],
                    remaining=limit - len(generated),
                    config=self._config,
                )
            )

        return _rank_and_dedupe_candidates(generated)[:limit]

    def _generate_learned_candidates(
        self,
        *,
        seed_event: Event,
        seed: str,
        hypotheses: Sequence[LearnedHostnameHypothesis],
    ) -> tuple[PermutationCandidate, ...]:
        result: list[PermutationCandidate] = []

        for hypothesis in hypotheses:
            if not _candidate_within_seed_branch(
                candidate=hypothesis.hostname,
                seed=seed,
                seed_type=seed_event.type,
            ):
                continue

            result.append(
                PermutationCandidate(
                    hostname=hypothesis.hostname,
                    lane=CandidateLane.TARGETED,
                    method=PermutationMethod.LEARNED_PATTERN,
                    score=hypothesis.score,
                    confidence=_bounded_confidence(
                        hypothesis.confidence,
                        self._config,
                    ),
                    source_event_ids=(
                        hypothesis.source_event_ids
                    ),
                    source_pattern=hypothesis.source_pattern,
                    metadata={
                        "learned_pattern": True,
                        **hypothesis.metadata,
                    },
                )
            )

        return _rank_and_dedupe_candidates(result)


def permutation_route_rules(
    *,
    include_confirmed_dns_seeds: bool = True,
    base_priority: float = 6.0,
) -> tuple[RouteRule, ...]:
    """Return two route tasks per eligible seed: targeted + exploration.

    Unconfirmed permutation hypotheses are never recursively permuted. DNS_NAME
    recursion requires the `confirmed` tag produced by workers/dns.py.
    """
    rules: list[RouteRule] = []

    for lane, action, priority_delta in (
        (
            CandidateLane.TARGETED,
            ACTION_GENERATE_TARGETED,
            0.0,
        ),
        (
            CandidateLane.EXPLORATION,
            ACTION_GENERATE_EXPLORATION,
            -1.0,
        ),
    ):
        rules.append(
            RouteRule(
                rule_id=(
                    f"permutations.root."
                    f"{lane.value.lower()}"
                ),
                accepts=frozenset({EventType.ROOT_DOMAIN}),
                worker=WORKER_NAME,
                action=action,
                reason=(
                    "generate bounded target-specific DNS hypotheses"
                    if lane is CandidateLane.TARGETED
                    else (
                        "generate bounded long-tail global-corpus "
                        "DNS hypotheses"
                    )
                ),
                base_priority=base_priority + priority_delta,
            )
        )

        if include_confirmed_dns_seeds:
            rules.append(
                RouteRule(
                    rule_id=(
                        "permutations.confirmed-dns."
                        f"{lane.value.lower()}"
                    ),
                    accepts=frozenset({EventType.DNS_NAME}),
                    worker=WORKER_NAME,
                    action=action,
                    reason=(
                        "generate bounded hypotheses from a confirmed "
                        "DNS branch"
                    ),
                    base_priority=(
                        base_priority
                        + priority_delta
                        - 0.5
                    ),
                    required_tags=frozenset({"confirmed"}),
                    excluded_tags=frozenset({"hypothesis"}),
                )
            )

    return tuple(rules)


def normalize_candidate_label(
    value: str,
) -> str | None:
    """Convert one vocabulary token into a conservative DNS label."""
    raw = value.strip().lower()
    if not raw:
        return None

    raw = _SEPARATOR_RE.sub("-", raw)
    raw = _LABEL_SANITIZE_RE.sub("-", raw)
    raw = _HYPHEN_RE.sub("-", raw).strip("-")

    if not raw or len(raw) > 63:
        return None

    return raw


def token_to_candidate_labels(
    token: str,
) -> tuple[str, ...]:
    """Return at most two conservative label variants.

    Example:
        internal_api -> ("internal-api", "internalapi")
    """
    primary = normalize_candidate_label(token)
    if primary is None:
        return ()

    variants = [primary]

    collapsed = primary.replace("-", "")
    if (
        collapsed
        and collapsed != primary
        and len(collapsed) <= 63
    ):
        variants.append(collapsed)

    return tuple(variants)


def _lane_for_action(
    action: str,
) -> CandidateLane | None:
    if action == ACTION_GENERATE_TARGETED:
        return CandidateLane.TARGETED

    if action == ACTION_GENERATE_EXPLORATION:
        return CandidateLane.EXPLORATION

    return None


def _dedupe_words(
    words: Sequence[PermutationWord],
) -> tuple[PermutationWord, ...]:
    """Merge duplicate tokens while preserving all source provenance."""
    merged: dict[str, PermutationWord] = {}

    for word in words:
        key = word.token.strip().lower()
        existing = merged.get(key)

        if existing is None:
            merged[key] = word
            continue

        target_sources = (
            existing.target_sources
            | word.target_sources
        )

        labels = tuple(
            dict.fromkeys(
                (*existing.labels, *word.labels)
            )
        )

        merged[key] = PermutationWord(
            token=existing.token,
            global_sources=(
                existing.global_sources
                | word.global_sources
            ),
            target_sources=target_sources,
            global_score=max(
                existing.global_score,
                word.global_score,
            ),
            global_rank=_best_rank(
                existing.global_rank,
                word.global_rank,
            ),
            target_frequency=(
                existing.target_frequency
                + word.target_frequency
            ),
            target_source_diversity=max(
                existing.target_source_diversity,
                word.target_source_diversity,
                len(target_sources),
            ),
            target_relevance=max(
                existing.target_relevance,
                word.target_relevance,
            ),
            successful_hits=(
                existing.successful_hits
                + word.successful_hits
            ),
            attempted_hypotheses=(
                existing.attempted_hypotheses
                + word.attempted_hypotheses
            ),
            confidence=max(
                existing.confidence,
                word.confidence,
            ),
            labels=labels,
            metadata={
                **existing.metadata,
                **word.metadata,
            },
        )

    return tuple(merged.values())


def _best_rank(
    left: int | None,
    right: int | None,
) -> int | None:
    ranks = [
        rank
        for rank in (left, right)
        if rank is not None
    ]

    return min(ranks) if ranks else None


def _targeted_word_sort_key(
    word: PermutationWord,
) -> tuple[float, int, str]:
    return (
        -word.ranking_score,
        word.global_rank or 10**12,
        word.token.lower(),
    )


def _exploration_word_sort_key(
    word: PermutationWord,
) -> tuple[int, float, str]:
    # Sorting supplies a stable corpus order; the rotating cursor ensures lower
    # ranked words eventually get their own exploration batch.
    return (
        word.global_rank or 10**12,
        -word.global_score,
        word.token.lower(),
    )


def _direct_word_candidate(
    *,
    seed_event: Event,
    seed: str,
    word: PermutationWord,
    label: str,
    lane: CandidateLane,
    config: PermutationsConfig,
) -> PermutationCandidate | None:
    if seed_event.type is EventType.ROOT_DOMAIN:
        method = PermutationMethod.DIRECT_CHILD
    else:
        if not config.nested_children:
            return None

        method = PermutationMethod.NESTED_CHILD

    try:
        hostname = normalize_dns_name(
            f"{label}.{seed}"
        )
    except ValueError:
        return None

    return PermutationCandidate(
        hostname=hostname,
        lane=lane,
        method=method,
        score=word.ranking_score,
        confidence=_bounded_confidence(
            word.confidence,
            config,
        ),
        word_tokens=(word.token,),
        metadata=_word_metadata(word),
    )


def _sibling_candidates(
    *,
    seed: str,
    word: PermutationWord,
    label: str,
    lane: CandidateLane,
    config: PermutationsConfig,
) -> tuple[PermutationCandidate, ...]:
    labels = seed.split(".")

    # Need at least host.parent.tld, e.g. api.example.com.
    if len(labels) < 3:
        return ()

    left = labels[0]
    parent = ".".join(labels[1:])

    raw = (
        (
            f"{label}-{left}.{parent}",
            PermutationMethod.PREFIX_LEFT_LABEL,
        ),
        (
            f"{left}-{label}.{parent}",
            PermutationMethod.SUFFIX_LEFT_LABEL,
        ),
    )

    result: list[PermutationCandidate] = []

    for hostname, method in raw:
        try:
            normalized = normalize_dns_name(hostname)
        except ValueError:
            continue

        if normalized == seed:
            continue

        result.append(
            PermutationCandidate(
                hostname=normalized,
                lane=lane,
                method=method,
                score=word.ranking_score * 0.9,
                confidence=_bounded_confidence(
                    word.confidence * 0.9,
                    config,
                ),
                word_tokens=(word.token,),
                metadata=_word_metadata(word),
            )
        )

    return tuple(result)


def _pairwise_candidates(
    *,
    seed: str,
    words: Sequence[PermutationWord],
    remaining: int,
    config: PermutationsConfig,
) -> tuple[PermutationCandidate, ...]:
    """Bounded pairwise combinations of only the top targeted words."""
    if remaining <= 0:
        return ()

    primary: list[tuple[PermutationWord, str]] = []

    for word in words:
        labels = word.label_variants()
        if labels:
            primary.append((word, labels[0]))

    result: list[PermutationCandidate] = []

    for left_index, (left_word, left_label) in enumerate(
        primary
    ):
        for right_word, right_label in primary[
            left_index + 1 :
        ]:
            for combined in (
                f"{left_label}-{right_label}",
                f"{right_label}-{left_label}",
            ):
                if len(result) >= remaining:
                    return _rank_and_dedupe_candidates(
                        result
                    )

                if len(combined) > 63:
                    continue

                try:
                    hostname = normalize_dns_name(
                        f"{combined}.{seed}"
                    )
                except ValueError:
                    continue

                score = (
                    left_word.ranking_score
                    + right_word.ranking_score
                ) / 2.0

                result.append(
                    PermutationCandidate(
                        hostname=hostname,
                        lane=CandidateLane.TARGETED,
                        method=PermutationMethod.PAIRWISE_HYPHEN,
                        score=score,
                        confidence=_bounded_confidence(
                            min(
                                left_word.confidence,
                                right_word.confidence,
                            )
                            * 0.8,
                            config,
                        ),
                        word_tokens=(
                            left_word.token,
                            right_word.token,
                        ),
                        metadata={
                            "pairwise": True,
                            "global_sources": sorted(
                                left_word.global_sources
                                | right_word.global_sources
                            ),
                            "target_sources": sorted(
                                left_word.target_sources
                                | right_word.target_sources
                            ),
                        },
                    )
                )

    return _rank_and_dedupe_candidates(result)


def _candidate_within_seed_branch(
    *,
    candidate: str,
    seed: str,
    seed_type: EventType,
) -> bool:
    """Reject pattern-engine cross-branch candidate injection.

    For ROOT_DOMAIN, candidate must be a strict descendant.

    For a confirmed DNS_NAME, learned patterns may produce either nested
    descendants or siblings under that seed's immediate parent.
    """
    normalized_candidate = normalize_dns_name(candidate)
    normalized_seed = normalize_dns_name(seed)

    if seed_type is EventType.ROOT_DOMAIN:
        return (
            normalized_candidate != normalized_seed
            and normalized_candidate.endswith(
                "." + normalized_seed
            )
        )

    if (
        normalized_candidate != normalized_seed
        and normalized_candidate.endswith(
            "." + normalized_seed
        )
    ):
        return True

    labels = normalized_seed.split(".")
    if len(labels) < 3:
        return False

    parent = ".".join(labels[1:])

    return (
        normalized_candidate != parent
        and normalized_candidate.endswith(
            "." + parent
        )
    )


def _word_metadata(
    word: PermutationWord,
) -> dict[str, Any]:
    return {
        "global_sources": sorted(word.global_sources),
        "target_sources": sorted(word.target_sources),
        "global_rank": word.global_rank,
        "global_score": word.global_score,
        "target_frequency": word.target_frequency,
        "target_source_diversity": (
            word.target_source_diversity
        ),
        "target_relevance": word.target_relevance,
        "successful_hits": word.successful_hits,
        "attempted_hypotheses": (
            word.attempted_hypotheses
        ),
        "historical_yield": word.yield_ratio,
        **word.metadata,
    }


def _bounded_confidence(
    value: float,
    config: PermutationsConfig,
) -> float:
    return min(
        config.candidate_confidence_ceiling,
        max(
            config.candidate_confidence_floor,
            value,
        ),
    )


def _candidate_novelty(
    candidate: PermutationCandidate,
) -> float:
    if candidate.lane is CandidateLane.EXPLORATION:
        return 0.90

    if candidate.method is PermutationMethod.LEARNED_PATTERN:
        return 0.85

    if candidate.method is PermutationMethod.PAIRWISE_HYPHEN:
        return 0.75

    return 0.65


def _rank_and_dedupe_candidates(
    candidates: Sequence[PermutationCandidate],
) -> tuple[PermutationCandidate, ...]:
    best: dict[str, PermutationCandidate] = {}

    for candidate in candidates:
        existing = best.get(candidate.hostname)

        if existing is None:
            best[candidate.hostname] = candidate
            continue

        candidate_key = (
            candidate.score,
            candidate.method
            is PermutationMethod.LEARNED_PATTERN,
        )
        existing_key = (
            existing.score,
            existing.method
            is PermutationMethod.LEARNED_PATTERN,
        )

        if candidate_key > existing_key:
            best[candidate.hostname] = candidate

    return tuple(
        sorted(
            best.values(),
            key=lambda candidate: (
                -candidate.score,
                candidate.hostname,
            ),
        )
    )


def _exploration_namespace(
    *,
    seed: str,
    tier: CandidateTier,
) -> str:
    material = f"{seed}|{tier.value}"
    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:16]

    return (
        f"permutations:{tier.value.lower()}:"
        f"{digest}"
    )
