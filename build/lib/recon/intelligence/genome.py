"""Target Genome assembly for Night Scout.

The Target Genome is the explainable, target-specific model learned from the
recon event graph. It does not perform discovery by itself and it never grants
scope or authorization.

It combines already existing intelligence layers:

    Events
      + vocabulary.py
      + patterns.py
      + confidence.py
      + novelty.py
      + yield_model.py
            |
            v
       TargetGenome

The genome captures, in bounded form:
- target vocabulary and its observed historical yield;
- naming patterns and pattern yield;
- environment / region / service / project / technology terms;
- common API versions and URL/path shapes;
- application titles;
- certificate-to-SAN relationships;
- representative assets with confidence + novelty assessments;
- overall target discovery yield.

Important separation of concerns
--------------------------------
A genome is descriptive intelligence. It is NOT:
- a scope decision;
- an ownership decision;
- a severity score;
- an exploitation recommendation;
- a credential store;
- a scheduler or budget controller.

All active follow-up still passes through the normal Night Scout lifecycle:
scope -> restrictions -> review -> budgets -> rate limits -> worker.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState, utc_now
from recon.intelligence.confidence import (
    ConfidenceAssessment,
    ConfidenceModel,
    confidence_subject_key,
)
from recon.intelligence.novelty import NoveltyAssessment, NoveltyModel
from recon.intelligence.patterns import (
    NamingPattern,
    PatternEngine,
    PatternDiscoveryReport,
    pattern_learning_root,
)
from recon.intelligence.vocabulary import (
    VocabularyAggregate,
    VocabularyCategory,
    VocabularyProjector,
    VocabularyProjectorConfig,
    event_contains_sensitive_material,
)
from recon.intelligence.wordlists import CorpusCategory
from recon.intelligence.yield_model import (
    PatternYieldFeedbackAdapter,
    YieldEstimate,
    YieldModel,
    YieldQuery,
    target_key_for_event,
)


GENOME_VERSION = 1

_API_VERSION_RE = re.compile(r"^v[0-9]{1,4}$", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_ID_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^[0-9]+$")


class GenomeSignalKind(StrEnum):
    """High-level learned feature families."""

    ENVIRONMENT = "environment"
    REGION = "region"
    SERVICE = "service"
    PROJECT = "project"
    TECHNOLOGY = "technology"
    API_VERSION = "api-version"
    APPLICATION_TITLE = "application-title"


class GenomeVocabularyEntry(BaseModel):
    """Ranked target-specific token with optional hypothesis yield history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    canonical_key: str
    categories: frozenset[VocabularyCategory]

    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)

    confidence: float = Field(ge=0.0, le=1.0)
    relevance: float = Field(ge=0.0, le=1.0)
    vocabulary_score: float = Field(ge=0.0)

    contexts: frozenset[str] = Field(default_factory=frozenset)
    source_families: frozenset[str] = Field(default_factory=frozenset)
    source_event_ids: tuple[str, ...] = ()

    yield_category: CorpusCategory | None = None
    yield_attempts: int = Field(default=0, ge=0)
    yield_successes: int = Field(default=0, ge=0)
    expected_yield: float | None = Field(default=None, ge=0.0, le=1.0)
    yield_uncertainty: float | None = Field(default=None, ge=0.0, le=1.0)

    case_sensitive: bool = False

    @field_validator("token", "canonical_key")
    @classmethod
    def text_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @property
    def genome_score(self) -> float:
        """Ranking only; not a severity or authorization score."""

        yield_bonus = 0.0
        if self.expected_yield is not None:
            reliability = min(1.0, self.yield_attempts / 12.0)
            yield_bonus = self.expected_yield * reliability * 2.0

        return self.vocabulary_score + yield_bonus


class GenomePatternEntry(BaseModel):
    """Compact learned naming pattern with feedback/yield context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str
    root_domain: str
    parent_domain: str
    template: str
    label_template: str

    support: int = Field(ge=2)
    combination_space: int = Field(ge=1)
    unseen_combination_count: int = Field(ge=0)

    score: float
    confidence: float = Field(ge=0.0, le=1.0)

    feedback_attempts: int = Field(default=0, ge=0)
    feedback_successes: int = Field(default=0, ge=0)
    expected_yield: float | None = Field(default=None, ge=0.0, le=1.0)
    yield_uncertainty: float | None = Field(default=None, ge=0.0, le=1.0)

    source_event_ids: tuple[str, ...] = ()
    slot_values: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @field_validator("pattern_id", "root_domain", "parent_domain", "template")
    @classmethod
    def text_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class GenomeLearnedSignal(BaseModel):
    """Aggregated semantic term such as environment, service or technology."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: GenomeSignalKind
    value: str

    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)
    confidence: float = Field(ge=0.0, le=1.0)
    relevance: float = Field(ge=0.0, le=1.0)

    source_event_ids: tuple[str, ...] = ()

    @field_validator("value")
    @classmethod
    def value_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @property
    def score(self) -> float:
        return (
            self.relevance * 3.0
            + self.confidence
            + math.log1p(self.occurrences)
            + min(4, self.source_diversity) * 0.45
        )


class GenomeUrlShape(BaseModel):
    """Typical path structure learned without retaining query values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template: str
    is_api: bool = False

    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)

    methods: frozenset[str] = Field(default_factory=frozenset)
    api_versions: frozenset[str] = Field(default_factory=frozenset)

    example_paths: tuple[str, ...] = ()
    source_event_ids: tuple[str, ...] = ()

    @field_validator("template")
    @classmethod
    def template_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("template must not be blank")
        return normalized

    @property
    def score(self) -> float:
        return (
            math.log1p(self.occurrences)
            + min(5, self.source_diversity) * 0.7
            + (0.8 if self.is_api else 0.0)
        )


class GenomeApplicationTitle(BaseModel):
    """Normalized HTTP application title frequency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str
    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)
    source_event_ids: tuple[str, ...] = ()

    @field_validator("title")
    @classmethod
    def title_required(cls, value: str) -> str:
        normalized = " ".join(value.split()).strip()
        if not normalized:
            raise ValueError("title must not be blank")
        return normalized


class GenomeTechnologyStack(BaseModel):
    """Frequently observed normalized technology combination."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technologies: tuple[str, ...]
    webserver: str | None = None
    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)
    source_event_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def has_material(self) -> "GenomeTechnologyStack":
        if not self.technologies and self.webserver is None:
            raise ValueError("technology stack requires material")
        return self


class GenomeCertificateRelation(BaseModel):
    """Observed certificate identity -> SAN relationship.

    Correlation only; never ownership or scope inference.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    certificate_key: str
    sans: tuple[str, ...]

    subject_cn: str | None = None
    issuer_cn: str | None = None

    occurrences: int = Field(ge=1)
    source_event_ids: tuple[str, ...] = ()

    @field_validator("certificate_key")
    @classmethod
    def key_required(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("certificate_key must not be blank")
        return normalized


class GenomeAssetSignal(BaseModel):
    """Representative asset with independently assessed confidence + novelty."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_key: str
    event_id: str
    event_type: EventType
    value: str
    source: str
    scope_state: ScopeState

    confidence: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)

    confidence_supporting_groups: int = Field(ge=0)
    confidence_contradicting_groups: int = Field(ge=0)
    confidence_source_diversity: int = Field(ge=0)
    confidence_conflict_score: float = Field(ge=0.0, le=1.0)

    novelty_factors: tuple[str, ...] = ()
    novelty_observation_count: int = Field(ge=0)

    confirmed: bool = False
    historical: bool = False
    hypothesis: bool = False

    first_seen: datetime
    last_seen: datetime

    @field_validator("subject_key", "event_id", "value", "source")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @property
    def attention_score(self) -> float:
        """Exploration attention only; deliberately not severity."""

        evidence_factor = min(
            1.0,
            self.confidence_source_diversity / 3.0,
        )
        confirmation = 0.08 if self.confirmed else 0.0
        hypothesis_penalty = 0.12 if self.hypothesis else 0.0

        return max(
            0.0,
            min(
                1.0,
                self.confidence * 0.42
                + self.novelty * 0.43
                + evidence_factor * 0.07
                + confirmation
                - hypothesis_penalty,
            ),
        )


class GenomeYieldSummary(BaseModel):
    """Target-wide discovery productivity snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attempted_units: int = Field(default=0, ge=0)
    successful_hits: int = Field(default=0, ge=0)
    new_assets: int = Field(default=0, ge=0)
    novel_assets: int = Field(default=0, ge=0)

    expected_yield: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)
    estimated_cost: float = Field(gt=0.0)


class TargetGenome(BaseModel):
    """Bounded, serializable target-specific intelligence snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    genome_version: int = GENOME_VERSION
    target_key: str
    root_domain: str | None = None

    generated_at: datetime = Field(default_factory=utc_now)
    fingerprint: str

    event_count: int = Field(ge=0)
    source_family_count: int = Field(ge=0)
    confirmed_event_count: int = Field(ge=0)
    hypothesis_event_count: int = Field(ge=0)
    historical_event_count: int = Field(ge=0)

    vocabulary: tuple[GenomeVocabularyEntry, ...]
    patterns: tuple[GenomePatternEntry, ...]

    learned_signals: tuple[GenomeLearnedSignal, ...]
    url_shapes: tuple[GenomeUrlShape, ...]
    application_titles: tuple[GenomeApplicationTitle, ...]
    technology_stacks: tuple[GenomeTechnologyStack, ...]
    certificate_relations: tuple[GenomeCertificateRelation, ...]

    assets: tuple[GenomeAssetSignal, ...]

    target_yield: GenomeYieldSummary | None = None
    pattern_report: PatternDiscoveryReport | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_key", "fingerprint")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("generated_at")
    @classmethod
    def generated_at_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value

    def signals(self, kind: GenomeSignalKind) -> tuple[GenomeLearnedSignal, ...]:
        return tuple(signal for signal in self.learned_signals if signal.kind is kind)


class TargetGenomeBuildReport(BaseModel):
    """Explainability/limits report for one genome build."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str
    events_loaded: int = Field(ge=0)
    events_used: int = Field(ge=0)
    sensitive_events_skipped: int = Field(ge=0)

    vocabulary_observations: int = Field(ge=0)
    vocabulary_entries: int = Field(ge=0)
    patterns: int = Field(ge=0)
    assets_assessed: int = Field(ge=0)

    truncated_events: bool = False
    truncated_vocabulary: bool = False
    truncated_assets: bool = False


class TargetGenomeConfig(BaseModel):
    """Hard bounds for Target Genome assembly."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_events: int = Field(default=250_000, ge=1, le=2_000_000)
    max_vocabulary_observations: int = Field(default=500_000, ge=1, le=2_000_000)
    max_vocabulary_entries: int = Field(default=512, ge=1, le=50_000)
    max_vocabulary_yield_queries: int = Field(default=256, ge=0, le=10_000)

    max_patterns: int = Field(default=128, ge=0, le=10_000)
    max_pattern_yield_queries: int = Field(default=128, ge=0, le=10_000)

    max_assets: int = Field(default=512, ge=0, le=50_000)
    max_asset_assessment_candidates: int = Field(default=2048, ge=1, le=100_000)
    assessment_concurrency: int = Field(default=24, ge=1, le=256)

    max_learned_signals: int = Field(default=256, ge=1, le=10_000)
    max_url_shapes: int = Field(default=128, ge=1, le=10_000)
    max_application_titles: int = Field(default=64, ge=1, le=10_000)
    max_technology_stacks: int = Field(default=64, ge=1, le=10_000)
    max_certificate_relations: int = Field(default=128, ge=1, le=10_000)

    max_examples_per_shape: int = Field(default=4, ge=1, le=32)
    max_certificate_sans: int = Field(default=256, ge=1, le=10_000)


class TargetGenomeEventProvider(Protocol):
    """Storage boundary; intentionally matches existing target-event providers."""

    async def events_for(self, seed_event: Event) -> Sequence[Event]:
        ...


class TargetGenomeStore(Protocol):
    """Optional persistence boundary for full genome snapshots."""

    async def save(self, genome: TargetGenome) -> None:
        ...

    async def latest(self, target_key: str) -> TargetGenome | None:
        ...


class InMemoryTargetGenomeStore:
    """Bootstrap/test store. SQLite persistence belongs in storage layer."""

    def __init__(self) -> None:
        self._items: dict[str, TargetGenome] = {}
        self._lock = asyncio.Lock()

    async def save(self, genome: TargetGenome) -> None:
        async with self._lock:
            self._items[genome.target_key] = genome.model_copy(deep=True)

    async def latest(self, target_key: str) -> TargetGenome | None:
        async with self._lock:
            item = self._items.get(target_key)
            return item.model_copy(deep=True) if item is not None else None


class TargetGenomeBuilder:
    """Assemble a bounded Target Genome from existing intelligence modules."""

    def __init__(
        self,
        *,
        events: TargetGenomeEventProvider,
        vocabulary: VocabularyProjector | None = None,
        patterns: PatternEngine | None = None,
        confidence: ConfidenceModel | None = None,
        novelty: NoveltyModel | None = None,
        yield_model: YieldModel | None = None,
        config: TargetGenomeConfig | None = None,
    ) -> None:
        self._events = events
        self._vocabulary = vocabulary or VocabularyProjector(
            VocabularyProjectorConfig()
        )
        self._yield_model = yield_model
        self._confidence = confidence or ConfidenceModel()
        self._novelty = novelty or NoveltyModel()
        self._config = config or TargetGenomeConfig()

        if patterns is not None:
            self._patterns = patterns
        else:
            feedback = (
                PatternYieldFeedbackAdapter(yield_model.store)
                if yield_model is not None
                else None
            )
            self._patterns = PatternEngine(
                target_events=events,
                feedback=feedback,
            )

    @property
    def config(self) -> TargetGenomeConfig:
        return self._config

    async def build(
        self,
        seed_event: Event,
    ) -> tuple[TargetGenome, TargetGenomeBuildReport]:
        raw_events = tuple(await self._events.events_for(seed_event))
        events_loaded = len(raw_events)

        bounded = dedupe_events((seed_event, *raw_events))[: self._config.max_events]
        truncated_events = len(dedupe_events((seed_event, *raw_events))) > len(bounded)

        safe_events = tuple(event for event in bounded if not event_contains_sensitive_material(event))
        sensitive_skipped = len(bounded) - len(safe_events)

        target_key = resolve_target_key(seed_event)
        root_domain = resolve_root_domain(seed_event)

        vocabulary_observations = project_genome_vocabulary(
            self._vocabulary,
            safe_events,
            max_observations=self._config.max_vocabulary_observations,
        )
        vocabulary_aggregates = self._vocabulary.aggregate(vocabulary_observations)

        truncated_vocabulary = len(vocabulary_aggregates) > self._config.max_vocabulary_entries
        selected_vocabulary = vocabulary_aggregates[: self._config.max_vocabulary_entries]

        vocabulary_entries = await self._build_vocabulary_entries(
            selected_vocabulary,
            target_key=target_key,
        )

        patterns, pattern_report = await self._patterns.patterns_for(seed_event)
        patterns = patterns[: self._config.max_patterns]
        pattern_entries = await self._build_pattern_entries(patterns, target_key=target_key)

        learned_signals = build_learned_signals(vocabulary_aggregates)[
            : self._config.max_learned_signals
        ]
        url_shapes = build_url_shapes(
            safe_events,
            max_examples=self._config.max_examples_per_shape,
        )[: self._config.max_url_shapes]
        titles = build_application_titles(safe_events)[: self._config.max_application_titles]
        stacks = build_technology_stacks(safe_events)[: self._config.max_technology_stacks]
        cert_relations = build_certificate_relations(
            safe_events,
            max_sans=self._config.max_certificate_sans,
        )[: self._config.max_certificate_relations]

        asset_candidates = representative_asset_events(safe_events)[
            : self._config.max_asset_assessment_candidates
        ]
        truncated_assets = len(representative_asset_events(safe_events)) > len(asset_candidates)
        assets = await self._assess_assets(asset_candidates)
        assets = tuple(
            sorted(
                assets,
                key=lambda item: (
                    -item.attention_score,
                    -item.novelty,
                    -item.confidence,
                    item.subject_key,
                ),
            )[: self._config.max_assets]
        )

        target_yield = await self._target_yield(target_key)

        counts = Counter(event_state_label(event) for event in safe_events)
        source_families = {source_family(event.source) for event in safe_events}

        fingerprint = genome_fingerprint(
            target_key=target_key,
            vocabulary=vocabulary_entries,
            patterns=pattern_entries,
            learned_signals=learned_signals,
            url_shapes=url_shapes,
            titles=titles,
            stacks=stacks,
            certificate_relations=cert_relations,
        )

        genome = TargetGenome(
            target_key=target_key,
            root_domain=root_domain,
            fingerprint=fingerprint,
            event_count=len(safe_events),
            source_family_count=len(source_families),
            confirmed_event_count=counts["confirmed"],
            hypothesis_event_count=counts["hypothesis"],
            historical_event_count=counts["historical"],
            vocabulary=vocabulary_entries,
            patterns=pattern_entries,
            learned_signals=learned_signals,
            url_shapes=url_shapes,
            application_titles=titles,
            technology_stacks=stacks,
            certificate_relations=cert_relations,
            assets=assets,
            target_yield=target_yield,
            pattern_report=pattern_report,
            metadata={
                "network_access": False,
                "scope_inference": False,
                "ownership_inference": False,
                "severity_inference": False,
                "raw_secret_storage": False,
                "bounded": True,
                "source_families": sorted(source_families),
            },
        )

        report = TargetGenomeBuildReport(
            target_key=target_key,
            events_loaded=events_loaded,
            events_used=len(safe_events),
            sensitive_events_skipped=sensitive_skipped,
            vocabulary_observations=len(vocabulary_observations),
            vocabulary_entries=len(vocabulary_entries),
            patterns=len(pattern_entries),
            assets_assessed=len(assets),
            truncated_events=truncated_events,
            truncated_vocabulary=truncated_vocabulary,
            truncated_assets=truncated_assets,
        )

        return genome, report

    async def _build_vocabulary_entries(
        self,
        aggregates: Sequence[VocabularyAggregate],
        *,
        target_key: str,
    ) -> tuple[GenomeVocabularyEntry, ...]:
        query_limit = min(
            len(aggregates),
            self._config.max_vocabulary_yield_queries,
        )

        estimates: list[YieldEstimate | None] = [None] * len(aggregates)
        categories: list[CorpusCategory | None] = [None] * len(aggregates)

        if self._yield_model is not None and query_limit > 0:
            async def estimate_one(index: int, aggregate: VocabularyAggregate) -> None:
                category = corpus_category_for_vocabulary(aggregate)
                categories[index] = category
                estimates[index] = await self._yield_model.estimate_for_token(
                    target_key=target_key,
                    token=aggregate.token,
                    category=category,
                )

            await asyncio.gather(
                *(estimate_one(index, aggregate) for index, aggregate in enumerate(aggregates[:query_limit]))
            )

        entries: list[GenomeVocabularyEntry] = []

        for index, aggregate in enumerate(aggregates):
            estimate = estimates[index]
            categories[index] = categories[index] or corpus_category_for_vocabulary(aggregate)

            entries.append(
                GenomeVocabularyEntry(
                    token=aggregate.token,
                    canonical_key=aggregate.canonical_key,
                    categories=aggregate.categories,
                    occurrences=aggregate.occurrences,
                    source_diversity=aggregate.source_diversity,
                    confidence=aggregate.confidence,
                    relevance=aggregate.relevance,
                    vocabulary_score=aggregate.score,
                    contexts=aggregate.contexts,
                    source_families=aggregate.source_families,
                    source_event_ids=aggregate.source_event_ids,
                    yield_category=categories[index],
                    yield_attempts=(estimate.aggregate.attempted_units if estimate else 0),
                    yield_successes=(estimate.aggregate.successful_hits if estimate else 0),
                    expected_yield=(estimate.expected_yield if estimate else None),
                    yield_uncertainty=(estimate.uncertainty if estimate else None),
                    case_sensitive=aggregate.case_sensitive,
                )
            )

        return tuple(
            sorted(
                entries,
                key=lambda entry: (-entry.genome_score, entry.canonical_key),
            )
        )

    async def _build_pattern_entries(
        self,
        patterns: Sequence[NamingPattern],
        *,
        target_key: str,
    ) -> tuple[GenomePatternEntry, ...]:
        estimates: list[YieldEstimate | None] = [None] * len(patterns)
        query_limit = min(len(patterns), self._config.max_pattern_yield_queries)

        if self._yield_model is not None and query_limit > 0:
            async def estimate_one(index: int, pattern: NamingPattern) -> None:
                estimates[index] = await self._yield_model.estimate_for_pattern(
                    target_key=target_key,
                    pattern_id=pattern.pattern_id,
                )

            await asyncio.gather(
                *(estimate_one(index, pattern) for index, pattern in enumerate(patterns[:query_limit]))
            )

        result: list[GenomePatternEntry] = []

        for index, pattern in enumerate(patterns):
            estimate = estimates[index]
            result.append(
                GenomePatternEntry(
                    pattern_id=pattern.pattern_id,
                    root_domain=pattern.root_domain,
                    parent_domain=pattern.parent_domain,
                    template=pattern.template,
                    label_template=pattern.label_template,
                    support=pattern.support,
                    combination_space=pattern.combination_space,
                    unseen_combination_count=pattern.unseen_combination_count,
                    score=pattern.score,
                    confidence=pattern.confidence,
                    feedback_attempts=pattern.feedback_attempts,
                    feedback_successes=pattern.feedback_successes,
                    expected_yield=(estimate.expected_yield if estimate else None),
                    yield_uncertainty=(estimate.uncertainty if estimate else None),
                    source_event_ids=pattern.source_event_ids,
                    slot_values=pattern_slot_values(pattern),
                )
            )

        return tuple(
            sorted(
                result,
                key=lambda item: (
                    -(item.score + item.confidence),
                    item.pattern_id,
                ),
            )
        )

    async def _assess_assets(
        self,
        events: Sequence[Event],
    ) -> tuple[GenomeAssetSignal, ...]:
        semaphore = asyncio.Semaphore(self._config.assessment_concurrency)

        async def assess_one(event: Event) -> GenomeAssetSignal:
            async with semaphore:
                confidence_task = self._confidence.assess(event)
                novelty_task = self._novelty.assess(event)
                confidence, novelty = await asyncio.gather(confidence_task, novelty_task)
                return asset_signal_from_assessments(event, confidence, novelty)

        if not events:
            return ()

        return tuple(await asyncio.gather(*(assess_one(event) for event in events)))

    async def _target_yield(self, target_key: str) -> GenomeYieldSummary | None:
        if self._yield_model is None:
            return None

        estimate = await self._yield_model.estimate(YieldQuery(target_key=target_key))
        aggregate = estimate.aggregate

        return GenomeYieldSummary(
            attempted_units=aggregate.attempted_units,
            successful_hits=aggregate.successful_hits,
            new_assets=aggregate.new_assets,
            novel_assets=aggregate.novel_assets,
            expected_yield=estimate.expected_yield,
            uncertainty=estimate.uncertainty,
            estimated_cost=estimate.estimated_cost,
        )


def resolve_target_key(seed_event: Event) -> str:
    target_key = target_key_for_event(seed_event)
    if target_key:
        return target_key

    return seed_event.value.strip().lower()


def resolve_root_domain(seed_event: Event) -> str | None:
    try:
        return pattern_learning_root(seed_event)
    except ValueError:
        return None


def dedupe_events(events: Sequence[Event]) -> tuple[Event, ...]:
    """Prefer the most recent copy for duplicate event IDs."""

    by_id: dict[str, Event] = {}
    for event in events:
        existing = by_id.get(event.event_id)
        if existing is None or event.last_seen >= existing.last_seen:
            by_id[event.event_id] = event

    return tuple(
        sorted(
            by_id.values(),
            key=lambda event: (event.first_seen, event.event_id),
        )
    )


def project_genome_vocabulary(
    projector: VocabularyProjector,
    events: Sequence[Event],
    *,
    max_observations: int,
) -> tuple[Any, ...]:
    """Avoid double-counting persisted VOCAB_TOKEN events and their loaded parent."""

    if max_observations <= 0:
        return ()

    event_ids = {event.event_id for event in events}
    raw_events = tuple(event for event in events if event.type is not EventType.VOCAB_TOKEN)

    explicit_tokens = tuple(
        event
        for event in events
        if event.type is EventType.VOCAB_TOKEN
        and (
            event.parent_event_id is None
            or event.parent_event_id not in event_ids
        )
    )

    result = list(
        projector.project_events(
            raw_events,
            max_observations=max_observations,
        )
    )

    remaining = max_observations - len(result)
    if remaining > 0:
        result.extend(
            projector.project_events(
                explicit_tokens,
                max_observations=remaining,
            )
        )

    return tuple(result[:max_observations])


def corpus_category_for_vocabulary(aggregate: VocabularyAggregate) -> CorpusCategory:
    categories = aggregate.categories

    if VocabularyCategory.PARAMETER in categories:
        return CorpusCategory.PARAMETER
    if VocabularyCategory.API in categories:
        return CorpusCategory.API
    if VocabularyCategory.PATH in categories:
        return CorpusCategory.PATH
    if VocabularyCategory.PROJECT in categories:
        return CorpusCategory.PROJECT
    if VocabularyCategory.TECHNOLOGY in categories:
        return CorpusCategory.TECHNOLOGY
    if VocabularyCategory.DNS in categories:
        return CorpusCategory.DNS

    return CorpusCategory.GENERAL


def pattern_slot_values(pattern: NamingPattern) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}

    for index, slot in enumerate(pattern.slots):
        values: Sequence[Any] = ()

        if hasattr(slot, "values"):
            raw = getattr(slot, "values")
            if isinstance(raw, (list, tuple, set)):
                values = tuple(raw)

        if not values and hasattr(slot, "value_counts"):
            raw_counts = getattr(slot, "value_counts")
            if isinstance(raw_counts, dict):
                values = tuple(raw_counts.keys())

        kind = str(getattr(slot, "kind", "value"))
        name = f"{index}:{kind}"
        result[name] = tuple(sorted({str(value) for value in values if str(value)}))

    return result


def build_learned_signals(
    aggregates: Sequence[VocabularyAggregate],
) -> tuple[GenomeLearnedSignal, ...]:
    mappings = (
        (VocabularyCategory.ENVIRONMENT, GenomeSignalKind.ENVIRONMENT),
        (VocabularyCategory.REGION, GenomeSignalKind.REGION),
        (VocabularyCategory.SERVICE, GenomeSignalKind.SERVICE),
        (VocabularyCategory.PROJECT, GenomeSignalKind.PROJECT),
        (VocabularyCategory.TECHNOLOGY, GenomeSignalKind.TECHNOLOGY),
    )

    result: list[GenomeLearnedSignal] = []
    seen: set[tuple[GenomeSignalKind, str]] = set()

    for aggregate in aggregates:
        for category, kind in mappings:
            if category not in aggregate.categories:
                continue

            key = (kind, aggregate.canonical_key)
            if key in seen:
                continue
            seen.add(key)

            result.append(
                GenomeLearnedSignal(
                    kind=kind,
                    value=aggregate.token,
                    occurrences=aggregate.occurrences,
                    source_diversity=aggregate.source_diversity,
                    confidence=aggregate.confidence,
                    relevance=aggregate.relevance,
                    source_event_ids=aggregate.source_event_ids,
                )
            )

        if _API_VERSION_RE.fullmatch(aggregate.token):
            key = (GenomeSignalKind.API_VERSION, aggregate.canonical_key)
            if key not in seen:
                seen.add(key)
                result.append(
                    GenomeLearnedSignal(
                        kind=GenomeSignalKind.API_VERSION,
                        value=aggregate.token.lower(),
                        occurrences=aggregate.occurrences,
                        source_diversity=aggregate.source_diversity,
                        confidence=aggregate.confidence,
                        relevance=max(0.7, aggregate.relevance),
                        source_event_ids=aggregate.source_event_ids,
                    )
                )

    return tuple(sorted(result, key=lambda signal: (-signal.score, signal.kind.value, signal.value)))


def build_url_shapes(
    events: Sequence[Event],
    *,
    max_examples: int,
) -> tuple[GenomeUrlShape, ...]:
    state: dict[str, dict[str, Any]] = {}

    for event in events:
        if event.type not in {
            EventType.URL,
            EventType.URL_PATH,
            EventType.API_ENDPOINT,
            EventType.JAVASCRIPT,
            EventType.HTTP_SERVICE,
        }:
            continue

        path = safe_event_path(event)
        if path is None:
            continue

        template = path_template(path)
        if template is None:
            continue

        item = state.setdefault(
            template,
            {
                "occurrences": 0,
                "source_families": set(),
                "methods": set(),
                "api_versions": set(),
                "examples": [],
                "event_ids": set(),
                "is_api": False,
            },
        )
        item["occurrences"] += 1
        item["source_families"].add(source_family(event.source))
        item["event_ids"].add(event.event_id)
        item["is_api"] = item["is_api"] or event.type is EventType.API_ENDPOINT or path_looks_api(path)

        method = event.metadata.get("method") or event.metadata.get("http_method")
        if isinstance(method, str) and method.strip():
            item["methods"].add(method.strip().upper())

        item["api_versions"].update(api_versions_in_path(path))

        if path not in item["examples"] and len(item["examples"]) < max_examples:
            item["examples"].append(path)

    result = [
        GenomeUrlShape(
            template=template,
            is_api=bool(item["is_api"]),
            occurrences=item["occurrences"],
            source_diversity=len(item["source_families"]),
            methods=frozenset(item["methods"]),
            api_versions=frozenset(item["api_versions"]),
            example_paths=tuple(item["examples"]),
            source_event_ids=tuple(sorted(item["event_ids"])),
        )
        for template, item in state.items()
    ]

    return tuple(sorted(result, key=lambda shape: (-shape.score, shape.template)))


def safe_event_path(event: Event) -> str | None:
    raw = event.value.strip()

    if event.type is EventType.URL_PATH:
        path = event.metadata.get("path")
        if isinstance(path, str) and path.startswith("/"):
            return path.split("?", 1)[0]

        slash = raw.find("/")
        return raw[slash:].split("?", 1)[0] if slash >= 0 else None

    try:
        parts = urlsplit(raw)
    except ValueError:
        return None

    if parts.scheme.lower() not in {"http", "https"}:
        return None

    return parts.path or "/"


def path_template(path: str) -> str | None:
    if not path.startswith("/"):
        return None

    segments: list[str] = []
    for raw_segment in path.split("/"):
        if not raw_segment:
            continue

        segment = raw_segment.strip()
        lower = segment.lower()

        if _NUMERIC_RE.fullmatch(segment):
            normalized = "{number}"
        elif _UUID_RE.fullmatch(segment):
            normalized = "{uuid}"
        elif _HEX_ID_RE.fullmatch(segment):
            normalized = "{id}"
        elif len(segment) > 80:
            normalized = "{value}"
        else:
            normalized = lower

        segments.append(normalized)

    return "/" + "/".join(segments) if segments else "/"


def path_looks_api(path: str) -> bool:
    tokens = {token.lower() for token in path.split("/") if token}
    return bool(
        tokens
        & {
            "api",
            "rest",
            "graphql",
            "graphiql",
            "swagger",
            "openapi",
        }
        or any(_API_VERSION_RE.fullmatch(token) for token in tokens)
    )


def api_versions_in_path(path: str) -> set[str]:
    return {
        token.lower()
        for token in path.split("/")
        if _API_VERSION_RE.fullmatch(token)
    }


def build_application_titles(events: Sequence[Event]) -> tuple[GenomeApplicationTitle, ...]:
    state: dict[str, dict[str, Any]] = {}

    for event in events:
        if event.type is not EventType.HTTP_RESPONSE:
            continue

        raw = event.metadata.get("title")
        if not isinstance(raw, str):
            continue

        title = " ".join(raw.split()).strip()
        if not title or len(title) > 256:
            continue

        key = title.casefold()
        item = state.setdefault(
            key,
            {"title": title, "count": 0, "families": set(), "event_ids": set()},
        )
        item["count"] += 1
        item["families"].add(source_family(event.source))
        item["event_ids"].add(event.event_id)

    result = [
        GenomeApplicationTitle(
            title=item["title"],
            occurrences=item["count"],
            source_diversity=len(item["families"]),
            source_event_ids=tuple(sorted(item["event_ids"])),
        )
        for item in state.values()
    ]

    return tuple(
        sorted(
            result,
            key=lambda item: (-item.occurrences, -item.source_diversity, item.title.casefold()),
        )
    )


def build_technology_stacks(events: Sequence[Event]) -> tuple[GenomeTechnologyStack, ...]:
    state: dict[tuple[tuple[str, ...], str | None], dict[str, Any]] = {}

    for event in events:
        if event.type is not EventType.HTTP_RESPONSE:
            continue

        raw_technologies = event.metadata.get("technologies")
        if isinstance(raw_technologies, str):
            raw_technologies = (raw_technologies,)
        if not isinstance(raw_technologies, (list, tuple, set)):
            raw_technologies = ()

        technologies = tuple(
            sorted(
                {
                    " ".join(str(value).split()).strip().lower()
                    for value in raw_technologies
                    if str(value).strip()
                }
            )
        )

        raw_server = event.metadata.get("webserver") or event.metadata.get("server")
        webserver = (
            " ".join(raw_server.split()).strip().lower()
            if isinstance(raw_server, str) and raw_server.strip()
            else None
        )

        if not technologies and webserver is None:
            continue

        key = (technologies, webserver)
        item = state.setdefault(key, {"count": 0, "families": set(), "event_ids": set()})
        item["count"] += 1
        item["families"].add(source_family(event.source))
        item["event_ids"].add(event.event_id)

    result = [
        GenomeTechnologyStack(
            technologies=technologies,
            webserver=webserver,
            occurrences=item["count"],
            source_diversity=len(item["families"]),
            source_event_ids=tuple(sorted(item["event_ids"])),
        )
        for (technologies, webserver), item in state.items()
    ]

    return tuple(
        sorted(
            result,
            key=lambda item: (
                -item.occurrences,
                -item.source_diversity,
                item.technologies,
                item.webserver or "",
            ),
        )
    )


def build_certificate_relations(
    events: Sequence[Event],
    *,
    max_sans: int,
) -> tuple[GenomeCertificateRelation, ...]:
    state: dict[str, dict[str, Any]] = {}

    for event in events:
        if event.type is not EventType.CERTIFICATE:
            continue

        fingerprint = first_certificate_key(event)
        if fingerprint is None:
            continue

        sans = certificate_sans(event)[:max_sans]
        if not sans:
            continue

        item = state.setdefault(
            fingerprint,
            {
                "sans": set(),
                "subject_cn": None,
                "issuer_cn": None,
                "count": 0,
                "event_ids": set(),
            },
        )
        item["sans"].update(sans)
        item["count"] += 1
        item["event_ids"].add(event.event_id)

        if item["subject_cn"] is None:
            item["subject_cn"] = normalized_optional_text(event.metadata.get("subject_cn"))
        if item["issuer_cn"] is None:
            item["issuer_cn"] = normalized_optional_text(event.metadata.get("issuer_cn"))

    result = [
        GenomeCertificateRelation(
            certificate_key=key,
            sans=tuple(sorted(item["sans"]))[:max_sans],
            subject_cn=item["subject_cn"],
            issuer_cn=item["issuer_cn"],
            occurrences=item["count"],
            source_event_ids=tuple(sorted(item["event_ids"])),
        )
        for key, item in state.items()
    ]

    return tuple(
        sorted(
            result,
            key=lambda item: (-len(item.sans), -item.occurrences, item.certificate_key),
        )
    )


def first_certificate_key(event: Event) -> str | None:
    candidates: list[Any] = [event.metadata.get("fingerprint_sha256")]
    surface = event.metadata.get("surface_state")
    if isinstance(surface, dict):
        candidates.append(surface.get("certificate_fingerprints"))

    for candidate in candidates:
        values = candidate if isinstance(candidate, (list, tuple, set)) else (candidate,)
        for value in values:
            if value is None:
                continue
            normalized = str(value).strip().lower().replace(":", "")
            if normalized.startswith("sha256"):
                normalized = normalized.split("=", 1)[-1].removeprefix(":")
            if normalized:
                return normalized

    value = event.value.strip().lower()
    return value or None


def certificate_sans(event: Event) -> tuple[str, ...]:
    surface = event.metadata.get("surface_state")
    raw: Any = surface.get("certificate_sans") if isinstance(surface, dict) else None

    if raw is None:
        raw = event.metadata.get("certificate_sans") or event.metadata.get("sans")

    values = raw if isinstance(raw, (list, tuple, set)) else ((raw,) if raw else ())
    result: set[str] = set()

    for value in values:
        normalized = str(value).strip().lower().rstrip(".")
        if normalized.startswith("*."):
            normalized = normalized[2:]
        if normalized:
            result.add(normalized)

    return tuple(sorted(result))


def representative_asset_events(events: Sequence[Event]) -> tuple[Event, ...]:
    allowed = {
        EventType.ROOT_DOMAIN,
        EventType.DNS_NAME,
        EventType.IP_ADDRESS,
        EventType.URL,
        EventType.HTTP_SERVICE,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
        EventType.CERTIFICATE,
        EventType.CERT_SAN,
        EventType.FINGERPRINT,
        EventType.MOBILE_ARTIFACT,
    }

    best: dict[str, Event] = {}

    for event in events:
        if event.type not in allowed or event_contains_sensitive_material(event):
            continue

        key = confidence_subject_key(event)
        existing = best.get(key)
        if existing is None or representative_event_rank(event) > representative_event_rank(existing):
            best[key] = event

    return tuple(
        sorted(
            best.values(),
            key=lambda event: (
                -representative_event_rank(event)[0],
                -representative_event_rank(event)[1],
                event.event_id,
            ),
        )
    )


def representative_event_rank(event: Event) -> tuple[float, float, float, float]:
    tags = {tag.lower() for tag in event.tags}
    confirmed = 1.0 if "confirmed" in tags or event.metadata.get("confirmed") is True else 0.0
    hypothesis = 1.0 if "hypothesis" in tags else 0.0
    historical = 1.0 if event_is_historical(event) else 0.0

    return (
        confirmed - hypothesis * 0.5 - historical * 0.2,
        event.confidence,
        event.novelty,
        event.last_seen.timestamp(),
    )


def asset_signal_from_assessments(
    event: Event,
    confidence: ConfidenceAssessment,
    novelty: NoveltyAssessment,
) -> GenomeAssetSignal:
    tags = {tag.lower() for tag in event.tags}

    return GenomeAssetSignal(
        subject_key=genome_asset_subject_key(event, confidence),
        event_id=event.event_id,
        event_type=event.type,
        value=safe_genome_event_value(event),
        source=event.source,
        scope_state=event.scope_state,
        confidence=confidence.confidence,
        novelty=novelty.novelty,
        confidence_supporting_groups=confidence.supporting_groups,
        confidence_contradicting_groups=confidence.contradicting_groups,
        confidence_source_diversity=confidence.source_family_diversity,
        confidence_conflict_score=confidence.conflict_score,
        novelty_factors=tuple(factor.kind.value for factor in novelty.factors),
        novelty_observation_count=novelty.observation_count,
        confirmed=("confirmed" in tags or event.metadata.get("confirmed") is True),
        historical=event_is_historical(event),
        hypothesis=("hypothesis" in tags),
        first_seen=event.first_seen,
        last_seen=event.last_seen,
    )



def safe_genome_event_value(event: Event) -> str:
    """Return an explainable asset value without retaining URL query values."""

    if event.type in {
        EventType.URL,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
        EventType.HTTP_SERVICE,
    }:
        sanitized = sanitize_url_query_values(event.value)
        if sanitized is not None:
            return sanitized

    return event.value


def genome_asset_subject_key(
    event: Event,
    confidence: ConfidenceAssessment,
) -> str:
    """Keep confidence grouping semantics while redacting URL query values."""

    if event.type in {
        EventType.URL,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
        EventType.HTTP_SERVICE,
    }:
        sanitized = sanitize_url_query_values(event.value)
        if sanitized is not None:
            return f"{event.type.value.lower()}:{sanitized}"

    return confidence.subject_key


def sanitize_url_query_values(value: str) -> str | None:
    """Preserve query parameter names for explainability, never their values."""

    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None

    if parts.scheme.lower() not in {"http", "https"} or parts.hostname is None:
        return None

    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return None

    default_port = (
        parts.scheme.lower() == "http" and port == 80
    ) or (
        parts.scheme.lower() == "https" and port == 443
    )
    if port is not None and not default_port:
        host = f"{host}:{port}"

    query_names: list[str] = []
    if parts.query:
        try:
            pairs = parse_qsl(
                parts.query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=256,
            )
        except ValueError:
            pairs = []

        for name, _value in pairs:
            normalized = name.strip()
            if normalized and normalized not in query_names:
                query_names.append(normalized)

    safe_query = "&".join(query_names)
    return urlunsplit(
        (parts.scheme.lower(), host, parts.path or "/", safe_query, "")
    )

def genome_fingerprint(
    *,
    target_key: str,
    vocabulary: Sequence[GenomeVocabularyEntry],
    patterns: Sequence[GenomePatternEntry],
    learned_signals: Sequence[GenomeLearnedSignal],
    url_shapes: Sequence[GenomeUrlShape],
    titles: Sequence[GenomeApplicationTitle],
    stacks: Sequence[GenomeTechnologyStack],
    certificate_relations: Sequence[GenomeCertificateRelation],
) -> str:
    """Stable fingerprint of learned structure, excluding volatile scores/timestamps."""

    payload = {
        "version": GENOME_VERSION,
        "target_key": target_key,
        "vocabulary": [
            [entry.canonical_key, sorted(category.value for category in entry.categories)]
            for entry in vocabulary
        ],
        "patterns": [[entry.pattern_id, entry.template] for entry in patterns],
        "signals": [[signal.kind.value, signal.value] for signal in learned_signals],
        "url_shapes": [shape.template for shape in url_shapes],
        "titles": [title.title.casefold() for title in titles],
        "stacks": [
            [list(stack.technologies), stack.webserver]
            for stack in stacks
        ],
        "certificate_relations": [
            [relation.certificate_key, list(relation.sans)]
            for relation in certificate_relations
        ],
    }

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def source_family(source: str) -> str:
    normalized = source.strip().lower()
    return normalized.split(":", 1)[0] if normalized else "unknown"


def event_state_label(event: Event) -> str:
    tags = {tag.lower() for tag in event.tags}
    if "hypothesis" in tags:
        return "hypothesis"
    if event_is_historical(event):
        return "historical"
    if "confirmed" in tags or event.metadata.get("confirmed") is True:
        return "confirmed"
    return "other"


def event_is_historical(event: Event) -> bool:
    tags = {tag.lower() for tag in event.tags}
    return bool(
        tags & {"historical", "archive", "wayback", "commoncrawl"}
        or event.metadata.get("historical") is True
        or event.metadata.get("historical_only") is True
    )


def normalized_optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split()).strip()
    return normalized or None
