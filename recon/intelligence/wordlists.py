"""Central wordlist/vocabulary corpus for Night Scout.

Combines local public wordlists, target-specific Event vocabulary, source
diversity, and historical hypothesis yield. The result directly satisfies the
candidate-provider contracts used by `workers/permutations.py` and
`workers/parameters.py`.

Runtime reconnaissance never downloads public wordlists from this module.
External corpora are cached by an explicit setup/update step and described by a
local YAML manifest. This keeps corpus provenance reproducible.

A token is TARGETED when the current target supplied evidence for it. A token
that exists only in global wordlists remains EXPLORATION. Therefore target
learning cannot starve long-tail global discovery, while target-only words that
do not exist in public lists can still become candidates immediately.

Persistent storage is intentionally abstracted behind:
    TargetEventProvider.events_for(seed_event)
    YieldFeedbackProvider.feedback_for(seed_event)

A future SQLite adapter can implement those protocols without coupling this
intelligence module to SQLAlchemy.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType
from recon.workers.parameters import ParameterCandidate, normalize_parameter_name
from recon.workers.passive_domains import normalize_dns_name
from recon.workers.permutations import (
    PermutationWord,
    normalize_candidate_label,
    token_to_candidate_labels,
)


class CorpusCategory(StrEnum):
    GENERAL = "general"
    DNS = "dns"
    PARAMETER = "parameter"
    PATH = "path"
    API = "api"
    VHOST = "vhost"
    PROJECT = "project"
    TECHNOLOGY = "technology"


class CorpusTier(StrEnum):
    MICRO = "micro"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    EXHAUSTIVE = "exhaustive"


TIER_LIMITS: dict[CorpusTier, int] = {
    CorpusTier.MICRO: 250,
    CorpusTier.SMALL: 2_000,
    CorpusTier.MEDIUM: 10_000,
    CorpusTier.LARGE: 50_000,
    CorpusTier.EXHAUSTIVE: 250_000,
}


class WordlistSourceSpec(BaseModel):
    """One local source in the corpus manifest."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    source_id: str = Field(alias="id")
    path: str

    categories: frozenset[CorpusCategory]

    weight: float = Field(default=1.0, ge=0.0, le=100.0)
    enabled: bool = True
    max_entries: int | None = Field(default=None, ge=1)

    encoding: str = "utf-8"
    comment_prefixes: tuple[str, ...] = ("#", ";")

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_id", "path", "encoding")
    @classmethod
    def required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("source_id")
    @classmethod
    def normalize_source_id(cls, value: str) -> str:
        value = value.strip().lower()

        if not re.fullmatch(
            r"[a-z0-9][a-z0-9_.:-]{0,127}",
            value,
        ):
            raise ValueError(
                "source id contains unsupported characters"
            )

        return value

    @field_validator("categories")
    @classmethod
    def require_categories(
        cls,
        values: frozenset[CorpusCategory],
    ) -> frozenset[CorpusCategory]:
        if not values:
            raise ValueError(
                "wordlist source needs at least one category"
            )
        return values

    @field_validator("comment_prefixes")
    @classmethod
    def normalize_comment_prefixes(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            value
            for value in values
            if value
        )

    @model_validator(mode="after")
    def reject_remote_runtime_source(
        self,
    ) -> "WordlistSourceSpec":
        if "://" in self.path.lower():
            raise ValueError(
                "wordlist source path must be local; "
                "runtime downloads are not supported"
            )

        return self


class WordlistManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    version: int = Field(default=1, ge=1)
    sources: tuple[WordlistSourceSpec, ...]

    @field_validator("sources")
    @classmethod
    def unique_source_ids(
        cls,
        values: tuple[WordlistSourceSpec, ...],
    ) -> tuple[WordlistSourceSpec, ...]:
        if not values:
            raise ValueError(
                "manifest must contain at least one source"
            )

        ids = [
            source.source_id
            for source in values
        ]

        if len(ids) != len(set(ids)):
            raise ValueError(
                "manifest source ids must be unique"
            )

        return values


class GlobalCorpusObservation(BaseModel):
    """One category-specific observation from one public source."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token: str
    category: CorpusCategory

    source_id: str
    rank: int = Field(ge=1)
    source_weight: float = Field(
        default=1.0,
        ge=0.0,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @field_validator("token", "source_id")
    @classmethod
    def required_text(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "must not be blank"
            )

        return value


class TargetTokenEvidence(BaseModel):
    """Target-specific token evidence with source/context provenance."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token: str
    categories: frozenset[CorpusCategory]

    source: str
    source_event_ids: tuple[str, ...] = ()
    contexts: frozenset[str] = Field(
        default_factory=frozenset
    )

    frequency: int = Field(
        default=1,
        ge=1,
    )
    relevance: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    labels: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @field_validator("token", "source")
    @classmethod
    def required_text(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "must not be blank"
            )

        return value

    @field_validator("categories")
    @classmethod
    def categories_required(
        cls,
        values: frozenset[CorpusCategory],
    ) -> frozenset[CorpusCategory]:
        if not values:
            raise ValueError(
                "target evidence categories cannot be empty"
            )

        return values

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

    @field_validator("contexts")
    @classmethod
    def normalize_contexts(
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
            label = normalize_candidate_label(
                value
            )

            if (
                label is not None
                and label not in result
            ):
                result.append(
                    label
                )

        return tuple(result)


class YieldFeedback(BaseModel):
    """Historical hypothesis attempts/successes for one token/category."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token: str
    category: CorpusCategory

    attempted_hypotheses: int = Field(
        default=0,
        ge=0,
    )
    successful_hits: int = Field(
        default=0,
        ge=0,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def successful_not_above_attempts(
        self,
    ) -> "YieldFeedback":
        if (
            self.successful_hits
            > self.attempted_hypotheses
        ):
            raise ValueError(
                "successful_hits cannot exceed attempted_hypotheses"
            )

        return self


class CorpusEntry(BaseModel):
    """Merged explainable state for one category/token."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token: str
    category: CorpusCategory

    global_sources: frozenset[str] = Field(
        default_factory=frozenset
    )
    target_sources: frozenset[str] = Field(
        default_factory=frozenset
    )

    source_event_ids: tuple[str, ...] = ()
    contexts: frozenset[str] = Field(
        default_factory=frozenset
    )

    global_rank: int | None = Field(
        default=None,
        ge=1,
    )
    global_score: float = Field(
        default=0.0,
        ge=0.0,
    )

    target_frequency: int = Field(
        default=0,
        ge=0,
    )
    target_source_diversity: int = Field(
        default=0,
        ge=0,
    )
    target_relevance: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    successful_hits: int = Field(
        default=0,
        ge=0,
    )
    attempted_hypotheses: int = Field(
        default=0,
        ge=0,
    )

    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    labels: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def is_targeted(self) -> bool:
        return bool(
            self.target_sources
            or self.target_frequency
            or self.target_source_diversity
            or self.target_relevance
        )

    @property
    def yield_ratio(self) -> float:
        if (
            self.attempted_hypotheses
            <= 0
        ):
            return 0.0

        return (
            self.successful_hits
            / self.attempted_hypotheses
        )


class CorpusBuildReport(BaseModel):
    """Compact explainability summary for one generated corpus view."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    global_observations: int = Field(ge=0)
    target_observations: int = Field(ge=0)
    feedback_observations: int = Field(ge=0)

    merged_entries: int = Field(ge=0)
    targeted_entries: int = Field(ge=0)
    exploration_entries: int = Field(ge=0)

    categories: dict[str, int] = Field(
        default_factory=dict
    )


class TargetEventProvider(Protocol):
    async def events_for(
        self,
        seed_event: Event,
    ) -> Sequence[Event]:
        ...


class YieldFeedbackProvider(Protocol):
    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[YieldFeedback]:
        ...


class GlobalCorpusProvider(Protocol):
    async def observations(
        self,
    ) -> Sequence[GlobalCorpusObservation]:
        ...


class StaticTargetEventProvider:
    def __init__(
        self,
        events: Sequence[Event],
    ) -> None:
        self._events = tuple(events)

    async def events_for(
        self,
        seed_event: Event,
    ) -> Sequence[Event]:
        del seed_event
        return self._events


class StaticYieldFeedbackProvider:
    def __init__(
        self,
        feedback: Sequence[YieldFeedback],
    ) -> None:
        self._feedback = tuple(feedback)

    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[YieldFeedback]:
        del seed_event
        return self._feedback


class EmptyTargetEvents:
    async def events_for(
        self,
        seed_event: Event,
    ) -> Sequence[Event]:
        del seed_event
        return ()


class NoYieldFeedback:
    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[YieldFeedback]:
        del seed_event
        return ()


class StaticGlobalCorpus:
    def __init__(
        self,
        observations: Sequence[GlobalCorpusObservation],
    ) -> None:
        self._observations = tuple(
            observations
        )

    async def observations(
        self,
    ) -> Sequence[GlobalCorpusObservation]:
        return self._observations


class ManifestGlobalCorpus:
    """Load attributed global corpora from a local YAML manifest."""

    def __init__(
        self,
        manifest_path: Path,
        *,
        corpus_root: Path | None = None,
        max_line_length: int = 4096,
        max_total_observations: int = 2_000_000,
    ) -> None:
        if (
            max_line_length <= 0
            or max_total_observations <= 0
        ):
            raise ValueError(
                "manifest corpus limits must be positive"
            )

        self._manifest_path = (
            manifest_path.expanduser()
            .resolve()
        )

        self._corpus_root = (
            corpus_root.expanduser().resolve()
            if corpus_root is not None
            else self._manifest_path.parent
        )

        self._max_line_length = (
            max_line_length
        )
        self._max_total_observations = (
            max_total_observations
        )

        self._cache: tuple[
            GlobalCorpusObservation,
            ...
        ] | None = None

        self._lock = asyncio.Lock()

    @property
    def manifest_path(
        self,
    ) -> Path:
        return self._manifest_path

    @property
    def corpus_root(
        self,
    ) -> Path:
        return self._corpus_root

    async def observations(
        self,
    ) -> Sequence[
        GlobalCorpusObservation
    ]:
        async with self._lock:
            if self._cache is None:
                self._cache = await asyncio.to_thread(
                    self._load_sync
                )

            return self._cache

    async def refresh(
        self,
    ) -> Sequence[
        GlobalCorpusObservation
    ]:
        async with self._lock:
            self._cache = await asyncio.to_thread(
                self._load_sync
            )

            return self._cache

    def load_manifest(
        self,
    ) -> WordlistManifest:
        raw = (
            self._manifest_path.read_text(
                encoding="utf-8"
            )
        )

        document = yaml.safe_load(
            raw
        )

        if not isinstance(
            document,
            dict,
        ):
            raise ValueError(
                "wordlist manifest root must be a mapping"
            )

        return WordlistManifest.model_validate(
            document
        )

    def _load_sync(
        self,
    ) -> tuple[
        GlobalCorpusObservation,
        ...
    ]:
        manifest = self.load_manifest()
        result: list[
            GlobalCorpusObservation
        ] = []

        for source in (
            manifest.sources
        ):
            if not source.enabled:
                continue

            source_path = (
                self._resolve_source_path(
                    source
                )
            )

            result.extend(
                self._load_source(
                    source,
                    source_path=source_path,
                )
            )

            if (
                len(result)
                > self._max_total_observations
            ):
                raise ValueError(
                    "global corpus exceeds configured observation limit "
                    f"{self._max_total_observations}"
                )

        return tuple(result)

    def _resolve_source_path(
        self,
        source: WordlistSourceSpec,
    ) -> Path:
        raw = Path(
            source.path
        )

        path = (
            raw.expanduser().resolve()
            if raw.is_absolute()
            else (
                self._corpus_root
                / raw
            ).resolve()
        )

        try:
            path.relative_to(
                self._corpus_root
            )
        except ValueError as exc:
            raise ValueError(
                "wordlist source escapes corpus_root: "
                f"{source.source_id}"
            ) from exc

        if not path.is_file():
            raise FileNotFoundError(
                f"wordlist source not found: {path}"
            )

        return path

    def _load_source(
        self,
        source: WordlistSourceSpec,
        *,
        source_path: Path,
    ) -> tuple[
        GlobalCorpusObservation,
        ...
    ]:
        result: list[
            GlobalCorpusObservation
        ] = []

        rank = 0

        with source_path.open(
            "r",
            encoding=source.encoding,
            errors="replace",
        ) as handle:
            for raw_line in handle:
                if (
                    len(raw_line)
                    > self._max_line_length
                ):
                    continue

                line = raw_line.strip()

                if (
                    not line
                    or any(
                        line.startswith(
                            prefix
                        )
                        for prefix
                        in source.comment_prefixes
                    )
                ):
                    continue

                rank += 1

                for category in (
                    source.categories
                ):
                    token = (
                        normalize_global_token(
                            line,
                            category=category,
                        )
                    )

                    if token is None:
                        continue

                    result.append(
                        GlobalCorpusObservation(
                            token=token,
                            category=category,
                            source_id=(
                                source.source_id
                            ),
                            rank=rank,
                            source_weight=(
                                source.weight
                            ),
                            metadata={
                                "source_path": (
                                    source.path
                                ),
                                **source.metadata,
                            },
                        )
                    )

                if (
                    source.max_entries
                    is not None
                    and rank
                    >= source.max_entries
                ):
                    break

        return tuple(result)


class WordlistCorpusConfig(BaseModel):
    """Bounded worker-facing views of the merged corpus."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    dns_tier: CorpusTier = (
        CorpusTier.MEDIUM
    )
    parameter_tier: CorpusTier = (
        CorpusTier.MEDIUM
    )

    max_target_dns_entries: int = Field(
        default=50_000,
        ge=1,
        le=1_000_000,
    )

    max_target_parameter_entries: int = Field(
        default=50_000,
        ge=1,
        le=1_000_000,
    )

    include_general_in_dns: bool = True
    include_general_in_parameters: bool = True

    max_target_events: int = Field(
        default=250_000,
        ge=1,
        le=5_000_000,
    )

    max_projected_evidence: int = Field(
        default=500_000,
        ge=1,
        le=10_000_000,
    )

    target_frequency_log_scale: float = Field(
        default=0.12,
        ge=0.0,
        le=1.0,
    )

    target_diversity_scale: float = Field(
        default=0.08,
        ge=0.0,
        le=1.0,
    )


class WordlistCorpus:
    """Unified provider for permutations and parameter-discovery workers."""

    def __init__(
        self,
        *,
        global_corpus: GlobalCorpusProvider,
        target_events: TargetEventProvider | None = None,
        yield_feedback: YieldFeedbackProvider | None = None,
        config: WordlistCorpusConfig | None = None,
    ) -> None:
        self._global = (
            global_corpus
        )

        self._target_events = (
            target_events
            or EmptyTargetEvents()
        )

        self._yield_feedback = (
            yield_feedback
            or NoYieldFeedback()
        )

        self._config = (
            config
            or WordlistCorpusConfig()
        )

    async def entries_for(
        self,
        seed_event: Event,
    ) -> tuple[
        tuple[CorpusEntry, ...],
        CorpusBuildReport,
    ]:
        global_observations = tuple(
            await self._global.observations()
        )

        events = tuple(
            await self._target_events.events_for(
                seed_event
            )
        )[
            : self._config.max_target_events
        ]

        target_evidence = (
            project_events_to_target_evidence(
                events,
                seed_event=seed_event,
                max_evidence=(
                    self._config.max_projected_evidence
                ),
            )
        )

        feedback = tuple(
            await self._yield_feedback.feedback_for(
                seed_event
            )
        )

        entries = merge_corpus(
            global_observations,
            target_evidence,
            feedback,
            config=self._config,
        )

        categories = Counter(
            entry.category.value
            for entry in entries
        )

        report = CorpusBuildReport(
            global_observations=len(
                global_observations
            ),
            target_observations=len(
                target_evidence
            ),
            feedback_observations=len(
                feedback
            ),
            merged_entries=len(
                entries
            ),
            targeted_entries=sum(
                entry.is_targeted
                for entry in entries
            ),
            exploration_entries=sum(
                not entry.is_targeted
                for entry in entries
            ),
            categories=dict(
                sorted(
                    categories.items()
                )
            ),
        )

        return entries, report

    async def words_for(
        self,
        seed_event: Event,
    ) -> Sequence[
        PermutationWord
    ]:
        """Implement workers.permutations.WordCorpusProvider."""

        entries, _report = (
            await self.entries_for(
                seed_event
            )
        )

        allowed = {
            CorpusCategory.DNS,
            CorpusCategory.VHOST,
        }

        if (
            self._config.include_general_in_dns
        ):
            allowed.add(
                CorpusCategory.GENERAL
            )

        targeted: list[
            CorpusEntry
        ] = []

        exploration: list[
            CorpusEntry
        ] = []

        for entry in entries:
            if (
                entry.category
                not in allowed
            ):
                continue

            if not (
                entry.labels
                or token_to_candidate_labels(
                    entry.token
                )
            ):
                continue

            if entry.is_targeted:
                targeted.append(
                    entry
                )
            else:
                exploration.append(
                    entry
                )

        targeted = sorted(
            targeted,
            key=corpus_targeted_sort_key,
        )[
            : self._config.max_target_dns_entries
        ]

        exploration = sorted(
            exploration,
            key=corpus_exploration_sort_key,
        )[
            : TIER_LIMITS[
                self._config.dns_tier
            ]
        ]

        return merge_permutation_words(
            tuple(
                entry_to_permutation_word(
                    entry
                )
                for entry in (
                    *targeted,
                    *exploration,
                )
            )
        )

    async def candidates_for(
        self,
        endpoint_event: Event,
    ) -> Sequence[
        ParameterCandidate
    ]:
        """Implement workers.parameters.ParameterCandidateProvider."""

        entries, _report = (
            await self.entries_for(
                endpoint_event
            )
        )

        allowed = {
            CorpusCategory.PARAMETER
        }

        if (
            self._config.include_general_in_parameters
        ):
            allowed.add(
                CorpusCategory.GENERAL
            )

        targeted: list[
            CorpusEntry
        ] = []

        exploration: list[
            CorpusEntry
        ] = []

        for entry in entries:
            if (
                entry.category
                not in allowed
            ):
                continue

            if (
                entry.category is CorpusCategory.GENERAL
                and entry.token.isdigit()
            ):
                continue

            try:
                normalize_parameter_name(
                    entry.token
                )
            except ValueError:
                continue

            if entry.is_targeted:
                targeted.append(
                    entry
                )
            else:
                exploration.append(
                    entry
                )

        targeted = sorted(
            targeted,
            key=corpus_targeted_sort_key,
        )[
            : self._config.max_target_parameter_entries
        ]

        exploration = sorted(
            exploration,
            key=corpus_exploration_sort_key,
        )[
            : TIER_LIMITS[
                self._config.parameter_tier
            ]
        ]

        return (
            merge_parameter_candidates(
                tuple(
                    entry_to_parameter_candidate(
                        entry
                    )
                    for entry in (
                        *targeted,
                        *exploration,
                    )
                )
            )
        )


def merge_corpus(
    global_observations: Sequence[
        GlobalCorpusObservation
    ],
    target_evidence: Sequence[
        TargetTokenEvidence
    ],
    feedback: Sequence[
        YieldFeedback
    ],
    *,
    config: WordlistCorpusConfig | None = None,
) -> tuple[
    CorpusEntry,
    ...
]:
    """Merge global, target and yield evidence without losing provenance."""

    cfg = (
        config
        or WordlistCorpusConfig()
    )

    state: dict[
        tuple[
            CorpusCategory,
            str,
        ],
        dict[str, Any],
    ] = {}

    def ensure(
        category: CorpusCategory,
        token: str,
    ) -> dict[str, Any] | None:
        normalized = (
            normalize_token_for_category(
                token,
                category=category,
            )
        )

        if normalized is None:
            return None

        key = corpus_key(
            normalized,
            category=category,
        )

        existing = state.get(
            key
        )

        if existing is not None:
            return existing

        value: dict[str, Any] = {
            "token": normalized,
            "category": category,
            "global_sources": set(),
            "target_sources": set(),
            "source_families": set(),
            "source_event_ids": set(),
            "contexts": set(),
            "global_rank": None,
            "global_score": 0.0,
            "target_frequency": 0,
            "base_relevance": 0.0,
            "successful_hits": 0,
            "attempted_hypotheses": 0,
            "confidence": 0.5,
            "labels": [],
            "metadata": {},
        }

        state[
            key
        ] = value

        return value

    for observation in (
        global_observations
    ):
        item = ensure(
            observation.category,
            observation.token,
        )

        if item is None:
            continue

        item[
            "global_sources"
        ].add(
            observation.source_id
        )

        current_rank = item[
            "global_rank"
        ]

        if (
            current_rank is None
            or observation.rank
            < current_rank
        ):
            item[
                "global_rank"
            ] = observation.rank

        item[
            "global_score"
        ] += (
            global_observation_score(
                observation
            )
        )

        item[
            "metadata"
        ].setdefault(
            "global_source_metadata",
            {},
        )[
            observation.source_id
        ] = dict(
            observation.metadata
        )

    for evidence in (
        target_evidence
    ):
        for category in (
            evidence.categories
        ):
            item = ensure(
                category,
                evidence.token,
            )

            if item is None:
                continue

            item[
                "target_sources"
            ].add(
                evidence.source
            )

            item[
                "source_families"
            ].add(
                source_family(
                    evidence.source
                )
            )

            item[
                "source_event_ids"
            ].update(
                evidence.source_event_ids
            )

            item[
                "contexts"
            ].update(
                evidence.contexts
            )

            item[
                "target_frequency"
            ] += evidence.frequency

            item[
                "base_relevance"
            ] = max(
                item[
                    "base_relevance"
                ],
                evidence.relevance,
            )

            item[
                "confidence"
            ] = max(
                item[
                    "confidence"
                ],
                evidence.confidence,
            )

            for label in (
                evidence.labels
            ):
                if (
                    label
                    not in item[
                        "labels"
                    ]
                ):
                    item[
                        "labels"
                    ].append(
                        label
                    )

            samples = item[
                "metadata"
            ].setdefault(
                "target_evidence_samples",
                [],
            )

            if (
                len(samples)
                < 64
            ):
                samples.append(
                    {
                        "source": (
                            evidence.source
                        ),
                        "event_ids": list(
                            evidence.source_event_ids
                        ),
                        "contexts": sorted(
                            evidence.contexts
                        ),
                        "relevance": (
                            evidence.relevance
                        ),
                    }
                )

    for feedback_item in (
        feedback
    ):
        item = ensure(
            feedback_item.category,
            feedback_item.token,
        )

        if item is None:
            continue

        item[
            "successful_hits"
        ] += (
            feedback_item.successful_hits
        )

        item[
            "attempted_hypotheses"
        ] += (
            feedback_item.attempted_hypotheses
        )

        feedback_samples = item[
            "metadata"
        ].setdefault(
            "yield_feedback",
            [],
        )

        if (
            len(feedback_samples)
            < 32
        ):
            feedback_samples.append(
                dict(
                    feedback_item.metadata
                )
            )

    entries: list[
        CorpusEntry
    ] = []

    for item in (
        state.values()
    ):
        frequency = int(
            item[
                "target_frequency"
            ]
        )

        diversity = len(
            item[
                "source_families"
            ]
        )

        relevance = min(
            1.0,
            float(
                item[
                    "base_relevance"
                ]
            )
            + math.log1p(
                frequency
            )
            * cfg.target_frequency_log_scale
            + diversity
            * cfg.target_diversity_scale,
        )

        labels = tuple(
            item[
                "labels"
            ]
        )

        if (
            not labels
            and item[
                "category"
            ]
            in {
                CorpusCategory.GENERAL,
                CorpusCategory.DNS,
                CorpusCategory.VHOST,
            }
        ):
            labels = (
                token_to_candidate_labels(
                    item[
                        "token"
                    ]
                )
            )

        entries.append(
            CorpusEntry(
                token=item[
                    "token"
                ],
                category=item[
                    "category"
                ],
                global_sources=frozenset(
                    item[
                        "global_sources"
                    ]
                ),
                target_sources=frozenset(
                    item[
                        "target_sources"
                    ]
                ),
                source_event_ids=tuple(
                    sorted(
                        item[
                            "source_event_ids"
                        ]
                    )
                ),
                contexts=frozenset(
                    item[
                        "contexts"
                    ]
                ),
                global_rank=item[
                    "global_rank"
                ],
                global_score=item[
                    "global_score"
                ],
                target_frequency=frequency,
                target_source_diversity=(
                    diversity
                ),
                target_relevance=relevance,
                successful_hits=item[
                    "successful_hits"
                ],
                attempted_hypotheses=item[
                    "attempted_hypotheses"
                ],
                confidence=item[
                    "confidence"
                ],
                labels=labels,
                metadata={
                    **item[
                        "metadata"
                    ],
                    "target_source_families": sorted(
                        item[
                            "source_families"
                        ]
                    ),
                },
            )
        )

    return tuple(
        sorted(
            entries,
            key=lambda entry: (
                entry.category.value,
                canonical_token_key(
                    entry.token,
                    category=(
                        entry.category
                    ),
                ),
            ),
        )
    )


def project_events_to_target_evidence(
    events: Sequence[Event],
    *,
    seed_event: Event,
    max_evidence: int = 500_000,
) -> tuple[
    TargetTokenEvidence,
    ...
]:
    """Project existing Event observations into target vocabulary evidence."""

    if max_evidence <= 0:
        return ()

    result: list[
        TargetTokenEvidence
    ] = []

    for event in events:
        if (
            len(result)
            >= max_evidence
        ):
            break

        result.extend(
            project_event(
                event,
                seed_event=seed_event,
                limit=(
                    max_evidence
                    - len(result)
                ),
            )
        )

    return tuple(
        result[
            :max_evidence
        ]
    )


def project_event(
    event: Event,
    *,
    seed_event: Event,
    limit: int = 10_000,
) -> tuple[
    TargetTokenEvidence,
    ...
]:
    """Convert one Event into category-specific target evidence."""

    if limit <= 0:
        return ()

    result: list[
        TargetTokenEvidence
    ] = []

    def add(
        token: str,
        *,
        categories: Iterable[
            CorpusCategory
        ],
        context: str,
        relevance: float,
        labels: Sequence[str] = (),
        preserve_case: bool = False,
    ) -> None:
        if (
            len(result)
            >= limit
        ):
            return

        normalized = (
            token.strip()
            if preserve_case
            else normalize_general_token(
                token
            )
        )

        if not normalized:
            return

        result.append(
            TargetTokenEvidence(
                token=normalized,
                categories=frozenset(
                    categories
                ),
                source=(
                    event.source
                    or "unknown"
                ),
                source_event_ids=(
                    event.event_id,
                ),
                contexts=frozenset(
                    {
                        context,
                        *(
                            tag.lower()
                            for tag
                            in event.tags
                        ),
                    }
                ),
                frequency=(
                    event_occurrence_count(
                        event
                    )
                ),
                relevance=relevance,
                confidence=(
                    event.confidence
                ),
                labels=tuple(
                    labels
                ),
                metadata={
                    "event_type": (
                        event.type.value
                    ),
                },
            )
        )

    if (
        event.type
        is EventType.VOCAB_TOKEN
    ):
        add(
            event.value,
            categories=(
                vocab_event_categories(
                    event
                )
            ),
            context="vocab-token",
            relevance=0.95,
            labels=(
                event_dns_labels(
                    event
                )
            ),
        )

        return tuple(
            result
        )

    if (
        event.type
        is EventType.PARAMETER_NAME
    ):
        try:
            name = (
                normalize_parameter_name(
                    event.value
                )
            )
        except ValueError:
            return ()

        add(
            name,
            categories=(
                CorpusCategory.PARAMETER,
                CorpusCategory.GENERAL,
            ),
            context="parameter",
            relevance=1.0,
            preserve_case=True,
        )

        return tuple(
            result
        )

    if (
        event.type
        in {
            EventType.DNS_NAME,
            EventType.CERT_SAN,
        }
    ):
        for label in (
            hostname_labels_from_event(
                event,
                seed_event=seed_event,
            )
        ):
            hostname_context = (
                "certificate-san"
                if event.type
                is EventType.CERT_SAN
                else "hostname"
            )
            hostname_relevance = (
                0.85
                if event.type
                is EventType.CERT_SAN
                else 1.0
            )

            # Preserve the observed compound label and also feed its
            # components into the Target Genome.
            add(
                label,
                categories=(
                    CorpusCategory.DNS,
                    CorpusCategory.VHOST,
                    CorpusCategory.GENERAL,
                ),
                context=hostname_context,
                relevance=hostname_relevance,
                labels=(label,),
            )

            for component in tokenize_text(label):
                if component == label:
                    continue
                add(
                    component,
                    categories=(
                        CorpusCategory.DNS,
                        CorpusCategory.VHOST,
                        CorpusCategory.GENERAL,
                    ),
                    context=f"{hostname_context}-component",
                    relevance=max(0.0, hostname_relevance - 0.08),
                    labels=(component,),
                )

        return tuple(
            result
        )

    if (
        event.type
        in {
            EventType.URL,
            EventType.URL_PATH,
            EventType.API_ENDPOINT,
            EventType.JAVASCRIPT,
            EventType.ARTIFACT,
        }
    ):
        for (
            token,
            context,
        ) in (
            tokens_from_urlish_event(
                event
            )
        ):
            categories = {
                CorpusCategory.GENERAL,
                CorpusCategory.PATH,
            }

            relevance = 0.65

            if (
                event.type
                is EventType.API_ENDPOINT
                or context
                == "api-path"
            ):
                categories.add(
                    CorpusCategory.API
                )
                relevance = 0.85

            if (
                context
                == "parameter"
            ):
                categories.add(
                    CorpusCategory.PARAMETER
                )
                relevance = max(
                    relevance,
                    0.90,
                )

            add(
                token,
                categories=categories,
                context=context,
                relevance=relevance,
                preserve_case=(context == "parameter"),
            )

        return tuple(
            result
        )

    if (
        event.type
        is EventType.PROJECT_NAME
    ):
        for token in (
            tokenize_text(
                event.value
            )
        ):
            add(
                token,
                categories=(
                    CorpusCategory.PROJECT,
                    CorpusCategory.GENERAL,
                    CorpusCategory.DNS,
                ),
                context="project-name",
                relevance=0.90,
            )

        return tuple(
            result
        )

    if (
        event.type
        is EventType.TECHNOLOGY
    ):
        for token in (
            tokenize_text(
                event.value
            )
        ):
            add(
                token,
                categories=(
                    CorpusCategory.TECHNOLOGY,
                    CorpusCategory.GENERAL,
                ),
                context="technology",
                relevance=0.55,
            )

    return tuple(
        result
    )


def hostname_labels_from_event(
    event: Event,
    *,
    seed_event: Event,
) -> tuple[str, ...]:
    """Extract hostname labels without adding the known target root suffix."""

    raw = (
        event.value.strip()
    )

    if raw.startswith(
        "*."
    ):
        raw = raw[2:]

    try:
        hostname = normalize_dns_name(
            raw
        )
    except ValueError:
        return ()

    labels = hostname.split(
        "."
    )

    root = infer_seed_domain(
        seed_event
    )

    if (
        root is not None
        and (
            hostname == root
            or hostname.endswith(
                "." + root
            )
        )
    ):
        relative_count = (
            len(labels)
            - len(
                root.split(".")
            )
        )

        labels = labels[
            : max(
                0,
                relative_count,
            )
        ]

    elif (
        len(labels)
        >= 3
    ):
        labels = labels[
            :-2
        ]

    else:
        labels = labels[
            :1
        ]

    result: list[str] = []

    for label in labels:
        normalized = (
            normalize_general_token(
                label
            )
        )

        if (
            normalized is not None
            and normalized
            not in result
        ):
            result.append(
                normalized
            )

    return tuple(
        result
    )


def tokens_from_urlish_event(
    event: Event,
) -> tuple[
    tuple[str, str],
    ...
]:
    """Extract URL/path/query-name vocabulary; query values are discarded."""

    value = (
        event.value.strip()
    )

    result: list[
        tuple[str, str]
    ] = []

    if "://" in value:
        try:
            parsed = urlsplit(
                value
            )
        except ValueError:
            parsed = None

        if (
            parsed is not None
            and parsed.scheme.lower()
            in {
                "http",
                "https",
            }
        ):
            for segment in (
                (
                    parsed.path
                    or "/"
                ).split(
                    "/"
                )
            ):
                context = (
                    "api-path"
                    if segment_has_api_token(
                        segment
                    )
                    else "url-path"
                )

                for token in (
                    tokenize_text(
                        segment
                    )
                ):
                    result.append(
                        (
                            token,
                            context,
                        )
                    )

            if parsed.query:
                try:
                    pairs = parse_qsl(
                        parsed.query,
                        keep_blank_values=True,
                        strict_parsing=False,
                        max_num_fields=4096,
                    )
                except ValueError:
                    pairs = []

                for (
                    name,
                    _value,
                ) in pairs:
                    try:
                        normalized = normalize_parameter_name(name)
                    except ValueError:
                        normalized = None

                    if normalized is not None:
                        result.append(
                            (
                                normalized,
                                "parameter",
                            )
                        )

    else:
        # Current URL_PATH values are host-aware:
        # api.example.com/internal-api/v3/orders
        pathish = value

        slash = (
            pathish.find(
                "/"
            )
        )

        if slash >= 0:
            pathish = pathish[
                slash:
            ]

        for segment in (
            pathish.split(
                "/"
            )
        ):
            context = (
                "api-path"
                if segment_has_api_token(
                    segment
                )
                else "url-path"
            )

            for token in (
                tokenize_text(
                    segment
                )
            ):
                result.append(
                    (
                        token,
                        context,
                    )
                )

    deduped: list[
        tuple[str, str]
    ] = []

    seen: set[
        tuple[str, str]
    ] = set()

    for item in result:
        if item in seen:
            continue

        seen.add(
            item
        )

        deduped.append(
            item
        )

    return tuple(
        deduped
    )


def tokenize_text(
    value: str,
) -> tuple[str, ...]:
    """Conservative path/project/technology tokenization."""

    result: list[str] = []

    for coarse in re.split(
        r"[^A-Za-z0-9]+",
        value,
    ):
        if not coarse:
            continue

        for part in re.split(
            r"(?<=[a-z0-9])(?=[A-Z])",
            coarse,
        ):
            normalized = (
                normalize_general_token(
                    part
                )
            )

            if (
                normalized is not None
                and normalized
                not in result
            ):
                result.append(
                    normalized
                )

    return tuple(
        result
    )


def normalize_global_token(
    value: str,
    *,
    category: CorpusCategory,
) -> str | None:
    if (
        category
        is CorpusCategory.PARAMETER
    ):
        try:
            return normalize_parameter_name(
                value
            )
        except ValueError:
            return None

    if category in {
        CorpusCategory.DNS,
        CorpusCategory.VHOST,
    }:
        return normalize_candidate_label(
            value
        )

    return normalize_general_token(
        value
    )


def normalize_general_token(
    value: str,
) -> str | None:
    """Normalize useful target vocabulary while filtering obvious noise."""

    normalized = (
        value.strip()
        .lower()
    )

    if (
        not normalized
        or len(normalized) < 2
        or len(normalized) > 128
    ):
        return None

    if normalized.isdigit():
        # Keep short numeric target vocabulary such as 01/02/2026 for the
        # future pattern engine, but reject long numeric noise.
        return normalized if len(normalized) <= 6 else None

    if (
        not any(
            character.isalpha()
            for character
            in normalized
        )
        and not re.fullmatch(
            r"v[0-9]{1,4}",
            normalized,
        )
    ):
        return None

    if (
        len(normalized) >= 24
        and looks_hash_like(
            normalized
        )
    ):
        return None

    if (
        re.fullmatch(
            r"[a-z0-9_.\-\[\]]+",
            normalized,
        )
        is None
    ):
        return None

    return normalized


def normalize_token_for_category(
    value: str,
    *,
    category: CorpusCategory,
) -> str | None:
    return normalize_global_token(
        value,
        category=category,
    )


def canonical_token_key(
    value: str,
    *,
    category: CorpusCategory,
) -> str:
    """Parameter names may be case-sensitive; other categories are not."""

    normalized = (
        normalize_token_for_category(
            value,
            category=category,
        )
    )

    if normalized is None:
        return value.strip()

    if (
        category
        is CorpusCategory.PARAMETER
    ):
        return normalized

    return normalized.lower()


def corpus_key(
    token: str,
    *,
    category: CorpusCategory,
) -> tuple[
    CorpusCategory,
    str,
]:
    return (
        category,
        canonical_token_key(
            token,
            category=category,
        ),
    )


def global_observation_score(
    observation: GlobalCorpusObservation,
) -> float:
    """Small rank-decayed public-list score; target evidence stays dominant."""

    return (
        observation.source_weight
        * (
            1.0
            / math.log2(
                observation.rank
                + 1
            )
        )
        * 0.5
    )


def source_family(
    source: str,
) -> str:
    """Collapse javascript:static/javascript:url-query into one source family."""

    normalized = (
        source.strip()
        .lower()
    )

    if not normalized:
        return "unknown"

    return (
        normalized.split(
            ":",
            1,
        )[0]
        or "unknown"
    )


def entry_to_permutation_word(
    entry: CorpusEntry,
) -> PermutationWord:
    return PermutationWord(
        token=entry.token,
        global_sources=(
            entry.global_sources
        ),
        target_sources=(
            entry.target_sources
        ),
        global_score=(
            entry.global_score
        ),
        global_rank=(
            entry.global_rank
        ),
        target_frequency=(
            entry.target_frequency
        ),
        target_source_diversity=(
            entry.target_source_diversity
        ),
        target_relevance=(
            entry.target_relevance
        ),
        successful_hits=(
            entry.successful_hits
        ),
        attempted_hypotheses=(
            entry.attempted_hypotheses
        ),
        confidence=(
            entry.confidence
        ),
        labels=entry.labels,
        metadata={
            **entry.metadata,
            "corpus_category": (
                entry.category.value
            ),
            "contexts": sorted(
                entry.contexts
            ),
            "source_event_ids": list(
                entry.source_event_ids
            ),
        },
    )


def entry_to_parameter_candidate(
    entry: CorpusEntry,
) -> ParameterCandidate:
    return ParameterCandidate(
        name=normalize_parameter_name(
            entry.token
        ),
        global_sources=(
            entry.global_sources
        ),
        target_sources=(
            entry.target_sources
        ),
        global_rank=(
            entry.global_rank
        ),
        global_score=(
            entry.global_score
        ),
        target_frequency=(
            entry.target_frequency
        ),
        target_source_diversity=(
            entry.target_source_diversity
        ),
        target_relevance=(
            entry.target_relevance
        ),
        successful_hits=(
            entry.successful_hits
        ),
        attempted_hypotheses=(
            entry.attempted_hypotheses
        ),
        confidence=(
            entry.confidence
        ),
        metadata={
            **entry.metadata,
            "corpus_category": (
                entry.category.value
            ),
            "contexts": sorted(
                entry.contexts
            ),
            "source_event_ids": list(
                entry.source_event_ids
            ),
        },
    )


def merge_permutation_words(
    words: Sequence[
        PermutationWord
    ],
) -> tuple[
    PermutationWord,
    ...
]:
    """Merge GENERAL/DNS/VHOST views without double-counting one token."""

    merged: dict[
        str,
        PermutationWord
    ] = {}

    for word in words:
        key = (
            word.token.strip()
            .lower()
        )

        existing = merged.get(
            key
        )

        if existing is None:
            merged[
                key
            ] = word
            continue

        target_sources = (
            existing.target_sources
            | word.target_sources
        )

        merged[
            key
        ] = PermutationWord(
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
            global_rank=best_rank(
                existing.global_rank,
                word.global_rank,
            ),
            target_frequency=max(
                existing.target_frequency,
                word.target_frequency,
            ),
            target_source_diversity=max(
                existing.target_source_diversity,
                word.target_source_diversity,
                len(
                    {
                        source_family(
                            source
                        )
                        for source
                        in target_sources
                    }
                ),
            ),
            target_relevance=max(
                existing.target_relevance,
                word.target_relevance,
            ),
            successful_hits=max(
                existing.successful_hits,
                word.successful_hits,
            ),
            attempted_hypotheses=max(
                existing.attempted_hypotheses,
                word.attempted_hypotheses,
            ),
            confidence=max(
                existing.confidence,
                word.confidence,
            ),
            labels=tuple(
                dict.fromkeys(
                    (
                        *existing.labels,
                        *word.labels,
                    )
                )
            ),
            metadata={
                **existing.metadata,
                **word.metadata,
            },
        )

    return tuple(
        merged.values()
    )


def merge_parameter_candidates(
    candidates: Sequence[
        ParameterCandidate
    ],
) -> tuple[
    ParameterCandidate,
    ...
]:
    """Merge PARAMETER/GENERAL views by exact parameter name."""

    merged: dict[
        str,
        ParameterCandidate
    ] = {}

    for candidate in candidates:
        existing = merged.get(
            candidate.name
        )

        if existing is None:
            merged[
                candidate.name
            ] = candidate
            continue

        target_sources = (
            existing.target_sources
            | candidate.target_sources
        )

        merged[
            candidate.name
        ] = ParameterCandidate(
            name=existing.name,
            global_sources=(
                existing.global_sources
                | candidate.global_sources
            ),
            target_sources=target_sources,
            global_rank=best_rank(
                existing.global_rank,
                candidate.global_rank,
            ),
            global_score=max(
                existing.global_score,
                candidate.global_score,
            ),
            target_frequency=max(
                existing.target_frequency,
                candidate.target_frequency,
            ),
            target_source_diversity=max(
                existing.target_source_diversity,
                candidate.target_source_diversity,
                len(
                    {
                        source_family(
                            source
                        )
                        for source
                        in target_sources
                    }
                ),
            ),
            target_relevance=max(
                existing.target_relevance,
                candidate.target_relevance,
            ),
            successful_hits=max(
                existing.successful_hits,
                candidate.successful_hits,
            ),
            attempted_hypotheses=max(
                existing.attempted_hypotheses,
                candidate.attempted_hypotheses,
            ),
            confidence=max(
                existing.confidence,
                candidate.confidence,
            ),
            metadata={
                **existing.metadata,
                **candidate.metadata,
            },
        )

    return tuple(
        merged.values()
    )


def corpus_targeted_sort_key(
    entry: CorpusEntry,
) -> tuple[
    float,
    int,
    int,
    str,
]:
    rank_bonus = (
        1.0
        / math.log2(
            entry.global_rank
            + 1
        )
        if entry.global_rank
        is not None
        else 0.0
    )

    score = (
        entry.target_relevance
        * 4.0
        + math.log1p(
            entry.target_frequency
        )
        * 1.5
        + entry.target_source_diversity
        + entry.yield_ratio
        * 3.0
        + entry.global_score
        + rank_bonus
        + entry.confidence
        * 0.25
    )

    return (
        -score,
        -entry.target_source_diversity,
        -entry.target_frequency,
        entry.token,
    )


def corpus_exploration_sort_key(
    entry: CorpusEntry,
) -> tuple[
    int,
    float,
    str,
]:
    return (
        (
            entry.global_rank
            if entry.global_rank
            is not None
            else 2**31
        ),
        -entry.global_score,
        entry.token,
    )


def infer_seed_domain(
    event: Event,
) -> str | None:
    explicit = (
        event.metadata.get(
            "seed_domain"
        )
    )

    if isinstance(
        explicit,
        str,
    ):
        try:
            return normalize_dns_name(
                explicit
            )
        except ValueError:
            pass

    if (
        event.type
        in {
            EventType.ROOT_DOMAIN,
            EventType.DNS_NAME,
        }
    ):
        try:
            return normalize_dns_name(
                event.value
            )
        except ValueError:
            return None

    if (
        event.type
        in {
            EventType.URL,
            EventType.API_ENDPOINT,
            EventType.JAVASCRIPT,
            EventType.ARTIFACT,
            EventType.HTTP_SERVICE,
        }
    ):
        try:
            parts = urlsplit(
                event.value
            )
        except ValueError:
            return None

        if (
            parts.hostname
            is None
        ):
            return None

        try:
            return normalize_dns_name(
                parts.hostname
            )
        except ValueError:
            return None

    return None


def vocab_event_categories(
    event: Event,
) -> tuple[
    CorpusCategory,
    ...
]:
    raw = event.metadata.get(
        "vocabulary_categories"
    )

    if isinstance(
        raw,
        str,
    ):
        values: Sequence[Any] = (
            raw,
        )
    elif isinstance(
        raw,
        (
            list,
            tuple,
            set,
        ),
    ):
        values = tuple(
            raw
        )
    else:
        values = ()

    result: list[
        CorpusCategory
    ] = []

    for value in values:
        try:
            category = CorpusCategory(
                str(
                    value
                )
                .strip()
                .lower()
            )
        except ValueError:
            continue

        if (
            category
            not in result
        ):
            result.append(
                category
            )

    return tuple(
        result
        or [
            CorpusCategory.GENERAL
        ]
    )


def event_dns_labels(
    event: Event,
) -> tuple[str, ...]:
    values: tuple[str, ...]
    raw = event.metadata.get(
        "dns_labels"
    )

    if isinstance(
        raw,
        str,
    ):
        values = (
            raw,
        )
    elif isinstance(
        raw,
        (
            list,
            tuple,
            set,
        ),
    ):
        values = tuple(
            str(
                value
            )
            for value
            in raw
        )
    else:
        values = ()

    result: list[str] = []

    for value in values:
        label = (
            normalize_candidate_label(
                value
            )
        )

        if (
            label is not None
            and label
            not in result
        ):
            result.append(
                label
            )

    return tuple(
        result
    )


def event_occurrence_count(
    event: Event,
) -> int:
    for key in (
        "occurrences",
        "frequency",
        "target_frequency",
    ):
        raw = (
            event.metadata.get(
                key
            )
        )

        try:
            if not isinstance(raw, (int, str)):
                continue
            value = int(raw)
        except (
            TypeError,
            ValueError,
        ):
            continue

        if value > 0:
            return value

    return 1


def segment_has_api_token(
    segment: str,
) -> bool:
    tokens = {
        token.lower()
        for token in re.split(
            r"[-_.]+",
            segment,
        )
        if token
    }

    return bool(
        {
            "api",
            "rest",
            "graphql",
            "graphiql",
            "swagger",
            "openapi",
        }
        & tokens
    )


def looks_hash_like(
    value: str,
) -> bool:
    normalized = (
        value.strip()
        .lower()
    )

    if not normalized:
        return False

    hex_fraction = (
        sum(
            character
            in "0123456789abcdef"
            for character
            in normalized
        )
        / len(
            normalized
        )
    )

    return (
        hex_fraction
        >= 0.90
    )


def best_rank(
    left: int | None,
    right: int | None,
) -> int | None:
    ranks = [
        rank
        for rank
        in (
            left,
            right,
        )
        if rank
        is not None
    ]

    return (
        min(
            ranks
        )
        if ranks
        else None
    )
