"""Explainable hostname naming-pattern intelligence for Night Scout.

This module implements the `LearnedHypothesisProvider` contract expected by
`workers/permutations.py`.

It learns bounded hostname patterns from confirmed DNS observations and emits
explicit `LearnedHostnameHypothesis` objects. It never performs DNS/network I/O
and never treats a generated hostname as fact or authorization.

Example
-------
Confirmed observations:

    warehouse-api-prod-msk-01.example.com
    warehouse-api-stage-msk-01.example.com
    delivery-api-prod-spb-02.example.com

can produce an explainable pattern similar to:

    {service}-api-{env}-{region}-{number}.example.com

with *known observed values only*:

    service = warehouse | delivery
    env     = prod | stage
    region  = msk | spb
    number  = 01 | 02

The engine may then produce bounded missing combinations. It does NOT infer
`03`, `eu`, `preprod`, or any other value that was not observed in a compatible
pattern slot.

Why this is not blind Cartesian generation
-------------------------------------------
Candidate generation is ordered by distance from facts:

1. unseen combinations one slot away from an observed hostname;
2. only then wider combinations, still using observed slot values;
3. hard per-pattern and global candidate limits always apply.

This makes a hypothesis such as:

    warehouse-api-stage-spb-01.example.com

rank ahead of a combination that simultaneously changes service, environment,
region and number.

Learning boundary
-----------------
Only `DNS_NAME` Events carrying the `confirmed` tag are pattern examples.
Unconfirmed `hypothesis` Events are ignored even if they came from this same
engine. That prevents a self-reinforcing feedback loop:

    guessed name -> learned as fact -> more guesses     [blocked]

The intended loop is:

    learned hypothesis
        -> DNS confirmation
        -> confirmed DNS_NAME
        -> pattern evidence

Branch boundary
---------------
For a ROOT_DOMAIN seed, learned candidates must remain strict descendants of
that root.

For a confirmed DNS_NAME seed, candidates may be:
- descendants of the seed; or
- siblings beneath its immediate parent.

This mirrors the defense-in-depth branch check already present in
`workers/permutations.py`.

Pattern persistence
-------------------
This module intentionally does not import SQLAlchemy. A storage layer can later
implement:

    TargetEventProvider
    PatternFeedbackProvider

and persist discovered patterns as `NAMING_PATTERN` Events using
`naming_pattern_event(...)`.

Pattern feedback is optional. When available, historical attempts/successes
raise or lower ranking but never authorize wider generation.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.intelligence.wordlists import TargetEventProvider, infer_seed_domain
from recon.workers.passive_domains import normalize_dns_name
from recon.workers.permutations import LearnedHostnameHypothesis

_ENVIRONMENT_TOKENS = frozenset(
    {
        "prod",
        "production",
        "prd",
        "stage",
        "staging",
        "stg",
        "preprod",
        "pre-prod",
        "preproduction",
        "dev",
        "development",
        "test",
        "testing",
        "qa",
        "uat",
        "sandbox",
        "demo",
        "beta",
        "alpha",
        "canary",
    }
)

_SERVICE_ANCHOR_TOKENS = frozenset(
    {
        "api",
        "rest",
        "grpc",
        "web",
        "app",
        "svc",
        "service",
        "worker",
        "admin",
        "internal",
        "public",
        "private",
    }
)

_SAFE_COMPONENT_RE = re.compile(r"^[a-z0-9]+$")


class PatternSlotKind(StrEnum):
    """Explainable semantic/structural slot kind."""

    LITERAL = "LITERAL"
    SERVICE = "SERVICE"
    ENVIRONMENT = "ENVIRONMENT"
    REGION = "REGION"
    NUMBER = "NUMBER"
    VALUE = "VALUE"


class PatternSlot(BaseModel):
    """One component position inside a hyphen-delimited DNS label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=0)

    kind: PatternSlotKind

    literal: str | None = None

    values: tuple[str, ...] = ()
    value_counts: dict[str, int] = Field(default_factory=dict)

    numeric_width: int | None = Field(default=None, ge=1, le=63)

    semantic_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    @field_validator("literal")
    @classmethod
    def normalize_literal(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = normalize_label_component(value)

        if normalized is None:
            raise ValueError("invalid literal slot value")

        return normalized

    @field_validator("values")
    @classmethod
    def normalize_values(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        result: list[str] = []

        for value in values:
            normalized = normalize_label_component(value)

            if normalized is None:
                continue

            if normalized not in result:
                result.append(normalized)

        return tuple(result)

    @model_validator(mode="after")
    def slot_shape(
        self,
    ) -> "PatternSlot":
        if self.kind is PatternSlotKind.LITERAL:
            if self.literal is None:
                raise ValueError("literal slot requires literal")
            if self.values and self.values != (self.literal,):
                raise ValueError(
                    "literal slot values must be empty or equal literal"
                )
        else:
            if self.literal is not None:
                raise ValueError(
                    "variable slot must not define literal"
                )
            if len(self.values) < 2:
                raise ValueError(
                    "variable slot requires at least two observed values"
                )

        if (
            self.kind is PatternSlotKind.NUMBER
            and self.numeric_width is None
        ):
            raise ValueError(
                "number slot requires numeric_width"
            )

        return self

    @property
    def variable(self) -> bool:
        return self.kind is not PatternSlotKind.LITERAL

    @property
    def template_name(self) -> str:
        return {
            PatternSlotKind.LITERAL: "literal",
            PatternSlotKind.SERVICE: "service",
            PatternSlotKind.ENVIRONMENT: "env",
            PatternSlotKind.REGION: "region",
            PatternSlotKind.NUMBER: "number",
            PatternSlotKind.VALUE: f"value{self.index}",
        }[self.kind]


class NamingPattern(BaseModel):
    """One learned sibling-label structure beneath a concrete parent domain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str

    parent_domain: str
    root_domain: str

    template: str
    label_template: str

    slots: tuple[PatternSlot, ...]

    observed_labels: tuple[str, ...]
    observed_hostnames: tuple[str, ...]

    source_event_ids: tuple[str, ...]

    support: int = Field(ge=2)
    combination_space: int = Field(ge=1)
    unseen_combination_count: int = Field(ge=0)

    score: float = 0.0
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    literal_slots: int = Field(ge=0)
    variable_slots: int = Field(ge=1)

    feedback_attempts: int = Field(default=0, ge=0)
    feedback_successes: int = Field(default=0, ge=0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parent_domain", "root_domain")
    @classmethod
    def normalize_domain(
        cls,
        value: str,
    ) -> str:
        return normalize_dns_name(value)

    @field_validator(
        "pattern_id",
        "template",
        "label_template",
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
        "observed_labels",
        "observed_hostnames",
        "source_event_ids",
    )
    @classmethod
    def dedupe_text_tuple(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                value.strip()
                for value in values
                if value.strip()
            )
        )

    @model_validator(mode="after")
    def support_matches_observations(
        self,
    ) -> "NamingPattern":
        if self.feedback_successes > self.feedback_attempts:
            raise ValueError(
                "pattern feedback successes cannot exceed attempts"
            )

        if self.support != len(self.observed_labels):
            raise ValueError(
                "pattern support must equal observed label count"
            )

        if self.literal_slots + self.variable_slots != len(self.slots):
            raise ValueError(
                "literal_slots + variable_slots must equal slot count"
            )

        return self

    @property
    def yield_ratio(self) -> float:
        if self.feedback_attempts <= 0:
            return 0.0

        return (
            self.feedback_successes
            / self.feedback_attempts
        )


class PatternFeedback(BaseModel):
    """Historical outcome statistics for one deterministic pattern id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str

    attempted_hypotheses: int = Field(default=0, ge=0)
    successful_hits: int = Field(default=0, ge=0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pattern_id")
    @classmethod
    def pattern_id_required(
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
    ) -> "PatternFeedback":
        if (
            self.successful_hits
            > self.attempted_hypotheses
        ):
            raise ValueError(
                "successful_hits cannot exceed attempted_hypotheses"
            )

        return self


class PatternFeedbackProvider(Protocol):
    """Persistence boundary for historical pattern productivity."""

    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[PatternFeedback]:
        ...


class NoPatternFeedback:
    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[PatternFeedback]:
        del seed_event
        return ()


class StaticPatternFeedbackProvider:
    def __init__(
        self,
        feedback: Sequence[PatternFeedback],
    ) -> None:
        self._feedback = tuple(feedback)

    async def feedback_for(
        self,
        seed_event: Event,
    ) -> Sequence[PatternFeedback]:
        del seed_event
        return self._feedback


class PatternEngineConfig(BaseModel):
    """Hard bounds and conservative pattern acceptance thresholds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_support: int = Field(default=3, ge=2, le=1000)

    max_target_events: int = Field(
        default=250_000,
        ge=10,
        le=5_000_000,
    )

    max_confirmed_hostnames: int = Field(
        default=100_000,
        ge=10,
        le=2_000_000,
    )

    max_components_per_label: int = Field(
        default=8,
        ge=2,
        le=32,
    )

    max_variable_slots: int = Field(
        default=5,
        ge=1,
        le=16,
    )

    max_patterns: int = Field(
        default=256,
        ge=1,
        le=100_000,
    )

    max_anchor_clusters_per_group: int = Field(
        default=32,
        ge=0,
        le=1024,
    )

    max_combination_space: int = Field(
        default=4096,
        ge=2,
        le=1_000_000,
    )

    max_hypotheses_per_pattern: int = Field(
        default=128,
        ge=1,
        le=100_000,
    )

    max_hypotheses_total: int = Field(
        default=1000,
        ge=1,
        le=1_000_000,
    )

    min_pattern_confidence: float = Field(
        default=0.52,
        ge=0.0,
        le=1.0,
    )

    candidate_confidence_floor: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
    )

    candidate_confidence_ceiling: float = Field(
        default=0.92,
        ge=0.0,
        le=1.0,
    )

    allow_unanchored_semantic_pattern: bool = True

    environment_tokens: frozenset[str] = Field(
        default_factory=lambda: _ENVIRONMENT_TOKENS
    )

    @field_validator("environment_tokens")
    @classmethod
    def normalize_environment_tokens(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )

    @model_validator(mode="after")
    def confidence_bounds(
        self,
    ) -> "PatternEngineConfig":
        if (
            self.candidate_confidence_floor
            > self.candidate_confidence_ceiling
        ):
            raise ValueError(
                "candidate confidence floor cannot exceed ceiling"
            )

        return self


class PatternDiscoveryReport(BaseModel):
    """Explainability summary for one seed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root_domain: str

    target_events_seen: int = Field(ge=0)
    confirmed_hostnames_seen: int = Field(ge=0)

    parent_groups_seen: int = Field(ge=0)
    raw_pattern_candidates: int = Field(ge=0)

    accepted_patterns: int = Field(ge=0)
    rejected_patterns: int = Field(ge=0)

    generated_hypotheses: int = Field(ge=0)

    @field_validator("root_domain")
    @classmethod
    def normalize_root(
        cls,
        value: str,
    ) -> str:
        return normalize_dns_name(value)


class _HostnameObservation(BaseModel):
    """Internal normalized confirmed-host observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    parent_domain: str
    child_label: str
    components: tuple[str, ...]

    event_id: str
    confidence: float = Field(ge=0.0, le=1.0)

    source: str

    @field_validator("hostname", "parent_domain")
    @classmethod
    def normalize_domains(
        cls,
        value: str,
    ) -> str:
        return normalize_dns_name(value)


class _PatternCandidateGroup(BaseModel):
    """Internal group from which one NamingPattern may be inferred."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    parent_domain: str
    observations: tuple[_HostnameObservation, ...]

    group_reason: str
    anchor_index: int | None = None
    anchor_value: str | None = None

    @field_validator("parent_domain")
    @classmethod
    def normalize_parent(
        cls,
        value: str,
    ) -> str:
        return normalize_dns_name(value)


class PatternEngine:
    """Discover patterns and implement `LearnedHypothesisProvider`."""

    def __init__(
        self,
        *,
        target_events: TargetEventProvider,
        feedback: PatternFeedbackProvider | None = None,
        config: PatternEngineConfig | None = None,
    ) -> None:
        self._target_events = target_events
        self._feedback = feedback or NoPatternFeedback()
        self._config = config or PatternEngineConfig()

    async def patterns_for(
        self,
        seed_event: Event,
    ) -> tuple[
        tuple[NamingPattern, ...],
        PatternDiscoveryReport,
    ]:
        root_domain = pattern_learning_root(
            seed_event
        )

        events = tuple(
            await self._target_events.events_for(
                seed_event
            )
        )[
            : self._config.max_target_events
        ]

        observations = collect_confirmed_hostname_observations(
            events,
            root_domain=root_domain,
            config=self._config,
        )

        groups = build_pattern_candidate_groups(
            observations,
            config=self._config,
        )

        feedback_items = tuple(
            await self._feedback.feedback_for(
                seed_event
            )
        )

        feedback_by_pattern = {
            item.pattern_id: item
            for item in feedback_items
        }

        patterns: list[NamingPattern] = []

        rejected = 0

        for group in groups:
            pattern = infer_naming_pattern(
                group,
                root_domain=root_domain,
                config=self._config,
            )

            if pattern is None:
                rejected += 1
                continue

            feedback_item = feedback_by_pattern.get(
                pattern.pattern_id
            )

            if feedback_item is not None:
                pattern = apply_pattern_feedback(
                    pattern,
                    feedback_item,
                )

            if (
                pattern.confidence
                < self._config.min_pattern_confidence
            ):
                rejected += 1
                continue

            patterns.append(pattern)

        ranked_patterns = dedupe_and_rank_patterns(
            patterns
        )[
            : self._config.max_patterns
        ]

        report = PatternDiscoveryReport(
            root_domain=root_domain,
            target_events_seen=len(events),
            confirmed_hostnames_seen=len(
                observations
            ),
            parent_groups_seen=len(
                {
                    observation.parent_domain
                    for observation in observations
                }
            ),
            raw_pattern_candidates=len(
                groups
            ),
            accepted_patterns=len(
                ranked_patterns
            ),
            rejected_patterns=rejected,
            generated_hypotheses=0,
        )

        return (
            ranked_patterns,
            report,
        )

    async def hypotheses_for(
        self,
        seed_event: Event,
    ) -> Sequence[
        LearnedHostnameHypothesis
    ]:
        """Implement workers.permutations.LearnedHypothesisProvider."""

        patterns, _report = await self.patterns_for(
            seed_event
        )

        root_domain = pattern_learning_root(
            seed_event
        )

        events = tuple(
            await self._target_events.events_for(
                seed_event
            )
        )[
            : self._config.max_target_events
        ]

        existing = {
            normalize_dns_name(event.value)
            for event in events
            if (
                event.type
                is EventType.DNS_NAME
                and "confirmed" in event.tags
                and _safe_dns_name(
                    event.value
                )
                is not None
            )
        }

        hypotheses: list[
            LearnedHostnameHypothesis
        ] = []

        for pattern in patterns:
            for candidate in generate_pattern_hypotheses(
                pattern,
                existing_hostnames=existing,
                config=self._config,
            ):
                if not candidate_within_seed_branch(
                    candidate.hostname,
                    seed_event=seed_event,
                ):
                    continue

                hypotheses.append(
                    candidate
                )

                if (
                    len(hypotheses)
                    >= self._config.max_hypotheses_total
                ):
                    break

            if (
                len(hypotheses)
                >= self._config.max_hypotheses_total
            ):
                break

        return tuple(
            rank_and_dedupe_hypotheses(
                hypotheses
            )[
                : self._config.max_hypotheses_total
            ]
        )


def pattern_learning_root(
    seed_event: Event,
) -> str:
    """Resolve the safe branch root used for pattern learning."""

    if (
        seed_event.type
        is EventType.ROOT_DOMAIN
    ):
        return normalize_dns_name(
            seed_event.value
        )

    explicit = seed_event.metadata.get(
        "seed_domain"
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
        seed_event.type
        is EventType.DNS_NAME
    ):
        hostname = normalize_dns_name(
            seed_event.value
        )

        labels = hostname.split(
            "."
        )

        if len(labels) < 3:
            raise ValueError(
                "confirmed DNS seed has no safe immediate parent branch"
            )

        return ".".join(
            labels[1:]
        )

    inferred = infer_seed_domain(
        seed_event
    )

    if inferred is None:
        raise ValueError(
            "pattern engine requires ROOT_DOMAIN or DNS branch context"
        )

    return inferred


def collect_confirmed_hostname_observations(
    events: Sequence[Event],
    *,
    root_domain: str,
    config: PatternEngineConfig,
) -> tuple[
    _HostnameObservation,
    ...
]:
    """Collect confirmed sibling labels beneath the current learning root."""

    root = normalize_dns_name(
        root_domain
    )

    result: list[
        _HostnameObservation
    ] = []

    seen: set[
        tuple[str, str]
    ] = set()

    for event in events:
        if (
            len(result)
            >= config.max_confirmed_hostnames
        ):
            break

        if (
            event.type
            is not EventType.DNS_NAME
        ):
            continue

        if (
            "confirmed"
            not in event.tags
        ):
            continue

        try:
            hostname = normalize_dns_name(
                event.value
            )
        except ValueError:
            continue

        if (
            hostname == root
            or not hostname.endswith(
                "." + root
            )
        ):
            continue

        labels = hostname.split(
            "."
        )

        if len(labels) < 3:
            continue

        child_label = labels[0]
        parent_domain = ".".join(
            labels[1:]
        )

        # A pattern is a structure, not a generic one-word sibling list.
        components = split_pattern_label(
            child_label
        )

        if (
            len(components) < 2
            or len(components)
            > config.max_components_per_label
        ):
            continue

        key = (
            hostname,
            event.event_id,
        )

        if key in seen:
            continue

        seen.add(key)

        result.append(
            _HostnameObservation(
                hostname=hostname,
                parent_domain=parent_domain,
                child_label=child_label,
                components=components,
                event_id=event.event_id,
                confidence=event.confidence,
                source=event.source,
            )
        )

    return tuple(
        result
    )


def build_pattern_candidate_groups(
    observations: Sequence[
        _HostnameObservation
    ],
    *,
    config: PatternEngineConfig,
) -> tuple[
    _PatternCandidateGroup,
    ...
]:
    """Build broad arity groups plus bounded frequent-anchor subgroups."""

    by_parent_arity: dict[
        tuple[str, int],
        list[_HostnameObservation],
    ] = defaultdict(list)

    for observation in observations:
        by_parent_arity[
            (
                observation.parent_domain,
                len(
                    observation.components
                ),
            )
        ].append(
            observation
        )

    groups: list[
        _PatternCandidateGroup
    ] = []

    dedupe_keys: set[
        tuple[str, tuple[str, ...]]
    ] = set()

    for (
        parent_domain,
        arity,
    ), raw_group in sorted(
        by_parent_arity.items()
    ):
        distinct_by_label = {
            observation.child_label: observation
            for observation in raw_group
        }

        group = tuple(
            sorted(
                distinct_by_label.values(),
                key=lambda observation: (
                    observation.child_label,
                    observation.event_id,
                ),
            )
        )

        if (
            len(group)
            < config.min_support
        ):
            continue

        _append_group_if_new(
            groups,
            dedupe_keys,
            _PatternCandidateGroup(
                parent_domain=parent_domain,
                observations=group,
                group_reason="parent-arity",
            ),
        )

        if (
            config.max_anchor_clusters_per_group
            <= 0
        ):
            continue

        anchor_clusters: list[
            tuple[
                int,
                int,
                str,
                tuple[_HostnameObservation, ...],
            ]
        ] = []

        for index in range(
            arity
        ):
            values: dict[
                str,
                list[_HostnameObservation],
            ] = defaultdict(list)

            for observation in group:
                values[
                    observation.components[
                        index
                    ]
                ].append(
                    observation
                )

            for (
                value,
                members,
            ) in values.items():
                if (
                    len(members)
                    < config.min_support
                    or len(members)
                    == len(group)
                ):
                    continue

                anchor_clusters.append(
                    (
                        -len(members),
                        index,
                        value,
                        tuple(
                            sorted(
                                members,
                                key=lambda observation: (
                                    observation.child_label,
                                    observation.event_id,
                                ),
                            )
                        ),
                    )
                )

        anchor_clusters.sort(
            key=lambda item: (
                item[0],
                item[1],
                item[2],
            )
        )

        for (
            _negative_support,
            index,
            value,
            anchor_members,
        ) in anchor_clusters[
            : config.max_anchor_clusters_per_group
        ]:
            _append_group_if_new(
                groups,
                dedupe_keys,
                _PatternCandidateGroup(
                    parent_domain=parent_domain,
                    observations=anchor_members,
                    group_reason="frequent-anchor",
                    anchor_index=index,
                    anchor_value=value,
                ),
            )

    return tuple(
        groups
    )


def _append_group_if_new(
    groups: list[
        _PatternCandidateGroup
    ],
    dedupe_keys: set[
        tuple[
            str,
            tuple[str, ...],
        ]
    ],
    group: _PatternCandidateGroup,
) -> None:
    key = (
        group.parent_domain,
        tuple(
            observation.child_label
            for observation in group.observations
        ),
    )

    if key in dedupe_keys:
        return

    dedupe_keys.add(
        key
    )

    groups.append(
        group
    )


def infer_naming_pattern(
    group: _PatternCandidateGroup,
    *,
    root_domain: str,
    config: PatternEngineConfig,
) -> NamingPattern | None:
    """Infer one strict positional pattern from a sibling group."""

    observations = group.observations

    if (
        len(observations)
        < config.min_support
    ):
        return None

    arity = len(
        observations[0].components
    )

    if (
        arity < 2
        or arity
        > config.max_components_per_label
    ):
        return None

    if any(
        len(
            observation.components
        )
        != arity
        for observation in observations
    ):
        return None

    columns = tuple(
        tuple(
            observation.components[
                index
            ]
            for observation
            in observations
        )
        for index
        in range(
            arity
        )
    )

    preliminary_kinds = [
        classify_variable_column_preliminary(
            column,
            index=index,
            environment_tokens=(
                config.environment_tokens
            ),
        )
        for index, column
        in enumerate(
            columns
        )
    ]

    slots: list[
        PatternSlot
    ] = []

    for index, column in enumerate(
        columns
    ):
        counts = Counter(
            column
        )

        values = tuple(
            value
            for value, _count
            in sorted(
                counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )
        )

        if len(values) == 1:
            slots.append(
                PatternSlot(
                    index=index,
                    kind=(
                        PatternSlotKind.LITERAL
                    ),
                    literal=values[0],
                    values=(
                        values[0],
                    ),
                    value_counts=dict(
                        counts
                    ),
                    semantic_confidence=1.0,
                )
            )
            continue

        kind = classify_variable_column(
            columns=columns,
            index=index,
            preliminary_kinds=(
                preliminary_kinds
            ),
            environment_tokens=(
                config.environment_tokens
            ),
        )

        numeric_width = (
            len(values[0])
            if (
                kind
                is PatternSlotKind.NUMBER
                and len(
                    {
                        len(value)
                        for value
                        in values
                    }
                )
                == 1
            )
            else None
        )

        if (
            kind
            is PatternSlotKind.NUMBER
            and numeric_width is None
        ):
            # Mixed-width numeric slots remain VALUE to avoid implying a
            # formatting rule that the observations do not actually support.
            kind = (
                PatternSlotKind.VALUE
            )

        slots.append(
            PatternSlot(
                index=index,
                kind=kind,
                values=values,
                value_counts=dict(
                    counts
                ),
                numeric_width=(
                    numeric_width
                ),
                semantic_confidence=(
                    semantic_confidence_for_kind(
                        kind
                    )
                ),
            )
        )

    variable_slots = sum(
        slot.variable
        for slot in slots
    )

    literal_slots = (
        len(slots)
        - variable_slots
    )

    if (
        variable_slots <= 0
        or variable_slots
        > config.max_variable_slots
    ):
        return None

    semantic_variable_slots = sum(
        slot.kind
        in {
            PatternSlotKind.SERVICE,
            PatternSlotKind.ENVIRONMENT,
            PatternSlotKind.REGION,
            PatternSlotKind.NUMBER,
        }
        for slot in slots
        if slot.variable
    )

    if (
        literal_slots == 0
        and (
            not config.allow_unanchored_semantic_pattern
            or semantic_variable_slots == 0
            or len(observations)
            < max(
                config.min_support,
                4,
            )
        )
    ):
        return None

    combination_space = 1

    for slot in slots:
        if slot.variable:
            combination_space *= len(
                slot.values
            )

            if (
                combination_space
                > config.max_combination_space
            ):
                return None

    observed_component_tuples = {
        observation.components
        for observation in observations
    }

    unseen_count = max(
        0,
        combination_space
        - len(
            observed_component_tuples
        ),
    )

    if unseen_count <= 0:
        return None

    label_template = render_label_template(
        slots
    )

    parent = group.parent_domain

    template = (
        f"{label_template}."
        f"{parent}"
    )

    pattern_id = deterministic_pattern_id(
        root_domain=root_domain,
        parent_domain=parent,
        slots=slots,
    )

    confidence = calculate_pattern_confidence(
        support=len(
            observations
        ),
        slots=slots,
        combination_space=(
            combination_space
        ),
        observed_count=len(
            observed_component_tuples
        ),
        group_reason=(
            group.group_reason
        ),
    )

    score = calculate_pattern_score(
        support=len(
            observations
        ),
        slots=slots,
        combination_space=(
            combination_space
        ),
        confidence=confidence,
        group_reason=(
            group.group_reason
        ),
    )

    return NamingPattern(
        pattern_id=pattern_id,
        parent_domain=parent,
        root_domain=(
            root_domain
        ),
        template=template,
        label_template=(
            label_template
        ),
        slots=tuple(
            slots
        ),
        observed_labels=tuple(
            observation.child_label
            for observation
            in observations
        ),
        observed_hostnames=tuple(
            observation.hostname
            for observation
            in observations
        ),
        source_event_ids=tuple(
            sorted(
                {
                    observation.event_id
                    for observation
                    in observations
                }
            )
        ),
        support=len(
            observations
        ),
        combination_space=(
            combination_space
        ),
        unseen_combination_count=(
            unseen_count
        ),
        score=score,
        confidence=confidence,
        literal_slots=(
            literal_slots
        ),
        variable_slots=(
            variable_slots
        ),
        metadata={
            "group_reason": (
                group.group_reason
            ),
            "anchor_index": (
                group.anchor_index
            ),
            "anchor_value": (
                group.anchor_value
            ),
            "semantic_variable_slots": (
                semantic_variable_slots
            ),
            "observed_sources": sorted(
                {
                    observation.source
                    for observation
                    in observations
                }
            ),
        },
    )


def classify_variable_column_preliminary(
    values: Sequence[str],
    *,
    index: int,
    environment_tokens: frozenset[str],
) -> PatternSlotKind:
    del index

    unique = set(
        values
    )

    if len(unique) <= 1:
        return (
            PatternSlotKind.LITERAL
        )

    if all(
        value.isdigit()
        for value in unique
    ):
        return (
            PatternSlotKind.NUMBER
        )

    if all(
        value
        in environment_tokens
        for value in unique
    ):
        return (
            PatternSlotKind.ENVIRONMENT
        )

    return (
        PatternSlotKind.VALUE
    )


def classify_variable_column(
    *,
    columns: Sequence[
        Sequence[str]
    ],
    index: int,
    preliminary_kinds: Sequence[
        PatternSlotKind
    ],
    environment_tokens: frozenset[str],
) -> PatternSlotKind:
    """Assign a conservative semantic hint to one variable position."""

    values = tuple(
        sorted(
            set(
                columns[
                    index
                ]
            )
        )
    )

    if all(
        value.isdigit()
        for value in values
    ):
        return (
            PatternSlotKind.NUMBER
        )

    if all(
        value
        in environment_tokens
        for value in values
    ):
        return (
            PatternSlotKind.ENVIRONMENT
        )

    # Example:
    #   warehouse-api-prod-msk-01
    #   delivery-api-stage-spb-02
    #
    # The varying first component is plausibly a service when the structure
    # contains a service anchor (`api`) or a later environment/number slot.
    if (
        index == 0
        and all(
            value.isalpha()
            for value in values
        )
        and (
            any(
                len(
                    set(
                        column
                    )
                )
                == 1
                and next(
                    iter(
                        set(
                            column
                        )
                    )
                )
                in _SERVICE_ANCHOR_TOKENS
                for column
                in columns[
                    1:
                ]
            )
            or any(
                kind
                in {
                    PatternSlotKind.ENVIRONMENT,
                    PatternSlotKind.NUMBER,
                }
                for kind
                in preliminary_kinds[
                    1:
                ]
            )
        )
    ):
        return (
            PatternSlotKind.SERVICE
        )

    # A short alphabetic variable immediately before a numeric slot is often a
    # region/site/datacenter code. This is only an explainability hint: the
    # generator still uses observed values only.
    if (
        index
        + 1
        < len(
            columns
        )
        and preliminary_kinds[
            index + 1
        ]
        is PatternSlotKind.NUMBER
        and all(
            value.isalpha()
            and 2
            <= len(value)
            <= 8
            for value in values
        )
    ):
        return (
            PatternSlotKind.REGION
        )

    return (
        PatternSlotKind.VALUE
    )


def semantic_confidence_for_kind(
    kind: PatternSlotKind,
) -> float:
    return {
        PatternSlotKind.LITERAL: 1.0,
        PatternSlotKind.NUMBER: 0.98,
        PatternSlotKind.ENVIRONMENT: 0.96,
        PatternSlotKind.SERVICE: 0.80,
        PatternSlotKind.REGION: 0.72,
        PatternSlotKind.VALUE: 0.50,
    }[
        kind
    ]


def calculate_pattern_confidence(
    *,
    support: int,
    slots: Sequence[
        PatternSlot
    ],
    combination_space: int,
    observed_count: int,
    group_reason: str,
) -> float:
    """Explainable confidence from support, anchors and hypothesis breadth."""

    variable_slots = sum(
        slot.variable
        for slot in slots
    )

    literal_slots = (
        len(slots)
        - variable_slots
    )

    semantic_slots = sum(
        slot.kind
        in {
            PatternSlotKind.SERVICE,
            PatternSlotKind.ENVIRONMENT,
            PatternSlotKind.REGION,
            PatternSlotKind.NUMBER,
        }
        for slot in slots
        if slot.variable
    )

    support_factor = min(
        1.0,
        support / 8.0,
    )

    anchor_factor = (
        literal_slots
        / len(
            slots
        )
    )

    semantic_factor = (
        semantic_slots
        / max(
            1,
            variable_slots,
        )
    )

    coverage = min(
        1.0,
        observed_count
        / max(
            1,
            combination_space,
        ),
    )

    breadth_penalty = min(
        0.18,
        math.log2(
            max(
                1,
                combination_space,
            )
        )
        * 0.015,
    )

    confidence = (
        0.38
        + support_factor
        * 0.24
        + anchor_factor
        * 0.16
        + semantic_factor
        * 0.12
        + min(
            coverage,
            0.5,
        )
        * 0.16
        - breadth_penalty
    )

    if (
        group_reason
        == "frequent-anchor"
    ):
        confidence += 0.03

    return min(
        0.96,
        max(
            0.0,
            confidence,
        ),
    )


def calculate_pattern_score(
    *,
    support: int,
    slots: Sequence[
        PatternSlot
    ],
    combination_space: int,
    confidence: float,
    group_reason: str,
) -> float:
    variable_slots = sum(
        slot.variable
        for slot in slots
    )

    literal_slots = (
        len(slots)
        - variable_slots
    )

    semantic_slots = sum(
        slot.kind
        not in {
            PatternSlotKind.LITERAL,
            PatternSlotKind.VALUE,
        }
        for slot in slots
    )

    score = (
        math.log1p(
            support
        )
        * 2.2
        + literal_slots
        * 0.65
        + semantic_slots
        * 0.45
        + confidence
        * 2.0
        - variable_slots
        * 0.22
        - math.log2(
            max(
                1,
                combination_space,
            )
        )
        * 0.12
    )

    if (
        group_reason
        == "frequent-anchor"
    ):
        score += 0.15

    return score


def apply_pattern_feedback(
    pattern: NamingPattern,
    feedback: PatternFeedback,
) -> NamingPattern:
    """Apply historical yield without changing the pattern's slot universe."""

    attempts = (
        feedback.attempted_hypotheses
    )

    successes = (
        feedback.successful_hits
    )

    yield_ratio = (
        successes / attempts
        if attempts > 0
        else 0.0
    )

    evidence_factor = min(
        1.0,
        attempts / 20.0,
    )

    confidence_delta = (
        (
            yield_ratio
            - 0.25
        )
        * 0.16
        * evidence_factor
    )

    score_delta = (
        math.log1p(
            successes
        )
        * 0.9
        - math.log1p(
            max(
                0,
                attempts
                - successes
            )
        )
        * 0.12
    )

    return pattern.model_copy(
        update={
            "feedback_attempts": (
                attempts
            ),
            "feedback_successes": (
                successes
            ),
            "confidence": min(
                0.98,
                max(
                    0.0,
                    pattern.confidence
                    + confidence_delta,
                ),
            ),
            "score": (
                pattern.score
                + score_delta
            ),
            "metadata": {
                **pattern.metadata,
                "pattern_feedback": {
                    "attempts": attempts,
                    "successes": successes,
                    "yield_ratio": (
                        yield_ratio
                    ),
                    **feedback.metadata,
                },
            },
        }
    )


def generate_pattern_hypotheses(
    pattern: NamingPattern,
    *,
    existing_hostnames: set[str],
    config: PatternEngineConfig,
) -> tuple[
    LearnedHostnameHypothesis,
    ...
]:
    """Generate bounded missing combinations using observed values only."""

    observed_tuples = {
        split_pattern_label(
            label
        )
        for label
        in pattern.observed_labels
    }

    observed_tuples = {
        values
        for values
        in observed_tuples
        if len(values)
        == len(
            pattern.slots
        )
    }

    variable_indexes = tuple(
        slot.index
        for slot
        in pattern.slots
        if slot.variable
    )

    if not variable_indexes:
        return ()

    candidate_components: dict[
        tuple[str, ...],
        int,
    ] = {}

    # Phase 1: mutate exactly one variable position from each observed sample.
    for observed in sorted(
        observed_tuples
    ):
        for index in variable_indexes:
            slot = pattern.slots[
                index
            ]

            for value in slot.values:
                if (
                    value
                    == observed[
                        index
                    ]
                ):
                    continue

                values = list(
                    observed
                )
                values[
                    index
                ] = value
                candidate = tuple(
                    values
                )

                if (
                    candidate
                    not in observed_tuples
                ):
                    candidate_components[
                        candidate
                    ] = min(
                        candidate_components.get(
                            candidate,
                            10**9,
                        ),
                        1,
                    )

    # Phase 2: bounded full known-value combinations, prioritized later by
    # minimum Hamming distance to actual observations.
    if (
        len(candidate_components)
        < config.max_hypotheses_per_pattern
    ):
        value_domains: list[
            tuple[str, ...]
        ] = []

        for slot in pattern.slots:
            if (
                slot.kind
                is PatternSlotKind.LITERAL
            ):
                assert (
                    slot.literal
                    is not None
                )

                value_domains.append(
                    (
                        slot.literal,
                    )
                )
            else:
                value_domains.append(
                    slot.values
                )

        for combination in itertools.product(
            *value_domains
        ):
            candidate = tuple(
                combination
            )

            if (
                candidate
                in observed_tuples
                or candidate
                in candidate_components
            ):
                continue

            distance = min(
                hamming_distance(
                    candidate,
                    observed,
                )
                for observed
                in observed_tuples
            )

            candidate_components[
                candidate
            ] = distance

            # We allow an overscan window so ranking can choose good
            # combinations rather than whichever product() happened to yield
            # first.
            if (
                len(
                    candidate_components
                )
                >= (
                    config.max_hypotheses_per_pattern
                    * 8
                )
            ):
                break

    hypotheses: list[
        LearnedHostnameHypothesis
    ] = []

    for (
        components,
        distance,
    ) in candidate_components.items():
        label = "-".join(
            components
        )

        if not valid_dns_label(
            label
        ):
            continue

        hostname = normalize_dns_name(
            f"{label}."
            f"{pattern.parent_domain}"
        )

        if (
            hostname
            in existing_hostnames
        ):
            continue

        value_frequency_score = (
            pattern_value_frequency_score(
                pattern,
                components,
            )
        )

        candidate_score = (
            pattern.score
            + value_frequency_score
            + (
                1.5
                / max(
                    1,
                    distance,
                )
            )
            + pattern.yield_ratio
            * 1.5
        )

        confidence = (
            pattern.confidence
            * (
                0.96
                ** max(
                    0,
                    distance
                    - 1,
                )
            )
        )

        confidence = min(
            config.candidate_confidence_ceiling,
            max(
                config.candidate_confidence_floor,
                confidence,
            ),
        )

        variable_values = {
            pattern.slots[
                index
            ].template_name: components[
                index
            ]
            for index
            in variable_indexes
        }

        hypotheses.append(
            LearnedHostnameHypothesis(
                hostname=hostname,
                score=candidate_score,
                confidence=confidence,
                source_event_ids=(
                    pattern.source_event_ids
                ),
                source_pattern=(
                    pattern.template
                ),
                metadata={
                    "pattern_id": (
                        pattern.pattern_id
                    ),
                    "pattern_template": (
                        pattern.template
                    ),
                    "label_template": (
                        pattern.label_template
                    ),
                    "pattern_parent_domain": (
                        pattern.parent_domain
                    ),
                    "pattern_root_domain": (
                        pattern.root_domain
                    ),
                    "pattern_support": (
                        pattern.support
                    ),
                    "pattern_confidence": (
                        pattern.confidence
                    ),
                    "pattern_score": (
                        pattern.score
                    ),
                    "pattern_combination_space": (
                        pattern.combination_space
                    ),
                    "hamming_distance_from_observed": (
                        distance
                    ),
                    "variable_values": (
                        variable_values
                    ),
                    "known_values_only": True,
                    "numeric_extrapolation": False,
                    "pattern_feedback_attempts": (
                        pattern.feedback_attempts
                    ),
                    "pattern_feedback_successes": (
                        pattern.feedback_successes
                    ),
                    "pattern_historical_yield": (
                        pattern.yield_ratio
                    ),
                },
            )
        )

    return tuple(
        sorted(
            hypotheses,
            key=lambda hypothesis: (
                -hypothesis.score,
                -hypothesis.confidence,
                hypothesis.hostname,
            ),
        )[
            : config.max_hypotheses_per_pattern
        ]
    )


def pattern_value_frequency_score(
    pattern: NamingPattern,
    components: Sequence[str],
) -> float:
    """Slightly prefer values that have stronger observed support."""

    score = 0.0

    for slot in pattern.slots:
        if not slot.variable:
            continue

        value = components[
            slot.index
        ]

        count = (
            slot.value_counts.get(
                value,
                0,
            )
        )

        score += (
            math.log1p(
                count
            )
            * 0.12
        )

    return score


def naming_pattern_event(
    pattern: NamingPattern,
    *,
    parent_event_id: str | None = None,
) -> Event:
    """Convert a learned pattern into a persistable Target Genome Event."""

    return Event(
        type=EventType.NAMING_PATTERN,
        value=pattern.template,
        source="patterns:hostname",
        parent_event_id=(
            parent_event_id
        ),
        scope_state=(
            ScopeState.UNKNOWN
        ),
        confidence=(
            pattern.confidence
        ),
        novelty=0.78,
        tags={
            "target-genome",
            "naming-pattern",
            "learned",
            "local-static-analysis",
        },
        metadata={
            "pattern_id": (
                pattern.pattern_id
            ),
            "parent_domain": (
                pattern.parent_domain
            ),
            "root_domain": (
                pattern.root_domain
            ),
            "label_template": (
                pattern.label_template
            ),
            "support": (
                pattern.support
            ),
            "source_event_ids": list(
                pattern.source_event_ids
            ),
            "observed_labels": list(
                pattern.observed_labels
            ),
            "observed_hostnames": list(
                pattern.observed_hostnames
            ),
            "combination_space": (
                pattern.combination_space
            ),
            "unseen_combination_count": (
                pattern.unseen_combination_count
            ),
            "literal_slots": (
                pattern.literal_slots
            ),
            "variable_slots": (
                pattern.variable_slots
            ),
            "pattern_score": (
                pattern.score
            ),
            "pattern_feedback_attempts": (
                pattern.feedback_attempts
            ),
            "pattern_feedback_successes": (
                pattern.feedback_successes
            ),
            "slots": [
                {
                    "index": slot.index,
                    "kind": (
                        slot.kind.value
                    ),
                    "literal": (
                        slot.literal
                    ),
                    "values": list(
                        slot.values
                    ),
                    "value_counts": dict(
                        slot.value_counts
                    ),
                    "numeric_width": (
                        slot.numeric_width
                    ),
                    "semantic_confidence": (
                        slot.semantic_confidence
                    ),
                }
                for slot
                in pattern.slots
            ],
            **pattern.metadata,
        },
    )


def render_label_template(
    slots: Sequence[
        PatternSlot
    ],
) -> str:
    """Render deterministic human-readable template names."""

    used_names: Counter[
        str
    ] = Counter()

    parts: list[str] = []

    for slot in slots:
        if (
            slot.kind
            is PatternSlotKind.LITERAL
        ):
            assert (
                slot.literal
                is not None
            )

            parts.append(
                slot.literal
            )
            continue

        base_name = (
            slot.template_name
        )

        used_names[
            base_name
        ] += 1

        if (
            used_names[
                base_name
            ]
            > 1
        ):
            name = (
                f"{base_name}"
                f"{used_names[base_name]}"
            )
        else:
            name = base_name

        parts.append(
            "{"
            + name
            + "}"
        )

    return "-".join(
        parts
    )


def deterministic_pattern_id(
    *,
    root_domain: str,
    parent_domain: str,
    slots: Sequence[
        PatternSlot
    ],
) -> str:
    """Stable id based on structural pattern and known slot values."""

    parts: list[str] = [
        normalize_dns_name(
            root_domain
        ),
        normalize_dns_name(
            parent_domain
        ),
    ]

    for slot in slots:
        parts.append(
            (
                f"{slot.index}:"
                f"{slot.kind.value}:"
                f"{slot.literal or ''}:"
                + ",".join(
                    slot.values
                )
            )
        )

    digest = hashlib.sha256(
        "\n".join(
            parts
        ).encode(
            "utf-8"
        )
    ).hexdigest()[
        :24
    ]

    return (
        "pat_"
        + digest
    )


def split_pattern_label(
    label: str,
) -> tuple[str, ...]:
    """Split a concrete DNS label into safe hyphen-delimited components."""

    normalized = (
        label.strip()
        .lower()
    )

    if (
        not normalized
        or len(normalized)
        > 63
    ):
        return ()

    parts = tuple(
        part
        for part in normalized.split(
            "-"
        )
        if part
    )

    if (
        "-".join(
            parts
        )
        != normalized
    ):
        return ()

    if any(
        normalize_label_component(
            part
        )
        is None
        for part in parts
    ):
        return ()

    return parts


def normalize_label_component(
    value: str,
) -> str | None:
    normalized = (
        value.strip()
        .lower()
    )

    if (
        not normalized
        or len(normalized)
        > 63
    ):
        return None

    if (
        _SAFE_COMPONENT_RE.fullmatch(
            normalized
        )
        is None
    ):
        return None

    return normalized


def valid_dns_label(
    value: str,
) -> bool:
    if (
        not value
        or len(value)
        > 63
        or value.startswith("-")
        or value.endswith("-")
    ):
        return False

    return bool(
        re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        )
    )


def candidate_within_seed_branch(
    candidate: str,
    *,
    seed_event: Event,
) -> bool:
    """Mirror permutations.py's branch containment defense."""

    normalized_candidate = normalize_dns_name(
        candidate
    )

    normalized_seed = normalize_dns_name(
        seed_event.value
    )

    if (
        seed_event.type
        is EventType.ROOT_DOMAIN
    ):
        return (
            normalized_candidate
            != normalized_seed
            and normalized_candidate.endswith(
                "."
                + normalized_seed
            )
        )

    if (
        seed_event.type
        is not EventType.DNS_NAME
    ):
        return False

    if (
        normalized_candidate
        != normalized_seed
        and normalized_candidate.endswith(
            "."
            + normalized_seed
        )
    ):
        return True

    labels = normalized_seed.split(
        "."
    )

    if len(labels) < 3:
        return False

    parent = ".".join(
        labels[1:]
    )

    return (
        normalized_candidate
        != parent
        and normalized_candidate.endswith(
            "."
            + parent
        )
    )


def hamming_distance(
    left: Sequence[str],
    right: Sequence[str],
) -> int:
    if len(left) != len(right):
        raise ValueError(
            "Hamming distance requires equal-length sequences"
        )

    return sum(
        left_value
        != right_value
        for (
            left_value,
            right_value,
        )
        in zip(
            left,
            right,
            strict=True,
        )
    )


def dedupe_and_rank_patterns(
    patterns: Sequence[
        NamingPattern
    ],
) -> tuple[
    NamingPattern,
    ...
]:
    """Keep strongest structurally identical pattern."""

    best: dict[
        tuple[str, str],
        NamingPattern
    ] = {}

    for pattern in patterns:
        key = (
            pattern.parent_domain,
            pattern.label_template,
        )

        existing = best.get(
            key
        )

        if (
            existing is None
            or (
                pattern.score,
                pattern.confidence,
                pattern.support,
            )
            > (
                existing.score,
                existing.confidence,
                existing.support,
            )
        ):
            best[
                key
            ] = pattern

    return tuple(
        sorted(
            best.values(),
            key=lambda pattern: (
                -pattern.score,
                -pattern.confidence,
                -pattern.support,
                pattern.template,
            ),
        )
    )


def rank_and_dedupe_hypotheses(
    hypotheses: Sequence[
        LearnedHostnameHypothesis
    ],
) -> tuple[
    LearnedHostnameHypothesis,
    ...
]:
    best: dict[
        str,
        LearnedHostnameHypothesis
    ] = {}

    for hypothesis in hypotheses:
        existing = best.get(
            hypothesis.hostname
        )

        if (
            existing is None
            or (
                hypothesis.score,
                hypothesis.confidence,
            )
            > (
                existing.score,
                existing.confidence,
            )
        ):
            best[
                hypothesis.hostname
            ] = hypothesis

    return tuple(
        sorted(
            best.values(),
            key=lambda hypothesis: (
                -hypothesis.score,
                -hypothesis.confidence,
                hypothesis.hostname,
            ),
        )
    )


def _safe_dns_name(
    value: str,
) -> str | None:
    try:
        return normalize_dns_name(
            value
        )
    except ValueError:
        return None
