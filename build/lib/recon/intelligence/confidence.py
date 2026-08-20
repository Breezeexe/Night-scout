"""Explainable confidence aggregation for Night Scout.

`confidence.py` answers a narrow question:

    "How strongly does the evidence support that this normalized observation is
    real/correct?"

It does NOT estimate vulnerability severity, scope, ownership, novelty or yield.
Those are separate Night Scout signals.

Why this module exists
----------------------
Workers already emit local confidence values, but a persistent recursive system
needs a second layer that can combine observations without double-counting the
same upstream fact.

For example::

    JavaScript bundle
        -> URL
        -> API_ENDPOINT
        -> VOCAB_TOKEN

is several Events but still largely one causal source. Conversely::

    archive observation
        + live DNS confirmation
        + live HTTP response

contains genuinely more independent evidence.

The model therefore tracks two dependency dimensions:

- `independence_key`: repeated observations that are essentially the same
  measurement/evidence channel are collapsed into one group;
- `upstream_key`: different derived channels sharing the same causal origin get
  a dependency discount instead of being counted as fully independent.

A repeated observation within one group can add a small corroboration bonus,
but never the same boost as an independent group.

Negative evidence
-----------------
Contradicting evidence is represented explicitly. Examples include NXDOMAIN or
other normalized negative observations supplied by a storage adapter.
Contradictions reduce confidence instead of merely being ignored.

Temporal semantics are deliberately not guessed here. A storage adapter should
select evidence appropriate to the question being asked (current/live state vs
historical existence) and may provide its own evidence strength/class.

Storage boundary
----------------
The module has no SQLAlchemy dependency. Persistent provenance/storage can
implement `ConfidenceEvidenceProvider` and supply evidence with causal-root
information.

The default `event_to_confidence_evidence(...)` helper can normalize an Event
when no richer storage adapter is available.

Safety
------
- no network I/O;
- no subprocesses;
- no scope/ownership inference;
- no raw bodies or secret values are copied into assessments;
- HUMAN_REVIEW/secret Events can still retain their worker confidence, but
  sensitive metadata is never copied into the explainability summary.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType


class EvidencePolarity(StrEnum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"


class EvidenceClass(StrEnum):
    """Broad evidence semantics used for reliability weighting."""

    USER_SEED = "USER_SEED"

    ACTIVE_CONFIRMATION = "ACTIVE_CONFIRMATION"
    ACTIVE_DIFFERENTIAL = "ACTIVE_DIFFERENTIAL"

    PASSIVE_OBSERVATION = "PASSIVE_OBSERVATION"
    STATIC_EXTRACTION = "STATIC_EXTRACTION"
    HISTORICAL_OBSERVATION = "HISTORICAL_OBSERVATION"

    GENERATED_HYPOTHESIS = "GENERATED_HYPOTHESIS"
    CORRELATION = "CORRELATION"
    REVIEW_SIGNAL = "REVIEW_SIGNAL"

    OTHER = "OTHER"


class ConfidenceEvidence(BaseModel):
    """One normalized piece of evidence about one logical subject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str
    subject_key: str

    polarity: EvidencePolarity
    evidence_class: EvidenceClass

    source: str
    source_family: str
    source_provider: str

    # Observations with the same independence_key are mostly one measurement.
    independence_key: str

    # Different independence groups with the same upstream key receive a
    # dependency discount rather than full independence credit.
    upstream_key: str | None = None

    # Worker/local confidence before class/dependency weighting.
    confidence: float = Field(ge=0.0, le=1.0)

    # Optional evidence-specific reliability. Class weighting is applied in
    # addition to this value.
    reliability: float = Field(default=1.0, ge=0.0, le=1.0)

    observed_at: datetime

    tags: frozenset[str] = Field(default_factory=frozenset)

    # Keep this metadata intentionally small/safe. Raw Event metadata is never
    # copied automatically.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "evidence_id",
        "subject_key",
        "source",
        "source_family",
        "source_provider",
        "independence_key",
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

    @field_validator("upstream_key")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("observed_at")
    @classmethod
    def timestamp_aware(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )


class ConfidenceGroupAssessment(BaseModel):
    """Explainability record for one collapsed evidence group."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    independence_key: str
    upstream_key: str | None = None

    polarity: EvidencePolarity

    source_families: tuple[str, ...]
    source_providers: tuple[str, ...]
    evidence_classes: tuple[EvidenceClass, ...]
    evidence_ids: tuple[str, ...]

    raw_strength: float = Field(ge=0.0, le=1.0)
    dependency_factor: float = Field(ge=0.0, le=1.0)
    effective_strength: float = Field(ge=0.0, le=1.0)

    repeated_observations: int = Field(ge=1)


class ConfidenceAssessment(BaseModel):
    """Serializable confidence result suitable for `nightscout explain`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_key: str

    prior: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    support_strength: float = Field(ge=0.0, le=1.0)
    contradiction_strength: float = Field(ge=0.0, le=1.0)
    conflict_score: float = Field(ge=0.0, le=1.0)

    supporting_groups: int = Field(ge=0)
    contradicting_groups: int = Field(ge=0)

    source_family_diversity: int = Field(ge=0)
    source_provider_diversity: int = Field(ge=0)

    evidence_count: int = Field(ge=0)
    independent_group_count: int = Field(ge=0)

    groups: tuple[ConfidenceGroupAssessment, ...]

    explanation: str

    @field_validator("subject_key", "explanation")
    @classmethod
    def required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class ConfidenceModelConfig(BaseModel):
    """Conservative weighting and dependency-discount configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    default_prior: float = Field(default=0.10, ge=0.0, le=1.0)

    event_type_priors: dict[EventType, float] = Field(
        default_factory=lambda: {
            EventType.ROOT_DOMAIN: 0.45,
            EventType.DNS_NAME: 0.10,
            EventType.DNS_RECORD: 0.12,
            EventType.IP_ADDRESS: 0.10,
            EventType.ASN: 0.10,
            EventType.CIDR: 0.10,
            EventType.URL: 0.08,
            EventType.URL_PATH: 0.08,
            EventType.HTTP_SERVICE: 0.12,
            EventType.HTTP_RESPONSE: 0.15,
            EventType.CERTIFICATE: 0.12,
            EventType.CERT_SAN: 0.08,
            EventType.FAVICON: 0.10,
            EventType.TECHNOLOGY: 0.10,
            EventType.FINGERPRINT: 0.08,
            EventType.JAVASCRIPT: 0.08,
            EventType.API_ENDPOINT: 0.08,
            EventType.PARAMETER_NAME: 0.08,
            EventType.ARTIFACT: 0.08,
            EventType.MOBILE_ARTIFACT: 0.20,
            EventType.PROJECT_NAME: 0.08,
            EventType.VOCAB_TOKEN: 0.06,
            EventType.NAMING_PATTERN: 0.06,
            EventType.VULNERABILITY_CANDIDATE: 0.18,
            EventType.VULNERABILITY_FINDING: 0.55,
            EventType.RELATIONSHIP: 0.08,
            EventType.POLICY_BLOCK: 0.90,
            EventType.HUMAN_REVIEW: 0.15,
        }
    )

    class_weights: dict[EvidenceClass, float] = Field(
        default_factory=lambda: {
            EvidenceClass.USER_SEED: 0.99,
            EvidenceClass.ACTIVE_CONFIRMATION: 1.00,
            EvidenceClass.ACTIVE_DIFFERENTIAL: 0.90,
            EvidenceClass.PASSIVE_OBSERVATION: 0.78,
            EvidenceClass.STATIC_EXTRACTION: 0.72,
            EvidenceClass.HISTORICAL_OBSERVATION: 0.62,
            EvidenceClass.GENERATED_HYPOTHESIS: 0.40,
            EvidenceClass.CORRELATION: 0.34,
            EvidenceClass.REVIEW_SIGNAL: 0.70,
            EvidenceClass.OTHER: 0.55,
        }
    )

    # Extra observations inside the same independence group only add a small
    # corroboration bonus.
    same_group_repeat_discount: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
    )

    # New groups using the same source family are useful but not fully
    # independent (e.g. two JS bundles parsed by the same extraction path).
    same_source_family_discount: float = Field(
        default=0.55,
        ge=0.0,
        le=1.0,
    )

    # Different derived evidence channels sharing one causal root are even more
    # dependent.
    same_upstream_discount: float = Field(
        default=0.40,
        ge=0.0,
        le=1.0,
    )

    # Contradictions should substantially reduce confidence but not erase all
    # historical evidence by arithmetic fiat.
    contradiction_impact: float = Field(
        default=0.92,
        ge=0.0,
        le=1.0,
    )

    hypothesis_tag_multiplier: float = Field(
        default=0.55,
        ge=0.0,
        le=1.0,
    )

    historical_tag_multiplier: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
    )

    correlation_ceiling: float = Field(
        default=0.45,
        ge=0.0,
        le=1.0,
    )

    @field_validator("event_type_priors")
    @classmethod
    def priors_in_range(
        cls,
        values: dict[EventType, float],
    ) -> dict[EventType, float]:
        for event_type, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"prior for {event_type.value} must be between 0 and 1"
                )
        return values

    @field_validator("class_weights")
    @classmethod
    def class_weights_in_range(
        cls,
        values: dict[EvidenceClass, float],
    ) -> dict[EvidenceClass, float]:
        for evidence_class, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"class weight for {evidence_class.value} must be 0..1"
                )
        return values


class ConfidenceEvidenceProvider(Protocol):
    """Storage/provenance boundary for related evidence."""

    async def evidence_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> Sequence[ConfidenceEvidence]:
        ...


class EmptyConfidenceEvidenceProvider:
    async def evidence_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> Sequence[ConfidenceEvidence]:
        del event, subject_key
        return ()


class StaticConfidenceEvidenceProvider:
    """Simple provider for tests/bootstrap."""

    def __init__(
        self,
        evidence: Sequence[ConfidenceEvidence],
    ) -> None:
        self._evidence = tuple(evidence)

    async def evidence_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> Sequence[ConfidenceEvidence]:
        del event
        return tuple(
            item
            for item in self._evidence
            if item.subject_key == subject_key
        )


class ConfidenceModel:
    """Aggregate dependent positive/negative evidence conservatively."""

    def __init__(
        self,
        *,
        provider: ConfidenceEvidenceProvider | None = None,
        config: ConfidenceModelConfig | None = None,
    ) -> None:
        self._provider = provider or EmptyConfidenceEvidenceProvider()
        self._config = config or ConfidenceModelConfig()

    @property
    def config(self) -> ConfidenceModelConfig:
        return self._config

    async def assess(
        self,
        event: Event,
        *,
        subject_key: str | None = None,
        causal_root_id: str | None = None,
    ) -> ConfidenceAssessment:
        subject = subject_key or confidence_subject_key(event)

        external = tuple(
            await self._provider.evidence_for(
                event,
                subject_key=subject,
            )
        )

        own = event_to_confidence_evidence(
            event,
            subject_key=subject,
            causal_root_id=causal_root_id,
            config=self._config,
        )

        evidence = (
            (own, *external)
            if own is not None
            else external
        )

        return assess_confidence(
            subject_key=subject,
            event_type=event.type,
            evidence=evidence,
            config=self._config,
        )

    async def apply(
        self,
        event: Event,
        *,
        subject_key: str | None = None,
        causal_root_id: str | None = None,
    ) -> Event:
        """Return an Event copy with aggregate confidence + safe explanation."""

        assessment = await self.assess(
            event,
            subject_key=subject_key,
            causal_root_id=causal_root_id,
        )

        metadata = {
            **event.metadata,
            "confidence_assessment": confidence_assessment_summary(
                assessment
            ),
        }

        return event.model_copy(
            update={
                "confidence": assessment.confidence,
                "metadata": metadata,
            },
            deep=True,
        )


def assess_confidence(
    *,
    subject_key: str,
    event_type: EventType,
    evidence: Sequence[ConfidenceEvidence],
    config: ConfidenceModelConfig | None = None,
) -> ConfidenceAssessment:
    """Pure function used by the async model and tests."""

    cfg = config or ConfidenceModelConfig()

    # Exact evidence ids are idempotent. This matters when the focus Event is
    # also returned by a storage provider.
    deduped: dict[str, ConfidenceEvidence] = {}

    for item in evidence:
        if item.subject_key != subject_key:
            continue

        existing = deduped.get(item.evidence_id)

        if existing is None or evidence_raw_strength(
            item,
            config=cfg,
        ) > evidence_raw_strength(
            existing,
            config=cfg,
        ):
            deduped[item.evidence_id] = item

    groups = collapse_evidence_groups(
        tuple(deduped.values()),
        config=cfg,
    )

    weighted_groups = apply_dependency_discounts(
        groups,
        config=cfg,
    )

    support_strength = combine_noisy_or(
        group.effective_strength
        for group in weighted_groups
        if group.polarity is EvidencePolarity.SUPPORTS
    )

    contradiction_strength = combine_noisy_or(
        group.effective_strength
        for group in weighted_groups
        if group.polarity is EvidencePolarity.CONTRADICTS
    )

    prior = cfg.event_type_priors.get(
        event_type,
        cfg.default_prior,
    )

    after_support = (
        prior
        + (
            1.0 - prior
        )
        * support_strength
    )

    final_confidence = after_support * (
        1.0
        - contradiction_strength
        * cfg.contradiction_impact
    )

    final_confidence = clamp01(final_confidence)

    source_families = {
        family
        for item in deduped.values()
        for family in (item.source_family,)
    }

    source_providers = {
        provider
        for item in deduped.values()
        for provider in (item.source_provider,)
    }

    supporting_groups = sum(
        group.polarity is EvidencePolarity.SUPPORTS
        for group in weighted_groups
    )

    contradicting_groups = sum(
        group.polarity is EvidencePolarity.CONTRADICTS
        for group in weighted_groups
    )

    conflict_score = min(
        support_strength,
        contradiction_strength,
    )

    explanation = build_confidence_explanation(
        confidence=final_confidence,
        supporting_groups=supporting_groups,
        contradicting_groups=contradicting_groups,
        source_family_diversity=len(source_families),
        conflict_score=conflict_score,
    )

    return ConfidenceAssessment(
        subject_key=subject_key,
        prior=prior,
        confidence=final_confidence,
        support_strength=support_strength,
        contradiction_strength=contradiction_strength,
        conflict_score=conflict_score,
        supporting_groups=supporting_groups,
        contradicting_groups=contradicting_groups,
        source_family_diversity=len(source_families),
        source_provider_diversity=len(source_providers),
        evidence_count=len(deduped),
        independent_group_count=len(weighted_groups),
        groups=weighted_groups,
        explanation=explanation,
    )


def event_to_confidence_evidence(
    event: Event,
    *,
    subject_key: str | None = None,
    causal_root_id: str | None = None,
    config: ConfidenceModelConfig | None = None,
) -> ConfidenceEvidence | None:
    """Normalize one Event into safe confidence evidence.

    This helper is deliberately conservative. A richer provenance adapter may
    override class/independence/upstream information when it knows more.
    """

    cfg = config or ConfidenceModelConfig()

    subject = subject_key or confidence_subject_key(event)

    evidence_class = classify_event_evidence(event)
    polarity = classify_event_polarity(event)

    source = event.source.strip()
    family = confidence_source_family(source)
    provider = confidence_source_provider(source)

    upstream = explicit_upstream_key(
        event,
        causal_root_id=causal_root_id,
        evidence_class=evidence_class,
    )

    independence = explicit_independence_key(
        event,
        subject_key=subject,
        source_provider=provider,
        upstream_key=upstream,
        evidence_class=evidence_class,
    )

    reliability = event_reliability_modifier(
        event,
        evidence_class=evidence_class,
        config=cfg,
    )

    safe_metadata = {
        "event_type": event.type.value,
        "confirmed": event_is_confirmed(event),
        "historical": event_is_historical(event),
        "hypothesis": event_is_hypothesis(event),
        "negative": polarity is EvidencePolarity.CONTRADICTS,
    }

    return ConfidenceEvidence(
        evidence_id=event.event_id,
        subject_key=subject,
        polarity=polarity,
        evidence_class=evidence_class,
        source=source,
        source_family=family,
        source_provider=provider,
        independence_key=independence,
        upstream_key=upstream,
        confidence=event.confidence,
        reliability=reliability,
        observed_at=event.last_seen,
        tags=frozenset(event.tags),
        metadata=safe_metadata,
    )


def collapse_evidence_groups(
    evidence: Sequence[ConfidenceEvidence],
    *,
    config: ConfidenceModelConfig,
) -> tuple[ConfidenceGroupAssessment, ...]:
    """Collapse repeat observations inside one independence channel."""

    grouped: dict[
        tuple[str, EvidencePolarity],
        list[ConfidenceEvidence],
    ] = defaultdict(list)

    for item in evidence:
        grouped[
            (
                item.independence_key,
                item.polarity,
            )
        ].append(item)

    result: list[ConfidenceGroupAssessment] = []

    for (
        independence_key,
        polarity,
    ), members in grouped.items():
        ordered = sorted(
            members,
            key=lambda item: (
                -evidence_raw_strength(
                    item,
                    config=config,
                ),
                item.evidence_id,
            ),
        )

        strengths = [
            evidence_raw_strength(
                item,
                config=config,
            )
            for item in ordered
        ]

        strongest = strengths[0]

        repeated_bonus = combine_noisy_or(
            strength
            * config.same_group_repeat_discount
            for strength in strengths[1:]
        )

        group_strength = strongest + (
            1.0 - strongest
        ) * repeated_bonus

        upstream_keys = {
            item.upstream_key
            for item in ordered
            if item.upstream_key is not None
        }

        # One independence group should usually have one upstream. If an
        # adapter supplied several, fail conservative and avoid pretending the
        # group has a single independent causal root.
        upstream_key = (
            next(iter(upstream_keys))
            if len(upstream_keys) == 1
            else None
        )

        result.append(
            ConfidenceGroupAssessment(
                independence_key=independence_key,
                upstream_key=upstream_key,
                polarity=polarity,
                source_families=tuple(
                    sorted(
                        {
                            item.source_family
                            for item in ordered
                        }
                    )
                ),
                source_providers=tuple(
                    sorted(
                        {
                            item.source_provider
                            for item in ordered
                        }
                    )
                ),
                evidence_classes=tuple(
                    sorted(
                        {
                            item.evidence_class
                            for item in ordered
                        },
                        key=lambda value: value.value,
                    )
                ),
                evidence_ids=tuple(
                    item.evidence_id
                    for item in ordered
                ),
                raw_strength=clamp01(group_strength),
                dependency_factor=1.0,
                effective_strength=clamp01(group_strength),
                repeated_observations=len(ordered),
            )
        )

    return tuple(
        sorted(
            result,
            key=lambda group: (
                group.polarity.value,
                -group.raw_strength,
                group.independence_key,
            ),
        )
    )


def apply_dependency_discounts(
    groups: Sequence[ConfidenceGroupAssessment],
    *,
    config: ConfidenceModelConfig,
) -> tuple[ConfidenceGroupAssessment, ...]:
    """Discount groups sharing source families or causal upstreams.

    Positive and negative evidence maintain separate dependency histories. A
    positive DNS confirmation must not suppress the weight of a negative DNS
    contradiction merely because both come from the DNS family.
    """

    result: list[ConfidenceGroupAssessment] = []

    for polarity in (
        EvidencePolarity.SUPPORTS,
        EvidencePolarity.CONTRADICTS,
    ):
        seen_families: Counter[str] = Counter()
        seen_upstreams: Counter[str] = Counter()

        relevant = sorted(
            (
                group
                for group in groups
                if group.polarity is polarity
            ),
            key=lambda group: (
                -group.raw_strength,
                group.independence_key,
            ),
        )

        for group in relevant:
            factor = 1.0

            if any(
                seen_families[family] > 0
                for family in group.source_families
            ):
                factor *= config.same_source_family_discount

            if (
                group.upstream_key is not None
                and seen_upstreams[group.upstream_key] > 0
            ):
                factor *= config.same_upstream_discount

            effective = clamp01(
                group.raw_strength
                * factor
            )

            result.append(
                group.model_copy(
                    update={
                        "dependency_factor": factor,
                        "effective_strength": effective,
                    }
                )
            )

            for family in group.source_families:
                seen_families[family] += 1

            if group.upstream_key is not None:
                seen_upstreams[group.upstream_key] += 1

    return tuple(
        sorted(
            result,
            key=lambda group: (
                group.polarity.value,
                -group.effective_strength,
                group.independence_key,
            ),
        )
    )


def evidence_raw_strength(
    evidence: ConfidenceEvidence,
    *,
    config: ConfidenceModelConfig,
) -> float:
    class_weight = config.class_weights.get(
        evidence.evidence_class,
        config.class_weights[EvidenceClass.OTHER],
    )

    strength = (
        evidence.confidence
        * evidence.reliability
        * class_weight
    )

    if (
        evidence.evidence_class
        is EvidenceClass.CORRELATION
    ):
        strength = min(
            strength,
            config.correlation_ceiling,
        )

    return clamp01(strength)


def classify_event_evidence(
    event: Event,
) -> EvidenceClass:
    tags = normalized_event_tags(event)
    source_family = confidence_source_family(event.source)

    if event.type is EventType.ROOT_DOMAIN and (
        "seed" in tags
        or source_family in {
            "seed",
            "user",
            "manual",
        }
    ):
        return EvidenceClass.USER_SEED

    if (
        "negative" in tags
        or event.metadata.get("negative") is True
    ):
        return EvidenceClass.ACTIVE_CONFIRMATION

    if event_is_confirmed(event):
        if (
            "vhost-confirmed" in tags
            or "differential" in tags
            or source_family == "vhost"
        ):
            return EvidenceClass.ACTIVE_DIFFERENTIAL

        if source_family in {
            "dns",
            "http",
            "tls",
            "crawler",
            "parameters",
            "content",
        }:
            return EvidenceClass.ACTIVE_CONFIRMATION

    if event_is_historical(event):
        return EvidenceClass.HISTORICAL_OBSERVATION

    if event_is_hypothesis(event):
        return EvidenceClass.GENERATED_HYPOTHESIS

    if (
        event.type is EventType.VULNERABILITY_FINDING
        and "nuclei-match" in tags
        and source_family == "nuclei"
    ):
        return EvidenceClass.ACTIVE_DIFFERENTIAL

    if event.type is EventType.FINGERPRINT or source_family == "fingerprints":
        return EvidenceClass.CORRELATION

    if event.type is EventType.HUMAN_REVIEW:
        return EvidenceClass.REVIEW_SIGNAL

    if source_family in {
        "javascript",
        "mobile",
        "vocabulary",
        "patterns",
    } or "local-static-analysis" in tags:
        return EvidenceClass.STATIC_EXTRACTION

    if source_family in {
        "archives",
        "archive",
        "subfinder",
        "asn",
        "passive",
    }:
        return EvidenceClass.PASSIVE_OBSERVATION

    if event.type in {
        EventType.CERT_SAN,
        EventType.TECHNOLOGY,
        EventType.PARAMETER_NAME,
        EventType.PROJECT_NAME,
        EventType.VOCAB_TOKEN,
        EventType.NAMING_PATTERN,
    }:
        return EvidenceClass.STATIC_EXTRACTION

    return EvidenceClass.OTHER


def classify_event_polarity(
    event: Event,
) -> EvidencePolarity:
    tags = normalized_event_tags(event)

    if (
        "negative" in tags
        or "nxdomain" in tags
        or "nodata" in tags
        or event.metadata.get("negative") is True
    ):
        return EvidencePolarity.CONTRADICTS

    return EvidencePolarity.SUPPORTS


def event_reliability_modifier(
    event: Event,
    *,
    evidence_class: EvidenceClass,
    config: ConfidenceModelConfig,
) -> float:
    reliability = 1.0

    if event_is_hypothesis(event):
        reliability *= config.hypothesis_tag_multiplier

    if event_is_historical(event):
        reliability *= config.historical_tag_multiplier

    if evidence_class is EvidenceClass.CORRELATION:
        reliability *= 0.90

    # A possible-secret review Event may be highly confident that a detector
    # fired, but that confidence must not be interpreted as credential validity.
    if event.type is EventType.HUMAN_REVIEW and (
        "possible-secret" in normalized_event_tags(event)
    ):
        reliability *= 0.75

    return clamp01(reliability)


def confidence_subject_key(
    event: Event,
) -> str:
    """Return a conservative same-semantic-type subject key.

    The default mapper intentionally does not equate an HTTP Host-header hit
    with DNS existence. Cross-type canonical-asset joins belong in storage.
    """

    explicit = event.metadata.get("confidence_subject_key")

    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()

    if event.type in {
        EventType.DNS_NAME,
        EventType.CERT_SAN,
    }:
        hostname = normalize_dnsish(event.value)
        return f"dns:{hostname}"

    if event.type is EventType.DNS_RECORD:
        owner = dns_record_owner(event)
        if owner is not None:
            return f"dns:{owner}"

    if event.type is EventType.IP_ADDRESS:
        return f"ip:{event.value.strip().lower()}"

    if event.type in {
        EventType.URL,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
    }:
        normalized_url = normalize_urlish(event.value)
        return f"url:{normalized_url}"

    if event.type is EventType.HTTP_SERVICE:
        normalized_url = normalize_urlish(event.value)
        return f"http-service:{normalized_url}"

    if event.type is EventType.HTTP_RESPONSE:
        url = first_string_metadata(
            event,
            "url",
            "service_url",
            "observed_on",
        )
        if url is not None:
            return f"http-response:{normalize_urlish(url)}"

    if event.type is EventType.CERTIFICATE:
        fingerprint = first_certificate_fingerprint(event)
        if fingerprint is not None:
            return f"certificate:{fingerprint}"

    return f"{event.type.value.lower()}:{event.value.strip().lower()}"


def explicit_upstream_key(
    event: Event,
    *,
    causal_root_id: str | None,
    evidence_class: EvidenceClass,
) -> str | None:
    explicit = event.metadata.get("confidence_upstream_key")

    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    if causal_root_id is not None and causal_root_id.strip():
        return causal_root_id.strip()

    # A live active measurement adds new evidence even when triggered by a
    # hypothesis, so its parent hypothesis is not treated as the measurement's
    # causal dependency for confidence purposes.
    if evidence_class in {
        EvidenceClass.ACTIVE_CONFIRMATION,
        EvidenceClass.ACTIVE_DIFFERENTIAL,
        EvidenceClass.USER_SEED,
    }:
        return None

    return event.parent_event_id


def explicit_independence_key(
    event: Event,
    *,
    subject_key: str,
    source_provider: str,
    upstream_key: str | None,
    evidence_class: EvidenceClass,
) -> str:
    explicit = event.metadata.get("confidence_independence_key")

    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    if evidence_class in {
        EvidenceClass.ACTIVE_CONFIRMATION,
        EvidenceClass.ACTIVE_DIFFERENTIAL,
    }:
        # Repeated A/AAAA records or repeated same-backend measurements about
        # the same subject collapse to one channel by default.
        return (
            f"measurement:{source_provider}:"
            f"{subject_key}"
        )

    if upstream_key is not None:
        return (
            f"derived:{source_provider}:"
            f"{upstream_key}"
        )

    return (
        f"source:{source_provider}:"
        f"{subject_key}"
    )


def confidence_source_family(
    source: str,
) -> str:
    normalized = source.strip().lower()

    if not normalized:
        return "unknown"

    return normalized.split(":", 1)[0] or "unknown"


def confidence_source_provider(
    source: str,
) -> str:
    """Keep one provider/backend component beyond the broad family."""

    normalized = source.strip().lower()

    if not normalized:
        return "unknown"

    parts = [
        part
        for part in normalized.split(":")
        if part
    ]

    if len(parts) <= 1:
        return parts[0] if parts else "unknown"

    return ":".join(parts[:2])


def event_is_confirmed(
    event: Event,
) -> bool:
    tags = normalized_event_tags(event)

    return bool(
        "confirmed" in tags
        or "vhost-confirmed" in tags
        or event.metadata.get("confirmed") is True
        or event.metadata.get("active_confirmation") is True
    )


def event_is_historical(
    event: Event,
) -> bool:
    tags = normalized_event_tags(event)

    return bool(
        "historical" in tags
        or "archive" in tags
        or confidence_source_family(event.source)
        in {
            "archives",
            "archive",
        }
        or "archive_observed_at" in event.metadata
    )


def event_is_hypothesis(
    event: Event,
) -> bool:
    tags = normalized_event_tags(event)

    return bool(
        "hypothesis" in tags
        or event.metadata.get("hypothesis") is True
        or event.metadata.get("requires_dns_confirmation") is True
        or event.metadata.get("requires_scope_reclassification") is True
    )


def normalized_event_tags(
    event: Event,
) -> frozenset[str]:
    return frozenset(
        tag.strip().lower()
        for tag in event.tags
        if tag.strip()
    )


def confidence_assessment_summary(
    assessment: ConfidenceAssessment,
) -> dict[str, Any]:
    """Return a safe compact JSON-ready explanation.

    Evidence metadata is intentionally omitted so secret/body data cannot be
    accidentally promoted into Event metadata through this helper.
    """

    return {
        "subject_key": assessment.subject_key,
        "prior": assessment.prior,
        "confidence": assessment.confidence,
        "support_strength": assessment.support_strength,
        "contradiction_strength": assessment.contradiction_strength,
        "conflict_score": assessment.conflict_score,
        "supporting_groups": assessment.supporting_groups,
        "contradicting_groups": assessment.contradicting_groups,
        "source_family_diversity": assessment.source_family_diversity,
        "source_provider_diversity": assessment.source_provider_diversity,
        "evidence_count": assessment.evidence_count,
        "independent_group_count": assessment.independent_group_count,
        "explanation": assessment.explanation,
        "groups": [
            {
                "independence_key": group.independence_key,
                "upstream_key": group.upstream_key,
                "polarity": group.polarity.value,
                "source_families": list(group.source_families),
                "source_providers": list(group.source_providers),
                "evidence_classes": [
                    evidence_class.value
                    for evidence_class in group.evidence_classes
                ],
                "evidence_ids": list(group.evidence_ids),
                "raw_strength": group.raw_strength,
                "dependency_factor": group.dependency_factor,
                "effective_strength": group.effective_strength,
                "repeated_observations": group.repeated_observations,
            }
            for group in assessment.groups
        ],
        "scope_inference": False,
        "ownership_inference": False,
    }


def build_confidence_explanation(
    *,
    confidence: float,
    supporting_groups: int,
    contradicting_groups: int,
    source_family_diversity: int,
    conflict_score: float,
) -> str:
    if supporting_groups == 0 and contradicting_groups == 0:
        return "no normalized evidence beyond the configured prior"

    parts = [
        f"{supporting_groups} supporting independent group(s)",
        f"{source_family_diversity} source family/families",
    ]

    if contradicting_groups:
        parts.append(
            f"{contradicting_groups} contradicting group(s)"
        )

    if conflict_score >= 0.35:
        parts.append("material evidence conflict")

    parts.append(
        f"aggregate confidence {confidence:.3f}"
    )

    return "; ".join(parts)


def combine_noisy_or(
    values: Sequence[float] | Any,
) -> float:
    product = 1.0
    seen = False

    for value in values:
        seen = True
        product *= 1.0 - clamp01(float(value))

    if not seen:
        return 0.0

    return clamp01(1.0 - product)


def clamp01(
    value: float,
) -> float:
    return min(
        1.0,
        max(
            0.0,
            float(value),
        ),
    )


def normalize_dnsish(
    value: str,
) -> str:
    normalized = value.strip().lower().rstrip(".")

    if normalized.startswith("*."):
        normalized = normalized[2:]

    return normalized


def normalize_urlish(
    value: str,
) -> str:
    raw = value.strip()

    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw.lower()

    if not parts.scheme or not parts.netloc:
        return raw.lower()

    hostname = (
        parts.hostname.lower()
        if parts.hostname is not None
        else ""
    )

    port = parts.port

    if port is None:
        netloc = hostname
    elif (
        parts.scheme.lower() == "http"
        and port == 80
    ) or (
        parts.scheme.lower() == "https"
        and port == 443
    ):
        netloc = hostname
    else:
        netloc = f"{hostname}:{port}"

    return urlunsplit(
        (
            parts.scheme.lower(),
            netloc,
            parts.path or "/",
            parts.query,
            "",
        )
    )


def dns_record_owner(
    event: Event,
) -> str | None:
    owner = event.metadata.get("owner")

    if isinstance(owner, str) and owner.strip():
        return normalize_dnsish(owner)

    value = event.value.strip()

    for marker in (
        " RCODE ",
        " A NODATA",
        " AAAA NODATA",
        " CNAME NODATA",
    ):
        if marker in value:
            candidate = value.split(marker, 1)[0].strip()
            return normalize_dnsish(candidate) if candidate else None

    # Positive DNS_RECORD values are usually: owner TYPE value.
    pieces = value.split()
    if len(pieces) >= 3:
        return normalize_dnsish(pieces[0])

    return None


def first_string_metadata(
    event: Event,
    *keys: str,
) -> str | None:
    for key in keys:
        value = event.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def first_certificate_fingerprint(
    event: Event,
) -> str | None:
    direct = event.metadata.get("fingerprint_sha256")

    if isinstance(direct, str) and direct.strip():
        return normalize_hashish(direct)

    surface = event.metadata.get("surface_state")
    if isinstance(surface, dict):
        values = surface.get("certificate_fingerprints")

        if isinstance(values, str) and values.strip():
            return normalize_hashish(values)

        if isinstance(values, (list, tuple, set)):
            for value in values:
                if isinstance(value, str) and value.strip():
                    return normalize_hashish(value)

    return None


def normalize_hashish(
    value: str,
) -> str:
    return re.sub(
        r"[^0-9a-f]",
        "",
        value.strip().lower(),
    )
