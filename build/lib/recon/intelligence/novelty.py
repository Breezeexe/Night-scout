"""Explainable novelty scoring for Night Scout.

`novelty.py` answers a deliberately narrow question:

    "How new / unusual / changed is this observation relative to the attack
    surface we already know?"

It does NOT estimate:
- vulnerability severity;
- exploitability;
- authorization/scope;
- confidence that the observation is correct;
- worker yield.

Those are separate Night Scout signals.

Why novelty is separate
-----------------------
A highly confident asset may be completely routine::

    www.example.com
    seen in 40 runs
    same body/title/fingerprint

Conversely, a weakly confirmed historical observation can be novel::

    preprod-api.example.com
    only present in archives
    never seen in the current surface

Novelty is therefore about *difference from known state*, not truth or risk.

Main inputs
-----------
The model can use:
- current Event type/tags/value;
- first/previous/last seen history;
- observation count;
- historical-only vs live observations;
- snapshot change types such as NEW_ENDPOINT, BODY_HASH_CHANGED,
  RESURRECTED_HOST, NEW_CERT_SAN;
- peer frequency of fingerprints/technology stacks;
- naming/token frequency supplied by Target Genome.

The persistence boundary is `NoveltyHistoryProvider`; this module has no
SQLAlchemy dependency. `history_with_surface_changes(...)` accepts snapshot
change objects by their public attributes without importing the storage layer.

Safety
------
- no network I/O;
- no subprocesses;
- no scope/ownership inference;
- no credential handling;
- novelty never authorizes a follow-up action;
- novelty alone never opens a human-review case.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType


class NoveltyFactorKind(StrEnum):
    """Explainable reasons that can raise/lower novelty."""

    EVENT_TYPE_BASELINE = "EVENT_TYPE_BASELINE"

    FIRST_OBSERVATION = "FIRST_OBSERVATION"
    LOW_OBSERVATION_COUNT = "LOW_OBSERVATION_COUNT"
    REPEATED_OBSERVATION = "REPEATED_OBSERVATION"

    HISTORICAL_ONLY = "HISTORICAL_ONLY"
    LIVE_AFTER_HISTORICAL = "LIVE_AFTER_HISTORICAL"

    NEW_HOST = "NEW_HOST"
    NEW_URL = "NEW_URL"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    NEW_CERT_SAN = "NEW_CERT_SAN"
    NEW_JAVASCRIPT = "NEW_JAVASCRIPT"
    NEW_ASSET = "NEW_ASSET"

    RESURRECTED_HOST = "RESURRECTED_HOST"
    REAPPEARED_ASSET = "REAPPEARED_ASSET"
    DISAPPEARED_HOST = "DISAPPEARED_HOST"
    DISAPPEARED_ASSET = "DISAPPEARED_ASSET"

    IP_CHANGED = "IP_CHANGED"
    STATUS_CHANGED = "STATUS_CHANGED"
    TITLE_CHANGED = "TITLE_CHANGED"
    BODY_HASH_CHANGED = "BODY_HASH_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    SCOPE_CHANGED = "SCOPE_CHANGED"
    STATE_CHANGED = "STATE_CHANGED"

    ENVIRONMENT_SIGNAL = "ENVIRONMENT_SIGNAL"
    API_VERSION_SIGNAL = "API_VERSION_SIGNAL"

    RARE_FINGERPRINT = "RARE_FINGERPRINT"
    COMMON_FINGERPRINT = "COMMON_FINGERPRINT"
    RARE_TECH_STACK = "RARE_TECH_STACK"
    COMMON_TECH_STACK = "COMMON_TECH_STACK"
    RARE_NAMING = "RARE_NAMING"
    COMMON_NAMING = "COMMON_NAMING"

    STATIC_SURFACE = "STATIC_SURFACE"
    CDN_SURFACE = "CDN_SURFACE"
    MARKETING_SURFACE = "MARKETING_SURFACE"


class NoveltyFactorDirection(StrEnum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL = "NEUTRAL"


class NoveltyFactor(BaseModel):
    """One explainability item used by the novelty assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: NoveltyFactorKind
    direction: NoveltyFactorDirection

    weight: float = Field(ge=0.0, le=1.0)
    value: float = Field(ge=0.0, le=1.0)

    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason")
    @classmethod
    def reason_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("novelty factor reason must not be blank")
        return normalized

    @property
    def contribution(self) -> float:
        amount = self.weight * self.value

        if self.direction is NoveltyFactorDirection.NEGATIVE:
            return -amount
        if self.direction is NoveltyFactorDirection.NEUTRAL:
            return 0.0
        return amount


class NoveltyHistory(BaseModel):
    """Storage-independent historical context for one logical subject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_key: str

    observation_count: int = Field(default=0, ge=0)
    live_observation_count: int = Field(default=0, ge=0)
    historical_observation_count: int = Field(default=0, ge=0)

    distinct_source_families: int = Field(default=0, ge=0)

    first_seen_at: datetime | None = None
    previous_seen_at: datetime | None = None
    last_seen_at: datetime | None = None

    # Snapshot change names are kept as strings to avoid coupling this module
    # to SQLAlchemy/storage imports. Expected values match ChangeType.value.
    change_types: tuple[str, ...] = ()
    change_fingerprints: tuple[str, ...] = ()

    # Number of *other or total peer assets* sharing an equivalent signature.
    # 0 means unknown unless the corresponding *_known flag is True.
    fingerprint_peer_count: int = Field(default=0, ge=0)
    fingerprint_peer_count_known: bool = False

    technology_peer_count: int = Field(default=0, ge=0)
    technology_peer_count_known: bool = False

    # Frequency among target naming observations, normalized 0..1.
    naming_frequency: float | None = Field(default=None, ge=0.0, le=1.0)

    # Explicit storage-derived state signals.
    historical_only: bool = False
    live_after_historical: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("subject_key")
    @classmethod
    def subject_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("subject_key must not be blank")
        return normalized

    @field_validator("first_seen_at", "previous_seen_at", "last_seen_at")
    @classmethod
    def timestamps_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ValueError("novelty history timestamps must be timezone-aware")
        return value

    @field_validator("change_types")
    @classmethod
    def normalize_change_types(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    str(value).strip().upper()
                    for value in values
                    if str(value).strip()
                }
            )
        )

    @field_validator("change_fingerprints")
    @classmethod
    def normalize_change_fingerprints(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    str(value).strip()
                    for value in values
                    if str(value).strip()
                }
            )
        )

    @model_validator(mode="after")
    def count_invariants(self) -> "NoveltyHistory":
        if self.live_observation_count > self.observation_count:
            raise ValueError(
                "live_observation_count cannot exceed observation_count"
            )
        if self.historical_observation_count > self.observation_count:
            raise ValueError(
                "historical_observation_count cannot exceed observation_count"
            )
        return self


class NoveltyAssessment(BaseModel):
    """Serializable novelty result suitable for `nightscout explain`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_key: str
    novelty: float = Field(ge=0.0, le=1.0)

    baseline: float = Field(ge=0.0, le=1.0)
    positive_union: float = Field(ge=0.0, le=1.0)
    negative_union: float = Field(ge=0.0, le=1.0)

    observation_count: int = Field(ge=0)
    distinct_source_families: int = Field(ge=0)

    factors: tuple[NoveltyFactor, ...]
    explanation: str

    @field_validator("subject_key", "explanation")
    @classmethod
    def text_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class NoveltyModelConfig(BaseModel):
    """Conservative novelty weights.

    Scores are intentionally bounded and interpretable. A single semantic hint
    such as `stage` cannot make a common duplicate maximally novel.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    default_baseline: float = Field(default=0.30, ge=0.0, le=1.0)

    event_type_baselines: dict[EventType, float] = Field(
        default_factory=lambda: {
            EventType.ROOT_DOMAIN: 0.15,
            EventType.DNS_NAME: 0.38,
            EventType.DNS_RECORD: 0.24,
            EventType.IP_ADDRESS: 0.22,
            EventType.ASN: 0.12,
            EventType.CIDR: 0.16,
            EventType.URL: 0.38,
            EventType.URL_PATH: 0.28,
            EventType.HTTP_SERVICE: 0.34,
            EventType.HTTP_RESPONSE: 0.24,
            EventType.CERTIFICATE: 0.32,
            EventType.CERT_SAN: 0.44,
            EventType.FAVICON: 0.30,
            EventType.TECHNOLOGY: 0.18,
            EventType.FINGERPRINT: 0.30,
            EventType.JAVASCRIPT: 0.42,
            EventType.API_ENDPOINT: 0.52,
            EventType.PARAMETER_NAME: 0.35,
            EventType.ARTIFACT: 0.40,
            EventType.MOBILE_ARTIFACT: 0.45,
            EventType.PROJECT_NAME: 0.34,
            EventType.VOCAB_TOKEN: 0.16,
            EventType.NAMING_PATTERN: 0.32,
            EventType.VULNERABILITY_CANDIDATE: 0.58,
            EventType.VULNERABILITY_FINDING: 0.82,
            EventType.RELATIONSHIP: 0.18,
            EventType.POLICY_BLOCK: 0.05,
            EventType.HUMAN_REVIEW: 0.20,
        }
    )

    first_observation_weight: float = Field(default=0.34, ge=0.0, le=1.0)
    low_observation_weight: float = Field(default=0.16, ge=0.0, le=1.0)

    historical_only_weight: float = Field(default=0.24, ge=0.0, le=1.0)
    live_after_historical_weight: float = Field(default=0.38, ge=0.0, le=1.0)

    environment_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    api_version_weight: float = Field(default=0.12, ge=0.0, le=1.0)

    rare_fingerprint_weight: float = Field(default=0.24, ge=0.0, le=1.0)
    rare_technology_weight: float = Field(default=0.14, ge=0.0, le=1.0)
    rare_naming_weight: float = Field(default=0.18, ge=0.0, le=1.0)

    repeated_penalty_weight: float = Field(default=0.42, ge=0.0, le=1.0)
    common_fingerprint_penalty_weight: float = Field(
        default=0.28, ge=0.0, le=1.0
    )
    common_technology_penalty_weight: float = Field(
        default=0.16, ge=0.0, le=1.0
    )
    common_naming_penalty_weight: float = Field(
        default=0.14, ge=0.0, le=1.0
    )

    static_penalty_weight: float = Field(default=0.16, ge=0.0, le=1.0)
    cdn_penalty_weight: float = Field(default=0.18, ge=0.0, le=1.0)
    marketing_penalty_weight: float = Field(default=0.14, ge=0.0, le=1.0)

    # Snapshot change weights. They express "interesting difference", not risk.
    change_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "NEW_HOST": 0.58,
            "NEW_URL": 0.48,
            "NEW_ENDPOINT": 0.70,
            "NEW_CERT_SAN": 0.58,
            "NEW_JAVASCRIPT": 0.52,
            "NEW_ASSET": 0.45,
            "RESURRECTED_HOST": 0.78,
            "REAPPEARED_ASSET": 0.68,
            "DISAPPEARED_HOST": 0.48,
            "DISAPPEARED_ASSET": 0.40,
            "IP_CHANGED": 0.44,
            "STATUS_CHANGED": 0.28,
            "TITLE_CHANGED": 0.24,
            "BODY_HASH_CHANGED": 0.42,
            "CERTIFICATE_CHANGED": 0.48,
            "SCOPE_CHANGED": 0.34,
            "STATE_CHANGED": 0.20,
        }
    )

    @field_validator("event_type_baselines")
    @classmethod
    def baselines_in_range(
        cls,
        values: dict[EventType, float],
    ) -> dict[EventType, float]:
        for event_type, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"baseline for {event_type.value} must be between 0 and 1"
                )
        return values

    @field_validator("change_weights")
    @classmethod
    def change_weights_in_range(
        cls,
        values: dict[str, float],
    ) -> dict[str, float]:
        normalized: dict[str, float] = {}
        for key, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"change weight for {key} must be 0..1")
            normalized[str(key).strip().upper()] = value
        return normalized


class NoveltyHistoryProvider(Protocol):
    """Persistence/Target-Genome boundary for novelty history."""

    async def history_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> NoveltyHistory:
        ...


class EmptyNoveltyHistoryProvider:
    async def history_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> NoveltyHistory:
        del event
        return NoveltyHistory(subject_key=subject_key)


class StaticNoveltyHistoryProvider:
    """Simple deterministic provider useful for bootstrap/tests."""

    def __init__(self, histories: Sequence[NoveltyHistory]) -> None:
        self._histories = {
            history.subject_key: history
            for history in histories
        }

    async def history_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> NoveltyHistory:
        del event
        return self._histories.get(
            subject_key,
            NoveltyHistory(subject_key=subject_key),
        )


class NoveltyModel:
    """Assess how different an Event is from the known target surface."""

    def __init__(
        self,
        provider: NoveltyHistoryProvider | None = None,
        *,
        config: NoveltyModelConfig | None = None,
    ) -> None:
        self._provider = provider or EmptyNoveltyHistoryProvider()
        self._config = config or NoveltyModelConfig()

    @property
    def config(self) -> NoveltyModelConfig:
        return self._config

    async def assess(self, event: Event) -> NoveltyAssessment:
        subject_key = novelty_subject_key(event)
        history = await self._provider.history_for(
            event,
            subject_key=subject_key,
        )

        if history.subject_key != subject_key:
            raise ValueError(
                "NoveltyHistoryProvider returned history for a different subject"
            )

        return assess_novelty(
            event,
            history=history,
            config=self._config,
        )

    async def score(self, event: Event) -> float:
        return (await self.assess(event)).novelty

    async def scored_event(
        self,
        event: Event,
        *,
        include_explainability_metadata: bool = True,
    ) -> Event:
        assessment = await self.assess(event)
        return event_with_novelty(
            event,
            assessment,
            include_explainability_metadata=include_explainability_metadata,
        )


def assess_novelty(
    event: Event,
    *,
    history: NoveltyHistory,
    config: NoveltyModelConfig | None = None,
) -> NoveltyAssessment:
    """Pure novelty assessment from an Event + normalized history."""

    cfg = config or NoveltyModelConfig()
    subject_key = novelty_subject_key(event)

    if history.subject_key != subject_key:
        raise ValueError("history subject_key does not match Event")

    baseline = cfg.event_type_baselines.get(
        event.type,
        cfg.default_baseline,
    )

    factors: list[NoveltyFactor] = [
        NoveltyFactor(
            kind=NoveltyFactorKind.EVENT_TYPE_BASELINE,
            direction=NoveltyFactorDirection.NEUTRAL,
            weight=1.0,
            value=baseline,
            reason=f"{event.type.value} baseline novelty",
        )
    ]

    positive: list[float] = []
    negative: list[float] = []

    def add_positive(
        kind: NoveltyFactorKind,
        *,
        weight: float,
        value: float,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        bounded = clamp01(value)
        factors.append(
            NoveltyFactor(
                kind=kind,
                direction=NoveltyFactorDirection.POSITIVE,
                weight=weight,
                value=bounded,
                reason=reason,
                metadata=dict(metadata or {}),
            )
        )
        positive.append(clamp01(weight * bounded))

    def add_negative(
        kind: NoveltyFactorKind,
        *,
        weight: float,
        value: float,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        bounded = clamp01(value)
        factors.append(
            NoveltyFactor(
                kind=kind,
                direction=NoveltyFactorDirection.NEGATIVE,
                weight=weight,
                value=bounded,
                reason=reason,
                metadata=dict(metadata or {}),
            )
        )
        negative.append(clamp01(weight * bounded))

    if history.observation_count <= 0:
        add_positive(
            NoveltyFactorKind.FIRST_OBSERVATION,
            weight=cfg.first_observation_weight,
            value=1.0,
            reason="subject has no prior normalized observations",
        )
    elif history.observation_count <= 3:
        add_positive(
            NoveltyFactorKind.LOW_OBSERVATION_COUNT,
            weight=cfg.low_observation_weight,
            value=(4 - history.observation_count) / 3.0,
            reason="subject has only a small prior observation history",
            metadata={"observation_count": history.observation_count},
        )
    else:
        repetition = repetition_penalty_value(history.observation_count)
        add_negative(
            NoveltyFactorKind.REPEATED_OBSERVATION,
            weight=cfg.repeated_penalty_weight,
            value=repetition,
            reason="repeated observations reduce marginal novelty",
            metadata={"observation_count": history.observation_count},
        )

    historical_only = history.historical_only or event_is_historical_only(
        event,
        history,
    )

    if historical_only:
        add_positive(
            NoveltyFactorKind.HISTORICAL_ONLY,
            weight=cfg.historical_only_weight,
            value=1.0,
            reason="asset is known only from historical/passive history",
        )

    if history.live_after_historical:
        add_positive(
            NoveltyFactorKind.LIVE_AFTER_HISTORICAL,
            weight=cfg.live_after_historical_weight,
            value=1.0,
            reason="asset moved from historical-only evidence to live observation",
        )

    for change_type in history.change_types:
        weight = cfg.change_weights.get(change_type)
        if weight is None:
            continue

        kind = novelty_factor_for_change(change_type)
        if kind is None:
            continue

        add_positive(
            kind,
            weight=weight,
            value=1.0,
            reason=f"snapshot/history reports {change_type}",
            metadata={"change_type": change_type},
        )

    environment_hits = environment_signals(event)
    if environment_hits:
        add_positive(
            NoveltyFactorKind.ENVIRONMENT_SIGNAL,
            weight=cfg.environment_weight,
            value=min(1.0, 0.55 + 0.15 * len(environment_hits)),
            reason="target naming contains non-production/environment vocabulary",
            metadata={"tokens": list(environment_hits)},
        )

    api_versions = api_version_signals(event)
    if api_versions:
        add_positive(
            NoveltyFactorKind.API_VERSION_SIGNAL,
            weight=cfg.api_version_weight,
            value=min(1.0, 0.6 + 0.1 * len(api_versions)),
            reason="API version vocabulary is present",
            metadata={"versions": list(api_versions)},
        )

    if history.fingerprint_peer_count_known:
        peers = history.fingerprint_peer_count
        if peers <= 1:
            add_positive(
                NoveltyFactorKind.RARE_FINGERPRINT,
                weight=cfg.rare_fingerprint_weight,
                value=1.0,
                reason="fingerprint is unique or nearly unique among target peers",
                metadata={"peer_count": peers},
            )
        elif peers >= 8:
            add_negative(
                NoveltyFactorKind.COMMON_FINGERPRINT,
                weight=cfg.common_fingerprint_penalty_weight,
                value=peer_commonness(peers, pivot=8),
                reason="fingerprint is shared by many target peers",
                metadata={"peer_count": peers},
            )

    if history.technology_peer_count_known:
        peers = history.technology_peer_count
        if peers <= 2:
            add_positive(
                NoveltyFactorKind.RARE_TECH_STACK,
                weight=cfg.rare_technology_weight,
                value=1.0,
                reason="technology combination is uncommon among target peers",
                metadata={"peer_count": peers},
            )
        elif peers >= 12:
            add_negative(
                NoveltyFactorKind.COMMON_TECH_STACK,
                weight=cfg.common_technology_penalty_weight,
                value=peer_commonness(peers, pivot=12),
                reason="technology combination is common among target peers",
                metadata={"peer_count": peers},
            )

    if history.naming_frequency is not None:
        frequency = history.naming_frequency
        if frequency <= 0.08:
            add_positive(
                NoveltyFactorKind.RARE_NAMING,
                weight=cfg.rare_naming_weight,
                value=clamp01((0.08 - frequency) / 0.08),
                reason="hostname/path vocabulary is rare in the target genome",
                metadata={"naming_frequency": frequency},
            )
        elif frequency >= 0.55:
            add_negative(
                NoveltyFactorKind.COMMON_NAMING,
                weight=cfg.common_naming_penalty_weight,
                value=clamp01((frequency - 0.55) / 0.45),
                reason="hostname/path vocabulary is common in the target genome",
                metadata={"naming_frequency": frequency},
            )

    surface_roles = low_novelty_surface_roles(event)

    if "static" in surface_roles:
        add_negative(
            NoveltyFactorKind.STATIC_SURFACE,
            weight=cfg.static_penalty_weight,
            value=1.0,
            reason="observation appears to be a routine static-asset surface",
        )

    if "cdn" in surface_roles:
        add_negative(
            NoveltyFactorKind.CDN_SURFACE,
            weight=cfg.cdn_penalty_weight,
            value=1.0,
            reason="observation appears to be a routine CDN edge/static surface",
        )

    if "marketing" in surface_roles:
        add_negative(
            NoveltyFactorKind.MARKETING_SURFACE,
            weight=cfg.marketing_penalty_weight,
            value=1.0,
            reason="observation appears to be a routine marketing/content surface",
        )

    positive_union = probability_union(positive)
    negative_union = probability_union(negative)

    # Positive signals can lift the event above its type baseline, but only
    # through the remaining headroom. Negative signals then reduce the result
    # multiplicatively, preventing one positive hint from dominating a clearly
    # repetitive/common surface.
    raised = baseline + (1.0 - baseline) * positive_union
    novelty = clamp01(raised * (1.0 - negative_union))

    explanation = novelty_explanation(
        event=event,
        novelty=novelty,
        baseline=baseline,
        factors=factors,
        history=history,
    )

    return NoveltyAssessment(
        subject_key=subject_key,
        novelty=novelty,
        baseline=baseline,
        positive_union=positive_union,
        negative_union=negative_union,
        observation_count=history.observation_count,
        distinct_source_families=history.distinct_source_families,
        factors=tuple(factors),
        explanation=explanation,
    )


def event_with_novelty(
    event: Event,
    assessment: NoveltyAssessment,
    *,
    include_explainability_metadata: bool = True,
) -> Event:
    """Return a copied Event with the computed novelty score.

    The helper deliberately does not alter confidence/scope/tags.
    """

    if assessment.subject_key != novelty_subject_key(event):
        raise ValueError("assessment does not belong to supplied Event")

    metadata = dict(event.metadata)

    if include_explainability_metadata:
        metadata["novelty_assessment"] = {
            "score": assessment.novelty,
            "baseline": assessment.baseline,
            "positive_union": assessment.positive_union,
            "negative_union": assessment.negative_union,
            "observation_count": assessment.observation_count,
            "distinct_source_families": assessment.distinct_source_families,
            "factor_kinds": [
                factor.kind.value
                for factor in assessment.factors
                if factor.direction is not NoveltyFactorDirection.NEUTRAL
            ],
            "severity_inference": False,
            "scope_inference": False,
        }

    return event.model_copy(
        deep=True,
        update={
            "novelty": assessment.novelty,
            "metadata": metadata,
        },
    )


def history_with_surface_changes(
    history: NoveltyHistory,
    changes: Sequence[Any],
) -> NoveltyHistory:
    """Return history enriched with snapshot change objects.

    This intentionally uses duck typing (`change_type`, `fingerprint`) so the
    intelligence module does not import `recon.storage.snapshots` and therefore
    stays usable without SQLAlchemy.
    """

    change_types = set(history.change_types)
    fingerprints = set(history.change_fingerprints)

    for change in changes:
        raw_type = getattr(change, "change_type", None)
        if raw_type is None:
            continue

        value = getattr(raw_type, "value", raw_type)
        normalized = str(value).strip().upper()
        if normalized:
            change_types.add(normalized)

        raw_fingerprint = getattr(change, "fingerprint", None)
        if isinstance(raw_fingerprint, str) and raw_fingerprint.strip():
            fingerprints.add(raw_fingerprint.strip())

    payload = history.model_dump(mode="python")
    payload.update(
        {
            "change_types": tuple(sorted(change_types)),
            "change_fingerprints": tuple(sorted(fingerprints)),
        }
    )
    return NoveltyHistory.model_validate(payload)


def novelty_subject_key(event: Event) -> str:
    """Return conservative canonical subject identity for novelty history."""

    value = event.value.strip()

    if event.type in {
        EventType.DNS_NAME,
        EventType.CERT_SAN,
    }:
        normalized = value.lower().rstrip(".")
        if normalized.startswith("*."):
            normalized = normalized[2:]
        return f"{event.type.value}:{normalized}"

    if event.type in {
        EventType.URL,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
        EventType.HTTP_SERVICE,
    }:
        normalized_url = canonical_http_url(value)
        return f"{event.type.value}:{normalized_url or value}"

    if event.type is EventType.PARAMETER_NAME:
        # Parameter names may be case-sensitive.
        return f"{event.type.value}:{value}"

    return f"{event.type.value}:{value}"


def canonical_http_url(value: str) -> str | None:
    try:
        parts = urlsplit(value)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or parts.hostname is None:
        return None

    hostname = parts.hostname.lower().rstrip(".")
    port = parts.port

    default_port = (
        scheme == "http" and port == 80
    ) or (
        scheme == "https" and port == 443
    )

    host = hostname
    if port is not None and not default_port:
        host = f"{hostname}:{port}"

    path = parts.path or "/"

    # Fragment never changes the HTTP target sent to the server.
    return urlunsplit((scheme, host, path, parts.query, ""))


_CHANGE_FACTOR_MAP: dict[str, NoveltyFactorKind] = {
    "NEW_HOST": NoveltyFactorKind.NEW_HOST,
    "NEW_URL": NoveltyFactorKind.NEW_URL,
    "NEW_ENDPOINT": NoveltyFactorKind.NEW_ENDPOINT,
    "NEW_CERT_SAN": NoveltyFactorKind.NEW_CERT_SAN,
    "NEW_JAVASCRIPT": NoveltyFactorKind.NEW_JAVASCRIPT,
    "NEW_ASSET": NoveltyFactorKind.NEW_ASSET,
    "RESURRECTED_HOST": NoveltyFactorKind.RESURRECTED_HOST,
    "REAPPEARED_ASSET": NoveltyFactorKind.REAPPEARED_ASSET,
    "DISAPPEARED_HOST": NoveltyFactorKind.DISAPPEARED_HOST,
    "DISAPPEARED_ASSET": NoveltyFactorKind.DISAPPEARED_ASSET,
    "IP_CHANGED": NoveltyFactorKind.IP_CHANGED,
    "STATUS_CHANGED": NoveltyFactorKind.STATUS_CHANGED,
    "TITLE_CHANGED": NoveltyFactorKind.TITLE_CHANGED,
    "BODY_HASH_CHANGED": NoveltyFactorKind.BODY_HASH_CHANGED,
    "CERTIFICATE_CHANGED": NoveltyFactorKind.CERTIFICATE_CHANGED,
    "SCOPE_CHANGED": NoveltyFactorKind.SCOPE_CHANGED,
    "STATE_CHANGED": NoveltyFactorKind.STATE_CHANGED,
}


def novelty_factor_for_change(change_type: str) -> NoveltyFactorKind | None:
    return _CHANGE_FACTOR_MAP.get(change_type.strip().upper())


_ENVIRONMENT_RE = re.compile(
    r"(?:^|[._/\-])"
    r"(prod|production|prd|stage|staging|stg|preprod|pre-prod|"
    r"preproduction|dev|development|test|testing|qa|uat|sandbox|demo|"
    r"beta|alpha|canary|preview)"
    r"(?:$|[._/\-])",
    re.IGNORECASE,
)

_API_VERSION_RE = re.compile(
    r"(?:^|[/._\-])(v[0-9]{1,4})(?:$|[/._\-])",
    re.IGNORECASE,
)


def environment_signals(event: Event) -> tuple[str, ...]:
    """Return explicit environment tokens from safe event text/metadata."""

    candidates = [event.value]

    for key in (
        "hostname",
        "url",
        "path",
        "seed_domain",
        "host_header",
        "subject",
    ):
        value = event.metadata.get(key)
        if isinstance(value, str) and len(value) <= 4096:
            candidates.append(value)

    result: set[str] = set()

    for candidate in candidates:
        for match in _ENVIRONMENT_RE.finditer(candidate.lower()):
            result.add(match.group(1).lower())

    return tuple(sorted(result))


def api_version_signals(event: Event) -> tuple[str, ...]:
    if event.type not in {
        EventType.API_ENDPOINT,
        EventType.URL,
        EventType.URL_PATH,
        EventType.JAVASCRIPT,
    }:
        return ()

    candidates = [event.value]

    path = event.metadata.get("path")
    if isinstance(path, str) and len(path) <= 4096:
        candidates.append(path)

    result: set[str] = set()

    for candidate in candidates:
        for match in _API_VERSION_RE.finditer(candidate.lower()):
            result.add(match.group(1).lower())

    return tuple(sorted(result))


def low_novelty_surface_roles(event: Event) -> frozenset[str]:
    """Conservative explicit/lexical hints for routine public surfaces."""

    tags = {tag.strip().lower() for tag in event.tags if tag.strip()}
    source = event.source.strip().lower()
    value = event.value.strip().lower()

    text = " ".join(
        [
            source,
            value,
            " ".join(sorted(tags)),
            str(event.metadata.get("role", "")).lower(),
            str(event.metadata.get("surface_role", "")).lower(),
        ]
    )

    roles: set[str] = set()

    # Exact/segment matching avoids e.g. "static-analysis" automatically
    # turning a mobile static-analysis result into a static web surface.
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", text)
        if token
    }

    if (
        "static" in tokens
        or "assets" in tokens
        or "images" in tokens
        or "img" in tokens
        or "media" in tokens
    ) and event.type in {
        EventType.DNS_NAME,
        EventType.URL,
        EventType.URL_PATH,
        EventType.HTTP_SERVICE,
        EventType.HTTP_RESPONSE,
        EventType.JAVASCRIPT,
    }:
        roles.add("static")

    if "cdn" in tokens or "edge" in tokens:
        roles.add("cdn")

    if (
        "marketing" in tokens
        or "blog" in tokens
        or "landing" in tokens
        or "press" in tokens
        or "news" in tokens
    ):
        roles.add("marketing")

    return frozenset(roles)


def event_is_historical_only(event: Event, history: NoveltyHistory) -> bool:
    tags = {tag.strip().lower() for tag in event.tags if tag.strip()}
    source = event.source.strip().lower()

    event_historical = bool(
        {"historical", "archive", "archived"} & tags
        or source.startswith("archives")
        or source.startswith("archive")
        or "wayback" in source
        or "commoncrawl" in source
    )

    if not event_historical:
        return False

    return history.live_observation_count <= 0


def repetition_penalty_value(observation_count: int) -> float:
    if observation_count <= 3:
        return 0.0

    # Smoothly approaches 1 while keeping moderate repetition distinguishable.
    return clamp01(math.log1p(observation_count - 3) / math.log(128.0))


def peer_commonness(peer_count: int, *, pivot: int) -> float:
    if peer_count < pivot:
        return 0.0

    return clamp01(
        math.log1p(peer_count - pivot + 1) / math.log(128.0)
    )


def probability_union(values: Sequence[float]) -> float:
    """Noisy-OR union keeps multiple factors bounded in [0,1]."""

    remaining = 1.0

    for value in values:
        remaining *= 1.0 - clamp01(value)

    return clamp01(1.0 - remaining)


def novelty_explanation(
    *,
    event: Event,
    novelty: float,
    baseline: float,
    factors: Sequence[NoveltyFactor],
    history: NoveltyHistory,
) -> str:
    positives = [
        factor
        for factor in factors
        if factor.direction is NoveltyFactorDirection.POSITIVE
        and factor.contribution > 0.0
    ]
    negatives = [
        factor
        for factor in factors
        if factor.direction is NoveltyFactorDirection.NEGATIVE
        and factor.contribution < 0.0
    ]

    positives.sort(key=lambda factor: factor.contribution, reverse=True)
    negatives.sort(key=lambda factor: abs(factor.contribution), reverse=True)

    positive_names = ", ".join(
        factor.kind.value
        for factor in positives[:4]
    ) or "none"

    negative_names = ", ".join(
        factor.kind.value
        for factor in negatives[:4]
    ) or "none"

    return (
        f"novelty={novelty:.3f}; baseline={baseline:.3f}; "
        f"observations={history.observation_count}; "
        f"positive={positive_names}; negative={negative_names}; "
        f"event_type={event.type.value}. Novelty measures difference from "
        "known surface only; it is not severity or authorization."
    )


def clamp01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))
