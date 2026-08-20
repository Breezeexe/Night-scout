"""Central target-vocabulary extraction and normalization for Night Scout.

`vocabulary.py` is the extraction layer between raw discovery Events and the
corpus layer in `intelligence/wordlists.py`.

It performs no network I/O and does not execute artifacts.

Responsibilities
----------------
- project useful target-specific words from normalized Night Scout Events;
- preserve provenance, context and source family;
- distinguish parameter names from case-insensitive general vocabulary;
- assign explainable semantic categories such as API/environment/region/service;
- suppress obvious hashes, minified identifiers, secrets and generic noise;
- merge repeated observations without losing source diversity;
- optionally emit normalized `VOCAB_TOKEN` Events for persistent Target Genome
  storage and consumption by `wordlists.py`.

Typical flow:

    crawler / javascript / mobile / tls / http / archives
                         |
                         v
                    Event stream
                         |
                         v
                   vocabulary.py
                         |
              VocabularyObservation
                         |
              +----------+----------+
              |                     |
              v                     v
         VOCAB_TOKEN            aggregate
              |                     |
              v                     v
         wordlists.py          explainability
              |
              v
     permutations / parameters / vhost

Security boundary
-----------------
Potential secrets are deliberately excluded from vocabulary. A secret value is
not a useful wordlist token and must not be copied into Target Genome, JSONL or
scheduler metadata.

Events with secret/review indicators are therefore skipped before tokenization.
High-entropy/hash-like values are also filtered.

This module does NOT:
- validate credentials;
- contact discovered hosts;
- infer scope from vocabulary;
- infer ownership from hostnames/certificates;
- generate active hypotheses itself.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.workers.passive_domains import normalize_dns_name


class VocabularyCategory(StrEnum):
    """Semantic/use category for target-specific vocabulary."""

    GENERAL = "general"
    DNS = "dns"
    PARAMETER = "parameter"
    PATH = "path"
    API = "api"
    PROJECT = "project"
    TECHNOLOGY = "technology"
    ENVIRONMENT = "environment"
    REGION = "region"
    SERVICE = "service"
    ARTIFACT = "artifact"


class VocabularyContext(StrEnum):
    """Where a token was observed."""

    EXPLICIT_VOCAB = "explicit-vocab"

    HOSTNAME = "hostname"
    CERTIFICATE_SAN = "certificate-san"
    CERTIFICATE_SUBJECT = "certificate-subject"

    URL_HOST = "url-host"
    URL_PATH = "url-path"
    API_PATH = "api-path"
    QUERY_PARAMETER = "query-parameter"

    PARAMETER = "parameter"
    PROJECT_NAME = "project-name"
    TECHNOLOGY = "technology"

    HTTP_TITLE = "http-title"
    HTTP_SERVER = "http-server"

    JAVASCRIPT = "javascript"
    MOBILE = "mobile"
    ARTIFACT = "artifact"

    NAMING_PATTERN = "naming-pattern"


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
        "preview",
    }
)

_REGION_TOKENS = frozenset(
    {
        "msk",
        "spb",
        "moscow",
        "piter",
        "ru",
        "eu",
        "emea",
        "apac",
        "us",
        "uk",
        "de",
        "fr",
        "nyc",
        "lon",
        "lhr",
        "fra",
        "ams",
    }
)

_SERVICE_TOKENS = frozenset(
    {
        "api",
        "rest",
        "graphql",
        "grpc",
        "gateway",
        "gw",
        "admin",
        "internal",
        "public",
        "private",
        "worker",
        "service",
        "svc",
        "backend",
        "frontend",
        "web",
        "app",
        "auth",
        "identity",
        "billing",
        "orders",
        "order",
        "delivery",
        "dispatch",
        "warehouse",
        "payments",
        "payment",
        "catalog",
        "search",
    }
)

_GENERIC_STOPWORDS = frozenset(
    {
        "www",
        "com",
        "net",
        "org",
        "http",
        "https",
        "html",
        "htm",
        "js",
        "css",
        "json",
        "xml",
        "true",
        "false",
        "null",
        "undefined",
        "object",
        "string",
        "number",
        "boolean",
        "function",
        "return",
        "const",
        "let",
        "var",
        "this",
        "window",
        "document",
        "default",
        "index",
        "main",
        "static",
        "assets",
        "asset",
        "bundle",
        "chunk",
        "content",
        "application",
        "javascript",
        "response",
        "request",
        "result",
        "value",
        "values",
        "item",
        "items",
        "data",
    }
)

_SECRET_TAG_MARKERS = frozenset(
    {
        "possible-secret",
        "secret",
        "credential",
        "credentials",
        "private-key",
        "access-token",
        "api-key",
    }
)

_SECRET_METADATA_KEYS = frozenset(
    {
        "possible_secret",
        "possible-secret",
        "credential_candidate",
        "secret_candidate",
        "sensitive",
        "contains_secret",
    }
)

_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_API_VERSION_RE = re.compile(r"^v[0-9]{1,4}$", re.IGNORECASE)
_SAFE_GENERAL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_SAFE_PARAMETER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,127}$")
_REGION_CODE_RE = re.compile(r"^[a-z]{2,8}[0-9]{0,2}$")


class VocabularyObservation(BaseModel):
    """One target-specific vocabulary observation.

    `token` is the display/use value. General categories are normalized to
    lowercase. PARAMETER preserves original case because parameter names may be
    case-sensitive.

    `canonical_key` is used for deterministic merge/dedupe.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    canonical_key: str

    categories: frozenset[VocabularyCategory]

    source: str
    source_family: str

    source_event_ids: tuple[str, ...] = ()
    contexts: frozenset[str] = Field(default_factory=frozenset)

    occurrences: int = Field(default=1, ge=1)
    source_diversity: int = Field(default=1, ge=1)

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    relevance: float = Field(default=0.5, ge=0.0, le=1.0)

    case_sensitive: bool = False
    target_specific: bool = True

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("token", "canonical_key", "source", "source_family")
    @classmethod
    def required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized

    @field_validator("categories")
    @classmethod
    def categories_required(
        cls,
        values: frozenset[VocabularyCategory],
    ) -> frozenset[VocabularyCategory]:
        if not values:
            raise ValueError(
                "vocabulary observation requires at least one category"
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


class VocabularyAggregate(BaseModel):
    """Merged Target Genome state for one logical token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    canonical_key: str

    categories: frozenset[VocabularyCategory]

    sources: frozenset[str]
    source_families: frozenset[str]

    source_event_ids: tuple[str, ...]
    contexts: frozenset[str]

    occurrences: int = Field(ge=1)
    source_diversity: int = Field(ge=1)

    confidence: float = Field(ge=0.0, le=1.0)
    relevance: float = Field(ge=0.0, le=1.0)

    case_sensitive: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def score(self) -> float:
        """Explainable target-vocabulary ranking score."""

        return (
            self.relevance * 4.0
            + math.log1p(self.occurrences) * 1.2
            + self.source_diversity * 0.8
            + self.confidence * 0.5
        )


class VocabularyProjectorConfig(BaseModel):
    """Bounded extraction and semantic classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_token_length: int = Field(default=2, ge=1, le=32)
    max_token_length: int = Field(default=64, ge=4, le=256)

    max_tokens_per_event: int = Field(default=512, ge=1, le=100_000)
    max_query_parameters: int = Field(default=256, ge=1, le=4096)
    max_certificate_sans: int = Field(default=512, ge=1, le=100_000)
    max_pattern_slot_values: int = Field(default=1024, ge=1, le=100_000)

    include_http_title: bool = True
    include_http_server: bool = True
    include_certificate_subject: bool = True

    include_url_hostname_labels: bool = True

    environment_tokens: frozenset[str] = Field(
        default_factory=lambda: _ENVIRONMENT_TOKENS
    )

    service_tokens: frozenset[str] = Field(
        default_factory=lambda: _SERVICE_TOKENS
    )

    region_tokens: frozenset[str] = Field(
        default_factory=lambda: _REGION_TOKENS
    )

    generic_stopwords: frozenset[str] = Field(
        default_factory=lambda: _GENERIC_STOPWORDS
    )

    @field_validator(
        "environment_tokens",
        "service_tokens",
        "region_tokens",
        "generic_stopwords",
    )
    @classmethod
    def normalize_lowercase_sets(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )

    @model_validator(mode="after")
    def token_bounds(
        self,
    ) -> "VocabularyProjectorConfig":
        if self.min_token_length > self.max_token_length:
            raise ValueError(
                "min_token_length cannot exceed max_token_length"
            )

        return self


class VocabularyProjector:
    """Project normalized Events into target vocabulary."""

    def __init__(
        self,
        config: VocabularyProjectorConfig | None = None,
    ) -> None:
        self.config = (
            config
            or VocabularyProjectorConfig()
        )

    def project_event(
        self,
        event: Event,
    ) -> tuple[VocabularyObservation, ...]:
        """Extract bounded vocabulary from one Event."""

        if event_contains_sensitive_material(
            event
        ):
            return ()

        result: list[VocabularyObservation] = []

        def emit(
            token: str,
            *,
            categories: Iterable[VocabularyCategory],
            context: VocabularyContext | str,
            relevance: float,
            case_sensitive: bool = False,
            occurrence_count: int | None = None,
            metadata: dict[str, Any] | None = None,
            extra_contexts: Iterable[str] = (),
        ) -> None:
            if len(result) >= self.config.max_tokens_per_event:
                return

            observation = make_vocabulary_observation(
                token,
                categories=categories,
                event=event,
                context=context,
                relevance=relevance,
                case_sensitive=case_sensitive,
                occurrence_count=occurrence_count,
                metadata=metadata,
                extra_contexts=extra_contexts,
                config=self.config,
            )

            if observation is not None:
                result.append(
                    observation
                )

        if event.type is EventType.VOCAB_TOKEN:
            raw_categories = vocabulary_categories_from_event(
                event
            )

            raw_contexts = event.metadata.get(
                "contexts"
            )

            extra_contexts = (
                tuple(
                    str(value)
                    for value in raw_contexts
                    if str(value).strip()
                )
                if isinstance(
                    raw_contexts,
                    (list, tuple, set),
                )
                else ()
            )

            emit(
                event.value,
                categories=raw_categories,
                context=VocabularyContext.EXPLICIT_VOCAB,
                extra_contexts=extra_contexts,
                relevance=(
                    float(
                        event.metadata.get(
                            "target_relevance",
                            0.95,
                        )
                    )
                    if _safe_float(
                        event.metadata.get(
                            "target_relevance"
                        )
                    )
                    is not None
                    else 0.95
                ),
                occurrence_count=event_occurrence_count(
                    event
                ),
                metadata={
                    "passthrough_vocab_token": True,
                },
            )

            return dedupe_observations(
                result
            )

        if event.type is EventType.PARAMETER_NAME:
            emit(
                event.value,
                categories=(
                    VocabularyCategory.PARAMETER,
                    VocabularyCategory.GENERAL,
                ),
                context=VocabularyContext.PARAMETER,
                relevance=1.0,
                case_sensitive=True,
                metadata={
                    "raw_value_stored": False,
                },
            )

            # Camel/snake pieces may also help DNS/path exploration, but do not
            # replace the exact case-sensitive parameter token.
            for token in tokenize_text(
                event.value,
                config=self.config,
            ):
                if token == event.value:
                    continue

                emit(
                    token,
                    categories=(
                        VocabularyCategory.GENERAL,
                    ),
                    context=VocabularyContext.PARAMETER,
                    relevance=0.74,
                )

            return dedupe_observations(
                result
            )

        if event.type in {
            EventType.DNS_NAME,
            EventType.CERT_SAN,
        }:
            hostname = event.value.strip()

            if hostname.startswith("*."):
                hostname = hostname[2:]

            for label in hostname_vocabulary_labels(
                hostname
            ):
                categories = {
                    VocabularyCategory.DNS,
                    VocabularyCategory.GENERAL,
                }

                categories.update(
                    semantic_categories(
                        label,
                        config=self.config,
                    )
                )

                emit(
                    label,
                    categories=categories,
                    context=(
                        VocabularyContext.CERTIFICATE_SAN
                        if event.type is EventType.CERT_SAN
                        else VocabularyContext.HOSTNAME
                    ),
                    relevance=(
                        0.90
                        if event.type is EventType.CERT_SAN
                        else 1.0
                    ),
                    metadata={
                        "hostname": hostname,
                    },
                )

            return dedupe_observations(
                result
            )

        if event.type in {
            EventType.URL,
            EventType.API_ENDPOINT,
            EventType.JAVASCRIPT,
            EventType.ARTIFACT,
        }:
            for item in vocabulary_from_url(
                event.value,
                config=self.config,
                api_context=(
                    event.type is EventType.API_ENDPOINT
                ),
            ):
                emit(
                    item.token,
                    categories=item.categories,
                    context=item.context,
                    relevance=item.relevance,
                    case_sensitive=item.case_sensitive,
                    metadata=item.metadata,
                )

            # Artifact file names (e.g. source maps) may be useful even if the
            # value is not a valid HTTP URL.
            if event.type is EventType.ARTIFACT:
                artifact_kind = str(
                    event.metadata.get(
                        "artifact_kind",
                        "",
                    )
                ).strip().lower()

                for token in tokenize_text(
                    artifact_filename(
                        event.value
                    ),
                    config=self.config,
                ):
                    emit(
                        token,
                        categories=(
                            VocabularyCategory.ARTIFACT,
                            VocabularyCategory.GENERAL,
                        ),
                        context=VocabularyContext.ARTIFACT,
                        relevance=0.58,
                        metadata={
                            "artifact_kind": artifact_kind or None,
                        },
                    )

            return dedupe_observations(
                result
            )

        if event.type is EventType.URL_PATH:
            path = event.metadata.get(
                "path"
            )

            if not isinstance(
                path,
                str,
            ):
                path = strip_host_from_url_path_event(
                    event.value
                )

            for token, is_api in path_tokens(
                path,
                config=self.config,
            ):
                categories = {
                    VocabularyCategory.PATH,
                    VocabularyCategory.GENERAL,
                }

                if is_api:
                    categories.add(
                        VocabularyCategory.API
                    )

                categories.update(
                    semantic_categories(
                        token,
                        config=self.config,
                    )
                )

                emit(
                    token,
                    categories=categories,
                    context=(
                        VocabularyContext.API_PATH
                        if is_api
                        else VocabularyContext.URL_PATH
                    ),
                    relevance=(
                        0.84
                        if is_api
                        else 0.70
                    ),
                )

            return dedupe_observations(
                result
            )

        if event.type is EventType.PROJECT_NAME:
            for token in tokenize_text(
                event.value,
                config=self.config,
            ):
                categories = {
                    VocabularyCategory.PROJECT,
                    VocabularyCategory.GENERAL,
                }

                categories.update(
                    semantic_categories(
                        token,
                        config=self.config,
                    )
                )

                emit(
                    token,
                    categories=categories,
                    context=VocabularyContext.PROJECT_NAME,
                    relevance=0.94,
                )

            return dedupe_observations(
                result
            )

        if event.type is EventType.TECHNOLOGY:
            for token in tokenize_text(
                event.value,
                config=self.config,
            ):
                emit(
                    token,
                    categories=(
                        VocabularyCategory.TECHNOLOGY,
                        VocabularyCategory.GENERAL,
                    ),
                    context=VocabularyContext.TECHNOLOGY,
                    relevance=0.56,
                )

            return dedupe_observations(
                result
            )

        if event.type is EventType.HTTP_RESPONSE:
            if self.config.include_http_title:
                title = event.metadata.get(
                    "title"
                )

                if isinstance(
                    title,
                    str,
                ):
                    for token in tokenize_text(
                        title,
                        config=self.config,
                    ):
                        emit(
                            token,
                            categories=(
                                VocabularyCategory.GENERAL,
                            ),
                            context=VocabularyContext.HTTP_TITLE,
                            relevance=0.48,
                        )

            if self.config.include_http_server:
                server = (
                    event.metadata.get(
                        "webserver"
                    )
                    or event.metadata.get(
                        "server"
                    )
                )

                if isinstance(
                    server,
                    str,
                ):
                    for token in tokenize_text(
                        server,
                        config=self.config,
                    ):
                        emit(
                            token,
                            categories=(
                                VocabularyCategory.TECHNOLOGY,
                                VocabularyCategory.GENERAL,
                            ),
                            context=VocabularyContext.HTTP_SERVER,
                            relevance=0.42,
                        )

            technologies = event.metadata.get(
                "technologies"
            )

            if isinstance(
                technologies,
                str,
            ):
                technologies = (
                    technologies,
                )

            if isinstance(
                technologies,
                (list, tuple, set),
            ):
                for technology in technologies:
                    for token in tokenize_text(
                        str(
                            technology
                        ),
                        config=self.config,
                    ):
                        emit(
                            token,
                            categories=(
                                VocabularyCategory.TECHNOLOGY,
                                VocabularyCategory.GENERAL,
                            ),
                            context=VocabularyContext.TECHNOLOGY,
                            relevance=0.56,
                        )

            return dedupe_observations(
                result
            )

        if event.type is EventType.CERTIFICATE:
            sans = nested_metadata(
                event.metadata,
                "surface_state",
                "certificate_sans",
            )

            if isinstance(
                sans,
                str,
            ):
                sans = (
                    sans,
                )

            if isinstance(
                sans,
                (list, tuple, set),
            ):
                for raw_san in list(
                    sans
                )[
                    : self.config.max_certificate_sans
                ]:
                    hostname = str(
                        raw_san
                    ).strip()

                    if hostname.startswith(
                        "*."
                    ):
                        hostname = hostname[2:]

                    for label in hostname_vocabulary_labels(
                        hostname
                    ):
                        categories = {
                            VocabularyCategory.DNS,
                            VocabularyCategory.GENERAL,
                        }

                        categories.update(
                            semantic_categories(
                                label,
                                config=self.config,
                            )
                        )

                        emit(
                            label,
                            categories=categories,
                            context=(
                                VocabularyContext.CERTIFICATE_SAN
                            ),
                            relevance=0.86,
                        )

            if self.config.include_certificate_subject:
                for key in (
                    "subject_cn",
                    "subject_org",
                    "issuer_cn",
                    "issuer_org",
                ):
                    raw = event.metadata.get(
                        key
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
                        (list, tuple, set),
                    ):
                        values = tuple(
                            raw
                        )
                    else:
                        values = ()

                    for value in values:
                        for token in tokenize_text(
                            str(
                                value
                            ),
                            config=self.config,
                        ):
                            emit(
                                token,
                                categories=(
                                    VocabularyCategory.GENERAL,
                                ),
                                context=(
                                    VocabularyContext.CERTIFICATE_SUBJECT
                                ),
                                relevance=0.42,
                                metadata={
                                    "certificate_field": key,
                                },
                            )

            return dedupe_observations(
                result
            )

        if event.type is EventType.NAMING_PATTERN:
            slots = event.metadata.get(
                "slots"
            )

            if isinstance(
                slots,
                list,
            ):
                for slot in slots:
                    if not isinstance(
                        slot,
                        dict,
                    ):
                        continue

                    kind = str(
                        slot.get(
                            "kind",
                            "",
                        )
                    ).strip().lower()

                    values = slot.get(
                        "values"
                    )

                    if isinstance(
                        values,
                        str,
                    ):
                        values = (
                            values,
                        )

                    if not isinstance(
                        values,
                        (list, tuple, set),
                    ):
                        continue

                    for raw in list(
                        values
                    )[
                        : self.config.max_pattern_slot_values
                    ]:
                        token = str(
                            raw
                        )

                        categories = {
                            VocabularyCategory.DNS,
                            VocabularyCategory.GENERAL,
                        }

                        categories.update(
                            semantic_categories(
                                token,
                                config=self.config,
                            )
                        )

                        if kind == "environment":
                            categories.add(
                                VocabularyCategory.ENVIRONMENT
                            )

                        elif kind == "region":
                            categories.add(
                                VocabularyCategory.REGION
                            )

                        elif kind == "service":
                            categories.add(
                                VocabularyCategory.SERVICE
                            )

                        emit(
                            token,
                            categories=categories,
                            context=VocabularyContext.NAMING_PATTERN,
                            relevance=0.88,
                            metadata={
                                "pattern_id": event.metadata.get(
                                    "pattern_id"
                                ),
                                "slot_kind": kind or None,
                            },
                        )

            return dedupe_observations(
                result
            )

        return ()

    def project_events(
        self,
        events: Sequence[Event],
        *,
        max_observations: int = 500_000,
    ) -> tuple[VocabularyObservation, ...]:
        """Project a bounded event sequence."""

        if max_observations <= 0:
            return ()

        result: list[
            VocabularyObservation
        ] = []

        for event in events:
            if len(result) >= max_observations:
                break

            remaining = (
                max_observations
                - len(result)
            )

            result.extend(
                self.project_event(
                    event
                )[
                    :remaining
                ]
            )

        return tuple(
            result
        )

    def aggregate(
        self,
        observations: Sequence[VocabularyObservation],
    ) -> tuple[VocabularyAggregate, ...]:
        return aggregate_vocabulary(
            observations
        )

    def token_events(
        self,
        event: Event,
    ) -> tuple[Event, ...]:
        """Project one Event directly into persistent VOCAB_TOKEN Events."""

        observations = self.project_event(
            event
        )

        return tuple(
            vocabulary_token_event(
                observation,
                parent_event=event,
            )
            for observation
            in observations
            if (
                event.type
                is not EventType.VOCAB_TOKEN
                and not observation.case_sensitive
            )
        )


class _UrlVocabularyItem(BaseModel):
    """Internal URL projection record."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token: str
    categories: frozenset[VocabularyCategory]
    context: str
    relevance: float = Field(ge=0.0, le=1.0)
    case_sensitive: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


def make_vocabulary_observation(
    token: str,
    *,
    categories: Iterable[VocabularyCategory],
    event: Event,
    context: VocabularyContext | str,
    relevance: float,
    case_sensitive: bool,
    occurrence_count: int | None,
    metadata: dict[str, Any] | None,
    extra_contexts: Iterable[str] = (),
    config: VocabularyProjectorConfig,
) -> VocabularyObservation | None:
    """Normalize one candidate token and preserve provenance."""

    category_set = frozenset(
        categories
    )

    parameter_mode = (
        VocabularyCategory.PARAMETER
        in category_set
        and case_sensitive
    )

    normalized = normalize_vocabulary_token(
        token,
        case_sensitive=(
            parameter_mode
        ),
        config=config,
    )

    if normalized is None:
        return None

    semantic = semantic_categories(
        normalized,
        config=config,
    )

    category_set = (
        category_set
        | semantic
    )

    canonical_key = vocabulary_canonical_key(
        normalized,
        case_sensitive=(
            parameter_mode
        ),
    )

    contexts = {
        (
            context.value
            if isinstance(
                context,
                VocabularyContext,
            )
            else str(
                context
            ).strip().lower()
        ),
        *(
            tag.strip().lower()
            for tag in event.tags
            if tag.strip()
        ),
        *(
            str(value).strip().lower()
            for value in extra_contexts
            if str(value).strip()
        ),
    }

    source = (
        event.source
        or "unknown"
    )

    return VocabularyObservation(
        token=normalized,
        canonical_key=canonical_key,
        categories=category_set,
        source=source,
        source_family=source_family(
            source
        ),
        source_event_ids=(
            event.event_id,
        ),
        contexts=frozenset(
            value
            for value in contexts
            if value
        ),
        occurrences=(
            occurrence_count
            if occurrence_count is not None
            else 1
        ),
        source_diversity=1,
        confidence=event.confidence,
        relevance=min(
            1.0,
            max(
                0.0,
                relevance,
            ),
        ),
        case_sensitive=(
            parameter_mode
        ),
        target_specific=True,
        metadata={
            "source_event_type": (
                event.type.value
            ),
            **(
                metadata
                or {}
            ),
        },
    )


def normalize_vocabulary_token(
    value: str,
    *,
    case_sensitive: bool,
    config: VocabularyProjectorConfig,
) -> str | None:
    """Validate one token while filtering secret/hash/minified noise."""

    raw = value.strip()

    if not raw:
        return None

    if (
        len(raw)
        < config.min_token_length
        or len(raw)
        > config.max_token_length
    ):
        return None

    if looks_like_secret_material(
        raw
    ):
        return None

    if case_sensitive:
        if (
            _SAFE_PARAMETER_RE.fullmatch(
                raw
            )
            is None
        ):
            return None

        return raw

    normalized = raw.lower()

    if (
        normalized
        in config.generic_stopwords
    ):
        return None

    if normalized.isdigit():
        # Numeric sequences belong to pattern inference rather than standalone
        # vocabulary. API versions (v1/v2) remain allowed.
        return None

    if (
        not any(
            character.isalpha()
            for character
            in normalized
        )
        and _API_VERSION_RE.fullmatch(
            normalized
        )
        is None
    ):
        return None

    if (
        _SAFE_GENERAL_RE.fullmatch(
            normalized
        )
        is None
    ):
        return None

    if (
        len(normalized) >= 20
        and looks_hash_like(
            normalized
        )
    ):
        return None

    if looks_minified_identifier(
        normalized
    ):
        return None

    return normalized


def vocabulary_canonical_key(
    token: str,
    *,
    case_sensitive: bool,
) -> str:
    return (
        token
        if case_sensitive
        else token.lower()
    )


def tokenize_text(
    value: str,
    *,
    config: VocabularyProjectorConfig,
) -> tuple[str, ...]:
    """Split separators/camelCase without executing source content."""

    if (
        not value
        or len(
            value
        )
        > 16_384
    ):
        return ()

    result: list[str] = []

    for coarse in _TOKEN_SPLIT_RE.split(
        value
    ):
        if not coarse:
            continue

        for part in _CAMEL_BOUNDARY_RE.split(
            coarse
        ):
            normalized = normalize_vocabulary_token(
                part,
                case_sensitive=False,
                config=config,
            )

            if (
                normalized is not None
                and normalized not in result
            ):
                result.append(
                    normalized
                )

    return tuple(
        result
    )


def vocabulary_from_url(
    value: str,
    *,
    config: VocabularyProjectorConfig,
    api_context: bool,
) -> tuple[_UrlVocabularyItem, ...]:
    """Project host/path/query names from an HTTP(S) URL.

    Query values are deliberately discarded.
    """

    try:
        parts = urlsplit(
            value.strip()
        )
    except ValueError:
        return ()

    if (
        parts.scheme.lower()
        not in {
            "http",
            "https",
        }
        or parts.hostname
        is None
    ):
        return ()

    result: list[
        _UrlVocabularyItem
    ] = []

    if (
        config.include_url_hostname_labels
    ):
        for label in hostname_vocabulary_labels(
            parts.hostname
        ):
            categories = {
                VocabularyCategory.DNS,
                VocabularyCategory.GENERAL,
            }

            categories.update(
                semantic_categories(
                    label,
                    config=config,
                )
            )

            result.append(
                _UrlVocabularyItem(
                    token=label,
                    categories=frozenset(
                        categories
                    ),
                    context=(
                        VocabularyContext.URL_HOST.value
                    ),
                    relevance=0.76,
                )
            )

    for token, is_api in path_tokens(
        parts.path or "/",
        config=config,
    ):
        categories = {
            VocabularyCategory.PATH,
            VocabularyCategory.GENERAL,
        }

        if (
            api_context
            or is_api
        ):
            categories.add(
                VocabularyCategory.API
            )

        categories.update(
            semantic_categories(
                token,
                config=config,
            )
        )

        result.append(
            _UrlVocabularyItem(
                token=token,
                categories=frozenset(
                    categories
                ),
                context=(
                    VocabularyContext.API_PATH.value
                    if (
                        api_context
                        or is_api
                    )
                    else VocabularyContext.URL_PATH.value
                ),
                relevance=(
                    0.88
                    if (
                        api_context
                        or is_api
                    )
                    else 0.72
                ),
            )
        )

    if parts.query:
        try:
            pairs = parse_qsl(
                parts.query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=(
                    config.max_query_parameters
                ),
            )
        except ValueError:
            pairs = []

        seen_names: set[str] = set()

        for (
            name,
            _value,
        ) in pairs:
            if (
                not name
                or name
                in seen_names
            ):
                continue

            seen_names.add(
                name
            )

            normalized = normalize_vocabulary_token(
                name,
                case_sensitive=True,
                config=config,
            )

            if normalized is None:
                continue

            result.append(
                _UrlVocabularyItem(
                    token=normalized,
                    categories=frozenset(
                        {
                            VocabularyCategory.PARAMETER,
                            VocabularyCategory.GENERAL,
                        }
                    ),
                    context=(
                        VocabularyContext.QUERY_PARAMETER.value
                    ),
                    relevance=0.92,
                    case_sensitive=True,
                    metadata={
                        "query_value_stored": False,
                    },
                )
            )

    return tuple(
        result
    )


def path_tokens(
    path: str,
    *,
    config: VocabularyProjectorConfig,
) -> tuple[tuple[str, bool], ...]:
    """Extract path tokens with an API-context hint."""

    result: list[
        tuple[str, bool]
    ] = []

    seen: set[
        tuple[str, bool]
    ] = set()

    api_seen = False

    for segment in path.split(
        "/"
    ):
        if not segment:
            continue

        segment_tokens = tokenize_text(
            segment,
            config=config,
        )

        segment_is_api = (
            api_seen
            or any(
                token in {
                    "api",
                    "rest",
                    "graphql",
                    "graphiql",
                    "swagger",
                    "openapi",
                }
                or _API_VERSION_RE.fullmatch(
                    token
                )
                is not None
                for token in segment_tokens
            )
        )

        if segment_is_api:
            api_seen = True

        for token in segment_tokens:
            item = (
                token,
                segment_is_api,
            )

            if item in seen:
                continue

            seen.add(
                item
            )

            result.append(
                item
            )

    return tuple(
        result
    )


def hostname_vocabulary_labels(
    hostname: str,
) -> tuple[str, ...]:
    """Extract useful labels without making ownership/public-suffix claims.

    We keep all non-terminal labels and additionally split hyphenated labels.
    The last label (usually a TLD) is never emitted.

    Example:
        warehouse-api-preprod.example.com
    ->
        warehouse-api-preprod
        warehouse
        api
        preprod
        example

    `example` is retained because without a public-suffix database we should
    not guess whether it is organizational noise or a meaningful internal
    naming component. Corpus ranking/source diversity can down-rank it later.
    """

    raw = hostname.strip().lower()

    if raw.startswith(
        "*."
    ):
        raw = raw[2:]

    try:
        normalized = normalize_dns_name(
            raw
        )
    except ValueError:
        return ()

    labels = normalized.split(
        "."
    )

    if len(labels) <= 1:
        return ()

    result: list[str] = []

    for label in labels[
        :-1
    ]:
        if label not in result:
            result.append(
                label
            )

        for piece in label.split(
            "-"
        ):
            if (
                piece
                and piece not in result
            ):
                result.append(
                    piece
                )

    return tuple(
        result
    )


def semantic_categories(
    token: str,
    *,
    config: VocabularyProjectorConfig,
) -> frozenset[VocabularyCategory]:
    """Assign conservative semantic hints; generation remains separate."""

    normalized = token.strip().lower()

    result: set[
        VocabularyCategory
    ] = set()

    if normalized in config.environment_tokens:
        result.add(
            VocabularyCategory.ENVIRONMENT
        )

    if normalized in config.service_tokens:
        result.add(
            VocabularyCategory.SERVICE
        )

    if normalized in config.region_tokens:
        # Conservative allowlist-based semantic hint. Unknown short words are
        # not guessed to be regions merely because of their shape.
        result.add(
            VocabularyCategory.REGION
        )

    if (
        normalized
        in {
            "api",
            "rest",
            "graphql",
            "graphiql",
            "swagger",
            "openapi",
        }
        or _API_VERSION_RE.fullmatch(
            normalized
        )
        is not None
    ):
        result.add(
            VocabularyCategory.API
        )

    return frozenset(
        result
    )


def aggregate_vocabulary(
    observations: Sequence[
        VocabularyObservation
    ],
) -> tuple[VocabularyAggregate, ...]:
    """Merge repeated observations while preserving independent sources."""

    state: dict[
        tuple[
            str,
            bool,
        ],
        dict[str, Any],
    ] = {}

    for observation in observations:
        key = (
            observation.canonical_key,
            observation.case_sensitive,
        )

        item = state.get(
            key
        )

        if item is None:
            item = {
                "token": observation.token,
                "canonical_key": observation.canonical_key,
                "categories": set(),
                "sources": set(),
                "source_families": set(),
                "source_event_ids": set(),
                "contexts": set(),
                "occurrences": 0,
                "confidence": 0.0,
                "relevance": 0.0,
                "case_sensitive": observation.case_sensitive,
                "samples": [],
            }

            state[
                key
            ] = item

        item[
            "categories"
        ].update(
            observation.categories
        )

        item[
            "sources"
        ].add(
            observation.source
        )

        item[
            "source_families"
        ].add(
            observation.source_family
        )

        item[
            "source_event_ids"
        ].update(
            observation.source_event_ids
        )

        item[
            "contexts"
        ].update(
            observation.contexts
        )

        item[
            "occurrences"
        ] += (
            observation.occurrences
        )

        item[
            "confidence"
        ] = max(
            item[
                "confidence"
            ],
            observation.confidence,
        )

        item[
            "relevance"
        ] = max(
            item[
                "relevance"
            ],
            observation.relevance,
        )

        if (
            len(
                item[
                    "samples"
                ]
            )
            < 32
        ):
            item[
                "samples"
            ].append(
                {
                    "source": (
                        observation.source
                    ),
                    "event_ids": list(
                        observation.source_event_ids
                    ),
                    "contexts": sorted(
                        observation.contexts
                    ),
                    "metadata": dict(
                        observation.metadata
                    ),
                }
            )

    aggregates: list[
        VocabularyAggregate
    ] = []

    for item in state.values():
        source_diversity = len(
            item[
                "source_families"
            ]
        )

        # Repeated, independently sourced words receive a bounded relevance
        # bump without becoming certain facts.
        relevance = min(
            1.0,
            item[
                "relevance"
            ]
            + math.log1p(
                item[
                    "occurrences"
                ]
            )
            * 0.04
            + source_diversity
            * 0.04,
        )

        aggregates.append(
            VocabularyAggregate(
                token=item[
                    "token"
                ],
                canonical_key=item[
                    "canonical_key"
                ],
                categories=frozenset(
                    item[
                        "categories"
                    ]
                ),
                sources=frozenset(
                    item[
                        "sources"
                    ]
                ),
                source_families=frozenset(
                    item[
                        "source_families"
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
                occurrences=item[
                    "occurrences"
                ],
                source_diversity=(
                    source_diversity
                ),
                confidence=item[
                    "confidence"
                ],
                relevance=relevance,
                case_sensitive=item[
                    "case_sensitive"
                ],
                metadata={
                    "evidence_samples": (
                        item[
                            "samples"
                        ]
                    ),
                },
            )
        )

    return tuple(
        sorted(
            aggregates,
            key=lambda aggregate: (
                -aggregate.score,
                aggregate.canonical_key,
            ),
        )
    )


def dedupe_observations(
    observations: Sequence[
        VocabularyObservation
    ],
) -> tuple[VocabularyObservation, ...]:
    """Merge duplicate projections created from one source Event."""

    grouped: dict[
        tuple[
            str,
            bool,
        ],
        list[VocabularyObservation],
    ] = defaultdict(
        list
    )

    for observation in observations:
        grouped[
            (
                observation.canonical_key,
                observation.case_sensitive,
            )
        ].append(
            observation
        )

    result: list[
        VocabularyObservation
    ] = []

    for group in grouped.values():
        first = group[0]

        categories: set[
            VocabularyCategory
        ] = set()

        contexts: set[str] = set()

        metadata_samples: list[
            dict[str, Any]
        ] = []

        for observation in group:
            categories.update(
                observation.categories
            )

            contexts.update(
                observation.contexts
            )

            if (
                observation.metadata
                and len(
                    metadata_samples
                )
                < 8
            ):
                metadata_samples.append(
                    dict(
                        observation.metadata
                    )
                )

        result.append(
            VocabularyObservation(
                token=first.token,
                canonical_key=(
                    first.canonical_key
                ),
                categories=frozenset(
                    categories
                ),
                source=first.source,
                source_family=(
                    first.source_family
                ),
                source_event_ids=(
                    first.source_event_ids
                ),
                contexts=frozenset(
                    contexts
                ),
                occurrences=max(
                    observation.occurrences
                    for observation
                    in group
                ),
                source_diversity=1,
                confidence=max(
                    observation.confidence
                    for observation
                    in group
                ),
                relevance=max(
                    observation.relevance
                    for observation
                    in group
                ),
                case_sensitive=(
                    first.case_sensitive
                ),
                target_specific=True,
                metadata={
                    "projection_samples": (
                        metadata_samples
                    ),
                },
            )
        )

    return tuple(
        sorted(
            result,
            key=lambda observation: (
                -observation.relevance,
                observation.canonical_key,
            ),
        )
    )


def vocabulary_token_event(
    observation: VocabularyObservation,
    *,
    parent_event: Event,
) -> Event:
    """Persist a normalized vocabulary observation as a VOCAB_TOKEN Event."""

    return Event(
        type=EventType.VOCAB_TOKEN,
        value=observation.token,
        source=(
            "vocabulary:projector"
        ),
        parent_event_id=(
            parent_event.event_id
        ),
        scope_state=(
            ScopeState.UNKNOWN
        ),
        confidence=(
            observation.confidence
        ),
        novelty=min(
            1.0,
            max(
                parent_event.novelty,
                0.70,
            ),
        ),
        depth=(
            parent_event.depth
            + 1
        ),
        tags={
            "vocabulary",
            "target-specific",
            "target-genome",
            "derived",
        },
        metadata={
            "target_specific": True,
            "canonical_key": (
                observation.canonical_key
            ),
            "vocabulary_categories": [
                category.value
                for category
                in sorted(
                    observation.categories,
                    key=lambda category: (
                        category.value
                    ),
                )
            ],
            "contexts": sorted(
                observation.contexts
            ),
            "occurrences": (
                observation.occurrences
            ),
            "source_family": (
                observation.source_family
            ),
            "source_event_ids": list(
                observation.source_event_ids
            ),
            "target_relevance": (
                observation.relevance
            ),
            "case_sensitive": (
                observation.case_sensitive
            ),
            "raw_sensitive_value_stored": False,
            "scope_inference": False,
            "ownership_inference": False,
            **observation.metadata,
        },
    )


def vocabulary_categories_from_event(
    event: Event,
) -> tuple[VocabularyCategory, ...]:
    """Read explicit categories from a pre-existing VOCAB_TOKEN Event."""

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
        (list, tuple, set),
    ):
        values = tuple(
            raw
        )
    else:
        values = ()

    result: list[
        VocabularyCategory
    ] = []

    for value in values:
        try:
            category = VocabularyCategory(
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
        or (
            VocabularyCategory.GENERAL,
        )
    )


def event_contains_sensitive_material(
    event: Event,
) -> bool:
    """Fail closed for Events associated with possible credentials/secrets."""

    tags = {
        tag.strip().lower()
        for tag in event.tags
        if tag.strip()
    }

    if (
        tags
        & _SECRET_TAG_MARKERS
    ):
        return True

    if any(
        marker in tag
        for tag in tags
        for marker in (
            "secret",
            "credential",
            "private-key",
            "access-token",
        )
    ):
        return True

    for key in _SECRET_METADATA_KEYS:
        raw = event.metadata.get(
            key
        )

        if raw is True:
            return True

    artifact_kind = str(
        event.metadata.get(
            "artifact_kind",
            "",
        )
    ).strip().lower()

    if any(
        marker in artifact_kind
        for marker in (
            "secret",
            "credential",
            "private-key",
            "token",
        )
    ):
        return True

    return False


def looks_like_secret_material(
    value: str,
) -> bool:
    """Suppress common secret-like/high-entropy token shapes.

    This is a safety filter, not credential detection. Credential classification
    belongs in mobile/secret scanners + review gate.
    """

    raw = value.strip()

    if not raw:
        return False

    lower = raw.lower()

    if lower.startswith(
        (
            "-----begin",
            "bearer ",
            "basic ",
        )
    ):
        return True

    if (
        raw.count(
            "."
        )
        == 2
        and all(
            len(
                piece
            )
            >= 8
            for piece in raw.split(
                "."
            )
        )
    ):
        # JWT-like compact token.
        return True

    if (
        len(raw) >= 24
        and entropy_bits_per_character(
            raw
        )
        >= 3.8
        and (
            any(
                character.isdigit()
                for character
                in raw
            )
            and any(
                character.isalpha()
                for character
                in raw
            )
        )
    ):
        return True

    return False


def looks_hash_like(
    value: str,
) -> bool:
    lower = value.lower()

    if not lower:
        return False

    if re.fullmatch(
        r"[0-9a-f]{20,}",
        lower,
    ):
        return True

    alnum = [
        character
        for character in lower
        if character.isalnum()
    ]

    if not alnum:
        return False

    hex_fraction = (
        sum(
            character
            in "0123456789abcdef"
            for character
            in alnum
        )
        / len(
            alnum
        )
    )

    return (
        len(
            alnum
        )
        >= 24
        and hex_fraction
        >= 0.90
    )


def looks_minified_identifier(
    value: str,
) -> bool:
    """Filter long consonant-heavy identifiers typical of minified bundles."""

    if len(value) < 32:
        return False

    if (
        "-" in value
        or "_" in value
        or "." in value
    ):
        return False

    vowels = sum(
        character
        in "aeiouy"
        for character
        in value.lower()
    )

    alpha = sum(
        character.isalpha()
        for character
        in value
    )

    if alpha <= 0:
        return False

    vowel_fraction = (
        vowels
        / alpha
    )

    return (
        vowel_fraction
        < 0.12
    )


def entropy_bits_per_character(
    value: str,
) -> float:
    if not value:
        return 0.0

    counts = Counter(
        value
    )

    length = len(
        value
    )

    entropy = 0.0

    for count in counts.values():
        probability = (
            count
            / length
        )

        entropy -= (
            probability
            * math.log2(
                probability
            )
        )

    return entropy


def source_family(
    source: str,
) -> str:
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


def event_occurrence_count(
    event: Event,
) -> int:
    for key in (
        "occurrences",
        "frequency",
        "target_frequency",
    ):
        raw = event.metadata.get(
            key
        )

        try:
            value = int(
                raw
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        if value > 0:
            return value

    return 1


def artifact_filename(
    value: str,
) -> str:
    try:
        parts = urlsplit(
            value
        )
    except ValueError:
        parts = None

    if (
        parts is not None
        and parts.scheme
        in {
            "http",
            "https",
        }
    ):
        path = parts.path
    else:
        path = value

    return (
        path.rsplit(
            "/",
            1,
        )[-1]
    )


def strip_host_from_url_path_event(
    value: str,
) -> str:
    slash = value.find(
        "/"
    )

    if slash < 0:
        return value

    return value[
        slash:
    ]


def nested_metadata(
    metadata: dict[str, Any],
    *path: str,
) -> Any:
    current: Any = metadata

    for key in path:
        if not isinstance(
            current,
            dict,
        ):
            return None

        current = current.get(
            key
        )

    return current


def _safe_float(
    value: Any,
) -> float | None:
    try:
        parsed = float(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if not math.isfinite(
        parsed
    ):
        return None

    return parsed
