"""Local static JavaScript analysis for Night Scout.

`javascript.py` never downloads a URL and never executes JavaScript.

It consumes a JAVASCRIPT Event whose content has already been materialized by
an approved fetch/archive/artifact stage through `JavaScriptContentProvider`.
The worker then performs bounded lexical/static analysis and emits normalized
Night Scout observations.

Why content delivery is a protocol
----------------------------------
Crawler/archive workers discover JavaScript URLs, but downloading a live file
is an active HTTP action while reading an already downloaded file is local
analysis. Combining both inside this worker would hide a network request behind
a policy descriptor that says "JAVASCRIPT_ANALYSIS".

The intended pipeline is therefore:

    JAVASCRIPT URL discovered
        -> scope/policy/rate-controlled content fetch
        -> JAVASCRIPT observation tagged `content:available`
        -> JavaScriptContentProvider
        -> javascript.py local analysis

A future content fetcher can implement this provider using SQLite/blob storage,
a workspace file store, archive responses, APK extraction, or another trusted
materialization layer without changing the analyzer.

Static analysis outputs
-----------------------
From strings and source-map comments the worker can emit:

- URL
- DNS_NAME
- URL_PATH
- API_ENDPOINT
- PARAMETER_NAME
- ARTIFACT             (source maps)
- VOCAB_TOKEN          (Target Genome input)
- JAVASCRIPT           (analysis summary observation)

Example:

    const u = "/internal-api/v3/orders?id=123";

becomes approximately:

    URL            https://app.example.com/internal-api/v3/orders?id=123
    URL_PATH       app.example.com/internal-api/v3/orders
    API_ENDPOINT   https://app.example.com/internal-api/v3/orders
    PARAMETER_NAME id

and target vocabulary such as:

    internal
    api
    v3
    orders
    id

New vocabulary does not need to exist in any public wordlist first. This is the
bridge from discovered application-specific strings into the future Target
Genome / permutations / pattern engine.

Safety properties
-----------------
- JavaScript is never evaluated, imported, executed, deobfuscated with eval,
  or passed to a shell.
- The worker performs no network I/O.
- Discovered URLs/hosts remain scope=UNKNOWN.
- String and output counts are bounded.
- Query parameter values are discarded.
- Source-map URLs are recorded as artifact candidates, not downloaded.
- Dynamic template strings (`${...}`) are not promoted to concrete URLs.
- Potentially sensitive raw values are not copied into vocabulary metadata.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "javascript"
ACTION_ANALYZE = "analyze"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_SOURCE_MAP_RE = re.compile(
    r"(?://[#@]\s*sourceMappingURL\s*=\s*|/\*[#@]\s*sourceMappingURL\s*=\s*)"
    r"(?P<value>[^\s*]+)",
    re.IGNORECASE,
)
_API_VERSION_TOKEN_RE = re.compile(r"^v[0-9]{1,4}$", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_HOST_LIKE_RE = re.compile(
    r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
_API_VERSION_PATH_RE = re.compile(
    r"/(?:api|rest)(?:/[^/?#]+)*/v[0-9]+(?:/|$)",
    re.IGNORECASE,
)

_JAVASCRIPT_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
)

_SOURCE_MAP_SUFFIXES = (
    ".map",
    ".js.map",
    ".css.map",
)

_GENERIC_VOCAB_STOPWORDS = frozenset(
    {
        "true",
        "false",
        "null",
        "undefined",
        "return",
        "function",
        "const",
        "let",
        "var",
        "this",
        "window",
        "document",
        "object",
        "string",
        "number",
        "boolean",
        "length",
        "prototype",
        "default",
        "exports",
        "module",
        "require",
        "import",
        "from",
        "async",
        "await",
        "then",
        "catch",
        "error",
        "data",
        "value",
        "values",
        "name",
        "type",
        "index",
        "item",
        "items",
        "result",
        "response",
        "request",
        "headers",
        "content",
        "application",
        "javascript",
        "static",
        "assets",
        "bundle",
        "chunk",
        "webpack",
    }
)


class JavaScriptMaterial(BaseModel):
    """Trusted local material returned by JavaScriptContentProvider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str

    origin_url: str | None = None
    content_sha256: str | None = None

    content_source: str = "local"
    content_ref: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content_source")
    @classmethod
    def content_source_required(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "content_source must not be blank"
            )

        return normalized

    @field_validator("origin_url", "content_sha256", "content_ref")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def ensure_hash(self) -> "JavaScriptMaterial":
        digest = hashlib.sha256(
            self.content.encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()

        if self.content_sha256 is None:
            object.__setattr__(
                self,
                "content_sha256",
                digest,
            )
            return self

        normalized = (
            self.content_sha256
            .strip()
            .lower()
            .replace(":", "")
        )

        if (
            len(normalized) != 64
            or any(
                char not in "0123456789abcdef"
                for char in normalized
            )
        ):
            raise ValueError(
                "content_sha256 must be a SHA-256 hex digest"
            )

        if normalized != digest:
            raise ValueError(
                "content_sha256 does not match content"
            )

        object.__setattr__(
            self,
            "content_sha256",
            normalized,
        )

        return self

    @property
    def size_bytes(self) -> int:
        return len(
            self.content.encode(
                "utf-8",
                errors="replace",
            )
        )


class JavaScriptContentProvider(Protocol):
    """Provide already-approved local JavaScript bytes/text."""

    async def material_for(
        self,
        event: Event,
    ) -> JavaScriptMaterial | None:
        ...


class EventPublisher(Protocol):
    """Publish normalized JavaScript-derived Events."""

    async def publish(
        self,
        event: Event,
    ) -> bool:
        ...


class InputEventProvider(Protocol):
    """Load the task input Event."""

    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class InMemoryJavaScriptContentProvider:
    """Deterministic provider for tests/bootstrap.

    Mapping keys may be event_id or JavaScript URL. Event-id material wins.
    """

    def __init__(
        self,
        materials: Mapping[
            str,
            JavaScriptMaterial,
        ],
    ) -> None:
        self._materials = dict(
            materials
        )

    async def material_for(
        self,
        event: Event,
    ) -> JavaScriptMaterial | None:
        return (
            self._materials.get(
                event.event_id
            )
            or self._materials.get(
                event.value
            )
        )


class FileJavaScriptContentProvider:
    """Read local material referenced by an Event inside a trusted root.

    The event must contain a relative metadata key such as:

        content_ref = "blobs/js/ab/cd123.js"

    Absolute paths and path traversal are rejected. This provider performs
    local filesystem I/O only.
    """

    def __init__(
        self,
        root: Path,
        *,
        metadata_key: str = "content_ref",
        encoding: str = "utf-8",
    ) -> None:
        self._root = (
            root.expanduser()
            .resolve()
        )
        self._metadata_key = (
            metadata_key.strip()
        )
        self._encoding = encoding

        if not self._metadata_key:
            raise ValueError(
                "metadata_key must not be blank"
            )

    async def material_for(
        self,
        event: Event,
    ) -> JavaScriptMaterial | None:
        raw_ref = event.metadata.get(
            self._metadata_key
        )

        if not isinstance(
            raw_ref,
            str,
        ):
            return None

        relative = Path(
            raw_ref
        )

        if relative.is_absolute():
            return None

        path = (
            self._root
            / relative
        ).resolve()

        try:
            path.relative_to(
                self._root
            )
        except ValueError:
            return None

        if (
            not path.is_file()
        ):
            return None

        content = path.read_text(
            encoding=self._encoding,
            errors="replace",
        )

        return JavaScriptMaterial(
            content=content,
            origin_url=event.value,
            content_source="workspace-file",
            content_ref=str(relative),
        )


class JavaScriptString(BaseModel):
    """One lexically extracted JS string/template literal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str
    offset: int = Field(ge=0)

    quote: str
    dynamic_template: bool = False


class JavaScriptAnalysisConfig(BaseModel):
    """Bounded local static-analysis configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_content_bytes: int = Field(
        default=32 * 1024 * 1024,
        ge=1024,
        le=512 * 1024 * 1024,
    )

    max_strings: int = Field(
        default=200_000,
        ge=100,
        le=2_000_000,
    )

    max_string_length: int = Field(
        default=16_384,
        ge=16,
        le=1_000_000,
    )

    max_urls: int = Field(
        default=20_000,
        ge=1,
        le=500_000,
    )

    max_api_endpoints: int = Field(
        default=20_000,
        ge=1,
        le=500_000,
    )

    max_parameters: int = Field(
        default=10_000,
        ge=1,
        le=200_000,
    )

    max_vocabulary_tokens: int = Field(
        default=30_000,
        ge=1,
        le=500_000,
    )

    max_source_maps: int = Field(
        default=1024,
        ge=1,
        le=100_000,
    )

    min_vocab_length: int = Field(
        default=2,
        ge=1,
        le=32,
    )

    max_vocab_length: int = Field(
        default=64,
        ge=4,
        le=256,
    )

    url_confidence: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
    )
    dns_confidence: float = Field(
        default=0.84,
        ge=0.0,
        le=1.0,
    )
    path_confidence: float = Field(
        default=0.88,
        ge=0.0,
        le=1.0,
    )
    api_confidence: float = Field(
        default=0.82,
        ge=0.0,
        le=1.0,
    )
    parameter_confidence: float = Field(
        default=0.86,
        ge=0.0,
        le=1.0,
    )
    vocabulary_confidence: float = Field(
        default=0.72,
        ge=0.0,
        le=1.0,
    )
    source_map_confidence: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
    )

    @model_validator(mode="after")
    def vocabulary_bounds(
        self,
    ) -> "JavaScriptAnalysisConfig":
        if (
            self.min_vocab_length
            > self.max_vocab_length
        ):
            raise ValueError(
                "min_vocab_length cannot exceed max_vocab_length"
            )

        return self


class JavaScriptWorker:
    """Network-free JavaScript static analyzer."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        content: JavaScriptContentProvider,
        config: JavaScriptAnalysisConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._content = content
        self._config = (
            config
            or JavaScriptAnalysisConfig()
        )

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if (
            task.status
            is not TaskStatus.RUNNING
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "javascript worker may only execute claimed "
                    f"RUNNING tasks, got {task.status.value}"
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

        if task.action != ACTION_ANALYZE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "unsupported javascript action: "
                    f"{task.action}"
                ),
            )

        event = await self._events.get_event(
            task.input_event_id
        )

        if event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        if (
            event.type
            is not EventType.JAVASCRIPT
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "javascript.analyze requires JAVASCRIPT input, got "
                    f"{event.type.value}"
                ),
            )

        if (
            "content:available"
            not in event.tags
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "javascript.analyze requires content:available; "
                    "this worker never downloads JavaScript itself"
                ),
            )

        material = await self._content.material_for(
            event
        )

        if material is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "JavaScript content is marked available but the "
                    "content provider returned no local material"
                ),
            )

        if (
            material.size_bytes
            > self._config.max_content_bytes
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "JavaScript material exceeds configured local "
                    f"analysis limit: {material.size_bytes} > "
                    f"{self._config.max_content_bytes} bytes"
                ),
            )

        try:
            origin_url = resolve_origin_url(
                event,
                material,
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        analysis = analyze_javascript(
            material.content,
            origin_url=origin_url,
            config=self._config,
        )

        await self._publish_analysis(
            input_event=event,
            material=material,
            origin_url=origin_url,
            analysis=analysis,
        )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _publish_analysis(
        self,
        *,
        input_event: Event,
        material: JavaScriptMaterial,
        origin_url: str,
        analysis: "JavaScriptAnalysis",
    ) -> None:
        source = (
            "javascript:static"
        )

        common = {
            "local_static_analysis": True,
            "network_access": False,
            "origin_url": origin_url,
            "content_sha256": (
                material.content_sha256
            ),
            "content_size_bytes": (
                material.size_bytes
            ),
            "content_source": (
                material.content_source
            ),
            "content_ref": (
                material.content_ref
            ),
        }

        # Summary observation is useful for explainability and yield models.
        summary = Event(
            type=EventType.JAVASCRIPT,
            value=input_event.value,
            source=source,
            parent_event_id=(
                input_event.event_id
            ),
            scope_state=(
                input_event.scope_state
            ),
            confidence=0.99,
            novelty=0.35,
            depth=input_event.depth + 1,
            tags={
                "javascript",
                "analysis:complete",
                "local-static-analysis",
            },
            metadata={
                **common,
                "string_count": (
                    analysis.string_count
                ),
                "dynamic_template_count": (
                    analysis.dynamic_template_count
                ),
                "url_count": len(
                    analysis.urls
                ),
                "api_endpoint_count": len(
                    analysis.api_endpoints
                ),
                "parameter_count": len(
                    analysis.parameters
                ),
                "vocabulary_token_count": len(
                    analysis.vocabulary
                ),
                "source_map_count": len(
                    analysis.source_maps
                ),
            },
        )

        await self._publisher.publish(
            summary
        )

        for url in analysis.urls:
            await self._publish_url(
                input_event=input_event,
                source=source,
                common=common,
                url=url,
                analysis=analysis,
            )

        for endpoint in analysis.api_endpoints:
            await self._publisher.publish(
                Event(
                    type=EventType.API_ENDPOINT,
                    value=endpoint,
                    source=source,
                    parent_event_id=(
                        input_event.event_id
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.api_confidence
                    ),
                    novelty=0.92,
                    depth=input_event.depth + 1,
                    tags={
                        "javascript",
                        "api-endpoint",
                        "hypothesis",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "discovered_via": (
                            "JAVASCRIPT_STATIC_ANALYSIS"
                        ),
                        "requires_scope_reclassification": True,
                        "requires_live_confirmation": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for parameter in analysis.parameters:
            await self._publisher.publish(
                Event(
                    type=EventType.PARAMETER_NAME,
                    value=parameter,
                    source=source,
                    parent_event_id=(
                        input_event.event_id
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.parameter_confidence
                    ),
                    novelty=0.78,
                    depth=input_event.depth + 1,
                    tags={
                        "javascript",
                        "parameter-name",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "parameter_location": (
                            "query-or-urlsearchparams"
                        ),
                        "raw_value_stored": False,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for source_map_url in analysis.source_maps:
            await self._publisher.publish(
                Event(
                    type=EventType.ARTIFACT,
                    value=source_map_url,
                    source=source,
                    parent_event_id=(
                        input_event.event_id
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.source_map_confidence
                    ),
                    novelty=0.94,
                    depth=input_event.depth + 1,
                    tags={
                        "javascript",
                        "source-map",
                        "artifact-candidate",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "artifact_kind": "source-map",
                        "downloaded": False,
                        "requires_scope_reclassification": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for token in analysis.vocabulary:
            token_contexts = (
                analysis.vocabulary_contexts.get(
                    token,
                    ()
                )
            )

            await self._publisher.publish(
                Event(
                    type=EventType.VOCAB_TOKEN,
                    value=token,
                    source=source,
                    parent_event_id=(
                        input_event.event_id
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.vocabulary_confidence
                    ),
                    novelty=0.86,
                    depth=input_event.depth + 1,
                    tags={
                        "javascript",
                        "vocabulary",
                        "target-specific",
                        "target-genome",
                    },
                    metadata={
                        **common,
                        "target_specific": True,
                        "occurrences": (
                            analysis.vocabulary_counts.get(
                                token,
                                1,
                            )
                        ),
                        "contexts": list(
                            token_contexts[:16]
                        ),
                        "source_diversity": 1,
                        "raw_sensitive_value_stored": False,
                    },
                )
            )

    async def _publish_url(
        self,
        *,
        input_event: Event,
        source: str,
        common: dict[str, Any],
        url: str,
        analysis: "JavaScriptAnalysis",
    ) -> None:
        url_event = Event(
            type=EventType.URL,
            value=url,
            source=source,
            parent_event_id=(
                input_event.event_id
            ),
            scope_state=(
                ScopeState.UNKNOWN
            ),
            confidence=(
                self._config.url_confidence
            ),
            novelty=0.90,
            depth=input_event.depth + 1,
            tags={
                "javascript",
                "url-reference",
                "hypothesis",
                "feeds-vocabulary",
            },
            metadata={
                **common,
                "discovered_via": (
                    "JAVASCRIPT_STATIC_ANALYSIS"
                ),
                "requires_scope_reclassification": True,
                "requires_live_confirmation": True,
                "feeds_vocabulary": True,
            },
        )

        url_accepted = (
            await self._publisher.publish(
                url_event
            )
        )

        child_parent = (
            url_event.event_id
            if url_accepted
            else input_event.event_id
        )

        parts = urlsplit(
            url
        )

        if parts.hostname is not None:
            try:
                hostname = normalize_dns_name(
                    parts.hostname
                )
            except ValueError:
                hostname = None

            if hostname is not None:
                await self._publisher.publish(
                    Event(
                        type=EventType.DNS_NAME,
                        value=hostname,
                        source=source,
                        parent_event_id=(
                            child_parent
                        ),
                        scope_state=(
                            ScopeState.UNKNOWN
                        ),
                        confidence=(
                            self._config.dns_confidence
                        ),
                        novelty=0.88,
                        depth=input_event.depth + 2,
                        tags={
                            "javascript",
                            "dns-candidate",
                            "hypothesis",
                            "feeds-vocabulary",
                        },
                        metadata={
                            **common,
                            "discovered_via": (
                                "JAVASCRIPT_URL_REFERENCE"
                            ),
                            "reference_url": url,
                            "requires_scope_reclassification": True,
                            "requires_dns_confirmation": True,
                            "feeds_vocabulary": True,
                        },
                    )
                )

        if (
            parts.path
            and parts.path != "/"
        ):
            await self._publisher.publish(
                Event(
                    type=EventType.URL_PATH,
                    value=url_path_identity(
                        url
                    ),
                    source=source,
                    parent_event_id=(
                        child_parent
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.path_confidence
                    ),
                    novelty=0.82,
                    depth=input_event.depth + 2,
                    tags={
                        "javascript",
                        "url-path",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "url": url,
                        "path": parts.path,
                        "feeds_vocabulary": True,
                    },
                )
            )

        # Parameters are also aggregated globally, but recording the URL parent
        # is useful provenance when a parameter occurs in a concrete reference.
        for parameter in query_parameter_names(
            url
        ):
            if (
                parameter
                not in analysis.parameters
            ):
                continue

            await self._publisher.publish(
                Event(
                    type=EventType.PARAMETER_NAME,
                    value=parameter,
                    source=(
                        "javascript:url-query"
                    ),
                    parent_event_id=(
                        child_parent
                    ),
                    scope_state=(
                        ScopeState.UNKNOWN
                    ),
                    confidence=(
                        self._config.parameter_confidence
                    ),
                    novelty=0.78,
                    depth=input_event.depth + 2,
                    tags={
                        "javascript",
                        "parameter-name",
                        "query",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "reference_url": url,
                        "parameter_location": "query",
                        "raw_value_stored": False,
                        "feeds_vocabulary": True,
                    },
                )
            )


class JavaScriptAnalysis(BaseModel):
    """Bounded deterministic local analysis result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    string_count: int = Field(ge=0)
    dynamic_template_count: int = Field(ge=0)

    urls: tuple[str, ...] = ()
    api_endpoints: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    source_maps: tuple[str, ...] = ()

    vocabulary: tuple[str, ...] = ()

    vocabulary_counts: dict[str, int] = Field(default_factory=dict)
    vocabulary_contexts: dict[str, tuple[str, ...]] = Field(
        default_factory=dict
    )


def javascript_route_rules(
    *,
    base_priority: float = 7.25,
) -> tuple[RouteRule, ...]:
    """Route only materialized JS observations into local analysis."""

    return (
        RouteRule(
            rule_id="javascript.analyze.local-content",
            accepts=frozenset(
                {EventType.JAVASCRIPT}
            ),
            worker=WORKER_NAME,
            action=ACTION_ANALYZE,
            reason=(
                "locally analyze already materialized JavaScript content"
            ),
            base_priority=base_priority,
            required_tags=frozenset(
                {"content:available"}
            ),
            excluded_tags=frozenset(
                {"analysis:complete"}
            ),
            predicate=_content_reference_present,
        ),
    )


def _content_reference_present(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    return bool(
        event.metadata.get(
            "content_ref"
        )
        or event.metadata.get(
            "content_available"
        )
        or "content:available" in event.tags
    )


def resolve_origin_url(
    event: Event,
    material: JavaScriptMaterial,
) -> str:
    """Choose the URL used to resolve static relative references."""

    candidate = (
        material.origin_url
        or event.metadata.get(
            "origin_url"
        )
        or event.value
    )

    if not isinstance(
        candidate,
        str,
    ):
        raise ValueError(
            "JavaScript material has no usable origin URL"
        )

    return normalize_http_url(
        candidate
    )


def analyze_javascript(
    content: str,
    *,
    origin_url: str,
    config: JavaScriptAnalysisConfig | None = None,
) -> JavaScriptAnalysis:
    """Perform bounded lexical/static analysis without executing JavaScript."""

    cfg = (
        config
        or JavaScriptAnalysisConfig()
    )

    normalized_origin = normalize_http_url(
        origin_url
    )

    strings = extract_javascript_strings(
        content,
        max_strings=cfg.max_strings,
        max_string_length=(
            cfg.max_string_length
        ),
    )

    urls: set[str] = set()
    api_endpoints: set[str] = set()
    parameters: set[str] = set()
    source_maps: set[str] = set()

    vocabulary_counter: Counter[str] = Counter()
    vocabulary_contexts: dict[
        str,
        set[str],
    ] = defaultdict(set)

    dynamic_count = 0

    for literal in strings:
        if literal.dynamic_template:
            dynamic_count += 1

            # Dynamic templates are useful vocabulary evidence, but are not
            # promoted to a concrete URL because `${...}` is unresolved.
            add_vocabulary_from_text(
                literal.value,
                context="dynamic-template",
                counter=vocabulary_counter,
                contexts=vocabulary_contexts,
                config=cfg,
            )
            continue

        value = (
            literal.value.strip()
        )

        if not value:
            continue

        add_vocabulary_from_text(
            value,
            context="javascript-string",
            counter=vocabulary_counter,
            contexts=vocabulary_contexts,
            config=cfg,
        )

        reference = resolve_static_reference(
            value,
            origin_url=normalized_origin,
        )

        if reference is not None:
            urls.add(reference)

            add_vocabulary_from_url(
                reference,
                counter=vocabulary_counter,
                contexts=vocabulary_contexts,
                config=cfg,
            )

            parameters.update(
                query_parameter_names(
                    reference
                )
            )

            if looks_like_api_endpoint(
                reference
            ):
                api_endpoints.add(
                    api_endpoint_identity(
                        reference
                    )
                )

        elif looks_like_relative_api_reference(
            value
        ):
            candidate = resolve_root_relative_api_reference(
                value,
                origin_url=normalized_origin,
            )

            if candidate is not None:
                urls.add(candidate)
                api_endpoints.add(
                    api_endpoint_identity(
                        candidate
                    )
                )

                add_vocabulary_from_url(
                    candidate,
                    counter=vocabulary_counter,
                    contexts=vocabulary_contexts,
                    config=cfg,
                )

                parameters.update(
                    query_parameter_names(
                        candidate
                    )
                )

    # sourceMappingURL often appears in comments rather than string literals.
    for match in _SOURCE_MAP_RE.finditer(
        content
    ):
        raw = (
            match.group("value")
            .strip()
            .strip('"\'')
        )

        if not raw:
            continue

        if raw.startswith(
            "data:"
        ):
            # Inline source maps are already local data, but putting enormous
            # data URIs into Event.value would be harmful and unnecessary.
            continue

        resolved = resolve_source_map_reference(
            raw,
            origin_url=normalized_origin,
        )

        if (
            resolved is not None
            and is_source_map_url(
                resolved
            )
        ):
            source_maps.add(
                resolved
            )

            add_vocabulary_from_url(
                resolved,
                counter=vocabulary_counter,
                contexts=vocabulary_contexts,
                config=cfg,
            )

        if (
            len(source_maps)
            >= cfg.max_source_maps
        ):
            break

    # URLSearchParams("foo=1&bar=2") provides parameter names even when the
    # query string is not attached to a concrete URL.
    parameters.update(
        extract_urlsearchparams_names(
            content,
            limit=cfg.max_parameters,
        )
    )

    for parameter in parameters:
        add_vocabulary_token(
            parameter,
            context="parameter",
            counter=vocabulary_counter,
            contexts=vocabulary_contexts,
            config=cfg,
        )

    ranked_vocabulary = tuple(
        token
        for token, _count in sorted(
            vocabulary_counter.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )[
            : cfg.max_vocabulary_tokens
        ]
    )

    bounded_urls = tuple(
        sorted(urls)
        [: cfg.max_urls]
    )

    bounded_api = tuple(
        sorted(api_endpoints)
        [: cfg.max_api_endpoints]
    )

    bounded_parameters = tuple(
        sorted(parameters)
        [: cfg.max_parameters]
    )

    bounded_maps = tuple(
        sorted(source_maps)
        [: cfg.max_source_maps]
    )

    return JavaScriptAnalysis(
        string_count=len(strings),
        dynamic_template_count=dynamic_count,
        urls=bounded_urls,
        api_endpoints=bounded_api,
        parameters=bounded_parameters,
        source_maps=bounded_maps,
        vocabulary=ranked_vocabulary,
        vocabulary_counts={
            token: vocabulary_counter[
                token
            ]
            for token in ranked_vocabulary
        },
        vocabulary_contexts={
            token: tuple(
                sorted(
                    vocabulary_contexts[
                        token
                    ]
                )
            )
            for token in ranked_vocabulary
        },
    )


def extract_javascript_strings(
    content: str,
    *,
    max_strings: int,
    max_string_length: int,
) -> tuple[JavaScriptString, ...]:
    """Extract quoted literals with a small non-executing lexer.

    This deliberately does not try to parse the full ECMAScript grammar. It is
    robust enough for common bundles/minified code while avoiding catastrophic
    regular expressions over multi-megabyte files.
    """

    result: list[
        JavaScriptString
    ] = []

    length = len(
        content
    )

    index = 0

    while (
        index < length
        and len(result) < max_strings
    ):
        char = content[index]

        # Skip comments so quote characters inside comments do not create huge
        # bogus strings. sourceMappingURL is handled separately.
        if (
            char == "/"
            and index + 1 < length
        ):
            next_char = (
                content[
                    index + 1
                ]
            )

            if next_char == "/":
                newline = content.find(
                    "\n",
                    index + 2,
                )

                if newline == -1:
                    break

                index = newline + 1
                continue

            if next_char == "*":
                end = content.find(
                    "*/",
                    index + 2,
                )

                if end == -1:
                    break

                index = end + 2
                continue

        if char not in {
            "'",
            '"',
            "`",
        }:
            index += 1
            continue

        quote = char
        start = index
        index += 1

        buffer: list[str] = []
        dynamic_template = False
        escaped = False
        terminated = False

        while index < length:
            current = (
                content[index]
            )

            if escaped:
                # Decode only deterministic lexical escapes. This is static
                # text decoding, not JavaScript evaluation.
                translated, extra_consumed = _translate_static_escape(
                    content,
                    index,
                )

                if (
                    len(buffer)
                    < max_string_length
                ):
                    buffer.append(
                        translated
                    )

                escaped = False
                index += 1 + extra_consumed
                continue

            if current == "\\":
                escaped = True
                index += 1
                continue

            if current == quote:
                terminated = True
                index += 1
                break

            if (
                quote == "`"
                and current == "$"
                and index + 1 < length
                and content[
                    index + 1
                ] == "{"
            ):
                dynamic_template = True

            if (
                len(buffer)
                < max_string_length
            ):
                buffer.append(
                    current
                )

            index += 1

        if not terminated:
            continue

        result.append(
            JavaScriptString(
                value="".join(
                    buffer
                ),
                offset=start,
                quote=quote,
                dynamic_template=(
                    dynamic_template
                ),
            )
        )

    return tuple(
        result
    )


def _translate_static_escape(
    content: str,
    index: int,
) -> tuple[str, int]:
    """Decode a bounded subset of deterministic JS string escapes.

    Returns `(decoded_text, extra_characters_consumed_after_current)`.

    Supported lexical escapes include escaped slash/backslash,
    newline/tab escapes, two-digit hex escapes, and four-digit Unicode
    escapes.

    We intentionally do not implement dynamic/template evaluation, octal
    escapes, surrogate-pair reconstruction, or arbitrary code execution.
    """

    char = content[index]

    simple = {
        "/": "/",
        "\\": "\\",
        "'": "'",
        '"': '"',
        "`": "`",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\0",
    }

    if char in simple:
        return simple[char], 0

    if char == "x":
        raw = content[
            index + 1 :
            index + 3
        ]

        if (
            len(raw) == 2
            and all(
                c in "0123456789abcdefABCDEF"
                for c in raw
            )
        ):
            return chr(
                int(raw, 16)
            ), 2

    if char == "u":
        raw = content[
            index + 1 :
            index + 5
        ]

        if (
            len(raw) == 4
            and all(
                c in "0123456789abcdefABCDEF"
                for c in raw
            )
        ):
            codepoint = int(
                raw,
                16,
            )

            # Avoid materializing isolated surrogate code points.
            if not (
                0xD800
                <= codepoint
                <= 0xDFFF
            ):
                return chr(
                    codepoint
                ), 4

    # Unknown escape: preserve the escaped character rather than pretending
    # the backslash was meaningful execution syntax.
    return char, 0


def resolve_static_reference(
    value: str,
    *,
    origin_url: str,
) -> str | None:
    """Resolve only unambiguous static HTTP(S) references."""

    raw = value.strip()

    if (
        not raw
        or len(raw) > 16_384
        or "${" in raw
    ):
        return None

    lower = raw.lower()

    if lower.startswith(
        ("javascript:", "data:", "mailto:", "tel:", "blob:")
    ):
        return None

    if raw.startswith("//"):
        scheme = urlsplit(
            origin_url
        ).scheme

        try:
            return normalize_http_url(
                f"{scheme}:{raw}"
            )
        except ValueError:
            return None

    if lower.startswith(
        ("http://", "https://")
    ):
        try:
            return normalize_http_url(
                raw
            )
        except ValueError:
            return None

    if raw.startswith(
        (
            "/",
            "./",
            "../",
        )
    ):
        try:
            return normalize_http_url(
                urljoin(
                    origin_url,
                    raw,
                )
            )
        except ValueError:
            return None

    return None


def resolve_source_map_reference(
    value: str,
    *,
    origin_url: str,
) -> str | None:
    """Resolve sourceMappingURL, including common bare relative filenames."""

    raw = value.strip()

    if (
        not raw
        or len(raw) > 16_384
        or "${" in raw
        or raw.lower().startswith(
            ("data:", "javascript:", "blob:")
        )
    ):
        return None

    resolved = resolve_static_reference(
        raw,
        origin_url=origin_url,
    )

    if resolved is not None:
        return resolved

    # sourceMappingURL=app.js.map is relative to the JavaScript file itself.
    if (
        "://" not in raw
        and not raw.startswith("#")
    ):
        try:
            return normalize_http_url(
                urljoin(
                    origin_url,
                    raw,
                )
            )
        except ValueError:
            return None

    return None


def looks_like_relative_api_reference(
    value: str,
) -> bool:
    """Recognize common endpoint strings that omit the leading slash."""

    raw = value.strip()

    if (
        not raw
        or "${" in raw
        or "://" in raw
        or raw.startswith(
            ("#", "?", ".")
        )
    ):
        return False

    first = (
        raw.split(
            "/",
            1,
        )[0]
        .lower()
    )

    tokens = {
        token
        for token in _TOKEN_SPLIT_RE.split(
            first
        )
        if token
    }

    if {
        "api",
        "rest",
        "graphql",
        "graphiql",
        "swagger",
        "openapi",
    } & tokens:
        return True

    return bool(
        re.fullmatch(
            r"v[0-9]{1,4}",
            first,
            flags=re.IGNORECASE,
        )
    )


def resolve_root_relative_api_reference(
    value: str,
    *,
    origin_url: str,
) -> str | None:
    """Resolve ambiguous API-like relative strings against the origin root."""

    origin = urlsplit(
        normalize_http_url(
            origin_url
        )
    )

    root = urlunsplit(
        (
            origin.scheme,
            origin.netloc,
            "/",
            "",
            "",
        )
    )

    candidate = (
        value.lstrip(
            "/"
        )
    )

    try:
        return normalize_http_url(
            urljoin(
                root,
                candidate,
            )
        )
    except ValueError:
        return None


def normalize_http_url(
    value: str,
) -> str:
    """Canonicalize an HTTP(S) URL without fetching it."""

    raw = value.strip()

    if not raw:
        raise ValueError(
            "URL must not be blank"
        )

    parts = urlsplit(
        raw
    )

    scheme = (
        parts.scheme
        .lower()
    )

    if scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "URL scheme must be http or https"
        )

    if (
        parts.username is not None
        or parts.password is not None
    ):
        raise ValueError(
            "userinfo is not allowed"
        )

    if parts.hostname is None:
        raise ValueError(
            "URL hostname is required"
        )

    hostname = normalize_dns_name(
        parts.hostname
    )

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(
            "URL contains invalid port"
        ) from exc

    default_port = (
        443
        if scheme == "https"
        else 80
    )

    if (
        port is None
        or port == default_port
    ):
        netloc = hostname
    else:
        netloc = (
            f"{hostname}:{port}"
        )

    path = (
        parts.path
        or "/"
    )

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parts.query,
            "",
        )
    )


def looks_like_api_endpoint(
    url: str,
) -> bool:
    """Conservative static API-path heuristic."""

    path = (
        urlsplit(
            normalize_http_url(
                url
            )
        ).path
        .lower()
    )

    if _API_VERSION_PATH_RE.search(
        path
    ):
        return True

    for segment in path.split(
        "/"
    ):
        if not segment:
            continue

        tokens = {
            token
            for token in _TOKEN_SPLIT_RE.split(
                segment
            )
            if token
        }

        if {
            "api",
            "rest",
            "graphql",
            "graphiql",
            "swagger",
            "openapi",
        } & tokens:
            return True

    return path.endswith(
        (
            "/graphql",
            "/graphiql",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
        )
    )


def api_endpoint_identity(
    url: str,
) -> str:
    """Endpoint identity strips query values and fragment."""

    normalized = normalize_http_url(
        url
    )

    parts = urlsplit(
        normalized
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            "",
            "",
        )
    )


def url_path_identity(
    url: str,
) -> str:
    """Host-aware URL path identity."""

    normalized = normalize_http_url(
        url
    )

    parts = urlsplit(
        normalized
    )

    if parts.hostname is None:
        raise ValueError(
            "URL path identity requires hostname"
        )

    authority = (
        parts.hostname
    )

    if parts.port is not None:
        authority = (
            f"{authority}:{parts.port}"
        )

    return (
        authority
        + (parts.path or "/")
    )


def query_parameter_names(
    url: str,
) -> tuple[str, ...]:
    """Extract unique query parameter names; values are discarded."""

    query = (
        urlsplit(
            normalize_http_url(
                url
            )
        ).query
    )

    if not query:
        return ()

    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=4096,
        )
    except ValueError:
        return ()

    return tuple(
        sorted(
            {
                name.strip()
                for name, _value
                in pairs
                if name.strip()
            }
        )
    )


def extract_urlsearchparams_names(
    content: str,
    *,
    limit: int,
) -> tuple[str, ...]:
    """Extract parameter names from static URLSearchParams query strings.

    Only quoted constructor arguments are considered. Object literals and
    dynamic values are deliberately left to a future AST-capable analyzer.
    """

    if limit <= 0:
        return ()

    pattern = re.compile(
        r"""
        new\s+URLSearchParams\s*
        \(\s*
        (?P<quote>['"])
        (?P<query>
            (?:\\.|(?!\1).)*
        )
        (?P=quote)
        \s*\)
        """,
        re.VERBOSE,
    )

    names: set[str] = set()

    for match in pattern.finditer(
        content
    ):
        query = (
            match.group(
                "query"
            )
        )

        # URLSearchParams expects a query string, not a full URL.
        try:
            pairs = parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=4096,
            )
        except ValueError:
            continue

        for name, _value in pairs:
            normalized = (
                name.strip()
            )

            if normalized:
                names.add(
                    normalized
                )

            if len(names) >= limit:
                return tuple(
                    sorted(
                        names
                    )
                )

    return tuple(
        sorted(
            names
        )
    )


def is_source_map_url(
    url: str,
) -> bool:
    path = (
        urlsplit(
            normalize_http_url(
                url
            )
        ).path
        .lower()
    )

    return path.endswith(
        _SOURCE_MAP_SUFFIXES
    )


def add_vocabulary_from_url(
    url: str,
    *,
    counter: Counter[str],
    contexts: dict[str, set[str]],
    config: JavaScriptAnalysisConfig,
) -> None:
    parts = urlsplit(
        normalize_http_url(
            url
        )
    )

    if parts.hostname is not None:
        for label in (
            parts.hostname.split(
                "."
            )
        ):
            add_vocabulary_from_text(
                label,
                context="hostname",
                counter=counter,
                contexts=contexts,
                config=config,
            )

    for segment in parts.path.split(
        "/"
    ):
        add_vocabulary_from_text(
            segment,
            context="url-path",
            counter=counter,
            contexts=contexts,
            config=config,
        )

    for name in query_parameter_names(
        url
    ):
        add_vocabulary_token(
            name,
            context="parameter",
            counter=counter,
            contexts=contexts,
            config=config,
        )


def add_vocabulary_from_text(
    text: str,
    *,
    context: str,
    counter: Counter[str],
    contexts: dict[str, set[str]],
    config: JavaScriptAnalysisConfig,
) -> None:
    """Split application strings into bounded Target Genome vocabulary."""

    if (
        not text
        or len(text) > 16_384
    ):
        return

    for coarse in _TOKEN_SPLIT_RE.split(
        text
    ):
        if not coarse:
            continue

        camel_parts = (
            _CAMEL_BOUNDARY_RE.split(
                coarse
            )
        )

        for part in camel_parts:
            add_vocabulary_token(
                part,
                context=context,
                counter=counter,
                contexts=contexts,
                config=config,
            )


def add_vocabulary_token(
    token: str,
    *,
    context: str,
    counter: Counter[str],
    contexts: dict[str, set[str]],
    config: JavaScriptAnalysisConfig,
) -> None:
    """Normalize and score one target-specific token occurrence."""

    normalized = (
        token.strip()
        .lower()
    )

    if not normalized:
        return

    if (
        len(normalized)
        < config.min_vocab_length
        or len(normalized)
        > config.max_vocab_length
    ):
        return

    if normalized in _GENERIC_VOCAB_STOPWORDS:
        return

    if normalized.isdigit():
        return

    # Keep API versions such as v1/v2/v3 as first-class vocabulary.
    if (
        not _API_VERSION_TOKEN_RE.fullmatch(
            normalized
        )
        and not any(
            char.isalpha()
            for char in normalized
        )
    ):
        return

    # Avoid hashes/minified identifiers dominating the vocabulary.
    if (
        len(normalized) >= 24
        and _looks_hash_like(
            normalized
        )
    ):
        return

    counter[
        normalized
    ] += 1

    contexts[
        normalized
    ].add(
        context
    )


def _looks_hash_like(
    value: str,
) -> bool:
    if not value:
        return False

    hex_fraction = (
        sum(
            char in "0123456789abcdef"
            for char in value.lower()
        )
        / len(value)
    )

    return (
        hex_fraction >= 0.90
    )


def _source_component(
    value: str,
) -> str:
    normalized = (
        value.strip()
        .lower()
    )

    normalized = (
        _SOURCE_COMPONENT_RE.sub(
            "-",
            normalized,
        ).strip("-")
    )

    return normalized or "unknown"
