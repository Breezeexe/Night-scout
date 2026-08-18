"""Passive historical URL discovery for Night Scout.

The archive worker builds a historical view of a target without contacting the
target itself. The initial backend is ProjectDiscovery URLFinder restricted by
default to historical URL datasets:

    waybackarchive
    commoncrawl

URLFinder is used in JSONL mode with source attribution. The worker streams
results, preserves provider diversity and derives structured Night Scout events
that later intelligence modules can learn from.

Typical flow
------------
ROOT_DOMAIN
    example.com
        |
        | passive archive/provider lookup
        v
URL
    https://api.example.com/internal-api/v3/orders?id=123
        |
        +--> DNS_NAME api.example.com             (historical hypothesis)
        +--> URL_PATH api.example.com/internal-api/v3/orders
        +--> API_ENDPOINT https://api.../orders   (heuristic hypothesis)
        +--> PARAMETER_NAME id
        +--> JAVASCRIPT ...                       (when path is JS)
        +--> ARTIFACT ...                         (when path looks like an
                                                   old build/source map/etc.)

These are historical observations, not proof that a URL is still live. Every
derived active target remains scope=UNKNOWN and must be reclassified before
later HTTP/DNS/crawl/content workers can touch it.

Important separation
--------------------
This module intentionally retrieves URL indexes only. It does NOT download
archived response bodies. Downloading Wayback/URLScan historical responses is
valuable for recovering old JavaScript, comments, project names and endpoints,
but it should be a separate archive-response action with its own storage,
redaction and review behavior.

The worker also does NOT create VOCAB_TOKEN events directly. It emits
URL_PATH/API_ENDPOINT/PARAMETER_NAME/JAVASCRIPT/ARTIFACT observations with
provenance. Future intelligence/vocabulary.py will extract target-specific
tokens from those events.

No target RateLimiter permit is consumed here: URLFinder talks to passive data
providers rather than to the bug-bounty target. Provider API throttling is
handled independently through URLFinder's provider-side rate limit flags.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "archives"
ACTION_DISCOVER_URLS = "discover_urls"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_API_PATH_RE = re.compile(
    r"""
    (?:
        ^|/
    )
    (?:
        api
        |rest
        |graphql
        |graphiql
        |swagger
        |openapi
    )
    (?:
        /|$|[._-]
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_API_VERSION_RE = re.compile(
    r"/(?:api|rest)(?:/[^/?#]+)*/v[0-9]+(?:/|$)",
    re.IGNORECASE,
)

_JAVASCRIPT_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
)

_SOURCE_MAP_SUFFIXES = (
    ".js.map",
    ".css.map",
    ".map",
)

_BUILD_ARTIFACT_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
    ".7z",
    ".rar",
    ".apk",
    ".ipa",
    ".jar",
    ".war",
    ".ear",
    ".msi",
    ".exe",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
)

_BACKUP_SUFFIXES = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".swp",
)

_CONFIG_BASENAMES = {
    ".env",
    "web.config",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.toml",
    "settings.py",
    "application.properties",
    "application.yml",
    "application.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}


class ArchiveArtifactKind(str):
    """String constants kept intentionally lightweight for metadata."""

    SOURCE_MAP = "source-map"
    BUILD_ARCHIVE = "build-archive"
    BACKUP_FILE = "backup-file"
    CONFIG_FILE = "config-file"


class ArchiveURLFinding(BaseModel):
    """One provider-attributed historical/passive URL observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str

    adapter: str
    provider: str | None = None

    observed_at: str | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    mime_type: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url", "adapter")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("provider", "observed_at", "mime_type")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class ArchiveURLSource(Protocol):
    """Streaming passive URL-index backend."""

    name: str

    def ensure_available(self) -> None:
        ...

    async def stream(
        self,
        domain: str,
    ) -> AsyncIterator[ArchiveURLFinding]:
        ...


class InputEventProvider(Protocol):
    """Load task input Event."""

    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class EventPublisher(Protocol):
    """Publish normalized archive-derived events."""

    async def publish(
        self,
        event: Event,
    ) -> bool:
        ...


class URLFinderConfig(BaseModel):
    """ProjectDiscovery URLFinder subprocess configuration.

    The rate limit here controls requests to passive providers such as the
    Wayback index/Common Crawl. It is separate from target-node rate limits.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "urlfinder"

    sources: tuple[str, ...] = (
        "waybackarchive",
        "commoncrawl",
    )

    all_sources: bool = False

    field_scope: str = "rdn"

    provider_rate_limit: int | None = Field(
        default=5,
        ge=1,
    )

    config_path: Path | None = None
    provider_config_path: Path | None = None

    process_timeout_seconds: float = Field(
        default=300.0,
        gt=0.0,
    )

    stderr_tail_lines: int = Field(
        default=100,
        ge=1,
        le=2000,
    )

    stream_limit_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=65536,
    )

    extra_args: tuple[str, ...] = ()

    @field_validator("binary", "field_scope")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("sources")
    @classmethod
    def normalize_sources(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    value.strip().lower()
                    for value in values
                    if value.strip()
                }
            )
        )

    @field_validator("extra_args")
    @classmethod
    def restrict_extra_args(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            value.strip()
            for value in values
            if value.strip()
        )

        forbidden = {
            # Input / source ownership.
            "-d",
            "-list",
            "-s",
            "-sources",
            "-es",
            "-exclude-sources",
            "-all",

            # Scope behavior is fixed by the adapter and rechecked locally.
            "-us",
            "-url-scope",
            "-uos",
            "-url-out-scope",
            "-fs",
            "-field-scope",
            "-ns",
            "-no-scope",
            "-do",
            "-display-out-scope",

            # Provider request rate is an explicit config field.
            "-rl",
            "-rate-limit",
            "-rls",
            "-rate-limits",

            # Output must stay structured stdout.
            "-o",
            "-output",
            "-od",
            "-output-dir",
            "-j",
            "-jsonl",
            "-cs",
            "-collect-sources",
            "-stats",
            "-v",
            "-version",
            "-ls",
            "-list-sources",

            # Network routing/configuration should be explicit.
            "-proxy",
            "-config",
            "-pc",
            "-provider-config",

            # Automatic updates.
            "-up",
            "-update",
        }

        if any(
            value in forbidden
            for value in normalized
        ):
            raise ValueError(
                "urlfinder extra_args cannot override input, source/scope "
                "selection, provider rate, configuration, or JSON stdout"
            )

        return normalized

    @model_validator(mode="after")
    def source_selection_is_valid(
        self,
    ) -> "URLFinderConfig":
        if self.all_sources and self.sources:
            raise ValueError(
                "all_sources and explicit sources are mutually exclusive"
            )
        return self


class ArchivesWorkerConfig(BaseModel):
    """Normalization and bounded derivation settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url_confidence: float = Field(
        default=0.82,
        ge=0.0,
        le=1.0,
    )

    hostname_confidence: float = Field(
        default=0.76,
        ge=0.0,
        le=1.0,
    )

    derived_confidence: float = Field(
        default=0.78,
        ge=0.0,
        le=1.0,
    )

    api_endpoint_confidence: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
    )

    artifact_confidence: float = Field(
        default=0.72,
        ge=0.0,
        le=1.0,
    )

    retry_after_seconds: float = Field(
        default=30.0,
        ge=0.0,
    )

    max_url_length: int = Field(
        default=16_384,
        ge=256,
        le=1_000_000,
    )

    max_parameters_per_url: int = Field(
        default=64,
        ge=0,
        le=1000,
    )

    # Worker-local duplicate cache is bounded. Durable dedupe remains the
    # responsibility of EventPublisher/storage.
    recent_dedupe_capacity: int = Field(
        default=250_000,
        ge=1000,
    )

    fail_if_all_sources_fail: bool = True


class ArchiveSourceError(RuntimeError):
    """Passive URL source failed."""


class ArchiveSourceUnavailable(ArchiveSourceError):
    """Configured passive URL tool is unavailable."""


class ArchiveSourceTimeout(ArchiveSourceError):
    """Passive URL tool exceeded its outer timeout."""


class URLFinderSource:
    """Streaming ProjectDiscovery URLFinder adapter."""

    name = "urlfinder"

    def __init__(
        self,
        config: URLFinderConfig | None = None,
    ) -> None:
        self.config = config or URLFinderConfig()

    def ensure_available(self) -> None:
        if (
            _resolve_executable(
                self.config.binary
            )
            is None
        ):
            raise ArchiveSourceUnavailable(
                "urlfinder executable not found: "
                f"{self.config.binary}"
            )

    def command_for(
        self,
        domain: str,
    ) -> tuple[str, ...]:
        """Build safe JSONL argv for one domain."""
        seed = normalize_dns_name(
            domain
        )

        executable = _resolve_executable(
            self.config.binary
        )
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-d",
            seed,
            "-j",
            "-cs",
            "-silent",
            "-nc",
            "-duc",
            "-fs",
            self.config.field_scope,
        ]

        if self.config.all_sources:
            args.append(
                "-all"
            )
        elif self.config.sources:
            args.extend(
                (
                    "-s",
                    ",".join(
                        self.config.sources
                    ),
                )
            )

        if (
            self.config.provider_rate_limit
            is not None
        ):
            args.extend(
                (
                    "-rl",
                    str(
                        self.config.provider_rate_limit
                    ),
                )
            )

        if (
            self.config.config_path
            is not None
        ):
            args.extend(
                (
                    "-config",
                    str(
                        self.config.config_path
                    ),
                )
            )

        if (
            self.config.provider_config_path
            is not None
        ):
            args.extend(
                (
                    "-pc",
                    str(
                        self.config.provider_config_path
                    ),
                )
            )

        args.extend(
            self.config.extra_args
        )

        return tuple(args)

    async def stream(
        self,
        domain: str,
    ) -> AsyncIterator[ArchiveURLFinding]:
        seed = normalize_dns_name(
            domain
        )

        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(seed),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=self.config.stream_limit_bytes,
            env=os.environ.copy(),
        )

        if (
            process.stdout is None
            or process.stderr is None
        ):
            await _terminate_process(
                process
            )
            raise ArchiveSourceError(
                "urlfinder subprocess pipes were not created"
            )

        stderr_tail: deque[str] = deque(
            maxlen=(
                self.config.stderr_tail_lines
            )
        )

        stderr_task = asyncio.create_task(
            _drain_stderr(
                process.stderr,
                stderr_tail,
            )
        )

        try:
            try:
                async with asyncio.timeout(
                    self.config.process_timeout_seconds
                ):
                    while True:
                        raw_line = (
                            await process.stdout.readline()
                        )

                        if not raw_line:
                            break

                        line = raw_line.decode(
                            "utf-8",
                            errors="replace",
                        ).strip()

                        if not line:
                            continue

                        for finding in (
                            parse_urlfinder_line(
                                line
                            )
                        ):
                            yield finding

                    returncode = (
                        await process.wait()
                    )

            except TimeoutError as exc:
                await _terminate_process(
                    process
                )

                raise ArchiveSourceTimeout(
                    "urlfinder exceeded outer process "
                    f"timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(
                    stderr_tail
                )

                raise ArchiveSourceError(
                    "urlfinder exited unsuccessfully "
                    f"(returncode={returncode})"
                    + (
                        f"; stderr_tail={detail}"
                        if detail
                        else ""
                    )
                )

        finally:
            if process.returncode is None:
                await _terminate_process(
                    process
                )

            try:
                await stderr_task
            except asyncio.CancelledError:
                raise
            except Exception:
                pass


class _BoundedSeen:
    """Small FIFO duplicate cache with bounded memory."""

    def __init__(
        self,
        capacity: int,
    ) -> None:
        if capacity <= 0:
            raise ValueError(
                "capacity must be positive"
            )

        self._capacity = capacity
        self._queue: deque[
            tuple[str, str]
        ] = deque()
        self._set: set[
            tuple[str, str]
        ] = set()

    def add(
        self,
        key: tuple[str, str],
    ) -> bool:
        """Return True for a newly inserted key."""
        if key in self._set:
            return False

        self._set.add(
            key
        )
        self._queue.append(
            key
        )

        while (
            len(self._queue)
            > self._capacity
        ):
            oldest = (
                self._queue.popleft()
            )
            self._set.discard(
                oldest
            )

        return True


class ArchivesWorker:
    """Discover historical URLs and derive structured passive observations."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        sources: Sequence[
            ArchiveURLSource
        ] | None = None,
        config: ArchivesWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._sources = tuple(
            sources
            if sources is not None
            else (
                URLFinderSource(),
            )
        )
        self._config = (
            config
            or ArchivesWorkerConfig()
        )

        if not self._sources:
            raise ValueError(
                "ArchivesWorker requires at least one source"
            )

        names = [
            source.name
            for source in self._sources
        ]

        if (
            len(names)
            != len(set(names))
        ):
            raise ValueError(
                "archive source names must be unique"
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
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "archives worker may only execute claimed "
                    f"RUNNING tasks, got "
                    f"{task.status.value}"
                ),
            )

        if task.worker != self.name:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "task worker mismatch: "
                    f"expected {self.name}, "
                    f"got {task.worker}"
                ),
            )

        if (
            task.action
            != ACTION_DISCOVER_URLS
        ):
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "unsupported archives action: "
                    f"{task.action}"
                ),
            )

        input_event = (
            await self._events.get_event(
                task.input_event_id
            )
        )

        if input_event is None:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        if input_event.type not in {
            EventType.ROOT_DOMAIN,
            EventType.DNS_NAME,
        }:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "archives.discover_urls requires "
                    "ROOT_DOMAIN or DNS_NAME input, got "
                    f"{input_event.type.value}"
                ),
            )

        try:
            seed = normalize_dns_name(
                input_event.value
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "invalid archive seed domain: "
                    f"{exc}"
                ),
            )

        successful_sources = 0
        errors: list[str] = []

        for source in self._sources:
            try:
                source.ensure_available()
                await self._run_source(
                    source,
                    input_event=input_event,
                    seed=seed,
                )
            except ArchiveSourceUnavailable as exc:
                errors.append(
                    str(exc)
                )
            except ArchiveSourceError as exc:
                errors.append(
                    str(exc)
                )
            else:
                successful_sources += 1

        if successful_sources > 0:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.SUCCEEDED
                ),
            )

        joined = (
            "; ".join(errors)
            or (
                "all archive sources produced no "
                "executable run"
            )
        )

        if (
            self._config.fail_if_all_sources_fail
        ):
            if (
                errors
                and all(
                    "executable not found"
                    in error
                    for error in errors
                )
            ):
                return WorkerExecutionResult(
                    outcome=(
                        WorkerOutcome.FAILED
                    ),
                    error=joined,
                )

            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.RETRY
                ),
                error=joined,
                retry_after_seconds=(
                    self._config.retry_after_seconds
                ),
            )

        return WorkerExecutionResult(
            outcome=(
                WorkerOutcome.SUCCEEDED
            ),
        )

    async def _run_source(
        self,
        source: ArchiveURLSource,
        *,
        input_event: Event,
        seed: str,
    ) -> None:
        seen = _BoundedSeen(
            self._config.recent_dedupe_capacity
        )

        async for finding in source.stream(
            seed
        ):
            if (
                len(finding.url)
                > self._config.max_url_length
            ):
                continue

            try:
                archive_url = normalize_archive_url(
                    finding.url
                )
            except ValueError:
                continue

            parts = urlsplit(
                archive_url
            )

            if parts.hostname is None:
                continue

            try:
                hostname = normalize_dns_name(
                    parts.hostname
                )
            except ValueError:
                continue

            if not host_within_seed(
                hostname,
                seed,
            ):
                # Provider associations, redirects or stale records may contain
                # external hosts. Preserve neither active target nor URL here;
                # a future external-reference relation can handle them without
                # silently broadening this branch.
                continue

            provider = (
                finding.provider
                or "unknown"
            )

            key = (
                archive_url,
                _source_component(
                    provider
                ),
            )

            if not seen.add(
                key
            ):
                continue

            await self._publish_finding(
                input_event=input_event,
                seed=seed,
                hostname=hostname,
                archive_url=archive_url,
                finding=finding,
                source=source,
            )

    async def _publish_finding(
        self,
        *,
        input_event: Event,
        seed: str,
        hostname: str,
        archive_url: str,
        finding: ArchiveURLFinding,
        source: ArchiveURLSource,
    ) -> None:
        provider_component = (
            _source_component(
                finding.provider
                or "unknown"
            )
        )

        source_name = (
            f"archives:"
            f"{_source_component(source.name)}:"
            f"{provider_component}"
        )[:128]

        historical_metadata = {
            "historical": True,
            "passive": True,
            "adapter": source.name,
            "provider": finding.provider,
            "archive_observed_at": (
                finding.observed_at
            ),
            "archive_status_code": (
                finding.status_code
            ),
            "archive_mime_type": (
                finding.mime_type
            ),
            "seed_domain": seed,
            **finding.metadata,
        }

        url_event = Event(
            type=EventType.URL,
            value=archive_url,
            source=source_name,
            parent_event_id=(
                input_event.event_id
            ),
            scope_state=(
                ScopeState.UNKNOWN
            ),
            confidence=(
                self._config.url_confidence
            ),
            novelty=0.75,
            depth=input_event.depth + 1,
            tags={
                "passive",
                "archive",
                "historical",
                "url",
                "hypothesis",
            },
            metadata={
                **historical_metadata,
                "requires_live_confirmation": True,
                "requires_scope_reclassification": True,
            },
        )

        url_accepted = (
            await self._publisher.publish(
                url_event
            )
        )

        child_parent_event_id = (
            url_event.event_id
            if url_accepted
            else input_event.event_id
        )

        # A historical subdomain is valuable input for DNS confirmation, but
        # it is not considered live or in-scope merely because an archive knew
        # about it.
        if hostname != seed:
            host_event = Event(
                type=EventType.DNS_NAME,
                value=hostname,
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.hostname_confidence
                ),
                novelty=0.85,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "dns-candidate",
                    "hypothesis",
                },
                metadata={
                    **historical_metadata,
                    "discovered_via": "ARCHIVE_URL",
                    "archive_url": archive_url,
                    "requires_dns_confirmation": True,
                    "requires_scope_reclassification": True,
                },
            )

            await self._publisher.publish(
                host_event
            )

        parts = urlsplit(
            archive_url
        )

        path = parts.path or "/"

        if path != "/":
            path_event = Event(
                type=EventType.URL_PATH,
                value=url_path_identity(
                    archive_url
                ),
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.derived_confidence
                ),
                novelty=0.72,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "url-path",
                    "feeds-vocabulary",
                },
                metadata={
                    **historical_metadata,
                    "url": archive_url,
                    "hostname": hostname,
                    "path": path,
                    "feeds_vocabulary": True,
                },
            )

            await self._publisher.publish(
                path_event
            )

        if is_javascript_url(
            archive_url
        ):
            javascript_event = Event(
                type=EventType.JAVASCRIPT,
                value=archive_url,
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.derived_confidence
                ),
                novelty=0.90,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "javascript",
                    "historical-js",
                    "feeds-vocabulary",
                },
                metadata={
                    **historical_metadata,
                    "requires_archive_response_fetch": True,
                    "requires_live_confirmation": True,
                    "feeds_vocabulary": True,
                },
            )

            await self._publisher.publish(
                javascript_event
            )

        if looks_like_api_endpoint(
            archive_url
        ):
            api_event = Event(
                type=EventType.API_ENDPOINT,
                value=api_endpoint_identity(
                    archive_url
                ),
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.api_endpoint_confidence
                ),
                novelty=0.92,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "api-endpoint",
                    "hypothesis",
                    "feeds-vocabulary",
                },
                metadata={
                    **historical_metadata,
                    "archive_url": archive_url,
                    "path": path,
                    "heuristic": True,
                    "requires_live_confirmation": True,
                    "feeds_vocabulary": True,
                },
            )

            await self._publisher.publish(
                api_event
            )

        artifact_kind = classify_archive_artifact(
            archive_url
        )

        if artifact_kind is not None:
            artifact_event = Event(
                type=EventType.ARTIFACT,
                value=archive_url,
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.artifact_confidence
                ),
                novelty=0.94,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "artifact-candidate",
                    f"artifact-kind:{artifact_kind}",
                    "feeds-vocabulary",
                },
                metadata={
                    **historical_metadata,
                    "artifact_kind": artifact_kind,
                    "downloaded": False,
                    "requires_archive_response_fetch": True,
                    "feeds_vocabulary": True,
                },
            )

            await self._publisher.publish(
                artifact_event
            )

        for parameter_name in query_parameter_names(
            archive_url,
            limit=(
                self._config.max_parameters_per_url
            ),
        ):
            parameter_event = Event(
                type=EventType.PARAMETER_NAME,
                value=parameter_name,
                source=source_name,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.derived_confidence
                ),
                novelty=0.80,
                depth=input_event.depth + 2,
                tags={
                    "passive",
                    "archive",
                    "historical",
                    "parameter-name",
                    "feeds-vocabulary",
                },
                metadata={
                    **historical_metadata,
                    "archive_url": archive_url,
                    "path": path,
                    "parameter_location": "query",
                    "feeds_vocabulary": True,
                },
            )

            await self._publisher.publish(
                parameter_event
            )


def archive_route_rules(
    *,
    include_dns_seeds: bool = False,
    base_priority: float = 5.5,
) -> tuple[RouteRule, ...]:
    """Route root seeds into one broad historical lookup.

    URLFinder/Waymore-style tools are most efficient when given the parent
    domain once rather than every discovered subdomain. DNS_NAME routing is
    therefore opt-in for programs whose scope consists of isolated exact hosts.
    """
    accepts = {
        EventType.ROOT_DOMAIN
    }

    if include_dns_seeds:
        accepts.add(
            EventType.DNS_NAME
        )

    return (
        RouteRule(
            rule_id=(
                "archives.discover-urls"
            ),
            accepts=frozenset(
                accepts
            ),
            worker=WORKER_NAME,
            action=(
                ACTION_DISCOVER_URLS
            ),
            reason=(
                "passively recover historical URLs, paths, JS, "
                "parameters and artifact candidates"
            ),
            base_priority=base_priority,
        ),
    )


def parse_urlfinder_line(
    line: str,
) -> tuple[
    ArchiveURLFinding,
    ...,
]:
    """Parse one URLFinder JSONL line.

    Current URLFinder JSON documents `url`, `input` and `source`. With `-cs`,
    versions may expose multiple source names; this parser accepts both forms
    so provider diversity is not collapsed.
    """
    normalized_line = line.strip()

    if not normalized_line:
        return ()

    try:
        payload = json.loads(
            normalized_line
        )
    except json.JSONDecodeError:
        # Tolerate plain URL output for older fixtures/versions, though the
        # adapter explicitly requests JSONL.
        return (
            ArchiveURLFinding(
                url=normalized_line,
                adapter="urlfinder",
                provider=None,
                metadata={
                    "output_format": "plain",
                },
            ),
        )

    if isinstance(
        payload,
        str,
    ):
        return (
            ArchiveURLFinding(
                url=payload,
                adapter="urlfinder",
                provider=None,
                metadata={
                    "output_format": "json-string",
                },
            ),
        )

    if not isinstance(
        payload,
        dict,
    ):
        return ()

    raw_url = _first_text(
        payload,
        (
            "url",
            "value",
        ),
    )

    if raw_url is None:
        return ()

    providers = (
        _provider_names(
            payload
        )
    )

    status_code = _parse_status_code(
        payload.get(
            "status_code"
        )
        if "status_code" in payload
        else payload.get("status")
    )

    mime_type = _first_text(
        payload,
        (
            "mime",
            "mime_type",
            "content_type",
        ),
    )

    observed_at = _first_text(
        payload,
        (
            "timestamp",
            "date",
            "datetime",
        ),
    )

    known = {
        "url",
        "value",
        "input",
        "source",
        "sources",
        "providers",
        "provider",
        "status",
        "status_code",
        "mime",
        "mime_type",
        "content_type",
        "timestamp",
        "date",
        "datetime",
    }

    metadata = {
        "output_format": "jsonl",
        **{
            key: value
            for key, value
            in payload.items()
            if key not in known
        },
    }

    tool_input = _first_text(
        payload,
        (
            "input",
        ),
    )

    if tool_input is not None:
        metadata["tool_input"] = (
            tool_input
        )

    if not providers:
        return (
            ArchiveURLFinding(
                url=raw_url,
                adapter="urlfinder",
                provider=None,
                observed_at=observed_at,
                status_code=status_code,
                mime_type=mime_type,
                metadata=metadata,
            ),
        )

    return tuple(
        ArchiveURLFinding(
            url=raw_url,
            adapter="urlfinder",
            provider=provider,
            observed_at=observed_at,
            status_code=status_code,
            mime_type=mime_type,
            metadata=metadata,
        )
        for provider in providers
    )


def normalize_archive_url(
    value: str,
) -> str:
    """Canonicalize an HTTP(S) historical URL without contacting it."""
    raw = value.strip()

    if not raw:
        raise ValueError(
            "archive URL must not be blank"
        )

    parts = urlsplit(
        raw
    )

    scheme = parts.scheme.lower()

    if scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "archive URL scheme must be http or https"
        )

    if (
        parts.username is not None
        or parts.password is not None
    ):
        raise ValueError(
            "userinfo is not allowed in archive URLs"
        )

    if parts.hostname is None:
        raise ValueError(
            "archive URL hostname is required"
        )

    hostname = normalize_dns_name(
        parts.hostname
    )

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(
            "archive URL has invalid port"
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

    path = parts.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parts.query,
            "",
        )
    )


def host_within_seed(
    hostname: str,
    seed: str,
) -> bool:
    """Accept only the seed apex or strict dot-boundary descendants."""
    host = normalize_dns_name(
        hostname
    )
    root = normalize_dns_name(
        seed
    )

    return (
        host == root
        or host.endswith(
            "." + root
        )
    )


def url_path_identity(
    url: str,
) -> str:
    """Contextual path identity avoids collapsing `/login` across hosts."""
    normalized = normalize_archive_url(
        url
    )
    parts = urlsplit(
        normalized
    )

    if parts.hostname is None:
        raise ValueError(
            "URL path identity requires hostname"
        )

    authority = parts.hostname

    if parts.port is not None:
        authority = (
            f"{authority}:{parts.port}"
        )

    return (
        authority
        + (parts.path or "/")
    )


def api_endpoint_identity(
    url: str,
) -> str:
    """Endpoint identity excludes query values but preserves host/path."""
    normalized = normalize_archive_url(
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


def looks_like_api_endpoint(
    url: str,
) -> bool:
    """Conservative historical API-path heuristic.

    Besides a literal `/api/` segment, target applications commonly use names
    such as `internal-api`, `partner_api` and `api-gateway`. Treat `api` as a
    separator-bounded token inside a path segment rather than requiring the
    whole segment to equal `api`.
    """
    parts = urlsplit(
        normalize_archive_url(
            url
        )
    )

    path = (
        parts.path
        or "/"
    )

    lower = path.lower()

    if _API_PATH_RE.search(
        lower
    ):
        return True

    if _API_VERSION_RE.search(
        lower
    ):
        return True

    for segment in lower.split("/"):
        if not segment:
            continue

        tokens = {
            token
            for token in re.split(
                r"[-_.]+",
                segment,
            )
            if token
        }

        if "api" in tokens:
            return True

    return lower.endswith(
        (
            "/graphql",
            "/graphiql",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
        )
    )


def is_javascript_url(
    url: str,
) -> bool:
    path = urlsplit(
        normalize_archive_url(
            url
        )
    ).path.lower()

    return path.endswith(
        _JAVASCRIPT_SUFFIXES
    )


def classify_archive_artifact(
    url: str,
) -> str | None:
    """Identify high-signal historical files without downloading them."""
    path = urlsplit(
        normalize_archive_url(
            url
        )
    ).path

    lower = path.lower()

    if lower.endswith(
        _SOURCE_MAP_SUFFIXES
    ):
        return (
            ArchiveArtifactKind.SOURCE_MAP
        )

    if lower.endswith(
        _BUILD_ARTIFACT_SUFFIXES
    ):
        return (
            ArchiveArtifactKind.BUILD_ARCHIVE
        )

    if (
        lower.endswith(
            _BACKUP_SUFFIXES
        )
        or lower.endswith("~")
    ):
        return (
            ArchiveArtifactKind.BACKUP_FILE
        )

    basename = (
        Path(lower).name
    )

    if (
        basename in _CONFIG_BASENAMES
        or basename.startswith(
            ".env."
        )
    ):
        return (
            ArchiveArtifactKind.CONFIG_FILE
        )

    return None


def query_parameter_names(
    url: str,
    *,
    limit: int,
) -> tuple[str, ...]:
    """Extract bounded unique query parameter names, never values."""
    if limit <= 0:
        return ()

    parts = urlsplit(
        normalize_archive_url(
            url
        )
    )

    if not parts.query:
        return ()

    try:
        pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=max(
                limit * 4,
                32,
            ),
        )
    except ValueError:
        return ()

    names: list[str] = []
    seen: set[str] = set()

    for name, _value in pairs:
        normalized = (
            name.strip()
        )

        if (
            not normalized
            or normalized in seen
        ):
            continue

        seen.add(
            normalized
        )
        names.append(
            normalized
        )

        if (
            len(names)
            >= limit
        ):
            break

    return tuple(
        names
    )


def _provider_names(
    payload: dict[str, Any],
) -> tuple[str, ...]:
    result: set[str] = set()

    for key in (
        "sources",
        "source",
        "providers",
        "provider",
    ):
        raw = payload.get(
            key
        )

        if isinstance(
            raw,
            str,
        ):
            result.update(
                item.strip()
                for item in raw.split(",")
                if item.strip()
            )

        elif isinstance(
            raw,
            (list, tuple, set),
        ):
            result.update(
                str(item).strip()
                for item in raw
                if str(item).strip()
            )

    return tuple(
        sorted(
            result
        )
    )


def _first_text(
    payload: dict[str, Any],
    keys: Iterable[str],
) -> str | None:
    for key in keys:
        value = payload.get(
            key
        )

        if value is None:
            continue

        normalized = str(
            value
        ).strip()

        if normalized:
            return normalized

    return None


def _parse_status_code(
    value: Any,
) -> int | None:
    try:
        status = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if (
        100
        <= status
        <= 599
    ):
        return status

    return None


def _source_component(
    value: str,
) -> str:
    normalized = value.strip().lower()

    normalized = (
        _SOURCE_COMPONENT_RE.sub(
            "-",
            normalized,
        ).strip("-")
    )

    return normalized or "unknown"


def _resolve_executable(
    binary: str,
) -> str | None:
    candidate = Path(
        binary
    ).expanduser()

    if (
        candidate.parent != Path(".")
        or candidate.is_absolute()
    ):
        if (
            candidate.exists()
            and os.access(
                candidate,
                os.X_OK,
            )
        ):
            return str(
                candidate.resolve()
            )

        return None

    return shutil.which(
        binary
    )


async def _drain_stderr(
    stream: asyncio.StreamReader,
    tail: deque[str],
) -> None:
    while True:
        raw = await stream.readline()

        if not raw:
            return

        line = raw.decode(
            "utf-8",
            errors="replace",
        ).strip()

        if line:
            tail.append(
                line
            )


async def _terminate_process(
    process: asyncio.subprocess.Process,
) -> None:
    if process.returncode is not None:
        return

    process.terminate()

    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=2.0,
        )
    except TimeoutError:
        process.kill()
        await process.wait()
