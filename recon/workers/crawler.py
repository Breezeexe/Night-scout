"""Bounded live web crawling for Night Scout using ProjectDiscovery Katana.

This worker consumes a *confirmed root URL* produced by workers/http.py and
crawls only that exact FQDN. It emits current URL/path/API/JavaScript/parameter
observations without storing response bodies.

Why the rate-limit integration is different
-------------------------------------------
Katana is an opaque multi-request subprocess. Unlike `http.py`, one process can
make many target requests internally, so consuming one shared token before
launch would not account for the real traffic.

Night Scout therefore uses an exclusive-host lease:

1. Resolve the shared RateLimitPlan for the target host.
2. Require both an RPS ceiling and a max_concurrency rule.
3. Acquire *all* concurrency slots of the strictest matching rule for the host.
4. Configure Katana itself to the full allowed host RPS.
5. Release the exclusive lease when Katana exits.

Any other active worker governed by the same shared rule cannot acquire a host
slot while the crawl is running. This keeps the opaque subprocess inside the
shared target-node request envelope. If the required rate controls are absent,
the crawler fails closed.

Crawler safety defaults
-----------------------
- exact FQDN scope (`-fs fqdn`);
- redirects disabled (`-dr`);
- no headless browser;
- no automatic form fill;
- form *extraction* only;
- no authenticated headers/cookies;
- no TLS impersonation;
- no secrets validation;
- no request/response/body storage;
- one input at a time;
- bounded depth, duration, page count and response-read size;
- JS endpoint parsing is allowed, but only within the same FQDN;
- robots.txt/sitemap.xml discovery is optionally enabled.

Every newly discovered URL is emitted with `scope=UNKNOWN` even though Katana
is locally constrained to one host. Scope may contain path-level exclusions,
so the normal ScopeGate must classify every new active follow-up separately.

Typical flow
------------
confirmed URL
    https://api.example.com/
        |
        | bounded Katana crawl
        v
URL
    https://api.example.com/internal-api/v3/orders?id=123
        |
        +--> URL_PATH
        +--> API_ENDPOINT
        +--> PARAMETER_NAME id
        +--> JAVASCRIPT (for .js/.mjs/.cjs)
        +--> HTTP_RESPONSE metadata for actually fetched pages

Future `javascript.py`, `parameters.py`, `content.py` and `vocabulary.py`
consume these normalized observations instead of re-parsing Katana output.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimiter,
    RateLimitOutcome,
    RateLimitPlan,
)
from recon.workers.passive_domains import normalize_dns_name

WORKER_NAME = "crawler"
ACTION_CRAWL = "crawl"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_API_TOKEN_SPLIT_RE = re.compile(r"[-_.]+")
_API_VERSION_RE = re.compile(
    r"/(?:api|rest)(?:/[^/?#]+)*/v[0-9]+(?:/|$)",
    re.IGNORECASE,
)

_JAVASCRIPT_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
)


class CrawlResult(BaseModel):
    """Normalized one-line Katana JSONL observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    method: str = "GET"

    status_code: int | None = Field(default=None, ge=100, le=599)

    content_type: str | None = None
    content_length: int | None = Field(default=None, ge=0)
    location: str | None = None
    webserver: str | None = None

    source: str | None = None
    tag: str | None = None
    attribute: str | None = None

    form_fields: tuple[str, ...] = ()

    fetched: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def normalize_url_value(cls, value: str) -> str:
        return normalize_crawl_url(value)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        return normalized or "GET"

    @field_validator(
        "content_type",
        "location",
        "webserver",
        "source",
        "tag",
        "attribute",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("form_fields")
    @classmethod
    def normalize_form_fields(
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


class InputEventProvider(Protocol):
    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(
        self,
        event: Event,
    ) -> bool:
        ...


class CrawlBackend(Protocol):
    """One bounded exact-host crawl backend."""

    name: str

    def ensure_available(self) -> None:
        ...

    def crawl(
        self,
        url: str,
        *,
        pacing: "KatanaPacing",
    ) -> AsyncIterator[CrawlResult]:
        ...


class KatanaPacing(BaseModel):
    """CLI pacing derived from a shared exclusive RateLimitPlan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_rps: int | None = Field(default=None, ge=1)
    request_delay_seconds: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def exactly_one_mode(self) -> "KatanaPacing":
        configured = sum(
            value is not None
            for value in (
                self.host_rps,
                self.request_delay_seconds,
            )
        )

        if configured != 1:
            raise ValueError(
                "Katana pacing requires exactly one of host_rps or "
                "request_delay_seconds"
            )

        return self


class KatanaConfig(BaseModel):
    """ProjectDiscovery Katana subprocess configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "katana"

    depth: int = Field(default=3, ge=1, le=10)
    crawl_duration_seconds: int = Field(default=60, ge=1, le=3600)
    max_domain_pages: int = Field(default=250, ge=1, le=100_000)

    timeout_seconds: int = Field(default=10, ge=1, le=120)

    max_response_size_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=4096,
        le=64 * 1024 * 1024,
    )

    process_timeout_seconds: float = Field(default=90.0, gt=0.0)

    js_crawl: bool = True
    form_extraction: bool = True
    ignore_query_param_values: bool = True
    filter_similar_urls: bool = True

    known_files: tuple[str, ...] = (
        "robotstxt",
        "sitemapxml",
    )

    user_agent: str = (
        "NightScout/0.1 authorized-security-research"
    )

    stderr_tail_lines: int = Field(default=120, ge=1, le=2000)
    stream_limit_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=65536,
    )

    extra_args: tuple[str, ...] = ()

    @field_validator("binary", "user_agent")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized

    @field_validator("known_files")
    @classmethod
    def normalize_known_files(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        allowed = {
            "robotstxt",
            "sitemapxml",
        }

        result: list[str] = []

        for value in values:
            normalized = value.strip().lower()

            if not normalized:
                continue

            if normalized not in allowed:
                raise ValueError(
                    "known_files supports only robotstxt/sitemapxml "
                    "in the initial Night Scout crawler"
                )

            if normalized not in result:
                result.append(normalized)

        return tuple(result)

    @model_validator(mode="after")
    def known_files_require_depth_three(self) -> "KatanaConfig":
        if self.known_files and self.depth < 3:
            raise ValueError(
                "Katana known_files requires depth >= 3"
            )
        return self

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
            # Input ownership.
            "-u",
            "-list",

            # Crawl expansion/bounds.
            "-d",
            "-depth",
            "-ct",
            "-crawl-duration",
            "-mdp",
            "-max-domain-pages",
            "-kf",
            "-known-files",
            "-jc",
            "-js-crawl",
            "-jsl",
            "-jsluice",
            "-mrs",
            "-max-response-size",
            "-timeout",
            "-retry",
            "-s",
            "-strategy",
            "-iqp",
            "-ignore-query-params",
            "-fsu",
            "-filter-similar",
            "-fst",
            "-filter-similar-threshold",
            "-dr",
            "-disable-redirects",

            # Forms/headless/browser state.
            "-aff",
            "-automatic-form-fill",
            "-fx",
            "-form-extraction",
            "-hl",
            "-headless",
            "-sc",
            "-system-chrome",
            "-sb",
            "-show-browser",
            "-ho",
            "-headless-options",
            "-nos",
            "-no-sandbox",
            "-cdd",
            "-chrome-data-dir",
            "-scp",
            "-system-chrome-path",
            "-noi",
            "-no-incognito",
            "-cwu",
            "-chrome-ws-url",
            "-xhr",
            "-xhr-extraction",
            "-csp",
            "-captcha-solver-provider",
            "-csk",
            "-captcha-solver-key",

            # Scope must remain exact FQDN.
            "-cs",
            "-crawl-scope",
            "-cos",
            "-crawl-out-scope",
            "-fs",
            "-field-scope",
            "-ns",
            "-no-scope",
            "-do",
            "-display-out-scope",

            # Request identity/auth/TLS behavior.
            "-r",
            "-resolvers",
            "-H",
            "-headers",
            "-proxy",
            "-tlsi",
            "-tls-impersonate",
            "-config",
            "-fc",
            "-form-config",
            "-flc",
            "-field-config",

            # Rate/concurrency belongs to the shared lease.
            "-c",
            "-concurrency",
            "-p",
            "-parallelism",
            "-rd",
            "-delay",
            "-rl",
            "-rate-limit",
            "-rlm",
            "-rate-limit-minute",
            "-hrl",
            "-host-rate-limit",
            "-hrlm",
            "-host-rate-limit-minute",

            # Knowledge-base secret validation or broader extraction.
            "-kb",
            "-knowledge-base",
            "-kb-secrets",
            "-kb-validate-secrets",
            "-kb-endpoints",

            # Output/body storage ownership.
            "-o",
            "-output",
            "-output-template",
            "-sr",
            "-store-response",
            "-srd",
            "-store-response-dir",
            "-or",
            "-omit-raw",
            "-ob",
            "-omit-body",
            "-j",
            "-jsonl",
            "-eof",
            "-exclude-output-fields",
            "-v",
            "-verbose",
            "-debug",

            # Automatic updates.
            "-up",
            "-update",
        }

        if any(
            value in forbidden
            for value in normalized
        ):
            raise ValueError(
                "katana extra_args cannot override input, scope, crawl "
                "bounds, authentication/browser behavior, shared rate "
                "controls, or structured output"
            )

        return normalized


class CrawlerWorkerConfig(BaseModel):
    """Event confidence and exclusive shared-rate behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url_confidence: float = Field(default=0.98, ge=0.0, le=1.0)
    path_confidence: float = Field(default=0.96, ge=0.0, le=1.0)
    api_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    javascript_confidence: float = Field(default=0.96, ge=0.0, le=1.0)
    parameter_confidence: float = Field(default=0.92, ge=0.0, le=1.0)
    response_confidence: float = Field(default=0.97, ge=0.0, le=1.0)

    retry_after_seconds: float = Field(default=5.0, ge=0.0)

    # Lease outlives the configured process timeout so a healthy crawl never
    # releases its exclusivity while Katana is still running.
    lease_margin_seconds: float = Field(default=30.0, ge=1.0)

    max_parameters_per_url: int = Field(default=64, ge=0, le=1000)
    max_form_fields_per_result: int = Field(default=128, ge=0, le=2000)


class CrawlBackendError(RuntimeError):
    """Katana/backend failure."""


class CrawlBackendUnavailable(CrawlBackendError):
    """Configured Katana binary is unavailable."""


class CrawlBackendTimeout(CrawlBackendError):
    """Katana exceeded the outer process timeout."""


class KatanaBackend:
    """Exact-FQDN, bounded ProjectDiscovery Katana adapter."""

    name = "katana"

    def __init__(
        self,
        config: KatanaConfig | None = None,
    ) -> None:
        self.config = config or KatanaConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise CrawlBackendUnavailable(
                f"katana executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        pacing: KatanaPacing,
    ) -> tuple[str, ...]:
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args: list[str] = [
            binary,

            "-j",
            "-silent",
            "-nc",
            "-duc",

            # Exact-host active boundary.
            "-fs",
            "fqdn",
            "-dr",

            # Bounded crawler behavior.
            "-d",
            str(self.config.depth),
            "-ct",
            f"{self.config.crawl_duration_seconds}s",
            "-mdp",
            str(self.config.max_domain_pages),
            "-mrs",
            str(self.config.max_response_size_bytes),
            "-timeout",
            str(self.config.timeout_seconds),
            "-retry",
            "0",

            # One input and one fetcher; host RPS is separately constrained.
            "-c",
            "1",
            "-p",
            "1",

            # Do not emit/store request/response raw material or bodies.
            "-or",
            "-ob",

            # Explicit, non-authenticated identity header.
            "-H",
            f"User-Agent: {self.config.user_agent}",
        ]

        if self.config.js_crawl:
            args.append("-jc")

        if self.config.form_extraction:
            args.append("-fx")

        if self.config.ignore_query_param_values:
            args.append("-iqp")

        if self.config.filter_similar_urls:
            args.append("-fsu")

        if self.config.known_files:
            args.extend(
                (
                    "-kf",
                    ",".join(self.config.known_files),
                )
            )

        if pacing.host_rps is not None:
            args.extend(
                (
                    "-hrl",
                    str(pacing.host_rps),
                )
            )
        else:
            args.extend(
                (
                    "-rd",
                    str(pacing.request_delay_seconds),
                )
            )

        args.extend(self.config.extra_args)

        return tuple(args)

    async def crawl(
        self,
        url: str,
        *,
        pacing: KatanaPacing,
    ) -> AsyncIterator[CrawlResult]:
        normalized_url = normalize_crawl_url(url)
        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(pacing=pacing),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=self.config.stream_limit_bytes,
            env=os.environ.copy(),
        )

        if (
            process.stdin is None
            or process.stdout is None
            or process.stderr is None
        ):
            await _terminate_process(process)
            raise CrawlBackendError(
                "katana subprocess pipes were not created"
            )

        stderr_tail: deque[str] = deque(
            maxlen=self.config.stderr_tail_lines
        )

        stderr_task = asyncio.create_task(
            _drain_stderr(
                process.stderr,
                stderr_tail,
            )
        )

        try:
            process.stdin.write(
                (normalized_url + "\n").encode("utf-8")
            )
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            try:
                async with asyncio.timeout(
                    self.config.process_timeout_seconds
                ):
                    while True:
                        raw_line = await process.stdout.readline()

                        if not raw_line:
                            break

                        line = raw_line.decode(
                            "utf-8",
                            errors="replace",
                        ).strip()

                        if not line:
                            continue

                        result = parse_katana_line(line)

                        if result is not None:
                            yield result

                    returncode = await process.wait()

            except TimeoutError as exc:
                await _terminate_process(process)

                raise CrawlBackendTimeout(
                    "katana exceeded outer process timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(stderr_tail)

                raise CrawlBackendError(
                    "katana exited unsuccessfully "
                    f"(returncode={returncode})"
                    + (
                        f"; stderr_tail={detail}"
                        if detail
                        else ""
                    )
                )

        finally:
            if process.returncode is None:
                await _terminate_process(process)

            try:
                await stderr_task
            except asyncio.CancelledError:
                raise
            except Exception:
                pass


class CrawlerWorker:
    """Bounded live crawl worker with exclusive shared-rate lease."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        backend: CrawlBackend | None = None,
        config: CrawlerWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._backend = backend or KatanaBackend()
        self._config = config or CrawlerWorkerConfig()

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "crawler worker may only execute claimed RUNNING tasks, "
                    f"got {task.status.value}"
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

        if task.action != ACTION_CRAWL:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported crawler action: {task.action}",
            )

        input_event = await self._events.get_event(
            task.input_event_id
        )

        if input_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"input event not found: {task.input_event_id}",
            )

        try:
            seed_url = crawl_seed_from_event(input_event)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        seed_parts = urlsplit(seed_url)

        if seed_parts.hostname is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error="crawl seed URL has no hostname",
            )

        hostname = normalize_dns_name(seed_parts.hostname)

        try:
            self._backend.ensure_available()
        except CrawlBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        context = RateLimitContext(
            resource_keys=frozenset(
                {f"host:{hostname}"}
            )
        )

        plan = self._rate_limiter.plan(
            task,
            context=context,
        )

        rate_error = validate_opaque_crawler_plan(plan)

        if rate_error is not None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=rate_error,
            )

        assert plan.max_concurrency_hint is not None
        assert plan.aggregate_rps_ceiling is not None

        pacing = katana_pacing_from_plan(plan)

        # Saturate the strictest matching shared concurrency rule. Other
        # active workers governed by that rule cannot touch this host until the
        # crawl exits and the lease is released.
        decision = await self._rate_limiter.acquire(
            task,
            context=context,
            demand=RateLimitDemand(
                requests=0.0,
                concurrency=plan.max_concurrency_hint,
            ),
            lease_for=timedelta(
                seconds=(
                    _backend_process_timeout(self._backend)
                    + self._config.lease_margin_seconds
                )
            ),
        )

        if decision.outcome is RateLimitOutcome.DEFER:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=(
                    decision.reason
                    or "crawler could not acquire exclusive host lease"
                ),
                retry_after_seconds=(
                    decision.retry_after_seconds
                    if decision.retry_after_seconds is not None
                    else self._config.retry_after_seconds
                ),
            )

        if decision.outcome is RateLimitOutcome.DENY:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    decision.reason
                    or "crawler shared rate policy denied execution"
                ),
            )

        lease_id = (
            decision.lease.lease_id
            if decision.lease is not None
            else None
        )

        try:
            async for result in self._backend.crawl(
                seed_url,
                pacing=pacing,
            ):
                if not result_within_seed_host(
                    result,
                    seed_url=seed_url,
                ):
                    continue

                await self._publish_result(
                    input_event=input_event,
                    result=result,
                )

        except CrawlBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.retry_after_seconds,
            )
        except CrawlBackendError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.retry_after_seconds,
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(lease_id)

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _publish_result(
        self,
        *,
        input_event: Event,
        result: CrawlResult,
    ) -> None:
        source_name = (
            f"crawler:{_source_component(self._backend.name)}"
        )

        common_metadata = {
            "live_crawl": True,
            "crawler": self._backend.name,
            "crawl_source": result.source,
            "crawl_tag": result.tag,
            "crawl_attribute": result.attribute,
            "fetched": result.fetched,
        }

        url_event = Event(
            type=EventType.URL,
            value=result.url,
            source=source_name,
            parent_event_id=input_event.event_id,
            scope_state=ScopeState.UNKNOWN,
            confidence=self._config.url_confidence,
            novelty=0.65,
            depth=input_event.depth + 1,
            tags={
                "crawler",
                "live",
                "url",
                (
                    "fetched"
                    if result.fetched
                    else "discovered"
                ),
            },
            metadata={
                **common_metadata,
                "requires_scope_reclassification": True,
                **result.metadata,
            },
        )

        url_accepted = await self._publisher.publish(
            url_event
        )

        child_parent_event_id = (
            url_event.event_id
            if url_accepted
            else input_event.event_id
        )

        parts = urlsplit(result.url)
        path = parts.path or "/"

        if path != "/":
            await self._publisher.publish(
                Event(
                    type=EventType.URL_PATH,
                    value=url_path_identity(result.url),
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.path_confidence,
                    novelty=0.60,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "url-path",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common_metadata,
                        "url": result.url,
                        "path": path,
                        "feeds_vocabulary": True,
                    },
                )
            )

        if looks_like_api_endpoint(result.url):
            await self._publisher.publish(
                Event(
                    type=EventType.API_ENDPOINT,
                    value=api_endpoint_identity(result.url),
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.api_confidence,
                    novelty=0.84,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "api-endpoint",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common_metadata,
                        "heuristic": True,
                        "path": path,
                        "requires_scope_reclassification": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        if is_javascript_url(result.url):
            await self._publisher.publish(
                Event(
                    type=EventType.JAVASCRIPT,
                    value=result.url,
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.javascript_confidence,
                    novelty=0.82,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "javascript",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common_metadata,
                        "requires_static_analysis": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for parameter_name in query_parameter_names(
            result.url,
            limit=self._config.max_parameters_per_url,
        ):
            await self._publisher.publish(
                Event(
                    type=EventType.PARAMETER_NAME,
                    value=parameter_name,
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.parameter_confidence,
                    novelty=0.72,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "parameter-name",
                        "query",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common_metadata,
                        "url": result.url,
                        "parameter_location": "query",
                        "feeds_vocabulary": True,
                    },
                )
            )

        for form_field in result.form_fields[
            : self._config.max_form_fields_per_result
        ]:
            await self._publisher.publish(
                Event(
                    type=EventType.PARAMETER_NAME,
                    value=form_field,
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.parameter_confidence,
                    novelty=0.78,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "parameter-name",
                        "form-field",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common_metadata,
                        "url": result.url,
                        "parameter_location": "form",
                        "form_submitted": False,
                        "feeds_vocabulary": True,
                    },
                )
            )

        if result.fetched and result.status_code is not None:
            await self._publisher.publish(
                Event(
                    type=EventType.HTTP_RESPONSE,
                    value=(
                        f"{result.method} {result.url} -> "
                        f"{result.status_code}"
                    ),
                    source=source_name,
                    parent_event_id=child_parent_event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.response_confidence,
                    novelty=0.58,
                    depth=input_event.depth + 2,
                    tags={
                        "crawler",
                        "live",
                        "http-response",
                        f"status:{result.status_code}",
                    },
                    metadata={
                        **common_metadata,
                        "url": result.url,
                        "method": result.method,
                        "status_code": result.status_code,
                        "content_type": result.content_type,
                        "content_length": result.content_length,
                        "location": result.location,
                        "webserver": result.webserver,
                        "response_body_stored": False,
                        "raw_request_stored": False,
                        "raw_response_stored": False,
                    },
                )
            )


def crawler_route_rules(
    *,
    base_priority: float = 7.5,
) -> tuple[RouteRule, ...]:
    """Route only confirmed root URLs emitted by the HTTP probe worker."""

    return (
        RouteRule(
            rule_id="crawler.crawl.confirmed-root-url",
            accepts=frozenset({EventType.URL}),
            worker=WORKER_NAME,
            action=ACTION_CRAWL,
            reason=(
                "bounded exact-host crawl of a confirmed root HTTP URL"
            ),
            base_priority=base_priority,
            required_tags=frozenset({"confirmed"}),
            excluded_tags=frozenset({"hypothesis", "archive"}),
            predicate=_root_http_probe_url,
        ),
    )


def _root_http_probe_url(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    if event.type is not EventType.URL:
        return False

    return bool(
        event.metadata.get("root_probe")
    )


def crawl_seed_from_event(
    event: Event,
) -> str:
    """Accept only confirmed live root URL observations."""

    if event.type is not EventType.URL:
        raise ValueError(
            "crawler.crawl requires URL input"
        )

    if (
        "confirmed" not in event.tags
        or "hypothesis" in event.tags
        or "archive" in event.tags
    ):
        raise ValueError(
            "crawler.crawl requires a confirmed non-historical URL"
        )

    if not event.metadata.get("root_probe"):
        raise ValueError(
            "crawler.crawl requires a root_probe URL from workers/http.py"
        )

    normalized = normalize_crawl_url(
        event.value
    )

    parts = urlsplit(normalized)

    if (parts.path or "/") != "/" or parts.query:
        raise ValueError(
            "crawler seed must be the confirmed service root URL"
        )

    return normalized


def validate_opaque_crawler_plan(
    plan: RateLimitPlan,
) -> str | None:
    """Fail closed unless a multi-request CLI can be coordinated safely."""

    if not plan.matched:
        return (
            "crawler has no matching shared rate-limit rule; "
            "opaque multi-request subprocess fails closed"
        )

    if (
        plan.aggregate_rps_ceiling is None
        or plan.aggregate_rps_ceiling <= 0.0
    ):
        return (
            "crawler requires an explicit requests_per_second ceiling "
            "in its matching shared rate-limit rule"
        )

    if (
        plan.max_concurrency_hint is None
        or plan.max_concurrency_hint < 1
    ):
        return (
            "crawler requires max_concurrency in its matching shared "
            "rate-limit rule so it can acquire an exclusive host lease"
        )

    return None


def katana_pacing_from_plan(
    plan: RateLimitPlan,
) -> KatanaPacing:
    """Convert full exclusive-host RPS into conservative Katana pacing."""

    if plan.aggregate_rps_ceiling is None:
        raise ValueError(
            "rate plan has no aggregate RPS ceiling"
        )

    rps = plan.aggregate_rps_ceiling

    if rps >= 1.0:
        return KatanaPacing(
            host_rps=max(
                1,
                math.floor(rps),
            )
        )

    # Katana delay is an integer number of seconds. ceil(1/rps) is always
    # equal to or slower than the configured fractional-RPS ceiling.
    return KatanaPacing(
        request_delay_seconds=math.ceil(
            1.0 / rps
        )
    )


def normalize_crawl_url(
    value: str,
) -> str:
    """Canonicalize an HTTP(S) URL without fetching it."""

    raw = value.strip()

    if not raw:
        raise ValueError(
            "crawl URL must not be blank"
        )

    parts = urlsplit(raw)

    scheme = parts.scheme.lower()

    if scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "crawl URL scheme must be http or https"
        )

    if (
        parts.username is not None
        or parts.password is not None
    ):
        raise ValueError(
            "userinfo is not allowed in crawl URLs"
        )

    if parts.hostname is None:
        raise ValueError(
            "crawl URL hostname is required"
        )

    hostname = normalize_dns_name(
        parts.hostname
    )

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(
            "crawl URL contains invalid port"
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


def result_within_seed_host(
    result: CrawlResult,
    *,
    seed_url: str,
) -> bool:
    """Local defense-in-depth for Katana exact-FQDN scope."""

    seed = urlsplit(
        normalize_crawl_url(seed_url)
    )
    candidate = urlsplit(
        result.url
    )

    if (
        seed.hostname is None
        or candidate.hostname is None
    ):
        return False

    return (
        normalize_dns_name(seed.hostname)
        == normalize_dns_name(candidate.hostname)
    )


def parse_katana_line(
    line: str,
) -> CrawlResult | None:
    """Parse one Katana JSONL result across tolerant field shapes.

    Katana JSON commonly provides nested `request` / `response` objects plus
    source/tag/attribute correlation fields. Form extraction may add nested
    form/input structures; only field names are retained.
    """

    normalized_line = line.strip()

    if not normalized_line:
        return None

    try:
        payload = json.loads(
            normalized_line
        )
    except json.JSONDecodeError:
        return None

    if not isinstance(
        payload,
        dict,
    ):
        return None

    request = payload.get(
        "request"
    )

    if not isinstance(
        request,
        dict,
    ):
        request = {}

    response = payload.get(
        "response"
    )

    if not isinstance(
        response,
        dict,
    ):
        response = {}

    raw_url = _first_text(
        request,
        (
            "endpoint",
            "url",
        ),
    ) or _first_text(
        payload,
        (
            "url",
            "endpoint",
        ),
    )

    if raw_url is None:
        return None

    try:
        url = normalize_crawl_url(
            raw_url
        )
    except ValueError:
        return None

    status_code = _parse_status_code(
        response.get(
            "status_code"
        )
        if "status_code" in response
        else payload.get("status_code")
    )

    headers = response.get(
        "headers"
    )

    if not isinstance(
        headers,
        dict,
    ):
        headers = {}

    content_type = _first_text(
        headers,
        (
            "content_type",
            "content-type",
        ),
    ) or _first_text(
        response,
        (
            "content_type",
        ),
    )

    location = _first_text(
        headers,
        (
            "location",
        ),
    ) or _first_text(
        response,
        (
            "location",
        ),
    )

    webserver = _first_text(
        headers,
        (
            "server",
        ),
    ) or _first_text(
        response,
        (
            "server",
            "webserver",
        ),
    )

    content_length = _parse_nonnegative_int(
        response.get(
            "content_length"
        )
        if "content_length" in response
        else headers.get(
            "content_length"
        )
    )

    form_fields = extract_form_field_names(
        payload
    )

    known = {
        "timestamp",
        "request",
        "response",
        "source",
        "tag",
        "attribute",
        "url",
        "endpoint",
        "status_code",
        "form",
        "forms",
    }

    metadata = {
        key: value
        for key, value in payload.items()
        if key not in known
        and key not in {
            # Never persist accidental raw/body aliases even if a Katana
            # version emits them despite -or/-ob.
            "body",
            "raw",
        }
    }

    return CrawlResult(
        url=url,
        method=(
            _first_text(
                request,
                ("method",),
            )
            or "GET"
        ),
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        location=location,
        webserver=webserver,
        source=_first_text(
            payload,
            ("source",),
        ),
        tag=_first_text(
            payload,
            ("tag",),
        ),
        attribute=_first_text(
            payload,
            ("attribute",),
        ),
        form_fields=form_fields,
        fetched=(
            status_code is not None
        ),
        metadata=metadata,
    )


def extract_form_field_names(
    payload: dict[str, Any],
) -> tuple[str, ...]:
    """Recursively collect form/input field *names*, never values."""

    names: set[str] = set()

    interesting_keys = {
        "name",
        "field",
        "field_name",
        "input_name",
    }

    def visit(
        value: Any,
        *,
        parent_key: str | None = None,
    ) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized_key = key.strip().lower()

                if (
                    normalized_key in interesting_keys
                    and isinstance(nested, str)
                    and nested.strip()
                ):
                    names.add(
                        nested.strip()
                    )

                # Restrict recursion to form-like structures so unrelated
                # response metadata named "name" does not become a parameter.
                if (
                    parent_key in {
                        "form",
                        "forms",
                        "input",
                        "inputs",
                        "textarea",
                        "select",
                        "fields",
                    }
                    or normalized_key in {
                        "form",
                        "forms",
                        "input",
                        "inputs",
                        "textarea",
                        "select",
                        "fields",
                    }
                ):
                    visit(
                        nested,
                        parent_key=normalized_key,
                    )

        elif isinstance(value, list):
            for nested in value:
                visit(
                    nested,
                    parent_key=parent_key,
                )

    for key in (
        "form",
        "forms",
    ):
        if key in payload:
            visit(
                payload[key],
                parent_key=key,
            )

    return tuple(
        sorted(
            names
        )
    )


def url_path_identity(
    url: str,
) -> str:
    """Host-aware URL path identity."""

    normalized = normalize_crawl_url(
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
    """API endpoint identity strips query values/fragments."""

    normalized = normalize_crawl_url(
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
    """Conservative API-path heuristic shared conceptually with archives.py."""

    path = urlsplit(
        normalize_crawl_url(
            url
        )
    ).path.lower()

    if _API_VERSION_RE.search(
        path
    ):
        return True

    for segment in path.split("/"):
        if not segment:
            continue

        tokens = {
            token
            for token in _API_TOKEN_SPLIT_RE.split(
                segment
            )
            if token
        }

        if (
            "api" in tokens
            or "rest" in tokens
            or "graphql" in tokens
            or "graphiql" in tokens
            or "swagger" in tokens
            or "openapi" in tokens
        ):
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


def is_javascript_url(
    url: str,
) -> bool:
    path = urlsplit(
        normalize_crawl_url(
            url
        )
    ).path.lower()

    return path.endswith(
        _JAVASCRIPT_SUFFIXES
    )


def query_parameter_names(
    url: str,
    *,
    limit: int,
) -> tuple[str, ...]:
    """Extract bounded query parameter names, discarding all values."""

    if limit <= 0:
        return ()

    query = urlsplit(
        normalize_crawl_url(
            url
        )
    ).query

    if not query:
        return ()

    try:
        pairs = parse_qsl(
            query,
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
        normalized = name.strip()

        if (
            not normalized
            or normalized in seen
        ):
            continue

        seen.add(normalized)
        names.append(normalized)

        if len(names) >= limit:
            break

    return tuple(names)


def _backend_process_timeout(
    backend: CrawlBackend,
) -> float:
    config = getattr(
        backend,
        "config",
        None,
    )

    value = getattr(
        config,
        "process_timeout_seconds",
        None,
    )

    if isinstance(
        value,
        (int, float),
    ) and value > 0:
        return float(value)

    # Protocol backends used in tests/adapters still need a safe lease floor.
    return 300.0


def _first_text(
    payload: dict[str, Any],
    keys: Iterable[str],
) -> str | None:
    for key in keys:
        value = payload.get(key)

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
        status = int(value)
    except (
        TypeError,
        ValueError,
    ):
        return None

    if 100 <= status <= 599:
        return status

    return None


def _parse_nonnegative_int(
    value: Any,
) -> int | None:
    try:
        parsed = int(value)
    except (
        TypeError,
        ValueError,
    ):
        return None

    return (
        parsed
        if parsed >= 0
        else None
    )


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

    return shutil.which(binary)


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
            tail.append(line)


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
