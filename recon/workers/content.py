"""Controlled JavaScript content materialization for Night Scout.

This worker is the network boundary between a discovered live JavaScript URL
and the network-free static analyzer in `workers/javascript.py`.

Pipeline
--------
JAVASCRIPT observation from crawler
    tags: javascript, live
    metadata: requires_static_analysis=true
        |
        | ScopeGate / RestrictionsGate / shared RateLimiter
        v
content.py
    one explicit GET, redirects disabled, retry=0
        |
        +--> HTTP_RESPONSE metadata (body is never placed in Event metadata)
        |
        +--> content-addressed local blob:
        |       blobs/javascript/ab/<sha256>.js
        |
        +--> JAVASCRIPT
                tags: content:available
                metadata:
                    content_ref=...
                    content_sha256=...
                    content_available=true
        |
        v
javascript.py
    local static analysis only

Important boundaries
--------------------
- This initial action fetches live JavaScript only. Historical archive response
  recovery is a separate future action because the network subject is the
  archive provider, not the target.
- It performs exactly one unauthenticated GET for one explicit URL.
- Redirects are not followed.
- No cookies, credentials, auth files, proxy, TLS impersonation or request body
  can be enabled through `extra_args`.
- The shared Night Scout RateLimiter is acquired before the subprocess starts.
- Response reads are bounded.
- Raw requests, response headers and bodies are never copied into Events.
- Only JavaScript-like successful responses are materialized.
- HTML/WAF/login pages are rejected as JavaScript material.
- Retryable HTTP status codes may retry the task, but httpx itself uses retry=0.

ProjectDiscovery httpx is used with JSONL `-include-response` so the bounded
response body can be captured in memory, validated, and written into Night
Scout's own content-addressed store. The JSON request/response raw fields are
discarded immediately after parsing.

Content-addressed storage
-------------------------
Blob identity is SHA-256 of the exact UTF-8 bytes written to disk. The default
workspace store writes atomically and reuses an existing identical blob. This
means the same bundle discovered from several provenance paths occupies one
physical blob while Events preserve all discovery relationships.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimitOutcome,
    RateLimiter,
    tool_integer_rps_hint,
)
from recon.workers.http import normalize_http_url
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "content"
ACTION_FETCH_JAVASCRIPT = "fetch_javascript"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")

_JAVASCRIPT_CONTENT_TYPES = frozenset(
    {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "text/plain",
        "application/octet-stream",
    }
)

_RETRYABLE_STATUS_CODES = frozenset(
    {
        408,
        425,
        429,
        500,
        502,
        503,
        504,
    }
)


class ContentFetchResult(BaseModel):
    """Normalized result from one explicit HTTP GET."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_url: str
    url: str

    status_code: int | None = Field(default=None, ge=100, le=599)

    content_type: str | None = None
    content_length: int | None = Field(default=None, ge=0)

    body: str | None = None

    location: str | None = None
    webserver: str | None = None
    response_time: str | float | int | None = None

    failed: bool = False
    error: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("input_url", "url")
    @classmethod
    def normalize_urls(cls, value: str) -> str:
        return normalize_http_url(value)

    @field_validator(
        "content_type",
        "location",
        "webserver",
        "error",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @property
    def body_bytes(self) -> bytes:
        if self.body is None:
            return b""

        return self.body.encode(
            "utf-8",
            errors="replace",
        )

    @property
    def body_size_bytes(self) -> int:
        return len(
            self.body_bytes
        )

    @property
    def body_sha256(self) -> str | None:
        if self.body is None:
            return None

        return hashlib.sha256(
            self.body_bytes
        ).hexdigest()


class StoredContent(BaseModel):
    """One content-addressed local blob."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content_ref: str
    sha256: str
    size_bytes: int = Field(ge=0)

    media_type: str | None = None

    reused_existing: bool = False

    @field_validator("content_ref", "sha256")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized


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


class ContentStore(Protocol):
    """Persist approved content and return a relative opaque reference."""

    async def put_javascript(
        self,
        body: bytes,
        *,
        media_type: str | None,
    ) -> StoredContent:
        ...


class ContentFetchBackend(Protocol):
    """One explicit URL -> one HTTP request backend."""

    name: str

    def ensure_available(self) -> None:
        ...

    async def fetch(
        self,
        url: str,
        *,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[ContentFetchResult]:
        ...


class WorkspaceContentStore:
    """Atomic content-addressed workspace blob store.

    Result references are relative to `root`, for example:

        blobs/javascript/ab/abcdef....js

    This is directly compatible with FileJavaScriptContentProvider when both
    components use the same workspace root.
    """

    def __init__(
        self,
        root: Path,
    ) -> None:
        self._root = (
            root.expanduser()
            .resolve()
        )

    @property
    def root(self) -> Path:
        return self._root

    async def put_javascript(
        self,
        body: bytes,
        *,
        media_type: str | None,
    ) -> StoredContent:
        return await asyncio.to_thread(
            self._put_javascript_sync,
            body,
            media_type,
        )

    def _put_javascript_sync(
        self,
        body: bytes,
        media_type: str | None,
    ) -> StoredContent:
        digest = hashlib.sha256(
            body
        ).hexdigest()

        relative = Path(
            "blobs",
            "javascript",
            digest[:2],
            f"{digest}.js",
        )

        target = (
            self._root
            / relative
        )

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        reused = target.exists()

        if reused:
            existing = (
                target.read_bytes()
            )

            if hashlib.sha256(
                existing
            ).hexdigest() != digest:
                raise RuntimeError(
                    "content-addressed blob hash collision/corruption "
                    f"at {target}"
                )

            if existing != body:
                raise RuntimeError(
                    "content-addressed blob bytes do not match digest"
                )

        else:
            temp = (
                target.parent
                / (
                    f".{target.name}."
                    f"{os.getpid()}."
                    f"{id(body)}.tmp"
                )
            )

            try:
                with temp.open(
                    "xb",
                ) as handle:
                    handle.write(
                        body
                    )
                    handle.flush()
                    os.fsync(
                        handle.fileno()
                    )

                try:
                    os.chmod(
                        temp,
                        0o600,
                    )
                except OSError:
                    pass

                try:
                    os.replace(
                        temp,
                        target,
                    )
                except OSError:
                    if not target.exists():
                        raise

                persisted = (
                    target.read_bytes()
                )

                if persisted != body:
                    raise RuntimeError(
                        "persisted content does not match source bytes"
                    )

            finally:
                if temp.exists():
                    try:
                        temp.unlink()
                    except OSError:
                        pass

        return StoredContent(
            content_ref=(
                relative.as_posix()
            ),
            sha256=digest,
            size_bytes=len(body),
            media_type=media_type,
            reused_existing=reused,
        )


class HttpxContentConfig(BaseModel):
    """ProjectDiscovery httpx configuration for bounded body capture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "httpx"

    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=120,
    )

    process_timeout_seconds: float = Field(
        default=20.0,
        gt=0.0,
    )

    max_response_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=4096,
        le=64 * 1024 * 1024,
    )

    user_agent: str = (
        "NightScout/0.1 authorized-security-research"
    )

    stderr_tail_lines: int = Field(
        default=100,
        ge=1,
        le=2000,
    )

    stream_limit_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=65536,
        le=512 * 1024 * 1024,
    )

    extra_args: tuple[str, ...] = ()

    @model_validator(mode="after")
    def json_line_buffer_is_large_enough(self) -> "HttpxContentConfig":
        # `-irr` returns the body inside one JSONL record. JSON escaping can
        # expand textual data substantially, so the StreamReader line limit
        # must be comfortably larger than the raw response-read ceiling.
        minimum_stream_limit = (self.max_response_bytes * 6) + 65536

        if self.stream_limit_bytes < minimum_stream_limit:
            raise ValueError(
                "stream_limit_bytes must be at least 6x "
                "max_response_bytes + 65536 when using httpx -irr"
            )

        return self

    @field_validator("binary", "user_agent")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized

    @field_validator("extra_args")
    @classmethod
    def reject_overrides(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            value.strip()
            for value in values
            if value.strip()
        )

        forbidden = {
            "-u", "-target", "-l", "-list", "-rr", "-request",
            "-im", "-input-mode", "-x", "-body",
            "-fr", "-follow-redirects", "-fhr", "-follow-host-redirects",
            "-maxr", "-max-redirects", "-rhsts", "-respect-hsts",
            "-pa", "-probe-all-ips", "-p", "-ports", "-path",
            "-tls-probe", "-csp-probe", "-tls-grab", "-pipeline",
            "-http2", "-vhost", "-vhost-input", "-favicon", "-jarm",
            "-ss", "-screenshot",
            "-sf", "-secrets-file", "-H", "-header", "-auth", "-ac",
            "-auth-config", "-auto-referer", "-proxy", "-http-proxy",
            "-sni", "-sni-name", "-unsafe", "-tlsi", "-tls-impersonate",
            "-t", "-threads", "-rl", "-rate-limit", "-rlm",
            "-rate-limit-minute", "-delay", "-retries", "-timeout",
            "-nf", "-no-fallback", "-nfs", "-no-fallback-scheme",
            "-j", "-json", "-irr", "-include-response", "-irrb",
            "-include-response-base64", "-irh", "-include-response-header",
            "-sr", "-store-response", "-srd", "-store-response-dir",
            "-o", "-output", "-oa", "-output-all", "-csv", "-ob",
            "-omit-body", "-rstr", "-response-size-to-read", "-rsts",
            "-response-size-to-save",
            "-rdb", "-result-db", "-rdbc", "-result-db-config",
            "-rdbt", "-result-db-type", "-rdbcs",
            "-result-db-conn", "-rdbn", "-result-db-name",
            "-rdbtb", "-result-db-table", "-rdbbs",
            "-result-db-batch-size", "-rdbor", "-result-db-omit-raw",
            "-pd", "-dashboard", "-pdu", "-dashboard-upload",
            "-tid", "-team-id", "-aid", "-asset-id",
            "-aname", "-asset-name",
            "-resume", "-no-decode", "-s", "-stream",
            "-sd", "-skip-dedupe",
            "-debug", "-debug-req", "-debug-resp", "-v", "-verbose",
            "-up", "-update",
        }

        if any(
            value in forbidden
            for value in normalized
        ):
            raise ValueError(
                "httpx content extra_args cannot override target/method, "
                "authentication, redirects, shared rate control, bounded "
                "response capture, or output"
            )

        return normalized


class ContentWorkerConfig(BaseModel):
    """Materialization and event behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rate_lease_seconds: float = Field(
        default=30.0,
        gt=0.0,
    )

    response_confidence: float = Field(
        default=0.98,
        ge=0.0,
        le=1.0,
    )

    content_confidence: float = Field(
        default=0.99,
        ge=0.0,
        le=1.0,
    )

    default_retry_after_seconds: float = Field(
        default=5.0,
        ge=0.0,
    )

    retryable_status_codes: frozenset[int] = Field(
        default_factory=lambda: _RETRYABLE_STATUS_CODES
    )

    accepted_content_types: frozenset[str] = Field(
        default_factory=lambda: _JAVASCRIPT_CONTENT_TYPES
    )

    allow_missing_content_type: bool = True

    reject_html_prefix_bytes: int = Field(
        default=2048,
        ge=128,
        le=65_536,
    )

    @field_validator("retryable_status_codes")
    @classmethod
    def validate_retryable_statuses(
        cls,
        values: frozenset[int],
    ) -> frozenset[int]:
        for value in values:
            if not 100 <= value <= 599:
                raise ValueError(
                    "retryable status codes must be valid HTTP statuses"
                )

        return values

    @field_validator("accepted_content_types")
    @classmethod
    def normalize_content_types(
        cls,
        values: frozenset[str],
    ) -> frozenset[str]:
        result = frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )

        if not result:
            raise ValueError(
                "accepted_content_types cannot be empty"
            )

        return result


class ContentBackendError(RuntimeError):
    """httpx content backend failed."""


class ContentBackendUnavailable(ContentBackendError):
    """Configured httpx executable is unavailable."""


class ContentBackendTimeout(ContentBackendError):
    """httpx exceeded its outer timeout."""


class HttpxContentBackend:
    """Exactly-one-request ProjectDiscovery httpx body-capture adapter."""

    name = "httpx"

    def __init__(
        self,
        config: HttpxContentConfig | None = None,
    ) -> None:
        self.config = config or HttpxContentConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(
            self.config.binary
        ) is None:
            raise ContentBackendUnavailable(
                f"httpx executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        rate_limit_rps: int | None,
    ) -> tuple[str, ...]:
        executable = _resolve_executable(
            self.config.binary
        )
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-nfs",
            "-x",
            "GET",
            "-retries",
            "0",
            "-t",
            "1",
            "-timeout",
            str(self.config.timeout_seconds),
            "-irr",
            "-rstr",
            str(self.config.max_response_bytes),
            "-rsts",
            str(self.config.max_response_bytes),
            "-H",
            f"User-Agent: {self.config.user_agent}",
        ]

        if rate_limit_rps is not None:
            args.extend(
                (
                    "-rl",
                    str(rate_limit_rps),
                )
            )

        args.extend(
            self.config.extra_args
        )

        return tuple(args)

    async def fetch(
        self,
        url: str,
        *,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[ContentFetchResult]:
        requested_url = normalize_http_url(
            url
        )

        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(
                rate_limit_rps=rate_limit_rps,
            ),
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
            await _terminate_process(
                process
            )
            raise ContentBackendError(
                "httpx subprocess pipes were not created"
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
                (requested_url + "\n").encode(
                    "utf-8"
                )
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

                        parsed = parse_httpx_content_line(
                            line,
                            expected_url=requested_url,
                        )

                        if parsed is not None:
                            yield parsed

                    returncode = await process.wait()

            except TimeoutError as exc:
                await _terminate_process(
                    process
                )

                raise ContentBackendTimeout(
                    "httpx content fetch exceeded outer process timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(
                    stderr_tail
                )

                raise ContentBackendError(
                    "httpx content fetch exited unsuccessfully "
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


class ContentWorker:
    """Rate-controlled live JavaScript fetch/materialization worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        store: ContentStore,
        backend: ContentFetchBackend | None = None,
        config: ContentWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._store = store
        self._backend = (
            backend
            or HttpxContentBackend()
        )
        self._config = (
            config
            or ContentWorkerConfig()
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
                    "content worker may only execute claimed RUNNING tasks, "
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

        if (
            task.action
            != ACTION_FETCH_JAVASCRIPT
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "unsupported content action: "
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
                outcome=WorkerOutcome.FAILED,
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        try:
            url = javascript_fetch_url(
                input_event
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        parts = urlsplit(
            url
        )

        if parts.hostname is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "JavaScript fetch URL has no hostname"
                ),
            )

        hostname = normalize_dns_name(
            parts.hostname
        )

        try:
            self._backend.ensure_available()
        except ContentBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        context = RateLimitContext(
            resource_keys=frozenset(
                {
                    f"host:{hostname}"
                }
            )
        )

        plan = self._rate_limiter.plan(
            task,
            context=context,
        )

        cli_rps = tool_integer_rps_hint(
            plan
        )

        decision = await self._rate_limiter.acquire(
            task,
            context=context,
            demand=RateLimitDemand(
                requests=1.0,
                concurrency=1,
            ),
            lease_for=timedelta(
                seconds=(
                    self._config.rate_lease_seconds
                )
            ),
        )

        if (
            decision.outcome
            is RateLimitOutcome.DEFER
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=(
                    decision.reason
                    or (
                        "content fetch shared rate limit "
                        "temporarily exhausted"
                    )
                ),
                retry_after_seconds=(
                    decision.retry_after_seconds
                    if decision.retry_after_seconds
                    is not None
                    else (
                        self._config.default_retry_after_seconds
                    )
                ),
            )

        if (
            decision.outcome
            is RateLimitOutcome.DENY
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    decision.reason
                    or (
                        "content fetch shared rate policy "
                        "denied execution"
                    )
                ),
            )

        lease_id = (
            decision.lease.lease_id
            if decision.lease is not None
            else None
        )

        saw_result = False

        try:
            async for result in (
                self._backend.fetch(
                    url,
                    rate_limit_rps=cli_rps,
                )
            ):
                if (
                    result.input_url
                    != url
                    or result.url
                    != url
                ):
                    continue

                saw_result = True

                await self._publish_response(
                    input_event=input_event,
                    result=result,
                )

                if result.failed:
                    return WorkerExecutionResult(
                        outcome=WorkerOutcome.RETRY,
                        error=(
                            result.error
                            or (
                                "httpx reported failed JavaScript "
                                "content fetch"
                            )
                        ),
                        retry_after_seconds=(
                            self._config.default_retry_after_seconds
                        ),
                    )

                if (
                    result.status_code
                    in self._config.retryable_status_codes
                ):
                    return WorkerExecutionResult(
                        outcome=WorkerOutcome.RETRY,
                        error=(
                            "JavaScript content fetch received "
                            f"retryable HTTP {result.status_code}"
                        ),
                        retry_after_seconds=(
                            self._config.default_retry_after_seconds
                        ),
                    )

                material_reason = (
                    javascript_material_rejection_reason(
                        result,
                        config=self._config,
                        backend=self._backend,
                    )
                )

                if material_reason is not None:
                    continue

                stored = (
                    await self._store.put_javascript(
                        result.body_bytes,
                        media_type=(
                            normalized_media_type(
                                result.content_type
                            )
                        ),
                    )
                )

                await self._publish_materialized(
                    input_event=input_event,
                    result=result,
                    stored=stored,
                )

            if not saw_result:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=(
                        "httpx content fetch produced no result"
                    ),
                    retry_after_seconds=(
                        self._config.default_retry_after_seconds
                    ),
                )

        except ContentBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=(
                    self._config.default_retry_after_seconds
                ),
            )
        except ContentBackendError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=(
                    self._config.default_retry_after_seconds
                ),
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(
                    lease_id
                )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _publish_response(
        self,
        *,
        input_event: Event,
        result: ContentFetchResult,
    ) -> None:
        status = (
            result.status_code
            if result.status_code is not None
            else "FAILED"
        )

        await self._publisher.publish(
            Event(
                type=EventType.HTTP_RESPONSE,
                value=(
                    f"GET {result.url} -> {status}"
                ),
                source=(
                    f"content:{_source_component(self._backend.name)}:"
                    "javascript"
                ),
                parent_event_id=(
                    input_event.event_id
                ),
                scope_state=(
                    input_event.scope_state
                ),
                confidence=(
                    self._config.response_confidence
                ),
                novelty=0.40,
                depth=input_event.depth + 1,
                tags={
                    "content",
                    "javascript-fetch",
                    "http-response",
                    (
                        f"status:{result.status_code}"
                        if result.status_code
                        is not None
                        else "fetch-failed"
                    ),
                },
                metadata={
                    "url": result.url,
                    "method": "GET",
                    "status_code": (
                        result.status_code
                    ),
                    "content_type": (
                        result.content_type
                    ),
                    "content_length": (
                        result.content_length
                    ),
                    "body_size_bytes": (
                        result.body_size_bytes
                    ),
                    "body_sha256": (
                        result.body_sha256
                    ),
                    "location": (
                        result.location
                    ),
                    "webserver": (
                        result.webserver
                    ),
                    "response_time": (
                        result.response_time
                    ),
                    "failed": result.failed,
                    "error": result.error,
                    "body_stored_in_event": False,
                    "raw_request_stored": False,
                    "raw_response_stored": False,
                    "redirect_followed": False,
                    **result.metadata,
                },
            )
        )

    async def _publish_materialized(
        self,
        *,
        input_event: Event,
        result: ContentFetchResult,
        stored: StoredContent,
    ) -> None:
        await self._publisher.publish(
            Event(
                type=EventType.JAVASCRIPT,
                value=input_event.value,
                source=(
                    f"content:{_source_component(self._backend.name)}:"
                    "javascript"
                ),
                parent_event_id=(
                    input_event.event_id
                ),
                scope_state=(
                    input_event.scope_state
                ),
                confidence=(
                    self._config.content_confidence
                ),
                novelty=0.65,
                depth=input_event.depth + 1,
                tags={
                    "javascript",
                    "live",
                    "fetched",
                    "content:available",
                },
                metadata={
                    "origin_url": result.url,
                    "content_available": True,
                    "content_ref": (
                        stored.content_ref
                    ),
                    "content_sha256": (
                        stored.sha256
                    ),
                    "content_size_bytes": (
                        stored.size_bytes
                    ),
                    "content_media_type": (
                        stored.media_type
                    ),
                    "content_store": (
                        "workspace-content-addressed"
                    ),
                    "reused_existing_blob": (
                        stored.reused_existing
                    ),
                    "fetched_by": (
                        self._backend.name
                    ),
                    "fetch_status_code": (
                        result.status_code
                    ),
                    "fetch_content_type": (
                        result.content_type
                    ),
                    "requires_static_analysis": True,
                    "network_fetch_complete": True,
                    "raw_response_stored": False,
                },
            )
        )


def content_route_rules(
    *,
    base_priority: float = 8.0,
) -> tuple[RouteRule, ...]:
    """Route only live JS discoveries that still need local material."""

    return (
        RouteRule(
            rule_id=(
                "content.fetch-javascript.live"
            ),
            accepts=frozenset(
                {
                    EventType.JAVASCRIPT
                }
            ),
            worker=WORKER_NAME,
            action=(
                ACTION_FETCH_JAVASCRIPT
            ),
            reason=(
                "fetch one approved live JavaScript URL into the local "
                "content-addressed store"
            ),
            base_priority=base_priority,
            required_tags=frozenset(
                {
                    "javascript",
                    "live",
                }
            ),
            excluded_tags=frozenset(
                {
                    "content:available",
                    "historical",
                    "archive",
                    "analysis:complete",
                }
            ),
            predicate=(
                _requires_static_analysis
            ),
        ),
    )


def _requires_static_analysis(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    return bool(
        event.metadata.get(
            "requires_static_analysis"
        )
    )


def javascript_fetch_url(
    event: Event,
) -> str:
    """Validate that the Event represents an unfetched live JS URL."""

    if (
        event.type
        is not EventType.JAVASCRIPT
    ):
        raise ValueError(
            "content.fetch_javascript requires JAVASCRIPT input"
        )

    if (
        "javascript"
        not in event.tags
        or "live"
        not in event.tags
    ):
        raise ValueError(
            "content.fetch_javascript requires a live JavaScript observation"
        )

    if (
        "historical" in event.tags
        or "archive" in event.tags
    ):
        raise ValueError(
            "historical JavaScript must use a future archive-response "
            "materializer, not the live target fetcher"
        )

    if (
        "content:available"
        in event.tags
    ):
        raise ValueError(
            "JavaScript content is already available locally"
        )

    if not event.metadata.get(
        "requires_static_analysis"
    ):
        raise ValueError(
            "JavaScript observation is not marked for static analysis"
        )

    url = normalize_http_url(
        event.value
    )

    path = (
        urlsplit(url)
        .path
        .lower()
    )

    if not path.endswith(
        (
            ".js",
            ".mjs",
            ".cjs",
        )
    ):
        raise ValueError(
            "initial content fetcher accepts only .js/.mjs/.cjs URLs"
        )

    return url


def parse_httpx_content_line(
    line: str,
    *,
    expected_url: str,
) -> ContentFetchResult | None:
    """Parse one current/tolerant httpx include-response JSONL line."""

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

    raw_input = _first_text(
        payload,
        (
            "input",
        ),
    )

    raw_url = _first_text(
        payload,
        (
            "url",
        ),
    )

    if raw_input is None:
        raw_input = expected_url

    if raw_url is None:
        raw_url = raw_input

    try:
        input_url = normalize_http_url(
            raw_input
        )
        url = normalize_http_url(
            raw_url
        )
        expected = normalize_http_url(
            expected_url
        )
    except ValueError:
        return None

    if input_url != expected:
        return None

    body_value = (
        payload.get(
            "response-body"
        )
        if "response-body" in payload
        else payload.get(
            "response_body"
        )
    )

    if (
        body_value is None
        and isinstance(
            payload.get("body"),
            str,
        )
    ):
        body_value = payload.get(
            "body"
        )

    body = (
        body_value
        if isinstance(
            body_value,
            str,
        )
        else None
    )

    status_code = _parse_status_code(
        payload.get(
            "status-code"
        )
        if "status-code" in payload
        else payload.get(
            "status_code"
        )
    )

    content_type = _first_text(
        payload,
        (
            "content-type",
            "content_type",
        ),
    )

    content_length = (
        _parse_nonnegative_int(
            payload.get(
                "content-length"
            )
            if "content-length"
            in payload
            else payload.get(
                "content_length"
            )
        )
    )

    location = _first_text(
        payload,
        (
            "location",
        ),
    )

    webserver = _first_text(
        payload,
        (
            "webserver",
            "server",
        ),
    )

    response_time = (
        payload.get(
            "response-time"
        )
        if "response-time"
        in payload
        else payload.get(
            "response_time"
        )
    )

    failed = bool(
        payload.get(
            "failed",
            False,
        )
    )

    error = _first_text(
        payload,
        (
            "error",
            "err",
        ),
    )

    safe_metadata_keys = {
        "scheme",
        "port",
        "path",
        "host",
        "method",
        "lines",
        "words",
    }

    safe_metadata = {
        key: payload[key]
        for key in safe_metadata_keys
        if key in payload
    }

    return ContentFetchResult(
        input_url=input_url,
        url=url,
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        body=body,
        location=location,
        webserver=webserver,
        response_time=response_time,
        failed=failed,
        error=error,
        metadata=safe_metadata,
    )


def javascript_material_rejection_reason(
    result: ContentFetchResult,
    *,
    config: ContentWorkerConfig,
    backend: ContentFetchBackend,
) -> str | None:
    """Return why a completed response must not become local JS material."""

    if (
        result.status_code is None
        or not (
            200
            <= result.status_code
            <= 299
        )
    ):
        return (
            "response is not successful 2xx"
        )

    if (
        result.body is None
        or not result.body
    ):
        return (
            "response body is empty"
        )

    max_bytes = _backend_max_response_bytes(
        backend
    )

    if (
        result.content_length
        is not None
        and result.content_length
        > max_bytes
    ):
        return (
            "declared response exceeds configured maximum"
        )

    if (
        result.body_size_bytes
        >= max_bytes
        and (
            result.content_length
            is None
            or result.content_length
            > result.body_size_bytes
        )
    ):
        return (
            "response may be truncated at configured read limit"
        )

    media_type = normalized_media_type(
        result.content_type
    )

    if media_type is None:
        if not config.allow_missing_content_type:
            return (
                "response content type is missing"
            )
    elif (
        media_type
        not in config.accepted_content_types
    ):
        return (
            "response content type is not JavaScript-compatible"
        )

    prefix = (
        result.body_bytes[
            : config.reject_html_prefix_bytes
        ]
        .lstrip()
        .lower()
    )

    if looks_like_html_prefix(
        prefix
    ):
        return (
            "response looks like HTML rather than JavaScript"
        )

    return None


def normalized_media_type(
    content_type: str | None,
) -> str | None:
    if content_type is None:
        return None

    media_type = (
        content_type
        .split(
            ";",
            1,
        )[0]
        .strip()
        .lower()
    )

    return (
        media_type
        or None
    )


def looks_like_html_prefix(
    prefix: bytes,
) -> bool:
    return prefix.startswith(
        (
            b"<!doctype html",
            b"<html",
            b"<head",
            b"<body",
        )
    )


def _backend_max_response_bytes(
    backend: ContentFetchBackend,
) -> int:
    config = getattr(
        backend,
        "config",
        None,
    )

    value = getattr(
        config,
        "max_response_bytes",
        None,
    )

    if isinstance(
        value,
        int,
    ) and value > 0:
        return value

    return (
        8 * 1024 * 1024
    )


def _first_text(
    payload: dict[str, Any],
    keys: tuple[str, ...],
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


def _parse_nonnegative_int(
    value: Any,
) -> int | None:
    try:
        parsed = int(
            value
        )
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
