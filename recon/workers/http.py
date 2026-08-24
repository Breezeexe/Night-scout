"""Controlled HTTP/HTTPS service probing for Night Scout.

This worker consumes confirmed DNS_NAME observations and performs bounded,
read-only HTTP probes using ProjectDiscovery httpx.

Safety / accounting invariants
------------------------------
- Only confirmed DNS_NAME events are routed here by default.
- HTTP and HTTPS are probed separately.
- `-no-fallback-scheme` prevents httpx from silently making a second request.
- Redirects are not followed.
- Retries are disabled.
- One shared RateLimiter acquisition corresponds to one scheme probe.
- No favicon/JARM/screenshot/http2/pipeline/vhost/tls-grab probing is mixed in.
- Response bodies are not stored; only normalized metadata and a SHA-256 body
  hash are emitted.
- A bounded response-read limit avoids unbounded body processing.

This makes the worker suitable as the first active HTTP confirmation layer.
Specialized workers (`tls.py`, `vhost.py`, `fingerprints.py`, `crawler.py`)
can build on its confirmed services later.

Typical output
--------------
DNS_NAME api.example.com (confirmed)
    -> URL https://api.example.com/
    -> HTTP_SERVICE https://api.example.com:443
    -> HTTP_RESPONSE GET https://api.example.com/ -> 200
    -> TECHNOLOGY nginx
    -> TECHNOLOGY React

A redirect Location header is preserved as a separate URL hypothesis but is
NOT followed by this worker. The redirect target uses scope=UNKNOWN and must
be reclassified before any later active follow-up.

HTTP_RESPONSE metadata includes a normalized `surface_state` block compatible
with storage/snapshots.py so the future ingestion coordinator can persist
differential recon state without coupling this worker directly to SQLAlchemy.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimiter,
    RateLimitOutcome,
    tool_integer_rps_hint,
)
from recon.policy.request_identity import RequestIdentityPolicy
from recon.workers.passive_domains import normalize_dns_name
from recon.workers.subprocess_stream import (
    completed_process_returncode,
    stream_process_stdout,
)

WORKER_NAME = "http"
ACTION_PROBE = "probe"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")


class HTTPProbeResult(BaseModel):
    """Normalized result of one explicit-scheme httpx probe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_url: str
    url: str

    scheme: str
    hostname: str
    port: int = Field(ge=1, le=65535)

    method: str = "GET"

    status_code: int | None = Field(default=None, ge=100, le=599)

    title: str | None = None
    body_sha256: str | None = None

    content_type: str | None = None
    content_length: int | None = Field(default=None, ge=0)

    location: str | None = None
    webserver: str | None = None

    technologies: tuple[str, ...] = ()

    response_time: str | float | int | None = None

    failed: bool = False
    error: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scheme")
    @classmethod
    def normalize_scheme(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        return normalized

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("method must not be blank")
        return normalized

    @field_validator(
        "title",
        "body_sha256",
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
        return value.strip() or None

    @field_validator("technologies")
    @classmethod
    def normalize_technologies(
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
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class HTTPProbeBackend(Protocol):
    """One explicit-scheme HTTP probe implementation."""

    name: str

    def ensure_available(self) -> None:
        ...

    def probe(
        self,
        url: str,
        *,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[HTTPProbeResult]:
        ...


class HttpxConfig(BaseModel):
    """ProjectDiscovery httpx subprocess configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "httpx"

    schemes: tuple[str, ...] = ("https", "http")

    timeout_seconds: int = Field(default=10, ge=1, le=120)
    process_timeout_seconds: float = Field(default=20.0, gt=0.0)

    max_response_read_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
    )

    user_agent: str = (
        "NightScout/0.1 authorized-security-research"
    )

    detect_technologies: bool = True

    stderr_tail_lines: int = Field(default=80, ge=1, le=1000)
    stream_limit_bytes: int = Field(
        default=1024 * 1024,
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

    @field_validator("schemes")
    @classmethod
    def normalize_schemes(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if not values:
            raise ValueError("schemes cannot be empty")

        result: list[str] = []
        for value in values:
            scheme = value.strip().lower()
            if scheme not in {"http", "https"}:
                raise ValueError(
                    "httpx schemes may contain only http/https"
                )
            if scheme not in result:
                result.append(scheme)

        return tuple(result)

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
            # Input / raw request overrides.
            "-u",
            "-target",
            "-l",
            "-list",
            "-rr",
            "-request",
            "-im",
            "-input-mode",

            # Can create additional requests or broaden the target set.
            "-fr",
            "-follow-redirects",
            "-fhr",
            "-follow-host-redirects",
            "-maxr",
            "-max-redirects",
            "-pa",
            "-probe-all-ips",
            "-p",
            "-ports",
            "-path",
            "-tls-probe",
            "-csp-probe",
            "-vhost",
            "-vhost-input",
            "-favicon",
            "-jarm",
            "-ss",
            "-screenshot",
            "-pipeline",
            "-http2",
            "-tls-grab",

            # Request behavior is owned by this adapter.
            "-x",
            "-body",
            "-unsafe",
            "-H",
            "-header",
            "-sni",
            "-sni-name",
            "-retries",
            "-timeout",
            "-delay",

            # Shared rate/concurrency is owned by Night Scout.
            "-rl",
            "-rate-limit",
            "-rlm",
            "-rate-limit-minute",
            "-t",
            "-threads",

            # Scheme behavior must remain one explicit request per permit.
            "-nf",
            "-no-fallback",
            "-nfs",
            "-no-fallback-scheme",

            # Output must remain JSONL on stdout and bodies must not be stored.
            "-o",
            "-output",
            "-oa",
            "-output-all",
            "-csv",
            "-sr",
            "-store-response",
            "-srd",
            "-store-response-dir",
            "-irr",
            "-include-response",
            "-irrb",
            "-include-response-base64",
            "-irh",
            "-include-response-header",
            "-debug",
            "-debug-req",
            "-debug-resp",

            # Probe selection/output fields are owned by this adapter.
            "-j",
            "-json",
            "-sc",
            "-status-code",
            "-cl",
            "-content-length",
            "-ct",
            "-content-type",
            "-location",
            "-hash",
            "-rt",
            "-response-time",
            "-title",
            "-server",
            "-web-server",
            "-td",
            "-tech-detect",
            "-method",
            "-probe",
            "-rstr",
            "-response-size-to-read",
        }

        if any(value in forbidden for value in normalized):
            raise ValueError(
                "httpx extra_args cannot override input, request count, "
                "rate control, probe fields, or streaming output"
            )

        return normalized


class HTTPWorkerConfig(BaseModel):
    """HTTP worker event/confidence behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rate_lease_seconds: float = Field(default=30.0, gt=0.0)

    service_confidence: float = Field(
        default=0.97,
        ge=0.0,
        le=1.0,
    )
    response_confidence: float = Field(
        default=0.98,
        ge=0.0,
        le=1.0,
    )
    technology_confidence: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
    )
    redirect_confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
    )
    failure_confidence: float = Field(
        default=0.55,
        ge=0.0,
        le=1.0,
    )

    default_retry_after_seconds: float = Field(
        default=5.0,
        ge=0.0,
    )


class HTTPBackendError(RuntimeError):
    """httpx/backend execution failure."""


class HTTPBackendUnavailable(HTTPBackendError):
    """Configured httpx executable is unavailable."""


class HTTPBackendTimeout(HTTPBackendError):
    """httpx exceeded the outer subprocess timeout."""


class HttpxBackend:
    """One-explicit-URL-at-a-time ProjectDiscovery httpx adapter."""

    name = "httpx"

    def __init__(
        self,
        config: HttpxConfig | None = None,
        *,
        request_identity: RequestIdentityPolicy | None = None,
    ) -> None:
        self.config = config or HttpxConfig()
        self.request_identity = request_identity or RequestIdentityPolicy()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise HTTPBackendUnavailable(
                f"httpx executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        rate_limit_rps: int | None,
    ) -> tuple[str, ...]:
        """Build argv for exactly one explicit-scheme input URL."""
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-j",
            "-silent",
            "-nc",
            "-duc",

            # Input URL already contains the desired scheme.
            "-nfs",

            # One shared permit must map to one HTTP request.
            "-retries",
            "0",
            "-t",
            "1",

            "-timeout",
            str(self.config.timeout_seconds),

            "-sc",
            "-cl",
            "-ct",
            "-location",
            "-rt",
            "-title",
            "-server",
            "-method",
            "-probe",
            "-hash",
            "sha256",

            "-rstr",
            str(self.config.max_response_read_bytes),

            "-H",
            f"User-Agent: {self.config.user_agent}",
        ]

        if self.config.detect_technologies:
            args.append("-td")

        if rate_limit_rps is not None:
            args.extend(
                (
                    "-rl",
                    str(rate_limit_rps),
                )
            )

        args.extend(self.request_identity.repeated_cli_args("-H"))
        args.extend(self.config.extra_args)
        return tuple(args)

    async def probe(
        self,
        url: str,
        *,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[HTTPProbeResult]:
        normalized_url = normalize_http_url(url)
        self.ensure_available()

        command = self.command_for(
            rate_limit_rps=rate_limit_rps,
        )

        process = await asyncio.create_subprocess_exec(
            *command,
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
            raise HTTPBackendError(
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
                (normalized_url + "\n").encode("utf-8")
            )
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            try:
                async for raw_line in stream_process_stdout(
                    process,
                    timeout_seconds=self.config.process_timeout_seconds,
                ):
                    line = raw_line.decode(
                        "utf-8",
                        errors="replace",
                    ).strip()

                    if not line:
                        continue

                    parsed = parse_httpx_line(line)

                    if parsed is not None:
                        yield parsed
            except TimeoutError as exc:
                await _terminate_process(process)
                raise HTTPBackendTimeout(
                    "httpx exceeded outer process timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            returncode = completed_process_returncode(process)
            if returncode != 0:
                detail = " | ".join(stderr_tail)
                raise HTTPBackendError(
                    "httpx exited unsuccessfully "
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


class HTTPWorker:
    """Rate-limited root HTTP/HTTPS service confirmation worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        backend: HTTPProbeBackend | None = None,
        config: HTTPWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._backend = backend or HttpxBackend()
        self._config = config or HTTPWorkerConfig()

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "http worker may only execute claimed RUNNING tasks, "
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

        if task.action != ACTION_PROBE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported http action: {task.action}",
            )

        input_event = await self._events.get_event(
            task.input_event_id
        )
        if input_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        if input_event.type is not EventType.DNS_NAME:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "http.probe requires DNS_NAME input, got "
                    f"{input_event.type.value}"
                ),
            )

        if (
            "confirmed" not in input_event.tags
            or "hypothesis" in input_event.tags
        ):
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "http.probe requires a confirmed non-hypothesis "
                    "DNS_NAME observation"
                ),
            )

        try:
            hostname = normalize_dns_name(
                input_event.value
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"invalid input DNS name: {exc}",
            )

        try:
            self._backend.ensure_available()
        except HTTPBackendUnavailable as exc:
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
        cli_rps = tool_integer_rps_hint(plan)

        for scheme in self._backend_schemes():
            decision = await self._rate_limiter.await_acquire(
                task,
                context=context,
                demand=RateLimitDemand(
                    requests=1.0,
                    concurrency=1,
                ),
                lease_for=timedelta(
                    seconds=self._config.rate_lease_seconds
                ),
            )

            if decision.outcome is RateLimitOutcome.DEFER:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=(
                        decision.reason
                        or (
                            "HTTP shared rate limit temporarily "
                            "exhausted"
                        )
                    ),
                    retry_after_seconds=(
                        decision.retry_after_seconds
                        if decision.retry_after_seconds is not None
                        else self._config.default_retry_after_seconds
                    ),
                )

            if decision.outcome is RateLimitOutcome.DENY:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.FAILED,
                    error=(
                        decision.reason
                        or (
                            "HTTP shared rate-limit policy "
                            "denied execution"
                        )
                    ),
                )

            lease_id = (
                decision.lease.lease_id
                if decision.lease is not None
                else None
            )

            try:
                requested_url = root_url(
                    hostname,
                    scheme=scheme,
                )

                results: list[HTTPProbeResult] = []

                async for result in self._backend.probe(
                    requested_url,
                    rate_limit_rps=cli_rps,
                ):
                    results.append(result)

                for result in results:
                    if not _result_matches_request(
                        result,
                        hostname=hostname,
                        scheme=scheme,
                    ):
                        continue

                    await self._publish_result(
                        input_event=input_event,
                        result=result,
                    )

            except HTTPBackendTimeout as exc:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=str(exc),
                    retry_after_seconds=(
                        self._config.default_retry_after_seconds
                    ),
                )
            except HTTPBackendError as exc:
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

    def _backend_schemes(self) -> tuple[str, ...]:
        config = getattr(
            self._backend,
            "config",
            None,
        )
        schemes = getattr(
            config,
            "schemes",
            ("https", "http"),
        )
        return tuple(schemes)

    async def _publish_result(
        self,
        *,
        input_event: Event,
        result: HTTPProbeResult,
    ) -> None:
        if result.failed:
            failure = Event(
                type=EventType.HTTP_RESPONSE,
                value=(
                    f"{result.method} {result.url} PROBE_FAILED"
                ),
                source=(
                    f"http:{_source_component(self._backend.name)}:"
                    f"{result.scheme}:failure"
                ),
                parent_event_id=input_event.event_id,
                scope_state=input_event.scope_state,
                confidence=self._config.failure_confidence,
                novelty=0.2,
                depth=input_event.depth + 1,
                tags={
                    "http",
                    "negative",
                    "probe-failed",
                    f"scheme:{result.scheme}",
                },
                metadata={
                    "scheme": result.scheme,
                    "url": result.url,
                    "error": result.error,
                    # A timeout/connection error is not authoritative evidence
                    # that a previously observed service disappeared. Keep it
                    # as negative knowledge, but do not feed it to snapshots.
                    "snapshot_eligible": False,
                    "absence_confirmed": False,
                },
            )
            await self._publisher.publish(failure)
            return

        if result.status_code is None:
            return

        url_event = Event(
            type=EventType.URL,
            value=result.url,
            source=(
                f"http:{_source_component(self._backend.name)}:"
                f"{result.scheme}:url"
            ),
            parent_event_id=input_event.event_id,
            scope_state=input_event.scope_state,
            confidence=self._config.service_confidence,
            novelty=0.45,
            depth=input_event.depth + 1,
            tags={
                "http",
                "url",
                "confirmed",
                f"scheme:{result.scheme}",
            },
            metadata={
                "root_probe": True,
                "hostname": result.hostname,
                "port": result.port,
                "scheme": result.scheme,
            },
        )
        await self._publisher.publish(url_event)

        service_event = Event(
            type=EventType.HTTP_SERVICE,
            value=http_service_identity(result),
            source=(
                f"http:{_source_component(self._backend.name)}:"
                f"{result.scheme}:service"
            ),
            parent_event_id=input_event.event_id,
            scope_state=input_event.scope_state,
            confidence=self._config.service_confidence,
            novelty=0.55,
            depth=input_event.depth + 1,
            tags={
                "http",
                "service",
                "confirmed",
                f"scheme:{result.scheme}",
            },
            metadata={
                "hostname": result.hostname,
                "port": result.port,
                "scheme": result.scheme,
                "url": result.url,
                "status_code": result.status_code,
            },
        )
        await self._publisher.publish(service_event)

        response_event = Event(
            type=EventType.HTTP_RESPONSE,
            value=(
                f"{result.method} {result.url} -> "
                f"{result.status_code}"
            ),
            source=(
                f"http:{_source_component(self._backend.name)}:"
                f"{result.scheme}:response"
            ),
            parent_event_id=input_event.event_id,
            scope_state=input_event.scope_state,
            confidence=self._config.response_confidence,
            novelty=0.60,
            depth=input_event.depth + 1,
            tags={
                "http",
                "response",
                "confirmed",
                "snapshot:http",
                f"scheme:{result.scheme}",
                f"status:{result.status_code}",
            },
            metadata={
                "url": result.url,
                "scheme": result.scheme,
                "hostname": result.hostname,
                "port": result.port,
                "method": result.method,
                "status_code": result.status_code,
                "title": result.title,
                "body_sha256": result.body_sha256,
                "content_type": result.content_type,
                "content_length": result.content_length,
                "location": result.location,
                "webserver": result.webserver,
                "technologies": list(
                    result.technologies
                ),
                "response_time": result.response_time,
                "body_hash_algorithm": "sha256",
                "body_hash_read_limit_bytes": (
                    getattr(
                        getattr(
                            self._backend,
                            "config",
                            None,
                        ),
                        "max_response_read_bytes",
                        None,
                    )
                ),
                "snapshot_kind": "HTTP",
                "surface_state": {
                    "present": True,
                    "ips": [],
                    "status_code": result.status_code,
                    "title": result.title,
                    "body_hash": result.body_sha256,
                    "certificate_fingerprints": [],
                    "certificate_sans": [],
                    "javascript_hashes": [],
                    "endpoint_keys": [],
                    "scope_state": input_event.scope_state.value,
                    "extra": {
                        "scheme": result.scheme,
                        "port": result.port,
                        "content_type": result.content_type,
                        "content_length": (
                            result.content_length
                        ),
                        "webserver": result.webserver,
                        "technologies": list(
                            result.technologies
                        ),
                    },
                },
                **result.metadata,
            },
        )
        await self._publisher.publish(response_event)

        for technology in result.technologies:
            technology_event = Event(
                type=EventType.TECHNOLOGY,
                value=technology,
                source=(
                    f"http:{_source_component(self._backend.name)}:"
                    f"{result.scheme}:technology"
                ),
                parent_event_id=input_event.event_id,
                scope_state=input_event.scope_state,
                confidence=self._config.technology_confidence,
                novelty=0.35,
                depth=input_event.depth + 1,
                tags={
                    "http",
                    "technology",
                    f"scheme:{result.scheme}",
                },
                metadata={
                    "observed_on": result.url,
                    "hostname": result.hostname,
                    "port": result.port,
                },
            )
            await self._publisher.publish(
                technology_event
            )

        redirect_url = redirect_target_url(result)
        if (
            redirect_url is not None
            and redirect_url != result.url
        ):
            redirect_event = Event(
                type=EventType.URL,
                value=redirect_url,
                source=(
                    f"http:{_source_component(self._backend.name)}:"
                    f"{result.scheme}:redirect"
                ),
                parent_event_id=input_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=self._config.redirect_confidence,
                novelty=0.70,
                depth=input_event.depth + 1,
                tags={
                    "http",
                    "redirect-target",
                    "hypothesis",
                },
                metadata={
                    "redirect_from": result.url,
                    "location": result.location,
                    "followed": False,
                    "requires_scope_reclassification": True,
                },
            )
            await self._publisher.publish(
                redirect_event
            )


def http_route_rules(
    *,
    base_priority: float = 8.5,
) -> tuple[RouteRule, ...]:
    """Route only confirmed DNS observations into active HTTP probing."""
    return (
        RouteRule(
            rule_id="http.probe.confirmed-dns",
            accepts=frozenset({EventType.DNS_NAME}),
            worker=WORKER_NAME,
            action=ACTION_PROBE,
            reason=(
                "probe confirmed DNS name for root HTTP/HTTPS services"
            ),
            base_priority=base_priority,
            required_tags=frozenset({"confirmed"}),
            excluded_tags=frozenset({"hypothesis"}),
        ),
    )


def root_url(
    hostname: str,
    *,
    scheme: str,
) -> str:
    normalized_host = normalize_dns_name(hostname)
    normalized_scheme = scheme.strip().lower()

    if normalized_scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")

    return f"{normalized_scheme}://{normalized_host}/"


def normalize_http_url(value: str) -> str:
    """Canonicalize an HTTP(S) URL without following it."""
    raw = value.strip()
    if not raw:
        raise ValueError("URL must not be blank")

    parts = urlsplit(raw)

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")

    if parts.username is not None or parts.password is not None:
        raise ValueError("userinfo is not allowed in probe URLs")

    if parts.hostname is None:
        raise ValueError("URL hostname is required")

    hostname = normalize_dns_name(parts.hostname)

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc

    default_port = 443 if scheme == "https" else 80

    if port is None or port == default_port:
        netloc = hostname
    else:
        netloc = f"{hostname}:{port}"

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


def http_service_identity(
    result: HTTPProbeResult,
) -> str:
    """Canonical service identity includes scheme and concrete port."""
    return (
        f"{result.scheme}://"
        f"{result.hostname}:{result.port}"
    )


def redirect_target_url(
    result: HTTPProbeResult,
) -> str | None:
    """Resolve a Location header without requesting it."""
    if result.location is None:
        return None

    try:
        combined = urljoin(
            result.url,
            result.location,
        )
        return normalize_http_url(combined)
    except ValueError:
        return None


def parse_httpx_line(
    line: str,
) -> HTTPProbeResult | None:
    """Parse one current/future-tolerant httpx JSONL object."""
    normalized_line = line.strip()
    if not normalized_line:
        return None

    try:
        payload = json.loads(normalized_line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    raw_url = payload.get("url")
    if not isinstance(raw_url, str):
        return None

    try:
        url = normalize_http_url(raw_url)
    except ValueError:
        return None

    parts = urlsplit(url)
    if parts.hostname is None:
        return None

    hostname = normalize_dns_name(parts.hostname)
    scheme = parts.scheme.lower()

    raw_port = payload.get("port")
    port = _parse_port(raw_port)

    if port is None:
        port = parts.port or (
            443 if scheme == "https" else 80
        )

    input_value = payload.get("input")
    if isinstance(input_value, str):
        try:
            input_url = normalize_http_url(
                input_value
                if "://" in input_value
                else f"{scheme}://{input_value}/"
            )
        except ValueError:
            input_url = url
    else:
        input_url = url

    status_code = _parse_status_code(
        payload.get("status_code")
    )

    technologies = _string_values(
        payload.get("tech")
    )

    body_sha256 = _body_sha256(
        payload.get("hash")
    )

    failed = bool(
        payload.get("failed", False)
    )

    error = _first_text(
        payload,
        (
            "error",
            "err",
        ),
    )

    known = {
        "timestamp",
        "url",
        "input",
        "title",
        "scheme",
        "webserver",
        "content_type",
        "method",
        "host",
        "path",
        "time",
        "tech",
        "status_code",
        "content_length",
        "failed",
        "error",
        "err",
        "location",
        "port",
        "hash",
        "words",
        "lines",
        "knowledgebase",
        "resolvers",
        "a",
        "aaaa",
        "cname",
    }

    metadata = {
        key: value
        for key, value in payload.items()
        if key not in known
    }

    return HTTPProbeResult(
        input_url=input_url,
        url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        method=(
            _first_text(
                payload,
                ("method",),
            )
            or "GET"
        ),
        status_code=status_code,
        title=_first_text(
            payload,
            ("title",),
        ),
        body_sha256=body_sha256,
        content_type=_first_text(
            payload,
            ("content_type", "content-type"),
        ),
        content_length=_parse_nonnegative_int(
            payload.get("content_length")
        ),
        location=_first_text(
            payload,
            ("location",),
        ),
        webserver=_first_text(
            payload,
            ("webserver", "server"),
        ),
        technologies=technologies,
        response_time=(
            payload.get("time")
            if "time" in payload
            else payload.get("response_time")
        ),
        failed=failed,
        error=error,
        metadata=metadata,
    )


def _result_matches_request(
    result: HTTPProbeResult,
    *,
    hostname: str,
    scheme: str,
) -> bool:
    """Reject malformed/misdirected subprocess output."""
    return (
        result.hostname == hostname
        and result.scheme == scheme
    )


def _body_sha256(value: Any) -> str | None:
    """Extract SHA-256 body hash across known httpx JSON shapes."""
    if isinstance(value, dict):
        for key in (
            "body_sha256",
            "body-sha256",
            "sha256",
        ):
            candidate = value.get(key)
            if isinstance(candidate, str):
                normalized = candidate.strip().lower()
                if _looks_like_sha256(normalized):
                    return normalized

    if isinstance(value, str):
        normalized = value.strip().lower()
        if _looks_like_sha256(normalized):
            return normalized

    return None


def _looks_like_sha256(value: str) -> bool:
    return (
        len(value) == 64
        and all(
            character in "0123456789abcdef"
            for character in value
        )
    )


def _parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def _parse_status_code(value: Any) -> int | None:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None

    if 100 <= status <= 599:
        return status

    return None


def _parse_nonnegative_int(
    value: Any,
) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None

    return parsed if parsed >= 0 else None


def _string_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        normalized = value.strip()
        return (normalized,) if normalized else ()

    if isinstance(value, (list, tuple, set)):
        return tuple(
            sorted(
                {
                    str(item).strip()
                    for item in value
                    if str(item).strip()
                }
            )
        )

    return ()


def _first_text(
    payload: dict[str, Any],
    keys: Sequence[str],
) -> str | None:
    for key in keys:
        value = payload.get(key)

        if value is None:
            continue

        normalized = str(value).strip()
        if normalized:
            return normalized

    return None


def _source_component(value: str) -> str:
    normalized = value.strip().lower()
    normalized = _SOURCE_COMPONENT_RE.sub(
        "-",
        normalized,
    ).strip("-")
    return normalized or "unknown"


def _resolve_executable(binary: str) -> str | None:
    candidate = Path(binary).expanduser()

    if (
        candidate.parent != Path(".")
        or candidate.is_absolute()
    ):
        if (
            candidate.exists()
            and os.access(candidate, os.X_OK)
        ):
            return str(candidate.resolve())

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
