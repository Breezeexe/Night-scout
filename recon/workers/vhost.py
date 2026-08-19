"""Bounded Host-header virtual-host discovery for Night Scout.

This worker tests candidate HTTP Host header values against an already confirmed
HTTP service. It performs no DNS ownership inference and never treats a virtual
host response as DNS confirmation.

Safety boundary
---------------
A lifecycle scope gate authorizes the *input* HTTP_SERVICE, but one VHOST task
can consider many candidate Host values. Every candidate is therefore
classified again before any network request. Only candidates explicitly
classified `ScopeState.IN_SCOPE` are sent.

The initial backend intentionally uses one ProjectDiscovery httpx subprocess per
candidate instead of a multi-request fuzzer. This preserves the strongest Night
Scout invariant:

    one shared RateLimiter permit == one target HTTP request

httpx is invoked with one explicit URL, one GET, retries=0, redirects disabled,
a bounded response read, and a custom Host header. Raw requests/responses and
bodies are not stored.

VHOST evidence is not DNS evidence
----------------------------------
A response that differs from the default virtual host emits:

    HTTP_RESPONSE  tags: vhost, differential, vhost-confirmed
    DNS_NAME       tags: vhost, hypothesis, requires-dns-confirmation

The DNS_NAME is never tagged generic `confirmed`; `workers/dns.py` must still
confirm DNS separately before downstream DNS-confirmed routes may use it.

False-positive control
----------------------
The known service Host header is requested twice. Response dimensions that are
unstable between those two controls (for example a dynamic body hash) are
excluded from differential matching. Candidate responses are compared only on
stable baseline dimensions such as status, content length, word/line counts,
body SHA-256, title, Location, and server.

Candidate intelligence
----------------------
The default candidate provider consumes the same WordCorpusProvider used by
`workers/permutations.py`:

- TARGETED lane: words for which the target itself supplied evidence;
- EXPLORATION lane: globally sourced long-tail words via a rotating cursor.

For a service such as `api.example.com`, direct candidates can be produced both
as siblings (`admin.example.com`) and children (`admin.api.example.com`). Scope
classification is the final authorization filter, so public-suffix heuristics
cannot silently broaden active work.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Sequence
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
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
from recon.policy.scope import (
    ScopeAssetKind,
    ScopeDecision,
    ScopeEngine,
    ScopeSubject,
)
from recon.workers.http import normalize_http_url
from recon.workers.passive_domains import normalize_dns_name
from recon.workers.permutations import (
    CandidateLane,
    ExplorationCursorStore,
    InMemoryExplorationCursorStore,
    PermutationWord,
    WordCorpusProvider,
)


WORKER_NAME = "vhost"
ACTION_DISCOVER_TARGETED = "discover_targeted"
ACTION_DISCOVER_EXPLORATION = "discover_exploration"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VHostCandidateMethod(StrEnum):
    WORD_SIBLING = "WORD_SIBLING"
    WORD_CHILD = "WORD_CHILD"


class VHostCandidate(BaseModel):
    """One fully-qualified Host-header candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    lane: CandidateLane
    method: VHostCandidateMethod

    score: float = 0.0
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    word_token: str
    global_sources: frozenset[str] = Field(default_factory=frozenset)
    target_sources: frozenset[str] = Field(default_factory=frozenset)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @field_validator("word_token")
    @classmethod
    def word_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("word_token must not be blank")
        return normalized


class VHostService(BaseModel):
    """Confirmed transport service against which Host values are tested."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    scheme: str
    transport_hostname: str
    port: int = Field(ge=1, le=65535)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return normalize_http_url(value)

    @field_validator("scheme")
    @classmethod
    def normalize_scheme(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        return normalized

    @field_validator("transport_hostname")
    @classmethod
    def normalize_transport_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @model_validator(mode="after")
    def url_matches_service(self) -> "VHostService":
        parts = urlsplit(self.url)

        if parts.hostname is None:
            raise ValueError("service URL requires hostname")

        url_hostname = normalize_dns_name(parts.hostname)
        url_port = parts.port or (443 if parts.scheme == "https" else 80)

        if url_hostname != self.transport_hostname:
            raise ValueError("service URL hostname does not match transport host")

        if parts.scheme != self.scheme:
            raise ValueError("service URL scheme does not match service scheme")

        if url_port != self.port:
            raise ValueError("service URL port does not match service port")

        return self


class VHostProbeResult(BaseModel):
    """One response to one explicit Host-header request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requested_url: str
    transport_hostname: str
    host_header: str

    status_code: int | None = Field(default=None, ge=100, le=599)

    title: str | None = None
    body_sha256: str | None = None

    content_type: str | None = None
    content_length: int | None = Field(default=None, ge=0)
    word_count: int | None = Field(default=None, ge=0)
    line_count: int | None = Field(default=None, ge=0)

    location: str | None = None
    webserver: str | None = None
    response_time: str | float | int | None = None

    failed: bool = False
    error: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("requested_url")
    @classmethod
    def normalize_requested_url(cls, value: str) -> str:
        return normalize_http_url(value)

    @field_validator("transport_hostname", "host_header")
    @classmethod
    def normalize_hostnames(cls, value: str) -> str:
        # Host headers in this initial worker are hostname-only. The HTTP
        # library handles the transport port from the URL.
        return normalize_dns_name(value)

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

    @field_validator("body_sha256")
    @classmethod
    def validate_body_sha256(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.lower().replace(":", "")
        if _SHA256_RE.fullmatch(normalized) is None:
            raise ValueError("body_sha256 must be a SHA-256 hex digest")

        return normalized


class VHostResponseSignature(BaseModel):
    """Response dimensions used for stable-baseline comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status_code: int | None = None
    body_sha256: str | None = None
    content_length: int | None = None
    word_count: int | None = None
    line_count: int | None = None
    title: str | None = None
    location: str | None = None
    webserver: str | None = None


class VHostDifferential(BaseModel):
    """Explainable candidate-vs-baseline differential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stable_dimensions: tuple[str, ...]
    changed_dimensions: tuple[str, ...]

    score: float = Field(ge=0.0)
    interesting: bool


class InputEventProvider(Protocol):
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class VHostCandidateProvider(Protocol):
    async def candidates_for(
        self,
        service_event: Event,
        *,
        lane: CandidateLane,
        limit: int,
    ) -> Sequence[VHostCandidate]:
        ...


class VHostCandidateScopeProvider(Protocol):
    """Per-candidate authorization boundary before any Host request."""

    async def classify(self, hostname: str) -> ScopeDecision:
        ...


class VHostProbeBackend(Protocol):
    """One explicit Host header -> one HTTP request backend."""

    name: str

    def ensure_available(self) -> None:
        ...

    async def probe(
        self,
        service: VHostService,
        *,
        host_header: str,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[VHostProbeResult]:
        ...


class ScopeEngineVHostCandidateScopeProvider:
    """Adapt the existing synchronous ScopeEngine to candidate filtering."""

    def __init__(self, engine: ScopeEngine) -> None:
        self._engine = engine

    async def classify(self, hostname: str) -> ScopeDecision:
        return self._engine.evaluate(
            ScopeSubject(
                kind=ScopeAssetKind.DOMAIN,
                value=hostname,
            )
        )


class WordlistVHostCandidateProvider:
    """Build bounded VHOST names from the shared WordCorpusProvider."""

    def __init__(
        self,
        *,
        words: WordCorpusProvider,
        cursor: ExplorationCursorStore | None = None,
        include_sibling_candidates: bool = True,
        include_child_candidates: bool = True,
        max_base_domains: int = 4,
    ) -> None:
        if not (include_sibling_candidates or include_child_candidates):
            raise ValueError("at least one VHOST candidate shape is required")

        if max_base_domains <= 0:
            raise ValueError("max_base_domains must be positive")

        self._words = words
        self._cursor = cursor or InMemoryExplorationCursorStore()
        self._include_sibling = include_sibling_candidates
        self._include_child = include_child_candidates
        self._max_base_domains = max_base_domains

    async def candidates_for(
        self,
        service_event: Event,
        *,
        lane: CandidateLane,
        limit: int,
    ) -> Sequence[VHostCandidate]:
        if limit <= 0:
            return ()

        service = service_from_event(service_event)
        words = tuple(await self._words.words_for(service_event))

        if lane is CandidateLane.TARGETED:
            selected = [
                word
                for word in words
                if word.lane is CandidateLane.TARGETED
            ]
            selected.sort(
                key=lambda word: (
                    -word.ranking_score,
                    word.token.lower(),
                )
            )

        else:
            exploration = [
                word
                for word in words
                if word.lane is CandidateLane.EXPLORATION
            ]
            exploration.sort(
                key=lambda word: (
                    word.global_rank
                    if word.global_rank is not None
                    else 2**31,
                    -word.global_score,
                    word.token.lower(),
                )
            )

            if not exploration:
                selected = []
            else:
                # A word may produce more than one hostname shape, so the
                # window is bounded at the word level and then output is
                # bounded again after hostname dedupe.
                word_window = max(1, math.ceil(limit / 2))
                indexes = await self._cursor.claim_window(
                    namespace=(
                        "vhost:exploration:"
                        + service.transport_hostname
                    ),
                    pool_size=len(exploration),
                    window_size=min(
                        word_window,
                        len(exploration),
                    ),
                )
                selected = [exploration[index] for index in indexes]

        base_domains = candidate_base_domains(
            service_event,
            service=service,
            include_sibling=self._include_sibling,
            include_child=self._include_child,
        )[: self._max_base_domains]

        candidates: dict[str, VHostCandidate] = {}

        for word in selected:
            for label in word.label_variants():
                for base_domain, method in base_domains:
                    try:
                        hostname = normalize_dns_name(
                            f"{label}.{base_domain}"
                        )
                    except ValueError:
                        continue

                    if hostname == service.transport_hostname:
                        continue

                    candidate = VHostCandidate(
                        hostname=hostname,
                        lane=lane,
                        method=method,
                        score=word.ranking_score,
                        confidence=word.confidence,
                        word_token=word.token,
                        global_sources=word.global_sources,
                        target_sources=word.target_sources,
                        metadata={
                            "base_domain": base_domain,
                            "global_rank": word.global_rank,
                            "global_score": word.global_score,
                            "target_frequency": word.target_frequency,
                            "target_source_diversity": (
                                word.target_source_diversity
                            ),
                            "target_relevance": word.target_relevance,
                            "successful_hits": word.successful_hits,
                            "attempted_hypotheses": word.attempted_hypotheses,
                            **word.metadata,
                        },
                    )

                    existing = candidates.get(hostname)
                    if (
                        existing is None
                        or (
                            candidate.score,
                            candidate.confidence,
                        )
                        > (
                            existing.score,
                            existing.confidence,
                        )
                    ):
                        candidates[hostname] = candidate

        return tuple(
            sorted(
                candidates.values(),
                key=lambda candidate: (
                    -candidate.score,
                    -candidate.confidence,
                    candidate.hostname,
                ),
            )[:limit]
        )


class HttpxVHostConfig(BaseModel):
    """One-request ProjectDiscovery httpx VHOST probe configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "httpx"

    timeout_seconds: int = Field(default=10, ge=1, le=120)
    process_timeout_seconds: float = Field(default=20.0, gt=0.0)

    max_response_read_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=4096,
        le=64 * 1024 * 1024,
    )

    user_agent: str = "NightScout/0.1 authorized-security-research"

    stderr_tail_lines: int = Field(default=100, ge=1, le=2000)
    stream_limit_bytes: int = Field(
        default=4 * 1024 * 1024,
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

    @field_validator("extra_args")
    @classmethod
    def reject_unsafe_overrides(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            value.strip()
            for value in values
            if value.strip()
        )

        forbidden = {
            # Input/method/request expansion.
            "-u", "-target", "-l", "-list", "-rr", "-request",
            "-im", "-input-mode", "-x", "-body", "-path", "-p", "-ports",
            "-pa", "-probe-all-ips", "-tls-probe", "-csp-probe",
            "-tls-grab", "-pipeline", "-http2", "-vhost", "-vhost-input",
            "-favicon", "-jarm", "-ss", "-screenshot",

            # Identity/auth/session/network routing.
            "-H", "-header", "-sf", "-secret-file", "-auth", "-ac",
            "-auth-config", "-auto-referer", "-proxy", "-http-proxy",
            "-sni", "-sni-name", "-unsafe", "-tlsi", "-tls-impersonate",
            "-resolvers", "-r", "-allow", "-deny", "-config", "-resume",
            "-random-agent", "-hae", "-http-api-endpoint",

            # Redirect behavior must remain disabled.
            "-fr", "-follow-redirects", "-fhr", "-follow-host-redirects",
            "-maxr", "-max-redirects", "-rhsts", "-respect-hsts",

            # One permit maps to one request; caller owns rate/concurrency.
            "-retries", "-timeout", "-delay", "-t", "-threads",
            "-rl", "-rate-limit", "-rlm", "-rate-limit-minute",

            # Exact input scheme only.
            "-nf", "-no-fallback", "-nfs", "-no-fallback-scheme",

            # Structured probe/output ownership.
            "-j", "-json", "-sc", "-status-code", "-cl", "-content-length",
            "-ct", "-content-type", "-location", "-hash", "-rt",
            "-response-time", "-title", "-server", "-web-server", "-method",
            "-wc", "-word-count", "-lc", "-line-count", "-probe",
            "-mc", "-match-code", "-ml", "-match-length", "-mlc",
            "-match-line-count", "-mwc", "-match-word-count", "-ms",
            "-match-string", "-mr", "-match-regex", "-mdc",
            "-match-condition", "-fc", "-filter-code", "-fl",
            "-filter-length", "-flc", "-filter-line-count", "-fwc",
            "-filter-word-count", "-fs", "-filter-string", "-fe",
            "-filter-regex", "-fd", "-filter-duplicates", "-fdc",
            "-filter-condition", "-fpt", "-filter-page-type",
            "-er", "-extract-regex", "-ep", "-extract-preset",
            "-rstr", "-response-size-to-read", "-rsts", "-response-size-to-save",
            "-irr", "-include-response", "-irrb", "-include-response-base64",
            "-irh", "-include-response-header", "-sr", "-store-response",
            "-srd", "-store-response-dir", "-o", "-output", "-oa",
            "-output-all", "-csv", "-result-db", "-rdb",

            # Debug/cloud/update side effects.
            "-debug", "-debug-req", "-debug-resp", "-v", "-verbose",
            "-pd", "-dashboard", "-pdu", "-dashboard-upload", "-tid",
            "-team-id", "-aid", "-asset-id", "-up", "-update",
        }

        def flag_name(value: str) -> str:
            name = value.split("=", 1)[0]
            if name.startswith("--"):
                name = "-" + name[2:]
            return name

        if any(flag_name(value) in forbidden for value in normalized):
            raise ValueError(
                "httpx vhost extra_args cannot override target/method, Host "
                "identity, authentication/configuration, redirects, shared "
                "rate control, matching/filtering, probe fields, raw response "
                "storage, or cloud/debug output"
            )

        return normalized


class VHostWorkerConfig(BaseModel):
    """Candidate limits and differential scoring."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    targeted_limit: int = Field(default=250, ge=1, le=100_000)
    exploration_limit: int = Field(default=100, ge=1, le=100_000)

    rate_lease_seconds: float = Field(default=30.0, gt=0.0)
    default_retry_after_seconds: float = Field(default=5.0, ge=0.0)

    min_differential_score: float = Field(default=2.0, ge=0.0)
    min_stable_dimensions: int = Field(default=1, ge=1, le=8)

    vhost_confidence_base: float = Field(default=0.72, ge=0.0, le=1.0)
    vhost_confidence_ceiling: float = Field(default=0.96, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def confidence_bounds(self) -> "VHostWorkerConfig":
        if self.vhost_confidence_base > self.vhost_confidence_ceiling:
            raise ValueError(
                "vhost confidence base cannot exceed ceiling"
            )
        return self


class VHostBackendError(RuntimeError):
    """VHOST probe backend failure."""


class VHostBackendUnavailable(VHostBackendError):
    """Configured httpx binary is unavailable."""


class VHostBackendTimeout(VHostBackendError):
    """One httpx VHOST probe exceeded the outer timeout."""


class HttpxVHostBackend:
    """ProjectDiscovery httpx adapter: one Host header per subprocess."""

    name = "httpx"

    def __init__(
        self,
        config: HttpxVHostConfig | None = None,
    ) -> None:
        self.config = config or HttpxVHostConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise VHostBackendUnavailable(
                f"httpx executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        host_header: str,
        rate_limit_rps: int | None,
    ) -> tuple[str, ...]:
        candidate = normalize_dns_name(host_header)
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-nfs",
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
            "-wc",
            "-lc",
            "-probe",
            "-hash",
            "sha256",
            "-rstr",
            str(self.config.max_response_read_bytes),
            "-H",
            f"Host: {candidate}",
            "-H",
            f"User-Agent: {self.config.user_agent}",
        ]

        if rate_limit_rps is not None:
            args.extend(("-rl", str(rate_limit_rps)))

        args.extend(self.config.extra_args)
        return tuple(args)

    async def probe(
        self,
        service: VHostService,
        *,
        host_header: str,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[VHostProbeResult]:
        candidate = normalize_dns_name(host_header)
        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(
                host_header=candidate,
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
            await _terminate_process(process)
            raise VHostBackendError(
                "httpx VHOST subprocess pipes were not created"
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
                (service.url + "\n").encode("utf-8")
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

                        result = parse_httpx_vhost_line(
                            line,
                            service=service,
                            host_header=candidate,
                        )

                        if result is not None:
                            yield result

                    returncode = await process.wait()

            except TimeoutError as exc:
                await _terminate_process(process)
                raise VHostBackendTimeout(
                    "httpx VHOST probe exceeded outer process timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(stderr_tail)
                raise VHostBackendError(
                    "httpx VHOST probe exited unsuccessfully "
                    f"(returncode={returncode})"
                    + (f"; stderr_tail={detail}" if detail else "")
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


class VHostWorker:
    """Scope-filtered, one-request-per-permit VHOST discovery worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        candidates: VHostCandidateProvider,
        candidate_scope: VHostCandidateScopeProvider,
        rate_limiter: RateLimiter,
        backend: VHostProbeBackend | None = None,
        config: VHostWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._candidates = candidates
        self._candidate_scope = candidate_scope
        self._rate_limiter = rate_limiter
        self._backend = backend or HttpxVHostBackend()
        self._config = config or VHostWorkerConfig()

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "vhost worker may only execute claimed RUNNING tasks, "
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

        lane = lane_for_action(task.action)

        if lane is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported vhost action: {task.action}",
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
            service = service_from_event(input_event)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        try:
            self._backend.ensure_available()
        except VHostBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        candidate_limit = (
            self._config.targeted_limit
            if lane is CandidateLane.TARGETED
            else self._config.exploration_limit
        )

        raw_candidates = tuple(
            await self._candidates.candidates_for(
                input_event,
                lane=lane,
                limit=candidate_limit,
            )
        )

        # Lifecycle authorizes the input service, not every Host header. Filter
        # the whole candidate set first and retain the exact ScopeDecision for
        # emitted evidence.
        authorized: list[
            tuple[VHostCandidate, ScopeDecision]
        ] = []

        for candidate in raw_candidates:
            if candidate.lane is not lane:
                continue

            scope_decision = await self._candidate_scope.classify(
                candidate.hostname
            )

            if scope_decision.state is not ScopeState.IN_SCOPE:
                continue

            authorized.append(
                (
                    candidate,
                    scope_decision,
                )
            )

        if not authorized:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.SUCCEEDED
            )

        # Unknown-host behavior can vary by parent suffix. Build a separate
        # control baseline for every immediate candidate parent instead of
        # comparing all candidates to the known primary virtual host.
        grouped: dict[
            str,
            list[
                tuple[VHostCandidate, ScopeDecision]
            ],
        ] = {}

        for item in authorized:
            candidate, _scope_decision = item
            parent = immediate_parent_domain(
                candidate.hostname
            )

            if parent is None:
                continue

            grouped.setdefault(
                parent,
                [],
            ).append(item)

        for parent_domain in sorted(grouped):
            controls = deterministic_control_hostnames(
                parent_domain,
                service=service,
                input_event=input_event,
            )

            # Crucial fail-closed boundary: generated controls are active Host
            # values too. If either one is not explicitly IN_SCOPE, do not use
            # a less reliable known-host baseline and do not test this group.
            control_decisions = []

            for control in controls:
                decision = await self._candidate_scope.classify(
                    control
                )

                if decision.state is not ScopeState.IN_SCOPE:
                    control_decisions = []
                    break

                control_decisions.append(decision)

            if len(control_decisions) != 2:
                continue

            baseline_results: list[VHostProbeResult] = []

            for control in controls:
                probe_result = await self._probe_one(
                    task,
                    service=service,
                    host_header=control,
                )

                if isinstance(probe_result, WorkerExecutionResult):
                    return probe_result

                if probe_result.failed:
                    return WorkerExecutionResult(
                        outcome=WorkerOutcome.RETRY,
                        error=(
                            "VHOST unknown-host control request failed for "
                            f"parent {parent_domain}"
                        ),
                        retry_after_seconds=(
                            self._config.default_retry_after_seconds
                        ),
                    )

                baseline_results.append(probe_result)

            baseline_a, baseline_b = baseline_results

            stable_dimensions = stable_signature_dimensions(
                response_signature(baseline_a),
                response_signature(baseline_b),
            )

            if (
                len(stable_dimensions)
                < self._config.min_stable_dimensions
            ):
                # This parent has no reliable unknown-host baseline. Skip it
                # rather than turning dynamic noise into VHOST findings.
                continue

            for (
                candidate,
                scope_decision,
            ) in grouped[parent_domain]:
                probe_result = await self._probe_one(
                    task,
                    service=service,
                    host_header=candidate.hostname,
                )

                if isinstance(probe_result, WorkerExecutionResult):
                    # Earlier findings have already been persisted. Retrying
                    # later does not discard partial yield.
                    return probe_result

                if probe_result.failed:
                    continue

                differential = compare_to_baseline(
                    response_signature(baseline_a),
                    response_signature(probe_result),
                    stable_dimensions=stable_dimensions,
                    min_score=self._config.min_differential_score,
                )

                if not differential.interesting:
                    continue

                await self._publish_hit(
                    input_event=input_event,
                    service=service,
                    candidate=candidate,
                    scope_decision=scope_decision,
                    baseline=baseline_a,
                    baseline_control_hostnames=controls,
                    result=probe_result,
                    differential=differential,
                )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED
        )

    async def _probe_one(
        self,
        task: Task,
        *,
        service: VHostService,
        host_header: str,
    ) -> VHostProbeResult | WorkerExecutionResult:
        context = RateLimitContext(
            resource_keys=frozenset(
                {
                    f"host:{service.transport_hostname}"
                }
            )
        )

        plan = self._rate_limiter.plan(
            task,
            context=context,
        )

        cli_rps = tool_integer_rps_hint(plan)

        decision = await self._rate_limiter.acquire(
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
                    or "VHOST shared rate limit temporarily exhausted"
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
                    or "VHOST shared rate policy denied request"
                ),
            )

        lease_id = (
            decision.lease.lease_id
            if decision.lease is not None
            else None
        )

        try:
            results: list[VHostProbeResult] = []

            async for result in self._backend.probe(
                service,
                host_header=host_header,
                rate_limit_rps=cli_rps,
            ):
                if not result_matches_probe(
                    result,
                    service=service,
                    host_header=host_header,
                ):
                    continue

                results.append(result)

                if len(results) > 1:
                    return WorkerExecutionResult(
                        outcome=WorkerOutcome.FAILED,
                        error=(
                            "VHOST backend emitted more than one result for "
                            "one explicit Host-header request"
                        ),
                    )

            if not results:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=(
                        "VHOST backend produced no result for explicit "
                        f"Host header {host_header}"
                    ),
                    retry_after_seconds=self._config.default_retry_after_seconds,
                )

            return results[0]

        except VHostBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.default_retry_after_seconds,
            )
        except VHostBackendError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.default_retry_after_seconds,
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(lease_id)

    async def _publish_hit(
        self,
        *,
        input_event: Event,
        service: VHostService,
        candidate: VHostCandidate,
        scope_decision: ScopeDecision,
        baseline: VHostProbeResult,
        baseline_control_hostnames: tuple[str, str],
        result: VHostProbeResult,
        differential: VHostDifferential,
    ) -> None:
        confidence = min(
            self._config.vhost_confidence_ceiling,
            self._config.vhost_confidence_base
            + min(differential.score, 8.0) * 0.025
            + candidate.confidence * 0.05,
        )

        source = (
            f"vhost:{_source_component(self._backend.name)}"
        )

        response_event = Event(
            type=EventType.HTTP_RESPONSE,
            value=(
                f"GET {service.url} Host:{candidate.hostname} -> "
                f"{result.status_code if result.status_code is not None else 'FAILED'}"
            ),
            source=source,
            parent_event_id=input_event.event_id,
            scope_state=ScopeState.IN_SCOPE,
            confidence=confidence,
            novelty=0.90,
            depth=input_event.depth + 1,
            tags={
                "vhost",
                "differential",
                "vhost-confirmed",
                f"lane:{candidate.lane.value.lower()}",
                (
                    f"status:{result.status_code}"
                    if result.status_code is not None
                    else "status:unknown"
                ),
            },
            metadata={
                "service_url": service.url,
                "transport_hostname": service.transport_hostname,
                "transport_port": service.port,
                "scheme": service.scheme,
                "host_header": candidate.hostname,
                "method": "GET",
                "status_code": result.status_code,
                "title": result.title,
                "body_sha256": result.body_sha256,
                "content_type": result.content_type,
                "content_length": result.content_length,
                "word_count": result.word_count,
                "line_count": result.line_count,
                "location": result.location,
                "webserver": result.webserver,
                "response_time": result.response_time,
                "baseline_host_headers": list(
                    baseline_control_hostnames
                ),
                "baseline_signature": response_signature(
                    baseline
                ).model_dump(),
                "stable_baseline_dimensions": list(
                    differential.stable_dimensions
                ),
                "changed_dimensions": list(
                    differential.changed_dimensions
                ),
                "differential_score": differential.score,
                "candidate_method": candidate.method.value,
                "candidate_word": candidate.word_token,
                "candidate_score": candidate.score,
                "candidate_confidence": candidate.confidence,
                "candidate_global_sources": sorted(
                    candidate.global_sources
                ),
                "candidate_target_sources": sorted(
                    candidate.target_sources
                ),
                "scope_matched_rule_id": scope_decision.matched_rule_id,
                "scope_matched_rule_ids": list(
                    scope_decision.matched_rule_ids
                ),
                "scope_tier": scope_decision.tier,
                "dns_confirmed": False,
                "redirect_followed": False,
                "raw_request_stored": False,
                "raw_response_stored": False,
                "response_body_stored": False,
                **candidate.metadata,
                **result.metadata,
            },
        )

        response_accepted = await self._publisher.publish(
            response_event
        )

        child_parent = (
            response_event.event_id
            if response_accepted
            else input_event.event_id
        )

        await self._publisher.publish(
            Event(
                type=EventType.DNS_NAME,
                value=candidate.hostname,
                source=source,
                parent_event_id=child_parent,
                scope_state=ScopeState.IN_SCOPE,
                confidence=confidence,
                novelty=0.94,
                depth=input_event.depth + 2,
                tags={
                    "vhost",
                    "vhost-discovered",
                    "hypothesis",
                    "requires-dns-confirmation",
                    f"lane:{candidate.lane.value.lower()}",
                },
                metadata={
                    "discovered_via": "HOST_HEADER_DIFFERENTIAL",
                    "transport_hostname": service.transport_hostname,
                    "transport_port": service.port,
                    "service_url": service.url,
                    "host_header": candidate.hostname,
                    "requires_dns_confirmation": True,
                    "dns_confirmed": False,
                    "scope_reclassified_before_request": True,
                    "scope_matched_rule_id": scope_decision.matched_rule_id,
                    "scope_matched_rule_ids": list(
                        scope_decision.matched_rule_ids
                    ),
                    "scope_tier": scope_decision.tier,
                    "differential_score": differential.score,
                    "changed_dimensions": list(
                        differential.changed_dimensions
                    ),
                    "candidate_method": candidate.method.value,
                    "candidate_word": candidate.word_token,
                    "candidate_global_sources": sorted(
                        candidate.global_sources
                    ),
                    "candidate_target_sources": sorted(
                        candidate.target_sources
                    ),
                    **candidate.metadata,
                },
            )
        )


def vhost_route_rules(
    *,
    targeted_priority: float = 6.75,
    exploration_priority: float = 4.25,
) -> tuple[RouteRule, ...]:
    """Route confirmed HTTP services into targeted + exploration lanes."""

    return (
        RouteRule(
            rule_id="vhost.discover-targeted.confirmed-http-service",
            accepts=frozenset({EventType.HTTP_SERVICE}),
            worker=WORKER_NAME,
            action=ACTION_DISCOVER_TARGETED,
            reason=(
                "test target-derived Host-header candidates against a "
                "confirmed HTTP service"
            ),
            base_priority=targeted_priority,
            required_tags=frozenset({"confirmed", "service"}),
            excluded_tags=frozenset({"hypothesis"}),
            predicate=_confirmed_http_service,
        ),
        RouteRule(
            rule_id="vhost.discover-exploration.confirmed-http-service",
            accepts=frozenset({EventType.HTTP_SERVICE}),
            worker=WORKER_NAME,
            action=ACTION_DISCOVER_EXPLORATION,
            reason=(
                "test a rotating global VHOST exploration window against a "
                "confirmed HTTP service"
            ),
            base_priority=exploration_priority,
            required_tags=frozenset({"confirmed", "service"}),
            excluded_tags=frozenset({"hypothesis"}),
            predicate=_confirmed_http_service,
        ),
    )


def _confirmed_http_service(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    try:
        service_from_event(event)
    except ValueError:
        return False

    return True


def lane_for_action(
    action: str,
) -> CandidateLane | None:
    if action == ACTION_DISCOVER_TARGETED:
        return CandidateLane.TARGETED

    if action == ACTION_DISCOVER_EXPLORATION:
        return CandidateLane.EXPLORATION

    return None


def service_from_event(
    event: Event,
) -> VHostService:
    """Validate one confirmed HTTP_SERVICE event."""

    if event.type is not EventType.HTTP_SERVICE:
        raise ValueError(
            "vhost discovery requires HTTP_SERVICE input"
        )

    if (
        "confirmed" not in event.tags
        or "hypothesis" in event.tags
    ):
        raise ValueError(
            "vhost discovery requires a confirmed non-hypothesis service"
        )

    raw_url = event.metadata.get("url")
    raw_hostname = event.metadata.get("hostname")
    raw_scheme = event.metadata.get("scheme")
    raw_port = event.metadata.get("port")

    if not isinstance(raw_url, str):
        raise ValueError("HTTP_SERVICE metadata.url is required")

    if not isinstance(raw_hostname, str):
        raise ValueError("HTTP_SERVICE metadata.hostname is required")

    if not isinstance(raw_scheme, str):
        raise ValueError("HTTP_SERVICE metadata.scheme is required")

    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "HTTP_SERVICE metadata.port must be an integer"
        ) from exc

    return VHostService(
        url=raw_url,
        scheme=raw_scheme,
        transport_hostname=raw_hostname,
        port=port,
    )


def candidate_base_domains(
    event: Event,
    *,
    service: VHostService,
    include_sibling: bool,
    include_child: bool,
) -> tuple[
    tuple[str, VHostCandidateMethod],
    ...,
]:
    """Return conservative sibling/child base domains.

    Explicit metadata is preferred. Without a public-suffix database, the
    immediate parent is only a generation hypothesis; candidate scope
    classification is the authorization boundary that prevents broadening.
    """

    result: list[
        tuple[str, VHostCandidateMethod]
    ] = []

    explicit_values: list[str] = []

    for key in (
        "vhost_base_domain",
        "seed_domain",
        "root_domain",
    ):
        value = event.metadata.get(key)
        if isinstance(value, str) and value.strip():
            explicit_values.append(value)

    raw_many = event.metadata.get("vhost_base_domains")
    if isinstance(raw_many, (list, tuple, set)):
        explicit_values.extend(
            str(value)
            for value in raw_many
            if str(value).strip()
        )

    for raw in explicit_values:
        try:
            base = normalize_dns_name(raw)
        except ValueError:
            continue

        if include_sibling:
            item = (base, VHostCandidateMethod.WORD_SIBLING)
            if item not in result:
                result.append(item)

    labels = service.transport_hostname.split(".")

    if include_sibling and len(labels) >= 3:
        parent = ".".join(labels[1:])
        item = (parent, VHostCandidateMethod.WORD_SIBLING)
        if item not in result:
            result.append(item)

    if include_child:
        item = (
            service.transport_hostname,
            VHostCandidateMethod.WORD_CHILD,
        )
        if item not in result:
            result.append(item)

    return tuple(result)


def immediate_parent_domain(
    hostname: str,
) -> str | None:
    """Return the DNS parent beneath which a one-label VHOST candidate lives."""

    normalized = normalize_dns_name(
        hostname
    )

    labels = normalized.split(
        "."
    )

    if len(labels) < 2:
        return None

    return ".".join(
        labels[1:]
    )


def deterministic_control_hostnames(
    parent_domain: str,
    *,
    service: VHostService,
    input_event: Event,
) -> tuple[str, str]:
    """Create two high-entropy unknown-host controls for one candidate parent.

    The values are deterministic for explainability/retries, but intentionally
    long enough that collision with a real virtual host is extremely unlikely.
    Both controls still require explicit IN_SCOPE classification before use.
    """

    parent = normalize_dns_name(
        parent_domain
    )

    seed = (
        f"{service.url}\n"
        f"{input_event.event_id}\n"
        f"{parent}"
    )

    digest = hashlib.sha256(
        seed.encode(
            "utf-8"
        )
    ).hexdigest()

    labels = (
        f"ns-vh-{digest[:16]}",
        f"ns-vh-{digest[16:32]}",
    )

    first = normalize_dns_name(
        f"{labels[0]}.{parent}"
    )
    second = normalize_dns_name(
        f"{labels[1]}.{parent}"
    )

    return (first, second)


def parse_httpx_vhost_line(
    line: str,
    *,
    service: VHostService,
    host_header: str,
) -> VHostProbeResult | None:
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

    if url != service.url:
        # A custom Host header must never let subprocess output silently change
        # the transport execution subject.
        return None

    hash_value = _body_sha256(payload.get("hash"))

    known = {
        "timestamp", "url", "input", "title", "scheme", "webserver",
        "content_type", "method", "host", "path", "time", "status_code",
        "content_length", "failed", "error", "err", "location", "port",
        "hash", "words", "lines", "probe_status", "knowledgebase",
    }

    safe_metadata = {
        key: value
        for key, value in payload.items()
        if key not in known
        and key not in {
            "body",
            "raw",
            "request",
            "response",
            "header",
            "headers",
        }
    }

    return VHostProbeResult(
        requested_url=url,
        transport_hostname=service.transport_hostname,
        host_header=host_header,
        status_code=_parse_status_code(
            payload.get("status_code")
        ),
        title=_first_text(payload, ("title",)),
        body_sha256=hash_value,
        content_type=_first_text(
            payload,
            ("content_type", "content-type"),
        ),
        content_length=_parse_nonnegative_int(
            payload.get("content_length")
        ),
        word_count=_parse_nonnegative_int(
            payload.get("words")
        ),
        line_count=_parse_nonnegative_int(
            payload.get("lines")
        ),
        location=_first_text(payload, ("location",)),
        webserver=_first_text(
            payload,
            ("webserver", "server"),
        ),
        response_time=(
            payload.get("time")
            if "time" in payload
            else payload.get("response_time")
        ),
        failed=bool(payload.get("failed", False)),
        error=_first_text(payload, ("error", "err")),
        metadata=safe_metadata,
    )


def result_matches_probe(
    result: VHostProbeResult,
    *,
    service: VHostService,
    host_header: str,
) -> bool:
    return (
        result.requested_url == service.url
        and result.transport_hostname == service.transport_hostname
        and result.host_header == normalize_dns_name(host_header)
    )


def response_signature(
    result: VHostProbeResult,
) -> VHostResponseSignature:
    return VHostResponseSignature(
        status_code=result.status_code,
        body_sha256=result.body_sha256,
        content_length=result.content_length,
        word_count=result.word_count,
        line_count=result.line_count,
        title=result.title,
        location=normalize_location_for_signature(
            result.location,
            hostnames=(
                result.transport_hostname,
                result.host_header,
            ),
        ),
        webserver=result.webserver,
    )


def stable_signature_dimensions(
    first: VHostResponseSignature,
    second: VHostResponseSignature,
) -> tuple[str, ...]:
    """Dimensions identical across two known-host controls."""

    result: list[str] = []

    for name in VHostResponseSignature.model_fields:
        left = getattr(first, name)
        right = getattr(second, name)

        if left is not None and left == right:
            result.append(name)

    return tuple(result)


def compare_to_baseline(
    baseline: VHostResponseSignature,
    candidate: VHostResponseSignature,
    *,
    stable_dimensions: Sequence[str],
    min_score: float,
) -> VHostDifferential:
    """Score only dimensions proven stable by duplicate control requests."""

    weights = {
        "status_code": 2.5,
        "body_sha256": 3.0,
        "content_length": 1.25,
        "word_count": 1.0,
        "line_count": 0.75,
        "title": 1.0,
        "location": 1.5,
        "webserver": 0.75,
    }

    changed: list[str] = []
    score = 0.0

    for name in stable_dimensions:
        if name not in VHostResponseSignature.model_fields:
            continue

        baseline_value = getattr(baseline, name)
        candidate_value = getattr(candidate, name)

        if candidate_value is None:
            continue

        if candidate_value != baseline_value:
            changed.append(name)
            score += weights.get(name, 0.5)

    return VHostDifferential(
        stable_dimensions=tuple(stable_dimensions),
        changed_dimensions=tuple(changed),
        score=score,
        interesting=(
            bool(changed)
            and score >= min_score
        ),
    )


def normalize_location_for_signature(
    value: str | None,
    *,
    hostnames: Sequence[str],
) -> str | None:
    """Remove expected reflected Host names from Location comparison."""

    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    for hostname in hostnames:
        try:
            host = normalize_dns_name(hostname)
        except ValueError:
            continue

        normalized = normalized.replace(
            host,
            "{host}",
        )

    return normalized


def _body_sha256(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in (
            "body_sha256",
            "body-sha256",
            "sha256",
        ):
            candidate = value.get(key)
            if isinstance(candidate, str):
                normalized = candidate.strip().lower().replace(":", "")
                if _SHA256_RE.fullmatch(normalized):
                    return normalized

    if isinstance(value, str):
        normalized = value.strip().lower().replace(":", "")
        if _SHA256_RE.fullmatch(normalized):
            return normalized

    return None


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


def _parse_status_code(value: Any) -> int | None:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None

    if 100 <= status <= 599:
        return status

    return None


def _parse_nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None

    return parsed if parsed >= 0 else None


def _source_component(value: str) -> str:
    normalized = value.strip().lower()
    normalized = _SOURCE_COMPONENT_RE.sub(
        "-",
        normalized,
    ).strip("-")
    return normalized or "unknown"


def _resolve_executable(binary: str) -> str | None:
    candidate = Path(binary).expanduser()

    if candidate.parent != Path(".") or candidate.is_absolute():
        if candidate.exists() and os.access(candidate, os.X_OK):
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