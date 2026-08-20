"""Bounded GET parameter discovery for Night Scout using Arjun.

This worker validates parameter-name hypotheses against an already discovered
HTTP API endpoint. It is active reconnaissance, but deliberately limited to
read-only GET query parameters.

Candidate lanes
---------------
Two independent task actions keep exploitation of learned target vocabulary
from starving long-tail discovery:

    discover_targeted
        Parameters already suggested by JavaScript, crawler output, historical
        data, Target Genome vocabulary, or previously productive patterns.

    discover_exploration
        Global-corpus parameter names not yet observed on this target. A
        rotating cursor prevents every run from retrying only the same top-N
        names.

Arjun receives a bounded custom wordlist from Night Scout for each task. The
initial adapter never asks Arjun to load its full built-in dictionary or its
passive sources automatically; corpus selection remains explainable in the
Night Scout intelligence layer.

Opaque subprocess rate accounting
----------------------------------
Arjun can make many requests internally, so one central request token cannot
represent one process. Like crawler.py, this worker therefore requires a
shared rule with both an RPS ceiling and max_concurrency:

1. derive the shared RateLimitPlan for host:<hostname>;
2. acquire all slots of the strictest matching concurrency rule;
3. configure Arjun itself to the full allowed host RPS (or conservative delay
   for sub-1-RPS policies);
4. release the exclusive lease when Arjun exits.

While the process owns the strict shared host slots, other active Night Scout
workers governed by that same host rule cannot concurrently touch the target.
If the necessary rate envelope is missing, the worker fails closed.

Safety defaults
---------------
- input: API_ENDPOINT by default;
- method: GET only;
- redirects disabled;
- one thread;
- bounded candidate count and Arjun chunk size;
- no POST/JSON/XML, request bodies, include-data, cookies, auth headers,
  imported raw requests, Burp export, proxying, passive-provider expansion, or
  casing mutations;
- no parameter values are persisted;
- output PARAMETER_NAME events are evidence of accepted names, not permission
  to exercise application functionality behind them.

Current Arjun JSON export is a mapping keyed by URL. Entries contain fields
such as method, params and headers. Night Scout reads only the URL/method/param
names and discards headers/values.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import shutil
import tempfile
from collections import deque
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimitOutcome,
    RateLimitPlan,
    RateLimiter,
)
from recon.workers.http import normalize_http_url
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "parameters"
ACTION_DISCOVER_TARGETED = "discover_targeted"
ACTION_DISCOVER_EXPLORATION = "discover_exploration"

_PARAMETER_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,128}$")
_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")


class ParameterLane(StrEnum):
    TARGETED = "TARGETED"
    EXPLORATION = "EXPLORATION"


class ParameterCandidate(BaseModel):
    """One explainable parameter-name hypothesis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str

    global_sources: frozenset[str] = Field(default_factory=frozenset)
    target_sources: frozenset[str] = Field(default_factory=frozenset)

    global_rank: int | None = Field(default=None, ge=1)
    global_score: float = Field(default=0.0, ge=0.0)

    target_frequency: int = Field(default=0, ge=0)
    target_source_diversity: int = Field(default=0, ge=0)
    target_relevance: float = Field(default=0.0, ge=0.0)

    successful_hits: int = Field(default=0, ge=0)
    attempted_hypotheses: int = Field(default=0, ge=0)

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return normalize_parameter_name(value)

    @field_validator("global_sources", "target_sources")
    @classmethod
    def normalize_sources(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(
            value.strip().lower()
            for value in values
            if value.strip()
        )

    @property
    def lane(self) -> ParameterLane:
        if (
            self.target_frequency > 0
            or self.target_source_diversity > 0
            or self.target_relevance > 0.0
            or bool(self.target_sources)
        ):
            return ParameterLane.TARGETED

        return ParameterLane.EXPLORATION

    @property
    def yield_ratio(self) -> float:
        if self.attempted_hypotheses <= 0:
            return 0.0

        return self.successful_hits / self.attempted_hypotheses

    @property
    def ranking_score(self) -> float:
        rank_bonus = (
            1.0 / math.log2(self.global_rank + 1)
            if self.global_rank is not None
            else 0.0
        )

        return (
            self.target_relevance * 4.0
            + math.log1p(self.target_frequency) * 1.5
            + self.target_source_diversity
            + len(self.target_sources) * 0.5
            + self.yield_ratio * 3.0
            + self.global_score
            + rank_bonus
            + self.confidence * 0.25
        )


class ParameterCandidateProvider(Protocol):
    """Implemented later by intelligence/parameters.py or vocabulary.py."""

    async def candidates_for(
        self,
        endpoint_event: Event,
    ) -> Sequence[ParameterCandidate]:
        ...


class ExplorationCursorStore(Protocol):
    """Rotate through global parameter names across repeated exploration."""

    async def claim_window(
        self,
        *,
        namespace: str,
        pool_size: int,
        window_size: int,
    ) -> tuple[int, ...]:
        ...


class InputEventProvider(Protocol):
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class StaticParameterCandidateProvider:
    """Deterministic candidate provider for tests/bootstrap."""

    def __init__(self, candidates: Sequence[ParameterCandidate]) -> None:
        self._candidates = tuple(candidates)

    async def candidates_for(
        self,
        endpoint_event: Event,
    ) -> Sequence[ParameterCandidate]:
        del endpoint_event
        return self._candidates


class InMemoryExplorationCursorStore:
    """Process-local rotating cursor.

    A future persistent intelligence store should implement the same protocol
    in SQLite so exploration position survives restarts.
    """

    def __init__(self) -> None:
        self._offsets: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def claim_window(
        self,
        *,
        namespace: str,
        pool_size: int,
        window_size: int,
    ) -> tuple[int, ...]:
        if pool_size < 0 or window_size < 0:
            raise ValueError("pool_size/window_size cannot be negative")

        if pool_size == 0 or window_size == 0:
            return ()

        count = min(pool_size, window_size)

        async with self._lock:
            start = self._offsets.get(namespace, 0) % pool_size
            indexes = tuple(
                (start + offset) % pool_size
                for offset in range(count)
            )
            self._offsets[namespace] = (start + count) % pool_size
            return indexes


class ArjunPacing(BaseModel):
    """Pacing derived from the exclusive shared host rate envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_per_second: int | None = Field(default=None, ge=1)
    delay_seconds: int | None = Field(default=None, ge=1)

    @field_validator("delay_seconds")
    @classmethod
    def delay_reasonable(cls, value: int | None) -> int | None:
        if value is not None and value > 3600:
            raise ValueError("delay_seconds is unreasonably large")
        return value

    def model_post_init(self, __context: Any) -> None:
        configured = sum(
            value is not None
            for value in (
                self.requests_per_second,
                self.delay_seconds,
            )
        )
        if configured != 1:
            raise ValueError(
                "Arjun pacing requires exactly one of requests_per_second "
                "or delay_seconds"
            )


class ParameterDiscoveryConfig(BaseModel):
    """Bounded active parameter-discovery configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    targeted_candidates: int = Field(default=300, ge=1, le=10_000)
    exploration_candidates: int = Field(default=150, ge=1, le=10_000)

    chunk_size: int = Field(default=50, ge=1, le=500)
    request_timeout_seconds: int = Field(default=15, ge=1, le=120)
    process_timeout_seconds: float = Field(default=300.0, gt=0.0)
    lease_margin_seconds: float = Field(default=30.0, ge=1.0)

    confirmed_confidence: float = Field(default=0.98, ge=0.0, le=1.0)
    heuristic_confidence: float = Field(default=0.90, ge=0.0, le=1.0)

    retry_after_seconds: float = Field(default=15.0, ge=0.0)


class ArjunConfig(BaseModel):
    """Arjun CLI adapter settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "arjun"
    stderr_tail_lines: int = Field(default=100, ge=1, le=2000)
    stdout_tail_lines: int = Field(default=100, ge=1, le=2000)
    stream_limit_bytes: int = Field(default=1024 * 1024, ge=65536)

    extra_args: tuple[str, ...] = ()

    @field_validator("binary")
    @classmethod
    def binary_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("binary must not be blank")
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
            # Target/method/input ownership.
            "-u", "--url", "-i", "--import-file", "-m", "--method",
            # Candidate source/shape ownership.
            "-w", "--wordlist", "--passive", "--casing", "-c", "--chunks",
            # Auth/session/request-body ownership.
            "--include", "--headers",
            # Concurrency/pacing/timeout ownership.
            "-t", "--threads", "-d", "--delay", "-T", "--timeout",
            "--stable", "--ratelimit",
            # Redirect behavior.
            "--disable-redirects",
            # Output and proxy/Burp side effects.
            "-oJ", "--json", "-oT", "--text", "-oB", "--burp",
            # Update/help/version are not runtime actions.
            "--help", "-h", "--version", "--update",
        }

        if any(value in forbidden for value in normalized):
            raise ValueError(
                "Arjun extra_args cannot override method/target, candidate "
                "source, auth/request data, pacing, redirects, or output"
            )

        return normalized


class ArjunDiscoveryResult(BaseModel):
    """Confirmed parameter names returned by one bounded Arjun run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_url: str
    parameters: tuple[str, ...] = ()

    @field_validator("target_url")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return parameter_target_url_value(value)

    @field_validator("parameters")
    @classmethod
    def normalize_parameters(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        result: list[str] = []

        for value in values:
            try:
                normalized = normalize_parameter_name(value)
            except ValueError:
                continue

            if normalized not in result:
                result.append(normalized)

        return tuple(sorted(result))


class ParameterDiscoveryBackend(Protocol):
    name: str

    def ensure_available(self) -> None:
        ...

    async def discover(
        self,
        target_url: str,
        *,
        candidate_names: Sequence[str],
        pacing: ArjunPacing,
        discovery: ParameterDiscoveryConfig,
    ) -> ArjunDiscoveryResult:
        ...


class ParameterBackendError(RuntimeError):
    pass


class ParameterBackendUnavailable(ParameterBackendError):
    pass


class ParameterBackendTimeout(ParameterBackendError):
    pass


class ArjunBackend:
    """One-target, GET-only, custom-wordlist Arjun adapter."""

    name = "arjun"

    def __init__(self, config: ArjunConfig | None = None) -> None:
        self.config = config or ArjunConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise ParameterBackendUnavailable(
                f"Arjun executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        target_url: str,
        wordlist_path: Path,
        output_path: Path,
        pacing: ArjunPacing,
        discovery: ParameterDiscoveryConfig,
    ) -> tuple[str, ...]:
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-u", parameter_target_url_value(target_url),
            "-m", "GET",
            "-w", str(wordlist_path),
            "-oJ", str(output_path),
            "-t", "1",
            "-c", str(discovery.chunk_size),
            "-T", str(discovery.request_timeout_seconds),
            "--disable-redirects",
        ]

        if pacing.requests_per_second is not None:
            args.extend(("--ratelimit", str(pacing.requests_per_second)))
        else:
            args.extend(("-d", str(pacing.delay_seconds)))

        args.extend(self.config.extra_args)
        return tuple(args)

    async def discover(
        self,
        target_url: str,
        *,
        candidate_names: Sequence[str],
        pacing: ArjunPacing,
        discovery: ParameterDiscoveryConfig,
    ) -> ArjunDiscoveryResult:
        target = parameter_target_url_value(target_url)

        names = tuple(
            sorted(
                {
                    normalize_parameter_name(value)
                    for value in candidate_names
                }
            )
        )

        if not names:
            return ArjunDiscoveryResult(target_url=target, parameters=())

        self.ensure_available()

        with tempfile.TemporaryDirectory(prefix="nightscout-arjun-") as tmp:
            temp_dir = Path(tmp)
            wordlist_path = temp_dir / "parameters.txt"
            output_path = temp_dir / "result.json"

            wordlist_path.write_text(
                "\n".join(names) + "\n",
                encoding="utf-8",
            )

            process = await asyncio.create_subprocess_exec(
                *self.command_for(
                    target_url=target,
                    wordlist_path=wordlist_path,
                    output_path=output_path,
                    pacing=pacing,
                    discovery=discovery,
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=self.config.stream_limit_bytes,
                env=_sanitized_subprocess_env(),
            )

            if process.stdout is None or process.stderr is None:
                await _terminate_process(process)
                raise ParameterBackendError(
                    "Arjun subprocess pipes were not created"
                )

            stdout_tail: deque[str] = deque(
                maxlen=self.config.stdout_tail_lines
            )
            stderr_tail: deque[str] = deque(
                maxlen=self.config.stderr_tail_lines
            )

            stdout_task = asyncio.create_task(
                _drain_stream(process.stdout, stdout_tail)
            )
            stderr_task = asyncio.create_task(
                _drain_stream(process.stderr, stderr_tail)
            )

            try:
                try:
                    async with asyncio.timeout(
                        discovery.process_timeout_seconds
                    ):
                        returncode = await process.wait()
                except TimeoutError as exc:
                    await _terminate_process(process)
                    raise ParameterBackendTimeout(
                        "Arjun exceeded outer process timeout "
                        f"({discovery.process_timeout_seconds}s)"
                    ) from exc

                if returncode != 0:
                    detail = " | ".join((*stdout_tail, *stderr_tail))
                    raise ParameterBackendError(
                        "Arjun exited unsuccessfully "
                        f"(returncode={returncode})"
                        + (f"; output_tail={detail}" if detail else "")
                    )

            finally:
                if process.returncode is None:
                    await _terminate_process(process)

                for task in (stdout_task, stderr_task):
                    try:
                        await task
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass

            parameters = parse_arjun_json_file(
                output_path,
                expected_url=target,
            )

            return ArjunDiscoveryResult(
                target_url=target,
                parameters=parameters,
            )


class ParametersWorker:
    """Bounded GET query-parameter discovery worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        candidates: ParameterCandidateProvider,
        exploration_cursors: ExplorationCursorStore,
        rate_limiter: RateLimiter,
        backend: ParameterDiscoveryBackend | None = None,
        config: ParameterDiscoveryConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._candidates = candidates
        self._exploration_cursors = exploration_cursors
        self._rate_limiter = rate_limiter
        self._backend = backend or ArjunBackend()
        self._config = config or ParameterDiscoveryConfig()

    @staticmethod
    def candidate_limit_for_tier(tier: str) -> int:
        return {
            "MICRO": 25,
            "SMALL": 100,
            "MEDIUM": 300,
            "LARGE": 1_000,
            "EXHAUSTIVE": 10_000,
        }[tier]

    async def execute(self, task: Task) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "parameters worker may only execute claimed RUNNING "
                    f"tasks, got {task.status.value}"
                ),
            )

        lane = _lane_for_action(task.action)

        if task.worker != self.name or lane is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    f"unsupported parameters task: worker={task.worker} "
                    f"action={task.action}"
                ),
            )

        input_event = await self._events.get_event(task.input_event_id)

        if input_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"input event not found: {task.input_event_id}",
            )

        try:
            target_url = parameter_target_from_event(input_event)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        selected = await self._select_candidates(
            input_event=input_event,
            target_url=target_url,
            lane=lane,
            limit_hint=task.candidate_limit_hint,
        )

        if not selected:
            return WorkerExecutionResult(outcome=WorkerOutcome.SUCCEEDED)

        parts = urlsplit(target_url)
        assert parts.hostname is not None
        hostname = normalize_dns_name(parts.hostname)

        try:
            self._backend.ensure_available()
        except ParameterBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        context = RateLimitContext(
            resource_keys=frozenset({f"host:{hostname}"})
        )

        plan = self._rate_limiter.plan(task, context=context)
        rate_error = validate_opaque_parameter_plan(plan)

        if rate_error is not None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=rate_error,
            )

        assert plan.max_concurrency_hint is not None

        pacing = arjun_pacing_from_plan(plan)

        decision = await self._rate_limiter.acquire(
            task,
            context=context,
            demand=RateLimitDemand(
                requests=0.0,
                concurrency=plan.max_concurrency_hint,
            ),
            lease_for=_parameter_lease_duration(
                self._config
            ),
        )

        if decision.outcome is RateLimitOutcome.DEFER:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=(
                    decision.reason
                    or "parameters could not acquire exclusive host lease"
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
                    or "parameter-discovery shared rate policy denied execution"
                ),
            )

        lease_id = (
            decision.lease.lease_id
            if decision.lease is not None
            else None
        )

        try:
            result = await self._backend.discover(
                target_url,
                candidate_names=tuple(candidate.name for candidate in selected),
                pacing=pacing,
                discovery=self._config,
            )

            if result.target_url != target_url:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.FAILED,
                    error="parameter backend returned a different target URL",
                )

            selected_by_name = {
                candidate.name: candidate
                for candidate in selected
            }

            for parameter in result.parameters:
                candidate = selected_by_name.get(parameter)

                await self._publisher.publish(
                    Event(
                        type=EventType.PARAMETER_NAME,
                        value=parameter,
                        source=(
                            f"parameters:{_source_component(self._backend.name)}:"
                            f"{lane.value.lower()}"
                        ),
                        parent_event_id=input_event.event_id,
                        scope_state=ScopeState.UNKNOWN,
                        confidence=(
                            self._config.confirmed_confidence
                            if candidate is not None
                            else self._config.heuristic_confidence
                        ),
                        novelty=(
                            0.82
                            if lane is ParameterLane.EXPLORATION
                            else 0.68
                        ),
                        depth=input_event.depth + 1,
                        tags={
                            "parameters",
                            "confirmed",
                            "get-query",
                            f"lane:{lane.value.lower()}",
                            "feeds-vocabulary",
                        },
                        metadata={
                            "endpoint_url": target_url,
                            "method": "GET",
                            "parameter_location": "query",
                            "active_confirmation": True,
                            "parameter_value_stored": False,
                            "candidate_lane": lane.value,
                            "candidate_was_supplied": candidate is not None,
                            "candidate_score": (
                                candidate.ranking_score
                                if candidate is not None
                                else None
                            ),
                            "global_sources": (
                                sorted(candidate.global_sources)
                                if candidate is not None
                                else []
                            ),
                            "target_sources": (
                                sorted(candidate.target_sources)
                                if candidate is not None
                                else ["arjun-page-heuristic"]
                            ),
                            "feeds_vocabulary": True,
                            "requires_human_review_for_stateful_use": True,
                        },
                    )
                )

        except ParameterBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.retry_after_seconds,
            )
        except ParameterBackendError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.retry_after_seconds,
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(lease_id)

        return WorkerExecutionResult(outcome=WorkerOutcome.SUCCEEDED)

    async def _select_candidates(
        self,
        *,
        input_event: Event,
        target_url: str,
        lane: ParameterLane,
        limit_hint: int | None = None,
    ) -> tuple[ParameterCandidate, ...]:
        candidates = _dedupe_candidates(
            await self._candidates.candidates_for(input_event)
        )

        existing = set(query_parameter_names(target_url))

        if lane is ParameterLane.TARGETED:
            pool = sorted(
                (
                    candidate
                    for candidate in candidates
                    if candidate.lane is ParameterLane.TARGETED
                    and candidate.name not in existing
                ),
                key=_targeted_sort_key,
            )

            limit = min(
                self._config.targeted_candidates,
                limit_hint or self._config.targeted_candidates,
            )
            return tuple(pool[:limit])

        pool = sorted(
            (
                candidate
                for candidate in candidates
                if candidate.lane is ParameterLane.EXPLORATION
                and candidate.name not in existing
            ),
            key=_exploration_sort_key,
        )

        if not pool:
            return ()

        limit = min(
            self._config.exploration_candidates,
            limit_hint or self._config.exploration_candidates,
        )
        indexes = await self._exploration_cursors.claim_window(
            namespace=_exploration_namespace(target_url),
            pool_size=len(pool),
            window_size=min(
                len(pool),
                limit,
            ),
        )

        return tuple(pool[index] for index in indexes)


def parameter_route_rules(
    *,
    base_priority: float = 6.75,
) -> tuple[RouteRule, ...]:
    """Schedule targeted and exploration scans for non-historical endpoints."""

    return (
        RouteRule(
            rule_id="parameters.api.targeted",
            accepts=frozenset({EventType.API_ENDPOINT}),
            worker=WORKER_NAME,
            action=ACTION_DISCOVER_TARGETED,
            reason=(
                "validate target-specific GET parameter-name hypotheses on "
                "an API endpoint"
            ),
            base_priority=base_priority,
            excluded_tags=frozenset({"historical", "archive"}),
        ),
        RouteRule(
            rule_id="parameters.api.exploration",
            accepts=frozenset({EventType.API_ENDPOINT}),
            worker=WORKER_NAME,
            action=ACTION_DISCOVER_EXPLORATION,
            reason=(
                "validate a rotating bounded global parameter corpus on an "
                "API endpoint"
            ),
            base_priority=base_priority - 1.0,
            excluded_tags=frozenset({"historical", "archive"}),
        ),
    )


def parameter_target_from_event(event: Event) -> str:
    if event.type is not EventType.API_ENDPOINT:
        raise ValueError(
            "parameters discovery requires API_ENDPOINT input by default"
        )

    if "historical" in event.tags or "archive" in event.tags:
        raise ValueError(
            "historical endpoints are not active parameter-discovery targets"
        )

    return parameter_target_url_value(event.value)


def parameter_target_url_value(value: str) -> str:
    """Canonical endpoint identity with all query values removed."""

    normalized = normalize_http_url(value)
    parts = urlsplit(normalized)

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            "",
            "",
        )
    )


def normalize_parameter_name(value: str) -> str:
    normalized = value.strip()

    if not normalized:
        raise ValueError("parameter name must not be blank")

    if not _PARAMETER_RE.fullmatch(normalized):
        raise ValueError(
            "parameter name contains unsupported characters or is too long"
        )

    return normalized


def validate_opaque_parameter_plan(plan: RateLimitPlan) -> str | None:
    if not plan.matched:
        return (
            "parameters has no matching shared rate-limit rule; opaque "
            "multi-request subprocess fails closed"
        )

    if plan.aggregate_rps_ceiling is None or plan.aggregate_rps_ceiling <= 0.0:
        return (
            "parameters requires an explicit requests_per_second ceiling in "
            "its matching shared rate-limit rule"
        )

    if plan.max_concurrency_hint is None or plan.max_concurrency_hint < 1:
        return (
            "parameters requires max_concurrency in its matching shared "
            "rate-limit rule so it can acquire an exclusive host lease"
        )

    return None


def arjun_pacing_from_plan(plan: RateLimitPlan) -> ArjunPacing:
    if plan.aggregate_rps_ceiling is None or plan.aggregate_rps_ceiling <= 0:
        raise ValueError("rate plan has no positive aggregate RPS ceiling")

    rps = plan.aggregate_rps_ceiling

    if rps >= 1.0:
        return ArjunPacing(
            requests_per_second=max(1, math.floor(rps))
        )

    return ArjunPacing(
        delay_seconds=math.ceil(1.0 / rps)
    )


def parse_arjun_json_file(
    path: Path,
    *,
    expected_url: str,
) -> tuple[str, ...]:
    """Read only confirmed GET parameter names from Arjun JSON export."""

    if not path.exists():
        return ()

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParameterBackendError(
            f"failed to parse Arjun JSON output: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise ParameterBackendError("Arjun JSON output must be an object")

    expected = parameter_target_url_value(expected_url)
    parameters: set[str] = set()

    for raw_url, data in payload.items():
        if not isinstance(raw_url, str) or not isinstance(data, dict):
            continue

        try:
            target = parameter_target_url_value(raw_url)
        except ValueError:
            continue

        if target != expected:
            continue

        method = str(data.get("method", "GET")).strip().upper()

        if method != "GET":
            continue

        raw_params = data.get("params", ())

        if isinstance(raw_params, dict):
            raw_values = raw_params.keys()
        elif isinstance(raw_params, (list, tuple, set)):
            raw_values = raw_params
        elif isinstance(raw_params, str):
            raw_values = (raw_params,)
        else:
            raw_values = ()

        for raw_param in raw_values:
            try:
                parameters.add(normalize_parameter_name(str(raw_param)))
            except ValueError:
                continue

    return tuple(sorted(parameters))


def query_parameter_names(url: str) -> tuple[str, ...]:
    """Extract existing query parameter names without retaining values."""

    from urllib.parse import parse_qsl

    normalized = normalize_http_url(url)
    query = urlsplit(normalized).query

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

    result: set[str] = set()

    for name, _value in pairs:
        try:
            result.add(normalize_parameter_name(name))
        except ValueError:
            continue

    return tuple(sorted(result))


def _lane_for_action(action: str) -> ParameterLane | None:
    if action == ACTION_DISCOVER_TARGETED:
        return ParameterLane.TARGETED

    if action == ACTION_DISCOVER_EXPLORATION:
        return ParameterLane.EXPLORATION

    return None


def _dedupe_candidates(
    candidates: Sequence[ParameterCandidate],
) -> tuple[ParameterCandidate, ...]:
    merged: dict[str, ParameterCandidate] = {}

    for candidate in candidates:
        existing = merged.get(candidate.name)

        if existing is None:
            merged[candidate.name] = candidate
            continue

        target_sources = existing.target_sources | candidate.target_sources

        merged[candidate.name] = ParameterCandidate(
            name=candidate.name,
            global_sources=(existing.global_sources | candidate.global_sources),
            target_sources=target_sources,
            global_rank=_best_rank(existing.global_rank, candidate.global_rank),
            global_score=max(existing.global_score, candidate.global_score),
            target_frequency=(
                existing.target_frequency + candidate.target_frequency
            ),
            target_source_diversity=max(
                existing.target_source_diversity,
                candidate.target_source_diversity,
                len(target_sources),
            ),
            target_relevance=max(
                existing.target_relevance,
                candidate.target_relevance,
            ),
            successful_hits=(
                existing.successful_hits + candidate.successful_hits
            ),
            attempted_hypotheses=(
                existing.attempted_hypotheses + candidate.attempted_hypotheses
            ),
            confidence=max(existing.confidence, candidate.confidence),
            metadata={**existing.metadata, **candidate.metadata},
        )

    return tuple(merged.values())


def _best_rank(left: int | None, right: int | None) -> int | None:
    ranks = [value for value in (left, right) if value is not None]
    return min(ranks) if ranks else None


def _targeted_sort_key(
    candidate: ParameterCandidate,
) -> tuple[float, int, str]:
    return (
        -candidate.ranking_score,
        candidate.global_rank or 10**12,
        candidate.name.lower(),
    )


def _exploration_sort_key(
    candidate: ParameterCandidate,
) -> tuple[int, float, str]:
    return (
        candidate.global_rank or 10**12,
        -candidate.global_score,
        candidate.name.lower(),
    )


def _exploration_namespace(target_url: str) -> str:
    import hashlib

    digest = hashlib.sha256(
        parameter_target_url_value(target_url).encode("utf-8")
    ).hexdigest()[:20]

    return f"parameters:exploration:{digest}"


def _parameter_lease_duration(
    config: ParameterDiscoveryConfig,
):
    from datetime import timedelta

    return timedelta(
        seconds=(
            config.process_timeout_seconds
            + config.lease_margin_seconds
        )
    )


def _sanitized_subprocess_env() -> dict[str, str]:
    """Disable ambient proxy variables so Arjun cannot silently proxy traffic."""

    env = os.environ.copy()

    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)

    return env


def _source_component(value: str) -> str:
    normalized = value.strip().lower()
    normalized = _SOURCE_COMPONENT_RE.sub("-", normalized).strip("-")
    return normalized or "unknown"


def _resolve_executable(binary: str) -> str | None:
    candidate = Path(binary).expanduser()

    if candidate.parent != Path(".") or candidate.is_absolute():
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        return None

    return shutil.which(binary)


async def _drain_stream(
    stream: asyncio.StreamReader,
    tail: deque[str],
) -> None:
    while True:
        raw = await stream.readline()

        if not raw:
            return

        line = raw.decode("utf-8", errors="replace").strip()

        if line:
            tail.append(line)


async def _terminate_process(
    process: asyncio.subprocess.Process,
) -> None:
    if process.returncode is not None:
        return

    process.terminate()

    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except TimeoutError:
        process.kill()
        await process.wait()
