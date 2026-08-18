"""Active DNS confirmation worker for Night Scout.

`passive_domains.py` discovers hostname candidates from passive sources.
This worker performs the next step: controlled DNS confirmation.

For each approved DNS_NAME task it can query:

    A
    AAAA
    CNAME

Each record type is executed as a separate rate-limited network operation.
This is deliberate. A single `dnsx -a -aaaa -cname` subprocess would make one
shared-rate acquisition represent several DNS requests, which becomes awkward
or unsafe under low per-target limits. Sequential per-type queries let Night
Scout acquire exactly one shared request token per query.

Output model
------------
A successful result produces provenance-preserving Events such as:

    DNS_NAME observation
        api.example.com                  source=dns:dnsx

    DNS_RECORD
        api.example.com A 203.0.113.10

    IP_ADDRESS
        203.0.113.10

    DNS_RECORD
        api.example.com CNAME edge.example.net

    DNS_NAME
        edge.example.net                 scope=UNKNOWN

The CNAME target is stored even when it is outside the current program scope.
Storage is not authorization: later scope/policy gates decide whether active
follow-up is allowed.

When dnsx returns NXDOMAIN (via -rcode noerror,nxdomain), Night Scout records a
negative DNS_RECORD observation rather than silently forgetting the failed
hypothesis. Future negative-knowledge/intelligence modules can attach TTL and
recheck policy to these observations.

dnsx usage assumptions are based on the current ProjectDiscovery CLI:
    -a / -aaaa / -cname
    -j / -json
    -or / -omit-raw
    -rl / -rate-limit
    -t / -threads
    -retry
    -timeout
    -rcode
    -r / -resolver

The worker never enables brute-force (-d/-w), AXFR, ANY, recon, trace, PTR
network-range expansion, or wildcard discovery. Those belong in explicitly
separate workers/policies.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Sequence
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimitOutcome,
    RateLimiter,
    tool_integer_rps_hint,
)
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "dns"
ACTION_RESOLVE = "resolve"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")


class DNSRecordType(StrEnum):
    """Record types handled by the initial confirmation worker."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"

    @property
    def dnsx_flag(self) -> str:
        return {
            DNSRecordType.A: "-a",
            DNSRecordType.AAAA: "-aaaa",
            DNSRecordType.CNAME: "-cname",
        }[self]


class DNSQueryResult(BaseModel):
    """Normalized result of one host + record-type query."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    record_type: DNSRecordType

    values: tuple[str, ...] = ()

    status_code: str | None = None
    ttl: int | None = Field(default=None, ge=0)

    resolvers: tuple[str, ...] = ()
    query_time: str | float | int | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @field_validator("status_code")
    @classmethod
    def normalize_rcode(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        return normalized or None

    @field_validator("resolvers")
    @classmethod
    def normalize_resolvers(
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
    """Load a task input Event."""

    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    """Publish normalized output into the Night Scout event pipeline."""

    async def publish(self, event: Event) -> bool:
        ...


class DNSQueryBackend(Protocol):
    """One controlled DNS query implementation."""

    name: str

    def ensure_available(self) -> None:
        """Raise when the backend cannot execute locally."""
        ...

    async def query(
        self,
        hostname: str,
        *,
        record_type: DNSRecordType,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[DNSQueryResult]:
        """Yield normalized results for one record type."""
        ...


class DnsxConfig(BaseModel):
    """ProjectDiscovery dnsx subprocess configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "dnsx"

    resolvers: tuple[str, ...] = ()

    retry: int = Field(default=1, ge=1, le=5)
    query_timeout: str = "3s"
    process_timeout_seconds: float = Field(default=15.0, gt=0.0)

    capture_nxdomain: bool = True

    stderr_tail_lines: int = Field(default=80, ge=1, le=1000)
    stream_limit_bytes: int = Field(
        default=1024 * 1024,
        ge=65536,
    )

    extra_args: tuple[str, ...] = ()

    @field_validator("binary", "query_timeout")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("resolvers")
    @classmethod
    def normalize_resolvers(
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
            # Input / brute-force / expansion.
            "-l",
            "-list",
            "-d",
            "-domain",
            "-w",
            "-wordlist",
            "-ptr",

            # Broader or potentially intrusive query modes.
            "-axfr",
            "-any",
            "-recon",
            "-trace",
            "-trace-max-recursion",
            "-auto-wildcard",
            "-wd",
            "-wildcard-domain",

            # Record types are owned by query(record_type=...).
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-mx",
            "-txt",
            "-srv",
            "-soa",
            "-caa",

            # Output must remain on stdout JSONL.
            "-o",
            "-output",
            "-ot",
            "-output-template",
            "-raw",
            "-debug",

            # Rate/concurrency is controlled centrally by Night Scout.
            "-rl",
            "-rate-limit",
            "-t",
            "-threads",
            "-retry",
            "-timeout",
            "-rcode",
            "-rc",
        }

        if any(value in forbidden for value in normalized):
            raise ValueError(
                "dnsx extra_args cannot override input, query type, "
                "rate control, or streaming output"
            )

        return normalized


class DNSWorkerConfig(BaseModel):
    """Worker-level DNS behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_types: tuple[DNSRecordType, ...] = (
        DNSRecordType.A,
        DNSRecordType.AAAA,
        DNSRecordType.CNAME,
    )

    rate_lease_seconds: float = Field(default=30.0, gt=0.0)

    confirmation_confidence: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
    )
    record_confidence: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
    )
    cname_target_confidence: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
    )
    negative_confidence: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
    )

    default_retry_after_seconds: float = Field(
        default=5.0,
        ge=0.0,
    )

    @field_validator("record_types")
    @classmethod
    def unique_record_types(
        cls,
        values: tuple[DNSRecordType, ...],
    ) -> tuple[DNSRecordType, ...]:
        if not values:
            raise ValueError("record_types cannot be empty")

        result: list[DNSRecordType] = []
        seen: set[DNSRecordType] = set()

        for value in values:
            if value not in seen:
                result.append(value)
                seen.add(value)

        return tuple(result)


class DNSBackendError(RuntimeError):
    """dnsx/backend execution failure."""


class DNSBackendUnavailable(DNSBackendError):
    """Configured DNS executable is unavailable."""


class DNSBackendTimeout(DNSBackendError):
    """DNS subprocess exceeded its outer timeout."""


class DnsxBackend:
    """One-record-type-at-a-time dnsx adapter."""

    name = "dnsx"

    def __init__(
        self,
        config: DnsxConfig | None = None,
    ) -> None:
        self.config = config or DnsxConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise DNSBackendUnavailable(
                f"dnsx executable not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        record_type: DNSRecordType,
        rate_limit_rps: int | None,
    ) -> tuple[str, ...]:
        """Build safe argv. Host input is intentionally supplied via stdin."""
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            record_type.dnsx_flag,
            "-j",
            "-or",
            "-silent",
            "-duc",
            "-nc",
            "-t",
            "1",
            "-retry",
            str(self.config.retry),
            "-timeout",
            self.config.query_timeout,
        ]

        if self.config.capture_nxdomain:
            args.extend(
                (
                    "-rcode",
                    "noerror,nxdomain",
                )
            )

        if self.config.resolvers:
            args.extend(
                (
                    "-r",
                    ",".join(self.config.resolvers),
                )
            )

        if rate_limit_rps is not None:
            args.extend(
                (
                    "-rl",
                    str(rate_limit_rps),
                )
            )

        args.extend(self.config.extra_args)
        return tuple(args)

    async def query(
        self,
        hostname: str,
        *,
        record_type: DNSRecordType,
        rate_limit_rps: int | None,
    ) -> AsyncIterator[DNSQueryResult]:
        normalized_host = normalize_dns_name(hostname)
        self.ensure_available()

        command = self.command_for(
            record_type=record_type,
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
            raise DNSBackendError(
                "dnsx subprocess pipes were not created"
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
                (normalized_host + "\n").encode("utf-8")
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

                        parsed = parse_dnsx_line(
                            line,
                            requested_type=record_type,
                        )

                        if parsed is not None:
                            yield parsed

                    returncode = await process.wait()
            except TimeoutError as exc:
                await _terminate_process(process)
                raise DNSBackendTimeout(
                    "dnsx exceeded outer process timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(stderr_tail)
                raise DNSBackendError(
                    "dnsx exited unsuccessfully "
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


class DNSWorker:
    """Rate-limited active DNS confirmation worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        backend: DNSQueryBackend | None = None,
        config: DNSWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._backend = backend or DnsxBackend()
        self._config = config or DNSWorkerConfig()

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        """Resolve one already-authorized DNS_NAME task."""
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "dns worker may only execute claimed RUNNING tasks, "
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

        if task.action != ACTION_RESOLVE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported dns action: {task.action}",
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
                    "dns.resolve requires DNS_NAME input, got "
                    f"{input_event.type.value}"
                ),
            )

        try:
            hostname = normalize_dns_name(input_event.value)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"invalid input DNS name: {exc}",
            )

        try:
            self._backend.ensure_available()
        except DNSBackendUnavailable as exc:
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

        emitted_confirmation = False

        for record_type in self._config.record_types:
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
                        or "DNS shared rate limit temporarily exhausted"
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
                        or "DNS shared rate-limit policy denied execution"
                    ),
                )

            lease_id = (
                decision.lease.lease_id
                if decision.lease is not None
                else None
            )

            try:
                query_results: list[DNSQueryResult] = []

                async for result in self._backend.query(
                    hostname,
                    record_type=record_type,
                    rate_limit_rps=cli_rps,
                ):
                    query_results.append(result)

                for result in query_results:
                    if result.hostname != hostname:
                        # The tool must never redirect this task to a different
                        # query subject via malformed output.
                        continue

                    if (
                        not emitted_confirmation
                        and _result_confirms_name(result)
                    ):
                        confirmation = self._confirmation_event(
                            input_event=input_event,
                            result=result,
                        )
                        await self._publisher.publish(
                            confirmation
                        )
                        emitted_confirmation = True

                    await self._publish_result(
                        input_event=input_event,
                        result=result,
                    )

            except DNSBackendTimeout as exc:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=str(exc),
                    retry_after_seconds=(
                        self._config.default_retry_after_seconds
                    ),
                )
            except DNSBackendError as exc:
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.RETRY,
                    error=str(exc),
                    retry_after_seconds=(
                        self._config.default_retry_after_seconds
                    ),
                )
            finally:
                if lease_id is not None:
                    await self._rate_limiter.release(lease_id)

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    def _confirmation_event(
        self,
        *,
        input_event: Event,
        result: DNSQueryResult,
    ) -> Event:
        return Event(
            type=EventType.DNS_NAME,
            value=result.hostname,
            source=f"dns:{_source_component(self._backend.name)}",
            parent_event_id=input_event.event_id,
            scope_state=input_event.scope_state,
            confidence=self._config.confirmation_confidence,
            novelty=max(input_event.novelty * 0.5, 0.2),
            depth=input_event.depth + 1,
            tags={
                "dns",
                "confirmed",
                "resolving",
            },
            metadata={
                "confirmed": True,
                "status_code": result.status_code,
                "resolvers": list(result.resolvers),
                "query_time": result.query_time,
            },
        )

    async def _publish_result(
        self,
        *,
        input_event: Event,
        result: DNSQueryResult,
    ) -> None:
        rcode = (result.status_code or "").upper()

        if rcode == "NXDOMAIN":
            negative = Event(
                type=EventType.DNS_RECORD,
                value=f"{result.hostname} RCODE NXDOMAIN",
                source=(
                    f"dns:{_source_component(self._backend.name)}:"
                    "rcode"
                ),
                parent_event_id=input_event.event_id,
                scope_state=input_event.scope_state,
                confidence=self._config.negative_confidence,
                novelty=0.1,
                depth=input_event.depth + 1,
                tags={
                    "dns",
                    "negative",
                    "nxdomain",
                },
                metadata={
                    "record_type": result.record_type.value,
                    "status_code": "NXDOMAIN",
                    "negative": True,
                    "resolvers": list(result.resolvers),
                    "ttl": result.ttl,
                    "query_time": result.query_time,
                },
            )
            await self._publisher.publish(negative)
            return

        if not result.values:
            if rcode == "NOERROR":
                nodata = Event(
                    type=EventType.DNS_RECORD,
                    value=(
                        f"{result.hostname} "
                        f"{result.record_type.value} NODATA"
                    ),
                    source=(
                        f"dns:{_source_component(self._backend.name)}:"
                        "nodata"
                    ),
                    parent_event_id=input_event.event_id,
                    scope_state=input_event.scope_state,
                    confidence=self._config.negative_confidence,
                    novelty=0.1,
                    depth=input_event.depth + 1,
                    tags={
                        "dns",
                        "negative",
                        "nodata",
                    },
                    metadata={
                        "record_type": result.record_type.value,
                        "status_code": "NOERROR",
                        "negative": True,
                        "nodata": True,
                        "resolvers": list(result.resolvers),
                        "ttl": result.ttl,
                        "query_time": result.query_time,
                    },
                )
                await self._publisher.publish(nodata)
            return

        for raw_value in result.values:
            if result.record_type in {
                DNSRecordType.A,
                DNSRecordType.AAAA,
            }:
                try:
                    canonical_value = str(
                        ipaddress.ip_address(raw_value)
                    )
                except ValueError:
                    continue
            else:
                try:
                    canonical_value = normalize_dns_name(
                        raw_value
                    )
                except ValueError:
                    continue

            record_event = Event(
                type=EventType.DNS_RECORD,
                value=(
                    f"{result.hostname} "
                    f"{result.record_type.value} "
                    f"{canonical_value}"
                ),
                source=(
                    f"dns:{_source_component(self._backend.name)}:"
                    f"{result.record_type.value.lower()}"
                ),
                parent_event_id=input_event.event_id,
                scope_state=input_event.scope_state,
                confidence=self._config.record_confidence,
                novelty=0.3,
                depth=input_event.depth + 1,
                tags={
                    "dns",
                    "record",
                    result.record_type.value.lower(),
                },
                metadata={
                    "owner": result.hostname,
                    "record_type": result.record_type.value,
                    "record_value": canonical_value,
                    "status_code": result.status_code,
                    "ttl": result.ttl,
                    "resolvers": list(result.resolvers),
                    "query_time": result.query_time,
                    **result.metadata,
                },
            )
            await self._publisher.publish(record_event)

            if result.record_type in {
                DNSRecordType.A,
                DNSRecordType.AAAA,
            }:
                ip_event = Event(
                    type=EventType.IP_ADDRESS,
                    value=canonical_value,
                    source=record_event.source,
                    parent_event_id=record_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.record_confidence,
                    novelty=0.4,
                    depth=record_event.depth + 1,
                    tags={
                        "dns",
                        "ip",
                        result.record_type.value.lower(),
                    },
                    metadata={
                        "dns_owner": result.hostname,
                        "record_type": result.record_type.value,
                    },
                )
                await self._publisher.publish(ip_event)

            elif result.record_type is DNSRecordType.CNAME:
                cname_event = Event(
                    type=EventType.DNS_NAME,
                    value=canonical_value,
                    source=record_event.source,
                    parent_event_id=record_event.event_id,
                    # CNAME targets can cross administrative/scope boundaries.
                    scope_state=ScopeState.UNKNOWN,
                    confidence=self._config.cname_target_confidence,
                    novelty=0.5,
                    depth=record_event.depth + 1,
                    tags={
                        "dns",
                        "cname",
                        "alias-target",
                    },
                    metadata={
                        "cname_owner": result.hostname,
                        "discovered_via": "CNAME",
                    },
                )
                await self._publisher.publish(cname_event)


def dns_route_rules(
    *,
    base_priority: float = 8.0,
) -> tuple[RouteRule, ...]:
    """Route DNS_NAME observations into active DNS confirmation."""
    return (
        RouteRule(
            rule_id="dns.resolve",
            accepts=frozenset({EventType.DNS_NAME}),
            worker=WORKER_NAME,
            action=ACTION_RESOLVE,
            reason="confirm DNS name and collect A/AAAA/CNAME records",
            base_priority=base_priority,
        ),
    )


def parse_dnsx_line(
    line: str,
    *,
    requested_type: DNSRecordType,
) -> DNSQueryResult | None:
    """Parse one dnsx JSONL result.

    Current dnsx JSON/template field names include host, a, aaaa, cname, ttl,
    resolver, status_code, and query-time. The parser intentionally accepts
    string or list representations for record fields because historical/tool
    versions differ slightly in their JSON shape.
    """
    normalized_line = line.strip()
    if not normalized_line:
        return None

    try:
        payload = json.loads(normalized_line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    raw_host = payload.get("host")
    if not isinstance(raw_host, str):
        return None

    try:
        hostname = normalize_dns_name(raw_host)
    except ValueError:
        return None

    field_name = {
        DNSRecordType.A: "a",
        DNSRecordType.AAAA: "aaaa",
        DNSRecordType.CNAME: "cname",
    }[requested_type]

    values = _string_values(
        payload.get(field_name)
    )

    if requested_type in {
        DNSRecordType.A,
        DNSRecordType.AAAA,
    }:
        normalized_values: list[str] = []
        for value in values:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue

            if (
                requested_type is DNSRecordType.A
                and ip.version != 4
            ):
                continue

            if (
                requested_type is DNSRecordType.AAAA
                and ip.version != 6
            ):
                continue

            normalized_values.append(str(ip))

        values = tuple(sorted(set(normalized_values)))
    else:
        normalized_cnames: list[str] = []
        for value in values:
            try:
                normalized_cnames.append(
                    normalize_dns_name(value)
                )
            except ValueError:
                continue

        values = tuple(sorted(set(normalized_cnames)))

    status_code = _first_text(
        payload,
        (
            "status_code",
            "status-code",
            "rcode",
        ),
    )

    ttl = _parse_nonnegative_int(
        payload.get("ttl")
    )

    resolvers = _string_values(
        payload.get("resolver")
    )

    query_time = (
        payload.get("query-time")
        if "query-time" in payload
        else payload.get("query_time")
    )

    known = {
        "host",
        "a",
        "aaaa",
        "cname",
        "ttl",
        "resolver",
        "status_code",
        "status-code",
        "rcode",
        "query-time",
        "query_time",
        "raw",
    }

    metadata = {
        key: value
        for key, value in payload.items()
        if key not in known
    }

    return DNSQueryResult(
        hostname=hostname,
        record_type=requested_type,
        values=values,
        status_code=status_code,
        ttl=ttl,
        resolvers=resolvers,
        query_time=query_time,
        metadata=metadata,
    )


def _result_confirms_name(
    result: DNSQueryResult,
) -> bool:
    return (
        (result.status_code or "NOERROR").upper() == "NOERROR"
        and bool(result.values)
    )


def _string_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        normalized = value.strip()
        return (normalized,) if normalized else ()

    if isinstance(value, (list, tuple, set)):
        result = {
            str(item).strip()
            for item in value
            if str(item).strip()
        }
        return tuple(sorted(result))

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


def _parse_nonnegative_int(
    value: Any,
) -> int | None:
    if value is None:
        return None

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
