"""Passive domain discovery worker for Night Scout.

This is the first real reconnaissance worker in the pipeline.

Responsibilities
----------------
- Load a ROOT_DOMAIN/DNS_NAME input Event.
- Run one or more passive discovery adapters.
- Stream tool output instead of buffering potentially huge result sets.
- Normalize concrete descendant DNS names.
- Preserve provider-level source diversity.
- Publish DNS_NAME Events immediately into the event-ingestion pipeline.
- Never perform active DNS/HTTP probing itself.

The first production adapter is ProjectDiscovery Subfinder. It is invoked
without `-active` and without IP output. JSONL + `-collect-sources` is used so
Night Scout can preserve which passive provider(s) produced each hostname.

The worker deliberately does not persist directly to SQLite. A future event
ingestion coordinator can implement EventPublisher by:

    persist Event
        -> classify scope
        -> record provenance
        -> route new event
        -> enqueue candidate tasks

This keeps worker subprocess logic independent from storage/router internals.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task
from recon.core.router import RouteRule
from recon.workers.subprocess_stream import (
    completed_process_returncode,
    stream_process_stdout,
)

WORKER_NAME = "passive_domains"
ACTION_ENUMERATE = "enumerate"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_ASCII_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


class PassiveDomainFinding(BaseModel):
    """One provider-attributed passive hostname observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str

    adapter: str
    provider: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname", "adapter")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("provider")
    @classmethod
    def normalize_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class PassiveDomainSource(Protocol):
    """Streaming passive enumeration backend."""

    name: str

    def stream(
        self,
        domain: str,
    ) -> AsyncIterator[PassiveDomainFinding]:
        """Yield provider-attributed passive findings."""
        ...


class InputEventProvider(Protocol):
    """Load task input Events without coupling workers to SQLite."""

    async def get_event(self, event_id: str) -> Event | None:
        """Return one Event by id."""
        ...


class EventPublisher(Protocol):
    """Publish normalized worker output into the Night Scout event pipeline."""

    async def publish(self, event: Event) -> bool:
        """Persist/route an Event.

        Return True when the pipeline accepted a new observation and False when
        an equivalent observation was already known.
        """
        ...


class SubfinderConfig(BaseModel):
    """Subfinder subprocess configuration.

    `rate_limit` here limits Subfinder's HTTP requests to its *passive data
    providers*. It is not Night Scout's target-node request limiter.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "subfinder"

    recursive: bool = False
    all_sources: bool = False

    sources: tuple[str, ...] = ()
    exclude_sources: tuple[str, ...] = ()

    rate_limit: int | None = Field(default=None, ge=1)
    max_results_per_source: int | None = Field(default=None, ge=1)

    source_timeout_seconds: int = Field(default=30, ge=1)
    max_time_minutes: int = Field(default=10, ge=1)

    # Independent outer guard in case a subprocess/provider hangs beyond the
    # tool's own max-time handling.
    process_timeout_seconds: float = Field(default=660.0, gt=0.0)

    config_path: Path | None = None
    provider_config_path: Path | None = None

    extra_args: tuple[str, ...] = ()

    stderr_tail_lines: int = Field(default=80, ge=1, le=1000)
    stream_limit_bytes: int = Field(
        default=1024 * 1024,
        ge=65536,
    )

    @field_validator("binary")
    @classmethod
    def binary_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("binary must not be blank")
        return normalized

    @field_validator("sources", "exclude_sources")
    @classmethod
    def normalize_sources(
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
    def reject_unsafe_active_flags(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Prevent extra_args from silently changing this passive worker."""
        normalized = tuple(value.strip() for value in values if value.strip())

        forbidden = {
            # Active behavior.
            "-nW",
            "-active",
            "-oI",
            "-ip",
            # Input overrides could make the subprocess enumerate something
            # other than the policy-approved task seed.
            "-d",
            "-domain",
            "-dL",
            "-list",
            # Output redirection would bypass Night Scout's streaming parser.
            "-o",
            "-output",
            "-oD",
            "-output-dir",
        }

        if any(value in forbidden for value in normalized):
            raise ValueError(
                "passive_domains extra_args cannot override active mode, "
                "task input, or streaming output"
            )

        return normalized

    @model_validator(mode="after")
    def source_selection_is_unambiguous(self) -> SubfinderConfig:
        if self.all_sources and self.sources:
            raise ValueError(
                "all_sources and explicit sources are mutually exclusive"
            )
        return self


class PassiveDomainsConfig(BaseModel):
    """Worker-level behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    confidence_single_provider: float = Field(
        default=0.55,
        ge=0.0,
        le=1.0,
    )

    # Confidence is still capped below direct active confirmation. The final
    # confidence model will combine truly independent evidence globally.
    confidence_named_provider: float = Field(
        default=0.60,
        ge=0.0,
        le=1.0,
    )

    retry_after_seconds: float = Field(
        default=30.0,
        ge=0.0,
    )

    fail_if_all_sources_fail: bool = True


class SourceExecutionError(RuntimeError):
    """Passive source process exited unsuccessfully."""

    def __init__(
        self,
        *,
        source: str,
        message: str,
        returncode: int | None = None,
        stderr_tail: Sequence[str] = (),
    ) -> None:
        self.source = source
        self.returncode = returncode
        self.stderr_tail = tuple(stderr_tail)

        detail = message
        if returncode is not None:
            detail += f" (returncode={returncode})"
        if self.stderr_tail:
            detail += "; stderr_tail=" + " | ".join(self.stderr_tail)

        super().__init__(detail)


class SourceUnavailableError(SourceExecutionError):
    """Configured passive source executable is unavailable."""


class SourceTimeoutError(SourceExecutionError):
    """Passive source exceeded its outer process timeout."""


@dataclass(frozen=True, slots=True)
class SourceRunStats:
    """Internal per-adapter execution statistics."""

    source: str
    findings: int
    published: int
    duplicates: int
    rejected: int


class SubfinderSource:
    """Streaming ProjectDiscovery Subfinder adapter."""

    name = "subfinder"

    def __init__(
        self,
        config: SubfinderConfig | None = None,
    ) -> None:
        self.config = config or SubfinderConfig()

    def command_for(self, domain: str) -> tuple[str, ...]:
        """Build argv without invoking a shell."""
        normalized_domain = normalize_dns_name(domain)

        args: list[str] = [
            self.config.binary,
            "-d",
            normalized_domain,
            "-oJ",
            "-cs",
            "-duc",
            "-nc",
            "-timeout",
            str(self.config.source_timeout_seconds),
            "-max-time",
            str(self.config.max_time_minutes),
        ]

        if self.config.recursive:
            args.append("-recursive")

        if self.config.all_sources:
            args.append("-all")

        if self.config.sources:
            args.extend(
                (
                    "-s",
                    ",".join(self.config.sources),
                )
            )

        if self.config.exclude_sources:
            args.extend(
                (
                    "-es",
                    ",".join(self.config.exclude_sources),
                )
            )

        if self.config.rate_limit is not None:
            args.extend(
                (
                    "-rl",
                    str(self.config.rate_limit),
                )
            )

        if self.config.max_results_per_source is not None:
            args.extend(
                (
                    "-mr",
                    str(self.config.max_results_per_source),
                )
            )

        if self.config.config_path is not None:
            args.extend(
                (
                    "-config",
                    str(self.config.config_path),
                )
            )

        if self.config.provider_config_path is not None:
            args.extend(
                (
                    "-pc",
                    str(self.config.provider_config_path),
                )
            )

        args.extend(self.config.extra_args)
        return tuple(args)

    async def stream(
        self,
        domain: str,
    ) -> AsyncIterator[PassiveDomainFinding]:
        """Run Subfinder and stream normalized JSONL/plain-text findings."""
        command = self.command_for(domain)
        binary = command[0]

        executable = _resolve_executable(binary)
        if executable is None:
            raise SourceUnavailableError(
                source=self.name,
                message=f"executable not found: {binary}",
            )

        command = (executable, *command[1:])

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=self.config.stream_limit_bytes,
            env=os.environ.copy(),
        )

        if process.stdout is None or process.stderr is None:
            await _terminate_process(process)
            raise SourceExecutionError(
                source=self.name,
                message="subprocess pipes were not created",
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

                    for finding in parse_subfinder_line(line):
                        yield finding
            except TimeoutError as exc:
                await _terminate_process(process)
                raise SourceTimeoutError(
                    source=self.name,
                    message=(
                        "Subfinder exceeded outer process timeout "
                        f"({self.config.process_timeout_seconds}s)"
                    ),
                    stderr_tail=tuple(stderr_tail),
                ) from exc

            returncode = completed_process_returncode(process)
            if returncode != 0:
                raise SourceExecutionError(
                    source=self.name,
                    message="Subfinder exited unsuccessfully",
                    returncode=returncode,
                    stderr_tail=tuple(stderr_tail),
                )
        finally:
            if process.returncode is None:
                await _terminate_process(process)

            try:
                await stderr_task
            except asyncio.CancelledError:
                raise
            except Exception:
                # stderr collection must never mask the real tool outcome.
                pass


class PassiveDomainsWorker:
    """Load a domain Event, run passive sources, and publish DNS_NAME Events."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        sources: Sequence[PassiveDomainSource] | None = None,
        config: PassiveDomainsConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._sources = tuple(
            sources if sources is not None else (SubfinderSource(),)
        )
        self._config = config or PassiveDomainsConfig()

        if not self._sources:
            raise ValueError(
                "PassiveDomainsWorker requires at least one source"
            )

        source_names = [source.name for source in self._sources]
        if len(source_names) != len(set(source_names)):
            raise ValueError(
                "passive source names must be unique"
            )

    async def execute(self, task: Task) -> WorkerExecutionResult:
        """Execute an already-authorized passive domain task."""
        if task.status.value != "RUNNING":
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "passive_domains worker may only execute claimed "
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

        if task.action != ACTION_ENUMERATE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported passive_domains action: {task.action}",
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

        if input_event.type not in {
            EventType.ROOT_DOMAIN,
            EventType.DNS_NAME,
        }:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "passive domain enumeration requires ROOT_DOMAIN "
                    f"or DNS_NAME input, got {input_event.type.value}"
                ),
            )

        try:
            seed_domain = normalize_dns_name(
                input_event.value
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"invalid input domain: {exc}",
            )

        successful_sources = 0
        errors: list[str] = []

        for source in self._sources:
            try:
                await self._run_source(
                    source,
                    input_event=input_event,
                    seed_domain=seed_domain,
                )
            except SourceUnavailableError as exc:
                # Missing configured binary is a local configuration problem,
                # not a transient target/provider condition.
                errors.append(str(exc))
                continue
            except SourceExecutionError as exc:
                errors.append(str(exc))
                continue
            else:
                successful_sources += 1

        if successful_sources > 0:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.SUCCEEDED,
            )

        joined = "; ".join(errors) or (
            "all passive domain sources produced no executable run"
        )

        if self._config.fail_if_all_sources_fail:
            # Missing executables are terminal configuration failures. Other
            # source/provider failures are generally worth retrying.
            if errors and all(
                "executable not found" in error
                for error in errors
            ):
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.FAILED,
                    error=joined,
                )

            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=joined,
                retry_after_seconds=(
                    self._config.retry_after_seconds
                ),
            )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _run_source(
        self,
        source: PassiveDomainSource,
        *,
        input_event: Event,
        seed_domain: str,
    ) -> SourceRunStats:
        seen: set[tuple[str, str]] = set()

        findings = 0
        published = 0
        duplicates = 0
        rejected = 0

        async for finding in source.stream(seed_domain):
            findings += 1

            try:
                hostname = normalize_dns_name(
                    finding.hostname
                )
            except ValueError:
                rejected += 1
                continue

            # A passive provider can contain stale/malformed/cross-domain data.
            # Only retain strict descendants of the task seed here.
            if not is_strict_subdomain(
                hostname,
                seed_domain,
            ):
                rejected += 1
                continue

            provider_component = _source_component(
                finding.provider or "unknown"
            )
            dedupe_key = (
                hostname,
                provider_component,
            )

            if dedupe_key in seen:
                duplicates += 1
                continue
            seen.add(dedupe_key)

            source_name = (
                f"{WORKER_NAME}:{_source_component(source.name)}:"
                f"{provider_component}"
            )

            metadata = {
                "passive": True,
                "adapter": source.name,
                "provider": finding.provider,
                "seed_domain": seed_domain,
                **finding.metadata,
            }

            event = Event(
                type=EventType.DNS_NAME,
                value=hostname,
                source=source_name[:128],
                parent_event_id=input_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=(
                    self._config.confidence_named_provider
                    if finding.provider
                    else self._config.confidence_single_provider
                ),
                novelty=0.5,
                depth=input_event.depth + 1,
                tags={
                    "passive",
                    "subdomain",
                    f"adapter:{_source_component(source.name)}",
                },
                metadata=metadata,
            )

            accepted = await self._publisher.publish(event)
            if accepted:
                published += 1
            else:
                duplicates += 1

        return SourceRunStats(
            source=source.name,
            findings=findings,
            published=published,
            duplicates=duplicates,
            rejected=rejected,
        )


def passive_domain_route_rules(
    *,
    include_dns_name_seeds: bool = False,
    base_priority: float = 5.0,
) -> tuple[RouteRule, ...]:
    """Return Router rules exposed by this worker.

    By default only ROOT_DOMAIN is automatically routed. Recursively scheduling
    every discovered DNS_NAME can create explosive fan-out, so that behavior
    must be explicitly enabled by a pipeline profile/convergence policy.
    """
    accepts = {EventType.ROOT_DOMAIN}

    if include_dns_name_seeds:
        accepts.add(EventType.DNS_NAME)

    return (
        RouteRule(
            rule_id="passive_domains.enumerate",
            accepts=frozenset(accepts),
            worker=WORKER_NAME,
            action=ACTION_ENUMERATE,
            reason=(
                "enumerate descendant DNS names from passive sources"
            ),
            base_priority=base_priority,
        ),
    )


def parse_subfinder_line(
    line: str,
) -> tuple[PassiveDomainFinding, ...]:
    """Parse one Subfinder output line.

    Current Subfinder supports JSONL. This parser is intentionally tolerant of
    small schema differences across versions and falls back to plain hostname
    lines, which also makes fixtures/simple adapters easy to test.
    """
    normalized_line = line.strip()
    if not normalized_line:
        return ()

    try:
        payload = json.loads(normalized_line)
    except json.JSONDecodeError:
        return (
            PassiveDomainFinding(
                hostname=normalized_line,
                adapter="subfinder",
                provider=None,
                metadata={"output_format": "plain"},
            ),
        )

    if isinstance(payload, str):
        return (
            PassiveDomainFinding(
                hostname=payload,
                adapter="subfinder",
                provider=None,
                metadata={"output_format": "json-string"},
            ),
        )

    if not isinstance(payload, dict):
        return ()

    hostname = _first_string(
        payload,
        (
            "host",
            "hostname",
            "subdomain",
            "domain",
            "value",
        ),
    )
    if hostname is None:
        return ()

    providers = _provider_names(payload)

    metadata: dict[str, Any] = {
        "output_format": "jsonl",
    }

    input_value = _first_string(
        payload,
        (
            "input",
            "root",
        ),
    )
    if input_value is not None:
        metadata["tool_input"] = input_value

    if not providers:
        return (
            PassiveDomainFinding(
                hostname=hostname,
                adapter="subfinder",
                provider=None,
                metadata=metadata,
            ),
        )

    return tuple(
        PassiveDomainFinding(
            hostname=hostname,
            adapter="subfinder",
            provider=provider,
            metadata=metadata,
        )
        for provider in providers
    )


def normalize_dns_name(value: str) -> str:
    """Canonicalize a concrete hostname-like DNS name.

    Wildcards, URLs, ports, whitespace-containing values, and labels that
    cannot safely be used as host candidates are rejected.
    """
    raw = value.strip().lower().rstrip(".")

    if not raw:
        raise ValueError("DNS name is blank")

    if raw.startswith("*."):
        raise ValueError("wildcard DNS names are not concrete host candidates")

    if "://" in raw:
        raise ValueError("URL supplied where DNS name was expected")

    if any(character.isspace() for character in raw):
        raise ValueError("DNS names cannot contain whitespace")

    if "/" in raw or "@" in raw:
        raise ValueError("invalid hostname delimiter")

    # An unbracketed colon is most likely a host:port or IPv6 value. Neither is
    # a concrete DNS hostname for this worker.
    if ":" in raw:
        raise ValueError("ports/IP literals are not DNS hostname candidates")

    labels = raw.split(".")
    if len(labels) < 2:
        raise ValueError("DNS name must contain at least two labels")

    encoded_labels: list[str] = []

    for label in labels:
        if not label:
            raise ValueError("DNS name contains an empty label")

        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(
                f"invalid IDNA label: {label!r}"
            ) from exc

        if not _ASCII_HOST_LABEL_RE.fullmatch(ascii_label):
            raise ValueError(
                f"invalid hostname label: {label!r}"
            )

        if ascii_label.startswith("-") or ascii_label.endswith("-"):
            raise ValueError(
                f"hostname label cannot start/end with '-': {label!r}"
            )

        encoded_labels.append(ascii_label)

    normalized = ".".join(encoded_labels)

    if len(normalized) > 253:
        raise ValueError("DNS name exceeds 253 characters")

    return normalized


def is_strict_subdomain(
    candidate: str,
    parent: str,
) -> bool:
    """Return True only for dot-boundary descendants, never the apex."""
    normalized_candidate = normalize_dns_name(candidate)
    normalized_parent = normalize_dns_name(parent)

    return (
        normalized_candidate != normalized_parent
        and normalized_candidate.endswith(
            "." + normalized_parent
        )
    )


def _provider_names(payload: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []

    for key in (
        "sources",
        "source",
        "providers",
        "provider",
    ):
        raw = payload.get(key)

        if isinstance(raw, str):
            # Some tools encode a comma-separated source list.
            values.extend(
                item.strip()
                for item in raw.split(",")
                if item.strip()
            )
        elif isinstance(raw, list):
            values.extend(
                str(item).strip()
                for item in raw
                if str(item).strip()
            )

    return tuple(sorted(set(values)))


def _first_string(
    payload: dict[str, Any],
    keys: Iterable[str],
) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str):
            normalized = value.strip()
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
    """Resolve either an explicit path or PATH executable."""
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
    """Continuously drain stderr so a noisy child cannot deadlock."""
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
    """Terminate a subprocess and escalate to kill if necessary."""
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
