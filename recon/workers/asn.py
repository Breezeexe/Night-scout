"""Passive ASN/network relationship discovery for Night Scout.

This worker enriches an already-known IP_ADDRESS using ProjectDiscovery
`asnmap`. It does not contact the bug-bounty target itself and it does not turn
ASN ownership into authorization.

Default flow
------------
IP_ADDRESS
    203.0.113.10
        |
        | passive asnmap lookup
        v
ASN
    AS64500
        |
        +--> CIDR 203.0.113.0/24       contains_input_ip=True
        +--> CIDR 198.51.100.0/24      contains_input_ip=False

Every derived ASN/CIDR is stored with scope=UNKNOWN. A range returned for the
same ASN can be useful context, but shared hosting, CDNs, subsidiaries and
provider infrastructure make "same ASN" an unsafe scope inference.

The initial worker intentionally supports IP input only. Although asnmap can
accept domains, ASNs and organization names, automatically using those modes
would blur several distinct questions:

- DNS_NAME -> IP is already handled by workers/dns.py.
- IP -> ASN/CIDR is this worker.
- organization -> ASN is ownership research and should be a separate,
  explicitly reviewed capability.
- ASN -> every CIDR can massively expand the frontier and must never imply
  permission for active probing.

Current ProjectDiscovery asnmap uses the ProjectDiscovery Cloud API and accepts
credentials through its normal configuration/environment. This adapter never
invokes interactive `-auth`.

No target RateLimiter permit is consumed here because the network request is
to the passive ASN data service, not to the program target. Provider-specific
API throttling can later be added independently from target-node rate limits.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
from collections import deque
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule

WORKER_NAME = "asn"
ACTION_LOOKUP_IP = "lookup_ip"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_ASN_RE = re.compile(r"^AS([0-9]{1,10})$", re.IGNORECASE)


class ASNLookupResult(BaseModel):
    """Normalized result from one passive asnmap JSON object."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    query_ip: str

    asn: str
    name: str | None = None
    country: str | None = None

    ranges: tuple[str, ...] = ()

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("query_ip")
    @classmethod
    def normalize_query_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("asn")
    @classmethod
    def normalize_asn(cls, value: str) -> str:
        return normalize_asn(value)

    @field_validator("name")
    @classmethod
    def normalize_name(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @field_validator("country")
    @classmethod
    def normalize_country(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip().upper()
        return normalized or None

    @field_validator("ranges")
    @classmethod
    def normalize_ranges(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized: set[str] = set()

        for value in values:
            try:
                network = ipaddress.ip_network(
                    value.strip(),
                    strict=False,
                )
            except ValueError:
                continue

            normalized.add(str(network))

        return tuple(
            sorted(
                normalized,
                key=lambda value: (
                    ipaddress.ip_network(value).version,
                    int(
                        ipaddress.ip_network(
                            value
                        ).network_address
                    ),
                    ipaddress.ip_network(value).prefixlen,
                ),
            )
        )


class InputEventProvider(Protocol):
    """Load task input Events."""

    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class EventPublisher(Protocol):
    """Publish normalized output into the Night Scout event pipeline."""

    async def publish(
        self,
        event: Event,
    ) -> bool:
        ...


class ASNLookupBackend(Protocol):
    """Passive IP -> ASN/CIDR lookup backend."""

    name: str

    def ensure_available(self) -> None:
        ...

    def lookup_ip(
        self,
        ip: str,
    ) -> AsyncIterator[ASNLookupResult]:
        ...


class AsnmapConfig(BaseModel):
    """ProjectDiscovery asnmap subprocess configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "asnmap"

    config_path: Path | None = None

    process_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
    )

    stderr_tail_lines: int = Field(
        default=80,
        ge=1,
        le=1000,
    )
    stream_limit_bytes: int = Field(
        default=1024 * 1024,
        ge=65536,
    )

    extra_args: tuple[str, ...] = ()

    @field_validator("binary")
    @classmethod
    def binary_required(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "binary must not be blank"
            )

        return normalized

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
            # Input mode belongs to the task.
            "-a",
            "-asn",
            "-i",
            "-ip",
            "-d",
            "-domain",
            "-org",
            "-f",
            "-file",

            # Resolver use is unnecessary for IP-only lookup.
            "-r",
            "-resolvers",

            # Configuration/auth are explicit adapter concerns. In particular,
            # never enter interactive `-auth` from an unattended worker.
            "-config",
            "-auth",

            # Update behavior.
            "-up",
            "-update",

            # Output must remain JSONL-ish stdout.
            "-o",
            "-output",
            "-c",
            "-csv",
            "-v",
            "-verbose",
            "-version",
            "-j",
            "-json",
            "-silent",
        }

        if any(
            value in forbidden
            for value in normalized
        ):
            raise ValueError(
                "asnmap extra_args cannot override input mode, auth, "
                "resolver behavior, or structured stdout"
            )

        return normalized


class ASNWorkerConfig(BaseModel):
    """Event confidence/behavior for passive ASN enrichment."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    asn_confidence: float = Field(
        default=0.92,
        ge=0.0,
        le=1.0,
    )
    containing_range_confidence: float = Field(
        default=0.92,
        ge=0.0,
        le=1.0,
    )
    related_range_confidence: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
    )

    retry_after_seconds: float = Field(
        default=30.0,
        ge=0.0,
    )


class ASNBackendError(RuntimeError):
    """asnmap/backend execution failure."""


class ASNBackendUnavailable(ASNBackendError):
    """Configured asnmap binary is unavailable."""


class ASNBackendTimeout(ASNBackendError):
    """asnmap exceeded its outer timeout."""


class AsnmapBackend:
    """One-IP-at-a-time ProjectDiscovery asnmap adapter."""

    name = "asnmap"

    def __init__(
        self,
        config: AsnmapConfig | None = None,
    ) -> None:
        self.config = config or AsnmapConfig()

    def ensure_available(self) -> None:
        if (
            _resolve_executable(
                self.config.binary
            )
            is None
        ):
            raise ASNBackendUnavailable(
                "asnmap executable not found: "
                f"{self.config.binary}"
            )

    def command_for(self) -> tuple[str, ...]:
        """Build a non-interactive JSON stdout command."""
        executable = _resolve_executable(
            self.config.binary
        )
        binary = executable or self.config.binary

        args: list[str] = [
            binary,
            "-j",
            "-silent",
            "-duc",
        ]

        if self.config.config_path is not None:
            args.extend(
                (
                    "-config",
                    str(
                        self.config.config_path
                    ),
                )
            )

        args.extend(
            self.config.extra_args
        )

        return tuple(args)

    async def lookup_ip(
        self,
        ip: str,
    ) -> AsyncIterator[ASNLookupResult]:
        canonical_ip = str(
            ipaddress.ip_address(
                ip.strip()
            )
        )

        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(),
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
            raise ASNBackendError(
                "asnmap subprocess pipes were not created"
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
            process.stdin.write(
                (
                    canonical_ip
                    + "\n"
                ).encode("utf-8")
            )
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

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

                        result = parse_asnmap_line(
                            line,
                            expected_ip=canonical_ip,
                        )

                        if result is not None:
                            yield result

                    returncode = (
                        await process.wait()
                    )

            except TimeoutError as exc:
                await _terminate_process(
                    process
                )

                raise ASNBackendTimeout(
                    "asnmap exceeded outer process "
                    f"timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                detail = " | ".join(
                    stderr_tail
                )

                raise ASNBackendError(
                    "asnmap exited unsuccessfully "
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
                # stderr collection should not hide
                # the actual backend outcome.
                pass


class ASNWorker:
    """Passive IP -> ASN/CIDR relationship worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        backend: ASNLookupBackend | None = None,
        config: ASNWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._backend = (
            backend
            or AsnmapBackend()
        )
        self._config = (
            config
            or ASNWorkerConfig()
        )

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        """Passively enrich one IP_ADDRESS observation."""
        if (
            task.status
            is not TaskStatus.RUNNING
        ):
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "asn worker may only execute claimed "
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
            != ACTION_LOOKUP_IP
        ):
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "unsupported asn action: "
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

        if (
            input_event.type
            is not EventType.IP_ADDRESS
        ):
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "asn.lookup_ip requires "
                    "IP_ADDRESS input, got "
                    f"{input_event.type.value}"
                ),
            )

        try:
            query_ip = str(
                ipaddress.ip_address(
                    input_event.value.strip()
                )
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=(
                    "invalid input IP address: "
                    f"{exc}"
                ),
            )

        try:
            self._backend.ensure_available()
        except ASNBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.FAILED
                ),
                error=str(exc),
            )

        saw_result = False

        try:
            async for result in (
                self._backend.lookup_ip(
                    query_ip
                )
            ):
                if (
                    result.query_ip
                    != query_ip
                ):
                    # Do not let malformed provider output
                    # redirect this task to another subject.
                    continue

                saw_result = True

                await self._publish_result(
                    input_event=input_event,
                    result=result,
                )

        except ASNBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.RETRY
                ),
                error=str(exc),
                retry_after_seconds=(
                    self._config.retry_after_seconds
                ),
            )
        except ASNBackendError as exc:
            return WorkerExecutionResult(
                outcome=(
                    WorkerOutcome.RETRY
                ),
                error=str(exc),
                retry_after_seconds=(
                    self._config.retry_after_seconds
                ),
            )

        # Empty output is not automatically a tool failure:
        # provider data may legitimately have no mapping.
        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _publish_result(
        self,
        *,
        input_event: Event,
        result: ASNLookupResult,
    ) -> None:
        source = (
            "asn:"
            + _source_component(
                self._backend.name
            )
        )

        asn_event = Event(
            type=EventType.ASN,
            value=result.asn,
            source=source,
            parent_event_id=(
                input_event.event_id
            ),
            scope_state=ScopeState.UNKNOWN,
            confidence=(
                self._config.asn_confidence
            ),
            novelty=0.55,
            depth=input_event.depth + 1,
            tags={
                "passive",
                "asn",
                "network-context",
                "relationship-only",
                "not-authorized",
            },
            metadata={
                "query_ip": result.query_ip,
                "as_name": result.name,
                "as_country": result.country,
                "range_count": len(
                    result.ranges
                ),
                "authorization_inference": False,
                **result.metadata,
            },
        )

        asn_accepted = (
            await self._publisher.publish(
                asn_event
            )
        )

        child_parent_event_id = (
            asn_event.event_id
            if asn_accepted
            else input_event.event_id
        )

        query_ip = ipaddress.ip_address(
            result.query_ip
        )

        for cidr in result.ranges:
            network = (
                ipaddress.ip_network(
                    cidr,
                    strict=False,
                )
            )

            contains_input_ip = (
                query_ip.version
                == network.version
                and query_ip in network
            )

            cidr_event = Event(
                type=EventType.CIDR,
                value=str(network),
                source=source,
                parent_event_id=(
                    child_parent_event_id
                ),
                scope_state=(
                    ScopeState.UNKNOWN
                ),
                confidence=(
                    self._config.containing_range_confidence
                    if contains_input_ip
                    else self._config.related_range_confidence
                ),
                novelty=(
                    0.50
                    if contains_input_ip
                    else 0.35
                ),
                depth=(
                    input_event.depth + 2
                ),
                tags={
                    "passive",
                    "asn",
                    "cidr",
                    "network-context",
                    "relationship-only",
                    "not-authorized",
                    (
                        "contains-input-ip"
                        if contains_input_ip
                        else "same-asn-range"
                    ),
                },
                metadata={
                    "asn": result.asn,
                    "as_name": result.name,
                    "as_country": (
                        result.country
                    ),
                    "query_ip": (
                        result.query_ip
                    ),
                    "contains_input_ip": (
                        contains_input_ip
                    ),
                    "authorization_inference": False,
                    "active_followup_allowed": False,
                },
            )

            await self._publisher.publish(
                cidr_event
            )


def asn_route_rules(
    *,
    base_priority: float = 4.5,
) -> tuple[RouteRule, ...]:
    """Route known IP observations into passive ASN enrichment."""
    return (
        RouteRule(
            rule_id="asn.lookup-ip",
            accepts=frozenset(
                {EventType.IP_ADDRESS}
            ),
            worker=WORKER_NAME,
            action=ACTION_LOOKUP_IP,
            reason=(
                "passively map known IP to ASN/CIDR "
                "relationship context"
            ),
            base_priority=base_priority,
        ),
    )


def parse_asnmap_line(
    line: str,
    *,
    expected_ip: str,
) -> ASNLookupResult | None:
    """Parse one asnmap JSON object.

    Current asnmap JSON fields include:
        input
        as_number
        as_name
        as_country
        as_range

    The parser tolerates string/list range representations and integer/string
    ASN values while refusing to accept output for a different query IP.
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

    if not isinstance(payload, dict):
        return None

    canonical_expected = str(
        ipaddress.ip_address(
            expected_ip.strip()
        )
    )

    raw_input = payload.get(
        "input"
    )

    if not isinstance(
        raw_input,
        str,
    ):
        return None

    try:
        canonical_input = str(
            ipaddress.ip_address(
                raw_input.strip()
            )
        )
    except ValueError:
        return None

    if (
        canonical_input
        != canonical_expected
    ):
        return None

    raw_asn = payload.get(
        "as_number"
    )

    if raw_asn is None:
        return None

    try:
        asn = normalize_asn(
            str(raw_asn)
        )
    except ValueError:
        return None

    ranges = _range_values(
        payload.get("as_range")
    )

    known = {
        "timestamp",
        "input",
        "as_number",
        "as_name",
        "as_country",
        "as_range",
    }

    metadata = {
        key: value
        for key, value
        in payload.items()
        if key not in known
    }

    return ASNLookupResult(
        query_ip=canonical_input,
        asn=asn,
        name=_optional_text(
            payload.get("as_name")
        ),
        country=_optional_text(
            payload.get(
                "as_country"
            )
        ),
        ranges=ranges,
        metadata=metadata,
    )


def normalize_asn(
    value: str,
) -> str:
    """Canonicalize AS13335 / 13335 into AS13335."""
    normalized = value.strip().upper()

    if normalized.isdigit():
        normalized = (
            "AS"
            + normalized
        )

    match = _ASN_RE.fullmatch(
        normalized
    )

    if match is None:
        raise ValueError(
            f"invalid ASN value: {value!r}"
        )

    number = int(
        match.group(1)
    )

    # RFC 6793 uses a 32-bit ASN space.
    if not (
        0 <= number <= 4_294_967_295
    ):
        raise ValueError(
            f"ASN is outside 32-bit range: {value!r}"
        )

    return f"AS{number}"


def _range_values(
    value: Any,
) -> tuple[str, ...]:
    if isinstance(value, str):
        raw_values = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]
    elif isinstance(
        value,
        (list, tuple, set),
    ):
        raw_values = [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]
    else:
        raw_values = []

    networks: set[str] = set()

    for raw in raw_values:
        try:
            network = (
                ipaddress.ip_network(
                    raw,
                    strict=False,
                )
            )
        except ValueError:
            continue

        networks.add(
            str(network)
        )

    return tuple(
        sorted(
            networks,
            key=lambda cidr: (
                ipaddress.ip_network(
                    cidr
                ).version,
                int(
                    ipaddress.ip_network(
                        cidr
                    ).network_address
                ),
                ipaddress.ip_network(
                    cidr
                ).prefixlen,
            ),
        )
    )


def _optional_text(
    value: Any,
) -> str | None:
    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    return normalized or None


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
