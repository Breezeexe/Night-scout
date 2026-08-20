"""Controlled TLS certificate inspection for Night Scout.

Consumes confirmed DNS_NAME observations and performs one rate-limited TLS
connection using ProjectDiscovery tlsx. It emits CERTIFICATE, CERT_SAN and
scope-UNKNOWN DNS/IP hypotheses discovered from certificate names.

Certificate relations are evidence, not authorization: SAN/CN targets never
inherit IN_SCOPE automatically.

For predictable accounting the tlsx adapter fixes:
- scan mode: ctls
- concurrency: 1
- retry: 0

and intentionally does not enable JARM/JA3, cipher/version enumeration,
revocation checks, scan-all-ips, CT streaming, PTR-derived SNI, or raw
certificate-chain storage.
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
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

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
)
from recon.workers.passive_domains import normalize_dns_name

WORKER_NAME = "tls"
ACTION_INSPECT = "inspect"

_SOURCE_COMPONENT_RE = re.compile(r"[^a-z0-9_.-]+")
_HEX_RE = re.compile(r"^[0-9a-f]+$")


class TLSTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    port: int = Field(default=443, ge=1, le=65535)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @property
    def authority(self) -> str:
        return f"{self.hostname}:{self.port}"


class TLSProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    port: int = Field(default=443, ge=1, le=65535)
    probe_status: bool = False

    ip: str | None = None
    sni: str | None = None

    tls_version: str | None = None
    cipher: str | None = None
    tls_connection: str | None = None

    subject_dn: str | None = None
    subject_cn: str | None = None
    subject_org: tuple[str, ...] = ()
    subject_alt_names: tuple[str, ...] = ()

    issuer_dn: str | None = None
    issuer_cn: str | None = None
    issuer_org: tuple[str, ...] = ()

    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None

    fingerprint_sha256: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return normalize_dns_name(value)

    @field_validator("ip")
    @classmethod
    def normalize_ip(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return None

    @field_validator(
        "sni",
        "tls_version",
        "cipher",
        "tls_connection",
        "subject_dn",
        "subject_cn",
        "issuer_dn",
        "issuer_cn",
        "serial",
        "not_before",
        "not_after",
        "fingerprint_sha256",
    )
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("subject_org", "issuer_org", "subject_alt_names")
    @classmethod
    def normalize_sets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({v.strip() for v in values if v.strip()}))


class InputEventProvider(Protocol):
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class TLSProbeBackend(Protocol):
    name: str

    def ensure_available(self) -> None:
        ...

    def inspect(
        self,
        target: TLSTarget,
    ) -> AsyncIterator[TLSProbeResult]:
        ...


class TlsxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "tlsx"
    timeout_seconds: int = Field(default=5, ge=1, le=120)
    process_timeout_seconds: float = Field(default=12.0, gt=0.0)
    scan_mode: str = "ctls"

    stderr_tail_lines: int = Field(default=80, ge=1, le=1000)
    stream_limit_bytes: int = Field(default=1024 * 1024, ge=65536)

    extra_args: tuple[str, ...] = ()

    @field_validator("binary")
    @classmethod
    def binary_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("binary must not be blank")
        return value

    @field_validator("scan_mode")
    @classmethod
    def require_ctls(cls, value: str) -> str:
        value = value.strip().lower()
        if value != "ctls":
            raise ValueError(
                "Night Scout initial TLS adapter requires scan_mode='ctls'"
            )
        return value

    @field_validator("extra_args")
    @classmethod
    def reject_overrides(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(v.strip() for v in values if v.strip())

        forbidden = {
            "-u", "-host", "-l", "-list", "-p", "-port",
            "-sa", "-scan-all-ips", "-iv", "-ip-version",
            "-rps", "-rev-ptr-sni", "-rs", "-random-sni", "-sni",
            "-sm", "-scan-mode", "-ps", "-pre-handshake",
            "-c", "-concurrency", "-retry", "-timeout", "-delay",
            "-jarm", "-ja3", "-ve", "-version-enum",
            "-ce", "-cipher-enum", "-ct", "-cipher-type",
            "-ci", "-cipher-input", "-min-version", "-max-version",
            "-ex", "-expired", "-ss", "-self-signed",
            "-mm", "-mismatched", "-re", "-revoked",
            "-un", "-untrusted", "-vc", "-verify-cert",
            "-cert", "-certificate", "-tc", "-tls-chain",
            "-ch", "-client-hello", "-sh", "-server-hello",
            "-o", "-output", "-pd", "-dashboard", "-pdu",
            "-dashboard-upload", "-auth", "-tid", "-team-id",
            "-aid", "-asset-id", "-aname", "-asset-name",
            "-ctl", "-cb", "-ctl-beginning", "-cti", "-ctl-index",
            "-j", "-json", "-san", "-cn", "-so",
            "-tv", "-tls-version", "-cipher", "-hash",
            "-se", "-serial", "-tps", "-probe-status",
            "-dns", "-ro", "-resp-only",
        }

        if any(v in forbidden for v in normalized):
            raise ValueError(
                "tlsx extra_args cannot override target expansion, "
                "connection accounting, probe set, or output"
            )

        return normalized


class TLSWorkerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    default_port: int = Field(default=443, ge=1, le=65535)
    rate_lease_seconds: float = Field(default=20.0, gt=0.0)

    certificate_confidence: float = Field(default=0.98, ge=0.0, le=1.0)
    san_confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    derived_target_confidence: float = Field(default=0.85, ge=0.0, le=1.0)

    default_retry_after_seconds: float = Field(default=5.0, ge=0.0)


class TLSBackendError(RuntimeError):
    pass


class TLSBackendUnavailable(TLSBackendError):
    pass


class TLSBackendTimeout(TLSBackendError):
    pass


class TlsxBackend:
    name = "tlsx"

    def __init__(self, config: TlsxConfig | None = None) -> None:
        self.config = config or TlsxConfig()

    def ensure_available(self) -> None:
        if _resolve_executable(self.config.binary) is None:
            raise TLSBackendUnavailable(
                f"tlsx executable not found: {self.config.binary}"
            )

    def command_for(self) -> tuple[str, ...]:
        executable = _resolve_executable(self.config.binary)
        binary = executable or self.config.binary

        args = [
            binary,
            "-j", "-silent", "-nc", "-duc",
            "-sm", self.config.scan_mode,
            "-c", "1",
            "-retry", "0",
            "-timeout", str(self.config.timeout_seconds),
            "-san", "-cn", "-so",
            "-tv", "-cipher",
            "-hash", "sha256",
            "-se", "-tps",
        ]
        args.extend(self.config.extra_args)
        return tuple(args)

    async def inspect(
        self,
        target: TLSTarget,
    ) -> AsyncIterator[TLSProbeResult]:
        self.ensure_available()

        process = await asyncio.create_subprocess_exec(
            *self.command_for(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=self.config.stream_limit_bytes,
            env=os.environ.copy(),
        )

        if process.stdin is None or process.stdout is None or process.stderr is None:
            await _terminate_process(process)
            raise TLSBackendError("tlsx subprocess pipes were not created")

        stderr_tail: deque[str] = deque(maxlen=self.config.stderr_tail_lines)
        stderr_task = asyncio.create_task(
            _drain_stderr(process.stderr, stderr_tail)
        )

        try:
            process.stdin.write((target.authority + "\n").encode())
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            try:
                async with asyncio.timeout(self.config.process_timeout_seconds):
                    while True:
                        raw = await process.stdout.readline()
                        if not raw:
                            break
                        result = parse_tlsx_line(
                            raw.decode("utf-8", errors="replace").strip()
                        )
                        if result is not None:
                            yield result

                    returncode = await process.wait()
            except TimeoutError as exc:
                await _terminate_process(process)
                raise TLSBackendTimeout(
                    f"tlsx exceeded outer timeout "
                    f"({self.config.process_timeout_seconds}s)"
                ) from exc

            if returncode != 0:
                tail = " | ".join(stderr_tail)
                raise TLSBackendError(
                    f"tlsx exited unsuccessfully (returncode={returncode})"
                    + (f"; stderr_tail={tail}" if tail else "")
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


class TLSWorker:
    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        backend: TLSProbeBackend | None = None,
        config: TLSWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._backend = backend or TlsxBackend()
        self._config = config or TLSWorkerConfig()

    async def execute(self, task: Task) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "tls worker may only execute claimed RUNNING tasks, "
                    f"got {task.status.value}"
                ),
            )

        if task.worker != self.name or task.action != ACTION_INSPECT:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    f"unsupported tls task: worker={task.worker} "
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
            target = target_from_event(
                input_event,
                default_port=self._config.default_port,
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        try:
            self._backend.ensure_available()
        except TLSBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        context = RateLimitContext(
            resource_keys=frozenset({f"host:{target.hostname}"})
        )

        decision = await self._rate_limiter.acquire(
            task,
            context=context,
            demand=RateLimitDemand(requests=1.0, concurrency=1),
            lease_for=timedelta(seconds=self._config.rate_lease_seconds),
        )

        if decision.outcome is RateLimitOutcome.DEFER:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=decision.reason or "TLS rate limit temporarily exhausted",
                retry_after_seconds=(
                    decision.retry_after_seconds
                    if decision.retry_after_seconds is not None
                    else self._config.default_retry_after_seconds
                ),
            )

        if decision.outcome is RateLimitOutcome.DENY:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=decision.reason or "TLS rate policy denied execution",
            )

        lease_id = decision.lease.lease_id if decision.lease is not None else None

        try:
            async for result in self._backend.inspect(target):
                if (
                    result.hostname != target.hostname
                    or result.port != target.port
                    or not result.probe_status
                ):
                    continue
                await self._publish_result(
                    input_event=input_event,
                    result=result,
                )
        except (TLSBackendTimeout, TLSBackendError) as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.default_retry_after_seconds,
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(lease_id)

        return WorkerExecutionResult(outcome=WorkerOutcome.SUCCEEDED)

    async def _publish_result(
        self,
        *,
        input_event: Event,
        result: TLSProbeResult,
    ) -> None:
        cert = Event(
            type=EventType.CERTIFICATE,
            value=certificate_identity(result),
            source=f"tls:{_source_component(self._backend.name)}",
            parent_event_id=input_event.event_id,
            scope_state=ScopeState.UNKNOWN,
            confidence=self._config.certificate_confidence,
            novelty=0.65,
            depth=input_event.depth + 1,
            tags={"tls", "certificate", "confirmed", "snapshot:tls"},
            metadata={
                "observed_on": f"{result.hostname}:{result.port}",
                "hostname": result.hostname,
                "port": result.port,
                "ip": result.ip,
                "sni": result.sni,
                "tls_version": result.tls_version,
                "cipher": result.cipher,
                "tls_connection": result.tls_connection,
                "subject_dn": result.subject_dn,
                "subject_cn": result.subject_cn,
                "subject_org": list(result.subject_org),
                "issuer_dn": result.issuer_dn,
                "issuer_cn": result.issuer_cn,
                "issuer_org": list(result.issuer_org),
                "serial": result.serial,
                "not_before": result.not_before,
                "not_after": result.not_after,
                "fingerprint_sha256": result.fingerprint_sha256,
                "snapshot_kind": "TLS",
                "surface_state": {
                    "present": True,
                    "ips": [result.ip] if result.ip else [],
                    "status_code": None,
                    "title": None,
                    "body_hash": None,
                    "certificate_fingerprints": (
                        [result.fingerprint_sha256]
                        if result.fingerprint_sha256 else []
                    ),
                    "certificate_sans": list(result.subject_alt_names),
                    "javascript_hashes": [],
                    "endpoint_keys": [],
                    "scope_state": input_event.scope_state.value,
                    "extra": {
                        "port": result.port,
                        "sni": result.sni,
                        "tls_version": result.tls_version,
                        "cipher": result.cipher,
                        "issuer_cn": result.issuer_cn,
                        "subject_cn": result.subject_cn,
                        "serial": result.serial,
                        "not_before": result.not_before,
                        "not_after": result.not_after,
                    },
                },
                **result.metadata,
            },
        )

        cert_accepted = await self._publisher.publish(cert)
        parent_id = cert.event_id if cert_accepted else input_event.event_id

        names = [(v, "subject_an") for v in result.subject_alt_names]
        if result.subject_cn and result.subject_cn not in result.subject_alt_names:
            names.append((result.subject_cn, "subject_cn"))

        seen: set[tuple[str, str]] = set()

        for raw_name, field_source in names:
            normalized = normalize_certificate_name(raw_name)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)

            san_type, san_value = normalized

            san = Event(
                type=EventType.CERT_SAN,
                value=san_value,
                source=(
                    f"tls:{_source_component(self._backend.name)}:"
                    f"{field_source}"
                ),
                parent_event_id=parent_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=self._config.san_confidence,
                novelty=0.75,
                depth=input_event.depth + 2,
                tags={
                    "tls",
                    "certificate-name",
                    f"field:{field_source}",
                    f"san-type:{san_type.lower()}",
                },
                metadata={
                    "certificate_fingerprint_sha256": result.fingerprint_sha256,
                    "observed_on": f"{result.hostname}:{result.port}",
                    "field_source": field_source,
                    "san_type": san_type,
                },
            )

            san_accepted = await self._publisher.publish(san)
            derived_parent = san.event_id if san_accepted else parent_id

            if san_type == "DNS" and not san_value.startswith("*."):
                await self._publisher.publish(
                    Event(
                        type=EventType.DNS_NAME,
                        value=san_value,
                        source=san.source,
                        parent_event_id=derived_parent,
                        scope_state=ScopeState.UNKNOWN,
                        confidence=self._config.derived_target_confidence,
                        novelty=0.80,
                        depth=input_event.depth + 3,
                        tags={
                            "tls",
                            "certificate-name",
                            "dns-candidate",
                            "hypothesis",
                        },
                        metadata={
                            "discovered_via": "TLS_CERTIFICATE",
                            "certificate_fingerprint_sha256": (
                                result.fingerprint_sha256
                            ),
                            "certificate_field": field_source,
                            "observed_on": f"{result.hostname}:{result.port}",
                            "requires_scope_reclassification": True,
                        },
                    )
                )

            elif san_type == "IP":
                await self._publisher.publish(
                    Event(
                        type=EventType.IP_ADDRESS,
                        value=san_value,
                        source=san.source,
                        parent_event_id=derived_parent,
                        scope_state=ScopeState.UNKNOWN,
                        confidence=self._config.derived_target_confidence,
                        novelty=0.65,
                        depth=input_event.depth + 3,
                        tags={
                            "tls",
                            "certificate-name",
                            "ip-candidate",
                            "hypothesis",
                        },
                        metadata={
                            "discovered_via": "TLS_CERTIFICATE",
                            "certificate_fingerprint_sha256": (
                                result.fingerprint_sha256
                            ),
                            "certificate_field": field_source,
                            "observed_on": f"{result.hostname}:{result.port}",
                            "requires_scope_reclassification": True,
                        },
                    )
                )


def tls_route_rules(
    *,
    include_http_services: bool = False,
    base_priority: float = 8.25,
) -> tuple[RouteRule, ...]:
    rules = [
        RouteRule(
            rule_id="tls.inspect.confirmed-dns",
            accepts=frozenset({EventType.DNS_NAME}),
            worker=WORKER_NAME,
            action=ACTION_INSPECT,
            reason="inspect TLS certificate metadata on confirmed DNS name",
            base_priority=base_priority,
            required_tags=frozenset({"confirmed"}),
            excluded_tags=frozenset({"hypothesis"}),
        )
    ]

    if include_http_services:
        rules.append(
            RouteRule(
                rule_id="tls.inspect.https-service",
                accepts=frozenset({EventType.HTTP_SERVICE}),
                worker=WORKER_NAME,
                action=ACTION_INSPECT,
                reason="inspect TLS metadata on confirmed HTTPS service",
                base_priority=base_priority - 0.25,
                required_tags=frozenset({"confirmed"}),
            )
        )

    return tuple(rules)


def target_from_event(event: Event, *, default_port: int = 443) -> TLSTarget:
    if event.type is EventType.DNS_NAME:
        if "confirmed" not in event.tags or "hypothesis" in event.tags:
            raise ValueError(
                "tls.inspect requires a confirmed non-hypothesis DNS_NAME"
            )
        return TLSTarget(hostname=event.value, port=default_port)

    if event.type is EventType.HTTP_SERVICE:
        if "confirmed" not in event.tags:
            raise ValueError("tls.inspect requires confirmed HTTP_SERVICE")

        parts = urlsplit(event.value)
        if parts.scheme.lower() != "https" or parts.hostname is None:
            raise ValueError(
                "TLS inspection from HTTP_SERVICE requires https://host:port"
            )

        try:
            port = parts.port or 443
        except ValueError as exc:
            raise ValueError("HTTP_SERVICE contains invalid port") from exc

        return TLSTarget(hostname=parts.hostname, port=port)

    raise ValueError(
        "tls.inspect requires DNS_NAME or HTTPS HTTP_SERVICE input"
    )


def parse_tlsx_line(line: str) -> TLSProbeResult | None:
    line = line.strip()
    if not line:
        return None

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict) or not isinstance(payload.get("host"), str):
        return None

    try:
        hostname = normalize_dns_name(payload["host"])
    except ValueError:
        return None

    known = {
        "timestamp", "host", "ip", "port", "probe_status",
        "tls_version", "cipher", "not_before", "not_after",
        "subject_dn", "subject_cn", "subject_org", "subject_an",
        "issuer_dn", "issuer_cn", "issuer_org", "fingerprint_hash",
        "tls_connection", "sni", "serial",
    }

    return TLSProbeResult(
        hostname=hostname,
        port=_parse_port(payload.get("port")) or 443,
        probe_status=_parse_bool(payload.get("probe_status")),
        ip=_optional_text(payload.get("ip")),
        sni=_optional_text(payload.get("sni")),
        tls_version=_optional_text(payload.get("tls_version")),
        cipher=_optional_text(payload.get("cipher")),
        tls_connection=_optional_text(payload.get("tls_connection")),
        subject_dn=_optional_text(payload.get("subject_dn")),
        subject_cn=_optional_text(payload.get("subject_cn")),
        subject_org=_string_values(payload.get("subject_org")),
        subject_alt_names=_string_values(payload.get("subject_an")),
        issuer_dn=_optional_text(payload.get("issuer_dn")),
        issuer_cn=_optional_text(payload.get("issuer_cn")),
        issuer_org=_string_values(payload.get("issuer_org")),
        serial=_optional_text(payload.get("serial")),
        not_before=_optional_text(payload.get("not_before")),
        not_after=_optional_text(payload.get("not_after")),
        fingerprint_sha256=_extract_sha256(payload.get("fingerprint_hash")),
        metadata={k: v for k, v in payload.items() if k not in known},
    )


def certificate_identity(result: TLSProbeResult) -> str:
    if result.fingerprint_sha256:
        return f"sha256:{result.fingerprint_sha256}"

    return (
        f"{result.hostname}:{result.port} "
        f"serial={result.serial or 'unknown-serial'} "
        f"subject={result.subject_cn or result.subject_dn or 'unknown-subject'}"
    )


def normalize_certificate_name(value: str) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw:
        return None

    try:
        return ("IP", str(ipaddress.ip_address(raw)))
    except ValueError:
        pass

    wildcard = raw.startswith("*.")
    candidate = raw[2:] if wildcard else raw

    try:
        normalized = normalize_dns_name(candidate)
    except ValueError:
        return None

    return ("DNS", f"*.{normalized}" if wildcard else normalized)


def _extract_sha256(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("sha256")

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower().replace(":", "")
    if len(normalized) == 64 and _HEX_RE.fullmatch(normalized):
        return normalized
    return None


def _parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {
            "1", "true", "yes", "ok", "success"
        }
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _string_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, (list, tuple, set)):
        return tuple(
            sorted({str(v).strip() for v in value if str(v).strip()})
        )
    return ()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _source_component(value: str) -> str:
    value = _SOURCE_COMPONENT_RE.sub(
        "-", value.strip().lower()
    ).strip("-")
    return value or "unknown"


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
        line = raw.decode("utf-8", errors="replace").strip()
        if line:
            tail.append(line)


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return

    process.terminate()

    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except TimeoutError:
        process.kill()
        await process.wait()
