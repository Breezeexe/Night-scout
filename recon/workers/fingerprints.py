"""Passive fingerprint normalization for Night Scout.

This worker performs NO network I/O. It converts metadata already collected by
`http.py`, `tls.py`, or a future favicon collector into stable FINGERPRINT
Events that can be used to correlate similar services/assets.

Examples:
- identical HTTP body SHA-256 on different hostnames;
- similar HTTP structure/technology stack;
- identical TLS certificate SHA-256;
- similar TLS certificate identity after reissue;
- identical favicon SHA-256/MMH3.

Fingerprint equality is correlation evidence only. It never implies ownership,
authorization, or scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext

WORKER_NAME = "fingerprints"
ACTION_ANALYZE = "analyze"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FingerprintKind(StrEnum):
    HTTP_CONTENT = "http-content"
    HTTP_STRUCTURE = "http-structure"
    HTTP_STACK = "http-stack"

    TLS_CERTIFICATE = "tls-certificate"
    TLS_IDENTITY = "tls-identity"

    FAVICON_SHA256 = "favicon-sha256"
    FAVICON_MMH3 = "favicon-mmh3"


class FingerprintRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: FingerprintKind
    algorithm: str
    digest: str
    subject: str

    components: dict[str, Any] = Field(default_factory=dict)

    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    novelty: float = Field(default=0.5, ge=0.0, le=1.0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("algorithm", "digest", "subject")
    @classmethod
    def required_text(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("must not be blank")

        return value

    @property
    def value(self) -> str:
        return (
            f"fp:{self.kind.value}:"
            f"{self.algorithm}:{self.digest}"
        )


class FingerprintWorkerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    emit_http_content: bool = True
    emit_http_structure: bool = True
    emit_http_stack: bool = True

    emit_tls_certificate: bool = True
    emit_tls_identity: bool = True

    emit_favicon_sha256: bool = True
    emit_favicon_mmh3: bool = True

    normalize_title_max_chars: int = Field(
        default=256,
        ge=16,
        le=4096,
    )

    max_technologies: int = Field(
        default=64,
        ge=1,
        le=1024,
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


class FingerprintWorker:
    """Pure local fingerprint worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        config: FingerprintWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._config = (
            config
            or FingerprintWorkerConfig()
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
                    "fingerprints worker requires a RUNNING task; "
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

        if task.action != ACTION_ANALYZE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "unsupported fingerprints action: "
                    f"{task.action}"
                ),
            )

        event = await self._events.get_event(
            task.input_event_id
        )

        if event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "input event not found: "
                    f"{task.input_event_id}"
                ),
            )

        for record in fingerprint_event(
            event,
            config=self._config,
        ):
            await self._publisher.publish(
                fingerprint_record_event(
                    record,
                    input_event=event,
                )
            )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )


def fingerprint_route_rules(
    *,
    base_priority: float = 4.75,
) -> tuple[RouteRule, ...]:
    return (
        RouteRule(
            rule_id="fingerprints.http-response",
            accepts=frozenset(
                {
                    EventType.HTTP_RESPONSE,
                }
            ),
            worker=WORKER_NAME,
            action=ACTION_ANALYZE,
            reason=(
                "normalize collected HTTP response metadata into "
                "correlation fingerprints"
            ),
            base_priority=base_priority,
            required_tags=frozenset(
                {
                    "confirmed",
                }
            ),
            predicate=(
                _http_response_has_material
            ),
        ),
        RouteRule(
            rule_id="fingerprints.certificate",
            accepts=frozenset(
                {
                    EventType.CERTIFICATE,
                }
            ),
            worker=WORKER_NAME,
            action=ACTION_ANALYZE,
            reason=(
                "normalize collected TLS certificate metadata into "
                "correlation fingerprints"
            ),
            base_priority=(
                base_priority
                - 0.10
            ),
            required_tags=frozenset(
                {
                    "confirmed",
                }
            ),
            predicate=(
                _certificate_has_material
            ),
        ),
        RouteRule(
            rule_id="fingerprints.favicon",
            accepts=frozenset(
                {
                    EventType.FAVICON,
                }
            ),
            worker=WORKER_NAME,
            action=ACTION_ANALYZE,
            reason=(
                "normalize already collected favicon hashes into "
                "correlation fingerprints"
            ),
            base_priority=(
                base_priority
                - 0.20
            ),
            predicate=(
                _favicon_has_material
            ),
        ),
    )


def fingerprint_event(
    event: Event,
    *,
    config: FingerprintWorkerConfig | None = None,
) -> tuple[FingerprintRecord, ...]:
    cfg = (
        config
        or FingerprintWorkerConfig()
    )

    if (
        event.type
        is EventType.HTTP_RESPONSE
    ):
        return fingerprint_http_response(
            event,
            config=cfg,
        )

    if (
        event.type
        is EventType.CERTIFICATE
    ):
        return fingerprint_certificate(
            event,
            config=cfg,
        )

    if (
        event.type
        is EventType.FAVICON
    ):
        return fingerprint_favicon(
            event,
            config=cfg,
        )

    return ()


def fingerprint_http_response(
    event: Event,
    *,
    config: FingerprintWorkerConfig,
) -> tuple[FingerprintRecord, ...]:
    metadata = event.metadata

    subject = (
        first_text(
            metadata,
            "url",
            "observed_on",
        )
        or event.value
    )

    records: list[
        FingerprintRecord
    ] = []

    body_sha256 = normalize_sha256(
        metadata.get(
            "body_sha256"
        )
        or metadata.get(
            "body_hash"
        )
    )

    if (
        config.emit_http_content
        and body_sha256 is not None
    ):
        records.append(
            FingerprintRecord(
                kind=(
                    FingerprintKind.HTTP_CONTENT
                ),
                algorithm="sha256",
                digest=body_sha256,
                subject=subject,
                components={
                    "body_sha256": (
                        body_sha256
                    ),
                },
                confidence=0.99,
                novelty=0.60,
                metadata={
                    "exact_content_match": True,
                    "body_bytes_stored": False,
                },
            )
        )

    title = normalize_title(
        metadata.get(
            "title"
        ),
        max_chars=(
            config.normalize_title_max_chars
        ),
    )

    content_type = (
        normalize_media_type(
            metadata.get(
                "content_type"
            )
        )
    )

    webserver = normalize_text(
        metadata.get(
            "webserver"
        )
    )

    technologies = (
        normalize_text_list(
            metadata.get(
                "technologies"
            ),
            limit=(
                config.max_technologies
            ),
        )
    )

    status_code = safe_status_code(
        metadata.get(
            "status_code"
        )
    )

    size_bucket = bucket_content_length(
        metadata.get(
            "content_length"
        )
    )

    if config.emit_http_structure:
        structure = {
            "status_code": status_code,
            "title": title,
            "content_type": (
                content_type
            ),
            "webserver": (
                webserver
            ),
            "content_length_bucket": (
                size_bucket
            ),
        }

        if any(
            value is not None
            for value
            in structure.values()
        ):
            records.append(
                FingerprintRecord(
                    kind=(
                        FingerprintKind.HTTP_STRUCTURE
                    ),
                    algorithm="sha256",
                    digest=canonical_sha256(
                        {
                            "version": 1,
                            "kind": (
                                FingerprintKind.HTTP_STRUCTURE.value
                            ),
                            **structure,
                        }
                    ),
                    subject=subject,
                    components=structure,
                    confidence=0.90,
                    novelty=0.48,
                    metadata={
                        "fingerprint_version": 1,
                        "coarse_content_length": True,
                    },
                )
            )

    if (
        config.emit_http_stack
        and (
            webserver is not None
            or technologies
        )
    ):
        stack = {
            "content_type": (
                content_type
            ),
            "webserver": (
                webserver
            ),
            "technologies": list(
                technologies
            ),
        }

        records.append(
            FingerprintRecord(
                kind=(
                    FingerprintKind.HTTP_STACK
                ),
                algorithm="sha256",
                digest=canonical_sha256(
                    {
                        "version": 1,
                        "kind": (
                            FingerprintKind.HTTP_STACK.value
                        ),
                        **stack,
                    }
                ),
                subject=subject,
                components=stack,
                confidence=0.88,
                novelty=0.52,
                metadata={
                    "fingerprint_version": 1,
                },
            )
        )

    return dedupe_records(
        records
    )


def fingerprint_certificate(
    event: Event,
    *,
    config: FingerprintWorkerConfig,
) -> tuple[FingerprintRecord, ...]:
    metadata = event.metadata

    subject = (
        first_text(
            metadata,
            "observed_on",
            "hostname",
        )
        or event.value
    )

    records: list[
        FingerprintRecord
    ] = []

    exact_sha256 = normalize_sha256(
        metadata.get(
            "fingerprint_sha256"
        )
        or nested(
            metadata,
            "surface_state",
            "certificate_fingerprints",
        )
    )

    if (
        config.emit_tls_certificate
        and exact_sha256
        is not None
    ):
        records.append(
            FingerprintRecord(
                kind=(
                    FingerprintKind.TLS_CERTIFICATE
                ),
                algorithm="sha256",
                digest=exact_sha256,
                subject=subject,
                components={
                    "certificate_sha256": (
                        exact_sha256
                    ),
                },
                confidence=1.0,
                novelty=0.62,
                metadata={
                    "exact_certificate_match": True,
                },
            )
        )

    if config.emit_tls_identity:
        identity = {
            "subject_cn": normalize_text(
                metadata.get(
                    "subject_cn"
                )
            ),
            "subject_org": list(
                normalize_text_list(
                    metadata.get(
                        "subject_org"
                    ),
                    limit=32,
                )
            ),
            "issuer_cn": normalize_text(
                metadata.get(
                    "issuer_cn"
                )
            ),
            "issuer_org": list(
                normalize_text_list(
                    metadata.get(
                        "issuer_org"
                    ),
                    limit=32,
                )
            ),
            "certificate_sans": list(
                normalize_dnsish_list(
                    nested(
                        metadata,
                        "surface_state",
                        "certificate_sans",
                    ),
                    limit=256,
                )
            ),
        }

        if (
            identity[
                "subject_cn"
            ]
            is not None
            or identity[
                "subject_org"
            ]
            or identity[
                "certificate_sans"
            ]
        ):
            records.append(
                FingerprintRecord(
                    kind=(
                        FingerprintKind.TLS_IDENTITY
                    ),
                    algorithm="sha256",
                    digest=canonical_sha256(
                        {
                            "version": 1,
                            "kind": (
                                FingerprintKind.TLS_IDENTITY.value
                            ),
                            **identity,
                        }
                    ),
                    subject=subject,
                    components=identity,
                    confidence=0.89,
                    novelty=0.55,
                    metadata={
                        "fingerprint_version": 1,
                        "serial_included": False,
                        "validity_included": False,
                    },
                )
            )

    return dedupe_records(
        records
    )


def fingerprint_favicon(
    event: Event,
    *,
    config: FingerprintWorkerConfig,
) -> tuple[FingerprintRecord, ...]:
    metadata = event.metadata

    subject = (
        first_text(
            metadata,
            "url",
            "observed_on",
        )
        or event.value
    )

    records: list[
        FingerprintRecord
    ] = []

    sha256_value = normalize_sha256(
        metadata.get(
            "sha256"
        )
        or metadata.get(
            "favicon_sha256"
        )
        or metadata.get(
            "body_sha256"
        )
    )

    if (
        config.emit_favicon_sha256
        and sha256_value
        is not None
    ):
        records.append(
            FingerprintRecord(
                kind=(
                    FingerprintKind.FAVICON_SHA256
                ),
                algorithm="sha256",
                digest=sha256_value,
                subject=subject,
                components={
                    "favicon_sha256": (
                        sha256_value
                    ),
                },
                confidence=0.99,
                novelty=0.72,
                metadata={
                    "exact_favicon_bytes_match": True,
                },
            )
        )

    mmh3_value = normalize_mmh3(
        metadata.get(
            "mmh3"
        )
        or metadata.get(
            "favicon_mmh3"
        )
    )

    if (
        config.emit_favicon_mmh3
        and mmh3_value
        is not None
    ):
        records.append(
            FingerprintRecord(
                kind=(
                    FingerprintKind.FAVICON_MMH3
                ),
                algorithm="mmh3",
                digest=mmh3_value,
                subject=subject,
                components={
                    "favicon_mmh3": (
                        mmh3_value
                    ),
                },
                confidence=0.92,
                novelty=0.68,
                metadata={
                    "hash_collision_possible": True,
                },
            )
        )

    return dedupe_records(
        records
    )


def fingerprint_record_event(
    record: FingerprintRecord,
    *,
    input_event: Event,
) -> Event:
    return Event(
        type=EventType.FINGERPRINT,
        value=record.value,
        source=(
            f"fingerprints:"
            f"{record.kind.value}"
        ),
        parent_event_id=(
            input_event.event_id
        ),
        scope_state=(
            input_event.scope_state
        ),
        confidence=(
            record.confidence
        ),
        novelty=(
            record.novelty
        ),
        depth=(
            input_event.depth
            + 1
        ),
        tags={
            "fingerprint",
            "correlation",
            "local-static-analysis",
            f"kind:{record.kind.value}",
        },
        metadata={
            "fingerprint_kind": (
                record.kind.value
            ),
            "fingerprint_algorithm": (
                record.algorithm
            ),
            "fingerprint_digest": (
                record.digest
            ),
            "subject": (
                record.subject
            ),
            "components": (
                record.components
            ),
            "derived_from_event_type": (
                input_event.type.value
            ),
            "derived_from_event_id": (
                input_event.event_id
            ),
            "network_access": False,
            "scope_inference": False,
            "ownership_inference": False,
            "raw_body_stored": False,
            **record.metadata,
        },
    )


def canonical_sha256(
    value: dict[str, Any],
) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


def normalize_sha256(
    value: Any,
) -> str | None:
    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        for item in value:
            normalized = normalize_sha256(
                item
            )

            if normalized is not None:
                return normalized

        return None

    if value is None:
        return None

    normalized = (
        str(
            value
        )
        .strip()
        .lower()
    )

    if normalized.startswith(
        "sha256:"
    ):
        normalized = normalized[7:]

    normalized = normalized.replace(
        ":",
        "",
    )

    if (
        _SHA256_RE.fullmatch(
            normalized
        )
        is None
    ):
        return None

    return normalized


def normalize_mmh3(
    value: Any,
) -> str | None:
    if value is None:
        return None

    try:
        number = int(
            str(
                value
            ).strip(),
            10,
        )
    except ValueError:
        return None

    if not (
        -(2**31)
        <= number
        <= 2**31 - 1
    ):
        return None

    return str(
        number
    )


def normalize_text(
    value: Any,
) -> str | None:
    if (
        value is None
        or isinstance(
            value,
            (
                list,
                tuple,
                set,
                dict,
            ),
        )
    ):
        return None

    normalized = " ".join(
        str(
            value
        )
        .strip()
        .split()
    )

    return (
        normalized.lower()
        if normalized
        else None
    )


def normalize_title(
    value: Any,
    *,
    max_chars: int,
) -> str | None:
    normalized = normalize_text(
        value
    )

    if normalized is None:
        return None

    return normalized[
        :max_chars
    ]


def normalize_media_type(
    value: Any,
) -> str | None:
    normalized = normalize_text(
        value
    )

    if normalized is None:
        return None

    return (
        normalized.split(
            ";",
            1,
        )[0]
        .strip()
        or None
    )


def normalize_text_list(
    value: Any,
    *,
    limit: int,
) -> tuple[str, ...]:
    values: tuple[Any, ...]
    if isinstance(
        value,
        str,
    ):
        values = (
            value,
        )
    elif isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        values = tuple(
            value
        )
    else:
        values = ()

    result: list[str] = []

    for item in values:
        normalized = normalize_text(
            item
        )

        if (
            normalized is None
            or normalized
            in result
        ):
            continue

        result.append(
            normalized
        )

        if (
            len(result)
            >= limit
        ):
            break

    return tuple(
        sorted(
            result
        )
    )


def normalize_dnsish_list(
    value: Any,
    *,
    limit: int,
) -> tuple[str, ...]:
    values: tuple[Any, ...]
    if isinstance(
        value,
        str,
    ):
        values = (
            value,
        )
    elif isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        values = tuple(
            value
        )
    else:
        values = ()

    result: list[str] = []

    for item in values:
        normalized = (
            str(
                item
            )
            .strip()
            .lower()
        )

        if (
            not normalized
            or normalized
            in result
        ):
            continue

        result.append(
            normalized
        )

        if (
            len(result)
            >= limit
        ):
            break

    return tuple(
        sorted(
            result
        )
    )


def bucket_content_length(
    value: Any,
) -> str | None:
    try:
        length = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if length < 0:
        return None

    if length == 0:
        return "0"

    lower = (
        1
        << (
            length.bit_length()
            - 1
        )
    )

    return (
        f"{lower}-"
        f"{lower * 2 - 1}"
    )


def safe_status_code(
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

    if 100 <= status <= 599:
        return status

    return None


def first_text(
    metadata: dict[str, Any],
    *keys: str,
) -> str | None:
    for key in keys:
        normalized = normalize_text(
            metadata.get(
                key
            )
        )

        if normalized is not None:
            return normalized

    return None


def nested(
    metadata: dict[str, Any],
    *path: str,
) -> Any:
    current: Any = metadata

    for key in path:
        if not isinstance(
            current,
            dict,
        ):
            return None

        current = current.get(
            key
        )

    return current


def dedupe_records(
    records: list[
        FingerprintRecord
    ],
) -> tuple[
    FingerprintRecord,
    ...
]:
    best: dict[
        str,
        FingerprintRecord
    ] = {}

    for record in records:
        existing = best.get(
            record.value
        )

        if (
            existing is None
            or (
                record.confidence,
                record.novelty,
            )
            > (
                existing.confidence,
                existing.novelty,
            )
        ):
            best[
                record.value
            ] = record

    return tuple(
        sorted(
            best.values(),
            key=lambda record: (
                record.kind.value,
                record.digest,
            ),
        )
    )


def _http_response_has_material(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    metadata = event.metadata

    return bool(
        normalize_sha256(
            metadata.get(
                "body_sha256"
            )
        )
        or metadata.get(
            "status_code"
        )
        is not None
        or normalize_text(
            metadata.get(
                "title"
            )
        )
        or normalize_text(
            metadata.get(
                "webserver"
            )
        )
        or normalize_text_list(
            metadata.get(
                "technologies"
            ),
            limit=64,
        )
    )


def _certificate_has_material(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    metadata = event.metadata

    return bool(
        normalize_sha256(
            metadata.get(
                "fingerprint_sha256"
            )
        )
        or normalize_text(
            metadata.get(
                "subject_cn"
            )
        )
        or normalize_text_list(
            metadata.get(
                "subject_org"
            ),
            limit=32,
        )
        or normalize_dnsish_list(
            nested(
                metadata,
                "surface_state",
                "certificate_sans",
            ),
            limit=256,
        )
    )


def _favicon_has_material(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    metadata = event.metadata

    return bool(
        normalize_sha256(
            metadata.get(
                "sha256"
            )
            or metadata.get(
                "favicon_sha256"
            )
            or metadata.get(
                "body_sha256"
            )
        )
        or normalize_mmh3(
            metadata.get(
                "mmh3"
            )
            or metadata.get(
                "favicon_mmh3"
            )
        )
    )
