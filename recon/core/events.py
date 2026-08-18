"""Core event model for Night Scout.

Every discovery produced by Night Scout is normalized into an Event before it
is stored, scored, routed, or used to schedule additional work.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_event_id() -> str:
    """Create a compact, human-recognizable event identifier."""
    return f"evt_{uuid4().hex}"


class EventType(StrEnum):
    """Normalized event types understood by Night Scout."""

    ROOT_DOMAIN = "ROOT_DOMAIN"

    DNS_NAME = "DNS_NAME"
    DNS_RECORD = "DNS_RECORD"
    IP_ADDRESS = "IP_ADDRESS"
    ASN = "ASN"
    CIDR = "CIDR"

    URL = "URL"
    URL_PATH = "URL_PATH"
    HTTP_SERVICE = "HTTP_SERVICE"
    HTTP_RESPONSE = "HTTP_RESPONSE"

    CERTIFICATE = "CERTIFICATE"
    CERT_SAN = "CERT_SAN"

    FAVICON = "FAVICON"
    TECHNOLOGY = "TECHNOLOGY"
    FINGERPRINT = "FINGERPRINT"

    JAVASCRIPT = "JAVASCRIPT"
    API_ENDPOINT = "API_ENDPOINT"
    PARAMETER_NAME = "PARAMETER_NAME"

    ARTIFACT = "ARTIFACT"
    MOBILE_ARTIFACT = "MOBILE_ARTIFACT"

    PROJECT_NAME = "PROJECT_NAME"
    VOCAB_TOKEN = "VOCAB_TOKEN"
    NAMING_PATTERN = "NAMING_PATTERN"

    RELATIONSHIP = "RELATIONSHIP"

    POLICY_BLOCK = "POLICY_BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class ScopeState(StrEnum):
    """Authorization state assigned by the scope engine."""

    UNKNOWN = "UNKNOWN"
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PASSIVE_ONLY = "PASSIVE_ONLY"
    AMBIGUOUS = "AMBIGUOUS"


class Event(BaseModel):
    """Canonical Night Scout event.

    Workers may collect data in any tool-specific format, but before that data
    enters the Night Scout core it must be normalized into this model.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
    )

    event_id: str = Field(default_factory=new_event_id)
    type: EventType
    value: str

    source: str
    parent_event_id: str | None = None

    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)

    scope_state: ScopeState = ScopeState.UNKNOWN

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty: float = Field(default=0.0, ge=0.0, le=1.0)

    depth: int = Field(default=0, ge=0)

    tags: set[str] = Field(default_factory=set)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value", "source")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        """Reject blank event values and blank source names."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("last_seen")
    @classmethod
    def last_seen_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Require timezone-aware timestamps."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("last_seen must be timezone-aware")
        return value

    @field_validator("first_seen")
    @classmethod
    def first_seen_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Require timezone-aware timestamps."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("first_seen must be timezone-aware")
        return value

    @property
    def identity_key(self) -> str:
        """Return the basic stable identity used by deduplication layers.

        More advanced normalization can later be applied before an Event is
        created, e.g. canonical URL formatting or normalized DNS names.
        """
        return f"{self.type.value}:{self.value}"

    def touch(self, *, seen_at: datetime | None = None) -> None:
        """Update last_seen when the same logical event is observed again."""
        self.last_seen = seen_at or utc_now()

    def add_tag(self, tag: str) -> None:
        """Attach a normalized tag to the event."""
        normalized = tag.strip().lower()
        if normalized:
            self.tags.add(normalized)
