"""Validated program identification attached to target-facing HTTP requests.

Bug-bounty programs commonly require a stable, non-secret identification
header on every request sent to their assets.  This module owns that policy so
worker adapters cannot each invent their own parsing or safety rules.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Identification headers are deliberately not an authentication/session or
# HTTP framing escape hatch.  Those concerns need separate, stricter designs.
_RESERVED_HEADER_NAMES = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
    }
)

TARGET_HTTP_IDENTITY_WORKERS = frozenset(
    {"http", "content", "crawler", "parameters", "vhost", "nuclei"}
)


class RequestIdentityPolicy(BaseModel):
    """Program-wide, non-secret headers required on target HTTP traffic."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    http_headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("http_headers")
    @classmethod
    def validate_http_headers(cls, values: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        seen_names: set[str] = set()

        for raw_name, raw_value in values.items():
            name = raw_name.strip()
            if not name or not _HEADER_NAME.fullmatch(name):
                raise ValueError(f"invalid HTTP identification header name: {raw_name!r}")

            canonical_name = name.casefold()
            if canonical_name in seen_names:
                raise ValueError(f"duplicate HTTP identification header name: {name!r}")
            if canonical_name in _RESERVED_HEADER_NAMES:
                raise ValueError(
                    f"HTTP identification header {name!r} is reserved; "
                    "authentication, session, framing, routing, and User-Agent "
                    "headers cannot be configured here"
                )

            value = raw_value.strip()
            if not value:
                raise ValueError(f"HTTP identification header {name!r} must not be blank")
            if len(value) > 1024:
                raise ValueError(
                    f"HTTP identification header {name!r} exceeds 1024 characters"
                )
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
                raise ValueError(
                    f"HTTP identification header {name!r} contains control characters"
                )

            seen_names.add(canonical_name)
            normalized[name] = value

        return normalized

    @property
    def configured(self) -> bool:
        return bool(self.http_headers)

    @property
    def header_names(self) -> tuple[str, ...]:
        return tuple(self.http_headers)

    @property
    def canonical_header_names(self) -> frozenset[str]:
        return frozenset(name.casefold() for name in self.http_headers)

    @property
    def fingerprint(self) -> str | None:
        """Return a value-sensitive digest without exposing header contents."""

        if not self.configured:
            return None
        material = "\n".join(
            f"{name.casefold()}:{value}"
            for name, value in sorted(
                self.http_headers.items(),
                key=lambda item: item[0].casefold(),
            )
        )
        return sha256(material.encode("utf-8")).hexdigest()

    @property
    def header_lines(self) -> tuple[str, ...]:
        return tuple(f"{name}: {value}" for name, value in self.http_headers.items())

    def repeated_cli_args(self, flag: str) -> tuple[str, ...]:
        """Return one validated ``flag, header`` pair per configured header."""

        return tuple(part for line in self.header_lines for part in (flag, line))

    def newline_cli_value(self) -> str:
        """Return the validated format expected by Arjun's --headers flag."""

        return "\n".join(self.header_lines)

    @classmethod
    def from_cli_header_lines(cls, values: Sequence[str]) -> "RequestIdentityPolicy":
        """Parse repeatable ``Name: value`` CLI options through normal validation."""

        headers: dict[str, str] = {}
        for raw_line in values:
            if ":" not in raw_line:
                raise ValueError("identity header must use the format 'Name: value'")
            name, value = raw_line.split(":", 1)
            normalized_name = name.strip()
            if not normalized_name:
                raise ValueError("identity header name must not be blank")
            if normalized_name in headers:
                raise ValueError(f"duplicate identity header name: {normalized_name!r}")
            headers[normalized_name] = value
        return cls(http_headers=headers)
