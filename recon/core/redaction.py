"""Irreversible sanitization applied at the ordinary event-storage boundary."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from recon.core.events import Event

REDACTED = "[REDACTED]"

_SENSITIVE_QUERY_RE = re.compile(
    r"(?:^|[_-])(?:pass(?:word|wd)?|secret|token|key|auth|session|cookie|code|credential|signature|sig|assertion|jwt|sas)(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(/(?:reset|verify|activate|invite|magic(?:-link)?|password-reset)/)([^/?#]{8,})"
)
_RAW_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passwd|secret|credential|token|access_token|refresh_token|client_secret|api_key|signature|authorization|session|cookie|set_cookie|private_key)(?:$|_)",
    re.IGNORECASE,
)
_SAFE_SECRET_METADATA_KEYS = frozenset(
    {
        "secret_type",
        "credential_used",
        "credential_verification_attempted",
        "verification_attempted",
        "raw_secret_stored",
        "raw_secret_stored_separately",
        "possible_secret_count",
        "masked_preview",
        "evidence_fingerprint",
        "sensitive_evidence_fingerprint",
        "token_count",
        "vocabulary_token_count",
    }
)


def sanitize_url(value: str) -> str:
    """Redact credentials/tokens in absolute and relative web references."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value

    scheme = parts.scheme.lower()
    if scheme not in {"", "http", "https"}:
        return value
    if scheme in {"http", "https"} and not parts.netloc:
        return value

    is_relative_reference = (
        scheme == ""
        and (
            bool(parts.netloc)
            or parts.path.startswith(("/", "./", "../"))
            or bool(parts.query)
            or bool(parts.fragment)
        )
    )
    if scheme == "" and not is_relative_reference:
        return value

    netloc = parts.netloc
    if parts.username is not None or parts.password is not None:
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = f":{parts.port}" if parts.port is not None else ""
        except ValueError:
            port = ""
        netloc = f"{REDACTED}@{host}{port}"

    query = _sanitize_parameter_string(parts.query)
    fragment = _sanitize_parameter_string(parts.fragment)
    path = _SENSITIVE_PATH_RE.sub(lambda match: match.group(1) + REDACTED, parts.path)
    return urlunsplit((parts.scheme, netloc, path, query, fragment))


def sanitize_event_for_storage(event: Event) -> Event:
    """Return an Event safe for SQLite, JSONL, routing and diagnostics."""
    safe_value = sanitize_url(event.value)
    safe_metadata = _sanitize_metadata(event.metadata)
    if safe_value == event.value and safe_metadata == event.metadata:
        return event

    tags = set(event.tags)
    tags.add("sensitive-data-redacted")
    return event.model_copy(
        update={
            "value": safe_value,
            "metadata": safe_metadata,
            "tags": tags,
        },
        deep=True,
    )


def _sanitize_parameter_string(value: str) -> str:
    if not value or "=" not in value:
        return value
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return value
    return urlencode(
        [
            (key, REDACTED if _is_sensitive_query_key(key) else item)
            for key, item in pairs
        ],
        doseq=True,
    )


def _is_sensitive_query_key(key: str) -> bool:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key.strip())
    compact = re.sub(r"[^a-z0-9]", "", snake.lower())
    return bool(
        _SENSITIVE_QUERY_RE.search(snake)
        or compact
        in {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "accesstoken",
            "refreshtoken",
            "idtoken",
            "apikey",
            "authorization",
            "auth",
            "session",
            "sessionid",
            "cookie",
            "code",
            "credential",
            "signature",
            "sig",
            "assertion",
            "jwt",
            "sas",
        }
    )


def _sanitize_metadata(value: Any, *, key: str | None = None) -> Any:
    normalized_key = key.strip().lower().replace("-", "_") if key else None
    if (
        normalized_key
        and normalized_key not in _SAFE_SECRET_METADATA_KEYS
        and _RAW_SECRET_KEY_RE.search(normalized_key)
    ):
        return REDACTED
    if isinstance(value, str):
        return sanitize_url(value)
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_metadata(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_metadata(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_metadata(item) for item in value)
    return value
