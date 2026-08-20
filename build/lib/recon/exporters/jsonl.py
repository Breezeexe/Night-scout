"""JSONL export for Night Scout with safe and sensitive-evidence modes.

SAFE is the default and never emits raw credential values. SENSITIVE_EVIDENCE
is an explicit opt-in mode for preparing authorized bug-bounty evidence. Raw
values are loaded from a separate protected evidence store, never from the
normal Event graph.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from recon.core.events import Event, EventType


class ExportMode(StrEnum):
    SAFE = "SAFE"
    SENSITIVE_EVIDENCE = "SENSITIVE_EVIDENCE"


class SensitiveEvidence(BaseModel):
    """Raw evidence loaded from the protected store only."""

    model_config = ConfigDict(extra="allow", frozen=True)

    evidence_fingerprint: str
    raw_secret: str
    secret_type: str | None = None
    detector: str | None = None
    source_file: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    artifact_ref: str | None = None
    artifact_sha256: str | None = None

    @field_validator("evidence_fingerprint", "raw_secret")
    @classmethod
    def required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class SensitiveEvidenceProvider(Protocol):
    async def evidence_for(
        self,
        evidence_fingerprint: str,
    ) -> SensitiveEvidence | None:
        ...


class WorkspaceSensitiveEvidenceProvider:
    """Read per-fingerprint JSON records written by mobile.py.

    The root is resolved once and each file must remain directly beneath it.
    Files with group/other permission bits are rejected by default.
    """

    def __init__(
        self,
        root: Path,
        *,
        require_private_permissions: bool = True,
    ) -> None:
        self._root = root.expanduser().resolve()
        self._require_private_permissions = require_private_permissions

    async def evidence_for(
        self,
        evidence_fingerprint: str,
    ) -> SensitiveEvidence | None:
        fingerprint = normalize_fingerprint(evidence_fingerprint)
        if fingerprint is None:
            return None

        path = (self._root / f"{fingerprint}.json").resolve()
        try:
            path.relative_to(self._root)
        except ValueError:
            return None

        if not path.is_file() or path.is_symlink():
            return None

        if self._require_private_permissions:
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                raise PermissionError(
                    f"sensitive evidence file is not private: {path} mode={oct(mode)}"
                )

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None

        try:
            return SensitiveEvidence.model_validate(payload)
        except ValueError:
            return None


class JsonlExportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ExportMode = ExportMode.SAFE
    include_metadata: bool = True
    include_tags: bool = True
    include_sensitive_records: bool = True

    # Required in addition to mode=SENSITIVE_EVIDENCE. This protects callers
    # from accidentally switching modes through a config merge.
    confirm_sensitive_export: bool = False

    file_permissions: int = Field(default=0o600, ge=0, le=0o777)


_RAW_SECRET_KEYS = frozenset(
    {
        "raw_secret",
        "secret",
        "secret_value",
        "credential",
        "credential_value",
        "password",
        "passwd",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "client_secret",
        "api_key_value",
        "authorization",
        "cookie",
        "set_cookie",
    }
)


_SAFE_SENSITIVE_METADATA_KEYS = frozenset(
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


def _metadata_key_is_sensitive(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SAFE_SENSITIVE_METADATA_KEYS:
        return False
    if normalized in _RAW_SECRET_KEYS:
        return True
    return bool(
        re.search(
            r"(?:^|_)(?:password|passwd|secret|credential|access_token|refresh_token|client_secret|authorization|cookie|private_key)(?:$|_)",
            normalized,
        )
    )

_SENSITIVE_QUERY_RE = re.compile(
    r"(?:^|[_-])(?:pass(?:word|wd)?|secret|token|key|auth|session|cookie|code|credential)(?:$|[_-])",
    re.IGNORECASE,
)


def normalize_fingerprint(value: str) -> str | None:
    normalized = value.strip().lower().replace(":", "")
    if not normalized or not re.fullmatch(r"[0-9a-f]{16,128}", normalized):
        return None
    return normalized


def is_sensitive_event(event: Event) -> bool:
    tags = {tag.strip().lower() for tag in event.tags}
    if any(
        marker in tag
        for tag in tags
        for marker in ("secret", "credential", "private-key", "access-token")
    ):
        return True

    artifact_kind = str(event.metadata.get("artifact_kind", "")).lower()
    review_category = str(event.metadata.get("review_category", "")).lower()
    return "secret" in artifact_kind or "secret" in review_category


def sensitive_fingerprint_for_event(event: Event) -> str | None:
    raw = event.metadata.get("evidence_fingerprint")
    if not isinstance(raw, str):
        return None
    return normalize_fingerprint(raw)


def sanitize_url_for_safe_export(value: str) -> str:
    """Keep useful query data while redacting likely credential parameters."""

    try:
        parts = urlsplit(value)
    except ValueError:
        return value

    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return value

    if not parts.query:
        return value

    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return value

    safe_pairs: list[tuple[str, str]] = []
    for key, val in pairs:
        if _SENSITIVE_QUERY_RE.search(key):
            safe_pairs.append((key, "[REDACTED]"))
        else:
            safe_pairs.append((key, val))

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(safe_pairs, doseq=True),
            parts.fragment,
        )
    )


def sanitize_export_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively remove known raw-secret fields from ordinary exports."""

    if key is not None and _metadata_key_is_sensitive(key):
        return "[REDACTED]"

    if isinstance(value, dict):
        return {
            str(child_key): sanitize_export_value(child_value, key=str(child_key))
            for child_key, child_value in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [sanitize_export_value(item) for item in value]

    if isinstance(value, str):
        return sanitize_url_for_safe_export(value)

    return value


def safe_event_record(
    event: Event,
    *,
    include_metadata: bool = True,
    include_tags: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "event",
        "event_id": event.event_id,
        "event_type": event.type.value,
        "value": sanitize_url_for_safe_export(event.value),
        "source": event.source,
        "parent_event_id": event.parent_event_id,
        "first_seen": event.first_seen.isoformat(),
        "last_seen": event.last_seen.isoformat(),
        "scope_state": event.scope_state.value,
        "confidence": event.confidence,
        "novelty": event.novelty,
        "depth": event.depth,
    }

    if include_tags:
        record["tags"] = sorted(event.tags)

    if include_metadata:
        record["metadata"] = sanitize_export_value(dict(event.metadata))

    if is_sensitive_event(event):
        record["sensitive_evidence_available"] = bool(
            sensitive_fingerprint_for_event(event)
        )
        record["raw_secret_in_event_export"] = False

    return record


async def sensitive_evidence_record(
    event: Event,
    *,
    provider: SensitiveEvidenceProvider,
) -> dict[str, Any] | None:
    fingerprint = sensitive_fingerprint_for_event(event)
    if fingerprint is None:
        return None

    evidence = await provider.evidence_for(fingerprint)
    if evidence is None:
        return None

    return {
        "record_type": "sensitive_evidence",
        "event_id": event.event_id,
        "event_type": event.type.value,
        "evidence_fingerprint": evidence.evidence_fingerprint,
        "secret_type": evidence.secret_type or event.metadata.get("secret_type"),
        "detector": evidence.detector or event.metadata.get("detector"),
        "source_file": evidence.source_file or event.metadata.get("source_file"),
        "line": evidence.line or event.metadata.get("line"),
        "column": evidence.column or event.metadata.get("column"),
        "artifact_ref": evidence.artifact_ref or event.metadata.get("artifact_ref"),
        "artifact_sha256": evidence.artifact_sha256 or event.metadata.get("artifact_sha256"),
        "confidence": event.confidence,
        "novelty": event.novelty,
        "review_category": event.metadata.get("review_category", "POSSIBLE_SECRET"),
        "verification_attempted": False,
        "credential_used": False,
        # Intentionally present only in explicit SENSITIVE_EVIDENCE mode.
        "raw_secret": evidence.raw_secret,
    }


async def build_jsonl_records(
    events: Sequence[Event],
    *,
    options: JsonlExportOptions | None = None,
    sensitive_provider: SensitiveEvidenceProvider | None = None,
) -> tuple[dict[str, Any], ...]:
    options = options or JsonlExportOptions()

    if options.mode is ExportMode.SENSITIVE_EVIDENCE:
        if not options.confirm_sensitive_export:
            raise ValueError(
                "SENSITIVE_EVIDENCE export requires confirm_sensitive_export=True"
            )
        if sensitive_provider is None:
            raise ValueError(
                "SENSITIVE_EVIDENCE export requires a SensitiveEvidenceProvider"
            )

    records: list[dict[str, Any]] = []

    for event in events:
        records.append(
            safe_event_record(
                event,
                include_metadata=options.include_metadata,
                include_tags=options.include_tags,
            )
        )

        if (
            options.mode is ExportMode.SENSITIVE_EVIDENCE
            and options.include_sensitive_records
            and is_sensitive_event(event)
        ):
            assert sensitive_provider is not None
            sensitive = await sensitive_evidence_record(
                event,
                provider=sensitive_provider,
            )
            if sensitive is not None:
                records.append(sensitive)

    return tuple(records)


async def export_jsonl(
    events: Sequence[Event],
    output_path: Path,
    *,
    options: JsonlExportOptions | None = None,
    sensitive_provider: SensitiveEvidenceProvider | None = None,
) -> Path:
    """Atomically write Night Scout JSONL records."""

    options = options or JsonlExportOptions()
    records = await build_jsonl_records(
        events,
        options=options,
        sensitive_provider=sensitive_provider,
    )

    output_path = output_path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        text=True,
    )
    tmp_path = Path(raw_tmp)

    try:
        os.fchmod(fd, options.file_permissions)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, output_path)
        os.chmod(output_path, options.file_permissions)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return output_path


def jsonl_bytes(records: Iterable[dict[str, Any]]) -> bytes:
    """Deterministic helper useful for tests/report attachment generation."""

    return (
        "".join(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        )
    ).encode("utf-8")
