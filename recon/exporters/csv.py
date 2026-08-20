"""CSV export for Night Scout with separate safe and sensitive reports."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from recon.core.events import Event
from recon.exporters.jsonl import (
    ExportMode,
    SensitiveEvidenceProvider,
    is_sensitive_event,
    safe_event_record,
    sensitive_evidence_record,
)


class CsvExportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ExportMode = ExportMode.SAFE
    confirm_sensitive_export: bool = False

    include_metadata_json: bool = True
    include_tags: bool = True

    safe_file_permissions: int = Field(default=0o600, ge=0, le=0o777)
    sensitive_file_permissions: int = Field(default=0o600, ge=0, le=0o777)


_SAFE_FIELDS = (
    "event_id",
    "event_type",
    "value",
    "source",
    "parent_event_id",
    "first_seen",
    "last_seen",
    "scope_state",
    "confidence",
    "novelty",
    "depth",
    "tags",
    "metadata_json",
    "sensitive_evidence_available",
)

_SENSITIVE_FIELDS = (
    "event_id",
    "event_type",
    "evidence_fingerprint",
    "secret_type",
    "detector",
    "artifact_ref",
    "artifact_sha256",
    "source_file",
    "line",
    "column",
    "confidence",
    "novelty",
    "verification_attempted",
    "credential_used",
    "raw_secret_json",
)


def safe_csv_rows(
    events: Sequence[Event],
    *,
    options: CsvExportOptions,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []

    for event in events:
        record = safe_event_record(
            event,
            include_metadata=options.include_metadata_json,
            include_tags=options.include_tags,
        )

        row = {
            "event_id": record["event_id"],
            "event_type": record["event_type"],
            "value": record["value"],
            "source": record["source"],
            "parent_event_id": record.get("parent_event_id") or "",
            "first_seen": record["first_seen"],
            "last_seen": record["last_seen"],
            "scope_state": record["scope_state"],
            "confidence": record["confidence"],
            "novelty": record["novelty"],
            "depth": record["depth"],
            "tags": (
                ";".join(record.get("tags", ()))
                if options.include_tags
                else ""
            ),
            "metadata_json": (
                json.dumps(
                    record.get("metadata", {}),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if options.include_metadata_json
                else ""
            ),
            "sensitive_evidence_available": bool(
                record.get("sensitive_evidence_available", False)
            ),
        }
        rows.append(row)

    return tuple(rows)


async def sensitive_csv_rows(
    events: Sequence[Event],
    *,
    provider: SensitiveEvidenceProvider,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    for event in events:
        if not is_sensitive_event(event):
            continue

        record = await sensitive_evidence_record(event, provider=provider)
        if record is None:
            continue

        fingerprint = str(record["evidence_fingerprint"])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        row = {
            field: record.get(field, "")
            for field in _SENSITIVE_FIELDS
            if field != "raw_secret_json"
        }
        # JSON encoding is reversible/exact and prevents spreadsheet formula
        # interpretation when a secret begins with =, +, -, or @.
        row["raw_secret_json"] = json.dumps(
            str(record["raw_secret"]),
            ensure_ascii=False,
        )
        rows.append(row)

    return tuple(rows)


def csv_safe_cell(value: Any) -> Any:
    """Prevent spreadsheet formula execution in ordinary string cells."""

    if not isinstance(value, str):
        return value

    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value

    return value


def _atomic_write_csv(
    path: Path,
    *,
    fields: Sequence[str],
    rows: Sequence[dict[str, Any]],
    permissions: int,
) -> Path:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    tmp = Path(raw_tmp)

    try:
        os.fchmod(fd, permissions)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=list(fields),
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        key: csv_safe_cell(value)
                        for key, value in row.items()
                    }
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, permissions)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp.unlink(missing_ok=True)
        raise

    return path


async def export_csv_bundle(
    events: Sequence[Event],
    output_dir: Path,
    *,
    options: CsvExportOptions | None = None,
    sensitive_provider: SensitiveEvidenceProvider | None = None,
) -> tuple[Path, ...]:
    options = options or CsvExportOptions()

    if options.mode is ExportMode.SENSITIVE_EVIDENCE:
        if not options.confirm_sensitive_export:
            raise ValueError(
                "SENSITIVE_EVIDENCE export requires confirm_sensitive_export=True"
            )
        if sensitive_provider is None:
            raise ValueError(
                "SENSITIVE_EVIDENCE export requires a SensitiveEvidenceProvider"
            )

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    written = [
        _atomic_write_csv(
            output_dir / "events.csv",
            fields=_SAFE_FIELDS,
            rows=safe_csv_rows(events, options=options),
            permissions=options.safe_file_permissions,
        )
    ]

    if options.mode is ExportMode.SENSITIVE_EVIDENCE:
        assert sensitive_provider is not None
        written.append(
            _atomic_write_csv(
                output_dir / "sensitive_evidence.csv",
                fields=_SENSITIVE_FIELDS,
                rows=await sensitive_csv_rows(events, provider=sensitive_provider),
                permissions=options.sensitive_file_permissions,
            )
        )

    return tuple(written)
