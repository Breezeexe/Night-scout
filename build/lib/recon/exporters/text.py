"""Plain-text bundle export for Night Scout.

SAFE mode emits operational lists without raw credentials. SENSITIVE_EVIDENCE
adds a separate private `sensitive_evidence.txt` file; raw values never appear
inside the ordinary domain/url/api/parameter lists.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from recon.core.events import Event, EventType
from recon.exporters.jsonl import (
    ExportMode,
    SensitiveEvidenceProvider,
    is_sensitive_event,
    sanitize_url_for_safe_export,
    sensitive_evidence_record,
)


class TextExportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ExportMode = ExportMode.SAFE
    confirm_sensitive_export: bool = False

    include_headers: bool = True
    include_empty_files: bool = False
    safe_file_permissions: int = Field(default=0o600, ge=0, le=0o777)
    sensitive_file_permissions: int = Field(default=0o600, ge=0, le=0o777)


_EVENT_FILES: dict[EventType, str] = {
    EventType.ROOT_DOMAIN: "root_domains.txt",
    EventType.DNS_NAME: "domains.txt",
    EventType.IP_ADDRESS: "ips.txt",
    EventType.ASN: "asns.txt",
    EventType.CIDR: "cidrs.txt",
    EventType.URL: "urls.txt",
    EventType.URL_PATH: "url_paths.txt",
    EventType.HTTP_SERVICE: "http_services.txt",
    EventType.API_ENDPOINT: "api_endpoints.txt",
    EventType.PARAMETER_NAME: "parameters.txt",
    EventType.CERT_SAN: "certificate_sans.txt",
    EventType.TECHNOLOGY: "technologies.txt",
    EventType.FINGERPRINT: "fingerprints.txt",
    EventType.PROJECT_NAME: "project_names.txt",
    EventType.VOCAB_TOKEN: "vocabulary.txt",
    EventType.NAMING_PATTERN: "naming_patterns.txt",
    EventType.VULNERABILITY_CANDIDATE: "vulnerability_candidates.txt",
    EventType.VULNERABILITY_FINDING: "vulnerability_findings.txt",
    EventType.JAVASCRIPT: "javascript.txt",
    EventType.ARTIFACT: "artifacts.txt",
    EventType.MOBILE_ARTIFACT: "mobile_artifacts.txt",
    EventType.HUMAN_REVIEW: "human_review.txt",
    EventType.POLICY_BLOCK: "policy_blocks.txt",
}


def _safe_text_value(event: Event) -> str:
    value = sanitize_url_for_safe_export(event.value)
    return value.replace("\r", " ").replace("\n", " ").strip()


def _event_line(event: Event) -> str:
    value = _safe_text_value(event)

    if event.type in {EventType.HUMAN_REVIEW, EventType.POLICY_BLOCK}:
        return "\t".join(
            (
                value,
                event.scope_state.value,
                f"confidence={event.confidence:.3f}",
                f"novelty={event.novelty:.3f}",
                f"source={event.source}",
            )
        )

    return value


def build_safe_text_lists(
    events: Sequence[Event],
) -> dict[str, tuple[str, ...]]:
    """Build deterministic de-duplicated text lists."""

    lists: dict[str, set[str]] = defaultdict(set)

    for event in events:
        filename = _EVENT_FILES.get(event.type)
        if filename is None:
            continue

        line = _event_line(event)
        if line:
            lists[filename].add(line)

    return {
        filename: tuple(sorted(lines))
        for filename, lines in sorted(lists.items())
    }


async def build_sensitive_text_lines(
    events: Sequence[Event],
    *,
    provider: SensitiveEvidenceProvider,
) -> tuple[str, ...]:
    lines: list[str] = []
    seen: set[str] = set()

    for event in events:
        if not is_sensitive_event(event):
            continue

        record = await sensitive_evidence_record(
            event,
            provider=provider,
        )
        if record is None:
            continue

        fingerprint = str(record["evidence_fingerprint"])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        location = str(record.get("source_file") or "unknown")
        if record.get("line"):
            location += f":{record['line']}"
        if record.get("column"):
            location += f":{record['column']}"

        # Deliberately simple block format: suitable for a private report
        # attachment while preserving the exact raw credential.
        lines.extend(
            (
                f"evidence_fingerprint: {fingerprint}",
                f"secret_type: {record.get('secret_type') or 'unknown'}",
                f"detector: {record.get('detector') or 'unknown'}",
                f"artifact_ref: {record.get('artifact_ref') or ''}",
                f"artifact_sha256: {record.get('artifact_sha256') or ''}",
                f"source: {location}",
                f"confidence: {float(record.get('confidence') or 0.0):.3f}",
                "verification_attempted: false",
                "credential_used: false",
                "raw_secret_json: " + json.dumps(
                    str(record["raw_secret"]),
                    ensure_ascii=False,
                ),
                "---",
            )
        )

    return tuple(lines)


def _atomic_write_lines(
    path: Path,
    lines: Sequence[str],
    *,
    permissions: int,
    header: str | None = None,
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
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if header:
                handle.write(header.rstrip("\n") + "\n")
            for line in lines:
                handle.write(str(line).replace("\r", " ").rstrip("\n"))
                handle.write("\n")
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


async def export_text_bundle(
    events: Sequence[Event],
    output_dir: Path,
    *,
    options: TextExportOptions | None = None,
    sensitive_provider: SensitiveEvidenceProvider | None = None,
) -> tuple[Path, ...]:
    options = options or TextExportOptions()

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

    written: list[Path] = []
    safe_lists = build_safe_text_lists(events)

    for filename, lines in safe_lists.items():
        if not lines and not options.include_empty_files:
            continue

        header = None
        if options.include_headers:
            header = "# Night Scout SAFE export — raw credentials are not included"

        written.append(
            _atomic_write_lines(
                output_dir / filename,
                lines,
                permissions=options.safe_file_permissions,
                header=header,
            )
        )

    if options.mode is ExportMode.SENSITIVE_EVIDENCE:
        assert sensitive_provider is not None
        sensitive_lines = await build_sensitive_text_lines(
            events,
            provider=sensitive_provider,
        )
        if sensitive_lines or options.include_empty_files:
            written.append(
                _atomic_write_lines(
                    output_dir / "sensitive_evidence.txt",
                    sensitive_lines,
                    permissions=options.sensitive_file_permissions,
                    header=(
                        "# Night Scout SENSITIVE_EVIDENCE export — contains raw credentials; "
                        "authorized handling only"
                    ),
                )
            )

    return tuple(written)
