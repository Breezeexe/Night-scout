from __future__ import annotations

import json
import stat

import pytest
from pydantic import SecretStr

from recon.core.events import Event, EventType
from recon.exporters.jsonl import (
    ExportMode,
    JsonlExportOptions,
    WorkspaceSensitiveEvidenceProvider,
    build_jsonl_records,
)
from recon.workers.mobile import SensitiveEvidenceRecord, WorkspaceSensitiveEvidenceStore


@pytest.mark.asyncio
async def test_safe_export_redacts_raw_secret_sensitive_mode_is_explicit(tmp_path):
    secret = "ghp_fixture_super_secret_value"
    fingerprint = "a" * 64
    store = WorkspaceSensitiveEvidenceStore(tmp_path / "protected")
    await store.store(
        SensitiveEvidenceRecord(
            evidence_fingerprint=fingerprint,
            raw_secret=SecretStr(secret),
            secret_type="github-token",
            detector="fixture",
            source_file="app/config.java",
            line=10,
            artifact_ref="apk:fixture",
            artifact_sha256="b" * 64,
        )
    )

    event = Event(
        type=EventType.ARTIFACT,
        value="possible credential",
        source="mobile:secret",
        tags={"possible-secret"},
        metadata={
            "evidence_fingerprint": fingerprint,
            "secret_type": "github-token",
        },
    )

    safe_records = await build_jsonl_records([event])
    assert secret not in json.dumps(safe_records)

    provider = WorkspaceSensitiveEvidenceProvider(tmp_path / "protected")
    with pytest.raises(ValueError):
        await build_jsonl_records(
            [event],
            options=JsonlExportOptions(mode=ExportMode.SENSITIVE_EVIDENCE),
            sensitive_provider=provider,
        )

    sensitive_records = await build_jsonl_records(
        [event],
        options=JsonlExportOptions(
            mode=ExportMode.SENSITIVE_EVIDENCE,
            confirm_sensitive_export=True,
        ),
        sensitive_provider=provider,
    )
    assert any(record.get("raw_secret") == secret for record in sensitive_records)

    evidence_file = next((tmp_path / "protected").glob("*.json"))
    assert stat.S_IMODE((tmp_path / "protected").stat().st_mode) == 0o700
    assert stat.S_IMODE(evidence_file.stat().st_mode) == 0o600
