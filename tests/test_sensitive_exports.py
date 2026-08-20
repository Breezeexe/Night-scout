from __future__ import annotations

import json
import stat

import pytest
from pydantic import SecretStr

from recon.core.events import Event, EventType
from recon.core.redaction import sanitize_url
from recon.exporters.jsonl import (
    ExportMode,
    JsonlExportOptions,
    WorkspaceSensitiveEvidenceProvider,
    build_jsonl_records,
)
from recon.storage.database import Database, EventRepository
from recon.storage.schema import upgrade_database
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


@pytest.mark.asyncio
async def test_sensitive_url_is_redacted_before_ordinary_event_storage(tmp_path):
    database_path = tmp_path / "events.sqlite3"
    upgrade_database(database_path)
    database = Database.from_path(database_path)
    secret = "raw-super-secret-token"
    event = Event(
        type=EventType.URL,
        value=(
            "https://user:password@example.com/reset/abcdefghijk"
            f"?page=2&access_token={secret}&apiKey={secret}"
            f"&X-Amz-Signature={secret}"
        ),
        source="test",
        metadata={
            "request_url": f"https://example.com/callback?code={secret}&page=2",
            "raw_secret": secret,
        },
    )
    try:
        await EventRepository(database).ingest(event)
        stored = await EventRepository(database).get_event(event.event_id)
        assert stored is not None
        serialized = json.dumps(stored.model_dump(mode="json"))
        assert secret not in serialized
        assert "password" not in stored.value
        assert "page=2" in stored.value
        assert stored.metadata["raw_secret"] == "[REDACTED]"
        assert "sensitive-data-redacted" in stored.tags
    finally:
        await database.dispose()


@pytest.mark.parametrize(
    "value",
    (
        "/oauth/callback?code=raw-super-secret-token",
        "/api/reset/raw-super-secret-token",
        "//example.com/callback?access_token=raw-super-secret-token",
        "../callback?apiKey=raw-super-secret-token&safe=visible",
    ),
)
def test_relative_web_references_are_redacted(value):
    sanitized = sanitize_url(value)
    assert "raw-super-secret-token" not in sanitized
    assert "[REDACTED]" in sanitized or "%5BREDACTED%5D" in sanitized


@pytest.mark.asyncio
async def test_relative_api_endpoint_is_redacted_before_storage(tmp_path):
    database_path = tmp_path / "relative-events.sqlite3"
    upgrade_database(database_path)
    database = Database.from_path(database_path)
    secret = "raw-super-secret-token"
    event = Event(
        type=EventType.API_ENDPOINT,
        value=f"/oauth/callback?access_token={secret}&page=2",
        source="test",
        metadata={"relative_url": f"//example.com/reset/{secret}"},
    )
    try:
        await EventRepository(database).ingest(event)
        stored = await EventRepository(database).get_event(event.event_id)
        assert stored is not None
        serialized = json.dumps(stored.model_dump(mode="json"))
        assert secret not in serialized
        assert "page=2" in stored.value
    finally:
        await database.dispose()
