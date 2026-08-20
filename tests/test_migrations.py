from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import create_engine

from recon.storage.models import Base
from recon.storage.schema import (
    SchemaMigrationError,
    SchemaUpgradeAction,
    current_revision,
    downgrade_database,
    head_revision,
    legacy_schema_compatible,
    upgrade_database,
    user_tables,
)


def test_empty_database_upgrade_downgrade_upgrade(tmp_path):
    path = tmp_path / "workspace.sqlite3"

    first = upgrade_database(path)
    assert first.action is SchemaUpgradeAction.CREATED
    assert first.current_revision == head_revision(path)
    assert current_revision(path) == first.current_revision
    assert legacy_schema_compatible(path)

    assert downgrade_database(path, "base") is None
    assert user_tables(path) == frozenset({"alembic_version"})

    second = upgrade_database(path)
    assert second.action is SchemaUpgradeAction.CREATED
    assert current_revision(path) == head_revision(path)


def test_legacy_create_all_database_is_adopted_without_data_loss(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(engine)
    engine.dispose()

    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO recon_runs(run_id,status,started_at,metadata_json) VALUES(?,?,?,?)",
            ("run_fixture", "RUNNING", "2026-08-19T00:00:00+00:00", "{}"),
        )
        connection.commit()

    assert current_revision(path) is None
    result = upgrade_database(path)
    assert result.action is SchemaUpgradeAction.ADOPTED_LEGACY
    assert current_revision(path) == head_revision(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT run_id FROM recon_runs WHERE run_id='run_fixture'"
        ).fetchone() == ("run_fixture",)


def test_incompatible_unversioned_database_fails_closed(tmp_path):
    path = tmp_path / "unknown.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE assets(asset_id TEXT PRIMARY KEY)")
        connection.commit()

    with pytest.raises(SchemaMigrationError):
        upgrade_database(path)

    assert current_revision(path) is None
    with sqlite3.connect(path) as connection:
        columns = connection.execute("PRAGMA table_info(assets)").fetchall()
    assert [row[1] for row in columns] == ["asset_id"]


def test_claim_fencing_migration_recovers_preexisting_running_task(tmp_path):
    path = tmp_path / "pre-fencing.sqlite3"
    upgrade_database(path)
    assert downgrade_database(path, "0002_task_execution_run") is not None

    timestamp = "2026-08-20T10:00:00.000000+00:00"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO assets(
                asset_id, event_type, value, identity_key, first_seen,
                last_seen, scope_state, confidence, novelty, min_depth,
                tags_json, metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "asset_fixture",
                "ROOT_DOMAIN",
                "example.com",
                "ROOT_DOMAIN:example.com",
                timestamp,
                timestamp,
                "IN_SCOPE",
                1.0,
                1.0,
                0,
                "[]",
                "{}",
            ),
        )
        connection.execute(
            """
            INSERT INTO event_observations(
                event_id, asset_id, event_type, value, source, first_seen,
                last_seen, scope_state, confidence, novelty, depth,
                tags_json, metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "event_fixture",
                "asset_fixture",
                "ROOT_DOMAIN",
                "example.com",
                "fixture",
                timestamp,
                timestamp,
                "IN_SCOPE",
                1.0,
                1.0,
                0,
                "[]",
                "{}",
            ),
        )
        connection.execute(
            """
            INSERT INTO tasks(
                task_id, worker, action, input_event_id, status, priority,
                attempts, max_attempts, created_at, updated_at, available_at,
                started_at, lease_expires_at, dedupe_key
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "task_running_fixture",
                "fixture",
                "probe",
                "event_fixture",
                "RUNNING",
                0.0,
                1,
                3,
                timestamp,
                timestamp,
                timestamp,
                timestamp,
                timestamp,
                "fixture:probe:event_fixture",
            ),
        )
        connection.commit()

    upgrade_database(path)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT status, started_at, lease_expires_at, claim_token, last_error
            FROM tasks WHERE task_id = 'task_running_fixture'
            """
        ).fetchone()

    assert row == (
        "DEFERRED",
        None,
        None,
        None,
        "worker claim invalidated by claim fencing migration",
    )
