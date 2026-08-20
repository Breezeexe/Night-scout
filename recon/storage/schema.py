"""Alembic schema management for Night Scout workspaces.

Runtime startup uses this module instead of blindly calling ``metadata.create_all``.
It supports three cases:

1. Empty database -> run migrations to ``head``.
2. Existing Alembic database -> upgrade to ``head``.
3. Legacy pre-Alembic Night Scout database -> verify table/column compatibility,
   then stamp the baseline revision without recreating or deleting data.

An incompatible unversioned database fails closed and is never modified.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from recon.resources import bundled_resource_root
from recon.storage.models import Base


class SchemaMigrationError(RuntimeError):
    """Raised when a workspace cannot be migrated safely."""


class SchemaUpgradeAction(StrEnum):
    CREATED = "CREATED"
    UPGRADED = "UPGRADED"
    ADOPTED_LEGACY = "ADOPTED_LEGACY"
    ALREADY_CURRENT = "ALREADY_CURRENT"


@dataclass(frozen=True, slots=True)
class SchemaUpgradeResult:
    path: Path
    action: SchemaUpgradeAction
    previous_revision: str | None
    current_revision: str | None


def project_root() -> Path:
    """Return the source/distribution root containing ``migrations``."""

    override = os.environ.get("NIGHTSCOUT_PROJECT_ROOT", "").strip()
    if override:
        root = Path(override).expanduser().resolve()
    else:
        root = bundled_resource_root()

    if not (root / "migrations").is_dir():
        raise SchemaMigrationError(
            f"Night Scout migrations directory not found under {root}"
        )

    return root


def alembic_config(database_path: str | Path) -> Config:
    """Build an Alembic Config without depending on process cwd."""

    root = project_root()
    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    ini_path = root / "alembic.ini"
    config = Config(str(ini_path) if ini_path.is_file() else None)
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("prepend_sys_path", str(root))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    return config


def head_revision(database_path: str | Path) -> str | None:
    config = alembic_config(database_path)
    return ScriptDirectory.from_config(config).get_current_head()


def current_revision(database_path: str | Path) -> str | None:
    path = Path(database_path).expanduser().resolve()
    if not path.exists():
        return None

    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            return context.get_current_revision()
    finally:
        engine.dispose()


def user_tables(database_path: str | Path) -> frozenset[str]:
    path = Path(database_path).expanduser().resolve()
    if not path.exists():
        return frozenset()

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()

    return frozenset(str(row[0]) for row in rows)


def legacy_schema_compatible(database_path: str | Path) -> bool:
    """Return whether an unversioned DB exactly matches current table columns.

    We deliberately require exact table and column sets. Constraint/index drift
    is not silently repaired during legacy adoption; future migrations can make
    explicit changes after the baseline has been stamped.
    """

    path = Path(database_path).expanduser().resolve()
    if not path.exists():
        return False

    existing_tables = set(user_tables(path))
    existing_tables.discard("alembic_version")
    expected_tables = set(Base.metadata.tables)

    if existing_tables != expected_tables:
        return False

    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        inspector = inspect(engine)
        for table_name, table in Base.metadata.tables.items():
            actual_columns = {
                str(column["name"])
                for column in inspector.get_columns(table_name)
            }
            expected_columns = {column.name for column in table.columns}
            if actual_columns != expected_columns:
                return False
    finally:
        engine.dispose()

    return True


def upgrade_database(database_path: str | Path) -> SchemaUpgradeResult:
    """Safely bring one SQLite workspace to the current Alembic head."""

    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    before = current_revision(path)
    head = head_revision(path)
    tables = set(user_tables(path))
    non_version_tables = tables - {"alembic_version"}
    config = alembic_config(path)

    if before == head and head is not None:
        return SchemaUpgradeResult(
            path=path,
            action=SchemaUpgradeAction.ALREADY_CURRENT,
            previous_revision=before,
            current_revision=before,
        )

    if before is None and non_version_tables:
        if not legacy_schema_compatible(path):
            raise SchemaMigrationError(
                "database has Night Scout-like/unversioned tables but does not "
                "exactly match the baseline schema; refusing automatic adoption"
            )

        command.stamp(config, "head")
        after = current_revision(path)
        return SchemaUpgradeResult(
            path=path,
            action=SchemaUpgradeAction.ADOPTED_LEGACY,
            previous_revision=None,
            current_revision=after,
        )

    was_empty = not non_version_tables
    command.upgrade(config, "head")
    after = current_revision(path)

    return SchemaUpgradeResult(
        path=path,
        action=(
            SchemaUpgradeAction.CREATED
            if was_empty
            else SchemaUpgradeAction.UPGRADED
        ),
        previous_revision=before,
        current_revision=after,
    )


def downgrade_database(
    database_path: str | Path,
    revision: str = "base",
) -> str | None:
    """Downgrade a workspace. Intended for development/tests, not runtime."""

    path = Path(database_path).expanduser().resolve()
    config = alembic_config(path)
    command.downgrade(config, revision)
    return current_revision(path)
