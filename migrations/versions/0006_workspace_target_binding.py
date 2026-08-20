"""bind each physical workspace to one scope target

Revision ID: 0006_workspace_target
Revises: 0005_task_attempts
Create Date: 2026-08-20
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

import recon.storage.models

revision: str = "0006_workspace_target"
down_revision: str | Sequence[str] | None = "0005_task_attempts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _scope_target_id(raw_metadata: Any) -> str | None:
    if isinstance(raw_metadata, str):
        try:
            raw_metadata = json.loads(raw_metadata)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw_metadata, dict):
        return None
    value = raw_metadata.get("scope_target_id")
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def upgrade() -> None:
    op.create_table(
        "workspace_metadata",
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            recon.storage.models.UTCDateTime(length=40),
            nullable=False,
        ),
        sa.CheckConstraint(
            "singleton_id = 1",
            name=op.f("ck_workspace_metadata_workspace_metadata_singleton"),
        ),
        sa.CheckConstraint(
            "schema_version >= 1",
            name=op.f("ck_workspace_metadata_workspace_metadata_schema_version_positive"),
        ),
        sa.PrimaryKeyConstraint("singleton_id", name=op.f("pk_workspace_metadata")),
        sa.UniqueConstraint("target_id", name=op.f("uq_workspace_metadata_target_id")),
    )

    with op.batch_alter_table("recon_runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("target_id", sa.Text(), nullable=True))
        batch_op.create_index("ix_recon_runs_target_id", ["target_id"], unique=False)

    # Earlier versions already wrote scope_target_id into run metadata. Promote
    # it into the typed audit column without binding a potentially mixed DB.
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT run_id, metadata_json FROM recon_runs")).fetchall()
    for run_id, metadata_json in rows:
        target_id = _scope_target_id(metadata_json)
        if target_id is not None:
            connection.execute(
                sa.text("UPDATE recon_runs SET target_id = :target_id WHERE run_id = :run_id"),
                {"target_id": target_id, "run_id": run_id},
            )


def downgrade() -> None:
    with op.batch_alter_table("recon_runs", schema=None) as batch_op:
        batch_op.drop_index("ix_recon_runs_target_id")
        batch_op.drop_column("target_id")
    op.drop_table("workspace_metadata")
