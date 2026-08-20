"""separate task origin from execution run attribution

Revision ID: 0002_task_execution_run
Revises: 0001_initial_schema
Create Date: 2026-08-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_task_execution_run"
down_revision: str | Sequence[str] | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tasks", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("execution_run_id", sa.String(length=40), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_tasks_execution_run_id_recon_runs",
            "recon_runs",
            ["execution_run_id"],
            ["run_id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_tasks_execution_run_id",
            ["execution_run_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("tasks", schema=None) as batch_op:
        batch_op.drop_index("ix_tasks_execution_run_id")
        batch_op.drop_constraint(
            "fk_tasks_execution_run_id_recon_runs",
            type_="foreignkey",
        )
        batch_op.drop_column("execution_run_id")
