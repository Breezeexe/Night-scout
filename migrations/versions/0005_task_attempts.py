"""add append-only task attempt attribution

Revision ID: 0005_task_attempts
Revises: 0004_exhausted_task_repair
Create Date: 2026-08-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_task_attempts"
down_revision: str | Sequence[str] | None = "0004_exhausted_task_repair"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "task_attempts",
        sa.Column("attempt_id", sa.String(length=40), nullable=False),
        sa.Column("run_id", sa.String(length=40), nullable=False),
        sa.Column("task_id", sa.String(length=40), nullable=False),
        sa.Column("worker", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("selected_at", sa.String(length=40), nullable=False),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.Column("queue_status", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("reservation_id", sa.String(length=40), nullable=True),
        sa.Column("claimed", sa.Boolean(), nullable=False),
        sa.Column("execution_attempt", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "execution_attempt IS NULL OR execution_attempt >= 1",
            name=op.f("ck_task_attempts_task_attempt_execution_positive"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["recon_runs.run_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.task_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("attempt_id"),
    )
    op.create_index("ix_task_attempts_run_id", "task_attempts", ["run_id"])
    op.create_index("ix_task_attempts_task_id", "task_attempts", ["task_id"])
    op.create_index("ix_task_attempts_selected_at", "task_attempts", ["selected_at"])
    op.create_index("ix_task_attempts_run_task", "task_attempts", ["run_id", "task_id"])


def downgrade() -> None:
    op.drop_index("ix_task_attempts_run_task", table_name="task_attempts")
    op.drop_index("ix_task_attempts_selected_at", table_name="task_attempts")
    op.drop_index("ix_task_attempts_task_id", table_name="task_attempts")
    op.drop_index("ix_task_attempts_run_id", table_name="task_attempts")
    op.drop_table("task_attempts")
