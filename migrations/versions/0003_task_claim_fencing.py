"""fence task execution attempts with claim tokens

Revision ID: 0003_task_claim_fencing
Revises: 0002_task_execution_run
Create Date: 2026-08-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_task_claim_fencing"
down_revision: str | Sequence[str] | None = "0002_task_execution_run"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A worker from the pre-fencing version cannot safely retain ownership.
    # Recover such rows into the durable frontier before enforcing the token
    # invariant; their consumed attempt count remains unchanged.
    op.execute(
        "UPDATE tasks SET status = 'DEFERRED', started_at = NULL, "
        "lease_expires_at = NULL, available_at = updated_at, "
        "last_error = 'worker claim invalidated by claim fencing migration' "
        "WHERE status = 'RUNNING'"
    )
    with op.batch_alter_table("tasks", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("claim_token", sa.String(length=64), nullable=True)
        )
        batch_op.create_check_constraint(
            "task_claim_token_matches_status",
            "(status = 'RUNNING' AND claim_token IS NOT NULL) OR "
            "(status != 'RUNNING' AND claim_token IS NULL)",
        )


def downgrade() -> None:
    with op.batch_alter_table("tasks", schema=None) as batch_op:
        batch_op.drop_constraint(
            "task_claim_token_matches_status",
            type_="check",
        )
        batch_op.drop_column("claim_token")
