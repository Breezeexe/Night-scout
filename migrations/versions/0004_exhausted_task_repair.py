"""repair active tasks that have exhausted their execution attempts

Revision ID: 0004_exhausted_task_repair
Revises: 0003_task_claim_fencing
Create Date: 2026-08-20
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_exhausted_task_repair"
down_revision: str | Sequence[str] | None = "0003_task_claim_fencing"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 0003 deliberately recovered legacy RUNNING rows into DEFERRED. Rows
    # already on their final allowed attempt cannot ever be claimed again, so
    # keeping them active creates an endless scheduler select/claim loop.
    op.execute(
        "UPDATE tasks SET status = 'FAILED', started_at = NULL, "
        "finished_at = COALESCE(finished_at, updated_at), "
        "lease_expires_at = NULL, claim_token = NULL, "
        "last_error = COALESCE(last_error, "
        "'retry budget exhausted before task repair migration') "
        "WHERE status IN ('PENDING', 'DEFERRED', 'REVIEW') "
        "AND attempts >= max_attempts"
    )


def downgrade() -> None:
    # The original active state cannot be reconstructed safely. A FAILED row
    # remains valid under the previous schema and preserves the audit trail.
    pass
