"""Fail-closed ownership binding for a physical Night Scout workspace."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from recon.storage.database import Database
from recon.storage.models import Base, ReconRunRecord, WorkspaceMetadataRecord


class WorkspaceBindingError(RuntimeError):
    """Base class for workspace ownership failures."""


class WorkspaceTargetMismatchError(WorkspaceBindingError):
    """The requested scope does not own the selected workspace."""


class WorkspaceContaminatedError(WorkspaceBindingError):
    """Historical runs attribute one workspace to multiple targets."""


class WorkspaceUnboundError(WorkspaceBindingError):
    """A populated legacy workspace has no trustworthy target attribution."""


@dataclass(frozen=True, slots=True)
class WorkspaceBinding:
    target_id: str
    created: bool
    adopted_from_history: bool


class WorkspaceRepository:
    """Bind or validate the single target allowed in one database."""

    _SINGLETON_ID = 1

    def __init__(self, database: Database) -> None:
        self._database = database

    async def bind_or_validate(
        self,
        target_id: str,
        *,
        allow_unattributed_adoption: bool = False,
    ) -> WorkspaceBinding:
        normalized = target_id.strip()
        if not normalized:
            raise ValueError("workspace target_id must not be blank")

        async with self._database.transaction(immediate=True) as session:
            marker = await session.get(WorkspaceMetadataRecord, self._SINGLETON_ID)
            history = frozenset(
                str(value)
                for value in (
                    await session.scalars(
                        select(ReconRunRecord.target_id)
                        .where(ReconRunRecord.target_id.is_not(None))
                        .distinct()
                    )
                ).all()
                if value is not None and str(value).strip()
            )

            if len(history) > 1:
                rendered = ", ".join(sorted(history))
                raise WorkspaceContaminatedError(
                    "workspace contains runs attributed to multiple targets: "
                    f"{rendered}; use a fresh target workspace and recover data manually"
                )

            if marker is not None:
                if marker.target_id != normalized:
                    raise WorkspaceTargetMismatchError(
                        f"workspace belongs to target {marker.target_id!r}, but scope requests "
                        f"{normalized!r}; select the matching scope or a different workspace"
                    )
                if history and history != {normalized}:
                    historical = next(iter(history))
                    raise WorkspaceContaminatedError(
                        f"workspace marker is {normalized!r}, but historical runs belong to "
                        f"{historical!r}"
                    )
                await session.execute(
                    update(ReconRunRecord)
                    .where(ReconRunRecord.target_id.is_(None))
                    .values(target_id=normalized)
                )
                return WorkspaceBinding(
                    target_id=normalized,
                    created=False,
                    adopted_from_history=False,
                )

            if history:
                historical = next(iter(history))
                if historical != normalized:
                    raise WorkspaceTargetMismatchError(
                        f"unbound legacy workspace contains runs for {historical!r}, but scope "
                        f"requests {normalized!r}"
                    )
                adopted_from_history = True
            else:
                has_data = await self._has_persisted_data(session)
                if has_data and not allow_unattributed_adoption:
                    raise WorkspaceUnboundError(
                        "populated legacy workspace has no target attribution; inspect it, then "
                        "run 'nightscout workspace adopt' with the intended scope"
                    )
                adopted_from_history = False

            session.add(
                WorkspaceMetadataRecord(
                    singleton_id=self._SINGLETON_ID,
                    target_id=normalized,
                    schema_version=1,
                )
            )
            await session.execute(
                update(ReconRunRecord)
                .where(ReconRunRecord.target_id.is_(None))
                .values(target_id=normalized)
            )
            return WorkspaceBinding(
                target_id=normalized,
                created=True,
                adopted_from_history=adopted_from_history,
            )

    @staticmethod
    async def _has_persisted_data(session: AsyncSession) -> bool:
        # All tables are present at migration head. Checking every domain table
        # prevents an apparently empty workspace with only budgets/cache/audit
        # state from being silently assigned to the wrong target.
        for table in Base.metadata.sorted_tables:
            if table.name in {"workspace_metadata"}:
                continue
            count = await session.scalar(select(func.count()).select_from(table))
            if int(count or 0) > 0:
                return True
        return False


_SAFE_WORKSPACE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")


def workspace_directory_name(target_id: str) -> str:
    """Return a deterministic path component without weakening target identity."""

    normalized = target_id.strip()
    if not normalized:
        raise ValueError("workspace target_id must not be blank")
    if normalized not in {".", ".."} and _SAFE_WORKSPACE_COMPONENT.fullmatch(normalized):
        return normalized
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"target-{digest}"


def recorded_workspace_target_ids(database_path: str | Path) -> frozenset[str]:
    """Read target attribution from a legacy DB without modifying its schema."""

    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        return frozenset()

    targets: set[str] = set()
    try:
        with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "workspace_metadata" in tables:
                for (value,) in connection.execute(
                    "SELECT target_id FROM workspace_metadata"
                ).fetchall():
                    if isinstance(value, str) and value.strip():
                        targets.add(value.strip())

            if "recon_runs" not in tables:
                return frozenset(targets)

            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(recon_runs)").fetchall()
            }
            if "target_id" in columns:
                for (value,) in connection.execute(
                    "SELECT DISTINCT target_id FROM recon_runs WHERE target_id IS NOT NULL"
                ).fetchall():
                    if isinstance(value, str) and value.strip():
                        targets.add(value.strip())

            if "metadata_json" in columns:
                for (raw_metadata,) in connection.execute(
                    "SELECT metadata_json FROM recon_runs"
                ).fetchall():
                    if not isinstance(raw_metadata, str):
                        continue
                    try:
                        metadata = json.loads(raw_metadata)
                    except json.JSONDecodeError:
                        continue
                    value = metadata.get("scope_target_id") if isinstance(metadata, dict) else None
                    if isinstance(value, str) and value.strip():
                        targets.add(value.strip())
    except sqlite3.DatabaseError:
        # The normal migration/open path will report an invalid selected DB.
        # It is not safe to infer ownership from an unreadable legacy candidate.
        return frozenset()

    return frozenset(targets)
