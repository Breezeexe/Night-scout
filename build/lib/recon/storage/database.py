"""Durable SQLite adapters for Night Scout.

This module is the boundary between storage-agnostic core/policy contracts and
SQLAlchemy/SQLite.

It provides:

    Database
        Async engine/session lifecycle plus SQLite safety pragmas.

    EventRepository
        Event -> canonical Asset + provenance-preserving Observation storage.

    SQLiteTaskStore
        Durable implementation of core.queue.TaskStore.

    SQLiteBudgetStore
        Transactional persistent budget reservations/usage.

    SQLiteReviewCaseStore
        Durable human-review backlog.

    SQLiteRateLimitStore
        Shared persistent token/concurrency buckets.

    DecisionRepository
        Append-only scheduler/policy decision history for explainability.

SQLite is treated as a single target-workspace database. A Night Scout process
may launch many external worker subprocesses, but the orchestrator remains the
writer/coordinator. Budget/rate acquisitions still use BEGIN IMMEDIATE so
concurrent lifecycle coroutines cannot collectively overspend shared limits.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, event as sa_event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from recon.core.budgets import (
    BudgetCheck,
    BudgetClass,
    BudgetMetric,
    BudgetReservation,
    BudgetReservationItem,
    BudgetUsage,
    BudgetViolation,
    ReservationState,
)
from recon.core.events import Event, EventType, ScopeState
from recon.core.queue import TERMINAL_TASK_STATUSES, Task, TaskStatus
from recon.core.scheduler import ScheduleDecision
from recon.policy.rate_limit import (
    RateBucketCheck,
    RateBucketState,
    RateLeaseItem,
    RateLeaseState,
    RateLimitDecision,
    RateLimitLease,
    RateLimitOutcome,
    RateLimitViolation,
)
from recon.policy.review_gate import (
    ReviewCase,
    ReviewCaseState,
    ReviewCategory,
    ReviewSignal,
)
from recon.storage.models import (
    AssetRecord,
    Base,
    BranchRecord,
    BudgetReservationItemRecord,
    BudgetReservationRecord,
    BudgetUsageRecord,
    EventObservationRecord,
    PolicyDecisionRecord,
    RateBucketRecord,
    RateLeaseItemRecord,
    RateLeaseRecord,
    ReconRunRecord,
    ReviewCaseRecord,
    ReviewSignalRecord,
    SchedulerDecisionRecord,
    TaskRecord,
)


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, *, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


class DatabaseConfig(BaseModel):
    """SQLite workspace configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    busy_timeout_ms: int = 5000
    echo: bool = False
    wal: bool = True
    synchronous: str = "NORMAL"


class Database:
    """Own the async SQLite engine and session factory."""

    def __init__(self, config: DatabaseConfig) -> None:
        if config.busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms cannot be negative")

        synchronous = config.synchronous.strip().upper()
        if synchronous not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
            raise ValueError(
                "synchronous must be OFF, NORMAL, FULL, or EXTRA"
            )

        path = config.path.expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        self.config = config.model_copy(
            update={
                "path": path,
                "synchronous": synchronous,
            }
        )

        url = f"sqlite+aiosqlite:///{path.as_posix()}"

        self.engine: AsyncEngine = create_async_engine(
            url,
            echo=self.config.echo,
            pool_pre_ping=True,
            connect_args={
                "timeout": self.config.busy_timeout_ms / 1000.0,
            },
        )

        timeout_ms = self.config.busy_timeout_ms
        wal = self.config.wal
        sync_mode = self.config.synchronous

        @sa_event.listens_for(self.engine.sync_engine, "connect")
        def _configure_sqlite(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute(f"PRAGMA busy_timeout={timeout_ms}")
                cursor.execute(f"PRAGMA synchronous={sync_mode}")
                if wal:
                    cursor.execute("PRAGMA journal_mode=WAL")
            finally:
                cursor.close()

        self.sessions = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
            autoflush=False,
        )

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5000,
        echo: bool = False,
        wal: bool = True,
        synchronous: str = "NORMAL",
    ) -> Database:
        """Construct a workspace database from a filesystem path."""
        return cls(
            DatabaseConfig(
                path=Path(path),
                busy_timeout_ms=busy_timeout_ms,
                echo=echo,
                wal=wal,
                synchronous=synchronous,
            )
        )

    async def initialize_schema(self) -> None:
        """Create the current schema directly for isolated tests/tools.

        Production runtime startup uses ``recon.storage.schema.upgrade_database``
        and Alembic migrations. Keeping this method is useful for narrow unit
        fixtures and legacy-schema compatibility tests.
        """
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        """Close pooled SQLite connections."""
        await self.engine.dispose()

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a plain session; caller controls transaction boundaries."""
        async with self.sessions() as session:
            yield session

    @asynccontextmanager
    async def transaction(
        self,
        *,
        immediate: bool = False,
    ) -> AsyncIterator[AsyncSession]:
        """Yield a transaction, optionally acquiring SQLite's write lock early.

        BEGIN IMMEDIATE is used by budget/rate-limit stores where a read-check-
        write sequence must be atomic across concurrent sessions.
        """
        async with self.sessions() as session:
            if immediate:
                await session.execute(text("BEGIN IMMEDIATE"))
                try:
                    yield session
                except BaseException:
                    await session.rollback()
                    raise
                else:
                    await session.commit()
            else:
                async with session.begin():
                    yield session


class EventWriteResult(BaseModel):
    """Result of durable event ingestion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    asset_id: str

    asset_created: bool
    observation_created: bool


class EventRepository:
    """Persist and retrieve canonical assets plus event observations."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def ingest(
        self,
        event: Event,
        *,
        run_id: str | None = None,
    ) -> EventWriteResult:
        """Persist an Event without destroying repeated-source evidence."""
        async with self._database.transaction(immediate=True) as session:
            existing_observation = await session.get(
                EventObservationRecord,
                event.event_id,
            )
            if existing_observation is not None:
                if (
                    existing_observation.event_type != event.type.value
                    or existing_observation.value != event.value
                    or existing_observation.source != event.source
                ):
                    raise ValueError(
                        f"event_id {event.event_id} already refers to a "
                        "different observation"
                    )

                asset = await session.get(
                    AssetRecord,
                    existing_observation.asset_id,
                )
                if asset is None:
                    raise RuntimeError(
                        "event observation references missing asset"
                    )

                self._merge_asset(asset, event)
                self._merge_observation(existing_observation, event)

                return EventWriteResult(
                    event_id=event.event_id,
                    asset_id=asset.asset_id,
                    asset_created=False,
                    observation_created=False,
                )

            asset = await session.scalar(
                select(AssetRecord).where(
                    AssetRecord.identity_key == event.identity_key
                )
            )

            asset_created = False
            if asset is None:
                asset = AssetRecord(
                    asset_id=f"ast_{uuid4().hex}",
                    event_type=event.type.value,
                    value=event.value,
                    identity_key=event.identity_key,
                    first_seen=event.first_seen,
                    last_seen=event.last_seen,
                    scope_state=event.scope_state.value,
                    confidence=event.confidence,
                    novelty=event.novelty,
                    min_depth=event.depth,
                    tags_json=sorted(event.tags),
                    metadata_json=dict(event.metadata),
                )
                session.add(asset)
                await session.flush()
                asset_created = True
            else:
                self._merge_asset(asset, event)

            observation = EventObservationRecord(
                event_id=event.event_id,
                asset_id=asset.asset_id,
                run_id=run_id,
                event_type=event.type.value,
                value=event.value,
                source=event.source,
                parent_event_id=event.parent_event_id,
                first_seen=event.first_seen,
                last_seen=event.last_seen,
                scope_state=event.scope_state.value,
                confidence=event.confidence,
                novelty=event.novelty,
                depth=event.depth,
                tags_json=sorted(event.tags),
                metadata_json=dict(event.metadata),
            )
            session.add(observation)

            return EventWriteResult(
                event_id=event.event_id,
                asset_id=asset.asset_id,
                asset_created=asset_created,
                observation_created=True,
            )

    async def get_event(self, event_id: str) -> Event | None:
        """Load one persisted observation as the core Event model."""
        async with self._database.session() as session:
            record = await session.get(EventObservationRecord, event_id)
            return _event_from_record(record) if record is not None else None

    async def asset_id_for_event(self, event_id: str) -> str | None:
        """Return canonical asset id represented by an event observation."""
        async with self._database.session() as session:
            return await session.scalar(
                select(EventObservationRecord.asset_id).where(
                    EventObservationRecord.event_id == event_id
                )
            )

    async def observations_for_asset(
        self,
        asset_id: str,
    ) -> list[Event]:
        """Return all provenance observations for an asset."""
        async with self._database.session() as session:
            rows = list(
                (
                    await session.scalars(
                        select(EventObservationRecord)
                        .where(
                            EventObservationRecord.asset_id == asset_id
                        )
                        .order_by(
                            EventObservationRecord.first_seen,
                            EventObservationRecord.event_id,
                        )
                    )
                ).all()
            )
            return [_event_from_record(row) for row in rows]

    @staticmethod
    def _merge_asset(asset: AssetRecord, event: Event) -> None:
        asset.first_seen = min(asset.first_seen, event.first_seen)
        asset.last_seen = max(asset.last_seen, event.last_seen)
        asset.confidence = max(asset.confidence, event.confidence)
        asset.novelty = max(asset.novelty, event.novelty)
        asset.min_depth = min(asset.min_depth, event.depth)

        asset.scope_state = _merge_scope_state(
            ScopeState(asset.scope_state),
            event.scope_state,
        ).value

        asset.tags_json = sorted(
            set(asset.tags_json) | set(event.tags)
        )

        # Canonical metadata is a convenience summary only; exact source data
        # remains intact on every EventObservationRecord.
        merged_metadata = dict(asset.metadata_json)
        merged_metadata.update(event.metadata)
        asset.metadata_json = merged_metadata

    @staticmethod
    def _merge_observation(
        observation: EventObservationRecord,
        event: Event,
    ) -> None:
        observation.first_seen = min(
            observation.first_seen,
            event.first_seen,
        )
        observation.last_seen = max(
            observation.last_seen,
            event.last_seen,
        )
        observation.confidence = max(
            observation.confidence,
            event.confidence,
        )
        observation.novelty = max(
            observation.novelty,
            event.novelty,
        )
        observation.scope_state = _merge_scope_state(
            ScopeState(observation.scope_state),
            event.scope_state,
        ).value
        observation.tags_json = sorted(
            set(observation.tags_json) | set(event.tags)
        )

        merged_metadata = dict(observation.metadata_json)
        merged_metadata.update(event.metadata)
        observation.metadata_json = merged_metadata


class SQLiteTaskStore:
    """Durable implementation of core.queue.TaskStore."""

    def __init__(
        self,
        database: Database,
        *,
        run_id: str | None = None,
    ) -> None:
        self._database = database
        self._run_id = run_id

    @property
    def run_id(self) -> str | None:
        """Return the run currently associated with newly inserted tasks."""

        return self._run_id

    def set_run_id(self, run_id: str | None) -> None:
        """Bind subsequent task inserts to a persistent reconnaissance run.

        Existing tasks keep their original run association. The runtime calls
        this at run start/end so recursive tasks created by the EventBus retain
        run provenance without adding run_id to the core Task contract.
        """

        self._run_id = run_id

    async def put(self, task: Task) -> bool:
        """Insert unless an active task with the same dedupe key exists."""
        try:
            async with self._database.transaction() as session:
                session.add(
                    TaskRecord(
                        run_id=self._run_id,
                        **_task_values(task),
                    )
                )
        except IntegrityError:
            duplicate = await self.active_by_dedupe_key(task.dedupe_key)
            if duplicate is not None:
                return False
            raise

        return True

    async def get(self, task_id: str) -> Task | None:
        async with self._database.session() as session:
            record = await session.get(TaskRecord, task_id)
            return _task_from_record(record) if record is not None else None

    async def save(self, task: Task) -> None:
        try:
            async with self._database.transaction(immediate=True) as session:
                record = await session.get(TaskRecord, task.task_id)
                if record is None:
                    raise KeyError(f"unknown task_id: {task.task_id}")

                values = _task_values(task)
                for key, value in values.items():
                    setattr(record, key, value)
        except IntegrityError as exc:
            duplicate = await self.active_by_dedupe_key(task.dedupe_key)
            if duplicate is not None and duplicate.task_id != task.task_id:
                raise ValueError(
                    "active task already exists for dedupe key: "
                    f"{task.dedupe_key}"
                ) from exc
            raise

    async def ready(
        self,
        *,
        now: datetime,
        limit: int | None = None,
    ) -> list[Task]:
        _require_aware(now, name="now")

        statement: Select[tuple[TaskRecord]] = (
            select(TaskRecord)
            .where(
                TaskRecord.status.in_(
                    (
                        TaskStatus.PENDING.value,
                        TaskStatus.DEFERRED.value,
                    )
                ),
                TaskRecord.available_at <= now,
            )
            .order_by(
                TaskRecord.priority.desc(),
                TaskRecord.available_at,
                TaskRecord.created_at,
                TaskRecord.task_id,
            )
        )

        if limit is not None:
            statement = statement.limit(limit)

        async with self._database.session() as session:
            rows = list((await session.scalars(statement)).all())
            return [_task_from_record(row) for row in rows]

    async def active_by_dedupe_key(
        self,
        dedupe_key: str,
    ) -> Task | None:
        active_statuses = tuple(
            status.value
            for status in TaskStatus
            if status not in TERMINAL_TASK_STATUSES
        )

        async with self._database.session() as session:
            record = await session.scalar(
                select(TaskRecord).where(
                    TaskRecord.dedupe_key == dedupe_key,
                    TaskRecord.status.in_(active_statuses),
                )
            )
            return _task_from_record(record) if record is not None else None

    async def all(self) -> list[Task]:
        async with self._database.session() as session:
            rows = list(
                (
                    await session.scalars(
                        select(TaskRecord).order_by(
                            TaskRecord.created_at,
                            TaskRecord.task_id,
                        )
                    )
                ).all()
            )
            return [_task_from_record(row) for row in rows]


class SQLiteBudgetStore:
    """Persistent atomic implementation of core.budgets.BudgetStore."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def try_reserve(
        self,
        *,
        reservation: BudgetReservation,
        checks: tuple[BudgetCheck, ...],
    ) -> tuple[bool, tuple[BudgetViolation, ...]]:
        async with self._database.transaction(immediate=True) as session:
            if await session.get(
                BudgetReservationRecord,
                reservation.reservation_id,
            ) is not None:
                raise ValueError(
                    "budget reservation already exists: "
                    f"{reservation.reservation_id}"
                )

            usages: dict[
                tuple[str, BudgetClass, BudgetMetric],
                BudgetUsageRecord,
            ] = {}
            violations: list[BudgetViolation] = []

            for check in checks:
                key = (
                    check.bucket_key,
                    check.budget_class,
                    check.metric,
                )
                usage = await self._get_or_create_usage(
                    session,
                    bucket_key=check.bucket_key,
                    budget_class=check.budget_class,
                    metric=check.metric,
                )
                usages[key] = usage

                if (
                    usage.committed
                    + usage.reserved
                    + check.requested
                    > check.effective_limit + 1e-9
                ):
                    violations.append(
                        BudgetViolation(
                            bucket_key=check.bucket_key,
                            metric=check.metric,
                            budget_class=check.budget_class,
                            committed=usage.committed,
                            reserved=usage.reserved,
                            requested=check.requested,
                            configured_limit=check.configured_limit,
                            effective_limit=check.effective_limit,
                        )
                    )

            if violations:
                return False, tuple(violations)

            session.add(
                BudgetReservationRecord(
                    reservation_id=reservation.reservation_id,
                    task_id=reservation.task_id,
                    state=reservation.state.value,
                    created_at=reservation.created_at,
                    expires_at=reservation.expires_at,
                )
            )
            # No ORM relationship is intentionally defined between the thin
            # storage records, so establish the FK parent before inserting
            # reservation items. SQLite foreign_keys=ON then remains strict.
            await session.flush()

            for item in reservation.items:
                session.add(
                    BudgetReservationItemRecord(
                        reservation_id=reservation.reservation_id,
                        bucket_key=item.bucket_key,
                        metric=item.metric.value,
                        budget_class=item.budget_class.value,
                        amount=item.amount,
                    )
                )

                usage = usages[
                    (
                        item.bucket_key,
                        item.budget_class,
                        item.metric,
                    )
                ]
                usage.reserved += item.amount
                usage.updated_at = utc_now()

            return True, ()

    async def commit(self, reservation_id: str) -> BudgetReservation:
        return await self._finalize(
            reservation_id,
            state=ReservationState.COMMITTED,
            commit_cumulative=True,
        )

    async def release(self, reservation_id: str) -> BudgetReservation:
        return await self._finalize(
            reservation_id,
            state=ReservationState.RELEASED,
            commit_cumulative=False,
        )

    async def renew(
        self,
        reservation_id: str,
        *,
        expires_at: datetime,
    ) -> BudgetReservation:
        _require_aware(expires_at, name="expires_at")
        if expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")

        async with self._database.transaction(immediate=True) as session:
            record = await self._require_active_reservation(
                session,
                reservation_id,
            )
            record.expires_at = expires_at
            return await self._reservation_from_record(session, record)

    async def reap_expired(
        self,
        *,
        now: datetime,
    ) -> list[BudgetReservation]:
        _require_aware(now, name="now")

        async with self._database.transaction(immediate=True) as session:
            records = list(
                (
                    await session.scalars(
                        select(BudgetReservationRecord).where(
                            BudgetReservationRecord.state
                            == ReservationState.ACTIVE.value,
                            BudgetReservationRecord.expires_at <= now,
                        )
                    )
                ).all()
            )

            expired: list[BudgetReservation] = []
            for record in records:
                items = await self._budget_items(
                    session,
                    record.reservation_id,
                )
                await self._release_budget_usage(
                    session,
                    items,
                    commit_cumulative=False,
                )
                record.state = ReservationState.EXPIRED.value
                expired.append(
                    _budget_reservation_from_rows(record, items)
                )

            return expired

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
        budget_class: BudgetClass,
    ) -> BudgetUsage:
        async with self._database.session() as session:
            record = await session.get(
                BudgetUsageRecord,
                (bucket_key, budget_class.value, metric.value),
            )
            return BudgetUsage(
                bucket_key=bucket_key,
                metric=metric,
                budget_class=budget_class,
                committed=record.committed if record is not None else 0.0,
                reserved=record.reserved if record is not None else 0.0,
            )

    async def get_reservation(
        self,
        reservation_id: str,
    ) -> BudgetReservation | None:
        async with self._database.session() as session:
            record = await session.get(
                BudgetReservationRecord,
                reservation_id,
            )
            if record is None:
                return None
            return await self._reservation_from_record(session, record)

    async def _finalize(
        self,
        reservation_id: str,
        *,
        state: ReservationState,
        commit_cumulative: bool,
    ) -> BudgetReservation:
        async with self._database.transaction(immediate=True) as session:
            record = await self._require_active_reservation(
                session,
                reservation_id,
            )
            items = await self._budget_items(session, reservation_id)

            await self._release_budget_usage(
                session,
                items,
                commit_cumulative=commit_cumulative,
            )

            record.state = state.value
            return _budget_reservation_from_rows(record, items)

    async def _release_budget_usage(
        self,
        session: AsyncSession,
        items: list[BudgetReservationItemRecord],
        *,
        commit_cumulative: bool,
    ) -> None:
        for item in items:
            if item.budget_class is None:
                raise RuntimeError(
                    "budget reservation item has no budget_class"
                )

            budget_class = BudgetClass(item.budget_class)
            metric = BudgetMetric(item.metric)

            usage = await session.get(
                BudgetUsageRecord,
                (item.bucket_key, budget_class.value, metric.value),
            )
            if usage is None:
                raise RuntimeError(
                    "missing budget usage row for reservation item"
                )

            usage.reserved -= item.amount
            if usage.reserved < -1e-9:
                raise RuntimeError(
                    "budget reserved usage underflow for "
                    f"{item.bucket_key}/{budget_class.value}/{metric.value}"
                )
            if usage.reserved < 0.0:
                usage.reserved = 0.0

            if commit_cumulative and not metric.is_capacity:
                usage.committed += item.amount

            usage.updated_at = utc_now()

    @staticmethod
    async def _get_or_create_usage(
        session: AsyncSession,
        *,
        bucket_key: str,
        budget_class: BudgetClass,
        metric: BudgetMetric,
    ) -> BudgetUsageRecord:
        key = (bucket_key, budget_class.value, metric.value)
        record = await session.get(BudgetUsageRecord, key)
        if record is not None:
            return record

        record = BudgetUsageRecord(
            bucket_key=bucket_key,
            budget_class=budget_class.value,
            metric=metric.value,
            committed=0.0,
            reserved=0.0,
            updated_at=utc_now(),
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def _require_active_reservation(
        session: AsyncSession,
        reservation_id: str,
    ) -> BudgetReservationRecord:
        record = await session.get(
            BudgetReservationRecord,
            reservation_id,
        )
        if record is None:
            raise KeyError(
                f"unknown budget reservation: {reservation_id}"
            )
        if record.state != ReservationState.ACTIVE.value:
            raise ValueError(
                f"budget reservation {reservation_id} is not ACTIVE"
            )
        return record

    @staticmethod
    async def _budget_items(
        session: AsyncSession,
        reservation_id: str,
    ) -> list[BudgetReservationItemRecord]:
        return list(
            (
                await session.scalars(
                    select(BudgetReservationItemRecord)
                    .where(
                        BudgetReservationItemRecord.reservation_id
                        == reservation_id
                    )
                    .order_by(
                        BudgetReservationItemRecord.bucket_key,
                        BudgetReservationItemRecord.metric,
                    )
                )
            ).all()
        )

    async def _reservation_from_record(
        self,
        session: AsyncSession,
        record: BudgetReservationRecord,
    ) -> BudgetReservation:
        items = await self._budget_items(
            session,
            record.reservation_id,
        )
        return _budget_reservation_from_rows(record, items)


class SQLiteReviewCaseStore:
    """Durable implementation of policy.review_gate.ReviewCaseStore."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def open_or_get(
        self,
        *,
        task: Task,
        signals: tuple[ReviewSignal, ...],
    ) -> ReviewCase:
        if not signals:
            raise ValueError(
                "cannot open review case without triggering signals"
            )

        unique_signals = tuple(
            {
                signal.stable_fingerprint: signal
                for signal in signals
            }.values()
        )
        fingerprints = tuple(
            sorted(
                signal.stable_fingerprint
                for signal in unique_signals
            )
        )
        dedupe_key = _review_dedupe_key(
            task.task_id,
            fingerprints,
        )

        try:
            async with self._database.transaction(immediate=True) as session:
                existing = await session.scalar(
                    select(ReviewCaseRecord).where(
                        ReviewCaseRecord.dedupe_key == dedupe_key,
                        ReviewCaseRecord.state
                        == ReviewCaseState.OPEN.value,
                    )
                )
                if existing is not None:
                    return await self._review_case_from_record(
                        session,
                        existing,
                    )

                domain_case = ReviewCase(
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    input_event_id=task.input_event_id,
                    signal_fingerprints=fingerprints,
                    categories=tuple(
                        sorted(
                            {signal.category for signal in unique_signals},
                            key=lambda category: category.value,
                        )
                    ),
                    summaries=tuple(
                        dict.fromkeys(
                            signal.summary for signal in unique_signals
                        )
                    ),
                )

                session.add(
                    ReviewCaseRecord(
                        case_id=domain_case.case_id,
                        task_id=task.task_id,
                        worker=task.worker,
                        action=task.action,
                        input_event_id=task.input_event_id,
                        state=domain_case.state.value,
                        dedupe_key=dedupe_key,
                        opened_at=domain_case.opened_at,
                    )
                )

                for signal in unique_signals:
                    session.add(
                        ReviewSignalRecord(
                            case_id=domain_case.case_id,
                            category=signal.category.value,
                            severity=int(signal.severity),
                            confidence=signal.confidence,
                            summary=signal.summary,
                            source_event_id=signal.source_event_id,
                            evidence_fingerprint=signal.stable_fingerprint,
                            tags_json=sorted(signal.tags),
                        )
                    )

                return domain_case
        except IntegrityError:
            # Cross-session race against the partial unique open-case index.
            async with self._database.session() as session:
                existing = await session.scalar(
                    select(ReviewCaseRecord).where(
                        ReviewCaseRecord.dedupe_key == dedupe_key,
                        ReviewCaseRecord.state
                        == ReviewCaseState.OPEN.value,
                    )
                )
                if existing is None:
                    raise
                return await self._review_case_from_record(
                    session,
                    existing,
                )

    async def get(self, case_id: str) -> ReviewCase | None:
        async with self._database.session() as session:
            record = await session.get(ReviewCaseRecord, case_id)
            if record is None:
                return None
            return await self._review_case_from_record(session, record)

    async def open_cases(self) -> list[ReviewCase]:
        async with self._database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(ReviewCaseRecord)
                        .where(
                            ReviewCaseRecord.state
                            == ReviewCaseState.OPEN.value
                        )
                        .order_by(
                            ReviewCaseRecord.opened_at,
                            ReviewCaseRecord.case_id,
                        )
                    )
                ).all()
            )
            return [
                await self._review_case_from_record(session, record)
                for record in records
            ]

    async def resolve(
        self,
        case_id: str,
        *,
        state: ReviewCaseState,
        reason: str | None = None,
    ) -> ReviewCase:
        if state is ReviewCaseState.OPEN:
            raise ValueError("resolve() requires a non-OPEN state")

        async with self._database.transaction(immediate=True) as session:
            record = await session.get(ReviewCaseRecord, case_id)
            if record is None:
                raise KeyError(f"unknown review case: {case_id}")
            if record.state != ReviewCaseState.OPEN.value:
                raise ValueError(
                    f"review case {case_id} is already resolved"
                )

            record.state = state.value
            record.resolved_at = utc_now()
            record.resolution_reason = (
                reason.strip() if reason is not None else None
            ) or None

            return await self._review_case_from_record(session, record)

    @staticmethod
    async def _review_case_from_record(
        session: AsyncSession,
        record: ReviewCaseRecord,
    ) -> ReviewCase:
        signals = list(
            (
                await session.scalars(
                    select(ReviewSignalRecord)
                    .where(
                        ReviewSignalRecord.case_id == record.case_id
                    )
                    .order_by(
                        ReviewSignalRecord.category,
                        ReviewSignalRecord.signal_id,
                    )
                )
            ).all()
        )

        fingerprints = tuple(
            sorted(signal.evidence_fingerprint for signal in signals)
        )
        categories = tuple(
            sorted(
                {
                    ReviewCategory(signal.category)
                    for signal in signals
                },
                key=lambda category: category.value,
            )
        )
        summaries = tuple(
            dict.fromkeys(signal.summary for signal in signals)
        )

        return ReviewCase(
            case_id=record.case_id,
            task_id=record.task_id,
            worker=record.worker,
            action=record.action,
            input_event_id=record.input_event_id,
            signal_fingerprints=fingerprints,
            categories=categories,
            summaries=summaries,
            state=ReviewCaseState(record.state),
            opened_at=record.opened_at,
            resolved_at=record.resolved_at,
            resolution_reason=record.resolution_reason,
        )


class SQLiteRateLimitStore:
    """Persistent shared token-bucket/concurrency implementation."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def try_acquire(
        self,
        *,
        task_id: str,
        checks: tuple[RateBucketCheck, ...],
        lease_for: timedelta,
        now: datetime,
    ) -> RateLimitDecision:
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")
        _require_aware(now, name="now")

        async with self._database.transaction(immediate=True) as session:
            projected: dict[
                tuple[str, str],
                tuple[RateBucketRecord, float, int],
            ] = {}
            violations: list[RateLimitViolation] = []

            for check in checks:
                key = (check.rule_id, check.bucket_key)
                record = await session.get(RateBucketRecord, key)

                if record is None:
                    tokens = check.burst or 0.0
                    active = 0
                    last_refill = now
                    record = RateBucketRecord(
                        rule_id=check.rule_id,
                        bucket_key=check.bucket_key,
                        tokens=tokens,
                        last_refill_at=last_refill,
                        active_concurrency=active,
                    )
                else:
                    tokens = record.tokens
                    active = record.active_concurrency
                    last_refill = record.last_refill_at

                    if (
                        check.requests_per_second is not None
                        and check.burst is not None
                    ):
                        elapsed = max(
                            (now - last_refill).total_seconds(),
                            0.0,
                        )
                        tokens = min(
                            check.burst,
                            tokens
                            + elapsed * check.requests_per_second,
                        )
                        last_refill = now

                token_retry = 0.0
                concurrency_retry = 0.0

                if (
                    check.requests > 0.0
                    and check.requests_per_second is not None
                    and check.burst is not None
                ):
                    if check.requests > check.burst + 1e-9:
                        raise ValueError(
                            "single rate-limit acquisition exceeds burst; "
                            "split demand into smaller acquisitions"
                        )
                    if tokens + 1e-9 < check.requests:
                        token_retry = (
                            check.requests - tokens
                        ) / check.requests_per_second

                if (
                    check.concurrency > 0
                    and check.max_concurrency is not None
                    and active + check.concurrency
                    > check.max_concurrency
                ):
                    concurrency_retry = (
                        await self._earliest_concurrency_release(
                            session,
                            rule_id=check.rule_id,
                            bucket_key=check.bucket_key,
                            now=now,
                        )
                    )

                retry_after = max(
                    token_retry,
                    concurrency_retry,
                )

                if retry_after > 0.0:
                    violations.append(
                        RateLimitViolation(
                            rule_id=check.rule_id,
                            bucket_key=check.bucket_key,
                            kind=(
                                "TOKENS_AND_CONCURRENCY"
                                if token_retry > 0.0
                                and concurrency_retry > 0.0
                                else "TOKENS"
                                if token_retry > 0.0
                                else "CONCURRENCY"
                            ),
                            reason=(
                                "shared rate/concurrency capacity is "
                                "temporarily unavailable"
                            ),
                            retry_after_seconds=retry_after,
                        )
                    )
                    continue

                if (
                    check.requests > 0.0
                    and check.requests_per_second is not None
                ):
                    tokens -= check.requests

                if (
                    check.concurrency > 0
                    and check.max_concurrency is not None
                ):
                    active += check.concurrency

                projected[key] = (
                    record,
                    tokens,
                    active,
                )

            if violations:
                return RateLimitDecision(
                    outcome=RateLimitOutcome.DEFER,
                    task_id=task_id,
                    violations=tuple(violations),
                    checked_buckets=checks,
                    reason=(
                        "shared rate-limit capacity is temporarily exhausted"
                    ),
                    retry_after_seconds=max(
                        violation.retry_after_seconds
                        for violation in violations
                    ),
                )

            for record, tokens, active in projected.values():
                record.tokens = tokens
                record.active_concurrency = active
                record.last_refill_at = now
                if await session.get(
                    RateBucketRecord,
                    (record.rule_id, record.bucket_key),
                ) is None:
                    session.add(record)

            lease_items = tuple(
                RateLeaseItem(
                    rule_id=check.rule_id,
                    bucket_key=check.bucket_key,
                    concurrency=check.concurrency,
                )
                for check in checks
                if (
                    check.max_concurrency is not None
                    and check.concurrency > 0
                )
            )

            lease: RateLimitLease | None = None
            if lease_items:
                lease = RateLimitLease(
                    task_id=task_id,
                    items=lease_items,
                    created_at=now,
                    expires_at=now + lease_for,
                )
                session.add(
                    RateLeaseRecord(
                        lease_id=lease.lease_id,
                        task_id=task_id,
                        state=lease.state.value,
                        created_at=lease.created_at,
                        expires_at=lease.expires_at,
                    )
                )
                # Persist the lease parent first for the same reason as budget
                # reservations: strict SQLite FKs + deliberately relationship-
                # free storage records require an explicit ordering barrier.
                await session.flush()
                for item in lease.items:
                    session.add(
                        RateLeaseItemRecord(
                            lease_id=lease.lease_id,
                            rule_id=item.rule_id,
                            bucket_key=item.bucket_key,
                            concurrency=item.concurrency,
                        )
                    )

            return RateLimitDecision(
                outcome=RateLimitOutcome.ALLOW,
                task_id=task_id,
                lease=lease,
                checked_buckets=checks,
            )

    async def release(self, lease_id: str) -> RateLimitLease:
        async with self._database.transaction(immediate=True) as session:
            record = await self._require_active_lease(session, lease_id)
            items = await self._rate_items(session, lease_id)
            await self._release_rate_items(session, items)
            record.state = RateLeaseState.RELEASED.value
            return _rate_lease_from_rows(record, items)

    async def renew(
        self,
        lease_id: str,
        *,
        expires_at: datetime,
    ) -> RateLimitLease:
        _require_aware(expires_at, name="expires_at")
        if expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")

        async with self._database.transaction(immediate=True) as session:
            record = await self._require_active_lease(session, lease_id)
            record.expires_at = expires_at
            items = await self._rate_items(session, lease_id)
            return _rate_lease_from_rows(record, items)

    async def reap_expired(
        self,
        *,
        now: datetime,
    ) -> list[RateLimitLease]:
        _require_aware(now, name="now")

        async with self._database.transaction(immediate=True) as session:
            records = list(
                (
                    await session.scalars(
                        select(RateLeaseRecord).where(
                            RateLeaseRecord.state
                            == RateLeaseState.ACTIVE.value,
                            RateLeaseRecord.expires_at <= now,
                        )
                    )
                ).all()
            )

            result: list[RateLimitLease] = []
            for record in records:
                items = await self._rate_items(
                    session,
                    record.lease_id,
                )
                await self._release_rate_items(session, items)
                record.state = RateLeaseState.EXPIRED.value
                result.append(_rate_lease_from_rows(record, items))

            return result

    async def get_lease(
        self,
        lease_id: str,
    ) -> RateLimitLease | None:
        async with self._database.session() as session:
            record = await session.get(RateLeaseRecord, lease_id)
            if record is None:
                return None
            items = await self._rate_items(session, lease_id)
            return _rate_lease_from_rows(record, items)

    async def bucket_state(
        self,
        *,
        rule_id: str,
        bucket_key: str,
    ) -> RateBucketState | None:
        async with self._database.session() as session:
            record = await session.get(
                RateBucketRecord,
                (rule_id, bucket_key),
            )
            if record is None:
                return None
            return RateBucketState(
                rule_id=rule_id,
                bucket_key=bucket_key,
                tokens=record.tokens,
                last_refill_at=record.last_refill_at,
                active_concurrency=record.active_concurrency,
            )

    async def _earliest_concurrency_release(
        self,
        session: AsyncSession,
        *,
        rule_id: str,
        bucket_key: str,
        now: datetime,
    ) -> float:
        earliest = await session.scalar(
            select(RateLeaseRecord.expires_at)
            .join(
                RateLeaseItemRecord,
                RateLeaseItemRecord.lease_id
                == RateLeaseRecord.lease_id,
            )
            .where(
                RateLeaseRecord.state == RateLeaseState.ACTIVE.value,
                RateLeaseItemRecord.rule_id == rule_id,
                RateLeaseItemRecord.bucket_key == bucket_key,
                RateLeaseItemRecord.concurrency > 0,
            )
            .order_by(RateLeaseRecord.expires_at)
            .limit(1)
        )

        if earliest is None:
            return 0.001

        return max(
            (earliest - now).total_seconds(),
            0.001,
        )

    @staticmethod
    async def _require_active_lease(
        session: AsyncSession,
        lease_id: str,
    ) -> RateLeaseRecord:
        record = await session.get(RateLeaseRecord, lease_id)
        if record is None:
            raise KeyError(f"unknown rate-limit lease: {lease_id}")
        if record.state != RateLeaseState.ACTIVE.value:
            raise ValueError(
                f"rate-limit lease {lease_id} is not ACTIVE"
            )
        return record

    @staticmethod
    async def _rate_items(
        session: AsyncSession,
        lease_id: str,
    ) -> list[RateLeaseItemRecord]:
        return list(
            (
                await session.scalars(
                    select(RateLeaseItemRecord)
                    .where(
                        RateLeaseItemRecord.lease_id == lease_id
                    )
                    .order_by(
                        RateLeaseItemRecord.rule_id,
                        RateLeaseItemRecord.bucket_key,
                    )
                )
            ).all()
        )

    @staticmethod
    async def _release_rate_items(
        session: AsyncSession,
        items: list[RateLeaseItemRecord],
    ) -> None:
        for item in items:
            if item.concurrency == 0:
                continue
            bucket = await session.get(
                RateBucketRecord,
                (item.rule_id, item.bucket_key),
            )
            if bucket is None:
                raise RuntimeError(
                    "missing rate bucket while releasing lease"
                )
            bucket.active_concurrency -= item.concurrency
            if bucket.active_concurrency < 0:
                raise RuntimeError(
                    "rate-limit concurrency underflow"
                )


class DecisionRepository:
    """Append scheduler/policy decisions for `nightscout explain`."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def record_schedule(
        self,
        decision: ScheduleDecision,
        *,
        selected: bool,
    ) -> str:
        async with self._database.transaction() as session:
            record = SchedulerDecisionRecord(
                task_id=decision.task_id,
                evaluated_at=decision.evaluated_at,
                score=decision.score,
                selected=selected,
                breakdown_json=decision.breakdown.model_dump(
                    mode="json"
                ),
                signals_json=decision.signals.model_dump(
                    mode="json"
                ),
            )
            session.add(record)
            await session.flush()
            return record.decision_id

    async def record_policy(
        self,
        *,
        task_id: str,
        gate: str,
        outcome: str,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        async with self._database.transaction() as session:
            record = PolicyDecisionRecord(
                task_id=task_id,
                gate=gate.strip(),
                outcome=outcome.strip(),
                reason=(reason.strip() if reason else None),
                details_json=dict(details or {}),
            )
            session.add(record)
            await session.flush()
            return record.decision_id


class BranchRepository:
    """Minimal persistent branch lifecycle used by the runtime frontier.

    Branch rows must exist before Tasks can reference ``branch_id`` because the
    durable task schema intentionally enforces that relationship with a foreign
    key. ``ensure`` is idempotent so the EventBus can call it defensively for
    every routed event in a branch.
    """

    def __init__(self, database: Database) -> None:
        self._database = database

    async def ensure(
        self,
        branch_id: str,
        *,
        run_id: str | None,
        root_event_id: str | None,
        parent_branch_id: str | None = None,
        depth: int = 0,
    ) -> None:
        normalized = branch_id.strip()
        if not normalized:
            raise ValueError("branch_id must not be blank")
        if depth < 0:
            raise ValueError("branch depth must be >= 0")

        async with self._database.transaction(immediate=True) as session:
            record = await session.get(BranchRecord, normalized)
            if record is None:
                session.add(
                    BranchRecord(
                        branch_id=normalized,
                        run_id=run_id,
                        parent_branch_id=parent_branch_id,
                        root_event_id=root_event_id,
                        state="OPEN",
                        depth=depth,
                    )
                )
                return

            # Fill missing provenance conservatively, but never silently move a
            # branch between runs or roots once those fields are established.
            if record.run_id is None and run_id is not None:
                record.run_id = run_id
            elif run_id is not None and record.run_id not in {None, run_id}:
                raise ValueError(
                    f"branch {normalized} already belongs to run {record.run_id}"
                )

            if record.root_event_id is None and root_event_id is not None:
                record.root_event_id = root_event_id
            elif (
                root_event_id is not None
                and record.root_event_id not in {None, root_event_id}
            ):
                raise ValueError(
                    f"branch {normalized} already has root event "
                    f"{record.root_event_id}"
                )

    async def get(self, branch_id: str) -> BranchRecord | None:
        async with self._database.session() as session:
            return await session.get(BranchRecord, branch_id)


class RunRepository:
    """Minimal run lifecycle persistence used by CLI startup/shutdown."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def start(
        self,
        *,
        config_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        async with self._database.transaction() as session:
            record = ReconRunRecord(
                status="RUNNING",
                config_hash=config_hash,
                metadata_json=dict(metadata or {}),
            )
            session.add(record)
            await session.flush()
            return record.run_id

    async def finish(
        self,
        run_id: str,
        *,
        status: str = "SUCCEEDED",
    ) -> None:
        normalized = status.strip().upper()
        if not normalized or normalized == "RUNNING":
            raise ValueError(
                "finished run status must be non-empty and not RUNNING"
            )

        async with self._database.transaction(immediate=True) as session:
            record = await session.get(ReconRunRecord, run_id)
            if record is None:
                raise KeyError(f"unknown run_id: {run_id}")
            record.status = normalized
            record.finished_at = utc_now()


def _event_from_record(record: EventObservationRecord) -> Event:
    return Event(
        event_id=record.event_id,
        type=EventType(record.event_type),
        value=record.value,
        source=record.source,
        parent_event_id=record.parent_event_id,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        scope_state=ScopeState(record.scope_state),
        confidence=record.confidence,
        novelty=record.novelty,
        depth=record.depth,
        tags=set(record.tags_json),
        metadata=dict(record.metadata_json),
    )


def _task_values(task: Task) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "worker": task.worker,
        "action": task.action,
        "input_event_id": task.input_event_id,
        "branch_id": task.branch_id,
        "route_rule_id": task.route_rule_id,
        "routing_reason": task.routing_reason,
        "status": task.status.value,
        "priority": task.priority,
        "attempts": task.attempts,
        "max_attempts": task.max_attempts,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "available_at": task.available_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "lease_expires_at": task.lease_expires_at,
        "last_error": task.last_error,
        "dedupe_key": task.dedupe_key,
    }


def _task_from_record(record: TaskRecord) -> Task:
    return Task(
        task_id=record.task_id,
        worker=record.worker,
        action=record.action,
        input_event_id=record.input_event_id,
        branch_id=record.branch_id,
        route_rule_id=record.route_rule_id,
        routing_reason=record.routing_reason,
        status=TaskStatus(record.status),
        priority=record.priority,
        attempts=record.attempts,
        max_attempts=record.max_attempts,
        created_at=record.created_at,
        updated_at=record.updated_at,
        available_at=record.available_at,
        started_at=record.started_at,
        finished_at=record.finished_at,
        lease_expires_at=record.lease_expires_at,
        last_error=record.last_error,
    )


def _merge_scope_state(
    current: ScopeState,
    incoming: ScopeState,
) -> ScopeState:
    """Conservatively merge independent scope classifications."""
    precedence = {
        ScopeState.UNKNOWN: 0,
        ScopeState.IN_SCOPE: 1,
        ScopeState.PASSIVE_ONLY: 2,
        ScopeState.AMBIGUOUS: 3,
        ScopeState.OUT_OF_SCOPE: 4,
    }
    return (
        incoming
        if precedence[incoming] > precedence[current]
        else current
    )


def _budget_reservation_from_rows(
    record: BudgetReservationRecord,
    items: list[BudgetReservationItemRecord],
) -> BudgetReservation:
    return BudgetReservation(
        reservation_id=record.reservation_id,
        task_id=record.task_id,
        items=tuple(
            BudgetReservationItem(
                bucket_key=item.bucket_key,
                metric=BudgetMetric(item.metric),
                budget_class=BudgetClass(item.budget_class),
                amount=item.amount,
            )
            for item in items
            if item.budget_class is not None
        ),
        created_at=record.created_at,
        expires_at=record.expires_at,
        state=ReservationState(record.state),
    )


def _rate_lease_from_rows(
    record: RateLeaseRecord,
    items: list[RateLeaseItemRecord],
) -> RateLimitLease:
    return RateLimitLease(
        lease_id=record.lease_id,
        task_id=record.task_id,
        items=tuple(
            RateLeaseItem(
                rule_id=item.rule_id,
                bucket_key=item.bucket_key,
                concurrency=item.concurrency,
            )
            for item in items
        ),
        created_at=record.created_at,
        expires_at=record.expires_at,
        state=RateLeaseState(record.state),
    )


def _review_dedupe_key(
    task_id: str,
    fingerprints: tuple[str, ...],
) -> str:
    material = "|".join((task_id, *fingerprints))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
