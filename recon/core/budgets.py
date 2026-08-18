"""Budget enforcement for Night Scout.

Budgets bound recursive reconnaissance without taking over policy or rate-limit
responsibilities.

The budget layer answers:

    "If this task is otherwise authorized, do we still have enough allocated
    recon budget to evaluate it?"

The future lifecycle order is expected to be:

    scope -> policy -> budget.reserve() -> review -> queue.claim() -> worker

Budget reservations are atomic. This prevents concurrent lifecycle loops from
all observing the same remaining capacity and collectively overspending it.

Budget scopes supported by this module:

    global
    per worker
    per branch
    per resource key (for example host:api.example.com or ip:203.0.113.10)

Time-based request pacing belongs to policy/rate_limit.py. This module tracks
cumulative/capacity limits rather than requests-per-second.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.queue import Task


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_reservation_id() -> str:
    """Create a globally unique budget reservation identifier."""
    return f"bgt_{uuid4().hex}"


class BudgetMetric(StrEnum):
    """Metrics that can be bounded by a BudgetProfile."""

    TASKS = "TASKS"
    COST = "COST"
    REQUESTS = "REQUESTS"
    CANDIDATES = "CANDIDATES"
    RUNTIME_SECONDS = "RUNTIME_SECONDS"

    # Capacity metric: reserved while work is active and released afterwards.
    CONCURRENT_TASKS = "CONCURRENT_TASKS"

    @property
    def is_capacity(self) -> bool:
        """Return whether usage should be released rather than committed."""
        return self is BudgetMetric.CONCURRENT_TASKS


class ReservationState(StrEnum):
    """Lifecycle of a budget reservation."""

    ACTIVE = "ACTIVE"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class BudgetCaps(BaseModel):
    """Optional limits for one budget scope.

    None means "no limit configured for this metric".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tasks: float | None = Field(default=None, ge=0.0)
    cost: float | None = Field(default=None, ge=0.0)
    requests: float | None = Field(default=None, ge=0.0)
    candidates: float | None = Field(default=None, ge=0.0)
    runtime_seconds: float | None = Field(default=None, ge=0.0)
    concurrent_tasks: float | None = Field(default=None, ge=0.0)

    def as_metric_limits(self) -> dict[BudgetMetric, float]:
        """Return only configured limits keyed by BudgetMetric."""
        values: dict[BudgetMetric, float] = {}

        mapping = {
            BudgetMetric.TASKS: self.tasks,
            BudgetMetric.COST: self.cost,
            BudgetMetric.REQUESTS: self.requests,
            BudgetMetric.CANDIDATES: self.candidates,
            BudgetMetric.RUNTIME_SECONDS: self.runtime_seconds,
            BudgetMetric.CONCURRENT_TASKS: self.concurrent_tasks,
        }

        for metric, value in mapping.items():
            if value is not None:
                values[metric] = value

        return values


class BudgetProfile(BaseModel):
    """Budget configuration shared by a Night Scout target/run.

    Each branch and resource key receives its own bucket using the configured
    branch/resource caps. Worker caps are keyed by worker name.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    global_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    branch_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    resource_limits: BudgetCaps = Field(default_factory=BudgetCaps)

    worker_limits: dict[str, BudgetCaps] = Field(default_factory=dict)

    max_branch_depth: int | None = Field(default=None, ge=0)

    @field_validator("worker_limits")
    @classmethod
    def normalize_worker_names(
        cls,
        value: dict[str, BudgetCaps],
    ) -> dict[str, BudgetCaps]:
        """Normalize worker names used as budget bucket selectors."""
        normalized: dict[str, BudgetCaps] = {}

        for worker, caps in value.items():
            name = worker.strip()
            if not name:
                raise ValueError("worker budget names must not be blank")
            if name in normalized:
                raise ValueError(f"duplicate worker budget after normalization: {name}")
            normalized[name] = caps

        return normalized


class BudgetDemand(BaseModel):
    """Estimated budget demand for one task execution.

    TASKS and CONCURRENT_TASKS default to one because a normal worker
    invocation represents one scheduled task occupying one execution slot.

    Other values are estimates supplied by lifecycle/worker metadata.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tasks: float = Field(default=1.0, ge=0.0)
    cost: float = Field(default=0.0, ge=0.0)
    requests: float = Field(default=0.0, ge=0.0)
    candidates: float = Field(default=0.0, ge=0.0)
    runtime_seconds: float = Field(default=0.0, ge=0.0)
    concurrent_tasks: float = Field(default=1.0, ge=0.0)

    def as_metric_amounts(self) -> dict[BudgetMetric, float]:
        """Return non-zero demand values keyed by metric."""
        mapping = {
            BudgetMetric.TASKS: self.tasks,
            BudgetMetric.COST: self.cost,
            BudgetMetric.REQUESTS: self.requests,
            BudgetMetric.CANDIDATES: self.candidates,
            BudgetMetric.RUNTIME_SECONDS: self.runtime_seconds,
            BudgetMetric.CONCURRENT_TASKS: self.concurrent_tasks,
        }
        return {
            metric: amount
            for metric, amount in mapping.items()
            if amount > 0.0
        }


class BudgetContext(BaseModel):
    """Runtime context needed to choose budget buckets.

    resource_keys are intentionally generic. Future lifecycle/storage code may
    supply values such as:

        host:api.example.com
        ip:203.0.113.10

    This keeps budgets.py independent from Event parsing and DNS/HTTP models.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    branch_depth: int = Field(default=0, ge=0)
    resource_keys: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("resource_keys")
    @classmethod
    def normalize_resource_keys(
        cls,
        value: frozenset[str],
    ) -> frozenset[str]:
        """Normalize resource budget bucket keys."""
        normalized: set[str] = set()

        for resource_key in value:
            key = resource_key.strip().lower()
            if key:
                normalized.add(key)

        return frozenset(normalized)


class BudgetCheck(BaseModel):
    """One atomic limit check performed by the BudgetStore."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    requested: float = Field(gt=0.0)
    limit: float = Field(ge=0.0)


class BudgetReservationItem(BaseModel):
    """Reserved amount for one bucket/metric pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    amount: float = Field(gt=0.0)


class BudgetReservation(BaseModel):
    """Atomic reservation held while a task is preparing/running."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: str = Field(default_factory=new_reservation_id)
    task_id: str

    items: tuple[BudgetReservationItem, ...]

    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime

    state: ReservationState = ReservationState.ACTIVE

    @field_validator("created_at", "expires_at")
    @classmethod
    def timestamps_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Require timezone-aware reservation timestamps."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reservation timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def expiry_must_follow_creation(self) -> BudgetReservation:
        """Require a positive reservation lease window."""
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self


class BudgetViolation(BaseModel):
    """Explainable reason why a reservation could not be created."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric

    committed: float = Field(ge=0.0)
    reserved: float = Field(ge=0.0)
    requested: float = Field(gt=0.0)
    limit: float = Field(ge=0.0)

    @property
    def projected(self) -> float:
        """Return usage if the denied reservation had been accepted."""
        return self.committed + self.reserved + self.requested


class BudgetUsage(BaseModel):
    """Current usage of one budget bucket and metric."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric

    committed: float = Field(default=0.0, ge=0.0)
    reserved: float = Field(default=0.0, ge=0.0)

    @property
    def total(self) -> float:
        """Return committed plus currently reserved usage."""
        return self.committed + self.reserved


class BudgetDecision(BaseModel):
    """Result of attempting to reserve budget for a task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    task_id: str

    reservation: BudgetReservation | None = None
    violations: tuple[BudgetViolation, ...] = ()
    checked_limits: tuple[BudgetCheck, ...] = ()

    reason: str | None = None


class BudgetStore(Protocol):
    """Atomic persistence contract used by BudgetManager.

    A future SQLiteBudgetStore must implement try_reserve transactionally so
    multiple lifecycle loops/processes cannot overspend the same bucket.
    """

    async def try_reserve(
        self,
        *,
        reservation: BudgetReservation,
        checks: tuple[BudgetCheck, ...],
    ) -> tuple[bool, tuple[BudgetViolation, ...]]:
        """Atomically verify all checks and create the reservation if allowed."""
        ...

    async def commit(self, reservation_id: str) -> BudgetReservation:
        """Commit cumulative metrics and release capacity metrics."""
        ...

    async def release(self, reservation_id: str) -> BudgetReservation:
        """Release an active reservation without consuming cumulative budget."""
        ...

    async def renew(
        self,
        reservation_id: str,
        *,
        expires_at: datetime,
    ) -> BudgetReservation:
        """Extend an active reservation lease."""
        ...

    async def reap_expired(self, *, now: datetime) -> list[BudgetReservation]:
        """Expire stale reservations and release their reserved capacity."""
        ...

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
    ) -> BudgetUsage:
        """Return committed/reserved usage for one bucket and metric."""
        ...

    async def get_reservation(
        self,
        reservation_id: str,
    ) -> BudgetReservation | None:
        """Return a reservation by identifier."""
        ...


class InMemoryBudgetStore:
    """Concurrency-safe development implementation of BudgetStore."""

    def __init__(self) -> None:
        self._committed: dict[tuple[str, BudgetMetric], float] = {}
        self._reserved: dict[tuple[str, BudgetMetric], float] = {}
        self._reservations: dict[str, BudgetReservation] = {}
        self._lock = asyncio.Lock()

    async def try_reserve(
        self,
        *,
        reservation: BudgetReservation,
        checks: tuple[BudgetCheck, ...],
    ) -> tuple[bool, tuple[BudgetViolation, ...]]:
        async with self._lock:
            if reservation.reservation_id in self._reservations:
                raise ValueError(
                    f"reservation already exists: {reservation.reservation_id}"
                )

            violations: list[BudgetViolation] = []

            for check in checks:
                key = (check.bucket_key, check.metric)
                committed = self._committed.get(key, 0.0)
                reserved = self._reserved.get(key, 0.0)

                if committed + reserved + check.requested > check.limit:
                    violations.append(
                        BudgetViolation(
                            bucket_key=check.bucket_key,
                            metric=check.metric,
                            committed=committed,
                            reserved=reserved,
                            requested=check.requested,
                            limit=check.limit,
                        )
                    )

            if violations:
                return False, tuple(violations)

            stored = reservation.model_copy(deep=True)
            self._reservations[stored.reservation_id] = stored

            for item in stored.items:
                key = (item.bucket_key, item.metric)
                self._reserved[key] = self._reserved.get(key, 0.0) + item.amount

            return True, ()

    async def commit(self, reservation_id: str) -> BudgetReservation:
        async with self._lock:
            reservation = self._require_active(reservation_id)

            for item in reservation.items:
                key = (item.bucket_key, item.metric)
                self._subtract_reserved(key, item.amount)

                if not item.metric.is_capacity:
                    self._committed[key] = (
                        self._committed.get(key, 0.0) + item.amount
                    )

            committed = reservation.model_copy(
                update={"state": ReservationState.COMMITTED}
            )
            self._reservations[reservation_id] = committed
            return committed.model_copy(deep=True)

    async def release(self, reservation_id: str) -> BudgetReservation:
        async with self._lock:
            reservation = self._require_active(reservation_id)

            for item in reservation.items:
                key = (item.bucket_key, item.metric)
                self._subtract_reserved(key, item.amount)

            released = reservation.model_copy(
                update={"state": ReservationState.RELEASED}
            )
            self._reservations[reservation_id] = released
            return released.model_copy(deep=True)

    async def renew(
        self,
        reservation_id: str,
        *,
        expires_at: datetime,
    ) -> BudgetReservation:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")

        async with self._lock:
            reservation = self._require_active(reservation_id)
            if expires_at <= utc_now():
                raise ValueError("expires_at must be in the future")

            renewed = reservation.model_copy(update={"expires_at": expires_at})
            self._reservations[reservation_id] = renewed
            return renewed.model_copy(deep=True)

    async def reap_expired(self, *, now: datetime) -> list[BudgetReservation]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")

        async with self._lock:
            expired: list[BudgetReservation] = []

            for reservation_id, reservation in list(self._reservations.items()):
                if (
                    reservation.state != ReservationState.ACTIVE
                    or reservation.expires_at > now
                ):
                    continue

                for item in reservation.items:
                    key = (item.bucket_key, item.metric)
                    self._subtract_reserved(key, item.amount)

                updated = reservation.model_copy(
                    update={"state": ReservationState.EXPIRED}
                )
                self._reservations[reservation_id] = updated
                expired.append(updated.model_copy(deep=True))

            return expired

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
    ) -> BudgetUsage:
        async with self._lock:
            key = (bucket_key, metric)
            return BudgetUsage(
                bucket_key=bucket_key,
                metric=metric,
                committed=self._committed.get(key, 0.0),
                reserved=self._reserved.get(key, 0.0),
            )

    async def get_reservation(
        self,
        reservation_id: str,
    ) -> BudgetReservation | None:
        async with self._lock:
            reservation = self._reservations.get(reservation_id)
            return (
                reservation.model_copy(deep=True)
                if reservation is not None
                else None
            )

    def _require_active(self, reservation_id: str) -> BudgetReservation:
        try:
            reservation = self._reservations[reservation_id]
        except KeyError as exc:
            raise KeyError(
                f"unknown budget reservation: {reservation_id}"
            ) from exc

        if reservation.state != ReservationState.ACTIVE:
            raise ValueError(
                f"reservation {reservation_id} is not ACTIVE "
                f"(state={reservation.state})"
            )

        return reservation

    def _subtract_reserved(
        self,
        key: tuple[str, BudgetMetric],
        amount: float,
    ) -> None:
        current = self._reserved.get(key, 0.0)
        updated = current - amount

        # Floating point tolerance protects against tiny arithmetic residue.
        if updated < -1e-9:
            raise RuntimeError(
                f"reserved budget underflow for {key}: {current} - {amount}"
            )

        if updated <= 1e-9:
            self._reserved.pop(key, None)
        else:
            self._reserved[key] = updated


class BudgetManager:
    """Compile profile limits and atomically reserve budget for tasks."""

    def __init__(
        self,
        store: BudgetStore,
        *,
        profile: BudgetProfile | None = None,
    ) -> None:
        self._store = store
        self._profile = profile or BudgetProfile()

    async def reserve(
        self,
        task: Task,
        *,
        demand: BudgetDemand | None = None,
        context: BudgetContext | None = None,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> BudgetDecision:
        """Attempt to reserve all relevant budget buckets atomically."""
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        budget_demand = demand or BudgetDemand()
        budget_context = context or BudgetContext()

        if (
            self._profile.max_branch_depth is not None
            and budget_context.branch_depth > self._profile.max_branch_depth
        ):
            return BudgetDecision(
                allowed=False,
                task_id=task.task_id,
                reason=(
                    "branch depth exceeds configured maximum: "
                    f"{budget_context.branch_depth} > "
                    f"{self._profile.max_branch_depth}"
                ),
            )

        checks = self._compile_checks(
            task=task,
            demand=budget_demand,
            context=budget_context,
        )

        # No configured caps matched this task. Nothing needs reservation.
        if not checks:
            return BudgetDecision(
                allowed=True,
                task_id=task.task_id,
                reason="no matching budget limits",
            )

        items = tuple(
            BudgetReservationItem(
                bucket_key=check.bucket_key,
                metric=check.metric,
                amount=check.requested,
            )
            for check in checks
        )

        now = utc_now()
        reservation = BudgetReservation(
            task_id=task.task_id,
            items=items,
            created_at=now,
            expires_at=now + lease_for,
        )

        allowed, violations = await self._store.try_reserve(
            reservation=reservation,
            checks=checks,
        )

        if not allowed:
            return BudgetDecision(
                allowed=False,
                task_id=task.task_id,
                violations=violations,
                checked_limits=checks,
                reason="one or more budget limits would be exceeded",
            )

        return BudgetDecision(
            allowed=True,
            task_id=task.task_id,
            reservation=reservation,
            checked_limits=checks,
        )

    async def commit(self, reservation_id: str) -> BudgetReservation:
        """Commit cumulative usage after a worker completes."""
        return await self._store.commit(reservation_id)

    async def release(self, reservation_id: str) -> BudgetReservation:
        """Release budget after a task is cancelled before consumption."""
        return await self._store.release(reservation_id)

    async def renew(
        self,
        reservation_id: str,
        *,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> BudgetReservation:
        """Extend a live reservation while its task is still active."""
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")
        return await self._store.renew(
            reservation_id,
            expires_at=utc_now() + lease_for,
        )

    async def reap_expired(self) -> list[BudgetReservation]:
        """Release reservations abandoned by crashed/stalled lifecycle work."""
        return await self._store.reap_expired(now=utc_now())

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
    ) -> BudgetUsage:
        """Expose current usage for status/explain commands."""
        return await self._store.usage(
            bucket_key=bucket_key,
            metric=metric,
        )

    def _compile_checks(
        self,
        *,
        task: Task,
        demand: BudgetDemand,
        context: BudgetContext,
    ) -> tuple[BudgetCheck, ...]:
        amounts = demand.as_metric_amounts()
        checks: list[BudgetCheck] = []

        checks.extend(
            _checks_for_caps(
                bucket_key="global",
                caps=self._profile.global_limits,
                amounts=amounts,
            )
        )

        worker_caps = self._profile.worker_limits.get(task.worker)
        if worker_caps is not None:
            checks.extend(
                _checks_for_caps(
                    bucket_key=f"worker:{task.worker}",
                    caps=worker_caps,
                    amounts=amounts,
                )
            )

        if task.branch_id is not None:
            checks.extend(
                _checks_for_caps(
                    bucket_key=f"branch:{task.branch_id}",
                    caps=self._profile.branch_limits,
                    amounts=amounts,
                )
            )

        for resource_key in sorted(context.resource_keys):
            checks.extend(
                _checks_for_caps(
                    bucket_key=f"resource:{resource_key}",
                    caps=self._profile.resource_limits,
                    amounts=amounts,
                )
            )

        return _merge_checks(checks)


def _checks_for_caps(
    *,
    bucket_key: str,
    caps: BudgetCaps,
    amounts: dict[BudgetMetric, float],
) -> list[BudgetCheck]:
    """Create checks for metrics that have both demand and configured limits."""
    limits = caps.as_metric_limits()
    checks: list[BudgetCheck] = []

    for metric, requested in amounts.items():
        limit = limits.get(metric)
        if limit is None:
            continue

        checks.append(
            BudgetCheck(
                bucket_key=bucket_key,
                metric=metric,
                requested=requested,
                limit=limit,
            )
        )

    return checks


def _merge_checks(checks: Iterable[BudgetCheck]) -> tuple[BudgetCheck, ...]:
    """Merge duplicate bucket/metric checks deterministically.

    Duplicate checks should not normally appear, but merging here keeps budget
    accounting correct if future context builders supply overlapping resource
    keys or profiles are composed programmatically.
    """
    merged: dict[tuple[str, BudgetMetric], BudgetCheck] = {}

    for check in checks:
        key = (check.bucket_key, check.metric)

        existing = merged.get(key)
        if existing is None:
            merged[key] = check
            continue

        if existing.limit != check.limit:
            raise ValueError(
                "conflicting limits for "
                f"{check.bucket_key}/{check.metric.value}: "
                f"{existing.limit} vs {check.limit}"
            )

        merged[key] = BudgetCheck(
            bucket_key=check.bucket_key,
            metric=check.metric,
            requested=existing.requested + check.requested,
            limit=check.limit,
        )

    return tuple(
        merged[key]
        for key in sorted(
            merged,
            key=lambda item: (item[0], item[1].value),
        )
    )
