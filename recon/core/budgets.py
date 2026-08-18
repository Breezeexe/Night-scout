"""Soft/hard reconnaissance budgets for Night Scout.

SOFT limits manage exploration effort. Exhaustion returns DEFER: the task stays
in the persistent frontier.

HARD cumulative limits are non-negotiable and return DENY.

HARD capacity limits (currently CONCURRENT_TASKS) are temporary and return
DEFER until capacity becomes available.

Rate-per-second policy is intentionally separate in policy/rate_limit.py.
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
    return datetime.now(timezone.utc)


def new_reservation_id() -> str:
    return f"bgt_{uuid4().hex}"


class BudgetMetric(StrEnum):
    TASKS = "TASKS"
    COST = "COST"
    REQUESTS = "REQUESTS"
    CANDIDATES = "CANDIDATES"
    RUNTIME_SECONDS = "RUNTIME_SECONDS"
    CONCURRENT_TASKS = "CONCURRENT_TASKS"

    @property
    def is_capacity(self) -> bool:
        return self is BudgetMetric.CONCURRENT_TASKS


class BudgetClass(StrEnum):
    SOFT = "SOFT"
    HARD = "HARD"


class BudgetOutcome(StrEnum):
    ALLOW = "ALLOW"
    DEFER = "DEFER"
    DENY = "DENY"


class BudgetLane(StrEnum):
    NORMAL = "NORMAL"
    EXPLORATION = "EXPLORATION"


class ReservationState(StrEnum):
    ACTIVE = "ACTIVE"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class BudgetCaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tasks: float | None = Field(default=None, ge=0.0)
    cost: float | None = Field(default=None, ge=0.0)
    requests: float | None = Field(default=None, ge=0.0)
    candidates: float | None = Field(default=None, ge=0.0)
    runtime_seconds: float | None = Field(default=None, ge=0.0)
    concurrent_tasks: float | None = Field(default=None, ge=0.0)

    def as_metric_limits(self) -> dict[BudgetMetric, float]:
        values = {
            BudgetMetric.TASKS: self.tasks,
            BudgetMetric.COST: self.cost,
            BudgetMetric.REQUESTS: self.requests,
            BudgetMetric.CANDIDATES: self.candidates,
            BudgetMetric.RUNTIME_SECONDS: self.runtime_seconds,
            BudgetMetric.CONCURRENT_TASKS: self.concurrent_tasks,
        }
        return {
            metric: value
            for metric, value in values.items()
            if value is not None
        }


class BudgetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    soft_global_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    soft_branch_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    soft_resource_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    soft_worker_limits: dict[str, BudgetCaps] = Field(default_factory=dict)

    hard_global_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    hard_branch_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    hard_resource_limits: BudgetCaps = Field(default_factory=BudgetCaps)
    hard_worker_limits: dict[str, BudgetCaps] = Field(default_factory=dict)

    soft_max_branch_depth: int | None = Field(default=None, ge=0)
    hard_max_branch_depth: int | None = Field(default=None, ge=0)

    exploration_reserve_fraction: float = Field(
        default=0.20,
        ge=0.0,
        lt=1.0,
    )

    @field_validator("soft_worker_limits", "hard_worker_limits")
    @classmethod
    def normalize_worker_limits(
        cls,
        value: dict[str, BudgetCaps],
    ) -> dict[str, BudgetCaps]:
        result: dict[str, BudgetCaps] = {}
        for worker, caps in value.items():
            name = worker.strip()
            if not name:
                raise ValueError("worker budget name must not be blank")
            if name in result:
                raise ValueError(f"duplicate worker budget: {name}")
            result[name] = caps
        return result

    @model_validator(mode="after")
    def validate_depths(self) -> "BudgetProfile":
        if (
            self.soft_max_branch_depth is not None
            and self.hard_max_branch_depth is not None
            and self.soft_max_branch_depth > self.hard_max_branch_depth
        ):
            raise ValueError(
                "soft_max_branch_depth cannot exceed hard_max_branch_depth"
            )
        return self


class BudgetDemand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tasks: float = Field(default=1.0, ge=0.0)
    cost: float = Field(default=0.0, ge=0.0)
    requests: float = Field(default=0.0, ge=0.0)
    candidates: float = Field(default=0.0, ge=0.0)
    runtime_seconds: float = Field(default=0.0, ge=0.0)
    concurrent_tasks: float = Field(default=1.0, ge=0.0)

    def as_metric_amounts(self) -> dict[BudgetMetric, float]:
        values = {
            BudgetMetric.TASKS: self.tasks,
            BudgetMetric.COST: self.cost,
            BudgetMetric.REQUESTS: self.requests,
            BudgetMetric.CANDIDATES: self.candidates,
            BudgetMetric.RUNTIME_SECONDS: self.runtime_seconds,
            BudgetMetric.CONCURRENT_TASKS: self.concurrent_tasks,
        }
        return {
            metric: amount
            for metric, amount in values.items()
            if amount > 0.0
        }


class BudgetContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    branch_depth: int = Field(default=0, ge=0)
    resource_keys: frozenset[str] = Field(default_factory=frozenset)
    lane: BudgetLane = BudgetLane.NORMAL
    branch_soft_multiplier: float = Field(default=1.0, ge=1.0)

    @field_validator("resource_keys")
    @classmethod
    def normalize_resource_keys(
        cls,
        value: frozenset[str],
    ) -> frozenset[str]:
        return frozenset(
            key.strip().lower()
            for key in value
            if key.strip()
        )


class BudgetCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    budget_class: BudgetClass
    requested: float = Field(gt=0.0)
    configured_limit: float = Field(ge=0.0)
    effective_limit: float = Field(ge=0.0)


class BudgetReservationItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    budget_class: BudgetClass
    amount: float = Field(gt=0.0)


class BudgetReservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: str = Field(default_factory=new_reservation_id)
    task_id: str
    items: tuple[BudgetReservationItem, ...]
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    state: ReservationState = ReservationState.ACTIVE

    @field_validator("created_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("budget timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def expiry_after_creation(self) -> "BudgetReservation":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self


class BudgetViolation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    budget_class: BudgetClass

    committed: float = Field(ge=0.0)
    reserved: float = Field(ge=0.0)
    requested: float = Field(gt=0.0)

    configured_limit: float = Field(ge=0.0)
    effective_limit: float = Field(ge=0.0)

    @property
    def projected(self) -> float:
        return self.committed + self.reserved + self.requested


class BudgetUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_key: str
    metric: BudgetMetric
    budget_class: BudgetClass

    committed: float = Field(default=0.0, ge=0.0)
    reserved: float = Field(default=0.0, ge=0.0)

    @property
    def total(self) -> float:
        return self.committed + self.reserved


class BudgetDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: BudgetOutcome
    task_id: str

    reservation: BudgetReservation | None = None
    violations: tuple[BudgetViolation, ...] = ()
    checked_limits: tuple[BudgetCheck, ...] = ()

    reason: str | None = None
    retry_after_seconds: float | None = Field(default=None, ge=0.0)

    @property
    def allowed(self) -> bool:
        return self.outcome is BudgetOutcome.ALLOW

    @property
    def should_defer(self) -> bool:
        return self.outcome is BudgetOutcome.DEFER

    @property
    def denied(self) -> bool:
        return self.outcome is BudgetOutcome.DENY


class BudgetStore(Protocol):
    async def try_reserve(
        self,
        *,
        reservation: BudgetReservation,
        checks: tuple[BudgetCheck, ...],
    ) -> tuple[bool, tuple[BudgetViolation, ...]]:
        ...

    async def commit(self, reservation_id: str) -> BudgetReservation:
        ...

    async def release(self, reservation_id: str) -> BudgetReservation:
        ...

    async def renew(
        self,
        reservation_id: str,
        *,
        expires_at: datetime,
    ) -> BudgetReservation:
        ...

    async def reap_expired(
        self,
        *,
        now: datetime,
    ) -> list[BudgetReservation]:
        ...

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
        budget_class: BudgetClass,
    ) -> BudgetUsage:
        ...

    async def get_reservation(
        self,
        reservation_id: str,
    ) -> BudgetReservation | None:
        ...


class InMemoryBudgetStore:
    def __init__(self) -> None:
        self._committed: dict[
            tuple[str, BudgetClass, BudgetMetric],
            float,
        ] = {}
        self._reserved: dict[
            tuple[str, BudgetClass, BudgetMetric],
            float,
        ] = {}
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
                key = (
                    check.bucket_key,
                    check.budget_class,
                    check.metric,
                )
                committed = self._committed.get(key, 0.0)
                reserved = self._reserved.get(key, 0.0)

                if (
                    committed
                    + reserved
                    + check.requested
                    > check.effective_limit + 1e-9
                ):
                    violations.append(
                        BudgetViolation(
                            bucket_key=check.bucket_key,
                            metric=check.metric,
                            budget_class=check.budget_class,
                            committed=committed,
                            reserved=reserved,
                            requested=check.requested,
                            configured_limit=check.configured_limit,
                            effective_limit=check.effective_limit,
                        )
                    )

            if violations:
                return False, tuple(violations)

            stored = reservation.model_copy(deep=True)
            self._reservations[stored.reservation_id] = stored

            for item in stored.items:
                key = (
                    item.bucket_key,
                    item.budget_class,
                    item.metric,
                )
                self._reserved[key] = (
                    self._reserved.get(key, 0.0) + item.amount
                )

            return True, ()

    async def commit(
        self,
        reservation_id: str,
    ) -> BudgetReservation:
        async with self._lock:
            reservation = self._require_active(reservation_id)

            for item in reservation.items:
                key = (
                    item.bucket_key,
                    item.budget_class,
                    item.metric,
                )
                self._subtract_reserved(key, item.amount)

                if not item.metric.is_capacity:
                    self._committed[key] = (
                        self._committed.get(key, 0.0)
                        + item.amount
                    )

            updated = reservation.model_copy(
                update={"state": ReservationState.COMMITTED}
            )
            self._reservations[reservation_id] = updated
            return updated.model_copy(deep=True)

    async def release(
        self,
        reservation_id: str,
    ) -> BudgetReservation:
        async with self._lock:
            reservation = self._require_active(reservation_id)

            for item in reservation.items:
                self._subtract_reserved(
                    (
                        item.bucket_key,
                        item.budget_class,
                        item.metric,
                    ),
                    item.amount,
                )

            updated = reservation.model_copy(
                update={"state": ReservationState.RELEASED}
            )
            self._reservations[reservation_id] = updated
            return updated.model_copy(deep=True)

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

            updated = reservation.model_copy(
                update={"expires_at": expires_at}
            )
            self._reservations[reservation_id] = updated
            return updated.model_copy(deep=True)

    async def reap_expired(
        self,
        *,
        now: datetime,
    ) -> list[BudgetReservation]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")

        async with self._lock:
            expired: list[BudgetReservation] = []

            for reservation_id, reservation in list(
                self._reservations.items()
            ):
                if (
                    reservation.state is not ReservationState.ACTIVE
                    or reservation.expires_at > now
                ):
                    continue

                for item in reservation.items:
                    self._subtract_reserved(
                        (
                            item.bucket_key,
                            item.budget_class,
                            item.metric,
                        ),
                        item.amount,
                    )

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
        budget_class: BudgetClass,
    ) -> BudgetUsage:
        async with self._lock:
            key = (bucket_key, budget_class, metric)

            return BudgetUsage(
                bucket_key=bucket_key,
                metric=metric,
                budget_class=budget_class,
                committed=self._committed.get(key, 0.0),
                reserved=self._reserved.get(key, 0.0),
            )

    async def get_reservation(
        self,
        reservation_id: str,
    ) -> BudgetReservation | None:
        async with self._lock:
            value = self._reservations.get(reservation_id)
            return (
                value.model_copy(deep=True)
                if value is not None
                else None
            )

    def _require_active(
        self,
        reservation_id: str,
    ) -> BudgetReservation:
        try:
            reservation = self._reservations[reservation_id]
        except KeyError as exc:
            raise KeyError(
                f"unknown budget reservation: {reservation_id}"
            ) from exc

        if reservation.state is not ReservationState.ACTIVE:
            raise ValueError(
                f"reservation {reservation_id} is not ACTIVE"
            )

        return reservation

    def _subtract_reserved(
        self,
        key: tuple[str, BudgetClass, BudgetMetric],
        amount: float,
    ) -> None:
        current = self._reserved.get(key, 0.0)
        updated = current - amount

        if updated < -1e-9:
            raise RuntimeError(
                f"reserved budget underflow for {key}"
            )

        if updated <= 1e-9:
            self._reserved.pop(key, None)
        else:
            self._reserved[key] = updated


class BudgetManager:
    def __init__(
        self,
        store: BudgetStore,
        *,
        profile: BudgetProfile | None = None,
        soft_retry_after: timedelta = timedelta(minutes=15),
        capacity_retry_after: timedelta = timedelta(seconds=1),
    ) -> None:
        if (
            soft_retry_after < timedelta(0)
            or capacity_retry_after < timedelta(0)
        ):
            raise ValueError("retry delays cannot be negative")

        self._store = store
        self._profile = profile or BudgetProfile()
        self._soft_retry_after = soft_retry_after
        self._capacity_retry_after = capacity_retry_after

    async def reserve(
        self,
        task: Task,
        *,
        demand: BudgetDemand | None = None,
        context: BudgetContext | None = None,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> BudgetDecision:
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        budget_demand = demand or BudgetDemand()
        budget_context = context or BudgetContext()

        if (
            self._profile.hard_max_branch_depth is not None
            and budget_context.branch_depth
            > self._profile.hard_max_branch_depth
        ):
            return BudgetDecision(
                outcome=BudgetOutcome.DENY,
                task_id=task.task_id,
                reason="branch depth exceeds hard maximum",
            )

        if (
            self._profile.soft_max_branch_depth is not None
            and budget_context.branch_depth
            > self._profile.soft_max_branch_depth
        ):
            return BudgetDecision(
                outcome=BudgetOutcome.DEFER,
                task_id=task.task_id,
                reason=(
                    "soft exploration depth exhausted; "
                    "preserve task in frontier"
                ),
                retry_after_seconds=(
                    self._soft_retry_after.total_seconds()
                ),
            )

        checks = self._compile_checks(
            task=task,
            demand=budget_demand,
            context=budget_context,
        )

        if not checks:
            return BudgetDecision(
                outcome=BudgetOutcome.ALLOW,
                task_id=task.task_id,
                reason="no matching budget limits",
            )

        now = utc_now()

        reservation = BudgetReservation(
            task_id=task.task_id,
            items=tuple(
                BudgetReservationItem(
                    bucket_key=check.bucket_key,
                    metric=check.metric,
                    budget_class=check.budget_class,
                    amount=check.requested,
                )
                for check in checks
            ),
            created_at=now,
            expires_at=now + lease_for,
        )

        allowed, violations = await self._store.try_reserve(
            reservation=reservation,
            checks=checks,
        )

        if allowed:
            return BudgetDecision(
                outcome=BudgetOutcome.ALLOW,
                task_id=task.task_id,
                reservation=reservation,
                checked_limits=checks,
            )

        hard = tuple(
            violation
            for violation in violations
            if violation.budget_class is BudgetClass.HARD
        )

        if hard and not all(
            violation.metric.is_capacity
            for violation in hard
        ):
            return BudgetDecision(
                outcome=BudgetOutcome.DENY,
                task_id=task.task_id,
                violations=violations,
                checked_limits=checks,
                reason=(
                    "hard cumulative budget limit would be exceeded"
                ),
            )

        retry = (
            self._capacity_retry_after
            if hard
            else self._soft_retry_after
        )

        return BudgetDecision(
            outcome=BudgetOutcome.DEFER,
            task_id=task.task_id,
            violations=violations,
            checked_limits=checks,
            reason=(
                "hard execution capacity exhausted; preserve task in frontier"
                if hard
                else (
                    "soft exploration budget exhausted; "
                    "preserve task in frontier"
                )
            ),
            retry_after_seconds=retry.total_seconds(),
        )

    async def commit(
        self,
        reservation_id: str,
    ) -> BudgetReservation:
        return await self._store.commit(reservation_id)

    async def release(
        self,
        reservation_id: str,
    ) -> BudgetReservation:
        return await self._store.release(reservation_id)

    async def renew(
        self,
        reservation_id: str,
        *,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> BudgetReservation:
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        return await self._store.renew(
            reservation_id,
            expires_at=utc_now() + lease_for,
        )

    async def reap_expired(
        self,
    ) -> list[BudgetReservation]:
        return await self._store.reap_expired(now=utc_now())

    async def usage(
        self,
        *,
        bucket_key: str,
        metric: BudgetMetric,
        budget_class: BudgetClass,
    ) -> BudgetUsage:
        return await self._store.usage(
            bucket_key=bucket_key,
            metric=metric,
            budget_class=budget_class,
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

        for budget_class in (
            BudgetClass.HARD,
            BudgetClass.SOFT,
        ):
            if budget_class is BudgetClass.HARD:
                global_caps = self._profile.hard_global_limits
                branch_caps = self._profile.hard_branch_limits
                resource_caps = self._profile.hard_resource_limits
                worker_caps = self._profile.hard_worker_limits.get(
                    task.worker
                )
            else:
                global_caps = self._profile.soft_global_limits
                branch_caps = self._profile.soft_branch_limits
                resource_caps = self._profile.soft_resource_limits
                worker_caps = self._profile.soft_worker_limits.get(
                    task.worker
                )

            checks.extend(
                _checks_for_caps(
                    bucket_key="global",
                    caps=global_caps,
                    amounts=amounts,
                    budget_class=budget_class,
                    context=context,
                    reserve_fraction=(
                        self._profile.exploration_reserve_fraction
                    ),
                )
            )

            if worker_caps is not None:
                checks.extend(
                    _checks_for_caps(
                        bucket_key=f"worker:{task.worker}",
                        caps=worker_caps,
                        amounts=amounts,
                        budget_class=budget_class,
                        context=context,
                        reserve_fraction=(
                            self._profile.exploration_reserve_fraction
                        ),
                    )
                )

            if task.branch_id is not None:
                multiplier = (
                    context.branch_soft_multiplier
                    if budget_class is BudgetClass.SOFT
                    else 1.0
                )

                checks.extend(
                    _checks_for_caps(
                        bucket_key=f"branch:{task.branch_id}",
                        caps=branch_caps,
                        amounts=amounts,
                        budget_class=budget_class,
                        context=context,
                        reserve_fraction=(
                            self._profile.exploration_reserve_fraction
                        ),
                        multiplier=multiplier,
                    )
                )

            for resource_key in sorted(context.resource_keys):
                checks.extend(
                    _checks_for_caps(
                        bucket_key=f"resource:{resource_key}",
                        caps=resource_caps,
                        amounts=amounts,
                        budget_class=budget_class,
                        context=context,
                        reserve_fraction=(
                            self._profile.exploration_reserve_fraction
                        ),
                    )
                )

        return _merge_checks(checks)


def _checks_for_caps(
    *,
    bucket_key: str,
    caps: BudgetCaps,
    amounts: dict[BudgetMetric, float],
    budget_class: BudgetClass,
    context: BudgetContext,
    reserve_fraction: float,
    multiplier: float = 1.0,
) -> list[BudgetCheck]:
    checks: list[BudgetCheck] = []

    for metric, configured in caps.as_metric_limits().items():
        requested = amounts.get(metric)
        if requested is None:
            continue

        configured_limit = configured * multiplier
        effective_limit = configured_limit

        if (
            budget_class is BudgetClass.SOFT
            and context.lane is BudgetLane.NORMAL
        ):
            effective_limit *= 1.0 - reserve_fraction

        checks.append(
            BudgetCheck(
                bucket_key=bucket_key,
                metric=metric,
                budget_class=budget_class,
                requested=requested,
                configured_limit=configured_limit,
                effective_limit=effective_limit,
            )
        )

    return checks


def _merge_checks(
    checks: Iterable[BudgetCheck],
) -> tuple[BudgetCheck, ...]:
    merged: dict[
        tuple[str, BudgetClass, BudgetMetric],
        BudgetCheck,
    ] = {}

    for check in checks:
        key = (
            check.bucket_key,
            check.budget_class,
            check.metric,
        )
        existing = merged.get(key)

        if existing is None:
            merged[key] = check
            continue

        if (
            existing.configured_limit != check.configured_limit
            or existing.effective_limit != check.effective_limit
        ):
            raise ValueError(
                f"conflicting budget limits for {key}"
            )

        merged[key] = check.model_copy(
            update={
                "requested": (
                    existing.requested
                    + check.requested
                )
            }
        )

    return tuple(
        merged[key]
        for key in sorted(
            merged,
            key=lambda item: (
                item[0],
                item[1].value,
                item[2].value,
            ),
        )
    )
