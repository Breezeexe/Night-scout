"""Central request pacing and concurrency control for Night Scout.

Why this module exists
----------------------

Individual reconnaissance tools often have their own `-rate-limit` flags, but
those limits are local to one process. If three workers each independently run
at 30 requests/second against the same target, the aggregate load may become
90 requests/second.

Night Scout therefore treats rate limits as shared policy state above any
specific CLI tool.

This module provides:

    RateLimitProfile / RateLimitRule
        Declarative limits from the bug-bounty program configuration.

    RateLimiter.plan()
        A conservative envelope workers can translate into native tool flags.

    RateLimiter.acquire()
        An atomic shared token-bucket + concurrency reservation.

    RateLimiter.release()
        Releases concurrency after work completes. Request tokens are not
        returned because they represent already-consumed pacing capacity.

The future worker runtime should use both layers:

    lifecycle selects authorized task
        -> worker obtains RateLimitPlan
        -> worker configures CLI/native request pacing
        -> worker acquires shared permits as close to network I/O as its
           execution model allows
        -> work finishes
        -> concurrency lease is released

For tools that expose only a process-level RPS flag, safe_rps_hint deliberately
divides a shared rule's RPS by its configured max_concurrency. This is
conservative, but prevents N parallel processes from each assuming they own the
entire program-wide request rate.

Scope authorization remains in policy/scope.py. Rate limiting never turns an
out-of-scope target into an authorized one.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.queue import Task


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_rate_lease_id() -> str:
    """Create a unique rate-limit lease identifier."""
    return f"rtl_{uuid4().hex}"


class RateLimitScope(StrEnum):
    """How a rule aggregates usage."""

    GLOBAL = "GLOBAL"
    PER_RESOURCE = "PER_RESOURCE"


class RateLimitOutcome(StrEnum):
    """Result of an atomic acquire attempt."""

    ALLOW = "ALLOW"
    DEFER = "DEFER"
    DENY = "DENY"


class RateLeaseState(StrEnum):
    """Lifecycle state of a concurrency/rate lease."""

    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class RateLimitRule(BaseModel):
    """One shared request-rate/concurrency rule.

    resource_pattern matches normalized resource keys, for example:

        *
        host:*.example.com
        host:api.example.com
        ip:203.0.113.*

    PER_RESOURCE creates a separate token/concurrency bucket for every matched
    concrete resource key.

    GLOBAL creates one shared bucket for all matching resources.

    `workers` optionally restricts the rule to specific worker names.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    scope: RateLimitScope = RateLimitScope.PER_RESOURCE
    resource_pattern: str = "*"

    requests_per_second: float | None = Field(default=None, gt=0.0)
    burst: float | None = Field(default=None, gt=0.0)
    max_concurrency: int | None = Field(default=None, ge=1)

    workers: frozenset[str] = Field(default_factory=frozenset)

    reason: str | None = None

    @field_validator("rule_id", "resource_pattern")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("workers")
    @classmethod
    def normalize_workers(
        cls,
        value: frozenset[str],
    ) -> frozenset[str]:
        normalized = {
            worker.strip()
            for worker in value
            if worker.strip()
        }
        return frozenset(normalized)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def validate_rule(self) -> RateLimitRule:
        if (
            self.requests_per_second is None
            and self.max_concurrency is None
        ):
            raise ValueError(
                "rate-limit rule must configure requests_per_second, "
                "max_concurrency, or both"
            )

        if self.burst is not None and self.requests_per_second is None:
            raise ValueError(
                "burst requires requests_per_second"
            )

        if (
            self.requests_per_second is not None
            and self.burst is None
        ):
            # Default burst allows one second of configured traffic.
            object.__setattr__(
                self,
                "burst",
                self.requests_per_second,
            )

        return self

    def matches_worker(self, worker: str) -> bool:
        """Return whether this rule applies to a worker."""
        return not self.workers or worker in self.workers

    def matches_resource(self, resource_key: str) -> bool:
        """Return whether this rule applies to a normalized resource key."""
        return fnmatchcase(resource_key, self.resource_pattern.lower())


class RateLimitProfile(BaseModel):
    """Target/run rate-limit configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[RateLimitRule, ...] = ()

    # Network work with request demand should normally have an explicit matching
    # rate rule. This prevents a newly added worker from silently running
    # unlimited because configuration forgot it.
    require_matching_rule: bool = True

    default_retry_after_seconds: float = Field(default=1.0, ge=0.0)

    @model_validator(mode="after")
    def validate_unique_rule_ids(self) -> RateLimitProfile:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                raise ValueError(
                    f"duplicate rate-limit rule_id: {rule.rule_id}"
                )
            seen.add(rule.rule_id)
        return self


class RateLimitContext(BaseModel):
    """Concrete resources that the task is expected to touch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_keys: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("resource_keys")
    @classmethod
    def normalize_resource_keys(
        cls,
        value: frozenset[str],
    ) -> frozenset[str]:
        normalized = {
            key.strip().lower()
            for key in value
            if key.strip()
        }
        return frozenset(normalized)


class RateLimitDemand(BaseModel):
    """Rate/concurrency demand for one acquisition.

    For request-aware Python workers this can represent one request.

    For subprocess workers this can represent one CLI process slot while the
    process itself is additionally configured using RateLimitPlan.safe_rps_hint.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    requests: float = Field(default=1.0, ge=0.0)
    concurrency: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def require_some_demand(self) -> RateLimitDemand:
        if self.requests == 0.0 and self.concurrency == 0:
            raise ValueError(
                "rate-limit demand must request tokens, concurrency, or both"
            )
        return self


class RateLimitPlan(BaseModel):
    """Conservative rate envelope for configuring a worker/tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    resource_keys: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]

    # Minimum configured RPS across all matching rules.
    aggregate_rps_ceiling: float | None = None

    # Conservative per-process/per-consumer hint. When a shared rule has both
    # RPS and max_concurrency, this becomes RPS / max_concurrency.
    safe_rps_hint: float | None = None

    max_concurrency_hint: int | None = None

    matched: bool


class RateBucketCheck(BaseModel):
    """Atomic check against one shared token/concurrency bucket."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    bucket_key: str

    requests: float = Field(default=0.0, ge=0.0)
    concurrency: int = Field(default=0, ge=0)

    requests_per_second: float | None = Field(default=None, gt=0.0)
    burst: float | None = Field(default=None, gt=0.0)
    max_concurrency: int | None = Field(default=None, ge=1)


class RateLimitViolation(BaseModel):
    """Explainable temporary inability to acquire a shared bucket."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    bucket_key: str

    kind: str
    reason: str

    retry_after_seconds: float = Field(ge=0.0)


class RateLeaseItem(BaseModel):
    """Usage reserved in one bucket by an active lease."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    bucket_key: str
    concurrency: int = Field(default=0, ge=0)


class RateLimitLease(BaseModel):
    """Lease representing active shared concurrency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: str = Field(default_factory=new_rate_lease_id)
    task_id: str

    items: tuple[RateLeaseItem, ...]

    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime

    state: RateLeaseState = RateLeaseState.ACTIVE

    @field_validator("created_at", "expires_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_expiry(self) -> RateLimitLease:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self


class RateLimitDecision(BaseModel):
    """Result of RateLimiter.acquire()."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: RateLimitOutcome
    task_id: str

    lease: RateLimitLease | None = None
    violations: tuple[RateLimitViolation, ...] = ()
    checked_buckets: tuple[RateBucketCheck, ...] = ()

    reason: str | None = None
    retry_after_seconds: float | None = Field(default=None, ge=0.0)

    @property
    def allowed(self) -> bool:
        return self.outcome is RateLimitOutcome.ALLOW

    @property
    def should_defer(self) -> bool:
        return self.outcome is RateLimitOutcome.DEFER

    @property
    def denied(self) -> bool:
        return self.outcome is RateLimitOutcome.DENY


class RateBucketState(BaseModel):
    """Persistable state of one token/concurrency bucket."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    bucket_key: str

    tokens: float = Field(ge=0.0)
    last_refill_at: datetime

    active_concurrency: int = Field(default=0, ge=0)

    @field_validator("last_refill_at")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("last_refill_at must be timezone-aware")
        return value


class RateLimitStore(Protocol):
    """Atomic persistence boundary for shared rate-limit state."""

    async def try_acquire(
        self,
        *,
        task_id: str,
        checks: tuple[RateBucketCheck, ...],
        lease_for: timedelta,
        now: datetime,
    ) -> RateLimitDecision:
        """Atomically consume request tokens and reserve concurrency."""
        ...

    async def release(self, lease_id: str) -> RateLimitLease:
        """Release concurrency held by an active lease."""
        ...

    async def renew(
        self,
        lease_id: str,
        *,
        expires_at: datetime,
    ) -> RateLimitLease:
        """Extend one active lease."""
        ...

    async def reap_expired(self, *, now: datetime) -> list[RateLimitLease]:
        """Release concurrency from abandoned leases."""
        ...

    async def get_lease(self, lease_id: str) -> RateLimitLease | None:
        """Return one lease."""
        ...

    async def bucket_state(
        self,
        *,
        rule_id: str,
        bucket_key: str,
    ) -> RateBucketState | None:
        """Return current bucket state for diagnostics."""
        ...


@dataclass(slots=True)
class _MutableBucket:
    tokens: float
    last_refill_at: datetime
    active_concurrency: int = 0


class InMemoryRateLimitStore:
    """Concurrency-safe token-bucket implementation for development/tests."""

    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], _MutableBucket] = {}
        self._leases: dict[str, RateLimitLease] = {}
        self._lock = asyncio.Lock()

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

        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")

        async with self._lock:
            violations: list[RateLimitViolation] = []
            projected: dict[tuple[str, str], _MutableBucket] = {}

            for check in checks:
                key = (check.rule_id, check.bucket_key)
                bucket = self._current_bucket(check, now=now)

                # Work on a copy so a failed multi-bucket acquisition mutates
                # no shared state.
                candidate = _MutableBucket(
                    tokens=bucket.tokens,
                    last_refill_at=bucket.last_refill_at,
                    active_concurrency=bucket.active_concurrency,
                )

                token_retry = 0.0
                concurrency_retry = 0.0

                if (
                    check.requests > 0.0
                    and check.requests_per_second is not None
                    and check.burst is not None
                ):
                    if check.requests > check.burst + 1e-9:
                        raise ValueError(
                            "single rate-limit acquisition requests more "
                            f"tokens than bucket burst for {check.rule_id}; "
                            "split the demand into smaller acquisitions"
                        )

                    if candidate.tokens + 1e-9 < check.requests:
                        missing = check.requests - candidate.tokens
                        token_retry = missing / check.requests_per_second

                if (
                    check.concurrency > 0
                    and check.max_concurrency is not None
                    and candidate.active_concurrency + check.concurrency
                    > check.max_concurrency
                ):
                    concurrency_retry = self._earliest_concurrency_release(
                        rule_id=check.rule_id,
                        bucket_key=check.bucket_key,
                        now=now,
                    )

                retry_after = max(token_retry, concurrency_retry)

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
                    candidate.tokens -= check.requests

                if (
                    check.concurrency > 0
                    and check.max_concurrency is not None
                ):
                    candidate.active_concurrency += check.concurrency

                projected[key] = candidate

            if violations:
                retry_after = max(
                    violation.retry_after_seconds
                    for violation in violations
                )
                return RateLimitDecision(
                    outcome=RateLimitOutcome.DEFER,
                    task_id=task_id,
                    violations=tuple(violations),
                    checked_buckets=checks,
                    reason="shared rate-limit capacity is temporarily exhausted",
                    retry_after_seconds=retry_after,
                )

            for key, candidate in projected.items():
                self._buckets[key] = candidate

            lease_items = tuple(
                RateLeaseItem(
                    rule_id=check.rule_id,
                    bucket_key=check.bucket_key,
                    concurrency=(
                        check.concurrency
                        if check.max_concurrency is not None
                        else 0
                    ),
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
                self._leases[lease.lease_id] = lease

            return RateLimitDecision(
                outcome=RateLimitOutcome.ALLOW,
                task_id=task_id,
                lease=lease,
                checked_buckets=checks,
            )

    async def release(self, lease_id: str) -> RateLimitLease:
        async with self._lock:
            lease = self._require_active_lease(lease_id)

            self._release_lease_items(lease)

            released = lease.model_copy(
                update={"state": RateLeaseState.RELEASED}
            )
            self._leases[lease_id] = released
            return released.model_copy(deep=True)

    async def renew(
        self,
        lease_id: str,
        *,
        expires_at: datetime,
    ) -> RateLimitLease:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")

        async with self._lock:
            lease = self._require_active_lease(lease_id)

            if expires_at <= utc_now():
                raise ValueError("expires_at must be in the future")

            renewed = lease.model_copy(
                update={"expires_at": expires_at}
            )
            self._leases[lease_id] = renewed
            return renewed.model_copy(deep=True)

    async def reap_expired(self, *, now: datetime) -> list[RateLimitLease]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")

        async with self._lock:
            expired: list[RateLimitLease] = []

            for lease_id, lease in list(self._leases.items()):
                if (
                    lease.state is not RateLeaseState.ACTIVE
                    or lease.expires_at > now
                ):
                    continue

                self._release_lease_items(lease)

                updated = lease.model_copy(
                    update={"state": RateLeaseState.EXPIRED}
                )
                self._leases[lease_id] = updated
                expired.append(updated.model_copy(deep=True))

            return expired

    async def get_lease(self, lease_id: str) -> RateLimitLease | None:
        async with self._lock:
            lease = self._leases.get(lease_id)
            return lease.model_copy(deep=True) if lease is not None else None

    async def bucket_state(
        self,
        *,
        rule_id: str,
        bucket_key: str,
    ) -> RateBucketState | None:
        async with self._lock:
            bucket = self._buckets.get((rule_id, bucket_key))
            if bucket is None:
                return None

            return RateBucketState(
                rule_id=rule_id,
                bucket_key=bucket_key,
                tokens=bucket.tokens,
                last_refill_at=bucket.last_refill_at,
                active_concurrency=bucket.active_concurrency,
            )

    def _current_bucket(
        self,
        check: RateBucketCheck,
        *,
        now: datetime,
    ) -> _MutableBucket:
        key = (check.rule_id, check.bucket_key)
        existing = self._buckets.get(key)

        if existing is None:
            initial_tokens = check.burst or 0.0
            return _MutableBucket(
                tokens=initial_tokens,
                last_refill_at=now,
                active_concurrency=0,
            )

        tokens = existing.tokens
        last_refill_at = existing.last_refill_at

        if (
            check.requests_per_second is not None
            and check.burst is not None
        ):
            elapsed = max(
                (now - last_refill_at).total_seconds(),
                0.0,
            )
            tokens = min(
                check.burst,
                tokens + elapsed * check.requests_per_second,
            )
            last_refill_at = now

        return _MutableBucket(
            tokens=tokens,
            last_refill_at=last_refill_at,
            active_concurrency=existing.active_concurrency,
        )

    def _earliest_concurrency_release(
        self,
        *,
        rule_id: str,
        bucket_key: str,
        now: datetime,
    ) -> float:
        expiries = [
            lease.expires_at
            for lease in self._leases.values()
            if lease.state is RateLeaseState.ACTIVE
            and any(
                item.rule_id == rule_id
                and item.bucket_key == bucket_key
                and item.concurrency > 0
                for item in lease.items
            )
        ]

        if not expiries:
            return 0.001

        earliest = min(expiries)
        return max(
            (earliest - now).total_seconds(),
            0.001,
        )

    def _require_active_lease(self, lease_id: str) -> RateLimitLease:
        try:
            lease = self._leases[lease_id]
        except KeyError as exc:
            raise KeyError(f"unknown rate-limit lease: {lease_id}") from exc

        if lease.state is not RateLeaseState.ACTIVE:
            raise ValueError(
                f"rate-limit lease {lease_id} is not ACTIVE "
                f"(state={lease.state})"
            )

        return lease

    def _release_lease_items(self, lease: RateLimitLease) -> None:
        for item in lease.items:
            if item.concurrency == 0:
                continue

            key = (item.rule_id, item.bucket_key)
            bucket = self._buckets.get(key)
            if bucket is None:
                raise RuntimeError(
                    f"missing bucket while releasing rate lease: {key}"
                )

            updated = bucket.active_concurrency - item.concurrency
            if updated < 0:
                raise RuntimeError(
                    f"rate-limit concurrency underflow for {key}"
                )

            bucket.active_concurrency = updated


class RateLimiter:
    """Compile matching rules and coordinate shared rate/concurrency state."""

    def __init__(
        self,
        store: RateLimitStore,
        *,
        profile: RateLimitProfile,
    ) -> None:
        self._store = store
        self._profile = profile

    def plan(
        self,
        task: Task,
        *,
        context: RateLimitContext,
    ) -> RateLimitPlan:
        """Return conservative CLI/runtime limits for this task."""
        matches = self._matching_rule_resources(
            task,
            context=context,
        )

        if not matches:
            return RateLimitPlan(
                task_id=task.task_id,
                resource_keys=tuple(sorted(context.resource_keys)),
                matched_rule_ids=(),
                matched=False,
            )

        matched_rules = {
            rule.rule_id: rule
            for rule, _resource in matches
        }

        rps_values = [
            rule.requests_per_second
            for rule in matched_rules.values()
            if rule.requests_per_second is not None
        ]

        aggregate_rps = min(rps_values) if rps_values else None

        safe_rps_candidates: list[float] = []
        concurrency_values: list[int] = []

        for rule in matched_rules.values():
            if rule.max_concurrency is not None:
                concurrency_values.append(rule.max_concurrency)

            if rule.requests_per_second is None:
                continue

            if rule.max_concurrency is not None:
                safe_rps_candidates.append(
                    rule.requests_per_second / rule.max_concurrency
                )
            else:
                safe_rps_candidates.append(rule.requests_per_second)

        safe_rps = (
            min(safe_rps_candidates)
            if safe_rps_candidates
            else None
        )
        max_concurrency = (
            min(concurrency_values)
            if concurrency_values
            else None
        )

        return RateLimitPlan(
            task_id=task.task_id,
            resource_keys=tuple(sorted(context.resource_keys)),
            matched_rule_ids=tuple(sorted(matched_rules)),
            aggregate_rps_ceiling=aggregate_rps,
            safe_rps_hint=safe_rps,
            max_concurrency_hint=max_concurrency,
            matched=True,
        )

    async def acquire(
        self,
        task: Task,
        *,
        context: RateLimitContext,
        demand: RateLimitDemand | None = None,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> RateLimitDecision:
        """Atomically consume shared request tokens/reserve concurrency."""
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        rate_demand = demand or RateLimitDemand()

        matches = self._matching_rule_resources(
            task,
            context=context,
        )

        if not matches:
            if (
                self._profile.require_matching_rule
                and (
                    rate_demand.requests > 0.0
                    or rate_demand.concurrency > 0
                )
            ):
                return RateLimitDecision(
                    outcome=RateLimitOutcome.DENY,
                    task_id=task.task_id,
                    reason=(
                        "network request demand has no matching rate-limit "
                        "rule; fail closed"
                    ),
                )

            return RateLimitDecision(
                outcome=RateLimitOutcome.ALLOW,
                task_id=task.task_id,
                reason="no matching rate-limit rule required",
            )

        checks = self._compile_checks(
            matches=matches,
            demand=rate_demand,
        )

        return await self._store.try_acquire(
            task_id=task.task_id,
            checks=checks,
            lease_for=lease_for,
            now=utc_now(),
        )

    async def release(self, lease_id: str) -> RateLimitLease:
        """Release active concurrency; consumed request tokens remain spent."""
        return await self._store.release(lease_id)

    async def renew(
        self,
        lease_id: str,
        *,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> RateLimitLease:
        """Extend an active concurrency lease."""
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        return await self._store.renew(
            lease_id,
            expires_at=utc_now() + lease_for,
        )

    async def reap_expired(self) -> list[RateLimitLease]:
        """Release concurrency from abandoned/crashed workers."""
        return await self._store.reap_expired(now=utc_now())

    async def bucket_state(
        self,
        *,
        rule_id: str,
        bucket_key: str,
    ) -> RateBucketState | None:
        """Expose shared bucket state for status/explain commands."""
        return await self._store.bucket_state(
            rule_id=rule_id,
            bucket_key=bucket_key,
        )

    def _matching_rule_resources(
        self,
        task: Task,
        *,
        context: RateLimitContext,
    ) -> list[tuple[RateLimitRule, str | None]]:
        matches: list[tuple[RateLimitRule, str | None]] = []

        for rule in self._profile.rules:
            if not rule.matches_worker(task.worker):
                continue

            if rule.scope is RateLimitScope.GLOBAL:
                # A GLOBAL rule still needs at least one resource match when
                # concrete resource keys are supplied. This lets a global rule
                # constrain a subset such as host:*.example.com.
                if context.resource_keys:
                    if any(
                        rule.matches_resource(resource_key)
                        for resource_key in context.resource_keys
                    ):
                        matches.append((rule, None))
                elif rule.resource_pattern == "*":
                    matches.append((rule, None))
                continue

            for resource_key in sorted(context.resource_keys):
                if rule.matches_resource(resource_key):
                    matches.append((rule, resource_key))

        return matches

    @staticmethod
    def _compile_checks(
        *,
        matches: list[tuple[RateLimitRule, str | None]],
        demand: RateLimitDemand,
    ) -> tuple[RateBucketCheck, ...]:
        checks: dict[tuple[str, str], RateBucketCheck] = {}

        for rule, resource_key in matches:
            bucket_key = (
                "global"
                if rule.scope is RateLimitScope.GLOBAL
                else f"resource:{resource_key}"
            )
            key = (rule.rule_id, bucket_key)

            if key in checks:
                continue

            checks[key] = RateBucketCheck(
                rule_id=rule.rule_id,
                bucket_key=bucket_key,
                requests=demand.requests,
                concurrency=demand.concurrency,
                requests_per_second=rule.requests_per_second,
                burst=rule.burst,
                max_concurrency=rule.max_concurrency,
            )

        return tuple(
            checks[key]
            for key in sorted(checks)
        )


def tool_integer_rps_hint(plan: RateLimitPlan) -> int | None:
    """Return a safe integer RPS for CLI tools that accept only integers.

    Floor is intentional: rounding upward could exceed the shared policy.
    A value below one cannot be safely expressed by integer-only RPS flags and
    returns None so the worker can choose delay/chunk-based pacing instead.
    """
    if plan.safe_rps_hint is None:
        return None

    floored = math.floor(plan.safe_rps_hint)
    return floored if floored >= 1 else None
