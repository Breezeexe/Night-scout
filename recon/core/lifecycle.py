"""Execution lifecycle orchestration for Night Scout.

Lifecycle is the coordination layer between:

    Scheduler
        -> Scope / Policy / Review gates
        -> BudgetManager
        -> TaskQueue claim
        -> WorkerExecutor
        -> Task completion / retry

It deliberately does not contain:
    - scope matching rules,
    - policy definitions,
    - budget scoring,
    - worker implementation details,
    - event persistence logic.

Those are injected through protocols so later modules can be added without
rewriting the lifecycle core.

Critical invariant:

    A soft budget exhaustion must never delete a discovered frontier item.

Therefore BudgetOutcome.DEFER always maps to TaskStatus.DEFERRED.

Another critical invariant:

    A task is never claimed RUNNING until every pre-execution gate has passed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from recon.core.budgets import (
    BudgetContext,
    BudgetDecision,
    BudgetDemand,
    BudgetManager,
    BudgetOutcome,
)
from recon.core.queue import Task, TaskQueue, TaskStatus
from recon.core.scheduler import ScheduleDecision, Scheduler


class GateOutcome(StrEnum):
    """Possible result of a pre-execution gate."""

    ALLOW = "ALLOW"
    DEFER = "DEFER"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class LifecycleOutcome(StrEnum):
    """Externally visible result of one lifecycle iteration."""

    IDLE = "IDLE"

    DEFERRED = "DEFERRED"
    BLOCKED = "BLOCKED"
    REVIEW = "REVIEW"

    SUCCEEDED = "SUCCEEDED"
    RETRY = "RETRY"
    FAILED = "FAILED"

    # The selected task changed state before it could be claimed.
    STALE = "STALE"


class WorkerOutcome(StrEnum):
    """Structured result returned by a worker runtime."""

    SUCCEEDED = "SUCCEEDED"
    RETRY = "RETRY"
    FAILED = "FAILED"


class GateDecision(BaseModel):
    """Decision returned by a scope/policy/review gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: GateOutcome
    reason: str | None = None

    retry_after_seconds: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_retry_metadata(self) -> GateDecision:
        """Only DEFER decisions may define a retry delay."""
        if (
            self.retry_after_seconds is not None
            and self.outcome is not GateOutcome.DEFER
        ):
            raise ValueError(
                "retry_after_seconds is only valid for DEFER decisions"
            )
        return self


class WorkerExecutionResult(BaseModel):
    """Result returned after a claimed worker task finishes.

    Workers are expected to normalize ordinary tool/process failures into this
    structure rather than raising exceptions. Exceptions are reserved for
    unexpected runtime/infrastructure failures.

    Event publication is intentionally not represented here. Worker adapters
    should publish normalized output through the future event-ingestion layer,
    keeping lifecycle.py independent from storage and routing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: WorkerOutcome

    error: str | None = None
    retry_after_seconds: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_outcome(self) -> WorkerExecutionResult:
        """Validate error/retry metadata against the worker outcome."""
        if self.outcome is WorkerOutcome.SUCCEEDED:
            if self.retry_after_seconds is not None:
                raise ValueError(
                    "SUCCEEDED worker results cannot define retry_after_seconds"
                )
            return self

        if not (self.error or "").strip():
            raise ValueError(
                "RETRY and FAILED worker results require an error message"
            )

        if (
            self.outcome is WorkerOutcome.FAILED
            and self.retry_after_seconds is not None
        ):
            raise ValueError(
                "FAILED worker results cannot define retry_after_seconds"
            )

        if (
            self.outcome is WorkerOutcome.RETRY
            and self.retry_after_seconds is None
        ):
            raise ValueError(
                "RETRY worker results require retry_after_seconds"
            )

        return self


class BudgetPlan(BaseModel):
    """Budget demand/context derived for a selected task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    demand: BudgetDemand = Field(default_factory=BudgetDemand)
    context: BudgetContext = Field(default_factory=BudgetContext)


class LifecycleRecoveryResult(BaseModel):
    """Summary of crash/restart lease recovery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recovered_tasks: int = Field(default=0, ge=0)
    expired_budget_reservations: int = Field(default=0, ge=0)


class LifecycleResult(BaseModel):
    """Explainable result of one run_once() iteration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: LifecycleOutcome

    task_id: str | None = None
    worker: str | None = None
    action: str | None = None

    reason: str | None = None

    schedule_score: float | None = None
    reservation_id: str | None = None

    queue_status: TaskStatus | None = None


class ExecutionGate(Protocol):
    """Pre-execution scope/policy/review gate.

    Future implementations may include:
        ScopeGate
        RestrictionGate
        ReviewGate

    Lifecycle evaluates them in configured order and stops at the first
    non-ALLOW decision.
    """

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        """Evaluate whether the selected task may continue."""
        ...


class BudgetPlanner(Protocol):
    """Derive budget demand/context from task and scheduling intelligence."""

    async def plan(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> BudgetPlan:
        """Return the budget plan for one execution attempt."""
        ...


class WorkerExecutor(Protocol):
    """Execute a claimed task through the future worker/runtime layer."""

    async def execute(self, task: Task) -> WorkerExecutionResult:
        """Run a worker for a task already in RUNNING state."""
        ...


class DefaultBudgetPlanner:
    """Minimal planner until worker descriptors/event storage exist.

    It reuses the scheduler's estimated cost. Future implementations can query
    the input Event and worker metadata to add:
        requests
        candidates
        runtime estimate
        resource_keys
        branch depth
        exploration lane
    """

    async def plan(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> BudgetPlan:
        return BudgetPlan(
            demand=BudgetDemand(
                cost=schedule.signals.estimated_cost,
            ),
            context=BudgetContext(),
        )


class Lifecycle:
    """Coordinate one safe Night Scout task execution at a time."""

    def __init__(
        self,
        *,
        queue: TaskQueue,
        scheduler: Scheduler,
        budgets: BudgetManager,
        gates: Iterable[ExecutionGate],
        executor: WorkerExecutor,
        budget_planner: BudgetPlanner | None = None,
        task_lease_for: timedelta = timedelta(minutes=5),
        heartbeat_interval: timedelta | None = None,
    ) -> None:
        gate_list = tuple(gates)

        # Fail closed: active execution cannot exist without at least one
        # explicit scope/policy gate.
        if not gate_list:
            raise ValueError(
                "Lifecycle requires at least one ExecutionGate"
            )

        if task_lease_for <= timedelta(0):
            raise ValueError("task_lease_for must be positive")

        if heartbeat_interval is None:
            heartbeat_interval = task_lease_for / 3

        if heartbeat_interval <= timedelta(0):
            raise ValueError("heartbeat_interval must be positive")

        if heartbeat_interval >= task_lease_for:
            raise ValueError(
                "heartbeat_interval must be shorter than task_lease_for"
            )

        self._queue = queue
        self._scheduler = scheduler
        self._budgets = budgets
        self._gates = gate_list
        self._executor = executor
        self._budget_planner = budget_planner or DefaultBudgetPlanner()

        self._task_lease_for = task_lease_for
        self._heartbeat_interval = heartbeat_interval

    async def recover_expired(
        self,
        *,
        task_retry_delay: timedelta = timedelta(seconds=0),
    ) -> LifecycleRecoveryResult:
        """Recover queue/budget leases left behind by interrupted execution.

        Queue tasks return to DEFERRED when retry budget remains. Budget
        reservations are expired/released independently. Both operations are
        idempotent with respect to already-finalized state.
        """
        if task_retry_delay < timedelta(0):
            raise ValueError("task_retry_delay cannot be negative")

        expired_reservations = await self._budgets.reap_expired()
        recovered_tasks = await self._queue.recover_expired_leases(
            retry_delay=task_retry_delay
        )

        return LifecycleRecoveryResult(
            recovered_tasks=len(recovered_tasks),
            expired_budget_reservations=len(expired_reservations),
        )

    async def run_once(self) -> LifecycleResult:
        """Evaluate and, when permitted, execute one ready task."""
        schedule = await self._scheduler.select_next()

        if schedule is None:
            return LifecycleResult(outcome=LifecycleOutcome.IDLE)

        task = await self._queue.get(schedule.task_id)

        if task is None:
            return LifecycleResult(
                outcome=LifecycleOutcome.STALE,
                task_id=schedule.task_id,
                worker=schedule.worker,
                action=schedule.action,
                reason="scheduled task no longer exists",
                schedule_score=schedule.score,
            )

        if task.status not in {TaskStatus.PENDING, TaskStatus.DEFERRED}:
            return LifecycleResult(
                outcome=LifecycleOutcome.STALE,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                reason=f"scheduled task is no longer runnable: {task.status}",
                schedule_score=schedule.score,
                queue_status=task.status,
            )

        gate_result = await self._apply_gates(task, schedule)
        if gate_result is not None:
            return gate_result

        plan = await self._budget_planner.plan(task, schedule)

        budget = await self._budgets.reserve(
            task,
            demand=plan.demand,
            context=plan.context,
            lease_for=self._task_lease_for,
        )

        if budget.outcome is BudgetOutcome.DEFER:
            delay = timedelta(
                seconds=budget.retry_after_seconds or 0.0
            )
            deferred = await self._queue.defer(
                task.task_id,
                delay=delay,
                reason=budget.reason or "budget deferred",
            )
            return LifecycleResult(
                outcome=LifecycleOutcome.DEFERRED,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                reason=budget.reason,
                schedule_score=schedule.score,
                queue_status=deferred.status,
            )

        if budget.outcome is BudgetOutcome.DENY:
            blocked = await self._queue.block(
                task.task_id,
                reason=budget.reason or "hard budget denied execution",
            )
            return LifecycleResult(
                outcome=LifecycleOutcome.BLOCKED,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                reason=budget.reason,
                schedule_score=schedule.score,
                queue_status=blocked.status,
            )

        reservation_id = (
            budget.reservation.reservation_id
            if budget.reservation is not None
            else None
        )

        try:
            running = await self._queue.claim(
                task.task_id,
                lease_for=self._task_lease_for,
            )
        except (KeyError, ValueError) as exc:
            # Another lifecycle loop may have claimed/changed the task between
            # scheduling and claim. Never leak a budget reservation.
            if reservation_id is not None:
                await self._budgets.release(reservation_id)

            current = await self._queue.get(task.task_id)

            return LifecycleResult(
                outcome=LifecycleOutcome.STALE,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                reason=f"task could not be claimed: {exc}",
                schedule_score=schedule.score,
                queue_status=current.status if current is not None else None,
            )

        heartbeat = asyncio.create_task(
            self._heartbeat_loop(
                task_id=running.task_id,
                reservation_id=reservation_id,
            )
        )

        try:
            execution = await self._executor.execute(running)
        except Exception as exc:
            # Unexpected executor exceptions are treated conservatively:
            # execution may already have touched the target, so a reservation
            # is committed rather than released.
            await self._stop_heartbeat(heartbeat)

            if reservation_id is not None:
                await self._budgets.commit(reservation_id)

            failed = await self._queue.fail(
                running.task_id,
                error=f"executor exception: {type(exc).__name__}: {exc}",
                retry_delay=None,
            )

            return LifecycleResult(
                outcome=LifecycleOutcome.FAILED,
                task_id=running.task_id,
                worker=running.worker,
                action=running.action,
                reason=failed.last_error,
                schedule_score=schedule.score,
                reservation_id=reservation_id,
                queue_status=failed.status,
            )

        await self._stop_heartbeat(heartbeat)

        # Once the worker was actually executed, conservatively commit the
        # reserved budget for every structured outcome. This prevents failed
        # tools from being retried indefinitely without consuming their
        # configured recon budget.
        if reservation_id is not None:
            await self._budgets.commit(reservation_id)

        if execution.outcome is WorkerOutcome.SUCCEEDED:
            succeeded = await self._queue.succeed(running.task_id)
            return LifecycleResult(
                outcome=LifecycleOutcome.SUCCEEDED,
                task_id=running.task_id,
                worker=running.worker,
                action=running.action,
                schedule_score=schedule.score,
                reservation_id=reservation_id,
                queue_status=succeeded.status,
            )

        if execution.outcome is WorkerOutcome.RETRY:
            retry_delay = timedelta(
                seconds=execution.retry_after_seconds or 0.0
            )
            retried = await self._queue.fail(
                running.task_id,
                error=execution.error or "worker requested retry",
                retry_delay=retry_delay,
            )

            lifecycle_outcome = (
                LifecycleOutcome.RETRY
                if retried.status is TaskStatus.DEFERRED
                else LifecycleOutcome.FAILED
            )

            return LifecycleResult(
                outcome=lifecycle_outcome,
                task_id=running.task_id,
                worker=running.worker,
                action=running.action,
                reason=retried.last_error,
                schedule_score=schedule.score,
                reservation_id=reservation_id,
                queue_status=retried.status,
            )

        failed = await self._queue.fail(
            running.task_id,
            error=execution.error or "worker failed",
            retry_delay=None,
        )

        return LifecycleResult(
            outcome=LifecycleOutcome.FAILED,
            task_id=running.task_id,
            worker=running.worker,
            action=running.action,
            reason=failed.last_error,
            schedule_score=schedule.score,
            reservation_id=reservation_id,
            queue_status=failed.status,
        )

    async def _apply_gates(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> LifecycleResult | None:
        for gate in self._gates:
            decision = await gate.evaluate(task, schedule)

            if decision.outcome is GateOutcome.ALLOW:
                continue

            if decision.outcome is GateOutcome.DEFER:
                delay = timedelta(
                    seconds=decision.retry_after_seconds or 0.0
                )
                deferred = await self._queue.defer(
                    task.task_id,
                    delay=delay,
                    reason=decision.reason or "execution gate deferred task",
                )
                return LifecycleResult(
                    outcome=LifecycleOutcome.DEFERRED,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=decision.reason,
                    schedule_score=schedule.score,
                    queue_status=deferred.status,
                )

            if decision.outcome is GateOutcome.REVIEW:
                review = await self._queue.send_to_review(
                    task.task_id,
                    reason=decision.reason or "manual review required",
                )
                return LifecycleResult(
                    outcome=LifecycleOutcome.REVIEW,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=decision.reason,
                    schedule_score=schedule.score,
                    queue_status=review.status,
                )

            blocked = await self._queue.block(
                task.task_id,
                reason=decision.reason or "execution gate blocked task",
            )
            return LifecycleResult(
                outcome=LifecycleOutcome.BLOCKED,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                reason=decision.reason,
                schedule_score=schedule.score,
                queue_status=blocked.status,
            )

        return None

    async def _heartbeat_loop(
        self,
        *,
        task_id: str,
        reservation_id: str | None,
    ) -> None:
        """Keep queue and budget leases alive while a worker is running."""
        interval = self._heartbeat_interval.total_seconds()

        try:
            while True:
                await asyncio.sleep(interval)

                await self._queue.heartbeat(
                    task_id,
                    lease_for=self._task_lease_for,
                )

                if reservation_id is not None:
                    await self._budgets.renew(
                        reservation_id,
                        lease_for=self._task_lease_for,
                    )
        except asyncio.CancelledError:
            raise
        except (KeyError, ValueError):
            # The main execution path owns final state transitions. If a lease
            # disappears because completion/recovery raced with heartbeat, the
            # loop should stop rather than mutate unrelated state.
            return

    @staticmethod
    async def _stop_heartbeat(task: asyncio.Task[None]) -> None:
        """Cancel and fully await the background heartbeat task."""
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
