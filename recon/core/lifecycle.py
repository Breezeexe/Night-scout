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

    A budget decision must leave an explicit durable task state.

Another critical invariant:

    A task is never claimed RUNNING until every pre-execution gate has passed.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Iterable
from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from recon.core.budgets import (
    BudgetContext,
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


class LeaseHeartbeatError(RuntimeError):
    """A worker can no longer be allowed to execute under its leases."""


class TaskLeaseLostError(LeaseHeartbeatError):
    """The queue claim was lost while the worker was executing."""


class BudgetLeaseLostError(LeaseHeartbeatError):
    """The budget reservation was lost while the worker was executing."""


class GateDecision(BaseModel):
    """Decision returned by a scope/policy/review gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: GateOutcome
    reason: str | None = None
    review_case_id: str | None = None

    retry_after_seconds: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_retry_metadata(self) -> GateDecision:
        """Only DEFER decisions may define a retry delay."""
        if self.retry_after_seconds is not None and self.outcome is not GateOutcome.DEFER:
            raise ValueError("retry_after_seconds is only valid for DEFER decisions")
        if self.review_case_id is not None and self.outcome is not GateOutcome.REVIEW:
            raise ValueError("review_case_id is only valid for REVIEW decisions")
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
                raise ValueError("SUCCEEDED worker results cannot define retry_after_seconds")
            return self

        if not (self.error or "").strip():
            raise ValueError("RETRY and FAILED worker results require an error message")

        if self.outcome is WorkerOutcome.FAILED and self.retry_after_seconds is not None:
            raise ValueError("FAILED worker results cannot define retry_after_seconds")

        if self.outcome is WorkerOutcome.RETRY and self.retry_after_seconds is None:
            raise ValueError("RETRY worker results require retry_after_seconds")

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
    claimed: bool = False
    execution_attempt: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_claim_metadata(self) -> LifecycleResult:
        if self.execution_attempt is not None and not self.claimed:
            raise ValueError("execution_attempt requires claimed=true")
        return self


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


class LifecycleReviewCoordinator(Protocol):
    """Open and authorize review decisions not owned by a specialized gate."""

    async def approved_for(
        self,
        *,
        task: Task,
        gate_name: str,
        reason: str,
    ) -> bool: ...

    async def open_case(
        self,
        *,
        task: Task,
        gate_name: str,
        reason: str,
    ) -> str: ...


class LifecycleAttemptObserver(Protocol):
    """Persist one run-attributed task selection and its eventual outcome."""

    async def start(self, task: Task, schedule: ScheduleDecision) -> str | None: ...

    async def finish(
        self,
        attempt_id: str,
        result: LifecycleResult,
    ) -> None: ...


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
        review_coordinator: LifecycleReviewCoordinator | None = None,
        attempt_observer: LifecycleAttemptObserver | None = None,
    ) -> None:
        gate_list = tuple(gates)

        # Fail closed: active execution cannot exist without at least one
        # explicit scope/policy gate.
        if not gate_list:
            raise ValueError("Lifecycle requires at least one ExecutionGate")

        if task_lease_for <= timedelta(0):
            raise ValueError("task_lease_for must be positive")

        if heartbeat_interval is None:
            heartbeat_interval = task_lease_for / 3

        if heartbeat_interval <= timedelta(0):
            raise ValueError("heartbeat_interval must be positive")

        if heartbeat_interval >= task_lease_for:
            raise ValueError("heartbeat_interval must be shorter than task_lease_for")

        self._queue = queue
        self._scheduler = scheduler
        self._budgets = budgets
        self._gates = gate_list
        self._executor = executor
        self._budget_planner = budget_planner or DefaultBudgetPlanner()

        self._task_lease_for = task_lease_for
        self._heartbeat_interval = heartbeat_interval
        self._review_coordinator = review_coordinator
        self._attempt_observer = attempt_observer

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
        recovered_tasks = await self._queue.recover_expired_leases(retry_delay=task_retry_delay)

        return LifecycleRecoveryResult(
            recovered_tasks=len(recovered_tasks),
            expired_budget_reservations=len(expired_reservations),
        )

    async def run_once(
        self,
        *,
        on_claimed: Callable[[Task], None] | None = None,
    ) -> LifecycleResult:
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

        attempt_id = (
            await self._attempt_observer.start(task, schedule)
            if self._attempt_observer is not None
            else None
        )
        running: Task | None = None

        async def complete(result: LifecycleResult) -> LifecycleResult:
            if running is not None:
                result = result.model_copy(
                    update={
                        "claimed": True,
                        "execution_attempt": running.attempts,
                    }
                )
            if attempt_id is not None and self._attempt_observer is not None:
                await self._attempt_observer.finish(attempt_id, result)
            return result

        gate_result = await self._apply_gates(task, schedule)
        if gate_result is not None:
            return await complete(gate_result)

        plan = await self._budget_planner.plan(task, schedule)

        budget = await self._budgets.reserve(
            task,
            demand=plan.demand,
            context=plan.context,
            lease_for=self._task_lease_for,
        )

        if budget.outcome is BudgetOutcome.DEFER:
            delay = timedelta(seconds=budget.retry_after_seconds or 0.0)
            deferred = await self._queue.defer(
                task.task_id,
                delay=delay,
                reason=budget.reason or "budget deferred",
            )
            return await complete(
                LifecycleResult(
                    outcome=LifecycleOutcome.DEFERRED,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=budget.reason,
                    schedule_score=schedule.score,
                    queue_status=deferred.status,
                )
            )

        if budget.outcome is BudgetOutcome.DENY:
            blocked = await self._queue.block(
                task.task_id,
                reason=budget.reason or "hard budget denied execution",
            )
            return await complete(
                LifecycleResult(
                    outcome=LifecycleOutcome.BLOCKED,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=budget.reason,
                    schedule_score=schedule.score,
                    queue_status=blocked.status,
                )
            )

        reservation_id = (
            budget.reservation.reservation_id if budget.reservation is not None else None
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

            return await complete(
                LifecycleResult(
                    outcome=LifecycleOutcome.STALE,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=f"task could not be claimed: {exc}",
                    schedule_score=schedule.score,
                    queue_status=current.status if current is not None else None,
                )
            )

        if on_claimed is not None:
            with contextlib.suppress(Exception):
                on_claimed(running)

        heartbeat = asyncio.create_task(
            self._heartbeat_loop(
                task_id=running.task_id,
                claim_token=running.claim_token,
                reservation_id=reservation_id,
            )
        )
        execution_task = asyncio.create_task(self._executor.execute(running))

        try:
            execution = await self._supervise_execution(
                execution_task=execution_task,
                heartbeat_task=heartbeat,
            )
        except LeaseHeartbeatError as exc:
            # Continuing target traffic without both live leases would permit
            # duplicate or unbudgeted execution. The supervisor has already
            # cancelled and awaited the worker before reaching this branch.
            if reservation_id is not None:
                with contextlib.suppress(Exception):
                    await self._budgets.commit(reservation_id)

            try:
                failed = await self._queue.fail(
                    running.task_id,
                    claim_token=self._claim_token(running),
                    error=f"lease heartbeat failed: {exc}",
                    retry_delay=timedelta(seconds=0),
                )
            except (KeyError, ValueError) as transition_error:
                return await complete(
                    await self._stale_completion_result(
                        running,
                        schedule,
                        reservation_id=reservation_id,
                        error=transition_error,
                    )
                )

            return await complete(
                LifecycleResult(
                    outcome=(
                        LifecycleOutcome.RETRY
                        if failed.status is TaskStatus.DEFERRED
                        else LifecycleOutcome.FAILED
                    ),
                    task_id=running.task_id,
                    worker=running.worker,
                    action=running.action,
                    reason=failed.last_error,
                    schedule_score=schedule.score,
                    reservation_id=reservation_id,
                    queue_status=failed.status,
                )
            )
        except Exception as exc:
            # Unexpected executor exceptions are treated conservatively:
            # execution may already have touched the target, so a reservation
            # is committed rather than released.
            if reservation_id is not None:
                await self._budgets.commit(reservation_id)

            try:
                failed = await self._queue.fail(
                    running.task_id,
                    claim_token=self._claim_token(running),
                    error=f"executor exception: {type(exc).__name__}: {exc}",
                    retry_delay=None,
                )
            except (KeyError, ValueError) as transition_error:
                return await complete(
                    await self._stale_completion_result(
                        running,
                        schedule,
                        reservation_id=reservation_id,
                        error=transition_error,
                    )
                )

            return await complete(
                LifecycleResult(
                    outcome=LifecycleOutcome.FAILED,
                    task_id=running.task_id,
                    worker=running.worker,
                    action=running.action,
                    reason=failed.last_error,
                    schedule_score=schedule.score,
                    reservation_id=reservation_id,
                    queue_status=failed.status,
                )
            )

        # Once the worker was actually executed, conservatively commit the
        # reserved budget for every structured outcome. This prevents failed
        # tools from being retried indefinitely without consuming their
        # configured recon budget.
        if reservation_id is not None:
            await self._budgets.commit(reservation_id)

        if execution.outcome is WorkerOutcome.SUCCEEDED:
            try:
                succeeded = await self._queue.succeed(
                    running.task_id,
                    claim_token=self._claim_token(running),
                )
            except (KeyError, ValueError) as exc:
                return await complete(
                    await self._stale_completion_result(
                        running,
                        schedule,
                        reservation_id=reservation_id,
                        error=exc,
                    )
                )
            return await complete(
                LifecycleResult(
                    outcome=LifecycleOutcome.SUCCEEDED,
                    task_id=running.task_id,
                    worker=running.worker,
                    action=running.action,
                    schedule_score=schedule.score,
                    reservation_id=reservation_id,
                    queue_status=succeeded.status,
                )
            )

        if execution.outcome is WorkerOutcome.RETRY:
            retry_delay = timedelta(seconds=execution.retry_after_seconds or 0.0)
            try:
                retried = await self._queue.fail(
                    running.task_id,
                    claim_token=self._claim_token(running),
                    error=execution.error or "worker requested retry",
                    retry_delay=retry_delay,
                )
            except (KeyError, ValueError) as exc:
                return await complete(
                    await self._stale_completion_result(
                        running,
                        schedule,
                        reservation_id=reservation_id,
                        error=exc,
                    )
                )

            lifecycle_outcome = (
                LifecycleOutcome.RETRY
                if retried.status is TaskStatus.DEFERRED
                else LifecycleOutcome.FAILED
            )

            return await complete(
                LifecycleResult(
                    outcome=lifecycle_outcome,
                    task_id=running.task_id,
                    worker=running.worker,
                    action=running.action,
                    reason=retried.last_error,
                    schedule_score=schedule.score,
                    reservation_id=reservation_id,
                    queue_status=retried.status,
                )
            )

        try:
            failed = await self._queue.fail(
                running.task_id,
                claim_token=self._claim_token(running),
                error=execution.error or "worker failed",
                retry_delay=None,
            )
        except (KeyError, ValueError) as exc:
            return await complete(
                await self._stale_completion_result(
                    running,
                    schedule,
                    reservation_id=reservation_id,
                    error=exc,
                )
            )

        return await complete(
            LifecycleResult(
                outcome=LifecycleOutcome.FAILED,
                task_id=running.task_id,
                worker=running.worker,
                action=running.action,
                reason=failed.last_error,
                schedule_score=schedule.score,
                reservation_id=reservation_id,
                queue_status=failed.status,
            )
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
                delay = timedelta(seconds=decision.retry_after_seconds or 0.0)
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
                reason = decision.reason or "manual review required"
                case_id = decision.review_case_id
                if case_id is None and self._review_coordinator is not None:
                    gate_name = type(gate).__name__
                    if await self._review_coordinator.approved_for(
                        task=task,
                        gate_name=gate_name,
                        reason=reason,
                    ):
                        continue
                    case_id = await self._review_coordinator.open_case(
                        task=task,
                        gate_name=gate_name,
                        reason=reason,
                    )
                review = await self._queue.send_to_review(
                    task.task_id,
                    reason=(
                        f"{reason}; case={case_id}"
                        if case_id is not None and f"case={case_id}" not in reason
                        else reason
                    ),
                )
                return LifecycleResult(
                    outcome=LifecycleOutcome.REVIEW,
                    task_id=task.task_id,
                    worker=task.worker,
                    action=task.action,
                    reason=(
                        f"{reason}; case={case_id}"
                        if case_id is not None and f"case={case_id}" not in reason
                        else reason
                    ),
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
        claim_token: str | None,
        reservation_id: str | None,
    ) -> None:
        """Keep queue and budget leases alive while a worker is running."""
        interval = self._heartbeat_interval.total_seconds()
        if claim_token is None:
            return

        while True:
            await asyncio.sleep(interval)

            try:
                await self._queue.heartbeat(
                    task_id,
                    claim_token=claim_token,
                    lease_for=self._task_lease_for,
                )
            except asyncio.CancelledError:
                raise
            except (KeyError, ValueError) as exc:
                raise TaskLeaseLostError(f"task lease for {task_id} was lost: {exc}") from exc
            except Exception as exc:
                raise LeaseHeartbeatError(
                    f"task heartbeat failed: {type(exc).__name__}: {exc}"
                ) from exc

            if reservation_id is not None:
                try:
                    await self._budgets.renew(
                        reservation_id,
                        lease_for=self._task_lease_for,
                    )
                except asyncio.CancelledError:
                    raise
                except (KeyError, ValueError) as exc:
                    raise BudgetLeaseLostError(
                        f"budget reservation {reservation_id} was lost: {exc}"
                    ) from exc
                except Exception as exc:
                    raise LeaseHeartbeatError(
                        f"budget heartbeat failed: {type(exc).__name__}: {exc}"
                    ) from exc

    async def _supervise_execution(
        self,
        *,
        execution_task: asyncio.Task[WorkerExecutionResult],
        heartbeat_task: asyncio.Task[None],
    ) -> WorkerExecutionResult:
        """Race worker completion against lease health and fence on failure."""
        try:
            done, _ = await asyncio.wait(
                {execution_task, heartbeat_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if heartbeat_task in done:
                # This normally raises the precise heartbeat failure. A clean
                # return is also unsafe because supervision ended early.
                await heartbeat_task
                raise LeaseHeartbeatError("lease heartbeat stopped unexpectedly")

            try:
                execution = execution_task.result()
            except Exception:
                # A heartbeat failure completing in the same event-loop turn
                # takes precedence because lease ownership is authoritative.
                if heartbeat_task.done():
                    await heartbeat_task
                raise

            await self._stop_heartbeat(heartbeat_task)
            return execution
        finally:
            for task in (execution_task, heartbeat_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                execution_task,
                heartbeat_task,
                return_exceptions=True,
            )

    @staticmethod
    async def _stop_heartbeat(task: asyncio.Task[None]) -> None:
        """Cancel and fully await the background heartbeat task."""
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    @staticmethod
    def _claim_token(task: Task) -> str:
        if task.claim_token is None:
            raise ValueError(f"RUNNING task {task.task_id} has no claim token")
        return task.claim_token

    async def _stale_completion_result(
        self,
        task: Task,
        schedule: ScheduleDecision,
        *,
        reservation_id: str | None,
        error: Exception,
    ) -> LifecycleResult:
        current = await self._queue.get(task.task_id)
        return LifecycleResult(
            outcome=LifecycleOutcome.STALE,
            task_id=task.task_id,
            worker=task.worker,
            action=task.action,
            reason=f"stale execution could not finalize task: {error}",
            schedule_score=schedule.score,
            reservation_id=reservation_id,
            queue_status=current.status if current is not None else None,
        )
