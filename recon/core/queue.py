"""Persistent-task abstractions for the Night Scout core.

The queue owns task lifecycle semantics, while persistence is delegated to a
TaskStore implementation. This keeps the core independent from SQLite and lets
the future storage layer provide durable, transactional queue semantics without
changing the scheduler, router, or workers.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_task_id() -> str:
    """Create a globally unique task identifier."""
    return f"tsk_{uuid4().hex}"


class TaskStatus(StrEnum):
    """Lifecycle states understood by the queue and future scheduler."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DEFERRED = "DEFERRED"

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    BLOCKED = "BLOCKED"
    REVIEW = "REVIEW"


TERMINAL_TASK_STATUSES = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.BLOCKED,
    }
)


class Task(BaseModel):
    """A normalized unit of work scheduled from an event.

    The queue stores references to events rather than embedding full Event
    objects. Workers will later load the referenced event from the storage
    layer, avoiding duplicated event data inside the queue.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
    )

    task_id: str = Field(default_factory=new_task_id)

    worker: str
    action: str
    input_event_id: str
    input_identity_key: str | None = None

    branch_id: str | None = None

    # Persist routing provenance so explainability survives process restarts.
    route_rule_id: str | None = None
    routing_reason: str | None = None

    status: TaskStatus = TaskStatus.PENDING
    priority: float = 0.0

    attempts: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1)

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    available_at: datetime = Field(default_factory=utc_now)

    started_at: datetime | None = None
    finished_at: datetime | None = None
    lease_expires_at: datetime | None = None

    last_error: str | None = None

    # Ephemeral execution hints are resolved from current convergence state
    # immediately before worker dispatch. Durable queue provenance remains
    # independent from the intelligence layer.
    search_tier: str | None = None
    candidate_limit_hint: int | None = Field(default=None, ge=1)

    @field_validator("worker", "action", "input_event_id")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        """Reject blank task routing fields."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("route_rule_id", "routing_reason")
    @classmethod
    def normalize_optional_routing_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("input_identity_key")
    @classmethod
    def normalize_optional_identity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("search_tier")
    @classmethod
    def normalize_search_tier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().upper() or None

    @field_validator(
        "created_at",
        "updated_at",
        "available_at",
        "started_at",
        "finished_at",
        "lease_expires_at",
    )
    @classmethod
    def timestamps_must_be_timezone_aware(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        """Require timezone-aware timestamps whenever a timestamp is present."""
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Task:
        """Protect basic lifecycle invariants."""
        if self.attempts > self.max_attempts:
            raise ValueError("attempts cannot exceed max_attempts")

        if self.finished_at is not None and self.status not in TERMINAL_TASK_STATUSES:
            raise ValueError("finished_at is only valid for terminal task states")

        if self.status == TaskStatus.RUNNING and self.started_at is None:
            raise ValueError("RUNNING tasks require started_at")

        if self.status != TaskStatus.RUNNING and self.lease_expires_at is not None:
            raise ValueError("only RUNNING tasks may hold a lease")

        return self

    @property
    def dedupe_key(self) -> str:
        """Return the stable key used to suppress duplicate logical work.

        A worker may expose more than one action for the same event, so action
        is deliberately part of the key.
        """
        logical_input = self.input_identity_key or self.input_event_id
        return f"{self.worker}:{self.action}:{logical_input}"

    @property
    def is_terminal(self) -> bool:
        """Return whether no further automatic state transition is expected."""
        return self.status in TERMINAL_TASK_STATUSES

    @property
    def retries_remaining(self) -> int:
        """Return how many execution attempts remain."""
        return max(self.max_attempts - self.attempts, 0)


class TaskStore(Protocol):
    """Persistence contract used by TaskQueue.

    A future SQLiteTaskStore should implement this protocol transactionally.
    """

    async def put(self, task: Task) -> bool:
        """Insert a task.

        Return False when an active task with the same dedupe key already
        exists and no new task was inserted.
        """
        ...

    async def get(self, task_id: str) -> Task | None:
        """Return a task by identifier."""
        ...

    async def save(self, task: Task) -> None:
        """Persist an existing task."""
        ...

    async def claim(
        self,
        task_id: str,
        *,
        now: datetime,
        lease_expires_at: datetime,
    ) -> Task:
        """Atomically claim one ready task or raise ValueError."""
        ...

    async def ready(
        self,
        *,
        now: datetime,
        limit: int | None = None,
        fair: bool = False,
    ) -> list[Task]:
        """Return runnable tasks ordered for scheduler consumption."""
        ...

    async def active_by_dedupe_key(self, dedupe_key: str) -> Task | None:
        """Return an unfinished logical duplicate, if one exists."""
        ...

    async def all(self) -> list[Task]:
        """Return all tasks for diagnostics and tests."""
        ...


class InMemoryTaskStore:
    """Concurrency-safe development backend for TaskStore.

    This implementation is intentionally simple. It validates queue behavior
    before the durable SQLite storage layer is introduced.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._active_keys: dict[str, str] = {}
        self._known_keys: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def put(self, task: Task) -> bool:
        async with self._lock:
            if task.dedupe_key in self._known_keys:
                return False
            existing_id = self._active_keys.get(task.dedupe_key)
            if existing_id is not None:
                existing = self._tasks.get(existing_id)
                if existing is not None and not existing.is_terminal:
                    return False
                self._active_keys.pop(task.dedupe_key, None)

            stored = task.model_copy(deep=True)
            self._tasks[stored.task_id] = stored
            self._known_keys[stored.dedupe_key] = stored.task_id

            if not stored.is_terminal:
                self._active_keys[stored.dedupe_key] = stored.task_id

            return True

    async def get(self, task_id: str) -> Task | None:
        async with self._lock:
            task = self._tasks.get(task_id)
            return task.model_copy(deep=True) if task is not None else None

    async def save(self, task: Task) -> None:
        async with self._lock:
            if task.task_id not in self._tasks:
                raise KeyError(f"unknown task_id: {task.task_id}")

            previous = self._tasks[task.task_id]

            if self._active_keys.get(previous.dedupe_key) == task.task_id:
                self._active_keys.pop(previous.dedupe_key, None)

            stored = task.model_copy(deep=True)
            self._tasks[stored.task_id] = stored

            if not stored.is_terminal:
                active_id = self._active_keys.get(stored.dedupe_key)
                if active_id is not None and active_id != stored.task_id:
                    raise ValueError(
                        f"active task already exists for dedupe key: {stored.dedupe_key}"
                    )
                self._active_keys[stored.dedupe_key] = stored.task_id

    async def claim(
        self,
        task_id: str,
        *,
        now: datetime,
        lease_expires_at: datetime,
    ) -> Task:
        """Atomically transition a ready in-memory task to RUNNING."""
        async with self._lock:
            try:
                current = self._tasks[task_id]
            except KeyError as exc:
                raise KeyError(f"unknown task_id: {task_id}") from exc

            if current.status not in {TaskStatus.PENDING, TaskStatus.DEFERRED}:
                raise ValueError(
                    f"task {task_id} is not claimable from {current.status}"
                )
            if current.available_at > now:
                raise ValueError(f"task {task_id} is not available yet")
            if current.attempts >= current.max_attempts:
                raise ValueError(f"task {task_id} has exhausted its retry budget")

            claimed = current.model_copy(
                update={
                    "attempts": current.attempts + 1,
                    "started_at": now,
                    "finished_at": None,
                    "status": TaskStatus.RUNNING,
                    "lease_expires_at": lease_expires_at,
                    "updated_at": now,
                    "last_error": None,
                }
            )
            self._tasks[task_id] = claimed
            return claimed.model_copy(deep=True)

    async def ready(
        self,
        *,
        now: datetime,
        limit: int | None = None,
        fair: bool = False,
    ) -> list[Task]:
        async with self._lock:
            candidates = [
                task
                for task in self._tasks.values()
                if task.status in {TaskStatus.PENDING, TaskStatus.DEFERRED}
                and task.available_at <= now
            ]

            def priority_key(task: Task) -> tuple[float, datetime, datetime, str]:
                return (
                    -task.priority,
                    task.available_at,
                    task.created_at,
                    task.task_id,
                )
            candidates.sort(key=priority_key)

            if limit is not None and fair:
                top_count, oldest_count, exploration_count, tail_count = (
                    fair_lane_limits(limit)
                )
                lanes = (
                    candidates[:top_count],
                    sorted(candidates, key=lambda task: (task.created_at, task.task_id))[
                        :oldest_count
                    ],
                    [
                        task
                        for task in candidates
                        if "exploration"
                        in " ".join(
                            filter(
                                None,
                                (
                                    task.action,
                                    task.route_rule_id or "",
                                    task.routing_reason or "",
                                ),
                            )
                        ).lower()
                    ][:exploration_count],
                    sorted(
                        candidates,
                        key=lambda task: (
                            task.priority,
                            task.created_at,
                            task.task_id,
                        ),
                    )[:tail_count],
                    candidates,
                )
                selected: list[Task] = []
                seen: set[str] = set()
                for lane in lanes:
                    for task in lane:
                        if task.task_id in seen:
                            continue
                        seen.add(task.task_id)
                        selected.append(task)
                        if len(selected) >= limit:
                            break
                    if len(selected) >= limit:
                        break
                candidates = selected
            elif limit is not None:
                candidates = candidates[:limit]

            return [task.model_copy(deep=True) for task in candidates]

    async def active_by_dedupe_key(self, dedupe_key: str) -> Task | None:
        async with self._lock:
            task_id = self._active_keys.get(dedupe_key)
            if task_id is None:
                return None

            task = self._tasks.get(task_id)
            if task is None or task.is_terminal:
                self._active_keys.pop(dedupe_key, None)
                return None

            return task.model_copy(deep=True)

    async def all(self) -> list[Task]:
        async with self._lock:
            return [task.model_copy(deep=True) for task in self._tasks.values()]


def fair_lane_limits(limit: int) -> tuple[int, int, int, int]:
    """Split a bounded shortlist across priority, age and diversity lanes."""
    if limit <= 0:
        return (0, 0, 0, 0)
    top = max(1, limit // 2)
    oldest = (limit - top) // 2
    exploration = (limit - top - oldest) // 2
    tail = limit - top - oldest - exploration
    return top, oldest, exploration, tail


class TaskQueue:
    """High-level task lifecycle API used by router, scheduler, and lifecycle.

    Responsibilities are deliberately limited to queue semantics:
    - deduplication
    - task state transitions
    - retries / deferrals
    - worker leases
    - recovery of interrupted RUNNING tasks

    Scoring remains the scheduler's job. Authorization remains the policy
    layer's job. Durable persistence remains the storage layer's job.
    """

    def __init__(self, store: TaskStore) -> None:
        self._store = store
        self._transition_lock = asyncio.Lock()

    async def enqueue(self, task: Task) -> bool:
        """Add a task unless the same logical work is already active."""
        if task.status not in {TaskStatus.PENDING, TaskStatus.DEFERRED}:
            raise ValueError("newly enqueued tasks must be PENDING or DEFERRED")

        task.updated_at = utc_now()
        return await self._store.put(task)

    async def enqueue_many(self, tasks: Iterable[Task]) -> int:
        """Enqueue tasks and return the number of newly inserted tasks."""
        inserted = 0
        for task in tasks:
            if await self.enqueue(task):
                inserted += 1
        return inserted

    async def get(self, task_id: str) -> Task | None:
        """Return a task by identifier."""
        return await self._store.get(task_id)

    async def ready(
        self,
        *,
        limit: int | None = None,
        fair: bool = False,
    ) -> list[Task]:
        """Return tasks that are eligible for scheduler consideration."""
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1")
        return await self._store.ready(now=utc_now(), limit=limit, fair=fair)

    async def claim(
        self,
        task_id: str,
        *,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> Task:
        """Atomically move a ready task into RUNNING state.

        A lease allows lifecycle recovery after a worker/process crashes.
        """
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        now = utc_now()
        return await self._store.claim(
            task_id,
            now=now,
            lease_expires_at=now + lease_for,
        )

    async def heartbeat(
        self,
        task_id: str,
        *,
        lease_for: timedelta = timedelta(minutes=5),
    ) -> Task:
        """Extend the lease of a running worker task."""
        if lease_for <= timedelta(0):
            raise ValueError("lease_for must be positive")

        async with self._transition_lock:
            task = await self._require(task_id)

            if task.status != TaskStatus.RUNNING:
                raise ValueError("only RUNNING tasks can be heartbeated")

            now = utc_now()
            task.lease_expires_at = now + lease_for
            task.updated_at = now

            await self._store.save(task)
            return task

    async def succeed(self, task_id: str) -> Task:
        """Mark a running task as successfully completed."""
        return await self._finish(task_id, status=TaskStatus.SUCCEEDED)

    async def fail(
        self,
        task_id: str,
        *,
        error: str,
        retry_delay: timedelta | None = None,
    ) -> Task:
        """Record a failed execution and retry it when budget remains.

        If retry_delay is provided and retries remain, the task becomes
        DEFERRED. Otherwise it becomes terminal FAILED.
        """
        normalized_error = error.strip() or "unknown error"

        async with self._transition_lock:
            task = await self._require_running(task_id)
            now = utc_now()

            task.last_error = normalized_error
            task.lease_expires_at = None
            task.updated_at = now

            if retry_delay is not None and task.attempts < task.max_attempts:
                if retry_delay < timedelta(0):
                    raise ValueError("retry_delay cannot be negative")

                task.status = TaskStatus.DEFERRED
                task.available_at = now + retry_delay
                task.started_at = None
                task.finished_at = None
            else:
                task.status = TaskStatus.FAILED
                task.finished_at = now

            await self._store.save(task)
            return task

    async def defer(
        self,
        task_id: str,
        *,
        delay: timedelta,
        reason: str | None = None,
    ) -> Task:
        """Move a pending/deferred task into a later runnable window."""
        if delay < timedelta(0):
            raise ValueError("delay cannot be negative")

        async with self._transition_lock:
            task = await self._require(task_id)

            if task.status not in {TaskStatus.PENDING, TaskStatus.DEFERRED}:
                raise ValueError("only PENDING or DEFERRED tasks can be deferred")

            now = utc_now()
            task.status = TaskStatus.DEFERRED
            task.available_at = now + delay
            task.updated_at = now

            if reason:
                task.last_error = reason.strip() or None

            await self._store.save(task)
            return task

    async def block(self, task_id: str, *, reason: str) -> Task:
        """Terminate a task because policy or scope forbids execution."""
        return await self._finish(
            task_id,
            status=TaskStatus.BLOCKED,
            error=reason,
            require_running=False,
        )

    async def send_to_review(self, task_id: str, *, reason: str) -> Task:
        """Pause automatic execution pending human review."""
        async with self._transition_lock:
            task = await self._require(task_id)

            if task.is_terminal:
                raise ValueError("terminal tasks cannot be sent to review")

            now = utc_now()
            task.lease_expires_at = None
            task.status = TaskStatus.REVIEW
            task.started_at = None
            task.finished_at = None
            task.updated_at = now
            task.last_error = reason.strip() or "manual review required"

            await self._store.save(task)
            return task

    async def release_review(
        self,
        task_id: str,
        *,
        delay: timedelta = timedelta(seconds=0),
    ) -> Task:
        """Return a manually approved REVIEW task to the runnable queue."""
        if delay < timedelta(0):
            raise ValueError("delay cannot be negative")

        async with self._transition_lock:
            task = await self._require(task_id)

            if task.status != TaskStatus.REVIEW:
                raise ValueError("only REVIEW tasks can be released")

            now = utc_now()
            task.available_at = now + delay
            task.updated_at = now
            task.last_error = None
            task.status = (
                TaskStatus.PENDING if delay == timedelta(0) else TaskStatus.DEFERRED
            )
            task.started_at = None

            await self._store.save(task)
            return task

    async def cancel(self, task_id: str, *, reason: str | None = None) -> Task:
        """Cancel any unfinished task."""
        return await self._finish(
            task_id,
            status=TaskStatus.CANCELLED,
            error=reason,
            require_running=False,
        )

    async def recover_expired_leases(
        self,
        *,
        retry_delay: timedelta = timedelta(seconds=0),
    ) -> list[Task]:
        """Recover RUNNING tasks whose worker lease expired.

        This provides the queue-side primitive that lifecycle.py can call at
        startup or periodically after process crashes.
        """
        if retry_delay < timedelta(0):
            raise ValueError("retry_delay cannot be negative")

        recovered: list[Task] = []
        now = utc_now()

        async with self._transition_lock:
            for task in await self._store.all():
                if (
                    task.status != TaskStatus.RUNNING
                    or task.lease_expires_at is None
                    or task.lease_expires_at > now
                ):
                    continue

                task.lease_expires_at = None
                task.updated_at = now
                task.last_error = "worker lease expired"

                if task.attempts < task.max_attempts:
                    task.status = TaskStatus.DEFERRED
                    task.started_at = None
                    task.available_at = now + retry_delay
                    task.finished_at = None
                else:
                    task.status = TaskStatus.FAILED
                    task.finished_at = now

                await self._store.save(task)
                recovered.append(task)

        return recovered

    async def _finish(
        self,
        task_id: str,
        *,
        status: TaskStatus,
        error: str | None = None,
        require_running: bool = True,
    ) -> Task:
        if status not in TERMINAL_TASK_STATUSES:
            raise ValueError("_finish requires a terminal task status")

        async with self._transition_lock:
            task = await self._require(task_id)

            if require_running and task.status != TaskStatus.RUNNING:
                raise ValueError("task must be RUNNING before completion")

            if task.is_terminal:
                raise ValueError("task is already terminal")

            now = utc_now()
            task.lease_expires_at = None
            task.status = status
            task.updated_at = now
            task.finished_at = now

            if error is not None:
                task.last_error = error.strip() or None

            await self._store.save(task)
            return task

    async def _require(self, task_id: str) -> Task:
        task = await self._store.get(task_id)
        if task is None:
            raise KeyError(f"unknown task_id: {task_id}")
        return task

    async def _require_running(self, task_id: str) -> Task:
        task = await self._require(task_id)
        if task.status != TaskStatus.RUNNING:
            raise ValueError(f"task {task_id} is not RUNNING")
        return task
