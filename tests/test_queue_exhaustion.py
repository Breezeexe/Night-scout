from __future__ import annotations

import pytest

from recon.core.queue import InMemoryTaskStore, Task, TaskQueue, TaskStatus


@pytest.mark.asyncio
async def test_exhausted_active_task_is_not_ready_or_next_ready() -> None:
    store = InMemoryTaskStore()
    queue = TaskQueue(store)
    exhausted = Task(
        worker="probe",
        action="scan",
        input_event_id="evt_exhausted",
        status=TaskStatus.DEFERRED,
        attempts=3,
        max_attempts=3,
    )
    assert await queue.enqueue(exhausted)

    assert await queue.ready() == []
    assert await store.next_ready_at() is None
