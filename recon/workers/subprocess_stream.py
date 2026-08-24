"""Cancellation-safe streaming helpers for subprocess adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator


async def stream_process_stdout(
    process: asyncio.subprocess.Process,
    *,
    timeout_seconds: float,
) -> AsyncIterator[bytes]:
    """Yield stdout lines without leaking the process timeout into consumers.

    An ``asyncio.timeout`` context must not remain open across ``yield``. If it
    does, time spent by the consuming worker publishing a parsed result can
    cancel that worker at an unrelated await point. Each timed I/O operation is
    therefore completed before control is yielded to the consumer.
    """
    if process.stdout is None:
        raise ValueError("subprocess stdout pipe is not available")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while True:
        if process.returncode is not None:
            raw_line = await process.stdout.readline()
        else:
            if loop.time() >= deadline:
                raise TimeoutError
            async with asyncio.timeout_at(deadline):
                raw_line = await process.stdout.readline()
        if not raw_line:
            break
        yield raw_line

    if process.returncode is None:
        if loop.time() >= deadline:
            raise TimeoutError
        async with asyncio.timeout_at(deadline):
            await process.wait()


def completed_process_returncode(process: asyncio.subprocess.Process) -> int:
    """Return a subprocess code after ``stream_process_stdout`` completed."""
    returncode = process.returncode
    if returncode is None:
        raise RuntimeError("subprocess stream completed before the process exited")
    return returncode
