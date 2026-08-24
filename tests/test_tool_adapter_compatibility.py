from __future__ import annotations

import asyncio
import sys

import pytest

from recon.workers.crawler import (
    KatanaBackend,
    KatanaPacing,
    _is_katana_invocation_failure,
)
from recon.workers.subprocess_stream import stream_process_stdout
from recon.workers.tls import TlsxBackend, _is_tlsx_invocation_failure


def test_tlsx_uses_default_json_certificate_fields_without_probe_conflicts() -> None:
    command = TlsxBackend().command_for()

    assert command[1:5] == ("-j", "-silent", "-nc", "-duc")
    for incompatible_probe in (
        "-san",
        "-cn",
        "-so",
        "-tv",
        "-cipher",
        "-hash",
        "-se",
        "-tps",
    ):
        assert incompatible_probe not in command


def test_katana_maps_both_known_file_sources_to_supported_all_enum() -> None:
    command = KatanaBackend().command_for(
        pacing=KatanaPacing(host_rps=1),
    )

    known_files_index = command.index("-kf")
    assert command[known_files_index + 1] == "all"
    assert "robotstxt,sitemapxml" not in command


def test_cli_validation_failures_are_non_retryable() -> None:
    assert _is_katana_invocation_failure(
        2,
        'stdout=invalid value "robotstxt,sitemapxml" for flag -kf',
    )
    assert _is_tlsx_invocation_failure(
        1,
        'cause="san or cn flag cannot be used with other probes" '
        'chain="could not validate options; could not create runner"',
    )


def test_runtime_backend_failures_remain_retryable() -> None:
    assert not _is_katana_invocation_failure(1, "connection reset by peer")
    assert not _is_tlsx_invocation_failure(1, "remote handshake timeout")


@pytest.mark.asyncio
async def test_process_timeout_does_not_cancel_slow_result_consumer() -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        (
            "import sys, time; "
            "sys.stdout.write('ready\\none\\ntwo\\n'); "
            "sys.stdout.flush(); time.sleep(1)"
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdout is not None
    assert await asyncio.wait_for(process.stdout.readline(), timeout=1) == b"ready\n"
    stream = stream_process_stdout(process, timeout_seconds=0.05)
    try:
        assert await anext(stream) == b"one\n"
        await asyncio.sleep(0.08)
        current = asyncio.current_task()
        assert current is not None and current.cancelling() == 0
        with pytest.raises(TimeoutError):
            await anext(stream)
        await asyncio.sleep(0)
    finally:
        await stream.aclose()
        if process.returncode is None:
            process.terminate()
            await process.wait()


@pytest.mark.asyncio
async def test_completed_process_buffer_survives_slow_result_consumer() -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "print('ready', flush=True); print('one', flush=True); print('two', flush=True)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdout is not None
    assert await asyncio.wait_for(process.stdout.readline(), timeout=1) == b"ready\n"
    stream = stream_process_stdout(process, timeout_seconds=0.05)
    try:
        assert await anext(stream) == b"one\n"
        await process.wait()
        await asyncio.sleep(0.08)
        assert await anext(stream) == b"two\n"
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
    finally:
        await stream.aclose()
