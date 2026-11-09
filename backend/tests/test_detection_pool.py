import asyncio
import multiprocessing
import time

import pytest
from gateway.detection import DetectorError, DetectorPool, Finding


class FakeDetector:
    def analyze(self, messages, dictionaries):
        value = messages[0]["content"]
        if value == "hang":
            time.sleep(10)
        if value == "error":
            raise ValueError("raw secret must not escape")
        if value == "file":
            with open(__file__):
                pass
        if value == "network":
            import socket

            socket.getaddrinfo("example.com", 443)
        return [Finding(0, 0, len(value), "EMAIL", 1, "fake")]


class BrokenDetector:
    def __init__(self):
        raise ValueError("unavailable raw details")


def message(value="ok"):
    return [{"role": "user", "content": value}]


async def wait_until(predicate):
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_pool_loads_two_workers_returns_findings_and_reaps_on_close():
    pool = DetectorPool(detector_factory=FakeDetector)
    await pool.start()
    assert pool.ready and len(pool._slots) == 2
    assert (await pool.analyze(message(), []))[0].recognizer_id == "fake"
    processes = [slot.process for slot in pool._slots]
    await pool.close()
    assert not pool.ready and all(not p.is_alive() for p in processes)


@pytest.mark.asyncio
async def test_execution_timeout_kills_reaps_replaces_and_does_not_reuse_pipe():
    pool = DetectorPool(workers=1, timeout_seconds=0.1, detector_factory=FakeDetector)
    await pool.start()
    old = pool._slots[0].process
    old_pipe = pool._slots[0].connection
    try:
        with pytest.raises(DetectorError) as error:
            await pool.analyze(message("hang"), [])
        assert error.value.code == "detector_timeout"
        assert not old.is_alive()
        await wait_until(lambda: pool.ready)
        assert pool._slots[0].process.pid != old.pid and pool._slots[0].connection is not old_pipe
        assert await pool.analyze(message(), [])
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_running_cancellation_reaps_before_return_and_releases_slot():
    pool = DetectorPool(workers=1, detector_factory=FakeDetector)
    await pool.start()
    old = pool._slots[0].process
    task = asyncio.create_task(pool.analyze(message("hang"), []))
    await wait_until(lambda: bool(pool._slots[0].busy))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not old.is_alive()
    await wait_until(lambda: pool.ready)
    assert await pool.analyze(message(), [])
    await pool.close()


@pytest.mark.asyncio
async def test_bounded_queue_wait_deadline_and_queued_cancel_free_capacity():
    pool = DetectorPool(
        workers=1,
        queue_size=1,
        timeout_seconds=0.6,
        queue_timeout_seconds=0.08,
        detector_factory=FakeDetector,
    )
    await pool.start()
    running = asyncio.create_task(pool.analyze(message("hang"), []))
    await wait_until(lambda: bool(pool._slots[0].busy))
    waiting = asyncio.create_task(pool.analyze(message(), []))
    await wait_until(lambda: len(pool._pending) == 1)
    with pytest.raises(DetectorError) as error:
        await pool.analyze(message(), [])
    assert error.value.code == "detector_queue_full" and error.value.status_code == 429
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert len(pool._pending) == 0
    with pytest.raises(DetectorError) as error:
        await pool.analyze(message(), [])
    assert error.value.code == "detector_queue_timeout"
    assert len(pool._pending) == 0
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    await pool.close()


@pytest.mark.asyncio
async def test_safe_worker_failure_and_failed_startup_readiness():
    pool = DetectorPool(workers=1, detector_factory=FakeDetector)
    await pool.start()
    try:
        with pytest.raises(DetectorError) as error:
            await pool.analyze(message("error"), [])
        assert str(error.value) == "detector_failed"
        assert await pool.analyze(message(), [])
    finally:
        await pool.close()
    broken = DetectorPool(workers=1, detector_factory=BrokenDetector)
    await broken.start()
    assert not broken.ready
    with pytest.raises(DetectorError):
        await broken.analyze(message(), [])
    await broken.close()
    assert not any(
        p.is_alive() and p.name.startswith("gateway-detector") for p in multiprocessing.active_children()
    )


@pytest.mark.asyncio
async def test_inference_cannot_open_files_or_network():
    pool = DetectorPool(workers=1, detector_factory=FakeDetector)
    await pool.start()
    try:
        for value in ("file", "network"):
            with pytest.raises(DetectorError, match="detector_failed"):
                await pool.analyze(message(value), [])
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_real_models_preloaded_and_offline_in_killable_workers():
    pool = DetectorPool()
    await pool.start()
    try:
        assert pool.ready
        text = "Контакт person@example.com +7 (912) 345-67-89 fd00::1 db.internal"
        found = await pool.analyze(message(text), [])
        assert {f.category for f in found} >= {"EMAIL", "PHONE", "IP_ADDRESS", "INTERNAL_HOSTNAME"}
    finally:
        await pool.close()
