import asyncio
import logging
import math
import multiprocessing
import sys
import time
from collections import deque
from dataclasses import dataclass, field

from .analyzer import Detector
from .types import DetectorError, validate_messages


def _child(connection, factory):
    logging.disable(logging.CRITICAL)
    try:
        detector = factory()
        connection.send(("ready", None))
    except Exception:  # noqa: BLE001 - send only a safe startup code across the process boundary
        connection.send(("error", "detector_initialization_failed"))
        connection.close()
        return
    inference = [False]

    def deny_inference_io(event, args):
        if inference[0] and (event == "open" or event.startswith("socket.")):
            raise RuntimeError("inference_io_forbidden")

    sys.addaudithook(deny_inference_io)
    try:
        while True:
            item = connection.recv()
            if item is None:
                break
            try:
                inference[0] = True
                findings = detector.analyze(*item)
                result = ("ok", findings)
            except DetectorError as error:
                result = ("error", error.code)
            except Exception:  # noqa: BLE001 - recognizer exceptions may contain original text
                result = ("error", "detector_failed")
            finally:
                inference[0] = False
            connection.send(result)
            item = findings = result = None
    except (EOFError, OSError):
        pass
    finally:
        connection.close()


@dataclass(eq=False)
class _Job:
    messages: list[dict]
    dictionaries: list[dict]
    result: asyncio.Future
    started: asyncio.Event = field(default_factory=asyncio.Event)
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False


@dataclass
class _Slot:
    process: object = None
    connection: object = None
    healthy: bool = False
    busy: bool = False
    task: object = None


class DetectorPool:
    """Bounded queue and dedicated killable processes; cancelled IPC is never reused."""

    def __init__(
        self,
        settings=None,
        *,
        workers=2,
        queue_size=6,
        timeout_seconds=5,
        queue_timeout_seconds=5,
        startup_timeout_seconds=45,
        detector_factory=Detector,
    ):
        if settings is not None:
            workers, queue_size = settings.detector_workers, settings.detector_queue_size
            timeout_seconds = settings.detector_timeout_seconds
            queue_timeout_seconds = settings.detector_queue_timeout_seconds
        if (
            not 1 <= workers <= 2
            or not 1 <= queue_size <= 6
            or any(
                not math.isfinite(value) or not 0 < value <= 5
                for value in (timeout_seconds, queue_timeout_seconds)
            )
        ):
            raise ValueError("invalid_detector_pool_configuration")
        self.workers, self.queue_size = workers, queue_size
        self.timeout_seconds, self.queue_timeout_seconds = timeout_seconds, queue_timeout_seconds
        self.startup_timeout_seconds, self.factory = startup_timeout_seconds, detector_factory
        self._context = multiprocessing.get_context("spawn")
        self._slots = [_Slot() for _ in range(workers)]
        self._pending = deque()
        self._available = asyncio.Event()
        self._closed = True

    @property
    def ready(self):
        return not self._closed and any(
            s.healthy and s.process is not None and s.process.is_alive() for s in self._slots
        )

    async def _reap(self, slot):
        slot.healthy = False
        process, connection = slot.process, slot.connection
        if process is not None:
            if process.is_alive():
                process.terminate()
            await asyncio.to_thread(process.join, 1)
            if process.is_alive():
                process.kill()
                await asyncio.to_thread(process.join, 1)
            if process.is_alive():
                raise DetectorError("detector_reap_failed")
        if connection is not None:
            connection.close()

    async def _spawn(self, slot):
        if self._closed:
            return False
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=_child, args=(child, self.factory), name="gateway-detector", daemon=True
        )
        slot.process, slot.connection, slot.healthy = process, parent, False
        try:
            process.start()
            child.close()
            deadline = time.monotonic() + self.startup_timeout_seconds
            while time.monotonic() < deadline and not self._closed:
                if parent.poll():
                    status, _ = parent.recv()
                    if status == "ready" and process.is_alive():
                        slot.healthy = True
                        return True
                    break
                if not process.is_alive():
                    break
                await asyncio.sleep(0.01)
        except (EOFError, OSError):
            pass
        finally:
            child.close()
        await self._reap(slot)
        return False

    async def start(self):
        if not self._closed:
            return
        self._closed = False
        try:
            await asyncio.gather(*(self._spawn(slot) for slot in self._slots))
        except BaseException:
            await self.close()
            raise
        for slot in self._slots:
            if slot.healthy:
                slot.task = asyncio.create_task(self._run(slot))

    async def _run(self, slot):
        job = None
        try:
            while not self._closed:
                while not self._pending and not self._closed:
                    self._available.clear()
                    await self._available.wait()
                if self._closed:
                    break
                job = self._pending.popleft()
                if job.cancelled:
                    job.finished.set()
                    continue
                slot.busy = True
                job.started.set()
                deadline, replacement, response = time.monotonic() + self.timeout_seconds, False, None
                try:
                    # Sending can fill an OS pipe for a large payload; keep it outside the event loop.
                    sending = asyncio.create_task(
                        asyncio.to_thread(slot.connection.send, (job.messages, job.dictionaries))
                    )
                    while not self._closed:
                        if job.cancelled:
                            replacement = True
                            break
                        if time.monotonic() >= deadline:
                            response, replacement = ("error", "detector_timeout"), True
                            break
                        if sending.done():
                            sending.result()
                        if sending.done() and slot.connection.poll():
                            response = slot.connection.recv()
                            break
                        if not slot.process.is_alive():
                            response, replacement = ("error", "detector_unavailable"), True
                            break
                        await asyncio.sleep(0.005)
                except (EOFError, OSError):
                    response, replacement = ("error", "detector_unavailable"), True
                if replacement or self._closed:
                    await self._reap(slot)
                # Reaping closes the receiver and releases any blocked OS pipe send.
                await asyncio.gather(sending, return_exceptions=True)
                if not job.result.done():
                    if response is not None and response[0] == "ok" and not job.cancelled:
                        job.result.set_result(response[1])
                    else:
                        code = response[1] if response else "detector_unavailable"
                        job.result.set_exception(DetectorError(code))
                job.finished.set()
                slot.busy = False
                job = None
                if replacement and not self._closed and not await self._spawn(slot):
                    break
        finally:
            if job is not None:
                await self._reap(slot)
                if not job.result.done():
                    job.result.set_exception(DetectorError("detector_unavailable"))
                job.finished.set()
            slot.busy = False

    async def analyze(self, messages, dictionaries):
        validate_messages(messages)
        if not self.ready:
            raise DetectorError("detector_unavailable")
        if len(self._pending) >= self.queue_size:
            raise DetectorError("detector_queue_full", 429)
        job = _Job(messages, dictionaries, asyncio.get_running_loop().create_future())
        self._pending.append(job)
        self._available.set()
        try:
            try:
                async with asyncio.timeout(self.queue_timeout_seconds):
                    await job.started.wait()
            except TimeoutError:
                if not job.started.is_set():
                    self._pending.remove(job)
                    job.finished.set()
                    raise DetectorError("detector_queue_timeout") from None
            return await asyncio.shield(job.result)
        except asyncio.CancelledError:
            job.cancelled = True
            if job in self._pending:
                self._pending.remove(job)
                job.finished.set()
            cleanup = asyncio.create_task(job.finished.wait())
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    continue
            raise
        finally:
            # Retrieve failed results after cancellation to avoid unhandled Future diagnostics.
            if job.result.done() and not job.result.cancelled():
                job.result.exception()

    async def close(self):
        self._closed = True
        while self._pending:
            job = self._pending.popleft()
            job.finished.set()
            job.started.set()
            if not job.result.done():
                job.result.set_exception(DetectorError("detector_unavailable"))
        self._available.set()
        # Closing pipes and killing children unblocks an in-progress send before awaiting dispatchers.
        await asyncio.gather(*(self._reap(slot) for slot in self._slots if slot.process is not None))
        await asyncio.gather(
            *(slot.task for slot in self._slots if slot.task is not None), return_exceptions=True
        )
