import asyncio
import json
import logging
import time
from functools import partial
from uuid import UUID

import anyio
import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from gateway import audit
from gateway.control import Admin
from gateway.detection import DetectorError, protect
from gateway.identity import authenticate
from gateway.protocol import GatewayError, load_json, parse_chat, wire_bytes
from gateway.provider import client_for, sse_frames, validate_completion

router = APIRouter()


async def db_call(func, *args, **kwargs):
    try:
        return await anyio.to_thread.run_sync(partial(func, *args, **kwargs))
    except GatewayError:
        raise
    except Exception:  # noqa: BLE001 - sanitize SQL/driver failures at the persistence boundary
        raise GatewayError(503, "required_storage_unavailable") from None


class Inflight:
    def __init__(self):
        self.users = {}
        self.total = 0

    def acquire(self, user):
        if self.total >= 8 or self.users.get(user, 0) >= 2:
            raise GatewayError(429, "request_limit_reached")
        self.total += 1
        self.users[user] = self.users.get(user, 0) + 1

    def release(self, user):
        self.total -= 1
        self.users[user] -= 1
        if not self.users[user]:
            del self.users[user]


class ObservedStream(StreamingResponse):
    def __init__(self, content, observed, cleanup, **kwargs):
        super().__init__(content, **kwargs)
        self.observed = observed
        self.cleanup = cleanup

    async def stream_response(self, send):
        try:
            await send(
                {"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers}
            )
            async for chunk in self.body_iterator:
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
                if (
                    chunk.startswith(b"data: ")
                    and chunk != b"data: [DONE]\n\n"
                    and not chunk.startswith(b'data: {"error":')
                ):
                    self.observed["chunks"] += 1
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    await self.body_iterator.aclose()
                finally:
                    await self.cleanup()


async def body_bytes(request):
    if request.headers.get("content-encoding", "identity") != "identity":
        raise GatewayError(400, "invalid_request")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise GatewayError(415, "invalid_content_type")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > request.app.state.settings.max_request_bytes:
            raise GatewayError(413, "request_too_large")
    return bytes(data)


@router.get("/v1/models")
async def models(request: Request):
    await db_call(authenticate, request)
    snap = await db_call(audit.snapshot, request.app.state.engine)
    return {
        "object": "list",
        "data": [
            {"id": m, "object": "model", "created": 0, "owned_by": "gateway"}
            for m in snap["provider"]["allowed_models"]
        ],
    }


@router.post("/admin/api/preview")
async def preview(request: Request, admin: Admin):
    raw = load_json(await body_bytes(request))
    if not isinstance(raw, dict) or set(raw) - {"messages", "policy_version_id"}:
        raise GatewayError(400, "invalid_request")
    parsed = parse_chat(
        json.dumps({"model": "preview", "messages": raw.get("messages")}, ensure_ascii=True).encode()
    )
    try:
        policy_id = UUID(raw["policy_version_id"]) if raw.get("policy_version_id") else None
    except (ValueError, TypeError):
        raise GatewayError(400, "invalid_request") from None
    user = str(admin["id"])
    request.app.state.inflight.acquire(user)
    start = time.monotonic()
    try:
        snap = await db_call(audit.snapshot, request.app.state.engine, policy_id)
        findings = await request.app.state.detector_pool.analyze(parsed["messages"], snap["dictionaries"])
        scope = {
            "integration_id": "00000000-0000-0000-0000-000000000000",
            "issuer": "admin-preview",
            "sub": user,
            "user_id": user,
            "chat_id": "preview",
        }
        result = protect(
            parsed["messages"],
            findings,
            snap["actions"],
            scope,
            request.app.state.settings.pseudonym_secret.encode(),
        )
        return {
            "decision": result.decision,
            "messages": [] if result.decision == "BLOCK" else result.messages,
            "findings": [{"category": category, "count": count} for category, count in result.counts.items()],
            "policy_version_id": str(snap["policy"]["id"]),
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
    except DetectorError as exc:
        raise GatewayError(exc.status_code, exc.code) from None
    finally:
        request.app.state.inflight.release(user)


@router.post("/v1/chat/completions")
async def chat(request: Request):
    identity = await db_call(authenticate, request, True)
    raw = await body_bytes(request)
    body = parse_chat(raw)
    snap = await db_call(audit.snapshot, request.app.state.engine)
    engine = request.app.state.engine
    request_id = request.state.request_id
    start = time.monotonic()

    def elapsed():
        return int((time.monotonic() - start) * 1000)

    if body["model"] not in snap["provider"]["allowed_models"]:
        await db_call(
            audit.record,
            engine,
            identity,
            snap,
            request_id,
            body | {"model": None},
            len(raw),
            "rejected",
            code="invalid_model",
            duration_ms=elapsed(),
        )
        raise GatewayError(400, "invalid_model")
    user = str(identity["user_id"])
    request.app.state.inflight.acquire(user)
    transferred = False
    try:
        try:
            findings = await request.app.state.detector_pool.analyze(body["messages"], snap["dictionaries"])
            result = protect(
                body["messages"],
                findings,
                snap["actions"],
                identity,
                request.app.state.settings.pseudonym_secret.encode(),
            )
        except DetectorError as exc:
            await db_call(
                audit.record,
                engine,
                identity,
                snap,
                request_id,
                body,
                len(raw),
                "detector_error",
                code="detector_timeout" if "timeout" in exc.code else "detector_failure",
                duration_ms=elapsed(),
            )
            raise GatewayError(exc.status_code, exc.code) from None
        if result.decision == "BLOCK":
            await db_call(
                audit.record,
                engine,
                identity,
                snap,
                request_id,
                body,
                len(raw),
                "blocked",
                decision="BLOCK",
                counts=result.counts,
                duration_ms=elapsed(),
            )
            raise GatewayError(403, "policy_blocked")
        outbound = wire_bytes(body | {"messages": result.messages})
        if len(outbound) > request.app.state.settings.max_request_bytes:
            await db_call(
                audit.record,
                engine,
                identity,
                snap,
                request_id,
                body,
                len(raw),
                "rejected",
                decision=result.decision,
                counts=result.counts,
                code="invalid_request",
                duration_ms=elapsed(),
            )
            raise GatewayError(413, "request_too_large")
        client = client_for(
            request.app.state.settings,
            snap["provider"],
            getattr(request.app.state, "provider_transport", None),
        )
        try:
            event_id = await db_call(
                audit.record,
                engine,
                identity,
                snap,
                request_id,
                body,
                len(raw),
                "forwarding_intent",
                decision=result.decision,
                counts=result.counts,
            )
        except BaseException:
            await client.aclose()
            raise
        # Only transformed bytes and fixed headers are passed to the provider adapter.
        if body.get("stream"):
            response = None
            dispatch_start = time.monotonic()
            try:
                async with asyncio.timeout(
                    min(
                        snap["provider"]["first_byte_timeout_seconds"],
                        snap["provider"]["total_timeout_seconds"],
                    )
                ):
                    response = await client.send(
                        client.build_request(
                            "POST",
                            snap["provider"]["base_url"].rstrip("/") + "/chat/completions",
                            content=outbound,
                        ),
                        stream=True,
                    )
                    if response.status_code != 200 or "text/event-stream" not in response.headers.get(
                        "content-type", ""
                    ):
                        raise GatewayError(502, "provider_error")
                    iterator = sse_frames(response).__aiter__()
                    first_frame = await anext(iterator)
            except BaseException as exc:
                code = (
                    "provider_timeout"
                    if isinstance(exc, (TimeoutError, httpx.TimeoutException))
                    else "provider_error"
                )
                cancelled = isinstance(exc, asyncio.CancelledError)
                await best_effort_finalize(
                    engine,
                    event_id,
                    "client_cancelled" if cancelled else "provider_error",
                    code="client_cancelled" if cancelled else code,
                    duration_ms=elapsed(),
                    status=response.status_code if response else None,
                )
                if response:
                    await response.aclose()
                await client.aclose()
                if cancelled:
                    raise
                raise GatewayError(504 if code == "provider_timeout" else 502, code) from None
            observed = {"chunks": 0, "released": False, "settled": False}

            async def cleanup():
                if observed["released"]:
                    return
                observed["released"] = True
                try:
                    if not observed["settled"]:
                        await best_effort_finalize(
                            engine,
                            event_id,
                            "client_cancelled",
                            chunks=observed["chunks"],
                            code="client_cancelled",
                            duration_ms=elapsed(),
                            status=response.status_code,
                        )
                    await response.aclose()
                    await client.aclose()
                finally:
                    request.app.state.inflight.release(user)

            transferred = True
            return ObservedStream(
                stream_response(
                    request,
                    client,
                    response,
                    iterator,
                    first_frame,
                    snap,
                    event_id,
                    user,
                    start,
                    dispatch_start,
                    observed,
                ),
                observed,
                cleanup,
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-store",
                    "X-Accel-Buffering": "no",
                    "X-Request-ID": str(request_id),
                },
            )
        status = None
        response = None
        try:
            async with asyncio.timeout(snap["provider"]["total_timeout_seconds"]):
                async with asyncio.timeout(snap["provider"]["first_byte_timeout_seconds"]):
                    response = await client.send(
                        client.build_request(
                            "POST",
                            snap["provider"]["base_url"].rstrip("/") + "/chat/completions",
                            content=outbound,
                        ),
                        stream=True,
                    )
                    status = response.status_code
                    if status != 200:
                        raise GatewayError(502, "provider_error")
                    iterator = response.aiter_bytes().__aiter__()
                    try:
                        chunk = await anext(iterator)
                    except StopAsyncIteration:
                        chunk = b""
                first = elapsed()
                content = bytearray(chunk)
                while True:
                    if len(content) > 8 * 1024 * 1024:
                        raise GatewayError(502, "provider_error")
                    try:
                        chunk = await asyncio.wait_for(
                            anext(iterator), snap["provider"]["idle_timeout_seconds"]
                        )
                    except StopAsyncIteration:
                        break
                    content.extend(chunk)
                try:
                    data = validate_completion(load_json(bytes(content)))
                except GatewayError:
                    raise GatewayError(502, "provider_error") from None
            await db_call(
                audit.finalize,
                engine,
                event_id,
                "completed",
                duration_ms=elapsed(),
                status=status,
                first_byte_ms=first,
            )
            return JSONResponse(data, headers={"X-Request-ID": str(request_id), "Cache-Control": "no-store"})
        except asyncio.CancelledError:
            await best_effort_finalize(
                engine,
                event_id,
                "client_cancelled",
                code="client_cancelled",
                duration_ms=elapsed(),
                status=status,
            )
            raise
        except (httpx.HTTPError, TimeoutError, GatewayError) as exc:
            code = (
                "provider_timeout"
                if isinstance(exc, (TimeoutError, httpx.TimeoutException))
                else "provider_error"
            )
            # A failed final audit must not turn an already-dispatched request into a retryable success.
            await best_effort_finalize(
                engine, event_id, "provider_error", code=code, duration_ms=elapsed(), status=status
            )
            if isinstance(exc, GatewayError) and exc.status_code == 503:
                raise
            raise GatewayError(504 if code == "provider_timeout" else 502, code) from None
        finally:
            if response:
                await response.aclose()
            await client.aclose()
    finally:
        if not transferred:
            request.app.state.inflight.release(user)


async def best_effort_finalize(engine, event_id, state, **kwargs):
    # Unrecorded finalizations remain forwarding_intent until deadline reconciliation.
    with anyio.CancelScope(shield=True):
        try:
            await db_call(audit.finalize, engine, event_id, state, **kwargs)
        except Exception:  # noqa: BLE001 - retain durable intent; diagnostics contain only a fixed code
            logging.getLogger("gateway").warning("audit_finalization_failed")


async def stream_response(
    request, client, response, iterator, first_frame, snap, event_id, user, start, dispatch_start, observed
):
    first = int((time.monotonic() - start) * 1000)
    status = response.status_code
    engine = request.app.state.engine

    def elapsed():
        return int((time.monotonic() - start) * 1000)

    try:
        remaining = max(
            0.001, snap["provider"]["total_timeout_seconds"] - (time.monotonic() - dispatch_start)
        )
        async with asyncio.timeout(remaining):
            frame = first_frame
            while True:
                if frame is None:
                    await db_call(
                        audit.finalize,
                        engine,
                        event_id,
                        "completed",
                        chunks=observed["chunks"],
                        duration_ms=elapsed(),
                        status=status,
                        first_byte_ms=first,
                    )
                    observed["settled"] = True
                    yield b"data: [DONE]\n\n"
                    return
                yield frame
                frame = await asyncio.wait_for(anext(iterator), snap["provider"]["idle_timeout_seconds"])
    except (asyncio.CancelledError, GeneratorExit):
        await best_effort_finalize(
            engine,
            event_id,
            "client_cancelled",
            chunks=observed["chunks"],
            code="client_cancelled",
            duration_ms=elapsed(),
            status=status,
            first_byte_ms=first,
        )
        observed["settled"] = True
        raise
    except Exception as exc:  # noqa: BLE001 - after response headers, emit only a classified safe SSE error
        code = (
            "provider_timeout"
            if isinstance(exc, (TimeoutError, httpx.TimeoutException))
            else "provider_error"
        )
        await best_effort_finalize(
            engine,
            event_id,
            "partial" if observed["chunks"] else "provider_error",
            chunks=observed["chunks"],
            code=code,
            duration_ms=elapsed(),
            status=status,
            first_byte_ms=first,
        )
        observed["settled"] = True
        safe = (
            "required_storage_unavailable"
            if isinstance(exc, GatewayError) and exc.status_code == 503
            else code
        )
        yield b"data: " + wire_bytes(GatewayError(502, safe).payload(request.state.request_id)) + b"\n\n"
