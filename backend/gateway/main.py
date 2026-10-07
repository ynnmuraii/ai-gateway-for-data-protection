import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException

from gateway import audit, control
from gateway.db import make_engine
from gateway.detection import DetectorPool, profile_checksum
from gateway.protocol import GatewayError, load_json
from gateway.routes import Inflight, db_call, router
from gateway.settings import Settings


class Boundary:
    """Bound input before framework decoding; suppress raw exceptions at the ASGI boundary."""

    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid4()
        scope.setdefault("state", {})["request_id"] = request_id
        started = False

        async def safe_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                if not any(key == b"x-request-id" for key, _ in headers):
                    headers.append((b"x-request-id", str(request_id).encode("ascii")))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-frame-options", b"DENY"),
                    ]
                )
                if scope["path"].startswith(("/admin/api", "/v1")):
                    headers.append((b"cache-control", b"no-store"))
                message = message | {"headers": headers}
            await send(message)

        try:
            if scope["method"] in ("POST", "PUT", "PATCH"):
                headers = scope.get("headers", [])
                for name in (
                    b"cookie",
                    b"origin",
                    b"referer",
                    b"x-csrf-token",
                    b"content-type",
                    b"content-length",
                ):
                    if sum(k == name for k, _ in headers) > 1:
                        raise GatewayError(400, "invalid_request")
                if any(k == b"content-encoding" and v != b"identity" for k, v in headers):
                    raise GatewayError(400, "invalid_request")
                length = next((v for k, v in headers if k == b"content-length"), None)
                if length is not None:
                    try:
                        if int(length) > self.limit or int(length) < 0:
                            raise GatewayError(413, "request_too_large")
                    except ValueError:
                        raise GatewayError(400, "invalid_request") from None
                body = bytearray()
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > self.limit:
                        raise GatewayError(413, "request_too_large")
                    if not message.get("more_body", False):
                        break
                if body and any(
                    k == b"content-type" and v.split(b";")[0] == b"application/json" for k, v in headers
                ):
                    load_json(
                        bytes(body)
                    )  # rejects duplicate keys and non-finite JSON, without reflecting values
                consumed = False

                async def replay():
                    nonlocal consumed
                    if not consumed:
                        consumed = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                await self.app(scope, replay, safe_send)
            else:
                await self.app(scope, receive, safe_send)
        except GatewayError as exc:
            if not started:
                await JSONResponse(exc.payload(request_id), status_code=exc.status_code)(
                    scope, receive, safe_send
                )
        except Exception:  # noqa: BLE001 - the final HTTP boundary must never expose raw exceptions
            # No traceback/body/SQL parameters reach application logs or the caller.
            if not started:
                logging.getLogger("gateway").warning("request_processing_failed")
                await JSONResponse(
                    GatewayError(503, "service_unavailable").payload(request_id), status_code=503
                )(scope, receive, safe_send)


def reconcile(engine):
    with engine.begin() as conn:
        stale = conn.execute(
            text("""UPDATE audit_events SET state='unknown',safe_error_code='unknown_outcome'
            WHERE state='forwarding_intent' AND outcome_deadline_at < now() RETURNING id""")
        ).all()
        for (event_id,) in stale:
            conn.execute(
                text(
                    "INSERT INTO audit_event_states (audit_event_id,sequence,state,safe_error_code) VALUES (:id,2,'unknown','unknown_outcome')"
                ),
                {"id": event_id},
            )


def create_app(settings=None, *, engine=None, detector_pool=None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings
        app.state.engine = engine or make_engine(settings)
        app.state.detector_pool = detector_pool or DetectorPool(settings)
        app.state.inflight = Inflight()
        await app.state.detector_pool.start()

        async def recovery():
            cycle = 0
            while True:
                try:
                    await db_call(reconcile, app.state.engine)
                    if cycle % 120 == 0:
                        await db_call(audit.maintenance, app.state.engine)
                except Exception:  # noqa: BLE001 - database exception text may contain protected values
                    logging.getLogger("gateway").warning("audit_maintenance_failed")
                cycle += 1
                await asyncio.sleep(30)

        task = asyncio.create_task(recovery())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await app.state.detector_pool.close()
            if engine is None:
                app.state.engine.dispose()

    app = FastAPI(
        title="AI Gateway",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(Boundary, limit=settings.max_request_bytes)

    @app.exception_handler(GatewayError)
    async def gateway_error(request, exc):
        if request.url.path == "/health/ready":
            return JSONResponse(
                {"status": "unavailable"}, status_code=503, headers={"Cache-Control": "no-store"}
            )
        return JSONResponse(
            exc.payload(getattr(request.state, "request_id", None)),
            status_code=exc.status_code,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        request_id = request.state.request_id
        content = (
            exc.detail | {"request_id": str(request_id)}
            if isinstance(exc.detail, dict) and "error" in exc.detail
            else GatewayError(exc.status_code, "request_rejected").payload(request_id)
        )
        return JSONResponse(content, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse(
            GatewayError(400, "invalid_request").payload(request.state.request_id), status_code=400
        )

    @app.get("/health/live")
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    async def ready(request: Request):
        if not request.app.state.detector_pool.ready:
            raise GatewayError(503, "detector_not_ready")
        snap = await db_call(audit.snapshot, request.app.state.engine)

        def checksum():
            with request.app.state.engine.connect() as conn:
                return conn.execute(
                    text("SELECT bundle_checksum FROM detector_profile_versions WHERE id=:id"),
                    {"id": snap["policy"]["detector_profile_id"]},
                ).scalar_one()

        if await db_call(checksum) != profile_checksum():
            raise GatewayError(503, "detector_profile_mismatch")
        from gateway.provider import client_for

        client = client_for(settings, snap["provider"])
        await client.aclose()
        return {"status": "ok", "mode": "demo" if settings.demo_mode else "provider"}

    app.include_router(control.router)
    app.include_router(router)
    frontend = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if frontend.is_dir():
        app.mount("/admin", StaticFiles(directory=frontend, html=True), name="admin")

    @app.get("/")
    async def root():
        return RedirectResponse("/admin/")

    return app
