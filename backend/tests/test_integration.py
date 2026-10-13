import json
import os
import time
import uuid
from types import SimpleNamespace

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from gateway import audit
from gateway.db import bootstrap, migrate
from gateway.detection import Detector, DetectorError
from gateway.main import create_app, reconcile
from gateway.protocol import wire_bytes
from gateway.provider import DemoStream, demo_transport
from gateway.settings import Settings
from sqlalchemy import create_engine, text


@pytest.fixture(scope="module")
def detector():
    return Detector()


class InlinePool:
    ready = True

    def __init__(self, detector):
        self.detector = detector

    async def start(self):
        pass

    async def close(self):
        pass

    async def analyze(self, messages, dictionaries):
        return self.detector.analyze(messages, dictionaries)


@pytest.fixture
def system(detector):
    url = os.getenv("GATEWAY_TEST_DATABASE_URL")
    if not url:
        pytest.skip("PostgreSQL URL required")
    owner = create_engine(url, hide_parameters=True)
    schema = "test_gateway_" + uuid.uuid4().hex
    with owner.begin() as conn:
        conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"}, hide_parameters=True)
    settings = Settings(
        database_url=url,
        public_origin="https://admin.test",
        csrf_secret="c" * 32,
        pseudonym_secret="p" * 32,
        identity_secret="i" * 32,
        demo_mode=True,
    )
    migrate(engine)
    initial = bootstrap(engine, settings, "admin", "Strong admin password 2026", "integration-secret" * 3)
    pool = InlinePool(detector)
    app = create_app(settings, engine=engine, detector_pool=pool)
    calls = []

    def upstream(request):
        calls.append(request)
        return demo_transport(request)

    with TestClient(app, base_url="https://admin.test") as client:
        app.state.provider_transport = httpx.MockTransport(upstream)
        yield SimpleNamespace(client=client, engine=engine, app=app, pool=pool, calls=calls, initial=initial)
    engine.dispose()
    with owner.begin() as conn:
        conn.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
    owner.dispose()


def headers(**claims):
    now = int(time.time())
    token = jwt.encode(
        {"iss": "open-webui", "sub": "demo-user", "iat": now, "exp": now + 300} | claims,
        "i" * 32,
        algorithm="HS256",
    )
    return {
        "Authorization": "Bearer " + "integration-secret" * 3,
        "X-OpenWebUI-User-JWT": token,
        "X-OpenWebUI-Chat-Id": "chat-1",
    }


def post(system, content="hello", stream=False, **extra):
    return system.client.post(
        "/v1/chat/completions",
        headers=headers(),
        json={"model": "demo-model", "messages": [{"role": "user", "content": content}], "stream": stream}
        | extra,
    )


def event(system):
    with system.engine.connect() as conn:
        return dict(
            conn.execute(text("SELECT * FROM audit_events ORDER BY occurred_at DESC LIMIT 1"))
            .mappings()
            .one()
        )


def test_all_message_roles_masked_before_egress_and_audit_contains_no_raw(system):
    messages = [
        {"role": role, "content": f"{role}: alice@example.com"}
        for role in ("system", "user", "assistant")
    ]
    response = post(system, messages=messages, user="private-user-metadata")
    assert response.status_code == 200, response.text
    assert len(system.calls) == 1
    sent = json.loads(system.calls[0].content)
    assert "alice@example.com" not in system.calls[0].content.decode()
    assert "10.20.30.40" not in system.calls[0].content.decode()
    assert "user" not in sent
    assert system.calls[0].headers["authorization"] == "Bearer demo"
    assert all("openwebui" not in name for name in system.calls[0].headers)
    row = event(system)
    assert row["state"] == "completed" and row["decision"] == "MASK"
    assert row["output_chunks_forwarded"] == 0
    with system.engine.connect() as conn:
        audit_dump = str(conn.execute(text("SELECT row_to_json(a) FROM audit_events a")).all())
        findings = str(conn.execute(text("SELECT row_to_json(a) FROM audit_findings a")).all())
    for secret in ("alice@example.com", "10.20.30.40", "chat-1", "[EMAIL_", "private-user-metadata"):
        assert secret not in audit_dump + findings


def test_block_and_unknown_fields_never_call_provider(system):
    secret = jwt.encode({"private": "example"}, "not-a-real-key" * 3, algorithm="HS256")
    response = post(system, "token=" + secret)
    assert response.status_code == 403, response.text
    assert event(system)["state"] == "blocked"
    assert (
        response.json()["request_id"] == str(event(system)["request_id"]) == response.headers["x-request-id"]
    )
    assert post(system, tools=[]).status_code == 400
    assert post(system, stop="hidden secret").status_code == 400
    assert not system.calls


def test_models_and_identity_scope(system):
    assert system.client.get("/v1/models").status_code == 401
    h = headers()
    h.pop("X-OpenWebUI-Chat-Id")
    assert system.client.get("/v1/models", headers=h).json()["data"][0]["id"] == "demo-model"
    assert (
        system.client.post(
            "/v1/chat/completions",
            headers=h,
            json={"model": "demo-model", "messages": [{"role": "user", "content": "safe"}]},
        ).status_code
        == 400
    )
    assert system.client.get("/v1/models", headers=headers(sub="unknown", role="admin")).status_code == 403
    assert (
        system.client.get("/v1/models", headers=headers() | {"X-OpenWebUI-User-Id": "demo-user"}).status_code
        == 401
    )
    assert not system.calls


def test_stable_same_chat_and_distinct_chat_markers(system):
    first = post(system, "alice@example.com").json()["choices"][0]["message"]["content"]
    second = post(system, "alice@example.com").json()["choices"][0]["message"]["content"]
    assert first == second
    other = system.client.post(
        "/v1/chat/completions",
        headers=headers() | {"X-OpenWebUI-Chat-Id": "chat-2"},
        json={"model": "demo-model", "messages": [{"role": "user", "content": "alice@example.com"}]},
    )
    assert other.json()["choices"][0]["message"]["content"] != first


def test_stream_done_follows_final_audit(system):
    response = post(system, "alice@example.com", stream=True)
    assert response.status_code == 200
    assert response.text.endswith("data: [DONE]\n\n")
    row = event(system)
    assert row["state"] == "completed"
    assert row["output_chunks_forwarded"] == response.text.count("data: ") - 1
    assert "alice@example.com" not in response.text


def test_followup_keeps_assistant_markers_without_releasing_original_history(system):
    first = post(system, "Please contact alice@example.com")
    assert first.status_code == 200
    history = [
        {"role": "user", "content": "Please contact alice@example.com"},
        first.json()["choices"][0]["message"],
        {"role": "user", "content": "Explain further"},
    ]
    second = post(system, messages=history)
    assert second.status_code == 200, second.text
    assert len(system.calls) == 2
    assert b"alice@example.com" not in system.calls[-1].content
    assert system.calls[-1].content.count(b"[EMAIL_") == 2


def test_provider_error_before_headers_is_http_error_and_sanitized(system):
    system.app.state.provider_transport = httpx.MockTransport(
        lambda r: httpx.Response(401, text="sensitive upstream credential")
    )
    response = post(system, stream=True)
    assert response.status_code == 502, response.text
    assert "sensitive" not in response.text
    row = event(system)
    assert row["state"] == "provider_error" and row["output_chunks_forwarded"] == 0


def test_stream_missing_done_becomes_partial_without_success(system):
    chunk = {
        "id": "test",
        "model": "demo-model",
        "created": 1,
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": None}],
    }
    system.app.state.provider_transport = httpx.MockTransport(
        lambda r: httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=DemoStream([b"data: " + wire_bytes(chunk) + b"\n\n"]),
        )
    )
    response = post(system, stream=True)
    assert response.status_code == 200
    assert "[DONE]" not in response.text and '"error"' in response.text
    row = event(system)
    assert row["state"] == "partial" and row["output_chunks_forwarded"] == 1
    error = next(
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ") and '"error"' in line
    )
    assert error["request_id"] == response.headers["x-request-id"] == str(row["request_id"])


def test_audit_intent_failure_is_closed(system, monkeypatch):
    def fail(*a, **kw):
        raise RuntimeError("PRIVATE SQL details")

    monkeypatch.setattr(audit, "record", fail)
    response = post(system, "alice@example.com")
    assert response.status_code == 503
    assert not system.calls and "PRIVATE" not in response.text


@pytest.mark.parametrize("stream", [False, True])
def test_final_audit_failure_never_returns_success(system, monkeypatch, stream):
    def fail(*a, **kw):
        raise RuntimeError("PRIVATE details")

    monkeypatch.setattr(audit, "finalize", fail)
    response = post(system, stream=stream)
    assert len(system.calls) == 1
    assert event(system)["state"] == "forwarding_intent"
    if stream:
        assert "[DONE]" not in response.text and '"error"' in response.text
    else:
        assert response.status_code == 503
    assert "PRIVATE" not in response.text
    with system.engine.begin() as conn:
        conn.execute(text("UPDATE audit_events SET outcome_deadline_at=now()-interval '1 second'"))
    reconcile(system.engine)
    assert event(system)["state"] == "unknown"
    assert len(system.calls) == 1


def test_detector_failure_is_closed(system):
    async def fail(*a):
        raise DetectorError("detector_timeout")

    system.pool.analyze = fail
    response = post(system)
    assert response.status_code == 503 and not system.calls
    assert event(system)["state"] == "detector_error"


def test_preview_auth_csrf_and_never_egress(system):
    payload = {"messages": [{"role": "user", "content": "alice@example.com"}]}
    assert system.client.post("/admin/api/preview", json=payload).status_code == 401
    login = system.client.post(
        "/admin/api/auth/login",
        headers={"Origin": "https://admin.test"},
        json={"username": "admin", "password": "Strong admin password 2026"},
    )
    assert login.status_code == 200, login.text
    assert system.client.post("/admin/api/preview", json=payload).status_code == 403
    response = system.client.post(
        "/admin/api/preview",
        headers={"Origin": "https://admin.test", "X-CSRF-Token": login.json()["csrf_token"]},
        json=payload,
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "MASK" and "alice@example.com" not in response.text
    assert not system.calls
    with system.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 0


def test_profile_mismatch_and_input_limits_closed(system, monkeypatch):
    assert system.client.get("/health/ready").status_code == 200
    assert post(system, "x" * 262145).status_code == 413
    assert (
        system.client.post(
            "/v1/chat/completions",
            headers=headers() | {"Content-Type": "application/json"},
            content=b'{"model":"demo-model","messages":[{"role":"user","content":"\\ud800"}]}',
        ).status_code
        == 400
    )
    monkeypatch.setattr(audit, "profile_checksum", lambda: "0" * 64)
    assert system.client.get("/health/ready").status_code == 503
    assert post(system).status_code == 503 and not system.calls
