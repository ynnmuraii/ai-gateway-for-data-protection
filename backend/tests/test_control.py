import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from gateway import control
from gateway.db import bootstrap, migrate, upgrade_detector
from gateway.detection.analyzer import previous_profile_checksums, profile_checksum
from gateway.security import digest
from gateway.settings import Settings
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


@pytest.fixture
def environment(request):
    url = os.environ.get("GATEWAY_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set GATEWAY_TEST_DATABASE_URL to run real PostgreSQL control tests.")
    schema = "test_control_" + uuid.uuid4().hex
    owner = create_engine(url, hide_parameters=True)
    with owner.begin() as conn:
        conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"}, hide_parameters=True)
    def cleanup():
        engine.dispose()
        try:
            with owner.begin() as conn:
                conn.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            owner.dispose()
    request.addfinalizer(cleanup)
    settings = Settings(database_url=url, public_origin="https://admin.test", csrf_secret="c" * 32,
                        identity_secret="i" * 32, pseudonym_secret="p" * 32, demo_mode=True)
    migrate(engine)
    fixture_profile = getattr(request, "param", None)
    checksum = "0" * 64 if fixture_profile == "unrecognized" else (
        previous_profile_checksums().get(fixture_profile, profile_checksum()))
    with patch("gateway.detection.profile_checksum", return_value=checksum):
        initial = bootstrap(engine, settings, "admin", "Strong admin password 2026", "integration-secret" * 3)
    app = FastAPI()
    app.state.settings = settings
    app.state.engine = engine
    app.include_router(control.router)
    @app.exception_handler(HTTPException)
    async def errors(request: Request, error):
        return JSONResponse(error.detail, status_code=error.status_code, headers=error.headers)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error):
        # Match the production boundary: validation errors never echo protected inputs.
        return JSONResponse({"error": {"code": "invalid_request"}}, status_code=400)
    with TestClient(app, base_url="https://admin.test") as client:
        yield client, engine, initial


def login(client):
    response = client.post("/admin/api/auth/login", headers={"Origin": "https://admin.test"},
                           json={"username": "admin", "password": "Strong admin password 2026"})
    assert response.status_code == 200, response.text
    return {"Origin": "https://admin.test", "X-CSRF-Token": response.json()["csrf_token"]}


def test_sessions_csrf_rotation_and_only_hashed_storage(environment):
    client, engine, initial = environment
    assert client.get("/admin/api/users").status_code == 401
    assert client.post("/admin/api/auth/login", json={"username": "admin", "password": "Strong admin password 2026"}).status_code == 403
    headers = login(client)
    session = client.cookies.get("gw_admin_session")
    cookie = next(cookie for cookie in client.cookies.jar if cookie.name == "gw_admin_session")
    assert cookie.secure and cookie.path == "/admin/api"
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite") == "strict"
    response = client.get("/admin/api/auth/me")
    assert response.json()["csrf_token"] == headers["X-CSRF-Token"]
    assert response.headers["cache-control"] == "no-store"
    with engine.connect() as conn:
        row = conn.execute(text("SELECT session_token_hash,csrf_token_hash FROM admin_sessions")).mappings().one()
        assert bytes(row["session_token_hash"]) == digest(session)
        assert bytes(row["csrf_token_hash"]) == digest(headers["X-CSRF-Token"])
    assert client.post("/admin/api/users", json={"username": "person", "display_name": "Person", "role": "user"}).status_code == 403
    assert client.patch(f'/admin/api/users/{initial["admin_id"]}', headers=headers, json={"enabled": False}).status_code == 409
    client.app.state.settings.csrf_secret = "x" * 32
    assert client.get("/admin/api/auth/me").status_code == 401


def test_user_credentials_integrations_and_mapping_revocation(environment):
    client, engine, _initial = environment
    headers = login(client)
    user = client.post("/admin/api/users", headers=headers,
                       json={"username": "second", "display_name": "Second", "role": "admin"})
    assert user.status_code == 201
    user_id = user.json()["id"]
    assert client.put(f"/admin/api/users/{user_id}/admin-credential", headers=headers,
                      json={"password": "Second strong password 2026"}).status_code == 204
    created = client.post("/admin/api/integrations", headers=headers, json={"name": "Other"})
    assert created.status_code == 201
    integration = created.json()["integration"]
    with engine.connect() as conn:
        key_hash = conn.execute(text("SELECT bearer_key_hash FROM client_integrations WHERE id=:id"), integration).scalar_one()
        assert bytes(key_hash) == digest(created.json()["integration_bearer_key"])
    mapping = {"integration_id": integration["id"], "external_subject": "external"}
    identity = client.post(f"/admin/api/users/{user_id}/identities", headers=headers, json=mapping)
    assert identity.status_code == 201
    assert client.post(f"/admin/api/users/{user_id}/identities", headers=headers, json=mapping).status_code == 409
    assert client.delete(f'/admin/api/users/{user_id}/identities/{identity.json()["id"]}', headers=headers).status_code == 204
    assert client.post(f"/admin/api/users/{user_id}/identities", headers=headers, json=mapping).status_code == 201
    assert "bearer_key_hash" not in client.get("/admin/api/integrations").text
    assert client.post(f'/admin/api/integrations/{integration["id"]}/rotate-key', headers=headers).status_code == 200


def test_published_snapshots_and_activation_compare_and_swap(environment):
    client, engine, initial = environment
    headers = login(client)
    dictionary = client.post("/admin/api/dictionary-versions", headers=headers,
                             json={"name": "Internal", "entries": [{"category": "INTERNAL_HOSTNAME", "value": "secret.internal"}]}).json()
    dictionary_id = dictionary["id"]
    assert client.post(f"/admin/api/dictionary-versions/{dictionary_id}/publish", headers=headers).status_code == 200
    assert client.put(f"/admin/api/dictionary-versions/{dictionary_id}", headers=headers, json={"entries": []}).status_code == 409
    draft = client.post("/admin/api/policy-versions", headers=headers, json={}).json()
    policy_id = draft["id"]
    payload = {key: draft[key] for key in ("rules", "dictionary_version_ids", "detector_profile_version")}
    payload["dictionary_version_ids"] = [dictionary_id]
    assert client.put(f"/admin/api/policy-versions/{policy_id}", headers=headers, json=payload).status_code == 200
    assert client.post(f"/admin/api/policy-versions/{policy_id}/publish", headers=headers).status_code == 200
    assert client.put(f"/admin/api/policy-versions/{policy_id}", headers=headers, json=payload).status_code == 409
    current = client.get("/admin/api/active-policy")
    activate_headers = headers | {"If-Match": current.headers["etag"]}
    response = client.put("/admin/api/active-policy", headers=activate_headers, json={"policy_version_id": policy_id})
    assert response.status_code == 200
    assert response.json()["revision"] == 2
    assert client.put("/admin/api/active-policy", headers=activate_headers, json={"policy_version_id": initial["policy_version_id"]}).status_code == 409
    assert len(client.get("/admin/api/policy-activations").json()["items"]) == 2
    with pytest.raises(DBAPIError), engine.begin() as conn:
        conn.execute(text("UPDATE policy_rules SET action='ALLOW' WHERE policy_version_id=:id"), {"id": policy_id})
    with pytest.raises(DBAPIError), engine.begin() as conn:
        conn.execute(text("UPDATE dictionary_entries SET entry_value='changed' WHERE dictionary_version_id=:id"), {"id": dictionary_id})


def test_provider_settings_cas_and_retention(environment):
    client, _engine, _initial = environment
    headers = login(client)
    original = client.get("/admin/api/settings/provider")
    data = original.json()
    data.pop("revision")
    change_headers = headers | {"If-Match": original.headers["etag"]}
    data["provider_label"] = "Updated simulator"
    assert client.put("/admin/api/settings/provider", headers=change_headers, json=data).status_code == 200
    assert client.put("/admin/api/settings/provider", headers=change_headers, json=data).status_code == 409
    data["credential_ref"] = "identity-default"
    assert client.put("/admin/api/settings/provider", headers=headers | {"If-Match": '"2"'}, json=data).status_code == 400
    assert client.put("/admin/api/settings/retention", headers=headers, json={"audit_retention_days": 7}).json() == {"audit_retention_days": 7}
    assert client.get("/admin/api/audit").json() == {"items": [], "next_cursor": None}
    assert client.get("/admin/api/statistics", params={"from": "2020-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z"}).json()["total_requests"] == 0


def test_concurrent_last_admin_change_serializes(environment):
    client, engine, initial = environment
    headers = login(client)
    second = client.post("/admin/api/users", headers=headers,
                         json={"username": "other-admin", "display_name": "Other", "role": "admin"}).json()
    assert client.put(f'/admin/api/users/{second["id"]}/admin-credential', headers=headers,
                      json={"password": "Second usable admin password 2026"}).status_code == 204
    # Both transactions begin while there are two administrators. Only one can commit.
    def demote(user_id):
        with engine.begin() as conn:
            return control.change_user(conn, uuid.UUID(user_id), {"role": "user"})
    def attempt(user_id):
        try:
            demote(user_id)
            return 200
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, [initial["admin_id"], second["id"]])) == [200, 409]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM users WHERE role='admin' AND enabled")).scalar() == 1


@pytest.mark.parametrize("alternate_role", ["admin", "user"])
@pytest.mark.parametrize("change", [{"role": "user"}, {"enabled": False}])
def test_passwordless_admin_cannot_replace_last_usable_admin(environment, alternate_role, change):
    client, _engine, initial = environment
    headers = login(client)
    alternate = client.post("/admin/api/users", headers=headers,
                            json={"username": "alternate", "display_name": "Alternate", "role": alternate_role}).json()
    if alternate_role == "user":
        assert client.patch(f'/admin/api/users/{alternate["id"]}', headers=headers, json={"role": "admin"}).status_code == 200
    target = f'/admin/api/users/{initial["admin_id"]}'
    rejected = client.patch(target, headers=headers, json=change)
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "last_admin"
    assert client.get("/admin/api/auth/me").status_code == 200
    assert client.put(f'/admin/api/users/{alternate["id"]}/admin-credential', headers=headers,
                      json={"password": "Alternate strong password 2026"}).status_code == 204
    assert client.patch(target, headers=headers, json=change).status_code == 200
    assert client.get("/admin/api/auth/me").status_code == 401
    signed_in = client.post("/admin/api/auth/login", headers={"Origin": "https://admin.test"},
                            json={"username": "alternate", "password": "Alternate strong password 2026"})
    assert signed_in.status_code == 200
    assert client.get("/admin/api/auth/me").json()["user"]["id"] == alternate["id"]


def test_session_expiry_password_reset_and_rate_limit(environment):
    client, engine, initial = environment
    headers = login(client)
    with engine.begin() as conn:
        conn.execute(text("UPDATE admin_sessions SET last_seen_at=now()-interval '31 minutes'"))
    assert client.get("/admin/api/auth/me").status_code == 401
    headers = login(client)
    assert client.put(f'/admin/api/users/{initial["admin_id"]}/admin-credential', headers=headers,
                      json={"password": "Replacement strong password 2026"}).status_code == 204
    assert client.get("/admin/api/auth/me").status_code == 401
    assert client.post("/admin/api/auth/login", headers={"Origin": "https://admin.test"},
                       json={"username": "admin", "password": "Strong admin password 2026"}).status_code == 401
    statuses = [client.post("/admin/api/auth/login", headers={"Origin": "https://admin.test"},
                            json={"username": "admin", "password": "Wrong strong password 2026"}).status_code for _ in range(9)]
    assert statuses[-1] == 429


def test_audit_retention_counts_cursor_and_safe_projection(environment):
    client, engine, initial = environment
    login(client)
    with engine.begin() as conn:
        identity = conn.execute(text("SELECT id FROM external_identities WHERE user_id=:id"),
                                {"id": uuid.UUID(initial["user_id"])}).scalar_one()
        for days in (0, 1, 40):
            event_id = uuid.uuid4()
            conn.execute(text("INSERT INTO audit_events(id,request_id,occurred_at,external_identity_id,integration_id,user_id,"
                              "policy_version_id,provider_config_revision,provider_label,state,decision,request_bytes,message_count,duration_ms) "
                              "VALUES (:id,:request,now()-(:days * interval '1 day'),:identity,:integration,:user,:policy,1,'Local simulator','blocked','BLOCK',100,1,10)"),
                         {"id": event_id, "request": uuid.uuid4(), "days": days, "identity": identity,
                          "integration": uuid.UUID(initial["integration_id"]), "user": uuid.UUID(initial["user_id"]),
                          "policy": uuid.UUID(initial["policy_version_id"])})
            conn.execute(text("INSERT INTO audit_event_states(audit_event_id,sequence,state) VALUES (:id,1,'blocked')"), {"id": event_id})
            conn.execute(text("INSERT INTO audit_findings(audit_event_id,category,action,finding_count) VALUES (:id,'JWT','BLOCK',2)"), {"id": event_id})
    first = client.get("/admin/api/audit", params={"limit": 1})
    assert first.status_code == 200
    page = first.json()
    assert len(page["items"]) == 1
    assert page["items"][0]["findings"] == [{"category": "JWT", "action": "BLOCK", "count": 2}]
    assert "external_identity_id" not in page["items"][0]
    assert not {"prompt", "messages", "output", "chat_id", "entry_value", "replacement", "offset", "hash"} & page["items"][0].keys()
    second = client.get("/admin/api/audit", params={"limit": 1, "cursor": page["next_cursor"]}).json()
    assert second["items"][0]["id"] != page["items"][0]["id"]
    assert second["next_cursor"] is None
    result = client.get("/admin/api/statistics", params={"from": "2020-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z"}).json()
    assert result["total_requests"] == 2
    assert result["states"] == {"blocked": 2}
    assert result["findings"] == [{"category": "JWT", "action": "BLOCK", "count": 4}]
    assert result["latency"] == {"p50_ms": 10, "p95_ms": 10, "p99_ms": 10}
    assert client.get("/admin/api/audit", params={"from": "2026-01-01T00:00:00"}).status_code == 400
    assert client.get("/admin/api/audit", params={"cursor": "malformed"}).status_code == 400
    assert len(client.get("/admin/api/audit", params={"decision": "BLOCK", "category": "JWT", "limit": 20}).json()["items"]) == 2
    assert client.get("/admin/api/audit", params={"category": "EMAIL"}).json()["items"] == []


@pytest.mark.parametrize("params", [{"decision": "DROP"}, {"limit": "oops"}, {"limit": 0},
                                    {"limit": 101}, {"category": "PASSWORD"}, {"user_id": "invalid"}])
def test_audit_benchmark_validates_filters_without_reflecting_input(environment, params):
    client, _engine, _initial = environment
    assert client.get("/admin/api/audit", params=params).status_code == 401
    login(client)
    response = client.get("/admin/api/audit", params=params)
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "invalid_request"}}


@pytest.mark.parametrize("environment", ["sprint1", "prototype", "sprint2-initial"], indirect=True)
def test_sprint1_upgrade_preserves_published_records_and_rejects_legacy_rollback(environment):
    from gateway.audit import snapshot
    from gateway.protocol import GatewayError

    client, engine, initial = environment
    headers = login(client)
    dictionary = client.post("/admin/api/dictionary-versions", headers=headers,
                             json={"name": "Corporate", "entries": [{"category": "INTERNAL_HOSTNAME", "value": "build.corp"}]}).json()
    assert client.post(f'/admin/api/dictionary-versions/{dictionary["id"]}/publish', headers=headers).status_code == 200
    # A legitimate S1 policy can contain customized actions and dictionary references.
    old_policy_id = uuid.uuid4()
    with engine.begin() as conn:
        params = {"old": uuid.UUID(initial["policy_version_id"]), "id": old_policy_id,
                  "admin": uuid.UUID(initial["admin_id"]), "dictionary": uuid.UUID(dictionary["id"])}
        conn.execute(text("INSERT INTO policy_versions(id,version,based_on_id,detector_profile_id,created_by_user_id) "
                          "SELECT :id,2,id,detector_profile_id,:admin FROM policy_versions WHERE id=:old"), params)
        conn.execute(text("INSERT INTO policy_rules(policy_version_id,category,action) SELECT :id,category,"
                          "CASE WHEN category='API_KEY' THEN 'ALLOW'::policy_action ELSE action END "
                          "FROM policy_rules WHERE policy_version_id=:old"), params)
        conn.execute(text("INSERT INTO policy_dictionaries(policy_version_id,dictionary_version_id) VALUES (:id,:dictionary)"), params)
        conn.execute(text("UPDATE policy_versions SET status='published',published_at=now(),published_by_user_id=:admin WHERE id=:id"), params)
        conn.execute(text("UPDATE active_policy SET policy_version_id=:id,revision=revision+1,updated_by_user_id=:admin WHERE singleton"), params)
        old_profiles = conn.execute(text("SELECT row_to_json(d) FROM detector_profile_versions d")).all()
        old_policy = conn.execute(text("SELECT row_to_json(p) FROM policy_versions p WHERE id=:id"), params).scalar_one()
        old_rules = conn.execute(text("SELECT category,action FROM policy_rules WHERE policy_version_id=:id ORDER BY category"), params).all()
    with pytest.raises(GatewayError) as unavailable:
        snapshot(engine)
    assert unavailable.value.code == "detector_profile_mismatch"
    result = upgrade_detector(engine)
    assert result["status"] == "upgraded" and result["revision"] == 3
    active = snapshot(engine)
    assert str(active["policy"]["id"]) == result["policy_version_id"]
    assert active["actions"]["API_KEY"] == "ALLOW"
    assert active["dictionaries"] == [{"category": "INTERNAL_HOSTNAME", "entry_value": "build.corp"}]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT row_to_json(d) FROM detector_profile_versions d WHERE version=1")).all() == old_profiles
        assert conn.execute(text("SELECT row_to_json(p) FROM policy_versions p WHERE id=:id"), {"id": old_policy_id}).scalar_one() == old_policy
        assert conn.execute(text("SELECT category,action FROM policy_rules WHERE policy_version_id=:id ORDER BY category"), {"id": old_policy_id}).all() == old_rules
        assert conn.execute(text("SELECT count(*) FROM detector_profile_versions")).scalar_one() == 2
        assert conn.execute(text("SELECT count(*) FROM policy_versions")).scalar_one() == 3
        assert conn.execute(text("SELECT count(*) FROM policy_activations")).scalar_one() == 3
    again = upgrade_detector(engine)
    assert again == result | {"status": "current"}
    profiles = client.get("/admin/api/detector-profile-versions").json()
    assert [(p["version"], p["deployed"]) for p in profiles] == [(2, True), (1, False)]
    rejected = client.put("/admin/api/active-policy", headers=headers | {"If-Match": '"3"'},
                          json={"policy_version_id": str(old_policy_id)})
    assert rejected.status_code == 409 and rejected.json()["error"]["code"] == "detector_profile_mismatch"
    assert client.get("/admin/api/active-policy").json()["revision"] == 3


@pytest.mark.parametrize("environment", ["unrecognized"], indirect=True)
def test_upgrade_refuses_unrecognized_bundle_without_writes(environment):
    _client, engine, _initial = environment
    with pytest.raises(ValueError, match="not a reviewed previous baseline"):
        upgrade_detector(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM detector_profile_versions")).scalar_one() == 1
        assert conn.execute(text("SELECT count(*) FROM policy_versions")).scalar_one() == 1
        assert conn.execute(text("SELECT revision FROM active_policy")).scalar_one() == 1


def test_migration_idempotency_bootstrap_refusal_and_runtime_cas(environment):
    client, engine, _initial = environment
    migrate(engine)
    with pytest.raises(ValueError, match="already bootstrapped"):
        bootstrap(engine, client.app.state.settings, "admin", "Another strong password", "i" * 32)
    headers = login(client)
    draft = client.post("/admin/api/policy-versions", headers=headers, json={}).json()
    assert client.put("/admin/api/active-policy", headers=headers | {"If-Match": '"1"'},
                      json={"policy_version_id": draft["id"]}).status_code == 409
    assert client.post(f'/admin/api/policy-versions/{draft["id"]}/publish', headers=headers).status_code == 200
    def activate():
        try:
            with engine.begin() as conn:
                return conn.execute(text("UPDATE active_policy SET policy_version_id=:id,revision=revision+1 "
                                         "WHERE singleton AND revision=1"), {"id": uuid.UUID(draft["id"])}).rowcount
        except DBAPIError:
            return -1
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: activate(), range(2))) == [0, 1]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM policy_activations")).scalar() == 2


def test_runtime_role_cannot_mutate_history_profiles_or_triggers(environment):
    from gateway.audit import maintenance

    _client, engine, initial = environment
    role = "test_runtime_" + uuid.uuid4().hex
    runtime = None
    with engine.connect() as conn:
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()
    script = (Path(__file__).parents[1] / "migrations" / "provision_roles.sql").read_text()
    script = script.replace("gateway_runtime", role).replace("public", schema)
    try:
        with engine.begin() as conn, conn.connection.driver_connection.cursor() as cursor:
            cursor.execute(script, prepare=False)
        with engine.begin() as conn:
            conn.exec_driver_sql(f'SET LOCAL ROLE "{role}"')
            assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() == 2
            assert conn.execute(text("SELECT count(*) FROM detector_profile_versions")).scalar_one() == 1
        forbidden = ["UPDATE audit_event_states SET sequence=2", "DELETE FROM audit_findings",
                     "UPDATE detector_profile_versions SET version=2", "DELETE FROM policy_activations",
                     "ALTER TABLE policy_versions DISABLE TRIGGER ALL", "CREATE TABLE bypass(id integer)",
                     "CREATE TEMP TABLE users(id uuid, role text)"]
        for sql in forbidden:
            with pytest.raises(DBAPIError), engine.begin() as conn:
                conn.exec_driver_sql(f'SET LOCAL ROLE "{role}"')
                conn.exec_driver_sql(sql)
        retained_identity, expired_identity, unused_identity = (uuid.uuid4() for _ in range(3))
        retained_event, expired_event, stale_event = (uuid.uuid4() for _ in range(3))
        with engine.begin() as conn:
            for identity in (retained_identity, expired_identity, unused_identity):
                conn.execute(text("INSERT INTO external_identities(id,integration_id,user_id,external_subject,revoked_at) "
                                  "VALUES (:id,:integration,:user,:subject,now())"),
                             {"id": identity, "integration": uuid.UUID(initial["integration_id"]),
                              "user": uuid.UUID(initial["user_id"]), "subject": str(identity)})
            for event, identity, days, state in ((retained_event, retained_identity, 0, "blocked"),
                                                 (expired_event, expired_identity, 40, "blocked"),
                                                 (stale_event, retained_identity, 0, "forwarding_intent")):
                conn.execute(text("INSERT INTO audit_events(id,request_id,occurred_at,external_identity_id,integration_id,user_id,"
                                  "policy_version_id,provider_config_revision,provider_label,state,decision,request_bytes,message_count,outcome_deadline_at) "
                                  "VALUES (:id,:request,now()-(:days * interval '1 day'),:identity,:integration,:user,:policy,1,'Local simulator',:state,:decision,100,1,:deadline)"),
                             {"id": event, "request": uuid.uuid4(), "days": days, "identity": identity,
                              "integration": uuid.UUID(initial["integration_id"]), "user": uuid.UUID(initial["user_id"]),
                              "policy": uuid.UUID(initial["policy_version_id"]), "state": state,
                              "decision": "ALLOW" if state == "forwarding_intent" else "BLOCK",
                              "deadline": conn.execute(text("SELECT now()-interval '1 minute'")).scalar_one() if state == "forwarding_intent" else None})
                conn.execute(text("INSERT INTO audit_event_states(audit_event_id,sequence,state) VALUES (:id,1,:state)"), {"id": event, "state": state})
                if state == "blocked":
                    conn.execute(text("INSERT INTO audit_findings(audit_event_id,category,action,finding_count) VALUES (:id,'JWT','BLOCK',2)"), {"id": event})
        runtime = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema} -crole={role}"}, hide_parameters=True)
        with runtime.connect() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == role
        maintenance(runtime)
        with runtime.connect() as conn:
            assert conn.execute(text("SELECT state FROM audit_events WHERE id=:id"), {"id": stale_event}).scalar_one() == "unknown"
            assert conn.execute(text("SELECT count(*) FROM audit_event_states WHERE audit_event_id=:id"), {"id": stale_event}).scalar_one() == 2
            assert conn.execute(text("SELECT count(*) FROM audit_events WHERE id=:id"), {"id": expired_event}).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM audit_event_states WHERE audit_event_id=:id"), {"id": expired_event}).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM audit_findings WHERE audit_event_id=:id"), {"id": expired_event}).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM external_identities WHERE id IN (:expired,:unused)"),
                                {"expired": expired_identity, "unused": unused_identity}).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM external_identities WHERE id=:id"), {"id": retained_identity}).scalar_one() == 1
        with pytest.raises(DBAPIError), runtime.begin() as conn:
            conn.execute(text("DELETE FROM external_identities WHERE id=:id"), {"id": retained_identity})
    finally:
        if runtime is not None:
            runtime.dispose()
        with engine.begin() as conn:
            if conn.execute(text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=:role)"), {"role": role}).scalar_one():
                conn.exec_driver_sql(f'DROP OWNED BY "{role}"')
                conn.exec_driver_sql(f'DROP ROLE "{role}"')
