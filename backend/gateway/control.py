"""Same-origin administrator API. Published snapshots remain guarded by PostgreSQL."""
import base64
import hmac
import re
import secrets
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from .db import ADMIN_LOCK, CATEGORIES, DEFAULT_ACTIONS, VERSION_LOCK
from .security import (
    COOKIE_NAME,
    DUMMY_HASH,
    LoginLimiter,
    csrf_token,
    digest,
    fail,
    hash_password,
    same_origin,
    verify_password,
)

router = APIRouter(prefix="/admin/api", tags=["Administration"])
_limiter_init_lock = threading.Lock()
Role = Literal["admin", "user"]
Action = Literal["ALLOW", "MASK", "BLOCK"]
Category = Literal["API_KEY", "ACCESS_TOKEN", "JWT", "EMAIL", "PHONE", "IP_ADDRESS", "INTERNAL_HOSTNAME"]
AuditState = Literal["received", "detected", "blocked", "detector_error", "rejected", "forwarding_intent", "completed", "partial", "provider_error", "client_cancelled", "unknown"]
WireUUID = Annotated[uuid.UUID, Field(strict=False)]


class DTO(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @model_validator(mode="after")
    def valid_unicode(self):
        for value in self.__dict__.values():
            strings = value if isinstance(value, list) else [value]
            for item in strings:
                if isinstance(item, str):
                    try:
                        item.encode("utf-8")
                    except UnicodeEncodeError:
                        raise ValueError("Text must contain valid Unicode.") from None
        return self


class Login(DTO):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=1024)


class CreateUser(DTO):
    username: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9._@+-]+$")
    display_name: str = Field(min_length=1, max_length=200)
    role: Role


class UpdateUser(DTO):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: Role | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self, key) is None for key in self.model_fields_set):
            raise ValueError("At least one non-null change is required.")
        return self


class Password(DTO):
    password: str = Field(min_length=12, max_length=1024)


class AddIdentity(DTO):
    integration_id: WireUUID
    external_subject: str = Field(min_length=1, max_length=255)


class CreateIntegration(DTO):
    name: str = Field(min_length=1, max_length=128)


class UpdateIntegration(DTO):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self, key) is None for key in self.model_fields_set):
            raise ValueError("At least one non-null change is required.")
        return self


class Rule(DTO):
    category: Category
    action: Action


class CreatePolicy(DTO):
    clone_policy_version_id: WireUUID | None = None
    detector_profile_version: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def reject_null(self):
        if any(getattr(self, key) is None for key in self.model_fields_set):
            raise ValueError("Optional fields must be omitted rather than null.")
        return self


class UpdatePolicy(DTO):
    rules: list[Rule] = Field(min_length=7, max_length=7)
    dictionary_version_ids: list[WireUUID]
    detector_profile_version: str = Field(max_length=128)

    @model_validator(mode="after")
    def complete(self):
        if {rule.category for rule in self.rules} != set(CATEGORIES):
            raise ValueError("Each of the seven categories must appear once.")
        if len(set(self.dictionary_version_ids)) != len(self.dictionary_version_ids):
            raise ValueError("Dictionary references must be unique.")
        return self


class ActivatePolicy(DTO):
    policy_version_id: WireUUID


class Entry(DTO):
    category: Category
    value: str = Field(min_length=1, max_length=2048)


class UpdateDictionary(DTO):
    entries: list[Entry] = Field(max_length=100000)

    @model_validator(mode="after")
    def unique_entries(self):
        if len({(entry.category, entry.value) for entry in self.entries}) != len(self.entries):
            raise ValueError("Dictionary entries must be unique.")
        return self


class CreateDictionary(UpdateDictionary):
    name: str = Field(min_length=1, max_length=128)


class Retention(DTO):
    audit_retention_days: int = Field(ge=1, le=3650)


class Provider(DTO):
    provider_label: str = Field(min_length=1, max_length=128)
    base_url: str = Field(pattern=r"^https://", max_length=2048)
    credential_ref: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    models: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1)
    connect_timeout_seconds: int = Field(ge=1, le=30)
    first_byte_timeout_seconds: int = Field(ge=1, le=120)
    idle_timeout_seconds: int = Field(ge=1, le=120)
    total_timeout_seconds: int = Field(ge=1, le=600)

    @model_validator(mode="after")
    def unique_models(self):
        if len(set(self.models)) != len(self.models):
            raise ValueError("Model identifiers must be unique.")
        return self


@contextmanager
def transaction(request):
    try:
        with request.app.state.engine.begin() as connection:
            yield connection
    except IntegrityError:
        fail(409, "conflict", "The change conflicts with an existing record.")
    except DBAPIError:
        fail(503, "database_unavailable", "The local database is unavailable.")


def rows(connection, sql, params=None):
    return [dict(row) for row in connection.execute(text(sql), params or {}).mappings().all()]


def one(connection, sql, params=None):
    result = rows(connection, sql, params)
    if not result:
        fail(404, "not_found", "The record was not found.")
    return result[0]


def identifier(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        fail(400, "invalid_request", "An identifier is invalid.")


def require_admin(request: Request) -> dict:
    raw_session = request.cookies.get(COOKIE_NAME, "")
    if not 32 <= len(raw_session) <= 128:
        fail(401, "invalid_session", "Sign in to continue.")
    expected_csrf = csrf_token(request.app.state.settings.csrf_secret, raw_session)
    with transaction(request) as connection:
        result = rows(connection, "SELECT u.id,u.username,u.display_name,u.role,s.id AS session_id,s.expires_at,"
                      "s.last_seen_at,s.created_at,s.csrf_token_hash FROM admin_sessions s JOIN users u ON u.id=s.user_id "
                      "WHERE s.session_token_hash=:hash AND s.revoked_at IS NULL AND u.role='admin' AND u.enabled "
                      "FOR UPDATE OF s", {"hash": digest(raw_session)})
        if not result:
            fail(401, "invalid_session", "Sign in to continue.")
        user = result[0]
        now = datetime.now(UTC)
        if (user["expires_at"] <= now or user["last_seen_at"] <= now - timedelta(minutes=30)
                or user["created_at"] <= now - timedelta(hours=8)
                or not hmac.compare_digest(bytes(user["csrf_token_hash"]), digest(expected_csrf))):
            fail(401, "invalid_session", "Sign in to continue.")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            same_origin(request.headers, request.app.state.settings.public_origin)
            token = request.headers.get("x-csrf-token", "")
            if not 32 <= len(token) <= 256 or not hmac.compare_digest(digest(token), bytes(user["csrf_token_hash"])):
                fail(403, "invalid_csrf", "Refresh the page and try again.")
        connection.execute(text("UPDATE admin_sessions SET last_seen_at=now() WHERE id=:id"), {"id": user["session_id"]})
    request.state.admin_session_id = user["session_id"]
    request.state.admin_expires_at = user["expires_at"]
    request.state.csrf_token = expected_csrf
    return {key: user[key] for key in ("id", "username", "display_name", "role")}


Admin = Annotated[dict, Depends(require_admin)]


@router.post("/auth/login")
def login_admin(body: Login, request: Request, response: Response):
    same_origin(request.headers, request.app.state.settings.public_origin)
    with _limiter_init_lock:
        if not hasattr(request.app.state, "login_limiter"):
            request.app.state.login_limiter = LoginLimiter()
    request.app.state.login_limiter.check(request.client.host if request.client else "unknown")
    with transaction(request) as connection:
        found = rows(connection, "SELECT u.id,u.username,u.display_name,u.role,c.password_hash FROM users u "
                     "JOIN admin_credentials c ON u.id=c.user_id WHERE u.username=:name AND u.enabled AND u.role='admin' "
                     "FOR SHARE OF u,c", {"name": body.username.lower()})
        valid = verify_password(found[0]["password_hash"] if found else DUMMY_HASH, body.password)
        if not found or not valid:
            fail(401, "invalid_credentials", "Username or password is incorrect.")
        raw_session = secrets.token_urlsafe(32)
        csrf = csrf_token(request.app.state.settings.csrf_secret, raw_session)
        expires = datetime.now(UTC) + timedelta(hours=8)
        connection.execute(text("INSERT INTO admin_sessions(id,user_id,session_token_hash,csrf_token_hash,expires_at) "
                                "VALUES (:id,:user,:session,:csrf,:expiry)"),
                           {"id": uuid.uuid4(), "user": found[0]["id"], "session": digest(raw_session), "csrf": digest(csrf), "expiry": expires})
        user = {key: found[0][key] for key in ("id", "username", "display_name", "role")}
    response.set_cookie(COOKIE_NAME, raw_session, max_age=8 * 3600, secure=True, httponly=True,
                        samesite="strict", path="/admin/api")
    response.headers["Cache-Control"] = "no-store"
    return {"user": user, "csrf_token": csrf, "expires_at": expires}


@router.get("/auth/me")
def current_admin(request: Request, response: Response, admin: Admin):
    response.headers["Cache-Control"] = "no-store"
    return {"user": admin, "csrf_token": request.state.csrf_token, "expires_at": request.state.admin_expires_at}


@router.post("/auth/logout", status_code=204)
def logout_admin(request: Request, response: Response, admin: Admin):
    with transaction(request) as connection:
        connection.execute(text("UPDATE admin_sessions SET revoked_at=now() WHERE id=:id"), {"id": request.state.admin_session_id})
    response.delete_cookie(COOKIE_NAME, path="/admin/api", secure=True, httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"


USER_SELECT = "SELECT u.id,u.username,u.display_name,u.role,u.enabled,u.created_at," \
              "(SELECT count(*) FROM external_identities i WHERE i.user_id=u.id AND i.revoked_at IS NULL) AS identity_count FROM users u "


def cursor_value(value, kind):
    if value is None:
        return None
    if len(value) > 512:
        fail(400, "invalid_cursor")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
        prefix, content = decoded.split(":", 1)
        if prefix != kind:
            raise ValueError
        return content
    except (ValueError, UnicodeError):
        fail(400, "invalid_cursor")


def encode_cursor(kind, value):
    return base64.urlsafe_b64encode(f"{kind}:{value}".encode()).decode().rstrip("=")


@router.get("/users")
def list_users(request: Request, admin: Admin, limit: int = Query(50, ge=1, le=100), cursor: str | None = None,
               role: Role | None = None, enabled: bool | None = None):
    after = cursor_value(cursor, "users")
    clauses, params = ["true"], {"limit": limit + 1}
    if after:
        clauses.append("u.id > :after")
        params["after"] = identifier(after)
    if role is not None:
        clauses.append("u.role=:role")
        params["role"] = role
    if enabled is not None:
        clauses.append("u.enabled=:enabled")
        params["enabled"] = enabled
    with transaction(request) as connection:
        result = rows(connection, USER_SELECT + "WHERE " + " AND ".join(clauses) + " ORDER BY u.id LIMIT :limit", params)
    return {"items": result[:limit], "next_cursor": encode_cursor("users", result[limit - 1]["id"]) if len(result) > limit else None}


@router.post("/users", status_code=201)
def create_user(body: CreateUser, request: Request, admin: Admin):
    user_id = uuid.uuid4()
    with transaction(request) as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK})
        connection.execute(text("INSERT INTO users(id,username,display_name,role) VALUES (:id,:username,:display_name,:role)"),
                           body.model_dump() | {"id": user_id})
        return one(connection, USER_SELECT + "WHERE u.id=:id", {"id": user_id})


@router.get("/users/{userId}")
def get_user(userId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        return one(connection, USER_SELECT + "WHERE u.id=:id", {"id": userId})


def change_user(connection, user_id, changes):
    # One installation-wide lock is sufficient for the deliberately small control plane.
    connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK})
    old = one(connection, "SELECT * FROM users WHERE id=:id FOR UPDATE", {"id": user_id})
    removing_admin = old["role"] == "admin" and old["enabled"] and (
        changes.get("role", old["role"]) != "admin" or not changes.get("enabled", old["enabled"]))
    if removing_admin and connection.execute(text(
        "SELECT count(*) FROM users u JOIN admin_credentials c ON c.user_id=u.id "
        "WHERE u.enabled AND u.role='admin' AND u.id<>:id"), {"id": user_id}).scalar_one() == 0:
        fail(409, "last_admin", "At least one enabled administrator with a password is required.")
    changed = {key: value for key, value in changes.items() if key in ("display_name", "role", "enabled")}
    assignment = ",".join(f"{key}=:{key}" for key in changed)
    connection.execute(text(f"UPDATE users SET {assignment},updated_at=now() WHERE id=:id"), changed | {"id": user_id})
    if old["role"] == "admin" and (changed.get("role", old["role"]) != "admin" or not changed.get("enabled", old["enabled"])):
        connection.execute(text("UPDATE admin_sessions SET revoked_at=now() WHERE user_id=:id AND revoked_at IS NULL"), {"id": user_id})
        if changed.get("role", old["role"]) != "admin":
            connection.execute(text("DELETE FROM admin_credentials WHERE user_id=:id"), {"id": user_id})
    return one(connection, USER_SELECT + "WHERE u.id=:id", {"id": user_id})


@router.patch("/users/{userId}")
def update_user(userId: uuid.UUID, body: UpdateUser, request: Request, admin: Admin):
    with transaction(request) as connection:
        return change_user(connection, userId, body.model_dump(exclude_unset=True))


@router.put("/users/{userId}/admin-credential", status_code=204)
def set_admin_credential(userId: uuid.UUID, body: Password, request: Request, admin: Admin):
    encoded = hash_password(body.password)
    with transaction(request) as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK})
        user = one(connection, "SELECT role FROM users WHERE id=:id FOR UPDATE", {"id": userId})
        if user["role"] != "admin":
            fail(400, "admin_role_required")
        connection.execute(text("INSERT INTO admin_credentials(user_id,password_hash) VALUES (:id,:hash) "
                                "ON CONFLICT(user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,changed_at=now()"),
                           {"id": userId, "hash": encoded})
        connection.execute(text("UPDATE admin_sessions SET revoked_at=now() WHERE user_id=:id AND revoked_at IS NULL"), {"id": userId})


IDENTITY_SELECT = "SELECT id,integration_id,external_subject,created_at,revoked_at FROM external_identities "


@router.get("/users/{userId}/identities")
def list_identities(userId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        one(connection, "SELECT id FROM users WHERE id=:id", {"id": userId})
        return rows(connection, IDENTITY_SELECT + "WHERE user_id=:id ORDER BY created_at,id", {"id": userId})


@router.post("/users/{userId}/identities", status_code=201)
def add_identity(userId: uuid.UUID, body: AddIdentity, request: Request, admin: Admin):
    integration_id, identity_id = identifier(body.integration_id), uuid.uuid4()
    with transaction(request) as connection:
        one(connection, "SELECT id FROM users WHERE id=:id", {"id": userId})
        one(connection, "SELECT id FROM client_integrations WHERE id=:id", {"id": integration_id})
        connection.execute(text("INSERT INTO external_identities(id,integration_id,user_id,external_subject) VALUES (:id,:integration,:user,:subject)"),
                           {"id": identity_id, "integration": integration_id, "user": userId, "subject": body.external_subject})
        return one(connection, IDENTITY_SELECT + "WHERE id=:id", {"id": identity_id})


@router.delete("/users/{userId}/identities/{identityId}", status_code=204)
def remove_identity(userId: uuid.UUID, identityId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        result = connection.execute(text("UPDATE external_identities SET revoked_at=COALESCE(revoked_at,now()) WHERE id=:id AND user_id=:user"),
                                    {"id": identityId, "user": userId})
        if result.rowcount != 1:
            fail(404, "not_found")


INTEGRATION_SELECT = "SELECT id,name,enabled,created_at FROM client_integrations "


@router.get("/integrations")
def list_integrations(request: Request, admin: Admin):
    with transaction(request) as connection:
        return rows(connection, INTEGRATION_SELECT + "ORDER BY created_at,id")


@router.post("/integrations", status_code=201)
def create_integration(body: CreateIntegration, request: Request, response: Response, admin: Admin):
    integration_id, key = uuid.uuid4(), secrets.token_urlsafe(32)
    with transaction(request) as connection:
        connection.execute(text("INSERT INTO client_integrations(id,name,bearer_key_hash) VALUES (:id,:name,:hash)"),
                           {"id": integration_id, "name": body.name, "hash": digest(key)})
        integration = one(connection, INTEGRATION_SELECT + "WHERE id=:id", {"id": integration_id})
    response.headers["Cache-Control"] = "no-store"
    return {"integration": integration, "integration_bearer_key": key}


@router.patch("/integrations/{integrationId}")
def update_integration(integrationId: uuid.UUID, body: UpdateIntegration, request: Request, admin: Admin):
    changes = body.model_dump(exclude_unset=True)
    assignments = ",".join(f"{key}=:{key}" for key in changes)
    with transaction(request) as connection:
        updated = connection.execute(text(f"UPDATE client_integrations SET {assignments},updated_at=now() WHERE id=:id"),
                                     changes | {"id": integrationId})
        if updated.rowcount != 1:
            fail(404, "not_found")
        return one(connection, INTEGRATION_SELECT + "WHERE id=:id", {"id": integrationId})


@router.post("/integrations/{integrationId}/rotate-key")
def rotate_integration_key(integrationId: uuid.UUID, request: Request, response: Response, admin: Admin):
    key = secrets.token_urlsafe(32)
    with transaction(request) as connection:
        updated = rows(connection, "UPDATE client_integrations SET bearer_key_hash=:hash,updated_at=now() WHERE id=:id RETURNING updated_at",
                       {"id": integrationId, "hash": digest(key)})
        if not updated:
            fail(404, "not_found")
    response.headers["Cache-Control"] = "no-store"
    return {"integration_id": integrationId, "integration_bearer_key": key, "rotated_at": updated[0]["updated_at"]}


POLICY_SELECT = "SELECT p.id,p.version,p.status,p.created_at,p.published_at," \
                "d.profile_name || ':' || d.version::text AS detector_profile_version," \
                "(SELECT count(*) FROM policy_rules r WHERE r.policy_version_id=p.id) AS rule_count," \
                "(SELECT count(*) FROM policy_dictionaries x WHERE x.policy_version_id=p.id) AS dictionary_count " \
                "FROM policy_versions p JOIN detector_profile_versions d ON d.id=p.detector_profile_id "
DICTIONARY_SELECT = "SELECT d.id,d.name,d.version,d.status,d.created_at,d.published_at," \
                    "(SELECT count(*) FROM dictionary_entries e WHERE e.dictionary_version_id=d.id) AS entry_count " \
                    "FROM dictionary_versions d "


def get_policy(connection, policy_id):
    policy = one(connection, POLICY_SELECT + "WHERE p.id=:id", {"id": policy_id})
    policy["rules"] = rows(connection, "SELECT category,action FROM policy_rules WHERE policy_version_id=:id ORDER BY category", {"id": policy_id})
    policy["dictionary_version_ids"] = [row["dictionary_version_id"] for row in rows(
        connection, "SELECT dictionary_version_id FROM policy_dictionaries WHERE policy_version_id=:id ORDER BY dictionary_version_id", {"id": policy_id})]
    return policy


def profile_id(connection, version):
    from .detection import profile_checksum

    if version is None:
        profile = one(connection, "SELECT id,bundle_checksum FROM detector_profile_versions WHERE bundle_checksum=:checksum "
                      "ORDER BY version DESC,created_at DESC LIMIT 1", {"checksum": profile_checksum()})
    else:
        profile = one(connection, "SELECT id,bundle_checksum FROM detector_profile_versions "
                      "WHERE profile_name || ':' || version::text=:version", {"version": version})
    if profile["bundle_checksum"] != profile_checksum():
        fail(409, "detector_profile_mismatch", "This detector bundle is not deployed. Run the reviewed installation upgrade.")
    return profile["id"]


@router.get("/detector-profile-versions")
def list_detector_profiles(request: Request, admin: Admin):
    from .detection import profile_checksum

    with transaction(request) as connection:
        profiles = rows(connection, "SELECT id,profile_name,version,bundle_checksum FROM detector_profile_versions "
                        "ORDER BY profile_name,version DESC")
    checksum = profile_checksum()
    return [profile | {"deployed": profile["bundle_checksum"] == checksum} for profile in profiles]


def ensure_draft(connection, table, version_id):
    # Table comes exclusively from fixed callers. Row lock serializes edits/publication.
    row = one(connection, f"SELECT status FROM {table} WHERE id=:id FOR UPDATE", {"id": version_id})
    if row["status"] != "draft":
        fail(409, "immutable_version", "Published versions cannot be changed.")


@router.get("/policy-versions")
def list_policy_versions(request: Request, admin: Admin):
    with transaction(request) as connection:
        return rows(connection, POLICY_SELECT + "ORDER BY p.version DESC")


@router.post("/policy-versions", status_code=201)
def create_policy_draft(body: CreatePolicy, request: Request, admin: Admin):
    policy_id = uuid.uuid4()
    with transaction(request) as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": VERSION_LOCK})
        clone_id = identifier(body.clone_policy_version_id) if body.clone_policy_version_id else None
        clone = None
        # Clone a single committed draft snapshot: edits/publication use the same parent row lock.
        if clone_id:
            one(connection, "SELECT id FROM policy_versions WHERE id=:id FOR SHARE", {"id": clone_id})
            clone = get_policy(connection, clone_id)
        detector_id = profile_id(connection, body.detector_profile_version or (clone["detector_profile_version"] if clone else None))
        next_version = connection.execute(text("SELECT COALESCE(max(version),0)+1 FROM policy_versions")).scalar_one()
        connection.execute(text("INSERT INTO policy_versions(id,version,based_on_id,detector_profile_id,created_by_user_id) "
                                "VALUES (:id,:version,:clone,:profile,:admin)"),
                           {"id": policy_id, "version": next_version, "clone": clone_id, "profile": detector_id, "admin": admin["id"]})
        rules = clone["rules"] if clone else [{"category": category, "action": action} for category, action in DEFAULT_ACTIONS.items()]
        connection.execute(text("INSERT INTO policy_rules(policy_version_id,category,action) VALUES (:id,:category,:action)"),
                           [{"id": policy_id} | rule for rule in rules])
        if clone and clone["dictionary_version_ids"]:
            connection.execute(text("INSERT INTO policy_dictionaries(policy_version_id,dictionary_version_id) VALUES (:id,:dictionary)"),
                               [{"id": policy_id, "dictionary": version} for version in clone["dictionary_version_ids"]])
        return get_policy(connection, policy_id)


@router.get("/policy-versions/{policyVersionId}")
def get_policy_version(policyVersionId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        return get_policy(connection, policyVersionId)


@router.put("/policy-versions/{policyVersionId}")
def update_policy_draft(policyVersionId: uuid.UUID, body: UpdatePolicy, request: Request, admin: Admin):
    with transaction(request) as connection:
        ensure_draft(connection, "policy_versions", policyVersionId)
        detector_id = profile_id(connection, body.detector_profile_version)
        dictionaries = [identifier(value) for value in body.dictionary_version_ids]
        if len(set(dictionaries)) != len(dictionaries):
            fail(400, "invalid_request")
        for dictionary_id in sorted(dictionaries):
            # The reference link trigger takes FOR UPDATE too. Taking the same
            # lock up front avoids concurrent SHARE-to-UPDATE lock upgrades.
            dictionary = one(connection, "SELECT status FROM dictionary_versions WHERE id=:id FOR UPDATE", {"id": dictionary_id})
            if dictionary["status"] != "published":
                fail(409, "unpublished_dictionary", "Publish each dictionary before linking it.")
        connection.execute(text("UPDATE policy_versions SET detector_profile_id=:profile WHERE id=:id"), {"profile": detector_id, "id": policyVersionId})
        connection.execute(text("DELETE FROM policy_rules WHERE policy_version_id=:id"), {"id": policyVersionId})
        connection.execute(text("INSERT INTO policy_rules(policy_version_id,category,action) VALUES (:id,:category,:action)"),
                           [{"id": policyVersionId} | rule.model_dump() for rule in body.rules])
        connection.execute(text("DELETE FROM policy_dictionaries WHERE policy_version_id=:id"), {"id": policyVersionId})
        if dictionaries:
            connection.execute(text("INSERT INTO policy_dictionaries(policy_version_id,dictionary_version_id) VALUES (:id,:dictionary)"),
                               [{"id": policyVersionId, "dictionary": dictionary_id} for dictionary_id in dictionaries])
        return get_policy(connection, policyVersionId)


@router.post("/policy-versions/{policyVersionId}/publish")
def publish_policy_version(policyVersionId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        ensure_draft(connection, "policy_versions", policyVersionId)
        policy = get_policy(connection, policyVersionId)
        if {rule["category"] for rule in policy["rules"]} != set(CATEGORIES):
            fail(409, "incomplete_policy", "All seven category actions are required.")
        connection.execute(text("UPDATE policy_versions SET status='published',published_at=now(),published_by_user_id=:admin WHERE id=:id"),
                           {"admin": admin["id"], "id": policyVersionId})
        return get_policy(connection, policyVersionId)


ACTIVE_SELECT = "SELECT a.policy_version_id,p.version AS policy_version,a.revision,a.updated_at " \
                "FROM active_policy a JOIN policy_versions p ON p.id=a.policy_version_id WHERE a.singleton"


def etag_revision(request):
    value = request.headers.get("if-match", "")
    if len(value) > 22 or not re.fullmatch(r'"[0-9]+"', value):
        fail(400, "invalid_revision", "A valid If-Match revision is required.")
    revision = int(value[1:-1])
    if not 1 <= revision <= 9223372036854775807:
        fail(400, "invalid_revision")
    return revision


@router.get("/active-policy")
def active_policy(request: Request, response: Response, admin: Admin):
    with transaction(request) as connection:
        pointer = one(connection, ACTIVE_SELECT)
    response.headers["ETag"] = f'"{pointer["revision"]}"'
    return pointer


@router.put("/active-policy")
def activate_policy(body: ActivatePolicy, request: Request, response: Response, admin: Admin):
    expected, policy_id = etag_revision(request), identifier(body.policy_version_id)
    with transaction(request) as connection:
        policy = one(connection, "SELECT status FROM policy_versions WHERE id=:id", {"id": policy_id})
        if policy["status"] != "published":
            fail(409, "unpublished_policy", "Publish the policy before activating it.")
        deployed = one(connection, POLICY_SELECT + "WHERE p.id=:id", {"id": policy_id})
        profile_id(connection, deployed["detector_profile_version"])
        changed = connection.execute(text("UPDATE active_policy SET policy_version_id=:id,revision=revision+1,updated_at=now(),"
                                          "updated_by_user_id=:admin WHERE singleton AND revision=:revision"),
                                     {"id": policy_id, "admin": admin["id"], "revision": expected})
        if changed.rowcount != 1:
            fail(409, "stale_revision", "The active policy changed. Reload and try again.")
        pointer = one(connection, ACTIVE_SELECT)
    response.headers["ETag"] = f'"{pointer["revision"]}"'
    return pointer


@router.get("/policy-activations")
def list_activations(request: Request, admin: Admin, limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    after = cursor_value(cursor, "activations")
    try:
        before = int(after) if after else 9223372036854775807
    except ValueError:
        fail(400, "invalid_cursor")
    if not 1 <= before <= 9223372036854775807:
        fail(400, "invalid_cursor")
    where = "a.revision<:before" if after else "true"
    with transaction(request) as connection:
        result = rows(connection, "SELECT a.revision,a.policy_version_id,p.version AS policy_version,a.actor_user_id,a.occurred_at "
                      "FROM policy_activations a JOIN policy_versions p ON p.id=a.policy_version_id "
                      f"WHERE {where} ORDER BY a.revision DESC LIMIT :limit", {"before": before, "limit": limit + 1})
    return {"items": result[:limit], "next_cursor": encode_cursor("activations", result[limit - 1]["revision"]) if len(result) > limit else None}


def get_dictionary(connection, dictionary_id, entries=True):
    dictionary = one(connection, DICTIONARY_SELECT + "WHERE d.id=:id", {"id": dictionary_id})
    if entries:
        dictionary["entries"] = rows(connection, "SELECT category,entry_value AS value FROM dictionary_entries "
                                     "WHERE dictionary_version_id=:id ORDER BY category,entry_value", {"id": dictionary_id})
    return dictionary


def insert_entries(connection, dictionary_id, entries):
    if entries:
        connection.execute(text("INSERT INTO dictionary_entries(id,dictionary_version_id,category,entry_value) VALUES (:id,:dictionary,:category,:value)"),
                           [{"id": uuid.uuid4(), "dictionary": dictionary_id} | entry.model_dump() for entry in entries])


@router.get("/dictionary-versions")
def list_dictionaries(request: Request, admin: Admin):
    with transaction(request) as connection:
        return rows(connection, DICTIONARY_SELECT + "ORDER BY d.created_at DESC,d.id DESC")


@router.post("/dictionary-versions", status_code=201)
def create_dictionary(body: CreateDictionary, request: Request, admin: Admin):
    dictionary_id = uuid.uuid4()
    with transaction(request) as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": VERSION_LOCK})
        version = connection.execute(text("SELECT COALESCE(max(version),0)+1 FROM dictionary_versions WHERE name=:name"), {"name": body.name}).scalar_one()
        connection.execute(text("INSERT INTO dictionary_versions(id,name,version,created_by_user_id) VALUES (:id,:name,:version,:admin)"),
                           {"id": dictionary_id, "name": body.name, "version": version, "admin": admin["id"]})
        insert_entries(connection, dictionary_id, body.entries)
        return get_dictionary(connection, dictionary_id)


@router.get("/dictionary-versions/{dictionaryVersionId}")
def get_dictionary_version(dictionaryVersionId: uuid.UUID, request: Request, response: Response, admin: Admin):
    response.headers["Cache-Control"] = "no-store"
    with transaction(request) as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        return get_dictionary(connection, dictionaryVersionId)


@router.put("/dictionary-versions/{dictionaryVersionId}")
def update_dictionary(dictionaryVersionId: uuid.UUID, body: UpdateDictionary, request: Request, admin: Admin):
    with transaction(request) as connection:
        ensure_draft(connection, "dictionary_versions", dictionaryVersionId)
        connection.execute(text("DELETE FROM dictionary_entries WHERE dictionary_version_id=:id"), {"id": dictionaryVersionId})
        insert_entries(connection, dictionaryVersionId, body.entries)
        return get_dictionary(connection, dictionaryVersionId)


@router.post("/dictionary-versions/{dictionaryVersionId}/publish")
def publish_dictionary(dictionaryVersionId: uuid.UUID, request: Request, admin: Admin):
    with transaction(request) as connection:
        ensure_draft(connection, "dictionary_versions", dictionaryVersionId)
        connection.execute(text("UPDATE dictionary_versions SET status='published',published_at=now(),published_by_user_id=:admin WHERE id=:id"),
                           {"id": dictionaryVersionId, "admin": admin["id"]})
        return get_dictionary(connection, dictionaryVersionId, entries=False)


PROVIDER_SELECT = "SELECT revision,provider_label,base_url,credential_ref,allowed_models AS models," \
                  "connect_timeout_seconds,first_byte_timeout_seconds,idle_timeout_seconds,total_timeout_seconds FROM provider_config WHERE singleton"


@router.get("/settings/provider")
def provider_settings(request: Request, response: Response, admin: Admin):
    with transaction(request) as connection:
        result = one(connection, PROVIDER_SELECT)
    response.headers["ETag"] = f'"{result["revision"]}"'
    return result


@router.put("/settings/provider")
def update_provider(body: Provider, request: Request, response: Response, admin: Admin):
    from .provider import validate_provider_settings
    expected, data = etag_revision(request), body.model_dump()
    try:
        validate_provider_settings(request.app.state.settings, data)
    except ValueError:
        fail(400, "invalid_provider_config", "Provider destination or secret reference is not allowed.")
    assignments = ",".join(f'{"allowed_models" if key == "models" else key}=:{key}' for key in data)
    with transaction(request) as connection:
        result = connection.execute(text(f"UPDATE provider_config SET {assignments},revision=revision+1,updated_at=now(),"
                                         "updated_by_user_id=:admin WHERE singleton AND revision=:revision"),
                                    data | {"admin": admin["id"], "revision": expected})
        if result.rowcount != 1:
            fail(409, "stale_revision", "Provider settings changed. Reload and try again.")
        updated = one(connection, PROVIDER_SELECT)
    response.headers["ETag"] = f'"{updated["revision"]}"'
    return updated


@router.get("/settings/retention")
def retention_settings(request: Request, admin: Admin):
    with transaction(request) as connection:
        return one(connection, "SELECT retention_days AS audit_retention_days FROM audit_retention_settings WHERE singleton")


@router.put("/settings/retention")
def update_retention(body: Retention, request: Request, admin: Admin):
    with transaction(request) as connection:
        connection.execute(text("UPDATE audit_retention_settings SET retention_days=:days,updated_at=now(),updated_by_user_id=:admin WHERE singleton"),
                           {"days": body.audit_retention_days, "admin": admin["id"]})
    return body.model_dump()


AUDIT_COLUMNS = "id,request_id,occurred_at,integration_id,user_id,policy_version_id,provider_config_revision,provider_label," \
                "decision,state,model,stream,output_chunks_forwarded,request_bytes,message_count,duration_ms,first_byte_ms," \
                "provider_http_status,safe_error_code,outcome_deadline_at"
RETAINED = "occurred_at >= now() - ((SELECT retention_days FROM audit_retention_settings WHERE singleton) * interval '1 day')"


def audit_details(connection, event):
    event["findings"] = rows(connection, "SELECT category,action,finding_count AS count FROM audit_findings WHERE audit_event_id=:id ORDER BY category,action", {"id": event["id"]})
    event["states"] = rows(connection, "SELECT sequence,state,occurred_at,safe_error_code FROM audit_event_states WHERE audit_event_id=:id ORDER BY sequence", {"id": event["id"]})
    return event


def time_range(from_time, to_time):
    if (from_time and from_time.utcoffset() is None) or (to_time and to_time.utcoffset() is None):
        fail(400, "invalid_time_range", "Time bounds must include a time zone.")
    if from_time and to_time and from_time >= to_time:
        fail(400, "invalid_time_range", "The start must be earlier than the end.")


@router.get("/audit")
def list_audit(request: Request, admin: Admin, limit: int = Query(50, ge=1, le=100), cursor: str | None = None,
               from_time: Annotated[datetime | None, Query(alias="from")] = None,
               to_time: Annotated[datetime | None, Query(alias="to")] = None,
               state: AuditState | None = None, decision: Action | None = None, user_id: uuid.UUID | None = None,
               category: Category | None = None):
    time_range(from_time, to_time)
    clauses, params = [RETAINED], {"limit": limit + 1}
    for value, name, clause in ((from_time, "from", "occurred_at>=:from"), (to_time, "to", "occurred_at<:to"),
                                (state, "state", "state=:state"), (decision, "decision", "decision=:decision"),
                                (user_id, "user", "user_id=:user")):
        if value is not None:
            clauses.append(clause)
            params[name] = value
    if category is not None:
        clauses.append("EXISTS (SELECT 1 FROM audit_findings f WHERE f.audit_event_id=audit_events.id AND f.category=:category)")
        params["category"] = category
    decoded = cursor_value(cursor, "audit")
    if decoded:
        try:
            occurred_at, event_id = decoded.split("|", 1)
            point = datetime.fromisoformat(occurred_at)
            if point.utcoffset() is None:
                raise ValueError
            params.update(before_time=point, before_id=identifier(event_id))
        except (ValueError, TypeError):
            fail(400, "invalid_cursor")
        clauses.append("(occurred_at,id)<(:before_time,:before_id)")
    with transaction(request) as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        result = rows(connection, "SELECT " + AUDIT_COLUMNS + " FROM audit_events WHERE " + " AND ".join(clauses) + " ORDER BY occurred_at DESC,id DESC LIMIT :limit", params)
        # ponytail: at most 100 events; batch child reads if audit latency warrants it.
        items = [audit_details(connection, event) for event in result[:limit]]
    next_cursor = encode_cursor("audit", f'{items[-1]["occurred_at"].isoformat()}|{items[-1]["id"]}') if len(result) > limit else None
    return {"items": items, "next_cursor": next_cursor}


@router.get("/statistics")
def statistics(request: Request, admin: Admin, from_time: Annotated[datetime, Query(alias="from")],
               to_time: Annotated[datetime, Query(alias="to")]):
    time_range(from_time, to_time)
    params = {"from": from_time, "to": to_time}
    filtered = " FROM audit_events WHERE " + RETAINED + " AND occurred_at>=:from AND occurred_at<:to"
    with transaction(request) as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        total = connection.execute(text("SELECT count(*)" + filtered), params).scalar_one()
        states = {row["state"]: row["count"] for row in rows(connection, "SELECT state,count(*) AS count" + filtered + " GROUP BY state", params)}
        decisions = {row["decision"]: row["count"] for row in rows(connection, "SELECT decision,count(*) AS count" + filtered + " AND decision IS NOT NULL GROUP BY decision", params)}
        findings = rows(connection, "SELECT f.category,f.action,sum(f.finding_count)::bigint AS count FROM audit_findings f JOIN audit_events a ON a.id=f.audit_event_id "
                        "WHERE a.id IN (SELECT id" + filtered + ") GROUP BY f.category,f.action ORDER BY f.category,f.action", params)
        latency = one(connection, "SELECT percentile_disc(0.50) WITHIN GROUP (ORDER BY duration_ms) AS p50_ms,"
                      "percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_ms,"
                      "percentile_disc(0.99) WITHIN GROUP (ORDER BY duration_ms) AS p99_ms" + filtered + " AND duration_ms IS NOT NULL", params)
    return {"from": from_time, "to": to_time, "total_requests": total, "states": states, "decisions": decisions, "findings": findings, "latency": latency}
