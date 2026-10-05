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
    base_url: str = Field(pattern=r"^https://")
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
