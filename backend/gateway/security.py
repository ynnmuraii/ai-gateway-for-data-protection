"""Small secret-handling helpers shared by local administration and bootstrap."""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from argon2.low_level import Type
from fastapi import HTTPException

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
COOKIE_NAME = "gw_admin_session"


def fail(status: int, code: str, message: str = "The operation could not be completed."):
    kind = {401: "authentication_error", 403: "authorization_error", 429: "rate_limit_exceeded"}.get(
        status, "gateway_error"
    )
    headers = {"Cache-Control": "no-store"}
    if status == 429:
        headers["Retry-After"] = "300"
    raise HTTPException(status, detail={"error": {"message": message, "type": kind, "param": None, "code": code}}, headers=headers)


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 1024:
        raise ValueError("Password must contain 12 to 1024 characters.")
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Password must contain valid Unicode.") from None
    return PASSWORDS.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, password)
    except (Argon2Error, ValueError, UnicodeError):
        return False


def csrf_token(secret: str, session: str) -> str:
    fields = (b"gateway-csrf-v1", session.encode("utf-8"))
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return base64.urlsafe_b64encode(hmac.digest(secret.encode(), framed, "sha256")).decode().rstrip("=")


def same_origin(headers, expected: str):
    def origin(value):
        try:
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                return None
            return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return None
    target = origin(expected)
    if target is None:
        fail(503, "invalid_origin_configuration")
    supplied = headers.get("origin")
    if supplied is not None:
        # An Origin is just an origin, never a URL path or an origin list.
        try:
            parts = urlsplit(supplied)
        except ValueError:
            fail(403, "invalid_origin")
        if any(ord(character) <= 32 for character in supplied):
            fail(403, "invalid_origin")
        if parts.path or parts.query or parts.fragment or origin(supplied) != target:
            fail(403, "invalid_origin")
    elif origin(headers.get("referer", "")) != target:
        fail(403, "invalid_origin")


class LoginLimiter:
    """Bounded process-local throttle; reverse-proxy limit applies across workers."""
    def __init__(self):
        self.lock = threading.Lock()
        self.attempts = {}
        self.global_attempts = deque()

    def check(self, address: str):
        now = time.monotonic()
        with self.lock:
            self.attempts = {key: values for key, values in self.attempts.items() if values[-1] > now - 300}
            while self.global_attempts and self.global_attempts[0] <= now - 60:
                self.global_attempts.popleft()
            attempts = self.attempts.get(address, deque())
            while attempts and attempts[0] <= now - 300:
                attempts.popleft()
            if len(attempts) >= 10 or len(self.global_attempts) >= 200 or len(self.attempts) >= 2048:
                fail(429, "rate_limit_exceeded", "Please try again later.")
            attempts.append(now)
            self.attempts[address] = attempts
            self.global_attempts.append(now)
