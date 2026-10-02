import base64
import hashlib
import re
import time

import jwt
from sqlalchemy import text

from gateway.protocol import GatewayError, load_json


def unique_header(request, name: str, required=True):
    values = request.headers.getlist(name)
    if len(values) != 1:
        if not required and not values:
            return None
        raise GatewayError(401 if name != "x-openwebui-chat-id" else 400, "invalid_identity")
    if len(values[0]) > 8192:
        raise GatewayError(401, "invalid_identity")
    return values[0]


def verify_claims(token: str, settings) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3 or len(token) > 8192:
            raise ValueError("jwt")
        for part in parts[:2]:
            decoded = load_json(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            if not isinstance(decoded, dict):
                raise TypeError("jwt")
        claims = jwt.decode(
            token,
            settings.identity_secret,
            algorithms=["HS256"],
            issuer="open-webui",
            options={"require": ["iss", "sub", "iat", "exp"], "verify_aud": False},
            leeway=60,
        )
        now = time.time()
        if (
            not isinstance(claims["sub"], str)
            or not 1 <= len(claims["sub"]) <= 255
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 300
            or claims["iat"] > now + 60
            or claims["exp"] <= now
        ):
            raise ValueError("claims")
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, GatewayError):
        raise GatewayError(401, "invalid_identity") from None


def authenticate(request, chat=False):
    auth = unique_header(request, "authorization")
    if not auth.startswith("Bearer ") or not 20 <= len(auth[7:]) <= 512:
        raise GatewayError(401, "invalid_identity")
    # Plain forwarded identity is never an alternative authority.
    if any(
        request.headers.getlist(k)
        for k in (
            "x-openwebui-user-id",
            "x-openwebui-user-email",
            "x-openwebui-user-role",
            "x-openwebui-user-name",
        )
    ):
        raise GatewayError(401, "invalid_identity")
    claims = verify_claims(unique_header(request, "x-openwebui-user-jwt"), request.app.state.settings)
    chat_id = None
    if chat:
        chat_id = unique_header(request, "x-openwebui-chat-id", False)
        if chat_id is None or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", chat_id):
            raise GatewayError(400, "conversation_scope_required")
    with request.app.state.engine.connect() as conn:
        row = (
            conn.execute(
                text("""SELECT i.id AS integration_id, e.id AS external_identity_id,
              e.user_id, e.external_subject FROM client_integrations i
              JOIN external_identities e ON e.integration_id=i.id
              JOIN users u ON u.id=e.user_id
              WHERE i.bearer_key_hash=:digest AND i.enabled AND e.external_subject=:sub
              AND e.revoked_at IS NULL AND u.enabled"""),
                {"digest": hashlib.sha256(auth[7:].encode()).digest(), "sub": claims["sub"]},
            )
            .mappings()
            .first()
        )
    if row is None:
        raise GatewayError(403, "identity_not_allowed")
    return dict(row) | {"issuer": "open-webui", "sub": claims["sub"], "chat_id": chat_id}
