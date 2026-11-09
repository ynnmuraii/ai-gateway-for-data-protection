import json
import time

import jwt
import pytest
from gateway.identity import verify_claims
from gateway.protocol import GatewayError, load_json, parse_chat
from gateway.provider import validate_provider_settings
from gateway.settings import Settings


def settings():
    return Settings(csrf_secret="c" * 32, pseudonym_secret="p" * 32, identity_secret="i" * 32)


def test_chat_rejects_unscanned_fields_and_drops_compatibility_user():
    base = {"model": "demo-model", "messages": [{"role": "user", "content": "safe"}]}
    for change in [
        {"stop": "secret"},
        {"tools": []},
        {"messages": [{"role": "tool", "content": "secret"}]},
        {"messages": [{"role": "user", "content": []}]},
        {"temperature": True},
    ]:
        with pytest.raises(GatewayError):
            parse_chat(json.dumps(base | change).encode())
    assert "user" not in parse_chat(json.dumps(base | {"user": "not-trusted"}).encode())


def test_json_duplicates_and_nonfinite_rejected():
    for body in [b'{"model":"a","model":"b","messages":[]}', b'{"temperature":NaN}', b"null"]:
        with pytest.raises(GatewayError):
            parse_chat(body)


@pytest.mark.parametrize(
    "body", [b'{"value":1e400}', b'{"nested":{"value":-1e400}}', b"[0,1e999]", b'{"x":Infinity}']
)
def test_json_loader_rejects_nested_overflow_before_schema_or_response_encoding(body):
    with pytest.raises(GatewayError) as failure:
        load_json(body)
    assert failure.value.status_code == 400 and failure.value.code == "invalid_request"
    assert body.decode() not in str(failure.value)


def test_json_loader_preserves_finite_exponent_values():
    assert load_json(b'{"value":1e3,"nested":[-1e-3]}') == {"value": 1000.0, "nested": [-0.001]}


def test_jwt_requires_exact_claims_and_lifetime():
    now = int(time.time())
    claims = {"iss": "open-webui", "sub": "user", "iat": now, "exp": now + 300}
    assert verify_claims(jwt.encode(claims, "i" * 32, algorithm="HS256"), settings())["sub"] == "user"
    for update in [{"iss": "other"}, {"sub": ""}, {"exp": now + 301}, {"iat": True}, {"exp": now - 1}]:
        with pytest.raises(GatewayError):
            verify_claims(jwt.encode(claims | update, "i" * 32, algorithm="HS256"), settings())


def test_provider_is_fixed_https_with_allowlisted_secret_and_host():
    config = {
        "base_url": "https://api.openai.com/v1",
        "credential_ref": "provider-default",
        "allowed_models": ["model"],
    }
    validate_provider_settings(settings(), config)
    for update in [
        {"base_url": "http://api.openai.com/v1"},
        {"base_url": "https://127.0.0.1/v1"},
        {"base_url": "https://user:pass@api.openai.com/v1"},
        {"base_url": "https://api.openai.com/v1?secret=x"},
        {"credential_ref": "arbitrary-env"},
    ]:
        with pytest.raises(ValueError):
            validate_provider_settings(settings(), config | update)
