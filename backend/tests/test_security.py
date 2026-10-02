import hashlib

import pytest
from fastapi import HTTPException
from gateway.security import csrf_token, digest, hash_password, same_origin, verify_password


def test_passwords_are_salted_argon2id_and_wrong_password_fails():
    password = "valid strong password 2026"
    first = hash_password(password)
    assert first.startswith("$argon2id$")
    assert first != hash_password(password)
    assert verify_password(first, password)
    assert not verify_password(first, "wrong strong password")
    assert not verify_password("broken encoded hash", password)


def test_csrf_is_stable_bound_to_session_and_deployment_key():
    token = csrf_token("c" * 32, "session-one")
    assert token == csrf_token("c" * 32, "session-one")
    assert token != csrf_token("d" * 32, "session-one")
    assert token != csrf_token("c" * 32, "session-two")
    assert digest(token) == hashlib.sha256(token.encode()).digest()


@pytest.mark.parametrize("headers", [
    {"origin": "https://evil.test"}, {}, {"origin": "null"},
    {"referer": "https://admin.test.evil.test/path"},
    {"origin": "https://evil.test", "referer": "https://admin.test/path"},
])
def test_origin_rejects_missing_cross_origin_and_conflicting_headers(headers):
    with pytest.raises(HTTPException) as error:
        same_origin(headers, "https://admin.test")
    assert error.value.status_code == 403


def test_origin_accepts_origin_or_same_origin_referer():
    same_origin({"origin": "https://admin.test"}, "https://admin.test")
    same_origin({"referer": "https://admin.test/admin"}, "https://admin.test")


def test_invalid_unicode_password_is_rejected_without_echoing_it():
    with pytest.raises(ValueError, match="valid Unicode") as error:
        hash_password("long-password-\ud800")
    assert "long-password" not in str(error.value)
    assert not verify_password(hash_password("Strong safe password"), "long-password-\ud800")
