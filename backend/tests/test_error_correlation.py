"""Error paths must retain the public request ID without reflecting submitted values."""

import pytest
from fastapi.testclient import TestClient
from gateway.main import create_app
from gateway.settings import Settings


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("POST", "/admin/api/auth/login", {}, 400),
        ("GET", "/not-a-route", None, 404),
        ("GET", "/admin/api/users", None, 401),
        ("GET", "/broken-boundary", None, 503),
    ],
)
def test_error_body_and_header_share_request_id(method, path, body, status):
    app = create_app(Settings(csrf_secret="c" * 32, pseudonym_secret="p" * 32, identity_secret="i" * 32))

    @app.get("/broken-boundary")
    def broken():
        raise RuntimeError("sensitive submitted text")

    client = TestClient(app)
    response = client.request(method, path, json=body)
    assert response.status_code == status
    assert response.json().get("request_id") == response.headers["x-request-id"]
    assert "sensitive submitted text" not in response.text
