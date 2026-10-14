from types import SimpleNamespace

import pytest
from gateway.protocol import GatewayError
from gateway.routes import body_bytes
from starlette.requests import Request


def incoming(content_type):
    payload = b'{"messages":[{"role":"user","content":"safe"}]}'

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    app = SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(max_request_bytes=1024)))
    request = Request(
        {"type": "http", "app": app, "headers": [(b"content-type", content_type.encode())]},
        receive,
    )
    return request, payload


@pytest.mark.parametrize("content_type", [
    "application/json", "Application/JSON", "APPLICATION/JSON; charset=UTF-8",
])
async def test_json_media_type_is_case_insensitive(content_type):
    request, payload = incoming(content_type)
    assert await body_bytes(request) == payload


@pytest.mark.parametrize("content_type", ["text/plain", "application/jsonp", ""])
async def test_non_json_media_types_remain_rejected(content_type):
    request, _ = incoming(content_type)
    with pytest.raises(GatewayError) as failure:
        await body_bytes(request)
    assert failure.value.status_code == 415
