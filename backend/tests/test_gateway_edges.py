"""Independent regressions for provider framing and identity trust boundaries."""

import base64
import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from gateway.identity import unique_header, verify_claims
from gateway.protocol import GatewayError, parse_chat, wire_bytes
from gateway.provider import sse_frames, validate_completion
from starlette.requests import Request

KEY = "i" * 32


def chunk(*, delta=None, finish=None):
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "demo-model",
        "choices": [
            {
                "index": 0,
                "delta": delta if delta is not None else {"content": "hello"},
                "finish_reason": finish,
            }
        ],
    }


def event(data):
    return b"data: " + (data if isinstance(data, bytes) else wire_bytes(data)) + b"\n\n"


class FragmentedBytes(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks

    async def __aiter__(self):
        for part in self.chunks:
            yield part


async def collect(parts):
    response = httpx.Response(200, stream=FragmentedBytes(parts))
    try:
        return [frame async for frame in sse_frames(response)]
    finally:
        await response.aclose()


@pytest.mark.asyncio
async def test_valid_sse_crlf_fragmented_at_every_byte_and_usage_before_done():
    usage = {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "demo-model",
        "choices": [],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    stream = (
        event(chunk()) + event(chunk(delta={}, finish="stop")) + event(usage) + event(b"[DONE]")
    ).replace(b"\n", b"\r\n")
    frames = await collect([bytes([value]) for value in stream])
    assert len(frames) == 4 and frames[-1] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        b"data: not-json\n\n",
        event(b"[DONE]"),
        event(chunk()),
        event(chunk(delta={}, finish="stop")),
        event(chunk())[:-1],
        event(chunk(delta={"content": {"unsupported": "object"}}, finish="stop")) + event(b"[DONE]"),
        event(chunk(delta={"role": "tool"}, finish="stop")) + event(b"[DONE]"),
        event({"choices": [{"delta": {}, "finish_reason": "stop"}]}) + event(b"[DONE]"),
        event(
            b'{"object":"chat.completion.chunk","choices":[],"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}'
        )
        + event(b"[DONE]"),
        event(chunk(delta={}, finish="stop")) + event(chunk()) + event(b"[DONE]"),
    ],
)
async def test_malformed_truncated_ambiguous_and_late_sse_fails_without_done(payload):
    frames = []
    response = httpx.Response(200, stream=FragmentedBytes([payload]))
    try:
        with pytest.raises(GatewayError) as error:
            async for frame in sse_frames(response):
                frames.append(frame)
        assert error.value.status_code == 502 and error.value.code == "provider_error"
        assert None not in frames
    finally:
        await response.aclose()


def test_nonstream_completion_requires_declared_metadata_and_text_content():
    good = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "demo-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "safe"}, "finish_reason": "stop"}
        ],
    }
    assert validate_completion(good) == good
    for field in ("id", "created", "model"):
        with pytest.raises(GatewayError, match="provider_error"):
            validate_completion({key: value for key, value in good.items() if key != field})


@pytest.mark.parametrize(
    "body",
    [
        b'{"model":"demo","messages":[{"role":"user","content":"a","content":"b"}]}',
        b'{"model":"demo","messages":[{"role":"user","role":"system","content":"a"}]}',
        b'{"model":"demo","messages":[{"role":"user","content":"a"}],"stream_options":{"include_usage":true,"include_usage":false}}',
        b'{"model":"demo","messages":[{"role":"user","content":"a"}],"temperature":1e999}',
    ],
)
def test_nested_duplicate_fields_and_overflow_numbers_are_safe_errors(body):
    with pytest.raises(GatewayError) as error:
        parse_chat(body)
    assert error.value.code == "invalid_request"


def sign_raw_payload(payload, header=b'{"alg":"HS256","typ":"JWT"}'):
    encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=")
    signing = encode(header) + b"." + encode(payload)
    signature = encode(hmac.new(KEY.encode(), signing, hashlib.sha256).digest())
    return (signing + b"." + signature).decode()


@pytest.mark.parametrize(
    "update",
    [
        {"iat": True},
        {"exp": True},
        {"iat": 1.1},
        {"exp": "9999999999"},
        {"sub": []},
        {"sub": ""},
        {"iat_offset": 61},
        {"exp_offset": 301},
    ],
)
def test_unusual_jwt_claim_types_lifetime_and_clock_skew_rejected(update):
    now = int(time.time())
    update = {key.removesuffix('_offset'): now + value if key.endswith('_offset') else value for key, value in update.items()}
    payload = {"iss": "open-webui", "sub": "user", "iat": now, "exp": now + 300} | update
    with pytest.raises(GatewayError) as error:
        verify_claims(jwt.encode(payload, KEY, algorithm="HS256"), SimpleNamespace(identity_secret=KEY))
    assert error.value.status_code == 401 and error.value.code == "invalid_identity"


def test_duplicate_signed_jwt_claims_and_algorithm_headers_rejected():
    now = int(time.time())
    payload = (f'{{"iss":"open-webui","sub":"first","sub":"second","iat":{now},"exp":{now + 300}}}').encode()
    for token in (
        sign_raw_payload(payload),
        sign_raw_payload(
            json.dumps({"iss": "open-webui", "sub": "user", "iat": now, "exp": now + 300}).encode(),
            b'{"alg":"HS512","alg":"HS256","typ":"JWT"}',
        ),
    ):
        with pytest.raises(GatewayError, match="invalid_identity"):
            verify_claims(token, SimpleNamespace(identity_secret=KEY))


def test_repeated_identity_header_is_rejected_before_credentials_are_used():
    request = Request(
        {"type": "http", "headers": [(b"x-openwebui-user-jwt", b"one"), (b"x-openwebui-user-jwt", b"two")]}
    )
    with pytest.raises(GatewayError, match="invalid_identity"):
        unique_header(request, "x-openwebui-user-jwt")
