"""Deliberately narrow, text-only wire profile. Never reflect rejected input."""

import json
import math
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError


class GatewayError(Exception):
    def __init__(self, status_code: int, code: str):
        self.status_code, self.code = status_code, code
        super().__init__(code)

    def payload(self, request_id=None):
        return {
            "error": {
                "message": self.code.replace("_", " "),
                "type": "gateway_error",
                "code": self.code,
            },
            "request_id": str(request_id or uuid.uuid4()),
        }


class TextMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    role: Literal["system", "user", "assistant"]
    content: StrictStr


class StreamOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    include_usage: StrictBool = False


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: StrictStr = Field(min_length=1, max_length=128)
    messages: list[TextMessage] = Field(min_length=1, max_length=100)
    stream: StrictBool = False
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, gt=0, le=1)
    max_tokens: StrictInt | None = Field(default=None, ge=1, le=32768)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: StrictInt | None = Field(default=None, ge=0, le=2147483647)
    stream_options: StreamOptions | None = None
    user: StrictStr | None = Field(default=None, max_length=256)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate_json_key")
        obj[key] = value
    return obj


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite")
    return result


def load_json(data: bytes):
    try:
        return json.loads(
            data,
            object_pairs_hook=_unique,
            parse_float=_finite_float,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise GatewayError(400, "invalid_request") from None


def parse_chat(data: bytes) -> dict:
    raw = load_json(data)
    try:
        parsed = ChatRequest.model_validate(raw)
    except ValidationError as exc:
        code = (
            "unsupported_request_field"
            if any(e["type"] == "extra_forbidden" for e in exc.errors())
            else "invalid_request"
        )
        raise GatewayError(400, code) from None
    try:
        for value in [parsed.model, parsed.user or ""] + [m.content for m in parsed.messages]:
            value.encode("utf-8")
    except UnicodeError:
        raise GatewayError(400, "invalid_request") from None
    return parsed.model_dump(exclude_none=True, exclude={"user"})


def wire_bytes(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
