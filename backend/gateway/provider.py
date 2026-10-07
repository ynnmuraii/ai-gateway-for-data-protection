"""One pinned provider, no redirects, inherited environment proxy, or retries."""

import asyncio
import ipaddress
import json
import socket
import time
import uuid
from urllib.parse import urlsplit

import httpx

from gateway.protocol import GatewayError, load_json, wire_bytes


class PinnedTransport(httpx.AsyncBaseTransport):
    """Resolve once per request, reject special ranges, connect to the numeric address with original TLS SNI."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request):
        host = request.url.host
        timeout = request.extensions.get("timeout", {}).get("connect", 5)
        try:
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM), timeout
            )
        except (OSError, TimeoutError):
            raise GatewayError(502, "provider_error") from None
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise GatewayError(502, "provider_error")
        request.headers["Host"] = host
        request.url = request.url.copy_with(host=addresses[0])
        request.extensions["sni_hostname"] = host
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


def validate_provider_settings(settings, data):
    url = urlsplit(data["base_url"])
    allowed = {h.strip().lower() for h in settings.provider_allowed_hosts.split(",") if h.strip()}
    if settings.demo_mode:
        allowed.add("demo.invalid")
    if (
        url.scheme != "https"
        or not url.hostname
        or url.hostname.lower() not in allowed
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.port not in (None, 443)
        or "%" in url.netloc
        or ".." in url.path
        or data["credential_ref"] != settings.provider_secret_ref
    ):
        raise ValueError("invalid_provider_configuration")
    models = data.get("allowed_models", data.get("models"))
    if not models or len(models) > 100:
        raise ValueError("invalid_provider_configuration")


class DemoStream(httpx.AsyncByteStream):
    def __init__(self, frames):
        self.frames = frames

    async def __aiter__(self):
        for frame in self.frames:
            await asyncio.sleep(0.015)
            yield frame


def demo_transport(request):
    body = json.loads(request.content)
    content = (
        "Демонстрационный провайдер (без LLM). Получен проверенный текст:\n" + body["messages"][-1]["content"]
    )
    common = {"id": "chatcmpl-demo-" + uuid.uuid4().hex, "created": int(time.time()), "model": body["model"]}
    if not body.get("stream"):
        return httpx.Response(
            200,
            json=common
            | {
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
            },
        )
    frames = []
    for start in range(0, len(content), 24):
        chunk = common | {
            "object": "chat.completion.chunk",
            "choices": [
                {"index": 0, "delta": {"content": content[start : start + 24]}, "finish_reason": None}
            ],
        }
        frames.append(b"data: " + wire_bytes(chunk) + b"\n\n")
    frames.append(
        b"data: "
        + wire_bytes(
            common
            | {
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
        )
        + b"\n\n"
    )
    frames.append(b"data: [DONE]\n\n")
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=DemoStream(frames))


def client_for(settings, config, transport=None):
    try:
        validate_provider_settings(settings, config)
    except ValueError:
        raise GatewayError(503, "provider_configuration_invalid") from None
    is_demo = settings.demo_mode and config["base_url"].rstrip("/") == "https://demo.invalid/v1"
    if not is_demo and not settings.provider_secret:
        raise GatewayError(503, "provider_credential_missing")
    if config["base_url"].split("/")[2] == "demo.invalid" and not is_demo:
        raise GatewayError(503, "provider_configuration_invalid")
    selected = transport or (httpx.MockTransport(demo_transport) if is_demo else PinnedTransport())
    return httpx.AsyncClient(
        transport=selected,
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(
            connect=config["connect_timeout_seconds"],
            read=config["idle_timeout_seconds"],
            write=config["connect_timeout_seconds"],
            pool=5,
        ),
        headers={
            "Authorization": "Bearer " + (settings.provider_secret if not is_demo else "demo"),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )


def validate_completion(data):
    try:
        if (
            not isinstance(data, dict)
            or data.get("object") != "chat.completion"
            or not data.get("choices")
            or not isinstance(data.get("id"), str)
            or not isinstance(data.get("model"), str)
            or type(data.get("created")) is not int
        ):
            raise ValueError()
        for choice in data["choices"]:
            if (
                choice["message"]["role"] != "assistant"
                or not isinstance(choice["message"]["content"], str)
                or type(choice.get("index")) is not int
                or choice.get("finish_reason") not in ("stop", "length", "content_filter")
            ):
                raise ValueError()
            choice["message"]["content"].encode("utf-8")
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise GatewayError(502, "provider_error") from None
    return data


async def sse_frames(response):
    """Yield validated data frames. DONE is emitted only after a terminal finish reason."""
    buffer = b""
    total = 0
    terminal = False
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > 8 * 1024 * 1024:
            raise GatewayError(502, "provider_error")
        buffer += chunk
        if len(buffer) > 262144:
            raise GatewayError(502, "provider_error")
        buffer = buffer.replace(b"\r\n", b"\n")
        while b"\n\n" in buffer:
            event, buffer = buffer.split(b"\n\n", 1)
            lines = [line[5:].lstrip() for line in event.split(b"\n") if line.startswith(b"data:")]
            if not lines:
                continue
            data = b"\n".join(lines)
            if data == b"[DONE]":
                if not terminal:
                    raise GatewayError(502, "provider_error")
                yield None
                return
            try:
                parsed = load_json(data)
                if (
                    not isinstance(parsed, dict)
                    or "error" in parsed
                    or parsed.get("object") != "chat.completion.chunk"
                    or not isinstance(parsed.get("id"), str)
                    or not isinstance(parsed.get("model"), str)
                    or type(parsed.get("created")) is not int
                    or not isinstance(parsed.get("choices"), list)
                    or len(parsed["choices"]) > 1
                    or (not parsed["choices"] and (not terminal or not isinstance(parsed.get("usage"), dict)))
                ):
                    raise ValueError()
                for choice in parsed["choices"]:
                    if (
                        not isinstance(choice, dict)
                        or not isinstance(choice.get("delta"), dict)
                        or type(choice.get("index")) is not int
                        or choice["index"] != 0
                    ):
                        raise ValueError()
                    delta = choice.get("delta", {})
                    if "role" in delta and delta["role"] != "assistant":
                        raise ValueError()
                    if delta.get("content") is not None and not isinstance(delta["content"], str):
                        raise ValueError()
                    if delta.get("tool_calls") or delta.get("function_call") or (terminal and delta):
                        raise ValueError()
                    finish = choice.get("finish_reason")
                    if finish is not None:
                        if finish not in ("stop", "length", "content_filter"):
                            raise ValueError()
                        terminal = True
                yield b"data: " + wire_bytes(parsed) + b"\n\n"
            except (ValueError, TypeError, KeyError, GatewayError):
                raise GatewayError(502, "provider_error") from None
    raise GatewayError(502, "provider_error")
