import socket

import httpx
import pytest
from gateway.protocol import GatewayError
from gateway.provider import PinnedTransport


class Receiver(httpx.AsyncBaseTransport):
    def __init__(self):
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return httpx.Response(200, json={})


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"])
async def test_final_dns_address_is_rejected_even_for_allowed_provider_hostname(monkeypatch, address):
    import asyncio

    async def resolve(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    transport = PinnedTransport()
    await transport.inner.aclose()
    transport.inner = Receiver()
    with pytest.raises(GatewayError, match="provider_error"):
        await transport.handle_async_request(
            httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        )
    assert not transport.inner.requests


@pytest.mark.asyncio
async def test_connect_uses_resolved_numeric_ip_with_original_host_and_tls_name(monkeypatch):
    import asyncio

    lookups = []

    async def resolve(host, *args, **kwargs):
        lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    transport = PinnedTransport()
    await transport.inner.aclose()
    transport.inner = Receiver()
    await transport.handle_async_request(httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
    sent = transport.inner.requests[0]
    assert sent.url.host == "8.8.8.8"
    assert sent.headers["host"] == "api.openai.com"
    assert sent.extensions["sni_hostname"] == "api.openai.com"
    assert lookups == ["api.openai.com"]
