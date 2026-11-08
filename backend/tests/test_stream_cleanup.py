import pytest
from gateway.routes import ObservedStream


@pytest.mark.asyncio
async def test_disconnect_before_first_generator_iteration_still_releases_owned_resources():
    state = {"chunks": 0, "closed": 0, "started": False}

    async def body():
        state["started"] = True
        yield b'data: {"choices":[]}\n\n'

    async def cleanup():
        state["closed"] += 1

    async def failed_send(message):
        raise OSError("client disconnected")

    response = ObservedStream(body(), state, cleanup)
    with pytest.raises(OSError):
        await response.stream_response(failed_send)
    assert not state["started"]
    assert state["closed"] == 1


@pytest.mark.asyncio
async def test_count_only_after_successful_send_and_not_done_or_errors():
    state = {"chunks": 0, "closed": 0}

    async def body():
        yield b'data: {"choices":[]}\n\n'
        assert state["chunks"] == 1
        yield b'data: {"error":{"code":"safe"}}\n\n'
        yield b"data: [DONE]\n\n"

    async def cleanup():
        state["closed"] += 1

    async def send(message):
        pass

    await ObservedStream(body(), state, cleanup).stream_response(send)
    assert state == {"chunks": 1, "closed": 1}
