"""
Tests for the asynchronous Discord webhook client, against a local aiohttp test server.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.discord.webhook_client import (
    AsyncWebhookClient,
    DiscordWebhookError,
    UnknownMessageError,
    WebhookCredentials,
    WebhookUnavailableError,
)


class TestWebhookCredentials:

    def test_plain_url(self):
        creds = WebhookCredentials.from_url("https://discord.com/api/webhooks/123/abc-DEF_1")
        assert (creds.webhook_id, creds.token, creds.thread_id) == ("123", "abc-DEF_1", None)

    def test_versioned_url_and_thread(self):
        creds = WebhookCredentials.from_url("https://discordapp.com/api/v10/webhooks/123/tok?thread_id=9")
        assert (creds.webhook_id, creds.token, creds.thread_id) == ("123", "tok", "9")

    @pytest.mark.parametrize("url", ["", "https://example.com/api/webhooks/1/x", "https://discord.com/foo"])
    def test_invalid(self, url):
        with pytest.raises(ValueError):
            WebhookCredentials.from_url(url)


class FakeDiscord:
    """Records requests and replays queued responses (status, json body)."""

    def __init__(self):
        self.requests = []
        self.responses = []

    async def handler(self, request):
        body = await request.json() if request.can_read_body else None
        self.requests.append((request.method, request.path, dict(request.query), body))
        status, data = self.responses.pop(0) if self.responses else (200, {"id": "1"})
        if status == 204:
            return web.Response(status=204)
        return web.json_response(data, status=status)


@pytest_asyncio.fixture
async def discord_api():
    fake = FakeDiscord()
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", fake.handler)
    server = TestServer(app)
    await server.start_server()
    client = AsyncWebhookClient(WebhookCredentials("123", "secret"), api_base=str(server.make_url("/api")),
                                max_retries=2)
    await client.open()
    yield fake, client
    await client.close()
    await server.close()


@pytest.mark.asyncio
async def test_execute_uses_wait_and_with_components(discord_api):
    fake, client = discord_api
    fake.responses.append((200, {"id": "555"}))
    message = await client.execute({"flags": 32768, "components": []})
    assert message["id"] == "555"
    method, path, query, body = fake.requests[0]
    assert (method, path) == ("POST", "/api/webhooks/123/secret")
    assert query == {"wait": "true", "with_components": "true"}
    assert body == {"flags": 32768, "components": []}


@pytest.mark.asyncio
async def test_edit_message(discord_api):
    fake, client = discord_api
    fake.responses.append((200, {"id": "555"}))
    await client.edit_message("555", {"components": []})
    method, path, query, _ = fake.requests[0]
    assert (method, path, query) == ("PATCH", "/api/webhooks/123/secret/messages/555", {"with_components": "true"})


@pytest.mark.asyncio
async def test_rate_limit_is_retried(discord_api):
    fake, client = discord_api
    fake.responses += [(429, {"retry_after": 0.5, "message": "rate limited"}), (200, {"id": "7"})]
    with patch("discord_gameserver_notifier.discord.webhook_client.asyncio.sleep", new=AsyncMock()) as sleep:
        message = await client.execute({})
    assert message["id"] == "7"
    sleep.assert_awaited_once_with(0.5)
    assert len(fake.requests) == 2


@pytest.mark.asyncio
async def test_unknown_message(discord_api):
    fake, client = discord_api
    fake.responses.append((404, {"message": "Unknown Message", "code": 10008}))
    with pytest.raises(UnknownMessageError):
        await client.edit_message("1", {})


@pytest.mark.parametrize("status,data", [
    (401, {"message": "Invalid Webhook Token", "code": 50027}),
    (404, {"message": "Unknown Webhook", "code": 10015}),
])
@pytest.mark.asyncio
async def test_webhook_unavailable(discord_api, status, data):
    fake, client = discord_api
    fake.responses.append((status, data))
    with pytest.raises(WebhookUnavailableError):
        await client.execute({})


@pytest.mark.asyncio
async def test_bad_request_raises(discord_api):
    fake, client = discord_api
    fake.responses.append((400, {"message": "Invalid Form Body", "code": 50035}))
    with pytest.raises(DiscordWebhookError) as excinfo:
        await client.execute({})
    assert excinfo.value.status == 400
    assert not isinstance(excinfo.value, WebhookUnavailableError)


@pytest.mark.asyncio
async def test_delete_message(discord_api):
    fake, client = discord_api
    fake.responses += [(204, None), (404, {"message": "Unknown Message", "code": 10008})]
    assert await client.delete_message("1") is True
    assert await client.delete_message("1") is True
    assert fake.requests[0][0] == "DELETE"


@pytest.mark.asyncio
async def test_network_error_does_not_leak_token():
    client = AsyncWebhookClient(WebhookCredentials("123", "supersecret"), api_base="http://127.0.0.1:9/api",
                                max_retries=0, timeout=2)
    await client.open()
    try:
        with pytest.raises(DiscordWebhookError) as excinfo:
            await client.execute({})
        assert "supersecret" not in str(excinfo.value)
    finally:
        await client.close()
