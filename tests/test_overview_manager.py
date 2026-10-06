"""
Tests for the OverviewManager (sync logic, state handling, triggers, shutdown).
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.database.models import GameServerModel
from discord_gameserver_notifier.discord.overview_manager import STATE_KEY, OverviewManager
from discord_gameserver_notifier.discord.overview_renderer import OverviewOptions
from discord_gameserver_notifier.discord.webhook_client import (
    DiscordWebhookError,
    UnknownMessageError,
    WebhookUnavailableError,
)

NOW = datetime(2026, 10, 6, 14, 30, 0)


def make_server(i=0, players=1, name=None):
    return GameServerModel(ip_address=f"10.0.0.{i}", port=27015, name=name or f"Server {i}",
                           game="Counter-Strike: Source", game_type="source",
                           players=players, max_players=16, map_name="de_dust2", last_seen=NOW)


def many_servers(count):
    return [make_server(i, name="N" * 60 + f"{i:03d}") for i in range(count)]


class FakeClient:
    webhook_id = "123"

    def __init__(self):
        self.calls = []
        self.next_id = 100
        self.edit_errors = {}
        self.execute_error = None
        self.closed = False

    async def open(self):
        pass

    async def close(self):
        self.closed = True

    async def execute(self, payload):
        if self.execute_error:
            raise self.execute_error
        self.next_id += 1
        self.calls.append(("execute", str(self.next_id), payload))
        return {"id": str(self.next_id)}

    async def edit_message(self, message_id, payload):
        if message_id in self.edit_errors:
            raise self.edit_errors.pop(message_id)
        self.calls.append(("edit", message_id, payload))
        return {"id": message_id}

    async def delete_message(self, message_id):
        self.calls.append(("delete", message_id, None))
        return True

    def kinds(self):
        return [(kind, message_id) for kind, message_id, _ in self.calls]


class FakeStore:
    def __init__(self, initial=None):
        self.data = dict(initial or {})

    def get_state(self, key, default=None):
        return self.data.get(key, default)

    def set_state(self, key, value):
        self.data[key] = value
        return True


def make_manager(client=None, store=None, servers=None, **kwargs):
    servers = servers if servers is not None else [make_server()]
    kwargs.setdefault("refresh_interval", 300)
    kwargs.setdefault("debounce_seconds", 0)
    return OverviewManager(client or FakeClient(), lambda: servers, store or FakeStore(),
                           OverviewOptions(), clock=lambda: NOW, **kwargs)


def stored_ids(store):
    return json.loads(store.data[STATE_KEY])["message_ids"]


@pytest.mark.asyncio
async def test_first_update_posts_and_stores_id():
    client, store = FakeClient(), FakeStore()
    manager = make_manager(client, store)
    assert await manager.update([make_server()])
    assert client.kinds() == [("execute", "101")]
    assert json.loads(store.data[STATE_KEY]) == {"webhook_id": "123", "message_ids": ["101"]}


@pytest.mark.asyncio
async def test_existing_state_is_edited():
    client = FakeClient()
    store = FakeStore({STATE_KEY: json.dumps({"webhook_id": "123", "message_ids": ["42"]})})
    manager = make_manager(client, store)
    manager._load_state()
    assert await manager.update([make_server()])
    assert client.kinds() == [("edit", "42")]


@pytest.mark.asyncio
async def test_state_of_other_webhook_is_ignored():
    client = FakeClient()
    store = FakeStore({STATE_KEY: json.dumps({"webhook_id": "999", "message_ids": ["42"]})})
    manager = make_manager(client, store)
    manager._load_state()
    assert manager.message_ids == []


@pytest.mark.asyncio
async def test_unchanged_data_sends_nothing():
    client = FakeClient()
    manager = make_manager(client)
    await manager.update([make_server()])
    await manager.update([make_server()])
    assert len(client.calls) == 1
    await manager.update([make_server(players=5)])
    assert client.kinds() == [("execute", "101"), ("edit", "101")]


@pytest.mark.asyncio
async def test_heartbeat_resends_unchanged_data():
    client = FakeClient()
    manager = make_manager(client, refresh_interval=300)
    with patch("discord_gameserver_notifier.discord.overview_manager.time.monotonic", return_value=1000.0):
        await manager.update([make_server()])
    with patch("discord_gameserver_notifier.discord.overview_manager.time.monotonic", return_value=1100.0):
        await manager.update([make_server()])
    assert len(client.calls) == 1
    with patch("discord_gameserver_notifier.discord.overview_manager.time.monotonic", return_value=1400.0):
        await manager.update([make_server()])
    assert client.kinds() == [("execute", "101"), ("edit", "101")]


@pytest.mark.asyncio
async def test_deleted_message_is_reposted_in_order():
    client, store = FakeClient(), FakeStore()
    manager = make_manager(client, store)
    manager.message_ids = ["1", "2", "3"]
    client.edit_errors["1"] = UnknownMessageError(404, 10008, "Unknown Message")
    servers = many_servers(80)
    assert await manager.update(servers)
    pages = len(manager.message_ids)
    assert pages >= 2
    kinds = client.kinds()
    assert ("delete", "2") in kinds and ("delete", "3") in kinds
    assert [k for k, _ in kinds if k == "execute"] == ["execute"] * pages
    assert manager.message_ids == [str(101 + i) for i in range(pages)]
    assert stored_ids(store) == manager.message_ids


@pytest.mark.asyncio
async def test_pages_grow_and_shrink():
    client = FakeClient()
    manager = make_manager(client)
    await manager.update([make_server()])
    assert len(manager.message_ids) == 1
    await manager.update(many_servers(80))
    grown = len(manager.message_ids)
    assert grown >= 2
    assert client.kinds()[1] == ("edit", "101")
    await manager.update([make_server()])
    assert manager.message_ids == ["101"]
    assert sum(1 for kind, _ in client.kinds() if kind == "delete") == grown - 1


@pytest.mark.asyncio
async def test_invalid_webhook_disables_overview():
    client = FakeClient()
    client.execute_error = WebhookUnavailableError(404, 10015, "Unknown Webhook")
    manager = make_manager(client)
    assert not await manager.update([make_server()])
    assert manager.disabled
    client.execute_error = None
    assert not await manager.update([make_server()])
    assert client.calls == []


@pytest.mark.asyncio
async def test_temporary_error_is_retried_on_next_update():
    client, store = FakeClient(), FakeStore()
    client.execute_error = DiscordWebhookError(0, None, "network error")
    manager = make_manager(client, store)
    assert not await manager.update([make_server()])
    assert not manager.disabled
    assert STATE_KEY not in store.data
    client.execute_error = None
    assert await manager.update([make_server()])
    assert client.kinds() == [("execute", "101")]


@pytest.mark.asyncio
async def test_triggers_are_coalesced():
    client = FakeClient()
    manager = make_manager(client, debounce_seconds=0.05)
    await manager.start()
    for _ in range(5):
        manager.trigger()
    await asyncio.sleep(0.2)
    assert client.kinds() == [("execute", "101")]
    await manager.shutdown(pause=False)
    assert client.closed


@pytest.mark.asyncio
async def test_provider_error_skips_update_and_worker_survives():
    client = FakeClient()
    calls = {"n": 0}

    def provider():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database locked")
        return [make_server()]

    manager = OverviewManager(client, provider, FakeStore(), OverviewOptions(), refresh_interval=300,
                              debounce_seconds=0, clock=lambda: NOW)
    await manager.start()
    manager.trigger()
    await asyncio.sleep(0.05)
    assert client.calls == []
    manager.trigger()
    await asyncio.sleep(0.05)
    assert client.kinds() == [("execute", "101")]
    await manager.shutdown(pause=False)


@pytest.mark.asyncio
async def test_shutdown_pauses_first_page_and_removes_others():
    client, store = FakeClient(), FakeStore()
    manager = make_manager(client, store)
    await manager.start()
    manager.message_ids = ["1", "2"]
    await manager.shutdown(pause=True)
    kind, message_id, payload = client.calls[0]
    assert (kind, message_id) == ("edit", "1")
    assert "Übersicht pausiert" in json.dumps(payload, ensure_ascii=False)
    assert ("delete", "2") in client.kinds()
    assert stored_ids(store) == ["1"]
    assert client.closed
