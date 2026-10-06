"""
Persistent Discord server overview.

Keeps one (or a few) messages in a dedicated channel up to date with all active
game servers. The messages are posted once through a separate webhook and then
edited in place; their IDs are stored in the database so a restart continues
with the same messages. Runs alongside the regular notifications and never
touches them.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence

from .overview_renderer import (
    OverviewOptions,
    build_paused_payload,
    render_overview,
)
from .webhook_client import (
    AsyncWebhookClient,
    DiscordWebhookError,
    UnknownMessageError,
    WebhookCredentials,
    WebhookUnavailableError,
)

STATE_KEY = "discord_overview"


class OverviewManager:
    """Renders the active servers and syncs them into the overview messages."""

    def __init__(self, client: AsyncWebhookClient, server_provider: Callable[[], Sequence],
                 state_store, options: OverviewOptions = OverviewOptions(), *,
                 refresh_interval: float = 300.0, debounce_seconds: float = 2.0,
                 clock: Callable[[], datetime] = datetime.now):
        """
        Args:
            client: Webhook client for the overview channel
            server_provider: Returns the active servers (may raise on database errors)
            state_store: Object with get_state(key, default) / set_state(key, value)
            options: Display options
            refresh_interval: Re-send at least this often (seconds) so the "Stand" stays
                              current; 0 = only on changes
            debounce_seconds: Wait time to coalesce bursts of triggers
            clock: Time source (for tests)
        """
        self.client = client
        self.server_provider = server_provider
        self.state_store = state_store
        self.options = options
        self.refresh_interval = refresh_interval
        self.debounce_seconds = debounce_seconds
        self.clock = clock
        self.logger = logging.getLogger("GameServerNotifier.OverviewManager")

        self.message_ids: List[str] = []
        self.disabled = False
        self._last_signature: Optional[str] = None
        self._last_sent: Optional[float] = None
        self._lock = asyncio.Lock()
        self._event = asyncio.Event()
        self._stopping = False
        self._worker_task: Optional[asyncio.Task] = None

    @classmethod
    def from_config(cls, overview_config: Dict[str, Any], database_manager) -> "OverviewManager":
        """Create the manager from the discord.overview config section."""
        credentials = WebhookCredentials.from_url(overview_config['webhook_url'])
        options = OverviewOptions(
            title=overview_config.get('title') or OverviewOptions.title,
            show_stale=overview_config.get('show_stale', True)
        )
        return cls(
            client=AsyncWebhookClient(credentials),
            server_provider=lambda: database_manager.get_all_active_servers(raise_errors=True),
            state_store=database_manager,
            options=options,
            refresh_interval=overview_config.get('refresh_interval', 300)
        )

    async def start(self) -> None:
        """Open the HTTP session, load the stored message IDs and start the worker."""
        await self.client.open()
        self._load_state()
        self._worker_task = asyncio.create_task(self._worker())
        self.logger.info(f"Server overview started (webhook {self.client.webhook_id}, "
                         f"{len(self.message_ids)} known message(s))")

    def trigger(self) -> None:
        """Request an update soon. Never blocks; bursts are coalesced by the worker."""
        if not self._stopping and not self.disabled:
            self._event.set()

    async def update(self, servers: Sequence, *, force: bool = False) -> bool:
        """
        Render the servers and sync the overview messages if something changed.

        Returns:
            True if the overview is up to date afterwards, False on errors
        """
        async with self._lock:
            if self.disabled:
                return False
            rendered = render_overview(servers, self.clock(), self.options)
            heartbeat_due = (
                self.refresh_interval > 0 and self._last_sent is not None
                and time.monotonic() - self._last_sent >= self.refresh_interval
            )
            if not force and rendered.signature == self._last_signature and not heartbeat_due:
                return True
            try:
                await self._sync_pages(rendered.pages)
            except WebhookUnavailableError as e:
                self.disabled = True
                self.logger.error(f"Overview webhook {self.client.webhook_id} is invalid or was deleted "
                                  f"({e.status}) - server overview disabled until restart")
                return False
            except DiscordWebhookError as e:
                self.logger.warning(f"Server overview update failed: {e}")
                return False
            self._last_signature = rendered.signature
            self._last_sent = time.monotonic()
            self.logger.debug(f"Server overview updated ({len(rendered.pages)} page(s), {len(servers)} server(s))")
            return True

    async def shutdown(self, *, pause: bool = True, timeout: float = 8.0) -> None:
        """Stop the worker and optionally switch the overview to the "paused" state."""
        self._stopping = True
        self._event.set()
        if self._worker_task is not None:
            try:
                await asyncio.wait_for(self._worker_task, timeout=timeout)
            except asyncio.TimeoutError:
                self._worker_task.cancel()
            except Exception as e:
                self.logger.debug(f"Overview worker ended with error: {e}")
        try:
            if pause and self.message_ids and not self.disabled:
                try:
                    await asyncio.wait_for(self._pause(), timeout=timeout)
                    self.logger.info("Server overview switched to paused state")
                except (DiscordWebhookError, asyncio.TimeoutError) as e:
                    self.logger.warning(f"Could not switch server overview to paused state: {e}")
        finally:
            await self.client.close()

    async def _worker(self) -> None:
        while not self._stopping:
            try:
                timeout = self.refresh_interval if self.refresh_interval > 0 else None
                try:
                    await asyncio.wait_for(self._event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    pass  # heartbeat
                if self._stopping:
                    break
                await asyncio.sleep(self.debounce_seconds)
                self._event.clear()
                if self._stopping or self.disabled:
                    continue
                try:
                    servers = await asyncio.to_thread(self.server_provider)
                except Exception as e:
                    self.logger.error(f"Server overview: could not load servers, skipping update: {e}")
                    continue
                await self.update(servers)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.error(f"Server overview worker error: {e}", exc_info=True)

    async def _sync_pages(self, pages: List[Dict[str, Any]]) -> None:
        """Edit existing messages, post missing ones, delete surplus ones (in this order)."""
        index = 0
        while index < len(pages):
            page = pages[index]
            if index < len(self.message_ids):
                try:
                    await self.client.edit_message(self.message_ids[index], page)
                    index += 1
                    continue
                except UnknownMessageError:
                    # Deleted manually: drop it and all following pages and repost them in order
                    self.logger.info(f"Overview message {index + 1} was deleted - reposting")
                    for message_id in self.message_ids[index + 1:]:
                        await self.client.delete_message(message_id)
                    self.message_ids = self.message_ids[:index]
                    self._save_state()
            message = await self.client.execute(page)
            self.message_ids.append(str(message['id']))
            self._save_state()
            index += 1

        while len(self.message_ids) > len(pages):
            await self.client.delete_message(self.message_ids[-1])
            self.message_ids.pop()
            self._save_state()

    async def _pause(self) -> None:
        await self.client.edit_message(self.message_ids[0], build_paused_payload(self.clock(), self.options))
        while len(self.message_ids) > 1:
            await self.client.delete_message(self.message_ids[-1])
            self.message_ids.pop()
            self._save_state()

    def _load_state(self) -> None:
        raw = self.state_store.get_state(STATE_KEY)
        if not raw:
            return
        try:
            state = json.loads(raw)
        except (TypeError, ValueError):
            self.logger.warning("Stored server overview state is invalid - starting with new messages")
            return
        message_ids = [str(m) for m in state.get('message_ids', [])]
        if state.get('webhook_id') != self.client.webhook_id:
            if message_ids:
                self.logger.warning(f"Overview webhook changed - {len(message_ids)} old overview message(s) "
                                    f"cannot be edited anymore, please delete them manually")
            return
        self.message_ids = message_ids

    def _save_state(self) -> None:
        state = {'webhook_id': self.client.webhook_id, 'message_ids': self.message_ids}
        if not self.state_store.set_state(STATE_KEY, json.dumps(state)):
            self.logger.warning("Could not persist server overview message IDs")
