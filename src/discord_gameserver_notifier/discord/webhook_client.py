"""
Minimal asynchronous Discord webhook client (aiohttp).

Used by the server overview: it needs the `with_components` query parameter
(Components V2 for non-application webhooks) and non-blocking requests, which
the synchronous discord-webhook library does not offer. The webhook token is
never logged.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import aiohttp

API_BASE = "https://discord.com/api/v10"
USER_AGENT = "DiscordBot (https://github.com/lan-dot-party/Discord-Gameserver-Notifier, overview)"

# Discord JSON error codes
ERROR_UNKNOWN_MESSAGE = 10008
ERROR_UNKNOWN_WEBHOOK = 10015

_WEBHOOK_PATH = re.compile(r'/api(?:/v\d+)?/webhooks/(\d+)/([^/?#]+)')


class DiscordWebhookError(Exception):
    """Request against the Discord webhook API failed."""

    def __init__(self, status: int, code: Optional[int] = None, message: str = ""):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"Discord API error {status} (code {code}): {message}")


class UnknownMessageError(DiscordWebhookError):
    """The message does not exist anymore (e.g. deleted manually)."""


class WebhookUnavailableError(DiscordWebhookError):
    """The webhook is invalid, deleted or not accessible."""


@dataclass(frozen=True)
class WebhookCredentials:
    """ID and token of a Discord webhook, parsed from its URL."""
    webhook_id: str
    token: str
    thread_id: Optional[str] = None

    @classmethod
    def from_url(cls, url: str) -> "WebhookCredentials":
        parsed = urlparse(url or "")
        host = parsed.netloc.lower()
        match = _WEBHOOK_PATH.search(parsed.path)
        if not match or not (host.endswith("discord.com") or host.endswith("discordapp.com")):
            raise ValueError("Not a Discord webhook URL")
        thread_id = parse_qs(parsed.query).get("thread_id", [None])[0]
        return cls(webhook_id=match.group(1), token=match.group(2), thread_id=thread_id)


class AsyncWebhookClient:
    """Execute, edit and delete messages of a single Discord webhook."""

    def __init__(self, credentials: WebhookCredentials, *, api_base: str = API_BASE,
                 timeout: float = 10.0, max_retries: int = 3, max_retry_after: float = 30.0,
                 session: Optional[aiohttp.ClientSession] = None):
        self.credentials = credentials
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_retry_after = max_retry_after
        self._session = session
        self._owns_session = session is None
        self.logger = logging.getLogger("GameServerNotifier.WebhookClient")

    @property
    def webhook_id(self) -> str:
        return self.credentials.webhook_id

    async def open(self) -> None:
        """Create the HTTP session (must run inside the event loop)."""
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": USER_AGENT}
            )
            self._owns_session = True

    async def close(self) -> None:
        """Close the HTTP session if it was created by this client."""
        if self._session is not None and self._owns_session:
            await self._session.close()
        self._session = None

    async def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Post a new message and return the created message object."""
        _, data = await self._request("POST", "", params={"wait": "true", "with_components": "true"},
                                      json=payload)
        return data

    async def edit_message(self, message_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Edit a message previously posted by this webhook."""
        _, data = await self._request("PATCH", f"/messages/{message_id}",
                                      params={"with_components": "true"}, json=payload)
        return data

    async def delete_message(self, message_id: str) -> bool:
        """Delete a message; an already deleted message counts as success."""
        try:
            await self._request("DELETE", f"/messages/{message_id}")
        except UnknownMessageError:
            pass
        return True

    async def _request(self, method: str, path: str, *, params: Optional[Dict[str, str]] = None,
                       json: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        if self._session is None:
            await self.open()

        url = f"{self.api_base}/webhooks/{self.credentials.webhook_id}/{self.credentials.token}{path}"
        query = dict(params or {})
        if self.credentials.thread_id:
            query["thread_id"] = self.credentials.thread_id

        attempt = 0
        while True:
            attempt += 1
            try:
                async with self._session.request(method, url, params=query, json=json) as response:
                    status = response.status
                    data = await self._read_body(response)
                    headers = response.headers
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # Never include the exception text: aiohttp puts the full URL (with token) into it
                if attempt > self.max_retries:
                    raise DiscordWebhookError(0, None, f"network error ({type(e).__name__})") from None
                self.logger.warning(f"Webhook {self.webhook_id}: network error ({type(e).__name__}), "
                                    f"retry {attempt}/{self.max_retries}")
                await asyncio.sleep(attempt)
                continue

            if status in (200, 204):
                return status, data

            code = data.get("code") if isinstance(data, dict) else None
            message = str(data.get("message", "")) if isinstance(data, dict) else ""

            if status == 429 and attempt <= self.max_retries:
                retry_after = self._retry_after(data, headers)
                self.logger.warning(f"Webhook {self.webhook_id}: rate limited, retrying in {retry_after:.1f}s")
                await asyncio.sleep(retry_after)
                continue
            if status >= 500 and attempt <= self.max_retries:
                self.logger.warning(f"Webhook {self.webhook_id}: Discord server error {status}, "
                                    f"retry {attempt}/{self.max_retries}")
                await asyncio.sleep(attempt)
                continue

            if status == 404 and code == ERROR_UNKNOWN_MESSAGE:
                raise UnknownMessageError(status, code, message)
            if status in (401, 403) or (status == 404 and code in (ERROR_UNKNOWN_WEBHOOK, None)):
                raise WebhookUnavailableError(status, code, message)

            details = data.get("errors") if isinstance(data, dict) else data
            self.logger.error(f"Webhook {self.webhook_id}: {method} failed with {status}: {message} {details}")
            raise DiscordWebhookError(status, code, message)

    def _retry_after(self, data: Any, headers) -> float:
        retry_after = None
        if isinstance(data, dict):
            retry_after = data.get("retry_after")
        if retry_after is None:
            retry_after = headers.get("Retry-After")
        try:
            value = float(retry_after) if retry_after is not None else 5.0
        except (TypeError, ValueError):
            value = 5.0
        return max(0.0, min(value, self.max_retry_after))

    @staticmethod
    async def _read_body(response: aiohttp.ClientResponse) -> Any:
        if response.status == 204:
            return {}
        try:
            return await response.json(content_type=None)
        except (ValueError, aiohttp.ContentTypeError):
            return {}
