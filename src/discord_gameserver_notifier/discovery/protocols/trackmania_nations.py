"""
Trackmania Nations protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
import re
import time
from typing import List, Optional

from opengsq.protocols.trackmania_nations import TrackmaniaNations
from .common import ServerResponse
from ..protocol_base import ProtocolBase

try:
    from opengsq.responses.trackmania_nations import strip_formatting
except ImportError:  # opengsq < 3.7
    _FORMATTING_PATTERN = re.compile(r"\$(\$|[0-9a-fA-F]{1,3}|[lLhHpP]\[[^\]]*\]|.)", re.DOTALL)

    def strip_formatting(text: str) -> str:
        return _FORMATTING_PATTERN.sub(lambda match: "$" if match.group(1) == "$" else "", text)


class TrackmaniaNationsProtocol(ProtocolBase):
    """Trackmania Nations protocol handler for network discovery"""

    # Concurrent TCP queries while scanning a range
    MAX_CONCURRENT_QUERIES = 64

    def __init__(self, timeout: float = 5.0):
        super().__init__('', 0, timeout)  # Initialize base class
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 2350,  # Trackmania Nations default port
            # Most hosts of a range do not exist, so their connect attempts
            # are cut short. A real server answers within milliseconds.
            'scan_timeout': min(timeout, 1.5),
        }

    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Trackmania Nations servers.

        Args:
            server_info: Server information dictionary from the protocol

        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []

        if server_info.get('environment'):
            fields.append({
                'name': '🏟️ Environment',
                'value': server_info['environment'],
                'inline': True
            })

        if server_info.get('game_mode'):
            game_mode = server_info['game_mode']
            limit = self._format_mode_limit(server_info)
            fields.append({
                'name': '🎮 Spielmodus',
                'value': f"{game_mode} ({limit})" if limit else game_mode,
                'inline': True
            })

        if server_info.get('password_protected'):
            server_type = "Password Protected"
        elif server_info.get('spectator_password_protected'):
            server_type = "Spectator Password"
        elif server_info.get('ladder_server'):
            server_type = "Ladder"
        else:
            server_type = "Public"

        fields.append({
            'name': '🔐 Server-Typ',
            'value': server_type,
            'inline': True
        })

        if server_info.get('max_spectators'):
            fields.append({
                'name': '👀 Zuschauer',
                'value': f"{server_info.get('spectators', 0)}/{server_info['max_spectators']}",
                'inline': True
            })

        next_maps = server_info.get('next_maps') or []
        if next_maps:
            fields.append({
                'name': '🗺️ Nächste Maps',
                'value': ", ".join(next_maps[:5]),
                'inline': False
            })

        if server_info.get('comment'):
            fields.append({
                'name': '💬 Kommentar',
                'value': server_info['comment'][:1024],
                'inline': False
            })

        return fields

    @staticmethod
    def _format_mode_limit(server_info: dict) -> Optional[str]:
        """Format the limit of the current game mode, e.g. 5:00 or 50 Punkte."""
        if server_info.get('time_limit'):
            seconds = server_info['time_limit'] // 1000
            return f"{seconds // 60}:{seconds % 60:02d}"
        if server_info.get('nb_laps'):
            return f"{server_info['nb_laps']} Runden"
        if server_info.get('points_limit'):
            return f"{server_info['points_limit']} Punkte"
        return None

    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Trackmania Nations servers.

        Trackmania servers do not answer broadcasts, so every host of the
        configured ranges is queried directly via TCP. The query validates the
        response (message checksum and TrackMania game tag), so only real
        Trackmania servers are reported.

        Args:
            scan_ranges: List of network ranges to scan

        Returns:
            List of ServerResponse objects for Trackmania Nations servers
        """
        port = self.protocol_config['port']
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_QUERIES)
        hosts = []

        for scan_range in scan_ranges:
            try:
                network = ipaddress.ip_network(scan_range, strict=False)
            except ValueError as e:
                self.logger.error("Invalid scan range %s: %s", scan_range, e)
                continue

            hosts.extend(str(host) for host in network.hosts())

        self.logger.debug("Querying %d hosts for Trackmania Nations servers on port %d", len(hosts), port)

        async def query(host: str) -> Optional[ServerResponse]:
            async with semaphore:
                return await self._query_server(host, port)

        results = await asyncio.gather(*(query(host) for host in dict.fromkeys(hosts)))
        servers = [server for server in results if server is not None]

        self.logger.info("Trackmania Nations discovery complete: Found %d servers", len(servers))
        return servers

    async def _query_server(self, ip_address: str, port: int) -> Optional[ServerResponse]:
        """
        Query a single host and return its server information.

        Args:
            ip_address: Host to query
            port: Game port of the server

        Returns:
            ServerResponse if a Trackmania server answered, None otherwise
        """
        start_time = time.perf_counter()

        try:
            server_info = await TrackmaniaNations(
                ip_address, port, self.protocol_config['scan_timeout']
            ).get_info()
        except Exception as e:
            # Connection refused/timeouts are normal for most hosts of a range
            self.logger.debug("No Trackmania Nations server at %s:%d: %s", ip_address, port, e)
            return None

        response_time = time.perf_counter() - start_time
        info_dict = self._build_info_dict(server_info)

        self.logger.info("Found Trackmania Nations server at %s:%d", ip_address, port)
        self.logger.debug(
            "Server details: Name='%s', Map='%s', Mode='%s'",
            info_dict['hostname'], info_dict['map'], info_dict['game_mode']
        )

        return ServerResponse(
            ip_address=ip_address,
            port=port,
            game_type='trackmania_nations',
            server_info=info_dict,
            response_time=response_time
        )

    @staticmethod
    def _build_info_dict(server_info) -> dict:
        """Convert the opengsq ServerInfo object into the DGN info dictionary."""
        pack_mask = getattr(server_info, 'pack_mask', '')
        challenges = getattr(server_info, 'challenges', [])

        if pack_mask.lower() in ('', 'stadium', 'nations'):
            game = 'Trackmania Nations Forever'
        else:
            game = 'Trackmania United Forever'

        return {
            'hostname': strip_formatting(server_info.name or '') or 'Unknown Server',
            'name_raw': server_info.name,
            'map': strip_formatting(server_info.map or '') or 'Unknown',
            'players': server_info.players or 0,
            'max_players': server_info.max_players or 0,
            'spectators': getattr(server_info, 'spectators', 0),
            'max_spectators': getattr(server_info, 'max_spectators', 0),
            'game_mode': server_info.game_mode or 'Unknown',
            'time_limit': getattr(server_info, 'time_limit', 0),
            'nb_laps': getattr(server_info, 'nb_laps', 0),
            'points_limit': getattr(server_info, 'points_limit', 0),
            'environment': server_info.environment or 'Stadium',
            'pack_mask': pack_mask,
            'password_protected': bool(server_info.password_protected),
            'spectator_password_protected': getattr(server_info, 'spectator_password_protected', False),
            'ladder_server': bool(server_info.ladder_server),
            'server_login': getattr(server_info, 'server_login', ''),
            'comment': strip_formatting(server_info.comment or ''),
            'player_names': [
                strip_formatting(player.name) for player in getattr(server_info, 'player_list', [])
            ],
            'next_maps': [strip_formatting(challenge.name) for challenge in challenges[1:]],
            'version': server_info.version,
            'game': game,
        }
