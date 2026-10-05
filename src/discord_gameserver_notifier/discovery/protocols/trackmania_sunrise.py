"""
Trackmania Sunrise protocol implementation for game server discovery.

Covers TrackMania Original, Sunrise and Nations ESWC, which share one
dedicated server (TrackManiaServer.exe) and network protocol.
"""

import asyncio
import ipaddress
import logging
import secrets
import time
from typing import Dict, List, Optional, Tuple

try:
    from opengsq.protocols.trackmania_sunrise import TrackmaniaSunrise
    from opengsq.responses.trackmania_nations import strip_formatting
except ImportError:  # opengsq without TrackMania Sunrise support
    TrackmaniaSunrise = None

from .common import ServerResponse, BroadcastResponseProtocol
from .trackmania_nations import TrackmaniaNationsProtocol


class TrackmaniaSunriseProtocol(TrackmaniaNationsProtocol):
    """
    Trackmania Original/Sunrise/Nations ESWC protocol handler for broadcast discovery.

    Shares the Discord fields of the Trackmania Nations Forever protocol.
    """

    def __init__(self, timeout: float = 5.0):
        super().__init__(timeout)
        self.logger = logging.getLogger(__name__)
        self.host = '255.255.255.255'
        self.port = 2350
        self._allow_broadcast = True
        self.protocol_config = {
            # Game ports to send the LAN session query to. Several servers on
            # one host use consecutive ports.
            'ports': [2350, 2351, 2352, 2353],
            # A server answers the session query within milliseconds
            'broadcast_timeout': min(timeout, 2.0),
            'query_timeout': timeout,
            # Also send to 255.255.255.255, not only to the broadcast
            # addresses of the scan ranges
            'global_broadcast': True,
        }

    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Trackmania Original/Sunrise/Nations ESWC servers.

        1. Broadcast a LAN session query for every game id. A server only
           answers for its own game, which identifies the game.
        2. Query each announced server via TCP for the detailed information.

        Args:
            scan_ranges: List of network ranges to scan

        Returns:
            List of ServerResponse objects for Trackmania Sunrise servers
        """
        if TrackmaniaSunrise is None:
            self.logger.warning(
                "Trackmania Sunrise discovery requires opengsq with TrackmaniaSunrise support"
            )
            return []

        sessions = await self._discover_sessions(self._broadcast_addresses(scan_ranges))
        self.logger.debug("Trackmania Sunrise session query: %d servers answered", len(sessions))

        results = await asyncio.gather(
            *(self._query_server(ip_address, port, session)
              for (ip_address, port), session in sessions.items())
        )
        servers = [server for server in results if server is not None]

        self.logger.info("Trackmania Sunrise discovery complete: Found %d servers", len(servers))
        return servers

    def _broadcast_addresses(self, scan_ranges: List[str]) -> List[str]:
        """Broadcast address of every scan range, plus the global broadcast."""
        addresses = ['255.255.255.255'] if self.protocol_config['global_broadcast'] else []

        for scan_range in scan_ranges:
            try:
                network = ipaddress.ip_network(scan_range, strict=False)
            except ValueError as e:
                self.logger.error("Invalid scan range %s: %s", scan_range, e)
                continue

            if network.version == 4:
                addresses.append(str(network.broadcast_address))

        return list(dict.fromkeys(addresses))

    async def _discover_sessions(self, broadcast_addresses: List[str]) -> Dict[Tuple[str, int], object]:
        """
        Send the LAN session query for every game id and collect the answers.

        Returns:
            Session info by (sender IP, game port)
        """
        responses = []
        nonce = secrets.randbits(32)
        loop = asyncio.get_running_loop()

        transport, _ = await loop.create_datagram_endpoint(
            lambda: BroadcastResponseProtocol(responses),
            local_addr=('0.0.0.0', 0),
            allow_broadcast=True
        )

        try:
            for game_id in TrackmaniaSunrise.GAMES:
                query = TrackmaniaSunrise.build_session_query(game_id, nonce)

                for address in broadcast_addresses:
                    for port in self.protocol_config['ports']:
                        try:
                            transport.sendto(query, (address, port))
                        except OSError as e:
                            self.logger.debug("Session query to %s:%d failed: %s", address, port, e)

            await asyncio.sleep(self.protocol_config['broadcast_timeout'])
        finally:
            transport.close()

        sessions = {}

        for data, (ip_address, sender_port) in responses:
            try:
                session = TrackmaniaSunrise.parse_session_reply(data, nonce)
            except Exception as e:
                self.logger.debug("Ignoring datagram from %s:%d: %s", ip_address, sender_port, e)
                continue

            sessions[(ip_address, session.server_port or sender_port)] = session

        return sessions

    async def _query_server(self, ip_address: str, port: int, session) -> Optional[ServerResponse]:
        """
        Query the details of a server that answered the session query.

        Args:
            ip_address: Address the session reply came from
            port: Game port announced by the server
            session: Session info of the server

        Returns:
            ServerResponse, or None if the server did not answer the query
        """
        start_time = time.perf_counter()

        try:
            server_info = await TrackmaniaSunrise(
                ip_address, port, self.protocol_config['query_timeout']
            ).get_info()
        except Exception as e:
            self.logger.debug("Trackmania Sunrise server at %s:%d did not answer the query: %s",
                              ip_address, port, e)
            return None

        response_time = time.perf_counter() - start_time
        info_dict = self._build_info_dict(server_info, session)

        self.logger.info("Found %s server at %s:%d", info_dict['game'], ip_address, port)
        self.logger.debug(
            "Server details: Name='%s', Map='%s', Mode='%s'",
            info_dict['hostname'], info_dict['map'], info_dict['game_mode']
        )

        return ServerResponse(
            ip_address=ip_address,
            port=port,
            game_type='trackmania_sunrise',
            server_info=info_dict,
            response_time=response_time
        )

    @staticmethod
    def _build_info_dict(server_info, session) -> dict:
        """Convert the opengsq ServerInfo and SessionInfo objects into the DGN info dictionary."""
        return {
            'hostname': strip_formatting(server_info.name) or session.host_name or 'Unknown Server',
            'name_raw': server_info.name,
            'map': strip_formatting(server_info.map) or 'Unknown',
            'players': server_info.players,
            'max_players': server_info.max_players,
            'spectators': server_info.spectators,
            'max_spectators': server_info.max_spectators,
            'game_mode': server_info.game_mode,
            'time_limit': server_info.time_limit,
            'nb_laps': server_info.nb_laps,
            'points_limit': server_info.points_limit,
            'password_protected': server_info.password_protected,
            'spectator_password_protected': server_info.spectator_password_protected,
            'ladder_server': server_info.ladder_server,
            'server_login': server_info.server_login,
            'comment': strip_formatting(server_info.comment),
            'player_names': [strip_formatting(player.name) for player in server_info.player_list],
            'next_maps': [strip_formatting(challenge.name) for challenge in server_info.challenges[1:]],
            'nb_challenges': server_info.nb_challenges,
            'game_id': session.game_id,
            'version': session.version,
            'game': session.game,
        }
