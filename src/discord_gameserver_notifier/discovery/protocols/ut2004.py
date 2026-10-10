"""
UT2004 (Unreal Tournament 2004) protocol implementation for game server discovery.

Uses the Unreal 2 query protocol of opengsq for the server details.
"""

import asyncio
import ipaddress
import logging
import time
from typing import List, Optional, Set, Tuple

from opengsq.protocols.unreal2 import Unreal2

from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class UT2004Protocol(ProtocolBase):
    """UT2004 protocol handler for broadcast discovery"""

    # LAN server query as sent by the UT2004 client: version header 0x80 and
    # query type 0x00 (server details)
    DISCOVERY_QUERY = b"\x80\x00\x00\x00\x00"

    # Readable names of the stock game types (class names without package)
    GAME_MODES = {
        'xDeathMatch': 'Deathmatch',
        'xTeamGame': 'Team Deathmatch',
        'xCTFGame': 'Capture the Flag',
        'xVehicleCTFGame': 'Vehicle CTF',
        'xBombingRun': 'Bombing Run',
        'xDoubleDom': 'Double Domination',
        'ONSOnslaughtGame': 'Onslaught',
        'ASGameInfo': 'Assault',
        'Invasion': 'Invasion',
        'xMutantGame': 'Mutant',
        'xLastManStandingGame': 'Last Man Standing',
    }

    def __init__(self, timeout: float = 5.0):
        super().__init__('255.255.255.255', 10777, timeout)
        self.logger = logging.getLogger(__name__)
        self._allow_broadcast = True
        self.protocol_config = {
            # Servers listen for LAN queries on this port and answer from
            # their query port (game port + 1)
            'lan_port': 10777,
            # A server answers the LAN query within milliseconds
            'broadcast_timeout': min(timeout, 2.0),
            'query_timeout': timeout,
            # Also send to 255.255.255.255, not only to the broadcast
            # addresses of the scan ranges
            'global_broadcast': True,
        }

    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for UT2004 servers.

        Args:
            server_info: Server information dictionary from the protocol

        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []

        if server_info.get('game_mode'):
            limits = []
            if server_info.get('goal_score'):
                limits.append(f"{server_info['goal_score']} Punkte")
            if server_info.get('time_limit'):
                limits.append(f"{server_info['time_limit']} min")
            game_mode = server_info['game_mode']
            fields.append({
                'name': '🎮 Spielmodus',
                'value': f"{game_mode} ({', '.join(limits)})" if limits else game_mode,
                'inline': True
            })

        # Version and password are already part of the standard embed fields
        mutators = server_info.get('mutators') or []
        if mutators:
            fields.append({
                'name': '🧩 Mutatoren',
                'value': ", ".join(mutators)[:1024],
                'inline': False
            })

        return fields

    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for UT2004 servers.

        1. Broadcast the LAN server query. Every server answers from its
           query port.
        2. Query the details, rules and players of each server directly.

        Args:
            scan_ranges: List of network ranges to scan

        Returns:
            List of ServerResponse objects for UT2004 servers
        """
        servers = await self._discover_servers(self._broadcast_addresses(scan_ranges))
        self.logger.debug("UT2004 LAN query: %d servers answered", len(servers))

        results = await asyncio.gather(
            *(self._query_server(ip_address, query_port) for ip_address, query_port in servers)
        )
        found = [server for server in results if server is not None]

        self.logger.info("UT2004 discovery complete: Found %d servers", len(found))
        return found

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

    async def _discover_servers(self, broadcast_addresses: List[str]) -> Set[Tuple[str, int]]:
        """
        Send the LAN server query and collect the answering servers.

        Returns:
            Set of (server IP, query port)
        """
        responses = []
        loop = asyncio.get_running_loop()

        transport, _ = await loop.create_datagram_endpoint(
            lambda: BroadcastResponseProtocol(responses),
            local_addr=('0.0.0.0', 0),
            allow_broadcast=True
        )

        try:
            for address in broadcast_addresses:
                try:
                    transport.sendto(self.DISCOVERY_QUERY, (address, self.protocol_config['lan_port']))
                except OSError as e:
                    self.logger.debug("LAN query to %s failed: %s", address, e)

            await asyncio.sleep(self.protocol_config['broadcast_timeout'])
        finally:
            transport.close()

        servers = set()

        for data, (ip_address, sender_port) in responses:
            # Details reply: version header and query type 0x00
            if not data.startswith(self.DISCOVERY_QUERY):
                self.logger.debug("Ignoring datagram from %s:%d", ip_address, sender_port)
                continue

            servers.add((ip_address, sender_port))

        return servers

    async def _query_server(self, ip_address: str, query_port: int) -> Optional[ServerResponse]:
        """
        Query the details, rules and players of a server that answered the LAN query.

        Args:
            ip_address: Address the LAN reply came from
            query_port: Port the LAN reply came from

        Returns:
            ServerResponse, or None if the server did not answer the details query
        """
        unreal2 = Unreal2(ip_address, query_port, self.protocol_config['query_timeout'])
        start_time = time.perf_counter()

        try:
            details = await unreal2.get_details()
        except Exception as e:
            self.logger.debug("UT2004 server at %s:%d did not answer the details query: %s",
                              ip_address, query_port, e)
            return None

        response_time = time.perf_counter() - start_time

        try:
            rules = await unreal2.get_rules()
        except Exception as e:
            self.logger.debug("UT2004 server at %s:%d did not answer the rules query: %s",
                              ip_address, query_port, e)
            rules = {}

        # An empty server does not answer the players query at all
        players = []
        if details.num_players > 0:
            try:
                players = await unreal2.get_players()
            except Exception as e:
                self.logger.debug("UT2004 server at %s:%d did not answer the players query: %s",
                                  ip_address, query_port, e)

        info_dict = self._build_info_dict(details, rules, players, query_port)
        game_port = details.game_port or query_port - 1

        self.logger.info("Found UT2004 server at %s:%d", ip_address, game_port)
        self.logger.debug(
            "Server details: Name='%s', Map='%s', Mode='%s'",
            info_dict['hostname'], info_dict['map'], info_dict['game_mode']
        )

        return ServerResponse(
            ip_address=ip_address,
            port=game_port,
            game_type='ut2004',
            server_info=info_dict,
            response_time=response_time
        )

    @classmethod
    def _build_info_dict(cls, details, rules: dict, players: list, query_port: int) -> dict:
        """Convert the opengsq Status, rules and players into the DGN info dictionary."""
        return {
            'hostname': details.server_name or 'Unknown Server',
            'map': details.map_name or 'Unknown',
            'game_mode': cls.GAME_MODES.get(details.game_type, details.game_type),
            'game_class': details.game_type,
            'players': details.num_players,
            'max_players': details.max_players,
            # Only present in the rules when a game password is set
            'password_protected': str(rules.get('GamePassword', '')).lower() == 'true',
            'version': rules.get('ServerVersion', ''),
            'goal_score': cls._to_int(rules.get('GoalScore')),
            'time_limit': cls._to_int(rules.get('TimeLimit')),
            'max_spectators': cls._to_int(rules.get('MaxSpectators')),
            'mutators': list(rules.get('Mutators', [])),
            'admin_name': rules.get('AdminName', ''),
            'server_mode': rules.get('ServerMode', ''),
            'player_names': [player.name for player in players],
            'game_port': details.game_port,
            'query_port': query_port,
        }

    @staticmethod
    def _to_int(value) -> int:
        """Convert a rules value to int, 0 if it is missing or not a number."""
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0
