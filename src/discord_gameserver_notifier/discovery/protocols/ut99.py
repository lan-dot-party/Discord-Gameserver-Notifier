"""
UT99 (Unreal Tournament 1999) protocol implementation for game server discovery.

Uses the GameSpy 1 query protocol of opengsq for the server details.
"""

import asyncio
import ipaddress
import logging
import re
import time
from typing import List, Optional, Set, Tuple

from opengsq.protocol_socket import UdpClient
from opengsq.protocols.gamespy1 import GameSpy1

from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class UT99Protocol(ProtocolBase):
    """UT99 protocol handler for broadcast discovery"""

    # LAN server query as sent by the UT99 client
    DISCOVERY_QUERY = b"REPORTQUERY"

    # Beacon reply: product name of the game and the query port of the server.
    # Other Unreal Engine 1 games answer with their own product name.
    BEACON_REPLY = re.compile(rb"ut (\d+)")

    # Version 436 servers report the mutators only in their first rules reply,
    # the game property is answered every time
    MUTATORS_QUERY = b"\\game_property\\EnabledMutators\\"
    MUTATORS_REPLY = re.compile(rb"\\EnabledMutators\\([^\\]*)")

    # Readable names of the stock game types (class names without package)
    GAME_MODES = {
        'DeathMatchPlus': 'Deathmatch',
        'TeamGamePlus': 'Team Deathmatch',
        'CTFGame': 'Capture the Flag',
        'Domination': 'Domination',
        'Assault': 'Assault',
        'LastManStanding': 'Last Man Standing',
    }

    def __init__(self, timeout: float = 5.0):
        super().__init__('255.255.255.255', 8777, timeout)
        self.logger = logging.getLogger(__name__)
        self._allow_broadcast = True
        self.protocol_config = {
            # A server listens for LAN queries on the first free one of these
            # ports and answers with its query port (game port + 1)
            'beacon_ports': range(8777, 8787),
            # A server answers the LAN query within milliseconds
            'broadcast_timeout': min(timeout, 2.0),
            'query_timeout': timeout,
            # Also send to 255.255.255.255, not only to the broadcast
            # addresses of the scan ranges
            'global_broadcast': True,
        }

    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for UT99 servers.

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
        Scan for UT99 servers.

        1. Broadcast the LAN server query. Every server answers with its
           query port.
        2. Query the info, rules, players and mutators of each server directly.

        Args:
            scan_ranges: List of network ranges to scan

        Returns:
            List of ServerResponse objects for UT99 servers
        """
        servers = await self._discover_servers(self._broadcast_addresses(scan_ranges))
        self.logger.debug("UT99 LAN query: %d servers answered", len(servers))

        results = await asyncio.gather(
            *(self._query_server(ip_address, query_port) for ip_address, query_port in servers)
        )
        found = [server for server in results if server is not None]

        self.logger.info("UT99 discovery complete: Found %d servers", len(found))
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
                for beacon_port in self.protocol_config['beacon_ports']:
                    try:
                        transport.sendto(self.DISCOVERY_QUERY, (address, beacon_port))
                    except OSError as e:
                        self.logger.debug("LAN query to %s:%d failed: %s", address, beacon_port, e)

            await asyncio.sleep(self.protocol_config['broadcast_timeout'])
        finally:
            transport.close()

        servers = set()

        for data, (ip_address, sender_port) in responses:
            match = self.BEACON_REPLY.fullmatch(data.rstrip(b"\x00\r\n "))
            query_port = int(match.group(1)) if match else 0

            if not 0 < query_port <= 65535:
                self.logger.debug("Ignoring datagram from %s:%d", ip_address, sender_port)
                continue

            servers.add((ip_address, query_port))

        return servers

    async def _query_server(self, ip_address: str, query_port: int) -> Optional[ServerResponse]:
        """
        Query the info, rules, players and mutators of a server that answered the LAN query.

        Args:
            ip_address: Address the beacon reply came from
            query_port: Query port named in the beacon reply

        Returns:
            ServerResponse, or None if the server did not answer the info query
        """
        gamespy1 = GameSpy1(ip_address, query_port, self.protocol_config['query_timeout'])
        start_time = time.perf_counter()

        try:
            info = await gamespy1.get_info(xserverquery=False)
        except Exception as e:
            self.logger.debug("UT99 server at %s:%d did not answer the info query: %s",
                              ip_address, query_port, e)
            return None

        response_time = time.perf_counter() - start_time

        try:
            rules = await gamespy1.get_rules(xserverquery=False)
        except Exception as e:
            self.logger.debug("UT99 server at %s:%d did not answer the rules query: %s",
                              ip_address, query_port, e)
            rules = {}

        players = []
        if self._to_int(info.get('numplayers')) > 0:
            try:
                players = await gamespy1.get_players(xserverquery=False)
            except Exception as e:
                self.logger.debug("UT99 server at %s:%d did not answer the players query: %s",
                                  ip_address, query_port, e)

        try:
            mutators = await self._query_mutators(ip_address, query_port)
        except Exception as e:
            self.logger.debug("UT99 server at %s:%d did not answer the mutators query: %s",
                              ip_address, query_port, e)
            mutators = None

        info_dict = self._build_info_dict(info, rules, players, mutators, query_port)
        game_port = info_dict['game_port']

        self.logger.info("Found UT99 server at %s:%d", ip_address, game_port)
        self.logger.debug(
            "Server details: Name='%s', Map='%s', Mode='%s'",
            info_dict['hostname'], info_dict['map'], info_dict['game_mode']
        )

        return ServerResponse(
            ip_address=ip_address,
            port=game_port,
            game_type='ut99',
            server_info=info_dict,
            response_time=response_time
        )

    async def _query_mutators(self, ip_address: str, query_port: int) -> Optional[str]:
        """
        Query the enabled mutators of a server.

        Returns:
            Comma separated mutator names, or None if the reply does not contain them
        """
        with UdpClient() as udp_client:
            udp_client.settimeout(self.protocol_config['query_timeout'])
            await udp_client.connect((ip_address, query_port))

            udp_client.send(self.MUTATORS_QUERY)
            data = await udp_client.recv()

        match = self.MUTATORS_REPLY.search(data)
        return match.group(1).decode('utf-8', errors='ignore') if match else None

    @classmethod
    def _build_info_dict(cls, info: dict, rules: dict, players: list,
                         mutators: Optional[str], query_port: int) -> dict:
        """Convert the opengsq info, rules, players and the mutators into the DGN info dictionary."""
        game_class = info.get('gametype', '')
        if mutators is None:
            mutators = rules.get('mutators', '')

        return {
            'hostname': info.get('hostname') or 'Unknown Server',
            'map': info.get('mapname') or 'Unknown',
            'map_title': info.get('maptitle', ''),
            'game_mode': cls.GAME_MODES.get(game_class, game_class),
            'game_class': game_class,
            'players': cls._to_int(info.get('numplayers')),
            'max_players': cls._to_int(info.get('maxplayers')),
            'password_protected': str(rules.get('password', '')).lower() == 'true',
            'version': info.get('gamever', ''),
            # Team games report a team goal instead of the frag limit
            'goal_score': cls._to_int(rules.get('goalteamscore')) or cls._to_int(rules.get('fraglimit')),
            'time_limit': cls._to_int(rules.get('timelimit')),
            'mutators': [name.strip() for name in mutators.split(',') if name.strip()],
            'game_style': rules.get('gamestyle', ''),
            'player_names': [player['player'] for player in players if player.get('player')],
            'game_port': cls._to_int(info.get('hostport')) or query_port - 1,
            'query_port': query_port,
        }

    @staticmethod
    def _to_int(value) -> int:
        """Convert a query value to int, 0 if it is missing or not a number."""
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0
