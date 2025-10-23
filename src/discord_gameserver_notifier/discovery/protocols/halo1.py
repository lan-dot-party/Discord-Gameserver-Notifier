"""
Halo 1 protocol implementation for game server discovery.
Uses GameSpy2 protocol on UDP port 2302.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.halo1 import Halo1
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class Halo1Protocol(ProtocolBase):
    """Halo 1 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("255.255.255.255", 2302, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 2302,
            'query_data': b'\xFE\xFD\x00\x04\x05\x06\x07\xFF\xFF\xFF'  # GameSpy2 query with all info
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Halo 1 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game version
        
        # Add game type (gametype)
        if 'gametype' in server_info:
            fields.append({
                'name': '🎯 Spielmodus',
                'value': server_info['gametype'],
                'inline': True
            })
        
        # Add game variant
        if 'gamevariant' in server_info and server_info['gamevariant']:
            fields.append({
                'name': '🎲 Variante',
                'value': server_info['gamevariant'],
                'inline': True
            })
        
        # Add game mode (status)
        if 'gamemode' in server_info:
            mode_text = server_info['gamemode']
            if mode_text == 'openplaying':
                mode_text = '🎮 Im Spiel'
            elif mode_text == 'openwaiting':
                mode_text = '⏳ Wartet auf Spieler'
            elif mode_text == 'closedplaying':
                mode_text = '🔒 Spiel läuft (geschlossen)'
            
            fields.append({
                'name': '📊 Status',
                'value': mode_text,
                'inline': True
            })
        
        # Add dedicated server info
        if 'dedicated' in server_info:
            dedicated_text = "🖥️ Dedicated" if server_info['dedicated'] == '1' else "🏠 Listen"
            fields.append({
                'name': '🔧 Server Typ',
                'value': dedicated_text,
                'inline': True
            })
        
        # Add password protection
        if 'password' in server_info:
            password_status = "🔒 Passwort geschützt" if server_info['password'] == '1' else "🌐 Öffentlich"
            fields.append({
                'name': '🔐 Zugang',
                'value': password_status,
                'inline': True
            })
        
        # Add team play status
        if 'teamplay' in server_info:
            teamplay_status = "👥 Team-Modus" if server_info['teamplay'] == '1' else "🎯 Deathmatch"
            fields.append({
                'name': '⚔️ Modus',
                'value': teamplay_status,
                'inline': True
            })
        
        # Add frag limit if available
        if 'fraglimit' in server_info and server_info['fraglimit'] != '0':
            fields.append({
                'name': '🏆 Frag Limit',
                'value': server_info['fraglimit'],
                'inline': True
            })
        
        # Add classic game status
        if 'game_classic' in server_info:
            classic_text = "📜 Classic" if server_info['game_classic'] == '1' else "⚡ Modern"
            fields.append({
                'name': '🎨 Spielstil',
                'value': classic_text,
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Halo 1 servers using broadcast queries.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Halo 1 servers
        """
        servers = []
        port = self.protocol_config['port']
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting Halo 1 query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect initial responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, self.protocol_config['query_data']
                )
                
                # Process responses and query each responding server directly
                for response_data, sender_addr in responses:
                    try:
                        # Use opengsq-python library to get complete server info
                        server_info_dict = await self._query_halo1_server_via_opengsq(
                            sender_addr[0], sender_addr[1]
                        )
                        
                        if server_info_dict:
                            # Use hostport from server info if available
                            actual_port = sender_addr[1]  # Default to query port
                            if 'hostport' in server_info_dict and server_info_dict['hostport']:
                                try:
                                    actual_port = int(server_info_dict['hostport'])
                                except (ValueError, TypeError):
                                    self.logger.debug(f"Invalid hostport value: {server_info_dict['hostport']}, using query port {sender_addr[1]}")
                            
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=actual_port,
                                game_type='halo1',
                                server_info=server_info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered Halo 1 server: {sender_addr[0]}:{actual_port}")
                            self.logger.debug(f"Halo 1 server details: Name='{server_info_dict.get('hostname', 'Unknown')}', Map='{server_info_dict.get('mapname', 'Unknown')}', Players={server_info_dict.get('numplayers', 0)}/{server_info_dict.get('maxplayers', 0)}, GameType={server_info_dict.get('gametype', 'Unknown')}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process Halo 1 response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting Halo 1 query to network {network_range}: {e}")
        
        return servers
    
    async def _send_broadcast_query(self, broadcast_addr: str, port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send a broadcast query and collect all responses within the timeout period.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to
            query_data: Query data to send
            
        Returns:
            List of tuples containing (response_data, sender_address)
        """
        responses = []
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', 0),
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query
                transport.sendto(query_data, (broadcast_addr, port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending Halo 1 broadcast query: {e}")
        
        return responses
    
    async def _query_halo1_server_via_opengsq(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Query a Halo 1 server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            
        Returns:
            Dictionary containing complete server information
        """
        try:
            # Create Halo1 protocol instance
            halo1_client = Halo1(host, port, self.timeout)
            
            # Get server status using opengsq-python
            server_status = await halo1_client.get_status()
            
            # Convert Status object to dictionary format
            info_dict = {}
            
            # Basic server information
            if hasattr(server_status, 'info') and server_status.info:
                info_dict.update(server_status.info)
            
            # Player information
            if hasattr(server_status, 'players') and server_status.players:
                info_dict['players_list'] = server_status.players
                # Update player count if not already set
                if 'numplayers' not in info_dict:
                    info_dict['numplayers'] = str(len(server_status.players))
            
            # Team information
            if hasattr(server_status, 'teams') and server_status.teams:
                info_dict['teams_list'] = server_status.teams
            
            # Ensure we have basic required fields
            if 'hostname' not in info_dict:
                info_dict['hostname'] = f"Halo 1 Server {host}:{port}"
            if 'mapname' not in info_dict:
                info_dict['mapname'] = "Unknown"
            if 'numplayers' not in info_dict:
                info_dict['numplayers'] = "0"
            if 'maxplayers' not in info_dict:
                info_dict['maxplayers'] = "0"
            
            self.logger.debug(f"opengsq-python returned Halo 1 server info for {host}:{port}")
            self.logger.debug(f"Server name: {info_dict.get('hostname')}, Map: {info_dict.get('mapname')}, GameType: {info_dict.get('gametype')}")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"Error querying Halo 1 server {host}:{port} via opengsq-python: {e}")
            return None

