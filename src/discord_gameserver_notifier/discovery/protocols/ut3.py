"""
UT3 (Unreal Tournament 3) protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.ut3 import UT3
from .common import ServerResponse, BroadcastResponseProtocol


class UT3Protocol:
    """UT3 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 14001,  # UT3 LAN beacon port
            'broadcast': True,  # Uses broadcast discovery
            'game_id': 0x4D5707DB  # UT3-specific game ID
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for UT3 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game type
        if 'game_type' in server_info and server_info['game_type']:
            fields.append({
                'name': '🎮 Spielmodus',
                'value': server_info['game_type'],
                'inline': True
            })
        
        # Add frag limit
        if 'frag_limit' in server_info and server_info['frag_limit'] is not None:
            fields.append({
                'name': '🎯 Frag Limit',
                'value': str(server_info['frag_limit']),
                'inline': True
            })
        
        # Add time limit
        if 'time_limit' in server_info and server_info['time_limit'] is not None:
            fields.append({
                'name': '⏱️ Zeit Limit',
                'value': f"{server_info['time_limit']} min",
                'inline': True
            })
        
        # Add bot skill (default to 'None' if not available)
        bot_skill = server_info.get('bot_skill', 'None')
        if bot_skill == 'None' or not bot_skill:
            bot_skill = 'None'
        fields.append({
            'name': '🤖 Bot Schwierigkeit',
            'value': bot_skill,
            'inline': True
        })
        
        # Add force respawn
        if 'force_respawn' in server_info:
            force_respawn_text = "✅ Aktiviert" if server_info['force_respawn'] else "❌ Deaktiviert"
            fields.append({
                'name': '💀 Force Respawn',
                'value': force_respawn_text,
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for UT3 servers using broadcast queries.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for UT3 servers
        """
        servers = []
        port = self.protocol_config['port']
        game_id = self.protocol_config['game_id']
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting UT3 query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect responses
                responses, ut3_query = await self._send_ut3_broadcast_query(
                    broadcast_addr, port, game_id
                )
                
                # Process responses using the original query instance for validation
                for response_data, sender_addr in responses:
                    try:
                        # Parse the response directly using the original query instance
                        server_info = await self._parse_ut3_response(response_data, ut3_query)
                        
                        if server_info:
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=sender_addr[1],
                                game_type='ut3',
                                server_info=server_info,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered UT3 server: {sender_addr[0]}:{sender_addr[1]}")
                            self.logger.debug(f"UT3 server details: Name='{server_info.get('name', 'Unknown')}', Map='{server_info.get('map', 'Unknown')}', Players={server_info.get('players', 0)}/{server_info.get('max_players', 0)}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process UT3 response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting UT3 to network {network_range}: {e}")
        
        return servers
    
    async def _send_ut3_broadcast_query(self, broadcast_addr: str, port: int, game_id: int) -> Tuple[List[Tuple[bytes, Tuple[str, int]]], UT3]:
        """
        Send a UT3 broadcast query using UDK protocol.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to
            game_id: UT3 game ID
            
        Returns:
            Tuple of (responses, ut3_query_instance) for validation
        """
        responses = []
        ut3_query = None
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', port),  # Use same port for UT3
                allow_broadcast=True
            )
            
            try:
                # Create UT3 query packet using UDK protocol
                ut3_query = UT3("255.255.255.255", port)
                query_packet = ut3_query._build_query_packet()
                
                # Send broadcast query
                transport.sendto(query_packet, (broadcast_addr, port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending UT3 broadcast query: {e}")
            # If port 14001 is already in use, log a specific message
            if "Address already in use" in str(e):
                self.logger.warning(f"Port {port} is already in use. This may happen if multiple UT3 scans run simultaneously.")
        
        return responses, ut3_query
    
    async def _parse_ut3_response(self, response_data: bytes, ut3_query: UT3) -> Optional[Dict[str, Any]]:
        """
        Parse a UT3 server response using the UT3 protocol.
        
        Args:
            response_data: Raw response data from UT3 server
            ut3_query: UT3 protocol instance for parsing
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Validate response using UT3 protocol
            if not ut3_query._is_valid_response(response_data):
                self.logger.debug(f"Invalid UT3 response received ({len(response_data)} bytes)")
                return None
            
            # Parse response using UT3 protocol
            parsed_data = ut3_query._parse_response(response_data)
            
            # Convert to our standard format
            server_info = {
                'name': parsed_data.get('name', 'Unknown UT3 Server'),
                'map': parsed_data.get('map', 'Unknown Map'),
                'game': 'Unreal Tournament 3',
                'players': parsed_data.get('num_players', 0),
                'max_players': parsed_data.get('max_players', 0),
                'game_type': parsed_data.get('game_type', 'Unknown'),
                'password_protected': parsed_data.get('password_protected', False),
                'stats_enabled': parsed_data.get('stats_enabled', False),
                'lan_mode': parsed_data.get('lan_mode', True),
                'version': 'UT3',
                # UT3-specific information
                'gamemode': parsed_data.get('raw', {}).get('gamemode', 'Unknown'),
                'mutators': parsed_data.get('raw', {}).get('stock_mutators', []) + parsed_data.get('raw', {}).get('custom_mutators', []),
                'frag_limit': parsed_data.get('raw', {}).get('frag_limit'),
                'time_limit': parsed_data.get('raw', {}).get('time_limit'),
                'numbots': parsed_data.get('raw', {}).get('numbots', 0),
                'bot_skill': parsed_data.get('raw', {}).get('bot_skill'),
                'pure_server': parsed_data.get('raw', {}).get('pure_server', False),
                'vs_bots': parsed_data.get('raw', {}).get('vs_bots', 'None'),
                'force_respawn': parsed_data.get('raw', {}).get('force_respawn', False)
            }
            
            return server_info
            
        except Exception as e:
            self.logger.debug(f"Failed to parse UT3 response: {e}")
        
        return None 