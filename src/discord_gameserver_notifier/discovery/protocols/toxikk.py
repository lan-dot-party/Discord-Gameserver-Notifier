"""
Toxikk protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.toxikk import Toxikk
from .common import ServerResponse, BroadcastResponseProtocol


class ToxikkProtocol:
    """Toxikk protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 14001,  # Toxikk LAN beacon port (same as UT3/UDK)
            'broadcast': True,  # Uses broadcast discovery
            'game_id': 0x4D5707DB  # Toxikk-specific game ID
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Toxikk servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game type (with Toxikk-specific gamemode names)
        if 'game_type' in server_info and server_info['game_type']:
            gametype = server_info.get('gametype', server_info['game_type'])
            fields.append({
                'name': '🎮 Spielmodus',
                'value': gametype,
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
        
        # Add bot count
        if 'numbots' in server_info and server_info['numbots'] is not None:
            fields.append({
                'name': '🤖 Bots',
                'value': str(server_info['numbots']),
                'inline': True
            })
        
        # Add bot skill (default to 'None' if not available)
        bot_skill = server_info.get('bot_skill', 'None')
        if bot_skill and bot_skill != 'None':
            fields.append({
                'name': '🤖 Bot Schwierigkeit',
                'value': bot_skill,
                'inline': True
            })
        
        # Add vs bots mode
        if 'vs_bots' in server_info and server_info['vs_bots'] and server_info['vs_bots'] != 'None':
            fields.append({
                'name': '🤖 VS Bots',
                'value': server_info['vs_bots'],
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
        
        # Add pure server status
        if 'pure_server' in server_info:
            pure_server_text = "✅ Pure Server" if server_info['pure_server'] else "❌ Modded Server"
            fields.append({
                'name': '🛡️ Server Status',
                'value': pure_server_text,
                'inline': True
            })
        
        # Add mutators if available
        if 'mutators' in server_info and server_info['mutators']:
            mutators_text = ', '.join(server_info['mutators'])
            if len(mutators_text) > 100:  # Limit length for Discord
                mutators_text = mutators_text[:97] + '...'
            fields.append({
                'name': '🔧 Mutators',
                'value': mutators_text,
                'inline': False
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Toxikk servers using broadcast queries.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Toxikk servers
        """
        servers = []
        port = self.protocol_config['port']
        game_id = self.protocol_config['game_id']
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting Toxikk query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect responses
                responses, toxikk_query = await self._send_toxikk_broadcast_query(
                    broadcast_addr, port, game_id
                )
                
                # Process responses using the original query instance for validation
                for response_data, sender_addr in responses:
                    try:
                        # Parse the response directly using the original query instance
                        server_info = await self._parse_toxikk_response(response_data, toxikk_query)
                        
                        if server_info:
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=sender_addr[1],
                                game_type='toxikk',
                                server_info=server_info,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered Toxikk server: {sender_addr[0]}:{sender_addr[1]}")
                            self.logger.debug(f"Toxikk server details: Name='{server_info.get('name', 'Unknown')}', Map='{server_info.get('map', 'Unknown')}', Players={server_info.get('players', 0)}/{server_info.get('max_players', 0)}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process Toxikk response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting Toxikk to network {network_range}: {e}")
        
        return servers
    
    async def _send_toxikk_broadcast_query(self, broadcast_addr: str, port: int, game_id: int) -> Tuple[List[Tuple[bytes, Tuple[str, int]]], Toxikk]:
        """
        Send a Toxikk broadcast query using UDK protocol.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to
            game_id: Toxikk game ID
            
        Returns:
            Tuple of (responses, toxikk_query_instance) for validation
        """
        responses = []
        toxikk_query = None
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', port),  # Use same port for Toxikk
                allow_broadcast=True
            )
            
            try:
                # Create Toxikk query packet using UDK protocol
                toxikk_query = Toxikk("255.255.255.255", port)
                query_packet = toxikk_query._build_query_packet()
                
                # Send broadcast query
                transport.sendto(query_packet, (broadcast_addr, port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending Toxikk broadcast query: {e}")
            # If port 14001 is already in use, log a specific message
            if "Address already in use" in str(e):
                self.logger.warning(f"Port {port} is already in use. This may happen if multiple Toxikk scans run simultaneously.")
        
        return responses, toxikk_query
    
    async def _parse_toxikk_response(self, response_data: bytes, toxikk_query: Toxikk) -> Optional[Dict[str, Any]]:
        """
        Parse a Toxikk server response using the Toxikk protocol.
        
        Args:
            response_data: Raw response data from Toxikk server
            toxikk_query: Toxikk protocol instance for parsing
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Validate response using Toxikk protocol
            if not toxikk_query._is_valid_response(response_data):
                self.logger.debug(f"Invalid Toxikk response received ({len(response_data)} bytes)")
                return None
            
            # Parse response using Toxikk protocol
            parsed_data = toxikk_query._parse_response(response_data)
            
            # Convert to our standard format
            server_info = {
                'name': parsed_data.get('name', 'Unknown Toxikk Server'),
                'map': parsed_data.get('map', 'Unknown Map'),
                'game': 'Toxikk',
                'players': parsed_data.get('num_players', 0),
                'max_players': parsed_data.get('max_players', 0),
                'game_type': parsed_data.get('game_type', 'Unknown'),
                'password_protected': parsed_data.get('password_protected', False),
                'stats_enabled': parsed_data.get('stats_enabled', False),
                'lan_mode': parsed_data.get('lan_mode', True),
                'version': 'Toxikk',
                # Toxikk-specific information
                'gametype': parsed_data.get('raw', {}).get('gametype', 'Unknown'),
                'mutators': parsed_data.get('raw', {}).get('mutators', []),
                'frag_limit': parsed_data.get('raw', {}).get('frag_limit'),
                'time_limit': parsed_data.get('raw', {}).get('time_limit'),
                'numbots': parsed_data.get('raw', {}).get('numbots', 0),
                'bot_skill': parsed_data.get('raw', {}).get('bot_skill'),
                'pure_server': parsed_data.get('raw', {}).get('pure_server', False),
                'vs_bots': parsed_data.get('raw', {}).get('vs_bots', 'None'),
                'force_respawn': parsed_data.get('raw', {}).get('force_respawn', False),
                'password': parsed_data.get('raw', {}).get('password', 0)
            }
            
            return server_info
            
        except Exception as e:
            self.logger.debug(f"Failed to parse Toxikk response: {e}")
        
        return None 