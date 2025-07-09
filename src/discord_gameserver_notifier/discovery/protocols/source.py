"""
Source engine protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.source import Source
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class BroadcastProtocol(ProtocolBase):
    """Custom protocol class for broadcast queries"""
    
    def __init__(self, game_type: str, port: int = 27015, timeout: float = 5.0):
        # Use broadcast address for discovery
        super().__init__("255.255.255.255", port, timeout)
        self._allow_broadcast = True
        self.game_type = game_type
        self.logger = logging.getLogger(f"{__name__}.{game_type}")
    
    @property
    def full_name(self) -> str:
        return f"Broadcast {self.game_type} Protocol"



class SourceProtocol(ProtocolBase):
    """Source engine protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("255.255.255.255", 27015, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 27015,
            'query_data': b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Source engine servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add VAC protection status (vac: 1 = enabled, 0 = disabled)
        if 'vac' in server_info:
            vac_status = "✅ Aktiviert" if server_info['vac'] == 1 else "❌ Deaktiviert"
            fields.append({
                'name': '🛡️ VAC Schutz',
                'value': vac_status,
                'inline': True
            })
        
        # Add server type (dedicated/listen) - handle both numeric ASCII codes and character values
        if 'server_type' in server_info:
            server_type = server_info['server_type']
            if server_type == 100 or server_type == 'd':  # 100 = ASCII 'd' (dedicated)
                server_type_text = "🖥️ Dedicated Server"
            elif server_type == 108 or server_type == 'l':  # 108 = ASCII 'l' (listen)
                server_type_text = "🏠 Listen Server"
            elif server_type == 112 or server_type == 'p':  # 112 = ASCII 'p' (SourceTV proxy)
                server_type_text = "📺 SourceTV Relay"
            else:
                server_type_text = f"❓ {server_type}"
            
            fields.append({
                'name': '🔧 Server Typ',
                'value': server_type_text,
                'inline': True
            })
        
        # Add environment (OS) - handle both numeric ASCII codes and character values
        if 'environment' in server_info:
            environment = server_info['environment']
            if environment == 108 or environment == 'l':  # 108 = ASCII 'l' (Linux)
                env_text = "🐧 Linux"
            elif environment == 119 or environment == 'w':  # 119 = ASCII 'w' (Windows)
                env_text = "🪟 Windows"
            elif environment == 109 or environment == 'm':  # 109 = ASCII 'm' (Mac)
                env_text = "🍎 Mac"
            elif environment == 111 or environment == 'o':  # 111 = ASCII 'o' (Mac old)
                env_text = "🍎 Mac (legacy)"
            else:
                env_text = f"❓ {environment}"
            
            fields.append({
                'name': '💻 Betriebssystem',
                'value': env_text,
                'inline': True
            })
        
        # Add protocol version
        if 'protocol' in server_info:
            fields.append({
                'name': '📡 Protokoll Version',
                'value': str(server_info['protocol']),
                'inline': True
            })
        
        # Add bots count if available and > 0
        if 'bots' in server_info and server_info['bots'] > 0:
            fields.append({
                'name': '🤖 Bots',
                'value': str(server_info['bots']),
                'inline': True
            })
        
        # Add server visibility (0 = public, 1 = private)
        if 'visibility' in server_info:
            visibility_text = "🔒 Privat" if server_info['visibility'] == 1 else "🌐 Öffentlich"
            fields.append({
                'name': '👁️ Sichtbarkeit',
                'value': visibility_text,
                'inline': True
            })
        
        # # Add Steam ID if available
        # if 'steam_id' in server_info and server_info['steam_id']:
        #     fields.append({
        #         'name': '🎮 Steam ID',
        #         'value': f"`{server_info['steam_id']}`",
        #         'inline': False
        #     })
        
        # Add keywords if available
        if 'keywords' in server_info and server_info['keywords']:
            keywords = server_info['keywords']
            if len(keywords) > 100:
                keywords = keywords[:97] + "..."
            fields.append({
                'name': '🏷️ Keywords',
                'value': f"`{keywords}`",
                'inline': False
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Source engine servers using broadcast queries.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Source servers
        """
        servers = []
        port = self.protocol_config['port']
        
        # Create broadcast protocol instance
        broadcast_protocol = BroadcastProtocol('source', port, self.timeout)
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting Source query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect initial responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, self.protocol_config['query_data']
                )
                
                # Process responses and query each responding server directly
                for response_data, sender_addr in responses:
                    try:
                        # Use opengsq-python library to get complete server info
                        server_info_dict = await self._query_source_server_via_opengsq(
                            sender_addr[0], sender_addr[1]
                        )
                        
                        if server_info_dict:
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=sender_addr[1],
                                game_type='source',
                                server_info=server_info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered Source server: {sender_addr[0]}:{sender_addr[1]}")
                            self.logger.debug(f"Source server details: Name='{server_info_dict.get('name', 'Unknown')}', Map='{server_info_dict.get('map', 'Unknown')}', Players={server_info_dict.get('players', 0)}/{server_info_dict.get('max_players', 0)}, Game={server_info_dict.get('game', 'Unknown')}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting to network {network_range}: {e}")
        
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
            self.logger.error(f"Error sending broadcast query: {e}")
        
        return responses
    
    async def _query_source_server_via_opengsq(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Query a Source server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            
        Returns:
            Dictionary containing complete server information with all fields needed for Discord
        """
        try:
            # Create Source protocol instance
            source_client = Source(host, port, self.timeout)
            
            # Get server info using opengsq-python
            server_info = await source_client.get_info()
            
            # Convert SourceInfo object to dictionary format
            # Handle enum values by extracting their numeric values
            info_dict = {
                'name': server_info.name,
                'map': server_info.map,
                'game': server_info.game,
                'players': server_info.players,
                'max_players': server_info.max_players,
                'bots': server_info.bots,
                'server_type': server_info.server_type.value if hasattr(server_info.server_type, 'value') else server_info.server_type,
                'environment': server_info.environment.value if hasattr(server_info.environment, 'value') else server_info.environment,
                'protocol': server_info.protocol,
                'visibility': server_info.visibility.value if hasattr(server_info.visibility, 'value') else server_info.visibility,
                'vac': server_info.vac.value if hasattr(server_info.vac, 'value') else server_info.vac,
                'version': server_info.version,
                'port': getattr(server_info, 'port', port),
                'steam_id': getattr(server_info, 'steam_id', None),
                'keywords': getattr(server_info, 'keywords', ''),
                'folder': server_info.folder,
                'id': getattr(server_info, 'id', None),
                'edf': getattr(server_info, 'edf', None)
            }
            
            self.logger.debug(f"opengsq-python returned server info for {host}:{port}")
            self.logger.debug(f"VAC status: {info_dict.get('vac')}, Server type: {info_dict.get('server_type')}, Environment: {info_dict.get('environment')}")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"Error querying Source server {host}:{port} via opengsq-python: {e}")
            return None 