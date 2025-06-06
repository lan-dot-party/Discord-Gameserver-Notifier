"""
Source engine protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.source import Source
from opengsq.binary_reader import BinaryReader
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



class SourceProtocol:
    """Source engine protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 27015,
            'query_data': b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
        }
    
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
                        # Create direct Source query instance for the responding server
                        source_query = Source(sender_addr[0], sender_addr[1])
                        
                        try:
                            # Query the server directly for full info
                            server_info = await source_query.get_info()
                            
                            if server_info:
                                # Convert SourceInfo object to dictionary
                                info_dict = {
                                    'name': server_info.name,
                                    'map': server_info.map,
                                    'game': server_info.game,
                                    'players': server_info.players,
                                    'max_players': server_info.max_players,
                                    'server_type': str(server_info.server_type),
                                    'environment': str(server_info.environment),
                                    'protocol': server_info.protocol,
                                    'visibility': server_info.visibility,
                                    'vac': server_info.vac,
                                    'version': server_info.version,
                                    'port': server_info.port,
                                    'steam_id': server_info.steam_id if hasattr(server_info, 'steam_id') else None,
                                    'keywords': server_info.keywords if hasattr(server_info, 'keywords') else None
                                }
                                
                                server_response = ServerResponse(
                                    ip_address=sender_addr[0],
                                    port=sender_addr[1],
                                    game_type='source',
                                    server_info=info_dict,
                                    response_time=0.0
                                )
                                servers.append(server_response)
                                self.logger.debug(f"Discovered Source server: {sender_addr[0]}:{sender_addr[1]}")
                                self.logger.debug(f"Source server details: Name='{info_dict['name']}', Map='{info_dict['map']}', Players={info_dict['players']}/{info_dict['max_players']}, Game={info_dict['game']}")
                        
                        except Exception as e:
                            self.logger.debug(f"Failed to query Source server at {sender_addr}: {e}")
                            
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
    
    async def _parse_source_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a Source engine server response.
        
        Args:
            response_data: Raw response data from server
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Check if this is a valid Source response
            if len(response_data) < 5:
                return None
            
            # Skip the initial 4 bytes (0xFFFFFFFF header)
            if response_data[:4] != b'\xFF\xFF\xFF\xFF':
                return None
            
            # Check for Source info response header (0x49)
            header = response_data[4]  # Read the 5th byte directly
            
            if header == 0x49:  # S2A_INFO_SRC
                # Use opengsq's BinaryReader to parse the response
                br = BinaryReader(response_data[5:])  # Skip 0xFFFFFFFF + header byte
                
                # Create a temporary Source instance for parsing
                temp_source = Source("127.0.0.1", 27015)  # Dummy values
                
                # Parse using Source protocol's internal method
                info = temp_source._Source__parse_from_info_src(br)
                
                return {
                    'name': info.name,
                    'map': info.map,
                    'game': info.game,
                    'players': info.players,
                    'max_players': info.max_players,
                    'server_type': str(info.server_type),
                    'environment': str(info.environment),
                    'protocol': info.protocol
                }
            
        except Exception as e:
            self.logger.debug(f"Failed to parse Source response: {e}")
        
        return None 