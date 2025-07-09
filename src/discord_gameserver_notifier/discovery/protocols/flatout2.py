"""
Flatout2 protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.flatout2 import Flatout2
from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class Flatout2Protocol(ProtocolBase):
    """Flatout2 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__('', 0, timeout)  # Initialize base class
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 23757,  # Flatout 2 broadcast port
            'query_data': (
                b"\x22\x00" +        # Protocol header
                b"\x99\x72\xcc\x8f" +            # Session ID
                b"\x00" * 4 +               # Padding pre-identifier
                b"FO14" +       # Game identifier
                b"\x00" * 8 +               # Padding post-identifier
                b"\x18\x0c" +         # Query command
                b"\x00\x00\x22\x00" +       # Command data
                b"\x2e\x55\x19\xb4\xe1\x4f\x81\x4a"              # Standard packet end
            )
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Flatout2 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game mode and car type
        if 'game_mode' in server_info:
            fields.append({
                'name': '🎮 Spielmodus',
                'value': server_info['game_mode'],
                'inline': True
            })
            
        if 'car_type' in server_info:
            fields.append({
                'name': '🚗 Fahrzeuge',
                'value': server_info['car_type'],
                'inline': True
            })
            
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Flatout 2 servers using two-step discovery process:
        1. Broadcast to 255.255.255.255:23757 to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Flatout2 servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.debug("Starting Flatout 2 two-step discovery process")
        
        # Step 1: Broadcast discovery to find server IPs
        discovered_ips = set()
        
        try:
            self.logger.debug(f"Step 1: Broadcasting Flatout2 discovery to 255.255.255.255:{port}")
            
            # Send broadcast query using specific source port for Flatout 2
            responses = await self._send_flatout2_broadcast_query(
                "255.255.255.255", port, self.protocol_config['query_data']
            )
            
            # Collect unique IP addresses from responses
            self.logger.debug(f"Processing {len(responses)} Flatout2 broadcast responses")
            for response_data, sender_addr in responses:
                self.logger.debug(f"Processing response from {sender_addr[0]}:{sender_addr[1]} ({len(response_data)} bytes)")
                if self._is_valid_flatout2_response(response_data):
                    discovered_ips.add(sender_addr[0])
                    self.logger.debug(f"Discovered Flatout2 server IP: {sender_addr[0]}")
                else:
                    self.logger.debug(f"Rejected response from {sender_addr[0]}:{sender_addr[1]} (validation failed)")
            
            self.logger.info(f"Step 1 complete: Found {len(discovered_ips)} Flatout2 server IPs")
            
        except Exception as e:
            self.logger.error(f"Error in Flatout2 broadcast discovery: {e}")
            return servers
        
        # Step 2: Query each discovered IP individually for detailed information
        if discovered_ips:
            self.logger.debug(f"Step 2: Querying {len(discovered_ips)} discovered IPs individually")
            
            for ip_address in discovered_ips:
                try:
                    # Small delay between queries to avoid port conflicts
                    await asyncio.sleep(0.1)
                    
                    self.logger.debug(f"Querying Flatout2 server at {ip_address}:{port}")
                    
                    # Create Flatout2 protocol instance for direct query
                    flatout2_query = Flatout2(ip_address, port, 5.0)  # 5 second timeout
                    
                    try:
                        # Query the server directly for full info
                        server_status = await flatout2_query.get_status()
                        
                        if server_status and server_status.info:
                            # Convert Status object to dictionary
                            info_dict = {
                                'hostname': server_status.info.get('hostname', 'Unknown Server'),
                                'timestamp': server_status.info.get('timestamp', '0'),
                                'flags': server_status.info.get('flags', '0'),
                                'status': server_status.info.get('status', '0'),
                                'config': server_status.info.get('config', ''),
                                'players': server_status.info.get('current_players', 0),
                                'max_players': server_status.info.get('max_players', 0),
                                'map': server_status.info.get('map', 'Unknown'),
                                'game_mode': server_status.info.get('game_mode', 'Unknown'),
                                'car_type': server_status.info.get('car_type', 'Unknown'),
                                'game': 'Flatout 2'
                            }
                            
                            server_response = ServerResponse(
                                ip_address=ip_address,
                                port=port,
                                game_type='flatout2',
                                server_info=info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            
                            self.logger.debug(f"Successfully queried Flatout2 server: {ip_address}:{port}")
                            self.logger.debug(f"Flatout2 server details: Name='{info_dict['hostname']}', Flags={info_dict['flags']}, Status={info_dict['status']}")
                    
                    except Exception as e:
                        self.logger.debug(f"Failed to query Flatout2 server at {ip_address}:{port}: {e}")
                        
                except Exception as e:
                    self.logger.debug(f"Error processing Flatout2 server {ip_address}: {e}")
        
        self.logger.info(f"Flatout2 discovery complete: Found {len(servers)} servers with detailed info")
        return servers
    
    async def _send_flatout2_broadcast_query(self, broadcast_addr: str, port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send a Flatout 2 broadcast query using the same port for sending and receiving.
        Flatout 2 requires both source and destination port to be 23757.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to (and bind to locally)
            query_data: Query data to send
            
        Returns:
            List of tuples containing (response_data, sender_address)
        """
        responses = []
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast with specific source port for Flatout 2
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', port),  # Use the same port as destination
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
            self.logger.error(f"Error sending Flatout2 broadcast query: {e}")
            # If port 23757 is already in use, log a specific message
            if "Address already in use" in str(e):
                self.logger.warning(f"Port {port} is already in use. This may happen if multiple Flatout2 scans run simultaneously.")
        
        return responses
    
    def _is_valid_flatout2_response(self, data: bytes) -> bool:
        """
        Check if response data is a valid Flatout 2 response.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid Flatout 2 response, False otherwise
        """
        # Require at least 80 bytes for a complete Flatout 2 response
        if len(data) < 80:
            self.logger.debug(f"Flatout2 response too short: {len(data)} bytes (minimum 80)")
            return False

        # Check game identifier at position 10-14 (this is the most reliable indicator)
        if len(data) >= 14 and data[10:14] != b"FO14":
            game_id = data[10:14] if len(data) >= 14 else b"N/A"
            self.logger.debug(f"Flatout2 response invalid game ID: {game_id}, expected: b'FO14'")
            return False

        header_hex = data[:2].hex()
        self.logger.debug(f"Flatout2 response validation passed: {len(data)} bytes, header: {header_hex}, game_id: {data[10:14]}")
        return True 