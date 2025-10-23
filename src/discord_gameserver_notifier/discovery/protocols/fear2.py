"""
F.E.A.R. 2: Project Origin protocol implementation for game server discovery.
"""

import asyncio
import logging
from typing import List, Tuple

from opengsq.protocols.gamespy3 import GameSpy3
from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class Fear2Protocol(ProtocolBase):
    """F.E.A.R. 2 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__('', 0, timeout)  # Initialize base class
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 27888,  # F.E.A.R. 2 server port (default)
            'broadcast_port': 52412,  # Source port for broadcast discovery
            'query_data': bytes.fromhex('fefd020000000000')  # GameSpy3 discovery packet
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for F.E.A.R. 2 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game type and game mode
        if 'gametype' in server_info and server_info['gametype']:
            fields.append({
                'name': '🎮 Spieltyp',
                'value': server_info['gametype'],
                'inline': True
            })
            
        if 'gamemode' in server_info and server_info['gamemode']:
            fields.append({
                'name': '🎯 Spielmodus',
                'value': server_info['gamemode'],
                'inline': True
            })
            
        # Add map name
        if 'mapname' in server_info and server_info['mapname']:
            fields.append({
                'name': '🗺️ Karte',
                'value': server_info['mapname'],
                'inline': True
            })
            
        # Add server settings
        settings = []
        if 'ranked' in server_info:
            ranked_status = "Ja" if server_info['ranked'] == '1' else "Nein"
            settings.append(f"Ranked: {ranked_status}")
        if 'lanonly' in server_info:
            lan_status = "Ja" if server_info['lanonly'] == '1' else "Nein"
            settings.append(f"LAN Only: {lan_status}")
        if 'requirespassword' in server_info:
            password_status = "Ja" if server_info['requirespassword'] == '1' else "Nein"
            settings.append(f"Passwort: {password_status}")
            
        if settings:
            fields.append({
                'name': '⚙️ Einstellungen',
                'value': ' | '.join(settings),
                'inline': False
            })
        
        # Add content package information if available
        if 'contentpackageindex' in server_info and server_info['contentpackageindex']:
            fields.append({
                'name': '📦 Content Package',
                'value': f"Index: {server_info['contentpackageindex']}",
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for F.E.A.R. 2 servers using two-step discovery process:
        1. Broadcast from port 52412 to 255.255.255.255:27888 to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for F.E.A.R. 2 servers
        """
        servers = []
        server_port = self.protocol_config['port']
        broadcast_port = self.protocol_config['broadcast_port']
        
        self.logger.debug("Starting F.E.A.R. 2 two-step discovery process")
        
        # Step 1: Broadcast discovery to find server IPs
        discovered_ips = set()
        
        try:
            self.logger.debug(f"Step 1: Broadcasting F.E.A.R. 2 discovery from port {broadcast_port} to 255.255.255.255:{server_port}")
            
            # Send broadcast query using specific source port for F.E.A.R. 2
            responses = await self._send_fear2_broadcast_query(
                "255.255.255.255", server_port, self.protocol_config['query_data']
            )
            
            # Collect unique IP addresses from responses
            self.logger.debug(f"Processing {len(responses)} F.E.A.R. 2 broadcast responses")
            for response_data, sender_addr in responses:
                self.logger.debug(f"Processing response from {sender_addr[0]}:{sender_addr[1]} ({len(response_data)} bytes)")
                if self._is_valid_fear2_response(response_data):
                    discovered_ips.add(sender_addr[0])
                    self.logger.debug(f"Discovered F.E.A.R. 2 server IP: {sender_addr[0]}")
                else:
                    self.logger.debug(f"Rejected response from {sender_addr[0]}:{sender_addr[1]} (validation failed)")
            
            self.logger.info(f"Step 1 complete: Found {len(discovered_ips)} F.E.A.R. 2 server IPs")
            
        except Exception as e:
            self.logger.error(f"Error in F.E.A.R. 2 broadcast discovery: {e}")
            return servers
        
        # Step 2: Query each discovered IP individually for detailed information
        if discovered_ips:
            self.logger.debug(f"Step 2: Querying {len(discovered_ips)} discovered IPs individually")
            
            for ip_address in discovered_ips:
                try:
                    # Small delay between queries to avoid port conflicts
                    await asyncio.sleep(0.1)
                    
                    self.logger.debug(f"Querying F.E.A.R. 2 server at {ip_address}:{server_port}")
                    
                    # Create GameSpy3 protocol instance for direct query
                    fear2_query = GameSpy3(ip_address, server_port, 5.0)  # 5 second timeout
                    
                    try:
                        # Query the server directly for full info
                        server_status = await fear2_query.get_status()
                        
                        if server_status and server_status.info:
                            # Convert Status object to dictionary and add game identifier
                            info_dict = dict(server_status.info)
                            
                            # Verify it's actually a F.E.A.R. 2 server
                            if not self._verify_fear2_game(info_dict):
                                self.logger.debug(f"Server at {ip_address}:{server_port} is not a F.E.A.R. 2 server")
                                continue
                            
                            info_dict['game'] = 'F.E.A.R. 2: Project Origin'
                            
                            server_response = ServerResponse(
                                ip_address=ip_address,
                                port=server_port,
                                game_type='fear2',
                                server_info=info_dict,
                                response_time=0.0
                            )
                            
                            servers.append(server_response)
                            self.logger.info(f"Successfully queried F.E.A.R. 2 server: {info_dict.get('hostname', 'Unknown')} at {ip_address}:{server_port}")
                        else:
                            self.logger.warning(f"F.E.A.R. 2 server at {ip_address}:{server_port} returned no status information")
                            
                    except Exception as query_error:
                        self.logger.warning(f"Failed to query F.E.A.R. 2 server at {ip_address}:{server_port}: {query_error}")
                        
                except Exception as e:
                    self.logger.error(f"Error processing F.E.A.R. 2 server at {ip_address}: {e}")
        
        self.logger.info(f"F.E.A.R. 2 discovery complete: {len(servers)} servers found")
        return servers
    
    async def _send_fear2_broadcast_query(self, target_host: str, target_port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send F.E.A.R. 2 broadcast query from specific source port and collect responses.
        
        Args:
            target_host: Target broadcast address
            target_port: Target port
            query_data: Query data to send
            
        Returns:
            List of tuples containing (response_data, sender_address)
        """
        responses = []
        broadcast_port = self.protocol_config['broadcast_port']
        
        try:
            # Create UDP socket with specific source port for F.E.A.R. 2
            loop = asyncio.get_event_loop()
            
            # Create endpoint with specific local port
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', broadcast_port),
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query
                self.logger.debug(f"Sending F.E.A.R. 2 broadcast query from port {broadcast_port} to {target_host}:{target_port}")
                transport.sendto(query_data, (target_host, target_port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending F.E.A.R. 2 broadcast query: {e}")
        
        return responses
    
    def _is_valid_fear2_response(self, data: bytes) -> bool:
        """
        Validate if the response data is from a F.E.A.R. 2 server.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid F.E.A.R. 2 response, False otherwise
        """
        try:
            # Check minimum length
            if len(data) < 1:
                return False
            
            # F.E.A.R. 2 servers respond to broadcast discovery with a short ACK packet
            # The response is typically: 05 00 00 00 00 00 (6 bytes)
            # First byte 0x05 indicates a GameSpy protocol response
            if data[0] == 0x05 and len(data) == 6:
                self.logger.debug(f"Valid F.E.A.R. 2 broadcast ACK response detected (0x05 packet)")
                return True
            
            # Also accept full GameSpy3 response (starts with 0x00)
            if data[0] == 0x00:
                try:
                    # Convert bytes to string and check for F.E.A.R. 2-specific markers
                    response_str = data.decode('utf-8', errors='ignore')
                    
                    # Look for F.E.A.R. 2-specific game identifier
                    # According to user, gameid should be "01Win32"
                    if 'gameid' in response_str and '01Win32' in response_str:
                        self.logger.debug(f"Valid F.E.A.R. 2 response detected with gameid: 01Win32")
                        return True
                    
                    # Also check for other potential F.E.A.R. 2 markers
                    fear2_markers = ['fear', 'f.e.a.r', 'project origin']
                    for marker in fear2_markers:
                        if marker.lower() in response_str.lower():
                            self.logger.debug(f"Valid F.E.A.R. 2 response detected with marker: {marker}")
                            return True
                            
                except Exception:
                    pass
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error validating F.E.A.R. 2 response: {e}")
            return False
    
    def _verify_fear2_game(self, info_dict: dict) -> bool:
        """
        Verify that the server info is actually from a F.E.A.R. 2 server.
        
        Args:
            info_dict: Server information dictionary
            
        Returns:
            True if this is a F.E.A.R. 2 server, False otherwise
        """
        # Primary verification: check gameid
        if 'gameid' in info_dict:
            if '01Win32' in info_dict['gameid']:
                return True
        
        # Secondary verification: check hostname or other fields
        hostname = info_dict.get('hostname', '').lower()
        gamename = info_dict.get('gamename', '').lower()
        
        fear2_indicators = ['fear', 'f.e.a.r', 'project origin']
        for indicator in fear2_indicators:
            if indicator in hostname or indicator in gamename:
                return True
        
        return False

