"""
AVP2 (Alien vs Predator 2) protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.avp2 import AVP2
from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class AVP2Protocol(ProtocolBase):
    """AVP2 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__('', 0, timeout)  # Initialize base class
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 27888,  # AVP2 server port
            'broadcast_port': 60052,  # Source port for broadcast discovery
            'query_data': bytes.fromhex('5c7374617475735c')  # \status\ in hex
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for AVP2 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game type and game mode
        if 'gametype' in server_info:
            fields.append({
                'name': '🎮 Spieltyp',
                'value': server_info['gametype'],
                'inline': True
            })
            
        if 'gamemode' in server_info:
            fields.append({
                'name': '🎯 Spielmodus',
                'value': server_info['gamemode'],
                'inline': True
            })
            
        # Add race information if available
        race_info = []
        if 'maxa' in server_info and server_info['maxa'] != '0':
            race_info.append(f"Aliens: {server_info['maxa']}")
        if 'maxm' in server_info and server_info['maxm'] != '0':
            race_info.append(f"Marines: {server_info['maxm']}")
        if 'maxp' in server_info and server_info['maxp'] != '0':
            race_info.append(f"Predators: {server_info['maxp']}")
        if 'maxc' in server_info and server_info['maxc'] != '0':
            race_info.append(f"Corporate: {server_info['maxc']}")
            
        if race_info:
            fields.append({
                'name': '👥 Rassen-Limits',
                'value': ' | '.join(race_info),
                'inline': False
            })
            
        # Add game settings
        settings = []
        if 'ff' in server_info:
            ff_status = "An" if server_info['ff'] == '1' else "Aus"
            settings.append(f"Friendly Fire: {ff_status}")
        if 'speed' in server_info and server_info['speed'] != '100':
            settings.append(f"Geschwindigkeit: {server_info['speed']}%")
        if 'damage' in server_info and server_info['damage'] != '100':
            settings.append(f"Schaden: {server_info['damage']}%")
            
        if settings:
            fields.append({
                'name': '⚙️ Einstellungen',
                'value': ' | '.join(settings),
                'inline': False
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for AVP2 servers using two-step discovery process:
        1. Broadcast from port 60052 to 255.255.255.255:27888 to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for AVP2 servers
        """
        servers = []
        server_port = self.protocol_config['port']
        broadcast_port = self.protocol_config['broadcast_port']
        
        self.logger.debug("Starting AVP2 two-step discovery process")
        
        # Step 1: Broadcast discovery to find server IPs
        discovered_ips = set()
        
        try:
            self.logger.debug(f"Step 1: Broadcasting AVP2 discovery from port {broadcast_port} to 255.255.255.255:{server_port}")
            
            # Send broadcast query using specific source port for AVP2
            responses = await self._send_avp2_broadcast_query(
                "255.255.255.255", server_port, self.protocol_config['query_data']
            )
            
            # Collect unique IP addresses from responses
            self.logger.debug(f"Processing {len(responses)} AVP2 broadcast responses")
            for response_data, sender_addr in responses:
                self.logger.debug(f"Processing response from {sender_addr[0]}:{sender_addr[1]} ({len(response_data)} bytes)")
                if self._is_valid_avp2_response(response_data):
                    discovered_ips.add(sender_addr[0])
                    self.logger.debug(f"Discovered AVP2 server IP: {sender_addr[0]}")
                else:
                    self.logger.debug(f"Rejected response from {sender_addr[0]}:{sender_addr[1]} (validation failed)")
            
            self.logger.info(f"Step 1 complete: Found {len(discovered_ips)} AVP2 server IPs")
            
        except Exception as e:
            self.logger.error(f"Error in AVP2 broadcast discovery: {e}")
            return servers
        
        # Step 2: Query each discovered IP individually for detailed information
        if discovered_ips:
            self.logger.debug(f"Step 2: Querying {len(discovered_ips)} discovered IPs individually")
            
            for ip_address in discovered_ips:
                try:
                    # Small delay between queries to avoid port conflicts
                    await asyncio.sleep(0.1)
                    
                    self.logger.debug(f"Querying AVP2 server at {ip_address}:{server_port}")
                    
                    # Create AVP2 protocol instance for direct query
                    avp2_query = AVP2(ip_address, server_port, 5.0)  # 5 second timeout
                    
                    try:
                        # Query the server directly for full info
                        server_status = await avp2_query.get_status()
                        
                        if server_status and server_status.info:
                            # Convert Status object to dictionary and add game identifier
                            info_dict = dict(server_status.info)
                            info_dict['game'] = 'Alien vs Predator 2'
                            
                            server_response = ServerResponse(
                                ip_address=ip_address,
                                port=server_port,
                                game_type='avp2',
                                server_info=info_dict,
                                response_time=0.0
                            )
                            
                            servers.append(server_response)
                            self.logger.info(f"Successfully queried AVP2 server: {info_dict.get('hostname', 'Unknown')} at {ip_address}:{server_port}")
                        else:
                            self.logger.warning(f"AVP2 server at {ip_address}:{server_port} returned no status information")
                            
                    except Exception as query_error:
                        self.logger.warning(f"Failed to query AVP2 server at {ip_address}:{server_port}: {query_error}")
                        
                except Exception as e:
                    self.logger.error(f"Error processing AVP2 server at {ip_address}: {e}")
        
        self.logger.info(f"AVP2 discovery complete: {len(servers)} servers found")
        return servers
    
    async def _send_avp2_broadcast_query(self, target_host: str, target_port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send AVP2 broadcast query from specific source port and collect responses.
        
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
            # Create UDP socket with specific source port for AVP2
            loop = asyncio.get_event_loop()
            
            # Create endpoint with specific local port
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', broadcast_port),
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query
                self.logger.debug(f"Sending AVP2 broadcast query from port {broadcast_port} to {target_host}:{target_port}")
                transport.sendto(query_data, (target_host, target_port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending AVP2 broadcast query: {e}")
        
        return responses
    
    def _is_valid_avp2_response(self, data: bytes) -> bool:
        """
        Validate if the response data is from an AVP2 server.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid AVP2 response, False otherwise
        """
        try:
            # Convert bytes to string and check for AVP2-specific markers
            response_str = data.decode('utf-8', errors='ignore')
            
            # Check for GameSpy1 protocol markers and AVP2-specific content
            if '\\' in response_str:
                # Look for AVP2-specific game identifiers
                avp2_markers = ['avp2', 'gamename\\avp2', 'Aliens vs. Predator 2', 'Alien vs Predator 2']
                
                for marker in avp2_markers:
                    if marker.lower() in response_str.lower():
                        self.logger.debug(f"Valid AVP2 response detected with marker: {marker}")
                        return True
                        
                # Also check for common GameSpy1 structure with hostname
                if 'hostname\\' in response_str and 'gamename\\' in response_str:
                    self.logger.debug("Valid GameSpy1 response structure detected")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error validating AVP2 response: {e}")
            return False
