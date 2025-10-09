"""
Call of Duty 4 protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.cod4 import CoD4
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class CoD4Protocol(ProtocolBase):
    """Call of Duty 4 protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        # CoD4 uses port 28960 for both source and destination
        super().__init__("255.255.255.255", 28960, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # CoD4 broadcast query configuration
        self.protocol_config = {
            'port': 28960,  # CoD4 standard port
            'query_data': bytes.fromhex('ffffffff676574696e666f20787878')  # getinfo xxx
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get Discord embed fields for CoD4 server information.
        
        Args:
            server_info: Dictionary containing CoD4 server information
            
        Returns:
            List of Discord embed field dictionaries
        """
        fields = []
        
        # Extract the additional_info from the nested structure
        additional_info = server_info.get('additional_info', {})
        
        # Game type with translation - ALWAYS show
        gametype = additional_info.get('gametype', 'unknown')
        gametype_translated = self._translate_gametype(gametype)
        fields.append({
            'name': '🎮 Spielmodus',
            'value': f"{gametype_translated} ({gametype})",
            'inline': True
        })
        
        # Hardcore mode - ALWAYS show
        hardcore_status = additional_info.get('hc', '0') == '1'
        fields.append({
            'name': '💀 Hardcore',
            'value': '✅ Aktiviert' if hardcore_status else '❌ Deaktiviert',
            'inline': True
        })
        
        # Friendly Fire - ALWAYS show (0 = Off, 1-3 = Different FF modes)
        ff_value = additional_info.get('ff', '0')
        try:
            ff_int = int(ff_value)
            if ff_int == 0:
                ff_display = '❌ Deaktiviert'
            elif ff_int >= 1 and ff_int <= 3:
                ff_display = f'✅ Aktiviert (Modus {ff_int})'
            else:
                ff_display = f'❓ Unbekannt ({ff_value})'
        except (ValueError, TypeError):
            ff_display = f'❓ Unbekannt ({ff_value})'
        
        fields.append({
            'name': '🔫 Friendly Fire',
            'value': ff_display,
            'inline': True
        })
        
        # Pure server - ALWAYS show
        pure_status = additional_info.get('pure', '0') == '1'
        fields.append({
            'name': '🛡️ Pure Server',
            'value': '✅ Aktiviert' if pure_status else '❌ Deaktiviert',
            'inline': True
        })
        
        # Voice chat - ALWAYS show
        voice_status = additional_info.get('voice', '0') == '1'
        fields.append({
            'name': '🎤 Voice Chat',
            'value': '✅ Aktiviert' if voice_status else '❌ Deaktiviert',
            'inline': True
        })
        
        # Mod information - ALWAYS show
        mod_info = additional_info.get('mod', '0')
        mod_status = 'Kein Mod' if mod_info == '0' else f'Mod: {mod_info}'
        fields.append({
            'name': '🔧 Mod',
            'value': mod_status,
            'inline': True
        })
        
        # Build version - ALWAYS show
        build_info = additional_info.get('build', 'Unbekannt')
        fields.append({
            'name': '🏗️ Build',
            'value': build_info,
            'inline': True
        })
        
        # Max Ping - ALWAYS show
        max_ping = additional_info.get('sv_maxPing', 'Unbegrenzt')
        fields.append({
            'name': '📡 Max Ping',
            'value': f"{max_ping}ms" if max_ping != 'Unbegrenzt' else max_ping,
            'inline': True
        })
        
        return fields
    
    def _translate_gametype(self, gametype_code: str) -> str:
        """
        Translate CoD4 gametype codes to German display names.
        
        Args:
            gametype_code: The gametype code from the server
            
        Returns:
            German display name for the gametype
        """
        gametype_translations = {
            'dm': 'Deathmatch',
            'war': 'Team Deathmatch',
            'dom': 'Domination',
            'koth': 'Hauptquartier',
            'sab': 'Sabotage',
            'sd': 'Suchen & Zerstören'
        }
        
        return gametype_translations.get(gametype_code.lower(), gametype_code)
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for CoD4 servers using broadcast discovery.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for CoD4 servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.debug("Starting CoD4 broadcast discovery")
        
        try:
            # Send broadcast queries to all configured network ranges
            for scan_range in scan_ranges:
                try:
                    network = ipaddress.ip_network(scan_range, strict=False)
                    broadcast_addr = str(network.broadcast_address)
                    
                    self.logger.debug(f"Broadcasting CoD4 discovery to {broadcast_addr}:{port}")
                    
                    # Send broadcast query using CoD4 specific source port
                    responses = await self._send_cod4_broadcast_query(
                        broadcast_addr, port, self.protocol_config['query_data']
                    )
                    
                    # Process responses
                    self.logger.debug(f"Processing {len(responses)} CoD4 broadcast responses")
                    for response_data, sender_addr in responses:
                        self.logger.debug(f"Processing response from {sender_addr[0]}:{sender_addr[1]} ({len(response_data)} bytes)")
                        
                        if self._is_valid_cod4_response(response_data):
                            # Parse the server info using opengsq-python
                            try:
                                server_info = await self._parse_cod4_response(response_data, sender_addr)
                                if server_info:
                                    servers.append(server_info)
                                    self.logger.info(f"Discovered CoD4 server: {sender_addr[0]}:{sender_addr[1]}")
                            except Exception as e:
                                self.logger.error(f"Error parsing CoD4 response from {sender_addr[0]}:{sender_addr[1]}: {e}")
                        else:
                            self.logger.debug(f"Rejected response from {sender_addr[0]}:{sender_addr[1]} (validation failed)")
                            
                except ValueError as e:
                    self.logger.error(f"Invalid network range '{scan_range}': {e}")
                    continue
                except Exception as e:
                    self.logger.error(f"Error scanning range {scan_range}: {e}")
                    continue
            
            self.logger.info(f"CoD4 discovery complete: Found {len(servers)} servers")
            
        except Exception as e:
            self.logger.error(f"Error during CoD4 broadcast discovery: {e}")
        
        return servers
    
    async def _send_cod4_broadcast_query(self, broadcast_addr: str, port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send CoD4 broadcast query and collect responses.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Target port
            query_data: Query payload to send
            
        Returns:
            List of (response_data, sender_address) tuples
        """
        responses = []
        
        # Create UDP socket with broadcast enabled and specific source port
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: BroadcastResponseProtocol(responses),
            local_addr=('0.0.0.0', 28960),  # CoD4 requires source port 28960
            allow_broadcast=True
        )
        
        try:
            # Send the broadcast query
            transport.sendto(query_data, (broadcast_addr, port))
            self.logger.debug(f"Sent CoD4 broadcast query to {broadcast_addr}:{port} (payload: {query_data.hex()})")
            
            # Wait for responses
            await asyncio.sleep(self.timeout)
            
        finally:
            transport.close()
        
        return responses
    
    def _is_valid_cod4_response(self, data: bytes) -> bool:
        """
        Validate if response data is a valid CoD4 server response.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid CoD4 response, False otherwise
        """
        if len(data) < 16:  # Minimum response size
            return False
        
        # Check for CoD4 response header (4 bytes of 0xFF)
        if data[:4] != b'\xFF\xFF\xFF\xFF':
            return False
        
        # Check for "infoResponse" string after header
        try:
            response_str = data[4:].decode('ascii', errors='ignore')
            if response_str.startswith('infoResponse'):
                return True
        except:
            pass
        
        return False
    
    async def _parse_cod4_response(self, data: bytes, sender_addr: Tuple[str, int]) -> Optional[ServerResponse]:
        """
        Parse CoD4 server response data.
        
        Args:
            data: Raw response data
            sender_addr: Sender address tuple (ip, port)
            
        Returns:
            ServerResponse object or None if parsing failed
        """
        try:
            # Create a temporary CoD4 client to parse the response
            cod4_client = CoD4(sender_addr[0], sender_addr[1], self.timeout)
            
            # Parse the response data manually (similar to opengsq-python implementation)
            if len(data) < 4 or data[:4] != b'\xFF\xFF\xFF\xFF':
                return None
            
            # Find the end of "infoResponse" and start of key-value pairs
            response_str = data[4:].decode('ascii', errors='ignore')
            if not response_str.startswith('infoResponse'):
                return None
            
            # Extract key-value pairs (after "infoResponse\n")
            kv_start = response_str.find('\n')
            if kv_start == -1:
                return None
            
            kv_data = response_str[kv_start + 1:]
            
            # Parse key-value pairs (CoD4 uses backslash as delimiter)
            server_data = self._parse_key_value_pairs(kv_data)
            
            # Extract standard server information
            hostname = server_data.get('hostname', 'Unknown CoD4 Server')
            mapname = server_data.get('mapname', 'Unknown')
            current_players = int(server_data.get('clients', '0'))
            max_players = int(server_data.get('sv_maxclients', '0'))
            
            # Create ServerResponse
            return ServerResponse(
                ip_address=sender_addr[0],
                port=sender_addr[1],
                game_type='cod4',
                server_info={
                    'hostname': hostname,
                    'map_name': mapname,
                    'current_players': current_players,
                    'max_players': max_players,
                    'additional_info': server_data
                },
                response_time=0.0  # We don't measure response time in broadcast discovery
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing CoD4 response from {sender_addr[0]}:{sender_addr[1]}: {e}")
            return None
    
    def _parse_key_value_pairs(self, data: str) -> Dict[str, str]:
        """
        Parse CoD4 key-value pairs from response data.
        CoD4 uses backslash (\) as delimiter between keys and values.
        
        Args:
            data: String data containing key-value pairs
            
        Returns:
            Dictionary containing parsed key-value pairs
        """
        result = {}
        
        # Split by backslash and process pairs
        parts = data.split('\\')
        
        # Remove empty first element if it exists (starts with \)
        if parts and parts[0] == '':
            parts = parts[1:]
        
        # Process pairs (key, value, key, value, ...)
        for i in range(0, len(parts) - 1, 2):
            if i + 1 < len(parts):
                key = parts[i].strip()
                value = parts[i + 1].strip()
                if key:  # Only add non-empty keys
                    result[key] = value
        
        return result



