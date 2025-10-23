"""
Quake 3 Arena protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.quake3 import Quake3
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class Quake3Protocol(ProtocolBase):
    """Quake 3 Arena protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        # Quake 3 uses port 27960 for both source and destination
        super().__init__("255.255.255.255", 27960, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Quake 3 broadcast query configuration
        self.protocol_config = {
            'port': 27960,  # Quake 3 standard port
            'getinfo_query': bytes.fromhex('ffffffff676574696e666f20787878')  # getinfo xxx
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get Discord embed fields for Quake 3 server information.
        
        Args:
            server_info: Dictionary containing Quake 3 server information
            
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
        
        # Protocol version - ALWAYS show
        protocol = additional_info.get('protocol', 'Unbekannt')
        fields.append({
            'name': '📡 Protokoll',
            'value': protocol,
            'inline': True
        })
        
        # Pure server - ALWAYS show
        pure_status = additional_info.get('pure', '0') == '1'
        fields.append({
            'name': '🛡️ Pure Server',
            'value': '✅ Aktiviert' if pure_status else '❌ Deaktiviert',
            'inline': True
        })
        
        # Password required - ALWAYS show
        password_required = additional_info.get('g_needpass', '0') == '1'
        fields.append({
            'name': '🔒 Passwort',
            'value': '✅ Erforderlich' if password_required else '❌ Nicht erforderlich',
            'inline': True
        })
        
        # VoIP codec - ALWAYS show
        voip = additional_info.get('voip', 'Keine')
        fields.append({
            'name': '🎤 VoIP',
            'value': voip if voip else 'Keine',
            'inline': True
        })
        
        # Human players - ALWAYS show
        human_players = additional_info.get('g_humanplayers', 'Unbekannt')
        fields.append({
            'name': '👥 Menschliche Spieler',
            'value': human_players,
            'inline': True
        })
        
        # Game name - ALWAYS show
        gamename = additional_info.get('gamename', 'Quake3Arena')
        fields.append({
            'name': '🎯 Spiel',
            'value': gamename,
            'inline': True
        })
        
        return fields
    
    def _translate_gametype(self, gametype_code: str) -> str:
        """
        Translate Quake 3 gametype codes to German display names.
        
        Args:
            gametype_code: The gametype code from the server
            
        Returns:
            German display name for the gametype
        """
        gametype_translations = {
            '0': 'Free For All',
            '1': 'Tournament',
            '2': 'Single Player',
            '3': 'Team Deathmatch',
            '4': 'Capture the Flag',
            '5': 'One Flag Capture',
            '6': 'Overload',
            '7': 'Harvester',
            '8': 'Team Tournament'
        }
        
        return gametype_translations.get(gametype_code, f'Unbekannt ({gametype_code})')
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Quake 3 servers using broadcast discovery.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Quake 3 servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.debug("Starting Quake 3 broadcast discovery")
        
        try:
            # Send broadcast queries to all configured network ranges
            for scan_range in scan_ranges:
                try:
                    network = ipaddress.ip_network(scan_range, strict=False)
                    broadcast_addr = str(network.broadcast_address)
                    
                    self.logger.debug(f"Broadcasting Quake 3 discovery to {broadcast_addr}:{port}")
                    
                    # Send broadcast query using Quake 3 specific source port
                    responses = await self._send_quake3_broadcast_query(
                        broadcast_addr, port
                    )
                    
                    # Process responses
                    self.logger.debug(f"Processing {len(responses)} Quake 3 servers")
                    for server_info in responses:
                        servers.append(server_info)
                        self.logger.info(f"Discovered Quake 3 server: {server_info.ip_address}:{server_info.port}")
                            
                except ValueError as e:
                    self.logger.error(f"Invalid network range '{scan_range}': {e}")
                    continue
                except Exception as e:
                    self.logger.error(f"Error scanning range {scan_range}: {e}")
                    continue
            
            self.logger.info(f"Quake 3 discovery complete: Found {len(servers)} servers")
            
        except Exception as e:
            self.logger.error(f"Error during Quake 3 broadcast discovery: {e}")
        
        return servers
    
    async def _send_quake3_broadcast_query(self, broadcast_addr: str, port: int) -> List[ServerResponse]:
        """
        Send Quake 3 broadcast query and collect responses.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Target port
            
        Returns:
            List of ServerResponse objects for Quake 3 servers
        """
        validated_servers = []
        all_responses = []
        
        # Create UDP socket for broadcast query
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: BroadcastResponseProtocol(all_responses),
            local_addr=('0.0.0.0', 27960),  # Quake 3 uses source port 27960
            allow_broadcast=True
        )
        
        try:
            # Send getinfo query
            getinfo_query = self.protocol_config['getinfo_query']
            transport.sendto(getinfo_query, (broadcast_addr, port))
            self.logger.debug(f"Sent Quake 3 getinfo query to {broadcast_addr}:{port}")
            
            # Wait for responses
            await asyncio.sleep(self.timeout)
            
            # Process responses
            for response_data, sender_addr in all_responses:
                if self._is_valid_quake3_response(response_data):
                    try:
                        server_info = await self._parse_quake3_response(response_data, sender_addr)
                        if server_info:
                            validated_servers.append(server_info)
                    except Exception as e:
                        self.logger.error(f"Error parsing Quake 3 response from {sender_addr[0]}:{sender_addr[1]}: {e}")
        
        finally:
            transport.close()
        
        return validated_servers
    
    def _is_valid_quake3_response(self, data: bytes) -> bool:
        """
        Validate if response data is a valid Quake 3 server response.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid Quake 3 response, False otherwise
        """
        if len(data) < 16:  # Minimum response size
            return False
        
        # Check for Quake 3 response header (4 bytes of 0xFF)
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
    
    async def _parse_quake3_response(self, data: bytes, sender_addr: Tuple[str, int]) -> Optional[ServerResponse]:
        """
        Parse Quake 3 server response data.
        
        Args:
            data: Raw response data
            sender_addr: Sender address tuple (ip, port)
            
        Returns:
            ServerResponse object or None if parsing failed
        """
        try:
            # Check response header
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
            
            # Parse key-value pairs (Quake 3 uses backslash as delimiter)
            server_data = self._parse_key_value_pairs(kv_data)
            
            # Check if this is a Quake 3 Arena server
            gamename = server_data.get('gamename', '')
            if 'Quake' not in gamename:
                self.logger.debug(f"Server {sender_addr[0]}:{sender_addr[1]} filtered out - not a Quake 3 server (gamename: {gamename})")
                return None
            
            # Extract standard server information
            hostname = server_data.get('hostname', 'Unknown Quake 3 Server')
            mapname = server_data.get('mapname', 'Unknown')
            current_players = int(server_data.get('clients', '0'))
            max_players = int(server_data.get('sv_maxclients', '0'))
            
            # Create ServerResponse
            return ServerResponse(
                ip_address=sender_addr[0],
                port=sender_addr[1],
                game_type='quake3',
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
            self.logger.error(f"Error parsing Quake 3 response from {sender_addr[0]}:{sender_addr[1]}: {e}")
            return None
    
    def _parse_key_value_pairs(self, data: str) -> Dict[str, str]:
        """
        Parse Quake 3 key-value pairs from response data.
        Quake 3 uses backslash (\) as delimiter between keys and values.
        
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

