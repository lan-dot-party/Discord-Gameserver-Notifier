"""
Star Wars Jedi Knight: Jedi Academy protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
import re
import socket
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.jediknight import JediKnight
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class JediKnightProtocol(ProtocolBase):
    """Jedi Academy protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        # Jedi Academy uses port 29070 for both source and destination
        super().__init__("255.255.255.255", 29070, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Jedi Academy broadcast query configuration
        self.protocol_config = {
            'port': 29070,  # Jedi Academy standard port
            'getstatus_query': bytes.fromhex('ffffffff67657473746174757320787878'),  # getstatus xxx (for gamename filtering)
            'getinfo_query': bytes.fromhex('ffffffff676574696e666f20787878')  # getinfo xxx (for detailed server info)
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get Discord embed fields for Jedi Academy server information.
        
        Args:
            server_info: Dictionary containing Jedi Academy server information
            
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
        
        # Password required - ALWAYS show
        needpass = additional_info.get('needpass', '0')
        password_status = '🔒 Ja' if needpass == '1' else '🔓 Nein'
        fields.append({
            'name': '🔑 Passwort',
            'value': password_status,
            'inline': True
        })
        
        # True Jedi mode - ALWAYS show
        truejedi = additional_info.get('truejedi', '0')
        truejedi_status = '✅ Aktiviert' if truejedi == '1' else '❌ Deaktiviert'
        fields.append({
            'name': '⚔️ True Jedi',
            'value': truejedi_status,
            'inline': True
        })

        # Protocol version - ALWAYS show
        protocol_info = additional_info.get('protocol', 'Unbekannt')
        fields.append({
            'name': '📡 Protokoll',
            'value': protocol_info,
            'inline': True
        })
        
        # Force Powers Disable - show if set
        fdisable = additional_info.get('fdisable', '0')
        if fdisable != '0':
            fields.append({
                'name': '🔮 Force Disable',
                'value': fdisable,
                'inline': True
            })
        
        # Weapons Disable - show if set
        wdisable = additional_info.get('wdisable', '0')
        if wdisable != '0':
            fields.append({
                'name': '🔫 Waffen Disable',
                'value': wdisable,
                'inline': True
            })
        
        # Max Ping - ALWAYS show (from status response)
        max_ping = additional_info.get('sv_maxPing', 'Unbegrenzt')
        if max_ping == '0':
            max_ping = 'Unbegrenzt'
        fields.append({
            'name': '📡 Max Ping',
            'value': f"{max_ping}ms" if max_ping != 'Unbegrenzt' else max_ping,
            'inline': True
        })
        
        # Players info if available
        players = additional_info.get('players', [])
        if players:
            player_list = []
            for player in players[:10]:  # Limit to 10 players for display
                if isinstance(player, dict):
                    name = player.get('name', 'Unknown')
                    score = player.get('score', 0)
                    ping = player.get('ping', 0)
                    player_list.append(f"• {name} (Score: {score}, Ping: {ping})")
            
            if player_list:
                # Truncate if too long
                player_text = '\n'.join(player_list)
                if len(player_text) > 1000:
                    player_text = player_text[:997] + '...'
                
                fields.append({
                    'name': f'👥 Spieler ({len(players)})',
                    'value': player_text if player_text else 'Keine Spieler',
                    'inline': False
                })
        
        return fields
    
    def _translate_gametype(self, gametype_code: str) -> str:
        """
        Translate Jedi Academy gametype codes to German display names.
        
        Args:
            gametype_code: The gametype code from the server
            
        Returns:
            German display name for the gametype
        """
        gametype_translations = {
            '0': 'Free For All',
            '3': 'Duell',
            '4': 'Power Duell',
            '6': 'Team FFA',
            '7': 'Siege',
            '8': 'Capture the Flag',
        }
        
        return gametype_translations.get(str(gametype_code), gametype_code)
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Jedi Academy servers using broadcast discovery.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Jedi Academy servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.debug("Starting Jedi Academy broadcast discovery")
        
        try:
            # Send broadcast queries to all configured network ranges
            for scan_range in scan_ranges:
                try:
                    network = ipaddress.ip_network(scan_range, strict=False)
                    broadcast_addr = str(network.broadcast_address)
                    
                    self.logger.debug(f"Broadcasting Jedi Academy discovery to {broadcast_addr}:{port}")
                    
                    # Send broadcast queries using Jedi Academy specific source port
                    # First getstatus to filter by gamename, then getinfo for details
                    responses = await self._send_jediknight_dual_broadcast_query(
                        broadcast_addr, port
                    )
                    
                    # Process responses (already filtered and parsed)
                    self.logger.debug(f"Processing {len(responses)} validated Jedi Academy servers")
                    for server_info in responses:
                        servers.append(server_info)
                        self.logger.info(f"Discovered Jedi Academy server: {server_info.ip_address}:{server_info.port}")
                            
                except ValueError as e:
                    self.logger.error(f"Invalid network range '{scan_range}': {e}")
                    continue
                except Exception as e:
                    self.logger.error(f"Error scanning range {scan_range}: {e}")
                    continue
            
            self.logger.info(f"Jedi Academy discovery complete: Found {len(servers)} servers")
            
        except Exception as e:
            self.logger.error(f"Error during Jedi Academy broadcast discovery: {e}")
        
        return servers
    
    async def _send_jediknight_dual_broadcast_query(self, broadcast_addr: str, port: int) -> List[ServerResponse]:
        """
        Send Jedi Academy dual broadcast queries (getstatus + getinfo) and collect validated responses.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Target port
            
        Returns:
            List of ServerResponse objects for validated Jedi Academy servers
        """
        validated_servers = []
        all_responses = []
        
        # Create UDP socket with SO_REUSEADDR to prevent "Address already in use" errors
        # when multiple scans run in sequence
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 29070))  # Jedi Academy requires source port 29070
        sock.setblocking(False)
        
        # Create datagram endpoint with the prepared socket
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: BroadcastResponseProtocol(all_responses),
            sock=sock
        )
        
        try:
            # Step 1: Send getstatus query to filter by gamename and collect status data
            getstatus_query = self.protocol_config['getstatus_query']
            transport.sendto(getstatus_query, (broadcast_addr, port))
            self.logger.debug(f"Sent Jedi Academy getstatus query to {broadcast_addr}:{port}")
            
            # Wait for getstatus responses
            await asyncio.sleep(self.timeout)
            
            # Filter servers by gamename from getstatus responses and store status data
            valid_server_addresses = set()
            server_status_data = {}  # Store getstatus data for each server
            getstatus_responses = all_responses.copy()  # Save current responses
            all_responses.clear()  # Clear for next query
            
            for response_data, sender_addr in getstatus_responses:
                if self._is_valid_jediknight_response(response_data):
                    try:
                        # Quick parse to check gamename
                        if self._check_gamename_from_response(response_data):
                            valid_server_addresses.add(sender_addr)
                            # Store the getstatus data for later combination
                            status_data, players = self._parse_jediknight_status_response(response_data)
                            if status_data:
                                server_status_data[sender_addr] = {
                                    'status': status_data,
                                    'players': players
                                }
                            self.logger.debug(f"Server {sender_addr[0]}:{sender_addr[1]} passed gamename filter")
                        else:
                            self.logger.debug(f"Server {sender_addr[0]}:{sender_addr[1]} filtered out by gamename")
                    except Exception as e:
                        self.logger.debug(f"Error checking gamename for {sender_addr[0]}:{sender_addr[1]}: {e}")
            
            if not valid_server_addresses:
                self.logger.debug("No valid Jedi Academy servers found after gamename filtering")
                return validated_servers
            
            # Step 2: Send getinfo query to get detailed information
            getinfo_query = self.protocol_config['getinfo_query']
            transport.sendto(getinfo_query, (broadcast_addr, port))
            self.logger.debug(f"Sent Jedi Academy getinfo query to {broadcast_addr}:{port}")
            
            # Wait for getinfo responses
            await asyncio.sleep(self.timeout)
            
            # Process getinfo responses from validated servers only and combine with status data
            for response_data, sender_addr in all_responses:
                if sender_addr in valid_server_addresses and self._is_valid_jediknight_response(response_data):
                    try:
                        # Parse getinfo response
                        info_data = self._parse_jediknight_info_response(response_data)
                        if info_data:
                            # Combine getinfo and getstatus data
                            status_info = server_status_data.get(sender_addr, {})
                            status_data = status_info.get('status', {})
                            players = status_info.get('players', [])
                            combined_data = {**info_data, **status_data}  # status_data overwrites info_data for duplicates
                            combined_data['players'] = players
                            
                            server_info = await self._create_jediknight_server_response(combined_data, sender_addr)
                            if server_info:
                                validated_servers.append(server_info)
                    except Exception as e:
                        self.logger.error(f"Error parsing Jedi Academy response from {sender_addr[0]}:{sender_addr[1]}: {e}")
        
        finally:
            transport.close()
        
        return validated_servers
    
    def _is_valid_jediknight_response(self, data: bytes) -> bool:
        """
        Validate if response data is a valid Jedi Academy server response.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid Jedi Academy response, False otherwise
        """
        if len(data) < 16:  # Minimum response size
            return False
        
        # Check for Jedi Academy response header (4 bytes of 0xFF)
        if data[:4] != b'\xFF\xFF\xFF\xFF':
            return False
        
        # Check for "infoResponse" or "statusResponse" string after header
        try:
            response_str = data[4:].decode('ascii', errors='ignore')
            if response_str.startswith('infoResponse') or response_str.startswith('statusResponse'):
                return True
        except:
            pass
        
        return False
    
    def _check_gamename_from_response(self, data: bytes) -> bool:
        """
        Check if response is from a Jedi Academy server.
        
        Validation criteria (at least one must match):
        1. gamename is one of: basejka, JAmp, japlus, lugormod, Movie Battles II
        2. version starts with "JAmp" (Jedi Academy Multiplayer)
        
        Args:
            data: Raw response data from getstatus query
            
        Returns:
            True if server is identified as Jedi Academy, False otherwise
        """
        try:
            if len(data) < 4 or data[:4] != b'\xFF\xFF\xFF\xFF':
                return False
            
            response_str = data[4:].decode('ascii', errors='ignore')
            if not response_str.startswith('statusResponse'):
                return False
            
            # Extract key-value pairs
            kv_start = response_str.find('\n')
            if kv_start == -1:
                return False
            
            kv_data = response_str[kv_start + 1:]
            server_data = self._parse_key_value_pairs(kv_data)
            
            # Check 1: Known gamename values for Jedi Academy
            gamename = server_data.get('gamename', '')
            known_gamenames = ('basejka', 'JAmp', 'japlus', 'lugormod', 'Movie Battles II')
            if gamename in known_gamenames:
                return True
            
            # Check 2: Version starts with "JAmp" (Jedi Academy Multiplayer)
            version = server_data.get('version', '')
            if version.startswith('JAmp'):
                self.logger.debug(f"Server identified by JAmp version: {version}")
                return True
            
            return False
            
        except Exception:
            return False
    
    def _parse_jediknight_status_response(self, data: bytes) -> Tuple[Optional[Dict[str, str]], List[Dict[str, Any]]]:
        """
        Parse Jedi Academy server getstatus response data.
        
        Args:
            data: Raw getstatus response data
            
        Returns:
            Tuple of (status_data dict, players list) or (None, []) if parsing failed
        """
        try:
            if len(data) < 4 or data[:4] != b'\xFF\xFF\xFF\xFF':
                return None, []
            
            response_str = data[4:].decode('ascii', errors='ignore')
            if not response_str.startswith('statusResponse'):
                return None, []
            
            # Extract key-value pairs and players
            kv_start = response_str.find('\n')
            if kv_start == -1:
                return None, []
            
            kv_data = response_str[kv_start + 1:]
            
            # Split by newline to separate server info from player info
            lines = kv_data.split('\n')
            
            # Parse server info from first line
            status_data = self._parse_key_value_pairs(lines[0]) if lines else {}
            
            # Parse players from remaining lines (format: score ping "name")
            players = []
            player_pattern = re.compile(r'^(-?\d+)\s+(-?\d+)\s+"([^"]*)"')
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                match = player_pattern.match(line)
                if match:
                    players.append({
                        'score': int(match.group(1)),
                        'ping': int(match.group(2)),
                        'name': match.group(3)
                    })
            
            return status_data, players
            
        except Exception as e:
            self.logger.debug(f"Error parsing Jedi Academy status response: {e}")
            return None, []
    
    def _parse_jediknight_info_response(self, data: bytes) -> Optional[Dict[str, str]]:
        """
        Parse Jedi Academy server getinfo response data.
        
        Args:
            data: Raw getinfo response data
            
        Returns:
            Dictionary containing parsed info data or None if parsing failed
        """
        try:
            if len(data) < 4 or data[:4] != b'\xFF\xFF\xFF\xFF':
                return None
            
            response_str = data[4:].decode('ascii', errors='ignore')
            if not response_str.startswith('infoResponse'):
                return None
            
            # Extract key-value pairs (after "infoResponse\n")
            kv_start = response_str.find('\n')
            if kv_start == -1:
                return None
            
            kv_data = response_str[kv_start + 1:]
            return self._parse_key_value_pairs(kv_data)
            
        except Exception as e:
            self.logger.debug(f"Error parsing Jedi Academy info response: {e}")
            return None
    
    async def _create_jediknight_server_response(self, combined_data: Dict[str, Any], sender_addr: Tuple[str, int]) -> Optional[ServerResponse]:
        """
        Create a ServerResponse object from combined Jedi Academy data.
        
        Args:
            combined_data: Combined data from getinfo and getstatus responses
            sender_addr: Sender address tuple (ip, port)
            
        Returns:
            ServerResponse object or None if creation failed
        """
        try:
            # Extract standard server information
            hostname = combined_data.get('hostname', combined_data.get('sv_hostname', 'Unknown Jedi Academy Server'))
            mapname = combined_data.get('mapname', 'Unknown')
            current_players = int(combined_data.get('clients', '0'))
            max_players = int(combined_data.get('sv_maxclients', '0'))
            players = combined_data.get('players', [])
            
            # Create ServerResponse
            return ServerResponse(
                ip_address=sender_addr[0],
                port=sender_addr[1],
                game_type='jediknight',
                server_info={
                    'hostname': hostname,
                    'map_name': mapname,
                    'current_players': current_players,
                    'max_players': max_players,
                    'additional_info': combined_data
                },
                response_time=0.0  # We don't measure response time in broadcast discovery
            )
            
        except Exception as e:
            self.logger.error(f"Error creating Jedi Academy server response for {sender_addr[0]}:{sender_addr[1]}: {e}")
            return None
    
    def _parse_key_value_pairs(self, data: str) -> Dict[str, str]:
        """
        Parse Jedi Academy key-value pairs from response data.
        Jedi Academy uses backslash (\) as delimiter between keys and values.
        
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

