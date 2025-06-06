"""
Network scanner for discovering game servers via broadcast queries
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import json

# Import opengsq protocols
from opengsq.protocols.source import Source
from opengsq.protocols.renegadex import RenegadeX
from opengsq.protocols.warcraft3 import Warcraft3
from opengsq.protocols.flatout2 import Flatout2
from opengsq.protocols.ut3 import UT3
from opengsq.protocol_base import ProtocolBase

# Import the server info wrapper
from .server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo


@dataclass
class ServerResponse:
    """Data class for server response information"""
    ip_address: str
    port: int
    game_type: str
    server_info: Dict[str, Any]
    response_time: float


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


class NetworkScanner:
    """
    Network scanner for discovering game servers via broadcast queries.
    Uses opengsq-python for protocol handling.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("GameServerNotifier.NetworkScanner")
        self.timeout = config.get('network', {}).get('timeout', 5.0)
        self.scan_ranges = config.get('network', {}).get('scan_ranges', [])
        self.enabled_games = config.get('games', {}).get('enabled', [])
        
        # Initialize the server info wrapper for standardization
        self.server_wrapper = ServerInfoWrapper()
        
        # Protocol configurations
        self.protocol_configs = {
            'source': {
                'port': 27015,
                'query_data': b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
            },
            'renegadex': {
                'port': 7777,  # Game server port
                'broadcast_port': 45542,  # Broadcast listening port
                'passive': True  # Uses passive listening instead of active queries
            },
            'warcraft3': {
                'port': 6112,  # Game server port
                'query_data': b'\xF7\x2F\x10\x00\x50\x58\x33\x57\x1A\x00\x00\x00\x00\x00\x00\x00'  # Search game packet
            },
            'flatout2': {
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
            },
            'ut3': {
                'port': 14001,  # UT3 LAN beacon port
                'broadcast': True,  # Uses broadcast discovery
                'game_id': 0x4D5707DB  # UT3-specific game ID
            }
        }
        
        self.logger.info(f"NetworkScanner initialized with {len(self.scan_ranges)} scan ranges")
        self.logger.info(f"Enabled games: {', '.join(self.enabled_games)}")
    
    async def scan_for_servers(self) -> List[ServerResponse]:
        """
        Perform broadcast scan for all enabled game types.
        
        Returns:
            List of ServerResponse objects for discovered servers
        """
        self.logger.info("Starting network scan for game servers")
        discovered_servers = []
        
        # Scan for each enabled game type
        for game_type in self.enabled_games:
            if game_type in self.protocol_configs:
                self.logger.debug(f"Scanning for {game_type} servers")
                servers = await self._scan_game_type(game_type)
                discovered_servers.extend(servers)
                self.logger.info(f"Found {len(servers)} {game_type} servers")
        
        self.logger.info(f"Network scan completed. Total servers found: {len(discovered_servers)}")
        return discovered_servers
    
    async def scan_for_standardized_servers(self) -> List[StandardizedServerInfo]:
        """
        Perform broadcast scan for all enabled game types and return standardized results.
        
        Returns:
            List of StandardizedServerInfo objects for discovered servers
        """
        # Get raw server responses
        raw_servers = await self.scan_for_servers()
        
        # Convert to standardized format
        standardized_servers = []
        for server_response in raw_servers:
            try:
                standardized_server = self.server_wrapper.standardize_server_response(server_response)
                standardized_servers.append(standardized_server)
                self.logger.debug(f"Standardized server: {standardized_server.name} ({standardized_server.game})")
            except Exception as e:
                self.logger.error(f"Failed to standardize server response from {server_response.ip_address}:{server_response.port}: {e}")
        
        self.logger.info(f"Standardized {len(standardized_servers)} servers")
        return standardized_servers
    
    async def _scan_game_type(self, game_type: str) -> List[ServerResponse]:
        """
        Scan for servers of a specific game type using broadcast.
        
        Args:
            game_type: The type of game to scan for (e.g., 'source')
            
        Returns:
            List of ServerResponse objects
        """
        if game_type not in self.protocol_configs:
            self.logger.warning(f"No protocol configuration found for game type: {game_type}")
            return []
        
        protocol_config = self.protocol_configs[game_type]
        servers = []
        
        try:
            if game_type == 'source':
                servers = await self._scan_source_servers(protocol_config)
            elif game_type == 'renegadex':
                servers = await self._scan_renegadex_servers(protocol_config)
            elif game_type == 'warcraft3':
                servers = await self._scan_warcraft3_servers(protocol_config)
            elif game_type == 'flatout2':
                servers = await self._scan_flatout2_servers(protocol_config)
            elif game_type == 'ut3':
                servers = await self._scan_ut3_servers(protocol_config)
        except Exception as e:
            self.logger.error(f"Error scanning for {game_type} servers: {e}")
        
        return servers
    
    async def _scan_source_servers(self, protocol_config: Dict[str, Any]) -> List[ServerResponse]:
        """
        Scan for Source engine servers using broadcast queries.
        
        Args:
            protocol_config: Configuration for the Source protocol
            
        Returns:
            List of ServerResponse objects for Source servers
        """
        servers = []
        port = protocol_config['port']
        
        # Create broadcast protocol instance
        broadcast_protocol = BroadcastProtocol('source', port, self.timeout)
        
        # For each network range, send broadcast queries
        for network_range in self.scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting Source query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect initial responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, protocol_config['query_data']
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
                from opengsq.binary_reader import BinaryReader
                
                # Create BinaryReader starting after the header
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
    
    async def _scan_renegadex_servers(self, protocol_config: Dict[str, Any]) -> List[ServerResponse]:
        """
        Scan for Renegade X servers using passive broadcast listening.
        
        Args:
            protocol_config: Configuration for the RenegadeX protocol
            
        Returns:
            List of ServerResponse objects for RenegadeX servers
        """
        servers = []
        broadcast_port = protocol_config['broadcast_port']
        
        self.logger.debug(f"Starting passive listening for RenegadeX broadcasts on port {broadcast_port}")
        
        try:
            # Create a queue to collect broadcast messages
            broadcast_queue = asyncio.Queue()
            
            # Create UDP socket for listening to broadcasts
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: RenegadeXBroadcastProtocol(broadcast_queue),
                local_addr=('0.0.0.0', broadcast_port),
                allow_broadcast=True
            )
            
            try:
                # Listen for broadcasts for the timeout period
                self.logger.debug(f"Listening for RenegadeX broadcasts for {self.timeout} seconds...")
                end_time = asyncio.get_event_loop().time() + self.timeout
                
                # Dictionary to collect data from each server
                server_data_buffers = {}
                server_fragment_counts = {}
                
                while asyncio.get_event_loop().time() < end_time:
                    try:
                        # Wait for broadcast messages
                        remaining_time = end_time - asyncio.get_event_loop().time()
                        if remaining_time <= 0:
                            break
                            
                        data, addr = await asyncio.wait_for(
                            broadcast_queue.get(), 
                            timeout=min(remaining_time, 1.0)
                        )
                        
                        # Collect data from this server
                        server_key = addr[0]  # Use IP as key
                        if server_key not in server_data_buffers:
                            server_data_buffers[server_key] = bytearray()
                            server_fragment_counts[server_key] = 0
                        
                        server_data_buffers[server_key].extend(data)
                        server_fragment_counts[server_key] += 1
                        
                        self.logger.debug(f"RenegadeX: Collected fragment {server_fragment_counts[server_key]} from {addr[0]} ({len(data)} bytes, total: {len(server_data_buffers[server_key])} bytes)")
                        
                        # Only try to parse if we have a potentially complete JSON message
                        # Check if the accumulated data looks like complete JSON (ends with '}')
                        complete_data = bytes(server_data_buffers[server_key])
                        if self._is_complete_renegadex_json(complete_data):
                            try:
                                server_info = await self._parse_renegadex_response(complete_data)
                                if server_info:
                                    # Successfully parsed - create server response
                                    server_response = ServerResponse(
                                        ip_address=addr[0],
                                        port=server_info.get('port', protocol_config['port']),
                                        game_type='renegadex',
                                        server_info=server_info,
                                        response_time=0.0
                                    )
                                    
                                    # Check if we already found this server
                                    if not any(s.ip_address == addr[0] for s in servers):
                                        servers.append(server_response)
                                        self.logger.debug(f"Discovered RenegadeX server: {addr[0]}:{server_info.get('port', protocol_config['port'])} (assembled from {server_fragment_counts[server_key]} fragments)")
                                    
                                    # Clear the buffer for this server
                                    server_data_buffers[server_key] = bytearray()
                                    server_fragment_counts[server_key] = 0
                            except Exception as e:
                                # Only log parsing errors if we think we have complete data
                                self.logger.debug(f"RenegadeX: Failed to parse seemingly complete JSON from {addr[0]}: {e}")
                        
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing RenegadeX broadcast: {e}")
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error listening for RenegadeX broadcasts: {e}")
        
        return servers
    
    def _is_complete_renegadex_json(self, data: bytes) -> bool:
        """
        Check if the accumulated RenegadeX data contains complete JSON.
        This method tries to extract valid JSON even if there are duplicates or extra data.
        
        Args:
            data: Accumulated broadcast data
            
        Returns:
            True if data contains complete JSON, False otherwise
        """
        try:
            # Convert to string and clean up
            json_str = data.decode('utf-8', errors='ignore').strip()
            
            if not json_str:
                return False
            
            # Try to find the first complete JSON object
            # Look for the first '{' and try to find its matching '}'
            start_idx = json_str.find('{')
            if start_idx == -1:
                return False
            
            # Count braces to find the end of the first complete JSON object
            brace_count = 0
            end_idx = -1
            
            for i in range(start_idx, len(json_str)):
                if json_str[i] == '{':
                    brace_count += 1
                elif json_str[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i
                        break
            
            if end_idx == -1:
                return False
            
            # Extract the potential JSON substring
            potential_json = json_str[start_idx:end_idx + 1]
            
            # Try to parse it to verify it's valid JSON
            try:
                import json
                json.loads(potential_json)
                return True
            except json.JSONDecodeError:
                return False
                
        except Exception as e:
            self.logger.debug(f"RenegadeX JSON validation error: {e}")
            return False
    
    async def _parse_renegadex_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a RenegadeX broadcast response.
        Extracts the first valid JSON object from the accumulated data.
        
        Args:
            response_data: Raw JSON broadcast data from RenegadeX server
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Convert to string and clean up
            json_str = response_data.decode('utf-8', errors='ignore').strip()
            
            # Find the first complete JSON object (same logic as validation)
            start_idx = json_str.find('{')
            if start_idx == -1:
                self.logger.debug(f"RenegadeX: No JSON start found in {len(json_str)} chars")
                return None
            
            # Count braces to find the end of the first complete JSON object
            brace_count = 0
            end_idx = -1
            
            for i in range(start_idx, len(json_str)):
                if json_str[i] == '{':
                    brace_count += 1
                elif json_str[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i
                        break
            
            if end_idx == -1:
                self.logger.debug(f"RenegadeX: No JSON end found, brace_count={brace_count}")
                return None
            
            # Extract and parse the JSON
            json_data = json_str[start_idx:end_idx + 1]
            self.logger.debug(f"RenegadeX: Extracted JSON ({len(json_data)} chars) from {len(json_str)} total chars")
            
            server_data = json.loads(json_data)
            
            # Use opengsq's RenegadeX protocol to parse the response
            from opengsq.responses.renegadex import Status
            status = Status.from_dict(server_data)
            
            return {
                'name': status.name,
                'map': status.map,
                'port': status.port,
                'players': status.players,
                'max_players': status.variables.player_limit,
                'game_version': status.game_version,
                'passworded': status.variables.passworded,
                'steam_required': status.variables.steam_required,
                'team_mode': status.variables.team_mode,
                'game_type': status.variables.game_type,
                'ranked': status.variables.ranked
            }
            
        except Exception as e:
            self.logger.debug(f"Failed to parse RenegadeX response ({len(response_data)} bytes): {e}")
            # Log first 200 chars of data for debugging
            preview = response_data[:200].decode('utf-8', errors='ignore')
            self.logger.debug(f"RenegadeX data preview: {repr(preview)}")
        
        return None

    async def _scan_warcraft3_servers(self, protocol_config: Dict[str, Any]) -> List[ServerResponse]:
        """
        Scan for Warcraft 3 servers using active broadcast queries.
        
        Args:
            protocol_config: Configuration for the Warcraft3 protocol
            
        Returns:
            List of ServerResponse objects for Warcraft3 servers
        """
        servers = []
        port = protocol_config['port']
        
        # For each network range, send broadcast queries
        for network_range in self.scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting Warcraft3 query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, protocol_config['query_data']
                )
                
                # Process responses
                for response_data, sender_addr in responses:
                    try:
                        server_info = await self._parse_warcraft3_response(response_data)
                        if server_info:
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=sender_addr[1],
                                game_type='warcraft3',
                                server_info=server_info,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered Warcraft3 server: {sender_addr[0]}:{sender_addr[1]}")
                    
                    except Exception as e:
                        self.logger.debug(f"Failed to parse Warcraft3 response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting Warcraft3 to network {network_range}: {e}")
        
        return servers
    
    async def _parse_warcraft3_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a Warcraft 3 server response.
        
        Args:
            response_data: Raw response data from Warcraft3 server
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Check if this is a valid Warcraft3 response
            if len(response_data) < 4:
                return None
            
            # Check for Warcraft3 protocol signature (0xF7)
            if response_data[0] != 0xF7:
                return None
            
            # Check for game info response (0x30)
            if response_data[1] != 0x30:
                return None
            
            # Use opengsq's Warcraft3 protocol to parse the response
            temp_warcraft3 = Warcraft3("127.0.0.1", 6112)  # Dummy values
            
            # Create a BinaryReader for parsing
            from opengsq.binary_reader import BinaryReader
            br = BinaryReader(response_data)
            
            # Skip protocol signature and packet type
            br.read_bytes(2)
            
            # Read packet size
            packet_size = int.from_bytes(br.read_bytes(2), 'little')
            
            # Read game version info
            product = br.read_bytes(4).decode('ascii', errors='ignore')
            version = int.from_bytes(br.read_bytes(4), 'little')
            host_counter = int.from_bytes(br.read_bytes(4), 'little')
            entry_key = int.from_bytes(br.read_bytes(4), 'little')
            
            # Read game name (null-terminated)
            game_name = ""
            while br.remaining_bytes() > 0:
                char = int.from_bytes(br.read_bytes(1), 'little')
                if char == 0:
                    break
                game_name += chr(char)
            
            # Skip unknown byte if available
            if br.remaining_bytes() > 0:
                br.read_bytes(1)
            
            # Read remaining fields if available
            slots_total = 0
            slots_used = 0
            if br.remaining_bytes() >= 12:
                # Skip settings string (find next null terminator)
                while br.remaining_bytes() > 0:
                    char = int.from_bytes(br.read_bytes(1), 'little')
                    if char == 0:
                        break
                
                if br.remaining_bytes() >= 12:
                    slots_total = int.from_bytes(br.read_bytes(4), 'little')
                    game_flags = int.from_bytes(br.read_bytes(4), 'little')
                    slots_used = int.from_bytes(br.read_bytes(4), 'little')
            
            return {
                'name': game_name or f"Warcraft3 Server",
                'map': "Unknown Map",
                'product': product,
                'version': version,
                'players': slots_used,
                'max_players': slots_total,
                'host_counter': host_counter,
                'entry_key': entry_key
            }
            
        except Exception as e:
            self.logger.debug(f"Failed to parse Warcraft3 response: {e}")
        
        return None

    async def _scan_flatout2_servers(self, protocol_config: Dict[str, Any]) -> List[ServerResponse]:
        """
        Scan for Flatout 2 servers using two-step discovery process:
        1. Broadcast to 255.255.255.255:23757 to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            protocol_config: Configuration for the Flatout2 protocol
            
        Returns:
            List of ServerResponse objects for Flatout2 servers
        """
        servers = []
        port = protocol_config['port']
        
        self.logger.debug("Starting Flatout 2 two-step discovery process")
        
        # Step 1: Broadcast discovery to find server IPs
        discovered_ips = set()
        
        try:
            self.logger.debug(f"Step 1: Broadcasting Flatout2 discovery to 255.255.255.255:{port}")
            
            # Send broadcast query using specific source port for Flatout 2
            responses = await self._send_flatout2_broadcast_query(
                "255.255.255.255", port, protocol_config['query_data']
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
                                'players': 0,  # Flatout2 doesn't provide player count in basic query
                                'max_players': 0,  # Would need additional parsing
                                'map': 'Unknown',  # Would need additional parsing
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
    
    async def _scan_ut3_servers(self, protocol_config: Dict[str, Any]) -> List[ServerResponse]:
        """
        Scan for Unreal Tournament 3 servers using UDK broadcast protocol.
        
        Args:
            protocol_config: Configuration for the UT3 protocol
            
        Returns:
            List of ServerResponse objects for UT3 servers
        """
        servers = []
        port = protocol_config['port']
        
        # For each network range, send broadcast queries
        for network_range in self.scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting UT3 query to {broadcast_addr}:{port}")
                
                                # Send broadcast query and collect responses
                responses, ut3_query = await self._send_ut3_broadcast_query(
                    broadcast_addr, port, protocol_config['game_id']
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


class BroadcastResponseProtocol(asyncio.DatagramProtocol):
    """Protocol for collecting broadcast responses"""
    
    def __init__(self, responses_list: List[Tuple[bytes, Tuple[str, int]]]):
        self.responses = responses_list
        self.logger = logging.getLogger("GameServerNotifier.BroadcastResponseProtocol")
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Called when a datagram is received"""
        self.logger.debug(f"Received response from {addr[0]}:{addr[1]} ({len(data)} bytes)")
        self.responses.append((data, addr))
    
    def error_received(self, exc: Exception) -> None:
        """Called when an error is received"""
        self.logger.debug(f"Error received: {exc}")


class RenegadeXBroadcastProtocol(asyncio.DatagramProtocol):
    """Protocol for collecting RenegadeX broadcast messages"""
    
    def __init__(self, broadcast_queue: asyncio.Queue):
        self.broadcast_queue = broadcast_queue
        self.logger = logging.getLogger("GameServerNotifier.RenegadeXBroadcastProtocol")
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Called when a RenegadeX broadcast is received"""
        self.logger.debug(f"Received RenegadeX broadcast from {addr[0]}:{addr[1]} ({len(data)} bytes)")
        self.broadcast_queue.put_nowait((data, addr))
    
    def error_received(self, exc: Exception) -> None:
        """Called when an error is received"""
        self.logger.debug(f"RenegadeX broadcast error: {exc}")


class DiscoveryEngine:
    """
    Discovery engine that coordinates network scanning and server discovery.
    Integrates with the main application loop for periodic scanning.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("GameServerNotifier.DiscoveryEngine")
        self.scanner = NetworkScanner(config)
        self.scan_interval = config.get('network', {}).get('scan_interval', 300)
        self.is_running = False
        self._scan_task = None
        
        # Callbacks for discovered/lost servers
        self.on_server_discovered = None
        self.on_server_lost = None
        
        self.logger.info(f"DiscoveryEngine initialized with {self.scan_interval}s scan interval")
    
    def set_callbacks(self, on_discovered=None, on_lost=None):
        """
        Set callback functions for server discovery events.
        
        Args:
            on_discovered: Callback function called when a new server is discovered
            on_lost: Callback function called when a server is no longer responding
        """
        self.on_server_discovered = on_discovered
        self.on_server_lost = on_lost
        self.logger.debug("Discovery callbacks configured")
    
    async def start(self):
        """Start the discovery engine with periodic scanning"""
        if self.is_running:
            self.logger.warning("DiscoveryEngine is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting DiscoveryEngine")
        
        try:
            # Start the periodic scanning task
            self.logger.debug("Creating periodic scan task...")
            self._scan_task = asyncio.create_task(self._periodic_scan_loop())
            self.logger.info("Periodic scan task created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create periodic scan task: {e}", exc_info=True)
            self.is_running = False
            raise
    
    async def stop(self):
        """Stop the discovery engine"""
        if not self.is_running:
            return
        
        self.logger.info("Stopping DiscoveryEngine")
        self.is_running = False
        
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("DiscoveryEngine stopped")
    
    async def scan_once(self) -> List[ServerResponse]:
        """
        Perform a single scan for servers.
        
        Returns:
            List of discovered servers
        """
        self.logger.info("Performing single network scan")
        return await self.scanner.scan_for_servers()
    
    async def scan_once_standardized(self) -> List[StandardizedServerInfo]:
        """
        Perform a single scan for servers and return standardized results.
        
        Returns:
            List of standardized discovered servers
        """
        self.logger.info("Performing single standardized network scan")
        return await self.scanner.scan_for_standardized_servers()
    
    async def _periodic_scan_loop(self):
        """Main loop for periodic server scanning"""
        self.logger.info("Starting periodic scan loop")
        
        while self.is_running:
            try:
                self.logger.info("Starting periodic network scan...")
                
                # Perform scan
                discovered_servers = await self.scanner.scan_for_servers()
                
                self.logger.info(f"Periodic scan completed. Found {len(discovered_servers)} servers")
                
                # Process discovered servers
                if discovered_servers and self.on_server_discovered:
                    for server in discovered_servers:
                        try:
                            await self.on_server_discovered(server)
                        except Exception as e:
                            self.logger.error(f"Error in server discovered callback: {e}")
                
                # Wait for next scan interval
                self.logger.info(f"Waiting {self.scan_interval} seconds until next scan...")
                await asyncio.sleep(self.scan_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic scan loop: {e}")
                # Wait a bit before retrying to avoid rapid error loops
                await asyncio.sleep(min(30, self.scan_interval))
        
        self.logger.info("Periodic scan loop ended") 