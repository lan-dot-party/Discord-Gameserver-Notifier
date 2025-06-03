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
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'opengsq-python'))

from opengsq.protocols.source import Source
from opengsq.protocols.renegadex import RenegadeX
from opengsq.protocol_base import ProtocolBase


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
                
                # Send broadcast query and collect responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, protocol_config['query_data']
                )
                
                # Process responses
                for response_data, sender_addr in responses:
                    try:
                        server_info = await self._parse_source_response(response_data)
                        if server_info:
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=sender_addr[1],
                                game_type='source',
                                server_info=server_info,
                                response_time=0.0  # Will be calculated in actual implementation
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered Source server: {sender_addr[0]}:{sender_addr[1]}")
                    
                    except Exception as e:
                        self.logger.debug(f"Failed to parse response from {sender_addr}: {e}")
                        
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
                        
                        server_data_buffers[server_key].extend(data)
                        
                        # Try to parse the accumulated data
                        try:
                            complete_data = bytes(server_data_buffers[server_key])
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
                                    self.logger.debug(f"Discovered RenegadeX server: {addr[0]}:{server_info.get('port', protocol_config['port'])}")
                                
                                # Clear the buffer for this server
                                server_data_buffers[server_key] = bytearray()
                        except:
                            # Not complete yet, continue collecting
                            pass
                        
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing RenegadeX broadcast: {e}")
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error listening for RenegadeX broadcasts: {e}")
        
        return servers
    
    async def _parse_renegadex_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a RenegadeX broadcast response.
        
        Args:
            response_data: Raw JSON broadcast data from RenegadeX server
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # RenegadeX sends JSON data
            json_str = response_data.decode('utf-8')
            server_data = json.loads(json_str)
            
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
            self.logger.debug(f"Failed to parse RenegadeX response: {e}")
        
        return None


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