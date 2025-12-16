"""
Network scanner for discovering game servers via broadcast queries
"""

import asyncio
import logging
from typing import List, Dict, Any

# Import the server info wrapper
from .server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo

# Import protocol implementations
from .protocols import (
    ServerResponse,
    SourceProtocol,
    RenegadeXProtocol,
    Flatout2Protocol,
    UT3Protocol,
    Warcraft3Protocol,
    ToxikkProtocol,
    TrackmaniaNationsProtocol,
    AoE1Protocol,
    AoE2Protocol,
    AVP2Protocol,
    Battlefield2Protocol,
    CoD4Protocol,
    CoD5Protocol,
    CoD1Protocol,
    JediKnightProtocol,
    ElDewritoProtocol,
    CnCGeneralsProtocol,
    Fear2Protocol,
    Halo1Protocol,
    Quake3Protocol,
    SSCTFEProtocol,
    SSCTSEProtocol,
    StrongholdCrusaderProtocol,
    StrongholdCEProtocol
)


class NetworkScanner:
    """
    Network scanner for discovering game servers via broadcast queries.
    Uses protocol implementations from the protocols module.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("GameServerNotifier.NetworkScanner")
        self.timeout = config.get('network', {}).get('timeout', 5.0)
        self.scan_ranges = config.get('network', {}).get('scan_ranges', [])
        self.enabled_games = config.get('games', {}).get('enabled', [])
        
        # Initialize protocol instances first
        self.protocols = {
            'source': SourceProtocol(self.timeout),
            'renegadex': RenegadeXProtocol(self.timeout),
            'flatout2': Flatout2Protocol(self.timeout),
            'ut3': UT3Protocol(self.timeout),
            'warcraft3': Warcraft3Protocol(timeout=self.timeout),
            'toxikk': ToxikkProtocol(self.timeout),
            'trackmania_nations': TrackmaniaNationsProtocol(self.timeout),
            'aoe1': AoE1Protocol(self.timeout),
            'aoe2': AoE2Protocol(self.timeout),
            'avp2': AVP2Protocol(self.timeout),
            'battlefield2': Battlefield2Protocol(self.timeout),
            'cod4': CoD4Protocol(self.timeout),
            'cod5': CoD5Protocol(self.timeout),
            'cod1': CoD1Protocol(self.timeout),
            'jediknight': JediKnightProtocol(self.timeout),
            'eldewrito': ElDewritoProtocol(self.timeout),
            'cnc_generals': CnCGeneralsProtocol(timeout=11.0),  # CnC Generals requires 11 seconds to detect 2 broadcasts
            'fear2': Fear2Protocol(self.timeout),
            'halo1': Halo1Protocol(self.timeout),
            'quake3': Quake3Protocol(self.timeout),
            'ssc_tfe': SSCTFEProtocol(self.timeout),  # Serious Sam Classic: The First Encounter
            'ssc_tse': SSCTSEProtocol(self.timeout),   # Serious Sam Classic: The Second Encounter
            'stronghold_crusader': StrongholdCrusaderProtocol(self.timeout),  # Stronghold Crusader
            'stronghold_ce': StrongholdCEProtocol(self.timeout)  # Stronghold Crusader Extreme
        }
        
        # Initialize the server info wrapper for standardization with protocols
        self.server_wrapper = ServerInfoWrapper(protocols=self.protocols)
        
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
            if game_type in self.protocols:
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
        if game_type not in self.protocols:
            self.logger.warning(f"No protocol implementation found for game type: {game_type}")
            return []
        
        protocol = self.protocols[game_type]
        servers = []
        
        try:
            servers = await protocol.scan_servers(self.scan_ranges)
        except Exception as e:
            self.logger.error(f"Error scanning for {game_type} servers: {e}")
        
        return servers


class DiscoveryEngine:
    """
    Main discovery engine that orchestrates periodic scanning and server tracking.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("GameServerNotifier.DiscoveryEngine")
        self.scanner = NetworkScanner(config)
        
        # Tracking state
        self.known_servers = {}  # ip:port -> ServerResponse
        self.is_running = False
        self.scan_task = None
        
        # Callbacks
        self.on_discovered = None
        self.on_lost = None
        self.on_scan_complete = None
        
        # Scan interval
        self.scan_interval = config.get('network', {}).get('scan_interval', 30.0)
    
    def set_callbacks(self, on_discovered=None, on_lost=None, on_scan_complete=None):
        """
        Set callback functions for server discovery events.
        
        Args:
            on_discovered: Called when a new server is discovered
            on_lost: Called when a previously known server is no longer responding
            on_scan_complete: Called when a scan cycle completes
        """
        self.on_discovered = on_discovered
        self.on_lost = on_lost
        self.on_scan_complete = on_scan_complete
    
    async def start(self):
        """Start the discovery engine with periodic scanning."""
        if self.is_running:
            self.logger.warning("Discovery engine is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting discovery engine")
        
        # Start the periodic scan loop (which will do an immediate initial scan)
        self.scan_task = asyncio.create_task(self._periodic_scan_loop())
    
    async def stop(self):
        """Stop the discovery engine."""
        if not self.is_running:
            return
        
        self.is_running = False
        self.logger.info("Stopping discovery engine")
        
        if self.scan_task:
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass
            self.scan_task = None
    
    async def scan_once(self) -> List[ServerResponse]:
        """
        Perform a single scan cycle.
        
        Returns:
            List of discovered servers
        """
        return await self.scanner.scan_for_servers()
    
    async def scan_once_standardized(self) -> List[StandardizedServerInfo]:
        """
        Perform a single scan cycle and return standardized results.
        
        Returns:
            List of standardized server info
        """
        return await self.scanner.scan_for_standardized_servers()
    
    async def _periodic_scan_loop(self):
        """Main periodic scanning loop."""
        first_run = True
        
        while self.is_running:
            try:
                # Skip sleep on first run for immediate initial scan
                if not first_run:
                    await asyncio.sleep(self.scan_interval)
                    
                    if not self.is_running:  # Check if we should stop after sleep
                        break
                
                first_run = False
                
                # Track all servers found in this scan cycle
                current_server_keys = set()
                all_current_servers = []
                
                # Scan each game type individually and process discoveries immediately
                for game_type in self.scanner.enabled_games:
                    if not self.is_running:  # Check if we should stop
                        break
                        
                    if game_type in self.scanner.protocols:
                        self.logger.debug(f"Scanning for {game_type} servers")
                        
                        # Scan this specific game type
                        try:
                            game_servers = await self.scanner._scan_game_type(game_type)
                            all_current_servers.extend(game_servers)
                            
                            # Process each discovered server immediately
                            for server in game_servers:
                                server_key = f"{server.ip_address}:{server.port}"
                                current_server_keys.add(server_key)
                                
                                is_new_server = server_key not in self.known_servers
                                
                                # Update or add server to known_servers
                                self.known_servers[server_key] = server
                                
                                if is_new_server:
                                    # New server discovered - send notification immediately
                                    self.logger.info(f"Found new {game_type} server: {server.ip_address}:{server.port}")
                                else:
                                    # Existing server still responding - update last_seen
                                    self.logger.debug(f"Server still active: {server.ip_address}:{server.port}")
                                
                                # Always call on_discovered callback to update last_seen in database
                                if self.on_discovered:
                                    try:
                                        await self.on_discovered(server)
                                    except Exception as e:
                                        self.logger.error(f"Error in on_discovered callback: {e}")
                            
                            if game_servers:
                                self.logger.info(f"Found {len(game_servers)} {game_type} servers")
                        
                        except Exception as e:
                            self.logger.error(f"Error scanning for {game_type} servers: {e}")
                
                # Check for lost servers after all games have been scanned
                lost_servers = []
                for server_key in list(self.known_servers.keys()):
                    if server_key not in current_server_keys:
                        lost_server = self.known_servers.pop(server_key)
                        lost_servers.append(lost_server)
                        if self.on_lost:
                            try:
                                await self.on_lost(lost_server)
                            except Exception as e:
                                self.logger.error(f"Error in on_lost callback: {e}")
                
                # Call scan complete callback
                if self.on_scan_complete:
                    try:
                        await self.on_scan_complete(all_current_servers, lost_servers)
                    except Exception as e:
                        self.logger.error(f"Error in on_scan_complete callback: {e}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic scan loop: {e}")
                await asyncio.sleep(5.0)  # Brief pause before retrying 