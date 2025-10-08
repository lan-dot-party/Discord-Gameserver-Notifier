"""
Trackmania Nations protocol implementation for game server discovery.
"""

import asyncio
import logging
import ipaddress
from typing import List

from opengsq.protocols.trackmania_nations import TrackmaniaNations
from .common import ServerResponse
from ..protocol_base import ProtocolBase


class TrackmaniaNationsProtocol(ProtocolBase):
    """Trackmania Nations protocol handler for network discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__('', 0, timeout)  # Initialize base class
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 2350,  # Trackmania Nations default port
            'packet_1': bytes.fromhex("0e000000820399f895580700000008000000"),
            'packet_2': bytes.fromhex("1200000082033bd464400700000007000000d53d4100")
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Trackmania Nations servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add environment
        if 'environment' in server_info and server_info['environment']:
            fields.append({
                'name': '🏟️ Environment',
                'value': server_info['environment'],
                'inline': True
            })
            
        # Add game mode
        if 'game_mode' in server_info and server_info['game_mode']:
            fields.append({
                'name': '🎮 Spielmodus',
                'value': server_info['game_mode'],
                'inline': True
            })
            
        # Add server type (private/ladder/etc)
        server_type = "Unknown"
        if server_info.get('private_server'):
            server_type = "Private"
        elif server_info.get('ladder_server'):
            server_type = "Ladder"
        elif server_info.get('password_protected'):
            server_type = "Password Protected"
        else:
            server_type = "Public"
            
        fields.append({
            'name': '🔐 Server-Typ',
            'value': server_type,
            'inline': True
        })
        
        # Add PC GUID if available
        if 'pc_guid' in server_info and server_info['pc_guid']:
            fields.append({
                'name': '💻 PC-UID',
                'value': server_info['pc_guid'],
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Trackmania Nations servers using two-step discovery process:
        1. Scan network ranges with TCP probes to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Trackmania Nations servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.debug("Starting Trackmania Nations two-step discovery process")
        
        # Step 1: Network scanning to find server IPs
        discovered_ips = set()
        
        try:
            self.logger.debug("Step 1: Scanning network ranges for Trackmania Nations servers on port %d", port)
            
            # For Trackmania Nations, we need to scan IP ranges since it's TCP-based
            for scan_range in scan_ranges:
                discovered_ips.update(await self._scan_range_for_trackmania(scan_range, port))
            
            self.logger.info("Step 1 complete: Found %d potential Trackmania Nations server IPs", len(discovered_ips))
            
        except Exception as e:
            self.logger.error("Error in Trackmania Nations discovery: %s", e)
            return servers
        
        # Step 2: Query each discovered IP individually for detailed information
        if discovered_ips:
            self.logger.debug("Step 2: Querying %d discovered IPs individually", len(discovered_ips))
            
            for ip_address in discovered_ips:
                try:
                    # Small delay between queries to avoid overwhelming servers
                    await asyncio.sleep(0.1)
                    
                    self.logger.debug("Querying Trackmania Nations server at %s:%d", ip_address, port)
                    
                    # Create Trackmania Nations protocol instance for direct query
                    trackmania_query = TrackmaniaNations(ip_address, port, self.timeout)
                    
                    try:
                        # Query the server directly for full info
                        server_info = await trackmania_query.get_info()
                        
                        if server_info:
                            # Convert ServerInfo object to dictionary
                            info_dict = {
                                'hostname': server_info.name or 'Unknown Server',
                                'map': server_info.map or 'Unknown',
                                'players': server_info.players or 0,
                                'max_players': server_info.max_players or 0,
                                'game_mode': server_info.game_mode or 'Unknown',
                                'environment': server_info.environment or 'Stadium',
                                'password_protected': server_info.password_protected or False,
                                'private_server': server_info.private_server or False,
                                'ladder_server': server_info.ladder_server or False,
                                'pc_guid': server_info.pc_guid,
                                'comment': server_info.comment,
                                'version': server_info.version,
                                'game': 'Trackmania Nations'
                            }
                            
                            server_response = ServerResponse(
                                ip_address=ip_address,
                                port=port,
                                game_type='trackmania_nations',
                                server_info=info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            
                            self.logger.debug("Successfully queried Trackmania Nations server: %s:%d", ip_address, port)
                            self.logger.debug("Server details: Name='%s', Map='%s', Mode='%s'", info_dict['hostname'], info_dict['map'], info_dict['game_mode'])
                    
                    except Exception as e:
                        self.logger.debug("Failed to query Trackmania Nations server at %s:%d: %s", ip_address, port, e)
                        
                except Exception as e:
                    self.logger.debug("Error processing Trackmania Nations server %s: %s", ip_address, e)
        
        self.logger.info("Trackmania Nations discovery complete: Found %d servers with detailed info", len(servers))
        return servers
    
    async def _scan_range_for_trackmania(self, scan_range: str, port: int) -> set:
        """
        Scan a network range for Trackmania Nations servers using TCP probes.
        This implements the "broadcast" phase for TCP-based discovery.
        
        Args:
            scan_range: Network range to scan (e.g., "192.168.1.0/24" or "10.253.250.0/24")
            port: Port to scan on (default: 2350)
            
        Returns:
            Set of IP addresses that responded to Trackmania Nations probes
        """
        discovered_ips = set()
        
        try:
            network = ipaddress.ip_network(scan_range, strict=False)
            
            # Create tasks for concurrent scanning with proper IP tracking
            all_hosts = list(network.hosts())
            batch_size = 50  # Increased concurrent connections for faster scanning
            
            self.logger.debug("Scanning %d hosts in range %s for Trackmania Nations servers", len(all_hosts), scan_range)
            
            for i in range(0, len(all_hosts), batch_size):
                batch_hosts = all_hosts[i:i + batch_size]
                
                # Create all tasks for this batch
                batch_tasks = [
                    self._test_trackmania_connection(str(host), port) 
                    for host in batch_hosts
                ]
                
                # Execute all tasks in parallel and get results
                results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process results
                for j, result in enumerate(results):
                    if result is True:
                        host_ip = str(batch_hosts[j])
                        discovered_ips.add(host_ip)
                        self.logger.info("Found Trackmania Nations server at %s:%d", host_ip, port)
                    elif isinstance(result, Exception):
                        host_ip = str(batch_hosts[j])
                        self.logger.debug("Failed to test %s:%d: %s", host_ip, port, result)
                
                # Progress indicator for large scans
                if len(all_hosts) > 50:
                    progress = min(100, int((i + batch_size) * 100 / len(all_hosts)))
                    self.logger.debug("Scan progress: %d%% (%d/%d hosts)", progress, min(i + batch_size, len(all_hosts)), len(all_hosts))
                
                # Small delay between batches to avoid overwhelming the network
                if i + batch_size < len(all_hosts):
                    await asyncio.sleep(0.02)
            
            self.logger.debug("Completed scanning range %s, found %d servers", scan_range, len(discovered_ips))
            
        except Exception as e:
            self.logger.error("Error scanning range %s: %s", scan_range, e)
        
        return discovered_ips
    
    async def _test_trackmania_connection(self, ip: str, port: int) -> bool:
        """
        Test if a Trackmania Nations server is running at the given IP:port.
        This sends the Trackmania Nations discovery packets to verify it's a real server.
        
        Args:
            ip: IP address to test
            port: Port to test
            
        Returns:
            True if server responds with valid Trackmania Nations data, False otherwise
        """
        try:
            # Try to establish a TCP connection with very short timeout for discovery phase
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 
                timeout=0.8  # Very quick timeout for discovery phase
            )
            
            try:
                # Send the first packet to test if it's a Trackmania server
                writer.write(self.protocol_config['packet_1'])
                await writer.drain()
                
                # Wait for server processing (Trackmania Nations needs this delay)
                await asyncio.sleep(0.2)
                
                # Send second packet
                writer.write(self.protocol_config['packet_2'])
                await writer.drain()
                
                # Try to read response with short timeout
                response_data = await asyncio.wait_for(
                    reader.read(4096),  # Sufficient buffer size
                    timeout=0.5  # Quick timeout for response
                )
                
                # Check if response contains Trackmania marker
                if b'#SRV#' in response_data:
                    self.logger.debug("Trackmania Nations server confirmed at %s:%d (response: %d bytes)", ip, port, len(response_data))
                    return True
                else:
                    self.logger.debug("Invalid response from %s:%d (no #SRV# marker found)", ip, port)
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
            # Connection failed or timeout - not a Trackmania server (this is normal for most IPs)
            pass
        except Exception as e:
            self.logger.debug("Unexpected error testing %s:%d: %s", ip, port, e)
        
        return False
