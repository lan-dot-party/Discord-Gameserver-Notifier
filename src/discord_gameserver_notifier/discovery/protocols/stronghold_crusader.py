"""
Stronghold Crusader DirectPlay protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.stronghold_crusader import StrongholdCrusader
from ..protocol_base import ProtocolBase
from .common import ServerResponse


class StrongholdCrusaderProtocol(ProtocolBase):
    """Stronghold Crusader DirectPlay protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        # Stronghold Crusader uses DirectPlay UDP port - get from opengsq-python constants
        from opengsq.protocols.directplay import DirectPlay
        from opengsq.protocols.stronghold_crusader import StrongholdCrusader as OpenGSQStrongholdCrusader
        
        # Broadcast address will be calculated dynamically per network range in scan_servers()
        super().__init__("0.0.0.0", DirectPlay.DIRECTPLAY_UDP_PORT, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Use constants from opengsq-python instead of hardcoding
        self.protocol_config = {
            'port': DirectPlay.DIRECTPLAY_UDP_PORT,  # 47624 - DirectPlay UDP port
            'tcp_port': OpenGSQStrongholdCrusader.STRONGHOLD_CRUSADER_TCP_PORT,  # 2301 - Stronghold specific!
            'query_data': OpenGSQStrongholdCrusader.STRONGHOLD_CRUSADER_UDP_PAYLOAD  # Use payload from opengsq-python
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Stronghold Crusader servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game version
        if 'game_version' in server_info and server_info['game_version']:
            fields.append({
                'name': '📦 Spiel Version',
                'value': server_info['game_version'],
                'inline': True
            })
        
        # Add game type info
        if 'game_type' in server_info and server_info['game_type']:
            fields.append({
                'name': '🎮 Spieltyp',
                'value': server_info['game_type'],
                'inline': True
            })
        
        # Add DirectPlay specific info with Stronghold TCP port
        tcp_port = self.protocol_config.get('tcp_port', 2301)
        fields.append({
            'name': '🔧 Protokoll',
            'value': f'DirectPlay (TCP {tcp_port})',
            'inline': True
        })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Stronghold Crusader servers using DirectPlay protocol.
        
        DirectPlay works by:
        1. Opening a TCP server on port 2301 (Stronghold Crusader specific!) to receive responses
        2. Sending UDP broadcast queries to port 47624
        3. Servers respond via TCP to our listening port
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for Stronghold Crusader servers
        """
        servers = []
        udp_port = self.protocol_config['port']  # 47624
        tcp_port = self.protocol_config['tcp_port']  # 2301
        
        self.logger.info("🏰 Starting Stronghold Crusader DirectPlay server discovery...")
        
        # For each network range, perform DirectPlay discovery
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.info(f"📡 DirectPlay discovery for Stronghold Crusader: {broadcast_addr}:{udp_port}")
                self.logger.debug(f"DirectPlay payload: {self.protocol_config['query_data'].hex()}")
                
                # Perform DirectPlay discovery (TCP server + UDP broadcast)
                discovered_servers = await self._directplay_discovery(
                    broadcast_addr, udp_port, tcp_port, self.protocol_config['query_data']
                )
                
                self.logger.info(f"🔍 DirectPlay found {len(discovered_servers)} potential Stronghold Crusader servers")
                
                # Query each discovered server for detailed information
                for server_ip, server_port in discovered_servers:
                    try:
                        # Use opengsq-python library to get complete server info
                        server_info_dict = await self._query_stronghold_server_via_opengsq(
                            server_ip, server_port
                        )
                        
                        if server_info_dict:
                            server_response = ServerResponse(
                                ip_address=server_ip,
                                port=server_port,
                                game_type='stronghold_crusader',
                                server_info=server_info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.info(f"✅ Stronghold Crusader server discovered: {server_ip}:{server_port}")
                            self.logger.info(f"   Name: {server_info_dict.get('name', 'Unknown')}")
                            self.logger.info(f"   Players: {server_info_dict.get('players', 0)}/{server_info_dict.get('max_players', 0)}")
                        else:
                            self.logger.debug(f"❌ Could not get details for Stronghold Crusader server {server_ip}:{server_port}")
                        
                    except Exception as e:
                        self.logger.debug(f"❌ Failed to query Stronghold Crusader server {server_ip}:{server_port}: {e}")
                        
            except Exception as e:
                self.logger.error(f"❌ Error in DirectPlay discovery for {network_range}: {e}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
        
        self.logger.info(f"🎯 Stronghold Crusader DirectPlay discovery completed: {len(servers)} servers found")
        return servers
    
    async def _directplay_discovery(self, broadcast_addr: str, udp_port: int, tcp_port: int, query_data: bytes) -> List[Tuple[str, int]]:
        """
        Perform DirectPlay discovery by opening TCP server and sending UDP broadcast.
        
        Args:
            broadcast_addr: Broadcast address to send UDP query to
            udp_port: UDP port to send query to (47624)
            tcp_port: TCP port to listen on (2301 for Stronghold Crusader!)
            query_data: DirectPlay query payload
            
        Returns:
            List of tuples containing (server_ip, server_port) for discovered servers
        """
        discovered_servers = []
        tcp_responses = []
        
        # TCP Protocol to collect DirectPlay responses
        class DirectPlayTcpProtocol(asyncio.Protocol):
            def __init__(self):
                self.transport = None
                self.received_data = b''
                self.logger = logging.getLogger(f"{__name__}.DirectPlayTcp")
                
            def connection_made(self, transport):
                self.transport = transport
                peer = transport.get_extra_info('peername')
                self.logger.info(f"🔗 DirectPlay TCP connection from {peer}")
                
            def data_received(self, data):
                self.received_data += data
                peer = self.transport.get_extra_info('peername')
                self.logger.info(f"📨 Received {len(data)} bytes from {peer}")
                self.logger.debug(f"Data preview: {data[:50].hex()}...")
                
                # Store the response with sender info
                tcp_responses.append((self.received_data, peer))
                
                # Close connection after receiving data
                if self.transport:
                    self.transport.close()
                
            def connection_lost(self, exc):
                if exc:
                    self.logger.debug(f"DirectPlay TCP connection lost: {exc}")
        
        try:
            loop = asyncio.get_running_loop()
            
            # Start TCP server on port 2301 for Stronghold Crusader (or next available port)
            tcp_server = None
            actual_tcp_port = tcp_port
            for port_offset in range(10):  # Try ports tcp_port through tcp_port+9
                try:
                    actual_tcp_port = tcp_port + port_offset
                    tcp_server = await loop.create_server(
                        DirectPlayTcpProtocol,
                        '0.0.0.0',
                        actual_tcp_port
                    )
                    break
                except OSError as e:
                    if port_offset == 9:  # Last attempt
                        raise Exception(f"Could not bind TCP server to ports {tcp_port}-{tcp_port+9}: {e}")
                    continue
            
            self.logger.info(f"🌐 DirectPlay TCP server listening on port {actual_tcp_port}")
            
            # Start serving
            await tcp_server.start_serving()
            await asyncio.sleep(0.1)  # Give server time to start
            
            # Send UDP broadcast query
            self.logger.info(f"📡 Sending DirectPlay UDP broadcast to {broadcast_addr}:{udp_port}")
            await self._send_udp_broadcast(broadcast_addr, udp_port, query_data)
            
            # Wait for TCP responses
            self.logger.info(f"⏳ Waiting {self.timeout} seconds for DirectPlay TCP responses...")
            await asyncio.sleep(self.timeout)
            
            # Process collected TCP responses
            self.logger.info(f"📊 Collected {len(tcp_responses)} DirectPlay TCP responses")
            
            for response_data, sender_info in tcp_responses:
                try:
                    # Extract server IP from TCP connection
                    server_ip = sender_info[0] if sender_info else None
                    
                    if server_ip:
                        # For DirectPlay, the server port is typically 47624 (UDP)
                        server_port = 47624
                        discovered_servers.append((server_ip, server_port))
                        self.logger.info(f"🎯 Discovered DirectPlay server at {server_ip}:{server_port}")
                    
                except Exception as e:
                    self.logger.debug(f"Error processing DirectPlay response: {e}")
            
        except Exception as e:
            self.logger.error(f"Error in DirectPlay discovery: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            # Clean up TCP server
            if tcp_server:
                tcp_server.close()
                await tcp_server.wait_closed()
                self.logger.debug("DirectPlay TCP server closed")
        
        return discovered_servers
    
    async def _send_udp_broadcast(self, broadcast_addr: str, port: int, query_data: bytes):
        """
        Send UDP broadcast query for DirectPlay discovery.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: UDP port to send to
            query_data: DirectPlay query payload
        """
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                local_addr=('0.0.0.0', 0),
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query
                self.logger.info(f"📤 Sending {len(query_data)} bytes DirectPlay query to {broadcast_addr}:{port}")
                transport.sendto(query_data, (broadcast_addr, port))
                
                # Brief pause to ensure packet is sent
                await asyncio.sleep(0.05)
                self.logger.debug("DirectPlay UDP broadcast sent successfully")
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending DirectPlay UDP broadcast: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
    
    async def _query_stronghold_server_via_opengsq(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Query a Stronghold Crusader server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            
        Returns:
            Dictionary containing complete server information with all fields needed for Discord
        """
        try:
            self.logger.debug(f"Querying Stronghold Crusader server {host}:{port} via opengsq-python...")
            
            # Create Stronghold Crusader protocol instance
            stronghold_client = StrongholdCrusader(host, port, self.timeout)
            
            # Get server info using opengsq-python
            server_info = await stronghold_client.get_status()
            
            # Convert Status object to dictionary format
            # server_info is a Status object, not a dict, so we access attributes directly
            info_dict = {
                'name': getattr(server_info, 'name', f'Stronghold Crusader Server {host}:{port}'),
                'map': getattr(server_info, 'map', 'Unknown Map'),
                'game': 'Stronghold Crusader',
                'players': getattr(server_info, 'num_players', 0),
                'max_players': getattr(server_info, 'max_players', 8),
                'game_version': getattr(server_info, 'game_version', '1.41'),
                'game_type': getattr(server_info, 'game_type', 'Stronghold Crusader'),
                'raw': getattr(server_info, 'raw', {})
            }
            
            self.logger.debug(f"✅ opengsq-python returned Stronghold Crusader server info for {host}:{port}")
            self.logger.debug(f"   Game version: {info_dict.get('game_version')}")
            self.logger.debug(f"   Map: {info_dict.get('map')}")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"❌ Error querying Stronghold Crusader server {host}:{port} via opengsq-python: {e}")
            return None

