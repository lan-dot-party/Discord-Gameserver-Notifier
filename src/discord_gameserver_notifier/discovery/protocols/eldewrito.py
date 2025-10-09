"""
ElDewrito protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.eldewrito import ElDewrito
from .common import ServerResponse, BroadcastResponseProtocol
from ..protocol_base import ProtocolBase


class ElDewritoProtocol(ProtocolBase):
    """ElDewrito protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("255.255.255.255", 11774, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 11774,  # ElDewrito broadcast port
            'http_port': 11775,  # ElDewrito HTTP port
            'query_data': bytes([
                0x01, 0x62, 0x6c, 0x61, 0x6d, 0x00, 0x00, 0x00, 
                0x09, 0x81, 0x00, 0x02, 0x00, 0x01, 0x2d, 0xc3, 
                0x04, 0x93, 0xdc, 0x05, 0xd9, 0x95, 0x40
            ])
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for ElDewrito servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add server status
        if 'status' in server_info:
            status_text = server_info['status']
            if status_text == 'InLobby':
                status_text = '🏠 In Lobby'
            elif status_text == 'InGame':
                status_text = '🎮 Im Spiel'
            elif status_text == 'EndGame':
                status_text = '🏁 Spiel beendet'
            
            fields.append({
                'name': '📊 Status',
                'value': status_text,
                'inline': True
            })
        
        # Add dedicated server info
        if 'is_dedicated' in server_info:
            dedicated_text = "✅ Dedicated Server" if server_info['is_dedicated'] else "❌ Listen Server"
            fields.append({
                'name': '🖥️ Server Typ',
                'value': dedicated_text,
                'inline': True
            })
        
        # Add team mode
        if 'teams' in server_info:
            team_text = "✅ Teams aktiviert" if server_info['teams'] else "❌ Kein Team-Modus"
            fields.append({
                'name': '👥 Team-Modus',
                'value': team_text,
                'inline': True
            })
        
        # Add host player
        if 'host_player' in server_info and server_info['host_player']:
            fields.append({
                'name': '👤 Host',
                'value': server_info['host_player'],
                'inline': True
            })
        
        # Add variant info
        if 'variant' in server_info and server_info['variant'] != 'none':
            fields.append({
                'name': '🎯 Variant',
                'value': server_info['variant'],
                'inline': True
            })
        
        # Add mod info if available
        if 'mod_count' in server_info and server_info['mod_count'] > 0:
            mod_text = f"{server_info['mod_count']} Mod(s)"
            if 'mod_package_name' in server_info and server_info['mod_package_name']:
                mod_text += f" - {server_info['mod_package_name']}"
            fields.append({
                'name': '🔧 Mods',
                'value': mod_text,
                'inline': True
            })
        
        # Add game settings
        settings = []
        if 'sprint_state' in server_info:
            if server_info['sprint_state'] == '2':
                settings.append('Sprint: Normal')
            elif server_info['sprint_state'] == '1':
                settings.append('Sprint: Aktiviert')
            else:
                settings.append('Sprint: Deaktiviert')
        
        if 'dual_wielding' in server_info and server_info['dual_wielding'] == '1':
            settings.append('Dual Wielding')
        
        if 'assassination_enabled' in server_info and server_info['assassination_enabled'] == '1':
            settings.append('Assassinations')
        
        if settings:
            fields.append({
                'name': '⚙️ Einstellungen',
                'value': ', '.join(settings),
                'inline': False
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Discover ElDewrito servers using two-step discovery process:
        1. Broadcast to all networks to discover server IPs
        2. Query each discovered IP individually for detailed information
        
        Args:
            scan_ranges: List of network ranges to scan (e.g., ["192.168.1.0/24"])
            
        Returns:
            List of ServerResponse objects for discovered servers
        """
        servers = []
        port = self.protocol_config['port']
        
        self.logger.info(f"Starting ElDewrito two-step discovery process on port {port}")
        
        # Step 1: Broadcast discovery to find server IPs
        discovered_ips = set()
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Step 1: Broadcasting ElDewrito query to {broadcast_addr}:{port}")
                
                # Send broadcast query and collect responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, port, self.protocol_config['query_data']
                )
                
                # Collect unique IP addresses from responses
                self.logger.debug(f"Processing {len(responses)} ElDewrito broadcast responses")
                for response_data, sender_addr in responses:
                    try:
                        # Validate response (must be > 120 bytes)
                        if len(response_data) > 120:
                            discovered_ips.add(sender_addr[0])
                            self.logger.debug(f"Discovered ElDewrito server IP: {sender_addr[0]}")
                        else:
                            self.logger.debug(f"Invalid ElDewrito response from {sender_addr[0]}:{sender_addr[1]} (size: {len(response_data)} bytes)")
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing ElDewrito response from {sender_addr[0]}:{sender_addr[1]}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error scanning network range {network_range}: {e}")
        
        self.logger.info(f"Step 1 complete: Found {len(discovered_ips)} ElDewrito server IPs")
        
        # Step 2: Query each discovered IP individually for detailed information
        if discovered_ips:
            self.logger.debug(f"Step 2: Querying {len(discovered_ips)} discovered IPs individually")
            
            for ip_address in discovered_ips:
                try:
                    # Small delay between queries to avoid overwhelming the servers
                    await asyncio.sleep(0.1)
                    
                    self.logger.debug(f"Querying ElDewrito server at {ip_address}:{port}")
                    
                    # Use opengsq-python library to get complete server info
                    server_info_dict = await self._query_eldewrito_server_via_opengsq(
                        ip_address, port
                    )
                    
                    if server_info_dict:
                        server_response = ServerResponse(
                            ip_address=ip_address,
                            port=port,
                            game_type='eldewrito',
                            server_info=server_info_dict,
                            response_time=0.0
                        )
                        servers.append(server_response)
                        self.logger.debug(f"Successfully queried ElDewrito server: {ip_address}:{port}")
                        self.logger.debug(f"ElDewrito server details: Name='{server_info_dict.get('name', 'Unknown')}', Map='{server_info_dict.get('map', 'Unknown')}', Players={server_info_dict.get('num_players', 0)}/{server_info_dict.get('max_players', 0)}, Status={server_info_dict.get('status', 'Unknown')}")
                    else:
                        self.logger.debug(f"Failed to get detailed info for ElDewrito server at {ip_address}:{port}")
                        
                except Exception as e:
                    self.logger.debug(f"Error querying ElDewrito server {ip_address}: {e}")
        
        self.logger.info(f"ElDewrito discovery completed. Found {len(servers)} servers with detailed info.")
        return servers
    
    async def _send_broadcast_query(self, broadcast_addr: str, port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send a broadcast query and collect responses.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to
            query_data: Query payload
            
        Returns:
            List of (response_data, sender_address) tuples
        """
        responses = []
        
        try:
            # Create broadcast protocol instance
            protocol = BroadcastResponseProtocol(responses)
            
            # Create UDP socket with broadcast enabled
            # Use a random local port instead of binding to the same port to avoid conflicts
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                local_addr=('0.0.0.0', 0),  # Use random local port (0) to avoid conflicts
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
            self.logger.error(f"Error sending ElDewrito broadcast query: {e}")
            # If port conflicts occur, log a specific message but continue
            if "Address already in use" in str(e):
                self.logger.warning(f"Port {port} conflict detected. This may happen if multiple ElDewrito scans run simultaneously.")
            
        return responses
    
    async def _query_eldewrito_server_via_opengsq(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Query an ElDewrito server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            
        Returns:
            Dictionary containing complete server information
        """
        try:
            # Create ElDewrito protocol instance
            eldewrito_client = ElDewrito(host, port, self.timeout)
            
            # Get server info using opengsq-python
            server_status = await eldewrito_client.get_status()
            
            # Convert Status object to dictionary format
            info_dict = {
                'name': server_status.name,
                'map': server_status.map,
                'num_players': server_status.num_players,
                'max_players': server_status.max_players,
                'port': server_status.port,
                'file_server_port': server_status.file_server_port,
                'host_player': server_status.host_player,
                'sprint_state': server_status.sprint_state,
                'sprint_unlimited_enabled': server_status.sprint_unlimited_enabled,
                'dual_wielding': server_status.dual_wielding,
                'assassination_enabled': server_status.assassination_enabled,
                'vote_system_type': server_status.vote_system_type,
                'teams': server_status.teams,
                'map_file': server_status.map_file,
                'variant': server_status.variant,
                'variant_type': server_status.variant_type,
                'status': server_status.status,
                'mod_count': server_status.mod_count,
                'mod_package_name': server_status.mod_package_name,
                'mod_package_author': server_status.mod_package_author,
                'mod_package_hash': server_status.mod_package_hash,
                'mod_package_version': server_status.mod_package_version,
                'xnkid': server_status.xnkid,
                'xnaddr': server_status.xnaddr,
                'is_dedicated': server_status.is_dedicated,
                'game_version': server_status.game_version,
                'eldewrito_version': server_status.eldewrito_version,
                'players': [
                    {
                        'name': player.name,
                        'uid': player.uid,
                        'team': player.team,
                        'score': player.score,
                        'kills': player.kills,
                        'assists': player.assists,
                        'deaths': player.deaths,
                        'betrayals': player.betrayals,
                        'time_spent_alive': player.time_spent_alive,
                        'suicides': player.suicides,
                        'best_streak': player.best_streak
                    }
                    for player in server_status.players
                ],
                'raw': server_status.raw
            }
            
            self.logger.debug(f"opengsq-python returned server info for {host}:{port}")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"Error querying ElDewrito server {host}:{port} via opengsq-python: {e}")
            return None 