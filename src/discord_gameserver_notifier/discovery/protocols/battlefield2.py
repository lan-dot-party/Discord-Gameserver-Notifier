"""
Battlefield 2 protocol implementation for game server discovery.
Uses LAN discovery via UDP broadcast on port 29900.
"""

import asyncio
import ipaddress
import logging
import socket
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.battlefield2 import Battlefield2
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class Battlefield2Protocol(ProtocolBase):
    """Battlefield 2 protocol handler for LAN discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("255.255.255.255", 29900, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 29900,
            'broadcast_port': 51170,  # Local port to send from
            'query_data': bytes.fromhex('fefd020000000000')  # BF2 LAN discovery packet
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Battlefield 2 servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add game version
        if 'gamever' in server_info:
            fields.append({
                'name': '🎮 Version',
                'value': server_info['gamever'],
                'inline': True
            })
        
        # Add mod information
        if 'gamename' in server_info:
            game_name = server_info['gamename']
            if game_name != 'battlefield2':
                fields.append({
                    'name': '🔧 Mod',
                    'value': game_name,
                    'inline': True
                })
        
        # Add server type (dedicated/ranked)
        if 'dedicated' in server_info:
            server_type = "🖥️ Dedicated" if server_info['dedicated'] == '1' else "🏠 Listen"
            fields.append({
                'name': '🔧 Server Typ',
                'value': server_type,
                'inline': True
            })
        
        # Add ranked status
        if 'ranked' in server_info:
            ranked_status = "⭐ Ranked" if server_info['ranked'] == '1' else "🎯 Unranked"
            fields.append({
                'name': '🏆 Ranking',
                'value': ranked_status,
                'inline': True
            })
        
        # Add password protection
        if 'password' in server_info:
            password_status = "🔒 Passwort geschützt" if server_info['password'] == '1' else "🌐 Öffentlich"
            fields.append({
                'name': '🔐 Zugang',
                'value': password_status,
                'inline': True
            })
        
        # Add PunkBuster status
        if 'punkbuster' in server_info:
            pb_status = "✅ Aktiviert" if server_info['punkbuster'] == '1' else "❌ Deaktiviert"
            fields.append({
                'name': '🛡️ PunkBuster',
                'value': pb_status,
                'inline': True
            })
        
        # Add team info if available
        if 'team_1' in server_info and 'team_2' in server_info:
            team1_score = server_info.get('score_1', '0')
            team2_score = server_info.get('score_2', '0')
            fields.append({
                'name': '⚔️ Teams',
                'value': f"{server_info['team_1']}: {team1_score}\n{server_info['team_2']}: {team2_score}",
                'inline': True
            })
        
        # Add time limit if available
        if 'timelimit' in server_info and server_info['timelimit'] != '0':
            fields.append({
                'name': '⏱️ Zeitlimit',
                'value': f"{server_info['timelimit']} min",
                'inline': True
            })
        
        # Add round time if available
        if 'roundtime' in server_info:
            try:
                round_time = int(server_info['roundtime'])
                minutes = round_time // 60
                seconds = round_time % 60
                fields.append({
                    'name': '⏰ Rundenzeit',
                    'value': f"{minutes:02d}:{seconds:02d}",
                    'inline': True
                })
            except (ValueError, TypeError):
                pass
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Battlefield 2 servers using LAN discovery broadcast.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for BF2 servers
        """
        servers = []
        port = self.protocol_config['port']
        broadcast_port = self.protocol_config['broadcast_port']
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting BF2 LAN discovery to {broadcast_addr}:{port} from port {broadcast_port}")
                
                # Send broadcast query and collect initial responses
                responses = await self._send_bf2_broadcast_query(
                    broadcast_addr, port, broadcast_port, self.protocol_config['query_data']
                )
                
                # Process responses and query each responding server directly
                for response_data, sender_addr in responses:
                    try:
                        # Use opengsq-python library to get complete server info
                        server_info_dict = await self._query_bf2_server_via_opengsq(
                            sender_addr[0], sender_addr[1]
                        )
                        
                        if server_info_dict:
                            # Use hostport from server info if available, otherwise fall back to query port
                            actual_port = sender_addr[1]  # Default to query port
                            if 'hostport' in server_info_dict:
                                try:
                                    actual_port = int(server_info_dict['hostport'])
                                except (ValueError, TypeError):
                                    self.logger.debug(f"Invalid hostport value: {server_info_dict['hostport']}, using query port {sender_addr[1]}")
                            
                            server_response = ServerResponse(
                                ip_address=sender_addr[0],
                                port=actual_port,
                                game_type='battlefield2',
                                server_info=server_info_dict,
                                response_time=0.0
                            )
                            servers.append(server_response)
                            self.logger.debug(f"Discovered BF2 server: {sender_addr[0]}:{actual_port} (query port: {sender_addr[1]})")
                            self.logger.debug(f"BF2 server details: Name='{server_info_dict.get('hostname', 'Unknown')}', Map='{server_info_dict.get('mapname', 'Unknown')}', Players={server_info_dict.get('numplayers', 0)}/{server_info_dict.get('maxplayers', 0)}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process BF2 response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting BF2 query to network {network_range}: {e}")
        
        return servers
    
    async def _send_bf2_broadcast_query(self, broadcast_addr: str, port: int, local_port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send a BF2 LAN discovery broadcast query and collect all responses.
        
        Args:
            broadcast_addr: Broadcast address to send to
            port: Port to send to (29900)
            local_port: Local port to bind to (51170)
            query_data: Query data to send (fefd020000000000)
            
        Returns:
            List of tuples containing (response_data, sender_address)
        """
        responses = []
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast with specific local port
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', local_port),
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query
                transport.sendto(query_data, (broadcast_addr, port))
                self.logger.debug(f"Sent BF2 broadcast query from port {local_port} to {broadcast_addr}:{port}")
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
                self.logger.debug(f"Received {len(responses)} BF2 broadcast responses")
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending BF2 broadcast query: {e}")
        
        return responses
    
    async def _query_bf2_server_via_opengsq(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Query a BF2 server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            
        Returns:
            Dictionary containing complete server information
        """
        try:
            # Create Battlefield2 protocol instance
            bf2_client = Battlefield2(host, port, self.timeout)
            
            # Get server status using opengsq-python
            server_status = await bf2_client.get_status()
            
            # Convert Status object to dictionary format
            info_dict = {}
            
            # Basic server information
            if hasattr(server_status, 'info') and server_status.info:
                info_dict.update(server_status.info)
            
            # Player information
            if hasattr(server_status, 'players') and server_status.players:
                info_dict['players_list'] = server_status.players
                info_dict['numplayers'] = str(len(server_status.players))
            
            # Team information
            if hasattr(server_status, 'teams') and server_status.teams:
                info_dict['teams_list'] = server_status.teams
                # Add team names and scores if available
                for i, team in enumerate(server_status.teams, 1):
                    if 'name' in team:
                        info_dict[f'team_{i}'] = team['name']
                    if 'score' in team:
                        info_dict[f'score_{i}'] = team['score']
            
            # Ensure we have basic required fields
            if 'hostname' not in info_dict:
                info_dict['hostname'] = f"BF2 Server {host}:{port}"
            if 'mapname' not in info_dict:
                info_dict['mapname'] = "Unknown"
            if 'numplayers' not in info_dict:
                info_dict['numplayers'] = "0"
            if 'maxplayers' not in info_dict:
                info_dict['maxplayers'] = "0"
            
            self.logger.debug(f"opengsq-python returned BF2 server info for {host}:{port}")
            self.logger.debug(f"Server name: {info_dict.get('hostname')}, Map: {info_dict.get('mapname')}")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"Error querying BF2 server {host}:{port} via opengsq-python: {e}")
            return None
