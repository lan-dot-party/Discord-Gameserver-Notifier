"""
Serious Sam Classic protocol implementation for game server discovery.
Supports both The First Encounter (TFE) and The Second Encounter (TSE).
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.ssc import SSC
from ..protocol_base import ProtocolBase
from .common import ServerResponse, BroadcastResponseProtocol


class SSCProtocol(ProtocolBase):
    """
    Base Serious Sam Classic protocol handler for broadcast discovery.
    Supports both The First Encounter and The Second Encounter.
    """
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("255.255.255.255", 25601, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'listen_port': 57500,  # Port to listen on for responses
            'target_port': 25601,  # Port to send broadcast to
            'query_data': bytes.fromhex('5c7374617475735c')  # \status\ query
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Serious Sam Classic servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        
        # Add location
        if 'location' in server_info:
            fields.append({
                'name': '🌍 Region',
                'value': server_info['location'],
                'inline': True
            })
        
        # Add game type (Cooperative, Deathmatch, etc.)
        if 'gametype' in server_info:
            fields.append({
                'name': '🎯 Spielmodus',
                'value': server_info['gametype'],
                'inline': True
            })
        
        # Add difficulty
        if 'difficulty' in server_info:
            difficulty_emoji = {
                'Tourist': '🟢',
                'Easy': '🟢',
                'Normal': '🟡',
                'Hard': '🟠',
                'Serious': '🔴',
                'Mental': '💀'
            }
            difficulty_text = server_info['difficulty']
            emoji = difficulty_emoji.get(difficulty_text, '❓')
            fields.append({
                'name': '⚔️ Schwierigkeit',
                'value': f"{emoji} {difficulty_text}",
                'inline': True
            })
        
        # Add active mod
        if 'activemod' in server_info and server_info['activemod']:
            fields.append({
                'name': '🔧 Mod',
                'value': server_info['activemod'],
                'inline': True
            })
        
        # Add game mode status
        if 'gamemode' in server_info:
            gamemode_emoji = {
                'openplaying': '🎮',
                'starting': '⏳',
                'waiting': '⏸️',
                'ended': '🏁'
            }
            gamemode_text = server_info['gamemode']
            emoji = gamemode_emoji.get(gamemode_text, '❓')
            fields.append({
                'name': '📊 Status',
                'value': f"{emoji} {gamemode_text.title()}",
                'inline': True
            })
        
        # Add friendly fire status
        if 'friendlyfire' in server_info:
            ff_status = "✅ An" if server_info['friendlyfire'] == '1' else "❌ Aus"
            fields.append({
                'name': '💥 Friendly Fire',
                'value': ff_status,
                'inline': True
            })
        
        # Add infinite ammo status
        if 'infiniteammo' in server_info:
            ammo_status = "♾️ Unendlich" if server_info['infiniteammo'] == '1' else "🎯 Limitiert"
            fields.append({
                'name': '🔫 Munition',
                'value': ammo_status,
                'inline': True
            })
        
        # Add password status
        if 'password' in server_info:
            password_status = "🔒 Ja" if server_info['password'] == '1' else "🔓 Nein"
            fields.append({
                'name': '🔐 Passwort',
                'value': password_status,
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Serious Sam Classic servers using broadcast queries.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for SSC servers
        """
        servers = []
        listen_port = self.protocol_config['listen_port']
        target_port = self.protocol_config['target_port']
        
        # For each network range, send broadcast queries
        for network_range in scan_ranges:
            try:
                network = ipaddress.ip_network(network_range, strict=False)
                broadcast_addr = str(network.broadcast_address)
                
                self.logger.debug(f"Broadcasting SSC query to {broadcast_addr}:{target_port} (listening on {listen_port})")
                
                # Send broadcast query and collect initial responses
                responses = await self._send_broadcast_query(
                    broadcast_addr, target_port, listen_port, self.protocol_config['query_data']
                )
                
                # Process responses and query each responding server directly for full info
                for response_data, sender_addr in responses:
                    try:
                        # Parse the initial response to determine which game variant this is
                        game_variant = self._determine_game_variant(response_data)
                        
                        if game_variant:
                            # Use opengsq-python library to get complete server info
                            server_info_dict = await self._query_ssc_server_via_opengsq(
                                sender_addr[0], sender_addr[1], game_variant
                            )
                            
                            if server_info_dict:
                                # Use the correct game type based on variant
                                game_type = 'ssc_tfe' if game_variant == 'tfe' else 'ssc_tse'
                                
                                # Get the actual server port from hostport field (not the broadcast port)
                                actual_port = int(server_info_dict.get('hostport', sender_addr[1]))
                                
                                server_response = ServerResponse(
                                    ip_address=sender_addr[0],
                                    port=actual_port,
                                    game_type=game_type,
                                    server_info=server_info_dict,
                                    response_time=0.0
                                )
                                servers.append(server_response)
                                self.logger.debug(f"Discovered SSC {game_variant.upper()} server: {sender_addr[0]}:{actual_port}")
                                self.logger.debug(f"SSC server details: Name='{server_info_dict.get('hostname', 'Unknown')}', Map='{server_info_dict.get('mapname', 'Unknown')}', Players={server_info_dict.get('numplayers', 0)}/{server_info_dict.get('maxplayers', 0)}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to process response from {sender_addr}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error broadcasting to network {network_range}: {e}")
        
        return servers
    
    async def _send_broadcast_query(self, broadcast_addr: str, target_port: int, listen_port: int, query_data: bytes) -> List[Tuple[bytes, Tuple[str, int]]]:
        """
        Send a Serious Sam Classic broadcast query.
        
        SSC requires listening on a specific port (57500) while sending to port 25601.
        
        Args:
            broadcast_addr: Broadcast address to send to
            target_port: Port to send to (25601)
            listen_port: Port to listen on for responses (57500)
            query_data: Query data to send
            
        Returns:
            List of tuples containing (response_data, sender_address)
        """
        responses = []
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP socket for broadcast with specific source port for SSC
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BroadcastResponseProtocol(responses),
                local_addr=('0.0.0.0', listen_port),  # Listen on port 57500
                allow_broadcast=True
            )
            
            try:
                # Send broadcast query to port 25601
                transport.sendto(query_data, (broadcast_addr, target_port))
                
                # Wait for responses
                await asyncio.sleep(self.timeout)
                
            finally:
                transport.close()
                
        except Exception as e:
            self.logger.error(f"Error sending SSC broadcast query: {e}")
            # If port 57500 is already in use, log a specific message
            if "Address already in use" in str(e):
                self.logger.warning(f"Port {listen_port} is already in use. This may happen if multiple SSC scans run simultaneously.")
        
        return responses
    
    def _determine_game_variant(self, response_data: bytes) -> Optional[str]:
        """
        Determine whether this is The First Encounter or The Second Encounter
        based on the response data.
        
        Args:
            response_data: Raw response data from server
            
        Returns:
            'tfe' for The First Encounter, 'tse' for The Second Encounter, or None if undetermined
        """
        try:
            # Convert response to string for parsing
            response_str = response_data.decode('utf-8', errors='ignore')
            
            # Look for the gamename field which differs between versions
            # First Encounter: "serioussam"
            # Second Encounter: "serioussamse"
            if 'gamename' in response_str:
                if 'serioussamse' in response_str:
                    return 'tse'  # The Second Encounter
                elif 'serioussam' in response_str:
                    return 'tfe'  # The First Encounter
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error determining SSC game variant: {e}")
            return None
    
    async def _query_ssc_server_via_opengsq(self, host: str, port: int, variant: str) -> Optional[Dict[str, Any]]:
        """
        Query a Serious Sam Classic server using opengsq-python library to get complete server information.
        
        Args:
            host: Server IP address
            port: Server port
            variant: Game variant ('tfe' or 'tse')
            
        Returns:
            Dictionary containing complete server information with all fields needed for Discord
        """
        try:
            # Create SSC protocol instance
            ssc_client = SSC(host, port, self.timeout)
            
            # Get server info using opengsq-python
            server_basic = await ssc_client.get_basic()
            
            # The get_basic() method returns a flattened dictionary with all info
            info_dict = {
                'hostname': server_basic.get('hostname', 'Unknown Server'),
                'mapname': server_basic.get('mapname', 'Unknown Map'),
                'gamename': server_basic.get('gamename', 'serioussam'),
                'gamever': server_basic.get('gamever', 'Unknown'),
                'location': server_basic.get('location', 'Unknown'),
                'gametype': server_basic.get('gametype', 'Unknown'),
                'numplayers': int(server_basic.get('numplayers', 0)),
                'maxplayers': int(server_basic.get('maxplayers', 0)),
                'activemod': server_basic.get('activemod', ''),
                'gamemode': server_basic.get('gamemode', 'unknown'),
                'difficulty': server_basic.get('difficulty', 'Normal'),
                'friendlyfire': server_basic.get('friendlyfire', '0'),
                'weaponsstay': server_basic.get('weaponsstay', '0'),
                'ammostays': server_basic.get('ammostays', '0'),
                'infiniteammo': server_basic.get('infiniteammo', '0'),
                'password': server_basic.get('password', '0'),
                'hostport': server_basic.get('hostport', str(port)),
            }
            
            # Add game name for display
            if variant == 'tfe':
                info_dict['game'] = 'Serious Sam: The First Encounter'
            else:
                info_dict['game'] = 'Serious Sam: The Second Encounter'
            
            self.logger.debug(f"opengsq-python returned server info for {host}:{port} ({variant.upper()})")
            
            return info_dict
            
        except Exception as e:
            self.logger.debug(f"Error querying SSC server {host}:{port} via opengsq-python: {e}")
            return None


class SSCTFEProtocol(SSCProtocol):
    """
    Serious Sam Classic: The First Encounter protocol handler.
    Filters results to only return TFE servers.
    """
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Serious Sam TFE servers only.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for TFE servers only
        """
        all_servers = await super().scan_servers(scan_ranges)
        # Filter to only TFE servers
        return [s for s in all_servers if s.game_type == 'ssc_tfe']


class SSCTSEProtocol(SSCProtocol):
    """
    Serious Sam Classic: The Second Encounter protocol handler.
    Filters results to only return TSE servers.
    """
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Serious Sam TSE servers only.
        
        Args:
            scan_ranges: List of network ranges to scan
            
        Returns:
            List of ServerResponse objects for TSE servers only
        """
        all_servers = await super().scan_servers(scan_ranges)
        # Filter to only TSE servers
        return [s for s in all_servers if s.game_type == 'ssc_tse']

