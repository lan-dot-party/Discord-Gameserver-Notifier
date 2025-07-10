"""
RenegadeX protocol implementation for game server discovery.
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.renegadex import RenegadeX
from ..protocol_base import ProtocolBase
from .common import ServerResponse


class RenegadeXProtocol(ProtocolBase):
    """RenegadeX protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("", 0, timeout)
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 7777,  # Game server port
            'broadcast_port': 45542,  # Broadcast listening port
            'passive': True  # Uses passive listening instead of active queries
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for RenegadeX servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add Steam requirement
        if 'steam_required' in server_info:
            steam_status = "✅ Erforderlich" if server_info['steam_required'] else "❌ Nicht erforderlich"
            fields.append({
                'name': '🎮 Steam',
                'value': steam_status,
                'inline': True
            })
        
        # Add team mode
        if 'team_mode' in server_info:
            team_mode = server_info['team_mode']
            team_mode_text = {
                0: "🔴 Keine Teams",
                1: "🔵 GDI vs NOD",
                2: "🟢 GDI vs NOD vs Mutant",
                3: "🟡 Alle gegen Alle",
                4: "🟠 Kooperativ",
                5: "🟣 Übung",
                6: "⚪ Standard"
            }.get(team_mode, f"❓ {team_mode}")
            
            fields.append({
                'name': '👥 Team Modus',
                'value': team_mode_text,
                'inline': True
            })
        
        # Add game type
        if 'game_type' in server_info:
            game_type = server_info['game_type']
            game_type_text = {
                0: "🎯 Arcade",
                1: "⚔️ Standard",
                2: "🏆 Wettkampf",
                3: "🎲 Zufällig"
            }.get(game_type, f"❓ {game_type}")
            
            fields.append({
                'name': '🎮 Spiel Typ',
                'value': game_type_text,
                'inline': True
            })
        
        # Add ranked status
        if 'ranked' in server_info:
            ranked_status = "🏆 Ja" if server_info['ranked'] else "🎯 Nein"
            fields.append({
                'name': '🏅 Ranked',
                'value': ranked_status,
                'inline': True
            })
        
        # Add vehicle limit
        if 'vehicle_limit' in server_info:
            fields.append({
                'name': '🚗 Fahrzeug Limit',
                'value': str(server_info['vehicle_limit']),
                'inline': True
            })
        
        # Add mine limit
        if 'mine_limit' in server_info:
            fields.append({
                'name': '💣 Minen Limit',
                'value': str(server_info['mine_limit']),
                'inline': True
            })
        
        # Add time limit
        if 'time_limit' in server_info and server_info['time_limit'] > 0:
            fields.append({
                'name': '⏱️ Zeit Limit',
                'value': f"{server_info['time_limit']} Min",
                'inline': True
            })
        
        # Add spawn crates
        if 'spawn_crates' in server_info:
            crates_status = "📦 Ja" if server_info['spawn_crates'] else "❌ Nein"
            fields.append({
                'name': '🎁 Spawn Crates',
                'value': crates_status,
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Renegade X servers using passive broadcast listening.
        
        Args:
            scan_ranges: List of network ranges to scan (not used for passive listening)
            
        Returns:
            List of ServerResponse objects for RenegadeX servers
        """
        servers = []
        broadcast_port = self.protocol_config['broadcast_port']
        
        self.logger.debug(f"Starting passive listening for RenegadeX broadcasts on port {broadcast_port}")
        
        try:
            # Create a queue to collect broadcast messages
            broadcast_queue = asyncio.Queue()
            
            # Create UDP socket for listening to broadcasts
            loop = asyncio.get_running_loop()
            
            class RenegadeXBroadcastProtocol(asyncio.DatagramProtocol):
                def __init__(self, queue):
                    self.queue = queue
                
                def datagram_received(self, data, addr):
                    asyncio.create_task(self.queue.put((data, addr)))
                
                def error_received(self, exc):
                    logging.getLogger(__name__).debug(f"RenegadeX broadcast protocol error: {exc}")
            
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
                        
                        self.logger.debug(f"RenegadeX: Collected data from {addr[0]} ({len(data)} bytes, total: {len(server_data_buffers[server_key])} bytes)")
                        
                        # Try to parse the accumulated data
                        complete_data = bytes(server_data_buffers[server_key])
                        if self._is_complete_renegadex_json(complete_data):
                            try:
                                server_info = self._parse_renegadex_response(complete_data)
                                if server_info:
                                    # Successfully parsed - create server response
                                    server_response = ServerResponse(
                                        ip_address=addr[0],
                                        port=server_info.get('port', self.protocol_config['port']),
                                        game_type='renegadex',
                                        server_info=server_info,
                                        response_time=0.0
                                    )
                                    
                                    # Check if we already found this server
                                    if not any(s.ip_address == addr[0] for s in servers):
                                        servers.append(server_response)
                                        self.logger.debug(f"Discovered RenegadeX server: {addr[0]}:{server_info.get('port', self.protocol_config['port'])}")
                                    
                                    # Clear the buffer for this server
                                    server_data_buffers[server_key] = bytearray()
                            except Exception as e:
                                self.logger.debug(f"RenegadeX: Failed to parse JSON from {addr[0]}: {e}")
                        
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
                json.loads(potential_json)
                return True
            except json.JSONDecodeError:
                return False
                
        except Exception:
            return False
    
    def _parse_renegadex_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a RenegadeX server response from broadcast data.
        
        Args:
            response_data: Raw response data from server broadcast
            
        Returns:
            Dictionary containing parsed server information, or None if parsing failed
        """
        try:
            # Convert bytes to string
            json_str = response_data.decode('utf-8', errors='ignore').strip()
            
            if not json_str:
                return None
            
            # Find the first complete JSON object
            start_idx = json_str.find('{')
            if start_idx == -1:
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
                return None
            
            # Extract and parse the JSON
            json_data = json_str[start_idx:end_idx + 1]
            raw_server_info = json.loads(json_data)
            
            # Validate that this looks like a RenegadeX server response
            if not isinstance(raw_server_info, dict):
                return None
            
            # Parse the raw data into the expected format using opengsq structure
            # The raw data should match the opengsq RenegadeX response format
            server_info = {
                'name': raw_server_info.get('Name', 'Unknown RenegadeX Server'),
                'map': raw_server_info.get('Current Map', 'Unknown Map'),
                'port': raw_server_info.get('Port', 7777),
                'players': raw_server_info.get('Players', 0),
                'game_version': raw_server_info.get('Game Version', 'Unknown'),
            }
            
            # Extract variables if present
            variables = raw_server_info.get('Variables', {})
            if variables:
                server_info.update({
                    'max_players': variables.get('Player Limit', 0),
                    'passworded': variables.get('bPassworded', False),
                    'steam_required': variables.get('bSteamRequired', False),
                    'team_mode': variables.get('Team Mode', 0),
                    'game_type': variables.get('Game Type', 0),
                    'ranked': variables.get('bRanked', False),
                    'vehicle_limit': variables.get('Vehicle Limit', 0),
                    'mine_limit': variables.get('Mine Limit', 0),
                    'time_limit': variables.get('Time Limit', 0),
                    'spawn_crates': variables.get('bSpawnCrates', False)
                })
            
            self.logger.debug(f"RenegadeX: Parsed server info: {server_info}")
            
            return server_info
            
        except Exception as e:
            self.logger.debug(f"Failed to parse RenegadeX response: {e}")
            return None 