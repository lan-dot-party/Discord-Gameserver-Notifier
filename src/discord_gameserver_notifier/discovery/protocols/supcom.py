"""
Supreme Commander protocol implementation for game server discovery.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Tuple

from opengsq.protocols.supcom import SupCom
from ..protocol_base import ProtocolBase
from .common import ServerResponse


class SupComProtocol(ProtocolBase):
    """Supreme Commander protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        # Supreme Commander uses UDP port 15000 for queries, 55582 for responses
        super().__init__("0.0.0.0", SupCom.QUERY_PORT, timeout)
        self._allow_broadcast = True
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Use constants from opengsq-python
        self.protocol_config = {
            'query_port': SupCom.QUERY_PORT,        # 15000 - UDP broadcast port
            'response_port': SupCom.RESPONSE_PORT,  # 55582 - Response port
            'query_payload': SupCom.QUERY_PAYLOAD   # 0x6E 0x03 0x00
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for Supreme Commander servers.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add product/game version
        if 'product_code' in server_info and server_info['product_code']:
            product_titles = {
                'SC1': 'Supreme Commander',
                'SCFA': 'Supreme Commander: Forged Alliance',
                'SC2': 'Supreme Commander 2',
                'FAF': 'Forged Alliance Forever'
            }
            product_display = product_titles.get(server_info['product_code'], server_info['product_code'])
            fields.append({
                'name': '🎮 Produkt',
                'value': product_display,
                'inline': True
            })
        
        # Add host player
        if 'hosted_by' in server_info and server_info['hosted_by']:
            fields.append({
                'name': '👑 Host',
                'value': server_info['hosted_by'],
                'inline': True
            })
        
        # Add game speed
        if 'game_speed' in server_info and server_info['game_speed']:
            speed_translations = {
                'slow': 'Langsam',
                'normal': 'Normal',
                'fast': 'Schnell'
            }
            speed_display = speed_translations.get(server_info['game_speed'].lower(), server_info['game_speed'])
            fields.append({
                'name': '⚡ Spielgeschwindigkeit',
                'value': speed_display,
                'inline': True
            })
        
        # Add victory condition
        if 'victory_condition' in server_info and server_info['victory_condition']:
            victory_translations = {
                'demoralization': 'Demoralisierung',
                'assassination': 'Attentat',
                'supremacy': 'Vorherrschaft',
                'annihilation': 'Vernichtung',
                'sandbox': 'Sandbox'
            }
            victory_display = victory_translations.get(server_info['victory_condition'].lower(), server_info['victory_condition'])
            fields.append({
                'name': '🏆 Siegbedingung',
                'value': victory_display,
                'inline': True
            })
        
        # Add unit cap
        if 'unit_cap' in server_info and server_info['unit_cap']:
            fields.append({
                'name': '🤖 Einheitenlimit',
                'value': str(server_info['unit_cap']),
                'inline': True
            })
        
        # Add map size if available
        if 'map_size_display' in server_info and server_info['map_size_display'] != '?':
            fields.append({
                'name': '📐 Kartengröße',
                'value': server_info['map_size_display'],
                'inline': True
            })
        
        # Add cheats enabled status
        if 'cheats_enabled' in server_info:
            cheats_text = "✅ Aktiviert" if server_info['cheats_enabled'] else "❌ Deaktiviert"
            fields.append({
                'name': '🔧 Cheats',
                'value': cheats_text,
                'inline': True
            })
        
        # Add team settings
        if 'team_lock' in server_info and server_info['team_lock']:
            team_lock_translations = {
                'locked': 'Gesperrt',
                'unlocked': 'Entsperrt'
            }
            team_lock_display = team_lock_translations.get(server_info['team_lock'].lower(), server_info['team_lock'])
            fields.append({
                'name': '🔒 Team-Lock',
                'value': team_lock_display,
                'inline': True
            })
        
        # Add observers allowed
        if 'allow_observers' in server_info:
            observers_text = "✅ Erlaubt" if server_info['allow_observers'] else "❌ Nicht erlaubt"
            fields.append({
                'name': '👁️ Beobachter',
                'value': observers_text,
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Supreme Commander servers using UDP broadcast discovery.
        
        Supreme Commander servers respond to broadcasts sent FROM port 55582
        to 255.255.255.255:15000. The server responds with its IP and full
        game status.
        
        Args:
            scan_ranges: List of network ranges (used for filtering results)
            
        Returns:
            List of ServerResponse objects for Supreme Commander servers
        """
        servers = []
        query_port = self.protocol_config['query_port']
        
        self.logger.info("🚀 Starting Supreme Commander server discovery via broadcast...")
        
        # Build list of valid network ranges for filtering
        valid_networks = []
        for network_range in scan_ranges:
            try:
                valid_networks.append(ipaddress.ip_network(network_range, strict=False))
            except Exception as e:
                self.logger.warning(f"Invalid network range {network_range}: {e}")
        
        # Use global broadcast 255.255.255.255 - SC servers only respond to this
        try:
            self.logger.info(f"📡 Broadcasting to 255.255.255.255:{query_port} from port {SupCom.RESPONSE_PORT}")
            
            supcom = SupCom("255.255.255.255", query_port, timeout=self.timeout)
            discovered = await supcom.discover_servers("255.255.255.255")
            
            self.logger.info(f"🔍 Broadcast discovered {len(discovered)} Supreme Commander servers")
            
            # Filter servers by configured network ranges and process
            for server_ip, server_status in discovered:
                # Check if server is in any of the configured scan ranges
                server_addr = ipaddress.ip_address(server_ip)
                in_range = any(server_addr in network for network in valid_networks)
                
                if not in_range:
                    self.logger.debug(f"⏭️ Skipping {server_ip} - not in configured scan ranges")
                    continue
                
                server_info_dict = self._status_to_dict(server_status)
                if server_info_dict:
                    servers.append(ServerResponse(
                        ip_address=server_ip,
                        port=query_port,
                        game_type='supcom',
                        server_info=server_info_dict,
                        response_time=0.0
                    ))
                    self.logger.info(f"✅ Found: {server_ip}:{query_port} - {server_info_dict.get('name', 'Unknown')}")
                    self.logger.info(f"   Host: {server_info_dict.get('hosted_by', 'Unknown')}, Map: {server_info_dict.get('map', 'Unknown')}, Players: {server_info_dict.get('players', 0)}/{server_info_dict.get('max_players', 0)}")
                    
        except OSError as e:
            if "Address already in use" in str(e):
                self.logger.warning(f"⚠️ Port {SupCom.RESPONSE_PORT} already in use")
            else:
                self.logger.error(f"❌ OS error in broadcast discovery: {e}")
        except Exception as e:
            self.logger.error(f"❌ Error in Supreme Commander discovery: {e}")
            import traceback
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
        
        self.logger.info(f"🎯 Supreme Commander discovery completed: {len(servers)} servers found")
        return servers
    
    def _status_to_dict(self, status) -> Optional[Dict[str, Any]]:
        """
        Convert a Supreme Commander Status object to dictionary format.
        
        Args:
            status: Status object from opengsq-python
            
        Returns:
            Dictionary containing server information
        """
        try:
            return {
                'name': getattr(status, 'game_name', 'Unknown Server'),
                'map': getattr(status, 'map_name', 'Unknown Map'),
                'game': getattr(status, 'game_title', 'Supreme Commander'),
                'players': getattr(status, 'num_players', 0),
                'max_players': getattr(status, 'max_players', 0),
                # Supreme Commander specific fields
                'hosted_by': getattr(status, 'hosted_by', 'Unknown'),
                'product_code': getattr(status, 'product_code', 'SC1'),
                'scenario_file': getattr(status, 'scenario_file', ''),
                'game_speed': getattr(status, 'game_speed', 'normal'),
                'victory_condition': getattr(status, 'victory_condition', 'demoralization'),
                'fog_of_war': getattr(status, 'fog_of_war', 'explored'),
                'unit_cap': getattr(status, 'unit_cap', '500'),
                'cheats_enabled': getattr(status, 'cheats_enabled', False),
                'team_lock': getattr(status, 'team_lock', 'unlocked'),
                'team_spawn': getattr(status, 'team_spawn', 'random'),
                'allow_observers': getattr(status, 'allow_observers', True),
                'no_rush_option': getattr(status, 'no_rush_option', 'Off'),
                'prebuilt_units': getattr(status, 'prebuilt_units', 'Off'),
                'civilian_alliance': getattr(status, 'civilian_alliance', 'enemy'),
                'timeouts': getattr(status, 'timeouts', '3'),
                # Map info
                'map_id': getattr(status, 'map_id', ''),
                'map_name_lookup': getattr(status, 'map_name_lookup', ''),
                'map_width': getattr(status, 'map_width', 0),
                'map_height': getattr(status, 'map_height', 0),
                'map_size_display': getattr(status, 'map_size_display', '?'),
                'map_size_category': getattr(status, 'map_size_category', 'Unknown'),
                # Raw data for debugging
                'options': getattr(status, 'options', {}),
                'raw': getattr(status, 'raw', {})
            }
        except Exception as e:
            self.logger.error(f"Error converting Status to dict: {e}")
            return None
    
    async def query_server(self, host: str, port: int = None) -> Optional[Dict[str, Any]]:
        """
        Query a specific Supreme Commander server directly.
        
        Args:
            host: Server IP address
            port: Server port (default: 15000)
            
        Returns:
            Dictionary containing server information, or None if query failed
        """
        if port is None:
            port = self.protocol_config['query_port']
            
        try:
            self.logger.debug(f"Querying Supreme Commander server {host}:{port}...")
            
            supcom = SupCom(host, port, self.timeout)
            status = await supcom.get_status()
            
            return self._status_to_dict(status)
            
        except Exception as e:
            self.logger.debug(f"Error querying Supreme Commander server {host}:{port}: {e}")
            return None

