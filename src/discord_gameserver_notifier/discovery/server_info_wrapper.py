"""
Server Information Wrapper for standardizing game server data across different protocols
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional
import logging


@dataclass
class StandardizedServerInfo:
    """Standardized server information across all game protocols"""
    name: str                           # Server Name
    game: str                          # Game Type/Name
    map: str                           # Current Map
    players: int                       # Current Players
    max_players: int                   # Maximum Players
    version: str                       # Game/Server Version
    password_protected: bool           # Is Password Protected
    ip_address: str                    # Server IP Address
    port: int                          # Server Port
    game_type: str                     # Protocol type (source, renegadex, etc.)
    response_time: float               # Response time in seconds
    additional_info: Dict[str, Any]    # Protocol-specific additional information
    discord_fields: Optional[list] = None  # Additional Discord embed fields from protocol


class ServerInfoWrapper:
    """
    Wrapper class that standardizes server information from different game protocols
    into a unified format for consistent processing.
    """
    
    def __init__(self, protocols: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger("GameServerNotifier.ServerInfoWrapper")
        self.protocols = protocols or {}
    
    def standardize_server_response(self, server_response) -> StandardizedServerInfo:
        """
        Convert a ServerResponse object to StandardizedServerInfo.
        
        Args:
            server_response: ServerResponse object from network scanner
            
        Returns:
            StandardizedServerInfo object with unified format
        """
        game_type = server_response.game_type.lower()
        
        # Get standardized server info
        if game_type == 'source':
            standardized_info = self._standardize_source_server(server_response)
        elif game_type == 'renegadex':
            standardized_info = self._standardize_renegadex_server(server_response)
        elif game_type == 'warcraft3':
            standardized_info = self._standardize_warcraft3_server(server_response)
        elif game_type == 'flatout2':
            standardized_info = self._standardize_flatout2_server(server_response)
        elif game_type == 'ut3':
            standardized_info = self._standardize_ut3_server(server_response)
        elif game_type == 'eldewrito':
            standardized_info = self._standardize_eldewrito_server(server_response)
        else:
            self.logger.warning(f"Unknown game type: {game_type}")
            standardized_info = self._standardize_generic_server(server_response)
        
        # Get additional Discord fields from protocol if available
        if game_type in self.protocols:
            protocol = self.protocols[game_type]
            if hasattr(protocol, 'get_discord_fields'):
                try:
                    discord_fields = protocol.get_discord_fields(server_response.server_info)
                    standardized_info.discord_fields = discord_fields
                except Exception as e:
                    self.logger.warning(f"Error getting Discord fields from {game_type} protocol: {e}")
        
        return standardized_info
    
    def _standardize_source_server(self, server_response) -> StandardizedServerInfo:
        """Standardize Source engine server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('name', 'Unknown Source Server')
        game = info.get('game', 'Source Engine Game')
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', 0)
        version = info.get('version', 'Unknown')
        
        # Determine if password protected based on visibility
        # According to Source protocol: 0 = Public (no password), 1 = Private (password required)
        password_protected = info.get('visibility', 0) == 1  # 1 = private, 0 = public
        
        # Additional Source-specific information
        additional_info = {
            'server_type': info.get('server_type', 'Unknown'),
            'environment': info.get('environment', 'Unknown'),
            'protocol': info.get('protocol', 0),
            'vac': info.get('vac', False),
            'steam_id': info.get('steam_id'),
            'keywords': info.get('keywords'),
            'visibility': info.get('visibility', 1)
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_renegadex_server(self, server_response) -> StandardizedServerInfo:
        """Standardize RenegadeX server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('name', 'Unknown RenegadeX Server')
        game = 'Renegade X'
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', 0)
        version = info.get('game_version', 'Unknown')
        
        # Check if password protected
        password_protected = info.get('passworded', False)
        
        # Additional RenegadeX-specific information
        additional_info = {
            'steam_required': info.get('steam_required', False),
            'team_mode': info.get('team_mode', 0),
            'game_type': info.get('game_type', 0),
            'ranked': info.get('ranked', False),
            'vehicle_limit': info.get('vehicle_limit', 0),
            'mine_limit': info.get('mine_limit', 0),
            'time_limit': info.get('time_limit', 0),
            'spawn_crates': info.get('spawn_crates', False)
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_warcraft3_server(self, server_response) -> StandardizedServerInfo:
        """Standardize Warcraft 3 server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('name', 'Unknown Warcraft 3 Server')
        game = 'Warcraft III'
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', 0)
        version = str(info.get('version', 'Unknown'))
        
        # Warcraft 3 doesn't provide password info in basic query
        password_protected = False
        
        # Additional Warcraft3-specific information
        additional_info = {
            'product': info.get('product', 'Unknown'),
            'host_counter': info.get('host_counter', 0),
            'entry_key': info.get('entry_key', 0)
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_flatout2_server(self, server_response) -> StandardizedServerInfo:
        """Standardize Flatout 2 server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('hostname', 'Unknown Flatout 2 Server')
        game = info.get('game', 'Flatout 2')
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', 0)
        version = 'Unknown'
        
        # Flatout 2 doesn't provide password info in basic query
        password_protected = False
        
        # Additional Flatout2-specific information
        additional_info = {
            'timestamp': info.get('timestamp', '0'),
            'flags': info.get('flags', '0'),
            'status': info.get('status', '0'),
            'config': info.get('config', '')
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_ut3_server(self, server_response) -> StandardizedServerInfo:
        """Standardize Unreal Tournament 3 server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('name', 'Unknown UT3 Server')
        game = info.get('game', 'Unreal Tournament 3')
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', 0)
        version = info.get('version', 'UT3')
        
        # Check if password protected
        password_protected = info.get('password_protected', False)
        
        # Additional UT3-specific information
        additional_info = {
            'gamemode': info.get('gamemode', 'Unknown'),
            'mutators': info.get('mutators', []),
            'frag_limit': info.get('frag_limit'),
            'time_limit': info.get('time_limit'),
            'numbots': info.get('numbots', 0),
            'bot_skill': info.get('bot_skill'),
            'pure_server': info.get('pure_server', False),
            'vs_bots': info.get('vs_bots', 'None'),
            'force_respawn': info.get('force_respawn', False),
            'stats_enabled': info.get('stats_enabled', False),
            'lan_mode': info.get('lan_mode', True)
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_eldewrito_server(self, server_response) -> StandardizedServerInfo:
        """Standardize ElDewrito server information"""
        info = server_response.server_info
        
        # Extract basic information
        name = info.get('name', 'Unknown ElDewrito Server')
        game = 'Halo Online (ElDewrito)'
        map_name = info.get('map', 'Unknown Map')
        players = info.get('num_players', 0)
        max_players = info.get('max_players', 16)
        version = info.get('eldewrito_version', 'Unknown')
        
        # ElDewrito doesn't provide password info in basic query
        password_protected = False
        
        # Additional ElDewrito-specific information
        additional_info = {
            'game_version': info.get('game_version', 'Unknown'),
            'eldewrito_version': info.get('eldewrito_version', 'Unknown'),
            'status': info.get('status', 'Unknown'),
            'host_player': info.get('host_player', ''),
            'teams': info.get('teams', False),
            'is_dedicated': info.get('is_dedicated', True),
            'variant': info.get('variant', 'none'),
            'variant_type': info.get('variant_type', 'none'),
            'mod_count': info.get('mod_count', 0),
            'mod_package_name': info.get('mod_package_name', ''),
            'sprint_state': info.get('sprint_state', '2'),
            'dual_wielding': info.get('dual_wielding', '1'),
            'assassination_enabled': info.get('assassination_enabled', '0'),
            'xnkid': info.get('xnkid', ''),
            'xnaddr': info.get('xnaddr', ''),
            'players': info.get('players', [])
        }
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=additional_info
        )
    
    def _standardize_generic_server(self, server_response) -> StandardizedServerInfo:
        """Fallback standardization for unknown server types"""
        info = server_response.server_info
        
        # Try to extract common fields with fallbacks
        name = info.get('name', info.get('hostname', f'Unknown {server_response.game_type} Server'))
        game = info.get('game', server_response.game_type.title())
        map_name = info.get('map', 'Unknown Map')
        players = info.get('players', 0)
        max_players = info.get('max_players', info.get('max_players', 0))
        version = str(info.get('version', info.get('game_version', 'Unknown')))
        password_protected = info.get('passworded', info.get('password_protected', False))
        
        return StandardizedServerInfo(
            name=name,
            game=game,
            map=map_name,
            players=players,
            max_players=max_players,
            version=version,
            password_protected=password_protected,
            ip_address=server_response.ip_address,
            port=server_response.port,
            game_type=server_response.game_type,
            response_time=server_response.response_time,
            additional_info=info
        )
    
    def format_server_summary(self, server_info: StandardizedServerInfo) -> str:
        """
        Format a standardized server info into a human-readable summary.
        
        Args:
            server_info: StandardizedServerInfo object
            
        Returns:
            Formatted string summary of the server
        """
        password_indicator = "🔒" if server_info.password_protected else "🔓"
        
        summary = (
            f"{password_indicator} **{server_info.name}**\n"
            f"🎮 Game: {server_info.game}\n"
            f"🗺️ Map: {server_info.map}\n"
            f"👥 Players: {server_info.players}/{server_info.max_players}\n"
            f"🌐 Address: {server_info.ip_address}:{server_info.port}\n"
            f"📦 Version: {server_info.version}"
        )
        
        # Add response time if available
        if server_info.response_time > 0:
            summary += f"\n⏱️ Response: {server_info.response_time:.2f}s"
        
        return summary
    
    def to_dict(self, server_info: StandardizedServerInfo) -> Dict[str, Any]:
        """
        Convert StandardizedServerInfo to dictionary for JSON serialization.
        
        Args:
            server_info: StandardizedServerInfo object
            
        Returns:
            Dictionary representation of the server info
        """
        return {
            'name': server_info.name,
            'game': server_info.game,
            'map': server_info.map,
            'players': server_info.players,
            'max_players': server_info.max_players,
            'version': server_info.version,
            'password_protected': server_info.password_protected,
            'ip_address': server_info.ip_address,
            'port': server_info.port,
            'game_type': server_info.game_type,
            'response_time': server_info.response_time,
            'additional_info': server_info.additional_info,
            'discord_fields': server_info.discord_fields
        }
    
    def from_dict(self, data: Dict[str, Any]) -> StandardizedServerInfo:
        """
        Create StandardizedServerInfo from dictionary.
        
        Args:
            data: Dictionary containing server information
            
        Returns:
            StandardizedServerInfo object
        """
        return StandardizedServerInfo(
            name=data.get('name', 'Unknown Server'),
            game=data.get('game', 'Unknown Game'),
            map=data.get('map', 'Unknown Map'),
            players=data.get('players', 0),
            max_players=data.get('max_players', 0),
            version=data.get('version', 'Unknown'),
            password_protected=data.get('password_protected', False),
            ip_address=data.get('ip_address', '0.0.0.0'),
            port=data.get('port', 0),
            game_type=data.get('game_type', 'unknown'),
            response_time=data.get('response_time', 0.0),
            additional_info=data.get('additional_info', {}),
            discord_fields=data.get('discord_fields', None)
        ) 