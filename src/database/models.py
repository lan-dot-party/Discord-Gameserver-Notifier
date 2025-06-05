"""
Database models and schema definitions for the Discord Gameserver Notifier
"""

import sqlite3
import json
from typing import Dict, Any, Optional
from datetime import datetime
import logging


class DatabaseSchema:
    """
    Database schema definitions for SQLite database.
    Schema is designed to work with StandardizedServerInfo from server_info_wrapper.py
    """
    
    # Main gameservers table schema
    CREATE_GAMESERVERS_TABLE = """
    CREATE TABLE IF NOT EXISTS gameservers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        
        -- Server identification (unique constraint on ip+port combination)
        ip_address TEXT NOT NULL,
        port INTEGER NOT NULL,
        
        -- Standardized server information (from StandardizedServerInfo)
        name TEXT NOT NULL,
        game TEXT NOT NULL,
        map_name TEXT,
        players INTEGER DEFAULT 0,
        max_players INTEGER DEFAULT 0,
        version TEXT,
        password_protected BOOLEAN DEFAULT 0,
        game_type TEXT NOT NULL,
        response_time REAL DEFAULT 0.0,
        
        -- Protocol-specific additional information (JSON serialized)
        additional_info TEXT DEFAULT '{}',
        
        -- Tracking and management fields
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        failed_attempts INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT 1,
        
        -- Discord integration fields
        discord_message_id TEXT,
        discord_channel_id TEXT,
        discord_embed_sent BOOLEAN DEFAULT 0,
        
        -- Performance tracking
        avg_response_time REAL DEFAULT 0.0,
        total_queries INTEGER DEFAULT 1,
        
        -- Unique constraint to prevent duplicate servers
        UNIQUE(ip_address, port)
    );
    """
    
    # Index for faster queries
    CREATE_INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_gameservers_active ON gameservers(is_active);",
        "CREATE INDEX IF NOT EXISTS idx_gameservers_game_type ON gameservers(game_type);",
        "CREATE INDEX IF NOT EXISTS idx_gameservers_last_seen ON gameservers(last_seen);",
        "CREATE INDEX IF NOT EXISTS idx_gameservers_ip_port ON gameservers(ip_address, port);",
        "CREATE INDEX IF NOT EXISTS idx_gameservers_discord_message ON gameservers(discord_message_id);"
    ]
    
    # Server history table for tracking changes over time
    CREATE_SERVER_HISTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS server_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        
        -- Snapshot of server state
        name TEXT,
        map_name TEXT,
        players INTEGER,
        max_players INTEGER,
        version TEXT,
        response_time REAL,
        
        -- Change tracking
        change_type TEXT NOT NULL, -- 'discovered', 'updated', 'lost', 'player_change'
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        -- Additional context
        notes TEXT,
        
        FOREIGN KEY (server_id) REFERENCES gameservers (id) ON DELETE CASCADE
    );
    """
    
    # Index for server history
    CREATE_HISTORY_INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_server_history_server_id ON server_history(server_id);",
        "CREATE INDEX IF NOT EXISTS idx_server_history_timestamp ON server_history(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_server_history_change_type ON server_history(change_type);"
    ]


class GameServerModel:
    """
    Model class representing a game server in the database.
    Maps directly to the gameservers table and StandardizedServerInfo structure.
    """
    
    def __init__(self, 
                 id: Optional[int] = None,
                 ip_address: str = "",
                 port: int = 0,
                 name: str = "",
                 game: str = "",
                 map_name: str = "",
                 players: int = 0,
                 max_players: int = 0,
                 version: str = "",
                 password_protected: bool = False,
                 game_type: str = "",
                 response_time: float = 0.0,
                 additional_info: Dict[str, Any] = None,
                 first_seen: Optional[datetime] = None,
                 last_seen: Optional[datetime] = None,
                 last_updated: Optional[datetime] = None,
                 failed_attempts: int = 0,
                 is_active: bool = True,
                 discord_message_id: Optional[str] = None,
                 discord_channel_id: Optional[str] = None,
                 discord_embed_sent: bool = False,
                 avg_response_time: float = 0.0,
                 total_queries: int = 1):
        
        self.id = id
        self.ip_address = ip_address
        self.port = port
        self.name = name
        self.game = game
        self.map_name = map_name
        self.players = players
        self.max_players = max_players
        self.version = version
        self.password_protected = password_protected
        self.game_type = game_type
        self.response_time = response_time
        self.additional_info = additional_info or {}
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.last_updated = last_updated
        self.failed_attempts = failed_attempts
        self.is_active = is_active
        self.discord_message_id = discord_message_id
        self.discord_channel_id = discord_channel_id
        self.discord_embed_sent = discord_embed_sent
        self.avg_response_time = avg_response_time
        self.total_queries = total_queries
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'port': self.port,
            'name': self.name,
            'game': self.game,
            'map_name': self.map_name,
            'players': self.players,
            'max_players': self.max_players,
            'version': self.version,
            'password_protected': self.password_protected,
            'game_type': self.game_type,
            'response_time': self.response_time,
            'additional_info': self.additional_info,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'failed_attempts': self.failed_attempts,
            'is_active': self.is_active,
            'discord_message_id': self.discord_message_id,
            'discord_channel_id': self.discord_channel_id,
            'discord_embed_sent': self.discord_embed_sent,
            'avg_response_time': self.avg_response_time,
            'total_queries': self.total_queries
        }
    
    @classmethod
    def from_standardized_info(cls, server_info, existing_model=None):
        """
        Create or update GameServerModel from StandardizedServerInfo.
        
        Args:
            server_info: StandardizedServerInfo object from server_info_wrapper
            existing_model: Optional existing GameServerModel to update
            
        Returns:
            GameServerModel instance
        """
        now = datetime.now()
        
        if existing_model:
            # Update existing model
            existing_model.name = server_info.name
            existing_model.game = server_info.game
            existing_model.map_name = server_info.map
            existing_model.players = server_info.players
            existing_model.max_players = server_info.max_players
            existing_model.version = server_info.version
            existing_model.password_protected = server_info.password_protected
            existing_model.game_type = server_info.game_type
            existing_model.response_time = server_info.response_time
            existing_model.additional_info = server_info.additional_info
            existing_model.last_seen = now
            existing_model.last_updated = now
            existing_model.failed_attempts = 0  # Reset on successful query
            existing_model.is_active = True
            
            # Update average response time
            existing_model.total_queries += 1
            existing_model.avg_response_time = (
                (existing_model.avg_response_time * (existing_model.total_queries - 1) + 
                 server_info.response_time) / existing_model.total_queries
            )
            
            return existing_model
        else:
            # Create new model
            return cls(
                ip_address=server_info.ip_address,
                port=server_info.port,
                name=server_info.name,
                game=server_info.game,
                map_name=server_info.map,
                players=server_info.players,
                max_players=server_info.max_players,
                version=server_info.version,
                password_protected=server_info.password_protected,
                game_type=server_info.game_type,
                response_time=server_info.response_time,
                additional_info=server_info.additional_info,
                first_seen=now,
                last_seen=now,
                last_updated=now,
                avg_response_time=server_info.response_time
            )
    
    def get_server_key(self) -> str:
        """Get unique server identifier (ip:port)"""
        return f"{self.ip_address}:{self.port}"
    
    def __str__(self) -> str:
        """String representation of the server"""
        return f"{self.name} ({self.game}) at {self.ip_address}:{self.port}"
    
    def __repr__(self) -> str:
        """Debug representation of the server"""
        return (f"GameServerModel(id={self.id}, name='{self.name}', "
                f"game='{self.game}', address='{self.ip_address}:{self.port}', "
                f"players={self.players}/{self.max_players}, active={self.is_active})")


class ServerHistoryModel:
    """
    Model class for server history tracking.
    Records changes in server state over time.
    """
    
    def __init__(self,
                 id: Optional[int] = None,
                 server_id: int = 0,
                 name: Optional[str] = None,
                 map_name: Optional[str] = None,
                 players: Optional[int] = None,
                 max_players: Optional[int] = None,
                 version: Optional[str] = None,
                 response_time: Optional[float] = None,
                 change_type: str = "",
                 timestamp: Optional[datetime] = None,
                 notes: Optional[str] = None):
        
        self.id = id
        self.server_id = server_id
        self.name = name
        self.map_name = map_name
        self.players = players
        self.max_players = max_players
        self.version = version
        self.response_time = response_time
        self.change_type = change_type
        self.timestamp = timestamp or datetime.now()
        self.notes = notes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert history model to dictionary"""
        return {
            'id': self.id,
            'server_id': self.server_id,
            'name': self.name,
            'map_name': self.map_name,
            'players': self.players,
            'max_players': self.max_players,
            'version': self.version,
            'response_time': self.response_time,
            'change_type': self.change_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'notes': self.notes
        }


# Database utility functions
def serialize_additional_info(additional_info: Dict[str, Any]) -> str:
    """Serialize additional_info dictionary to JSON string for database storage"""
    try:
        return json.dumps(additional_info, default=str)
    except (TypeError, ValueError) as e:
        logging.warning(f"Failed to serialize additional_info: {e}")
        return "{}"


def deserialize_additional_info(json_str: str) -> Dict[str, Any]:
    """Deserialize JSON string back to dictionary"""
    try:
        return json.loads(json_str) if json_str else {}
    except (json.JSONDecodeError, TypeError) as e:
        logging.warning(f"Failed to deserialize additional_info: {e}")
        return {} 