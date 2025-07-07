"""
Database Manager for Discord Gameserver Notifier
Handles all database operations for game servers and their history.
"""

import sqlite3
import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager
import threading
import os

from .models import (
    DatabaseSchema, 
    GameServerModel, 
    ServerHistoryModel,
    serialize_additional_info,
    deserialize_additional_info
)
from ..discovery.server_info_wrapper import StandardizedServerInfo


class DatabaseManager:
    """
    Manages all database operations for game server tracking.
    Thread-safe implementation with connection pooling.
    """
    
    def __init__(self, db_path: str = "./gameservers.db"):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.logger = logging.getLogger("GameServerNotifier.DatabaseManager")
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        
        # Ensure database directory exists
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        # Initialize database schema
        self._initialize_database()
        
        self.logger.info(f"DatabaseManager initialized with database: {db_path}")
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections with proper error handling.
        Thread-safe connection management.
        """
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,  # 30 second timeout
                check_same_thread=False  # Allow multi-threading
            )
            conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
            conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _initialize_database(self):
        """Initialize database schema and indexes with migration support"""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Check if we need to migrate from old schema
                    self._migrate_database_if_needed(conn)
                    
                    # Create main tables
                    conn.execute(DatabaseSchema.CREATE_GAMESERVERS_TABLE)
                    conn.execute(DatabaseSchema.CREATE_SERVER_HISTORY_TABLE)
                    
                    # Create indexes
                    for index_sql in DatabaseSchema.CREATE_INDEXES:
                        conn.execute(index_sql)
                    
                    for index_sql in DatabaseSchema.CREATE_HISTORY_INDEXES:
                        conn.execute(index_sql)
                    
                    conn.commit()
                    self.logger.info("Database schema initialized successfully")
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to initialize database: {e}")
                raise
    
    def _migrate_database_if_needed(self, conn: sqlite3.Connection):
        """Check and migrate database schema if needed"""
        try:
            # Check if gameservers table exists and get its schema
            cursor = conn.execute("""
                SELECT sql FROM sqlite_master 
                WHERE type='table' AND name='gameservers'
            """)
            result = cursor.fetchone()
            
            if result:
                schema_sql = result[0]
                self.logger.debug(f"Existing schema: {schema_sql}")
                
                # Check if old schema (has server_name instead of name)
                if 'server_name' in schema_sql and 'name TEXT NOT NULL' not in schema_sql:
                    self.logger.info("Detected old database schema. Performing migration...")
                    self._migrate_from_old_schema(conn)
                    
        except sqlite3.Error as e:
            self.logger.warning(f"Error checking database schema for migration: {e}")
            # Continue with normal initialization
    
    def _migrate_from_old_schema(self, conn: sqlite3.Connection):
        """Migrate from old database schema to new schema"""
        try:
            # Backup old data
            self.logger.info("Backing up existing server data...")
            cursor = conn.execute("SELECT * FROM gameservers")
            old_servers = cursor.fetchall()
            
            # Drop old table and indexes
            self.logger.info("Dropping old table and recreating with new schema...")
            conn.execute("DROP TABLE IF EXISTS gameservers")
            
            # Drop old indexes if they exist
            old_indexes = [
                "idx_gameservers_active",
                "idx_gameservers_game_type", 
                "idx_gameservers_last_seen",
                "idx_gameservers_ip_port",
                "idx_gameservers_discord_message"
            ]
            
            for index_name in old_indexes:
                try:
                    conn.execute(f"DROP INDEX IF EXISTS {index_name}")
                except sqlite3.Error:
                    pass  # Index might not exist
            
            # Create new table with new schema
            conn.execute(DatabaseSchema.CREATE_GAMESERVERS_TABLE)
            
            # Migrate old data to new schema
            if old_servers:
                self.logger.info(f"Migrating {len(old_servers)} servers to new schema...")
                
                for old_server in old_servers:
                    try:
                        # Map old columns to new columns
                        migrated_data = {
                            'ip_address': old_server[1] if len(old_server) > 1 else '',
                            'port': old_server[2] if len(old_server) > 2 else 0,
                            'name': old_server[4] if len(old_server) > 4 else 'Unknown Server',  # server_name -> name
                            'game': 'Unknown Game',  # New field, set default
                            'map_name': old_server[7] if len(old_server) > 7 else '',
                            'players': old_server[5] if len(old_server) > 5 else 0,  # current_players -> players
                            'max_players': old_server[6] if len(old_server) > 6 else 0,
                            'version': 'Unknown',  # New field, set default
                            'password_protected': False,  # New field, set default
                            'game_type': old_server[3] if len(old_server) > 3 else 'unknown',
                            'response_time': 0.0,  # New field, set default
                            'additional_info': '{}',  # New field, set default
                            'first_seen': old_server[9] if len(old_server) > 9 else 'CURRENT_TIMESTAMP',
                            'last_seen': old_server[10] if len(old_server) > 10 else 'CURRENT_TIMESTAMP',
                            'last_updated': 'CURRENT_TIMESTAMP',  # New field
                            'failed_attempts': old_server[11] if len(old_server) > 11 else 0,
                            'is_active': old_server[14] if len(old_server) > 14 else 1,
                            'discord_message_id': old_server[12] if len(old_server) > 12 else None,
                            'discord_channel_id': old_server[13] if len(old_server) > 13 else None,
                            'discord_embed_sent': False,  # New field, set default
                            'avg_response_time': 0.0,  # New field, set default
                            'total_queries': 1  # New field, set default
                        }
                        
                        # Insert migrated data
                        conn.execute("""
                            INSERT INTO gameservers (
                                ip_address, port, name, game, map_name, players, max_players,
                                version, password_protected, game_type, response_time, additional_info,
                                first_seen, last_seen, last_updated, failed_attempts, is_active,
                                discord_message_id, discord_channel_id, discord_embed_sent,
                                avg_response_time, total_queries
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            migrated_data['ip_address'], migrated_data['port'], migrated_data['name'],
                            migrated_data['game'], migrated_data['map_name'], migrated_data['players'],
                            migrated_data['max_players'], migrated_data['version'], migrated_data['password_protected'],
                            migrated_data['game_type'], migrated_data['response_time'], migrated_data['additional_info'],
                            migrated_data['first_seen'], migrated_data['last_seen'], migrated_data['last_updated'],
                            migrated_data['failed_attempts'], migrated_data['is_active'], migrated_data['discord_message_id'],
                            migrated_data['discord_channel_id'], migrated_data['discord_embed_sent'],
                            migrated_data['avg_response_time'], migrated_data['total_queries']
                        ))
                        
                    except sqlite3.Error as e:
                        self.logger.warning(f"Failed to migrate server record: {e}")
                        continue
                
                self.logger.info("Database migration completed successfully")
            
            conn.commit()
            
        except sqlite3.Error as e:
            self.logger.error(f"Database migration failed: {e}")
            conn.rollback()
            raise
    
    def add_or_update_server(self, server_info: StandardizedServerInfo) -> GameServerModel:
        """
        Add a new server or update an existing one.
        
        Args:
            server_info: StandardizedServerInfo object from server discovery
            
        Returns:
            GameServerModel: The created or updated server model
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Check if server already exists
                    existing_server = self._get_server_by_address(
                        conn, server_info.ip_address, server_info.port
                    )
                    
                    if existing_server:
                        # Update existing server
                        updated_model = GameServerModel.from_standardized_info(
                            server_info, existing_server
                        )
                        self._update_server_in_db(conn, updated_model)
                        
                        # Record history if significant changes occurred
                        if self._has_significant_changes(existing_server, updated_model):
                            self._add_server_history(
                                conn, updated_model.id, "updated", 
                                f"Server updated: {updated_model.name}"
                            )
                        
                        self.logger.debug(f"Updated server: {updated_model}")
                        return updated_model
                    else:
                        # Add new server
                        new_model = GameServerModel.from_standardized_info(server_info)
                        server_id = self._insert_server_to_db(conn, new_model)
                        new_model.id = server_id
                        
                        # Record discovery in history
                        self._add_server_history(
                            conn, server_id, "discovered",
                            f"New server discovered: {new_model.name}"
                        )
                        
                        self.logger.info(f"Added new server: {new_model}")
                        return new_model
                        
            except sqlite3.Error as e:
                self.logger.error(f"Failed to add/update server {server_info.ip_address}:{server_info.port}: {e}")
                raise
    
    def get_server_by_address(self, ip_address: str, port: int) -> Optional[GameServerModel]:
        """
        Get server by IP address and port.
        
        Args:
            ip_address: Server IP address
            port: Server port
            
        Returns:
            GameServerModel or None if not found
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    return self._get_server_by_address(conn, ip_address, port)
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get server {ip_address}:{port}: {e}")
                return None
    
    def get_all_active_servers(self) -> List[GameServerModel]:
        """
        Get all active servers from the database.
        
        Returns:
            List of active GameServerModel objects
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        SELECT * FROM gameservers 
                        WHERE is_active = 1 
                        ORDER BY last_seen DESC
                    """)
                    
                    servers = []
                    for row in cursor.fetchall():
                        server = self._row_to_gameserver_model(row)
                        servers.append(server)
                    
                    self.logger.debug(f"Retrieved {len(servers)} active servers")
                    return servers
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get active servers: {e}")
                return []
    
    def get_servers_by_game_type(self, game_type: str) -> List[GameServerModel]:
        """
        Get all servers of a specific game type.
        
        Args:
            game_type: Game type to filter by
            
        Returns:
            List of GameServerModel objects
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        SELECT * FROM gameservers 
                        WHERE game_type = ? AND is_active = 1
                        ORDER BY last_seen DESC
                    """, (game_type,))
                    
                    servers = []
                    for row in cursor.fetchall():
                        server = self._row_to_gameserver_model(row)
                        servers.append(server)
                    
                    return servers
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get servers by game type {game_type}: {e}")
                return []
    
    def mark_server_failed(self, ip_address: str, port: int) -> bool:
        """
        Mark a server as failed (increment failed attempts).
        
        Args:
            ip_address: Server IP address
            port: Server port
            
        Returns:
            True if server was marked as failed, False otherwise
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        UPDATE gameservers 
                        SET failed_attempts = failed_attempts + 1,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE ip_address = ? AND port = ?
                    """, (ip_address, port))
                    
                    if cursor.rowcount > 0:
                        self.logger.debug(f"Marked server {ip_address}:{port} as failed")
                        return True
                    return False
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to mark server as failed {ip_address}:{port}: {e}")
                return False
    
    def cleanup_inactive_servers(self, max_failed_attempts: int = 3, 
                                inactive_minutes: int = 3) -> int:
        """
        Clean up servers that have been inactive or failed too many times.
        
        Args:
            max_failed_attempts: Maximum failed attempts before marking inactive (default: 3)
            inactive_minutes: Minutes of inactivity before cleanup (default: 3 minutes)
            
        Returns:
            Number of servers cleaned up
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cutoff_time = datetime.now() - timedelta(minutes=inactive_minutes)
                    
                    # Get servers to be cleaned up for history logging
                    cursor = conn.execute("""
                        SELECT id, name, ip_address, port FROM gameservers
                        WHERE (failed_attempts >= ? OR last_seen < ?) AND is_active = 1
                    """, (max_failed_attempts, cutoff_time))
                    
                    servers_to_cleanup = cursor.fetchall()
                    
                    # Mark servers as inactive
                    cursor = conn.execute("""
                        UPDATE gameservers 
                        SET is_active = 0, last_updated = CURRENT_TIMESTAMP
                        WHERE (failed_attempts >= ? OR last_seen < ?) AND is_active = 1
                    """, (max_failed_attempts, cutoff_time))
                    
                    cleanup_count = cursor.rowcount
                    
                    # Add history entries for cleaned up servers
                    for server in servers_to_cleanup:
                        self._add_server_history(
                            conn, server['id'], "lost",
                            f"Server marked inactive: {server['name']} at {server['ip_address']}:{server['port']}"
                        )
                    
                    conn.commit()
                    
                    if cleanup_count > 0:
                        self.logger.info(f"Cleaned up {cleanup_count} inactive servers")
                    
                    return cleanup_count
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to cleanup inactive servers: {e}")
                return 0
    
    def get_servers_to_cleanup(self, max_failed_attempts: int = 3, 
                              inactive_minutes: int = 3) -> List[GameServerModel]:
        """
        Get servers that will be cleaned up (marked as inactive) with their Discord message IDs.
        This method should be called before cleanup_inactive_servers to get Discord message IDs for deletion.
        
        Args:
            max_failed_attempts: Maximum failed attempts before marking inactive (default: 3)
            inactive_minutes: Minutes of inactivity before cleanup (default: 3 minutes)
            
        Returns:
            List of GameServerModel objects that will be cleaned up
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cutoff_time = datetime.now() - timedelta(minutes=inactive_minutes)
                    
                    # Get servers that will be cleaned up
                    cursor = conn.execute("""
                        SELECT * FROM gameservers
                        WHERE (failed_attempts >= ? OR last_seen < ?) AND is_active = 1
                    """, (max_failed_attempts, cutoff_time))
                    
                    servers_to_cleanup = []
                    for row in cursor.fetchall():
                        server_model = self._row_to_gameserver_model(row)
                        servers_to_cleanup.append(server_model)
                    
                    return servers_to_cleanup
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get servers to cleanup: {e}")
                return []
    
    def update_discord_info(self, server_id: int, message_id: str, 
                           channel_id: str, embed_sent: bool = True) -> bool:
        """
        Update Discord message information for a server.
        
        Args:
            server_id: Database ID of the server
            message_id: Discord message ID
            channel_id: Discord channel ID
            embed_sent: Whether embed was successfully sent
            
        Returns:
            True if update was successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        UPDATE gameservers 
                        SET discord_message_id = ?, 
                            discord_channel_id = ?,
                            discord_embed_sent = ?,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (message_id, channel_id, embed_sent, server_id))
                    
                    success = cursor.rowcount > 0
                    if success:
                        conn.commit()
                        self.logger.debug(f"Updated Discord info for server ID {server_id}")
                    
                    return success
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to update Discord info for server {server_id}: {e}")
                return False
    
    def update_discord_info_by_address(self, ip_address: str, port: int, message_id: str, 
                                     channel_id: str, embed_sent: bool = True) -> bool:
        """
        Update Discord message information for a server by IP address and port.
        
        Args:
            ip_address: Server IP address
            port: Server port
            message_id: Discord message ID
            channel_id: Discord channel ID
            embed_sent: Whether embed was successfully sent
            
        Returns:
            True if update was successful
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        UPDATE gameservers 
                        SET discord_message_id = ?, 
                            discord_channel_id = ?,
                            discord_embed_sent = ?,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE ip_address = ? AND port = ?
                    """, (message_id, channel_id, embed_sent, ip_address, port))
                    
                    success = cursor.rowcount > 0
                    if success:
                        conn.commit()
                        self.logger.debug(f"Updated Discord info for server {ip_address}:{port}")
                    else:
                        self.logger.warning(f"No server found to update Discord info: {ip_address}:{port}")
                    
                    return success
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to update Discord info for server {ip_address}:{port}: {e}")
                return False
    
    def get_server_history(self, server_id: int, limit: int = 50) -> List[ServerHistoryModel]:
        """
        Get history entries for a specific server.
        
        Args:
            server_id: Database ID of the server
            limit: Maximum number of history entries to return
            
        Returns:
            List of ServerHistoryModel objects
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        SELECT * FROM server_history 
                        WHERE server_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (server_id, limit))
                    
                    history = []
                    for row in cursor.fetchall():
                        history_entry = self._row_to_history_model(row)
                        history.append(history_entry)
                    
                    return history
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get server history for {server_id}: {e}")
                return []
    
    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    stats = {}
                    
                    # Total servers
                    cursor = conn.execute("SELECT COUNT(*) as total FROM gameservers")
                    stats['total_servers'] = cursor.fetchone()['total']
                    
                    # Active servers
                    cursor = conn.execute("SELECT COUNT(*) as active FROM gameservers WHERE is_active = 1")
                    stats['active_servers'] = cursor.fetchone()['active']
                    
                    # Servers by game type
                    cursor = conn.execute("""
                        SELECT game_type, COUNT(*) as count 
                        FROM gameservers 
                        WHERE is_active = 1 
                        GROUP BY game_type
                    """)
                    stats['servers_by_game_type'] = {row['game_type']: row['count'] for row in cursor.fetchall()}
                    
                    # History entries
                    cursor = conn.execute("SELECT COUNT(*) as total FROM server_history")
                    stats['total_history_entries'] = cursor.fetchone()['total']
                    
                    return stats
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to get database stats: {e}")
                return {}
    
    def increment_failed_attempts_for_missing_servers(self, found_servers: List[Tuple[str, int]]) -> int:
        """
        Increment failed_attempts for servers that were not found in the current scan.
        This method should be called after each scan with the list of servers that were found.
        
        Args:
            found_servers: List of (ip_address, port) tuples for servers that were found in the current scan
            
        Returns:
            Number of servers that had their failed_attempts incremented
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Get all active servers from database
                    cursor = conn.execute("""
                        SELECT ip_address, port FROM gameservers 
                        WHERE is_active = 1
                    """)
                    
                    all_active_servers = [(row['ip_address'], row['port']) for row in cursor.fetchall()]
                    
                    # Find servers that were not found in the current scan
                    found_servers_set = set(found_servers)
                    missing_servers = [server for server in all_active_servers if server not in found_servers_set]
                    
                    if not missing_servers:
                        return 0
                    
                    # Increment failed_attempts for missing servers
                    updated_count = 0
                    for ip_address, port in missing_servers:
                        cursor = conn.execute("""
                            UPDATE gameservers 
                            SET failed_attempts = failed_attempts + 1,
                                last_updated = CURRENT_TIMESTAMP
                            WHERE ip_address = ? AND port = ? AND is_active = 1
                        """, (ip_address, port))
                        
                        if cursor.rowcount > 0:
                            updated_count += 1
                            self.logger.debug(f"Incremented failed_attempts for missing server: {ip_address}:{port}")
                    
                    conn.commit()
                    
                    if updated_count > 0:
                        self.logger.info(f"Incremented failed_attempts for {updated_count} missing servers")
                    
                    return updated_count
                    
            except sqlite3.Error as e:
                self.logger.error(f"Failed to increment failed_attempts for missing servers: {e}")
                return 0
    
    # Private helper methods
    
    def _get_server_by_address(self, conn: sqlite3.Connection, 
                              ip_address: str, port: int) -> Optional[GameServerModel]:
        """Get server by address from database connection"""
        cursor = conn.execute("""
            SELECT * FROM gameservers 
            WHERE ip_address = ? AND port = ?
        """, (ip_address, port))
        
        row = cursor.fetchone()
        return self._row_to_gameserver_model(row) if row else None
    
    def _insert_server_to_db(self, conn: sqlite3.Connection, server: GameServerModel) -> int:
        """Insert new server to database"""
        cursor = conn.execute("""
            INSERT INTO gameservers (
                ip_address, port, name, game, map_name, players, max_players,
                version, password_protected, game_type, response_time, additional_info,
                first_seen, last_seen, last_updated, failed_attempts, is_active,
                avg_response_time, total_queries
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            server.ip_address, server.port, server.name, server.game, server.map_name,
            server.players, server.max_players, server.version, server.password_protected,
            server.game_type, server.response_time, serialize_additional_info(server.additional_info),
            server.first_seen, server.last_seen, server.last_updated, server.failed_attempts,
            server.is_active, server.avg_response_time, server.total_queries
        ))
        
        conn.commit()
        return cursor.lastrowid
    
    def _update_server_in_db(self, conn: sqlite3.Connection, server: GameServerModel):
        """Update existing server in database"""
        conn.execute("""
            UPDATE gameservers SET
                name = ?, game = ?, map_name = ?, players = ?, max_players = ?,
                version = ?, password_protected = ?, game_type = ?, response_time = ?,
                additional_info = ?, last_seen = ?, last_updated = ?, failed_attempts = ?,
                is_active = ?, avg_response_time = ?, total_queries = ?
            WHERE id = ?
        """, (
            server.name, server.game, server.map_name, server.players, server.max_players,
            server.version, server.password_protected, server.game_type, server.response_time,
            serialize_additional_info(server.additional_info), server.last_seen, server.last_updated,
            server.failed_attempts, server.is_active, server.avg_response_time, server.total_queries,
            server.id
        ))
        
        conn.commit()
    
    def _add_server_history(self, conn: sqlite3.Connection, server_id: int, 
                           change_type: str, notes: str = None):
        """Add entry to server history"""
        conn.execute("""
            INSERT INTO server_history (server_id, change_type, timestamp, notes)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?)
        """, (server_id, change_type, notes))
    
    def _has_significant_changes(self, old_server: GameServerModel, 
                                new_server: GameServerModel) -> bool:
        """Check if server has significant changes worth logging"""
        return (
            old_server.name != new_server.name or
            old_server.map_name != new_server.map_name or
            abs(old_server.players - new_server.players) >= 2 or  # Player count change threshold
            old_server.version != new_server.version
        )
    
    def _row_to_gameserver_model(self, row: sqlite3.Row) -> GameServerModel:
        """Convert database row to GameServerModel"""
        return GameServerModel(
            id=row['id'],
            ip_address=row['ip_address'],
            port=row['port'],
            name=row['name'],
            game=row['game'],
            map_name=row['map_name'],
            players=row['players'],
            max_players=row['max_players'],
            version=row['version'],
            password_protected=bool(row['password_protected']),
            game_type=row['game_type'],
            response_time=row['response_time'],
            additional_info=deserialize_additional_info(row['additional_info']),
            first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
            last_seen=datetime.fromisoformat(row['last_seen']) if row['last_seen'] else None,
            last_updated=datetime.fromisoformat(row['last_updated']) if row['last_updated'] else None,
            failed_attempts=row['failed_attempts'],
            is_active=bool(row['is_active']),
            discord_message_id=row['discord_message_id'],
            discord_channel_id=row['discord_channel_id'],
            discord_embed_sent=bool(row['discord_embed_sent']),
            avg_response_time=row['avg_response_time'],
            total_queries=row['total_queries']
        )
    
    def _row_to_history_model(self, row: sqlite3.Row) -> ServerHistoryModel:
        """Convert database row to ServerHistoryModel"""
        return ServerHistoryModel(
            id=row['id'],
            server_id=row['server_id'],
            name=row['name'],
            map_name=row['map_name'],
            players=row['players'],
            max_players=row['max_players'],
            version=row['version'],
            response_time=row['response_time'],
            change_type=row['change_type'],
            timestamp=datetime.fromisoformat(row['timestamp']) if row['timestamp'] else None,
            notes=row['notes']
        ) 