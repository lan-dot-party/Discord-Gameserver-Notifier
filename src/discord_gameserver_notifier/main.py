"""
Discord Gameserver Notifier - Main Entry Point

This module serves as the entry point for the Discord Gameserver Notifier application.
It handles the main event loop, graceful shutdown, and error recovery.
"""

import asyncio
import signal
import sys
import os
import argparse
from typing import Optional, List, Tuple
import logging
try:
    from importlib.metadata import version as get_version
except ImportError:
    from importlib_metadata import version as get_version
from discord_gameserver_notifier.config.config_manager import ConfigManager
from discord_gameserver_notifier.utils.logger import LoggerSetup
from discord_gameserver_notifier.utils.network_filter import NetworkFilter
from discord_gameserver_notifier.discovery.network_scanner import DiscoveryEngine, ServerResponse
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo
from discord_gameserver_notifier.database.database_manager import DatabaseManager
from discord_gameserver_notifier.discord.webhook_manager import WebhookManager

class GameServerNotifier:
    """Main application class for the Discord Gameserver Notifier."""
    
    def __init__(self):
        """Initialize the GameServerNotifier application."""
        self.config_manager = ConfigManager()
        self.logger = LoggerSetup.setup_logger(self.config_manager.config)
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Initialize network filter for ignoring specific network ranges
        network_config = self.config_manager.config.get('network', {})
        ignore_ranges = network_config.get('ignore_ranges', [])
        self.network_filter = NetworkFilter(ignore_ranges)
        
        # Initialize database manager
        try:
            db_path = self.config_manager.config.get('database', {}).get('path', './gameservers.db')
            self.database_manager = DatabaseManager(db_path)
            self.logger.info("Database manager initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database manager: {e}", exc_info=True)
            self.database_manager = None
        
        # Initialize Discord webhook manager
        try:
            discord_config = self.config_manager.config.get('discord', {})
            webhook_url = discord_config.get('webhook_url')
            
            if webhook_url and webhook_url != "https://discord.com/api/webhooks/...":
                self.webhook_manager = WebhookManager(
                    webhook_url=webhook_url,
                    channel_id=discord_config.get('channel_id'),
                    mentions=discord_config.get('mentions', []),
                    game_mentions=discord_config.get('game_mentions', {})
                )
                
                # Test webhook connection
                if self.webhook_manager.test_webhook():
                    self.logger.info("Discord webhook manager initialized and tested successfully")
                else:
                    self.logger.warning("Discord webhook test failed - notifications may not work")
            else:
                self.logger.warning("Discord webhook URL not configured - Discord notifications disabled")
                self.webhook_manager = None
                
        except Exception as e:
            self.logger.error(f"Failed to initialize Discord webhook manager: {e}", exc_info=True)
            self.webhook_manager = None
        
        # Initialize discovery engine
        try:
            self.discovery_engine = DiscoveryEngine(self.config_manager.config)
            self.discovery_engine.set_callbacks(
                on_discovered=self._on_server_discovered,
                on_lost=self._on_server_lost,
                on_scan_complete=self._on_scan_complete
            )
            self.logger.info("Discovery engine initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize discovery engine: {e}", exc_info=True)
            self.discovery_engine = None
        
        # Initialize server info wrapper for standardized server data (AFTER discovery engine)
        # Pass protocols from the discovery engine's scanner for discord_fields support
        protocols = None
        if self.discovery_engine and hasattr(self.discovery_engine, 'scanner') and hasattr(self.discovery_engine.scanner, 'protocols'):
            protocols = self.discovery_engine.scanner.protocols
            self.logger.debug(f"ServerInfoWrapper initialized with protocols: {list(protocols.keys())}")
        else:
            self.logger.warning("Discovery engine or protocols not available - ServerInfoWrapper will not have discord_fields support")
            
        self.server_wrapper = ServerInfoWrapper(protocols=protocols)
        
        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle system signals for graceful shutdown."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received {signal_name} signal. Initiating graceful shutdown...")
        self.running = False
        self.shutdown_event.set()

    async def _error_recovery(self, error: Exception, context: str) -> None:
        """
        Handle errors and attempt recovery.
        
        Args:
            error: The exception that occurred
            context: Description of where the error occurred
        """
        self.logger.error(f"Error in {context}: {str(error)}", exc_info=True)
        
        try:
            # Implement recovery mechanisms based on error type
            if isinstance(error, (ConnectionError, TimeoutError)):
                self.logger.info("Network-related error detected. Waiting before retry...")
                await asyncio.sleep(30)  # Wait 30 seconds before retry
            else:
                self.logger.warning("Unhandled error type. Waiting before retry...")
                await asyncio.sleep(60)  # Wait 60 seconds for other types of errors
        except Exception as recovery_error:
            self.logger.error(f"Error during recovery attempt: {str(recovery_error)}", exc_info=True)

    async def _main_loop(self) -> None:
        """Main application loop."""
        self.logger.info("Starting main application loop...")
        self.running = True
        
        # Start the discovery engine
        if self.discovery_engine:
            try:
                await self.discovery_engine.start()
                self.logger.info("Discovery engine started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start discovery engine: {e}", exc_info=True)
        else:
            self.logger.warning("Discovery engine not available - skipping network scanning")
        
        # Periodic cleanup interval (configurable for responsive cleanup)
        cleanup_config = self.config_manager.config.get('database', {})
        cleanup_interval = cleanup_config.get('cleanup_interval', 60)  # 1 minute in seconds
        last_cleanup = 0
        
        while self.running:
            try:
                # Periodic database statistics logging
                if self.database_manager:
                    import time
                    current_time = time.time()
                    if current_time - last_cleanup >= cleanup_interval:
                        try:
                            # Log database statistics periodically
                            stats = self.database_manager.get_database_stats()
                            self.logger.info(f"📊 Database stats: {stats['active_servers']}/{stats['total_servers']} active servers")
                            
                            last_cleanup = current_time
                        except Exception as e:
                            self.logger.error(f"Error during periodic stats logging: {e}", exc_info=True)
                
                # Check for inactive servers and delete their Discord messages
                if self.database_manager and self.webhook_manager:
                    try:
                        await self._check_and_cleanup_inactive_servers()
                    except Exception as e:
                        self.logger.error(f"Error during inactive server check: {e}", exc_info=True)
                
                # The discovery engine runs in the background via its own task
                self.logger.debug("Main loop iteration - discovery engine running in background")
                
                # Check for shutdown signal with shorter timeout for more responsive cleanup
                try:
                    await asyncio.wait_for(self.shutdown_event.wait(), timeout=30.0)
                    if self.shutdown_event.is_set():
                        break
                except asyncio.TimeoutError:
                    continue
                    
            except Exception as e:
                await self._error_recovery(e, "main loop")
                if not self.running:  # Check if shutdown was requested during recovery
                    break

    async def shutdown(self) -> None:
        """Perform graceful shutdown operations."""
        self.logger.info("Shutting down...")
        
        try:
            # Stop the discovery engine
            if self.discovery_engine:
                try:
                    await self.discovery_engine.stop()
                    self.logger.info("Discovery engine stopped successfully")
                except Exception as e:
                    self.logger.error(f"Error stopping discovery engine: {e}", exc_info=True)
            
            # Close database manager
            if self.database_manager:
                try:
                    # Perform final cleanup before shutdown
                    cleanup_config = self.config_manager.config.get('database', {})
                    max_failed_attempts = cleanup_config.get('cleanup_after_fails', 3)
                    inactive_minutes = cleanup_config.get('inactive_minutes', 3)
                    
                    # Get servers that will be cleaned up (with Discord message IDs) before marking them inactive
                    servers_to_cleanup = self.database_manager.get_servers_to_cleanup(
                        max_failed_attempts=max_failed_attempts,
                        inactive_minutes=inactive_minutes
                    )
                    
                    # Delete Discord messages for servers that will be marked inactive
                    if servers_to_cleanup and self.webhook_manager:
                        for server in servers_to_cleanup:
                            if server.discord_message_id:
                                try:
                                    success = self.webhook_manager.delete_server_message(server.discord_message_id)
                                    if success:
                                        self.logger.info(f"Final cleanup: Deleted Discord message for inactive server: {server.name} ({server.ip_address}:{server.port})")
                                    else:
                                        self.logger.warning(f"Final cleanup: Failed to delete Discord message for server: {server.name}")
                                except Exception as discord_error:
                                    self.logger.error(f"Final cleanup: Error deleting Discord message for server {server.name}: {discord_error}", exc_info=True)
                    
                    final_cleanup_count = self.database_manager.cleanup_inactive_servers(
                        max_failed_attempts=max_failed_attempts,
                        inactive_minutes=inactive_minutes
                    )
                    
                    if final_cleanup_count > 0:
                        self.logger.info(f"Final database cleanup: {final_cleanup_count} servers marked inactive")
                    
                    # Log final database statistics
                    final_stats = self.database_manager.get_database_stats()
                    self.logger.info(f"Final database stats: {final_stats}")
                    
                    self.logger.info("Database manager closed successfully")
                except Exception as e:
                    self.logger.error(f"Error closing database manager: {e}", exc_info=True)
            
            # Close Discord webhook manager
            if self.webhook_manager:
                try:
                    self.logger.info("Discord webhook manager closed successfully")
                except Exception as e:
                    self.logger.error(f"Error closing Discord webhook manager: {e}", exc_info=True)
            
            self.logger.info("All components shut down successfully")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}", exc_info=True)
        finally:
            self.logger.info("Shutdown complete")

    async def run(self) -> None:
        """Run the application."""
        try:
            self.logger.info("Starting Discord Gameserver Notifier...")
            await self._main_loop()
        except Exception as e:
            self.logger.critical(f"Critical error in main application: {str(e)}", exc_info=True)
        finally:
            await self.shutdown()

    async def _on_server_discovered(self, server: ServerResponse) -> None:
        """
        Callback for when a new server is discovered.
        
        Args:
            server: The discovered server information
        """
        try:
            # Check if this server should be ignored based on network filtering
            if self.network_filter.should_ignore_server(server.ip_address, server.port):
                self.logger.info(f"🚫 Server {server.ip_address}:{server.port} ({server.game_type}) IGNORED by network filter - skipping database and Discord processing")
                return
            
            # Standardize the server information using the wrapper
            standardized_server = self.server_wrapper.standardize_server_response(server)
            self.logger.debug(f"Standardized server: {standardized_server.name} ({standardized_server.game})")
            
            self.logger.info(f"Discovered {standardized_server.game} server: {standardized_server.name}")
            self.logger.info(f"Server details: {standardized_server.ip_address}:{standardized_server.port}")
            self.logger.info(f"Players: {standardized_server.players}/{standardized_server.max_players}, Map: {standardized_server.map}")
            
            # Log the formatted server summary for better readability
            if self.logger.isEnabledFor(logging.DEBUG):
                summary = self.server_wrapper.format_server_summary(standardized_server)
                self.logger.debug(f"Server summary:\n{summary}")
                
                # Log additional protocol-specific information
                if standardized_server.additional_info:
                    self.logger.debug(f"Additional info: {standardized_server.additional_info}")
            
            # Store server in database
            is_new_server = False
            was_inactive_server = False
            if self.database_manager:
                try:
                    # Check if server was previously inactive before updating
                    existing_server = self.database_manager.get_server_by_address(
                        standardized_server.ip_address, 
                        standardized_server.port
                    )
                    if existing_server and not existing_server.is_active:
                        was_inactive_server = True
                        self.logger.info(f"Previously inactive server coming back online: {standardized_server.ip_address}:{standardized_server.port}")
                    
                    server_model = self.database_manager.add_or_update_server(standardized_server)
                    self.logger.info(f"Server stored in database with ID: {server_model.id}")
                    
                    # Check if this is a new discovery, update, or reactivated server
                    if server_model.first_seen == server_model.last_seen:
                        self.logger.info(f"New server discovery recorded: {server_model.get_server_key()}")
                        is_new_server = True
                    elif was_inactive_server:
                        self.logger.info(f"Inactive server reactivated - treating as new discovery: {server_model.get_server_key()}")
                        is_new_server = True  # Treat reactivated servers as new for Discord notifications
                    else:
                        self.logger.debug(f"Server updated in database: {server_model.get_server_key()}")
                        
                except Exception as db_error:
                    self.logger.error(f"Failed to store server in database: {db_error}", exc_info=True)
            
            # Send Discord notification for new server discoveries or servers without Discord message ID
            should_send_discord = False
            if is_new_server:
                should_send_discord = True
                self.logger.debug(f"Will send Discord notification: new server discovery")
            elif self.database_manager and server_model and not server_model.discord_message_id:
                should_send_discord = True
                self.logger.debug(f"Will send Discord notification: existing server without Discord message ID")
            
            if should_send_discord and self.webhook_manager:
                try:
                    message_id = self.webhook_manager.send_new_server_notification(standardized_server)
                    if message_id:
                        notification_type = "new server" if is_new_server else "existing server (first Discord notification)"
                        self.logger.info(f"Discord notification sent for {notification_type}: {standardized_server.name}")
                        
                        # Update database with Discord message ID for future reference
                        if self.database_manager:
                            try:
                                self.database_manager.update_discord_info_by_address(
                                    standardized_server.ip_address,
                                    standardized_server.port,
                                    message_id,
                                    self.webhook_manager.channel_id
                                )
                                self.logger.debug(f"Discord message ID stored in database: {message_id}")
                            except Exception as db_error:
                                self.logger.error(f"Failed to store Discord message ID: {db_error}", exc_info=True)
                    else:
                        self.logger.warning(f"Failed to send Discord notification for server: {standardized_server.name}")
                        
                except Exception as discord_error:
                    self.logger.error(f"Error sending Discord notification: {discord_error}", exc_info=True)
            
        except Exception as e:
            self.logger.error(f"Error processing discovered server {server.ip_address}:{server.port}: {e}", exc_info=True)
            # Fallback to original logging if standardization fails
            self.logger.info(f"Discovered {server.game_type} server: {server.ip_address}:{server.port} (raw data)")
            
            # Log game-specific details as fallback
            if server.game_type == 'source':
                self.logger.debug(f"Source server details: Name='{server.server_info.get('name', 'Unknown')}', "
                                f"Map='{server.server_info.get('map', 'Unknown')}', "
                                f"Players={server.server_info.get('players', 0)}/{server.server_info.get('max_players', 0)}")
            elif server.game_type == 'renegadex':
                self.logger.debug(f"RenegadeX server details: Name='{server.server_info.get('name', 'Unknown')}', "
                                f"Map='{server.server_info.get('map', 'Unknown')}', "
                                f"Players={server.server_info.get('players', 0)}/{server.server_info.get('max_players', 0)}, "
                                f"Version='{server.server_info.get('game_version', 'Unknown')}', "
                                f"Passworded={server.server_info.get('passworded', False)}")
            elif server.game_type == 'warcraft3':
                self.logger.debug(f"Warcraft3 server details: Name='{server.server_info.get('name', 'Unknown')}', "
                                f"Map='{server.server_info.get('map', 'Unknown')}', "
                                f"Players={server.server_info.get('players', 0)}/{server.server_info.get('max_players', 0)}, "
                                f"Product='{server.server_info.get('product', 'Unknown')}', "
                                f"Version={server.server_info.get('version', 'Unknown')}")
            elif server.game_type == 'flatout2':
                self.logger.debug(f"Flatout2 server details: Name='{server.server_info.get('hostname', 'Unknown')}', "
                                f"Flags={server.server_info.get('flags', '0')}, "
                                f"Status={server.server_info.get('status', '0')}, "
                                f"Timestamp={server.server_info.get('timestamp', '0')}")

    async def _on_server_lost(self, server: ServerResponse) -> None:
        """
        Callback for when a server is no longer responding.
        This method only marks the server as failed and does NOT delete Discord messages immediately.
        Discord messages are deleted by the cleanup process when failed_attempts reaches the configured threshold.
        
        Args:
            server: The lost server information
        """
        try:
            # Check if this server should be ignored based on network filtering
            # Note: We still process "lost" events for ignored servers in case they were
            # added to the database before the ignore rule was configured
            if self.network_filter.should_ignore_server(server.ip_address, server.port):
                self.logger.info(f"🚫 Lost server {server.ip_address}:{server.port} ({server.game_type}) IGNORED by network filter - skipping processing")
                return
            
            # Standardize the server information using the wrapper
            standardized_server = self.server_wrapper.standardize_server_response(server)
            
            self.logger.info(f"Lost {standardized_server.game} server: {standardized_server.name}")
            self.logger.info(f"Server was at: {standardized_server.ip_address}:{standardized_server.port}")
            
            # Log the formatted server summary for better readability
            if self.logger.isEnabledFor(logging.DEBUG):
                summary = self.server_wrapper.format_server_summary(standardized_server)
                self.logger.debug(f"Lost server summary:\n{summary}")
            
            # Mark server as failed in database (increment failed_attempts)
            if self.database_manager:
                try:
                    success = self.database_manager.mark_server_failed(
                        standardized_server.ip_address, 
                        standardized_server.port
                    )
                    if success:
                        self.logger.info(f"Server marked as failed in database: {standardized_server.ip_address}:{standardized_server.port}")
                    else:
                        self.logger.warning(f"Failed to mark server as failed (not found in database): {standardized_server.ip_address}:{standardized_server.port}")
                        
                except Exception as db_error:
                    self.logger.error(f"Database error when marking server as failed: {db_error}", exc_info=True)
            
            # NOTE: We do NOT delete Discord messages here immediately!
            # Discord messages are deleted by the cleanup process (_check_and_cleanup_inactive_servers)
            # when failed_attempts reaches the configured threshold (cleanup_after_fails).
            # This ensures that temporary network issues don't immediately remove Discord notifications.
            
        except Exception as e:
            self.logger.error(f"Error processing lost server {server.ip_address}:{server.port}: {e}", exc_info=True)
            # Fallback to original logging if standardization fails
            self.logger.info(f"Lost {server.game_type} server: {server.ip_address}:{server.port} (raw data)")
            
            # Mark server as failed in database (fallback for raw data)
            if self.database_manager:
                try:
                    success = self.database_manager.mark_server_failed(server.ip_address, server.port)
                    if success:
                        self.logger.info(f"Server marked as failed in database (fallback): {server.ip_address}:{server.port}")
                    else:
                        self.logger.warning(f"Failed to mark server as failed (not found in database, fallback): {server.ip_address}:{server.port}")
                        
                except Exception as db_error:
                    self.logger.error(f"Database error when marking server as failed (fallback): {db_error}", exc_info=True)

    async def _on_scan_complete(self, found_servers: List[ServerResponse], lost_servers: List[ServerResponse]) -> None:
        """
        Callback for when a scan is complete.
        Updates failed_attempts for servers that were not found in the scan.
        
        Args:
            found_servers: List of ServerResponse objects for servers found in the scan
            lost_servers: List of ServerResponse objects for servers that were lost in the scan
        """
        try:
            if self.database_manager:
                # Convert ServerResponse objects to (ip_address, port) tuples
                found_server_tuples = [(server.ip_address, server.port) for server in found_servers]
                
                # Increment failed_attempts for servers that were not found
                updated_count = self.database_manager.increment_failed_attempts_for_missing_servers(found_server_tuples)
                if updated_count > 0:
                    self.logger.debug(f"Updated failed_attempts for {updated_count} missing servers")
        except Exception as e:
            self.logger.error(f"Error processing scan completion: {e}", exc_info=True)

    async def _check_and_cleanup_inactive_servers(self) -> None:
        """
        Check for servers that should be marked inactive and delete their Discord messages.
        This runs continuously in the main loop to provide immediate cleanup.
        """
        try:
            cleanup_config = self.config_manager.config.get('database', {})
            max_failed_attempts = cleanup_config.get('cleanup_after_fails', 3)
            inactive_minutes = cleanup_config.get('inactive_minutes', 3)
            
            self.logger.debug(f"Checking for inactive servers (failed_attempts >= {max_failed_attempts} OR inactive > {inactive_minutes} min)")
            
            # Get servers that should be cleaned up
            servers_to_cleanup = self.database_manager.get_servers_to_cleanup(
                max_failed_attempts=max_failed_attempts,
                inactive_minutes=inactive_minutes
            )
            
            if servers_to_cleanup:
                self.logger.debug(f"Found {len(servers_to_cleanup)} servers that need cleanup")
                
                # Delete Discord messages for servers that will be marked inactive
                discord_deletions = 0
                for server in servers_to_cleanup:
                    if server.discord_message_id:
                        try:
                            self.logger.debug(f"Attempting to delete Discord message for server: {server.name} ({server.ip_address}:{server.port}) - Message ID: {server.discord_message_id}")
                            success = self.webhook_manager.delete_server_message(server.discord_message_id)
                            if success:
                                discord_deletions += 1
                                self.logger.info(f"✅ Deleted Discord message for inactive server: {server.name} ({server.ip_address}:{server.port})")
                            else:
                                self.logger.warning(f"❌ Failed to delete Discord message for server: {server.name} ({server.ip_address}:{server.port})")
                        except Exception as discord_error:
                            self.logger.error(f"Error deleting Discord message for server {server.name}: {discord_error}", exc_info=True)
                    else:
                        self.logger.debug(f"Server {server.name} ({server.ip_address}:{server.port}) has no Discord message ID to delete")
                
                # Mark servers as inactive in database
                cleanup_count = self.database_manager.cleanup_inactive_servers(
                    max_failed_attempts=max_failed_attempts,
                    inactive_minutes=inactive_minutes
                )
                
                if cleanup_count > 0:
                    self.logger.info(f"🧹 Marked {cleanup_count} servers as inactive (Discord messages deleted: {discord_deletions})")
                    
                    # Log details about cleaned up servers
                    for server in servers_to_cleanup:
                        self.logger.debug(f"Cleaned up server: {server.name} ({server.ip_address}:{server.port}) - failed_attempts: {server.failed_attempts}, last_seen: {server.last_seen}")
                
            else:
                self.logger.debug("No servers need cleanup at this time")
                
        except Exception as e:
            self.logger.error(f"Error in inactive server cleanup check: {e}", exc_info=True)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Discord Gameserver Notifier - Automatic detection of game servers with Discord notifications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file search order:
  1. --config <path> (command line argument)
  2. DGN_CONFIG environment variable
  3. /etc/dgn/config.yaml (system-wide)
  4. ~/.config/dgn/config.yaml (user config)
  5. config/config.yaml (repository fallback)

Examples:
  %(prog)s                           # Use default config search
  %(prog)s --config /path/to/config.yaml
  DGN_CONFIG=/etc/dgn/config.yaml %(prog)s
        """
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (overrides default search order)'
    )
    
    # Get version dynamically from package metadata
    try:
        package_version = get_version('Discord-Gameserver-Notifier')
        version_string = f'Discord Gameserver Notifier {package_version}'
    except Exception:
        # Fallback if package metadata is not available
        version_string = 'Discord Gameserver Notifier (development version)'
    
    parser.add_argument(
        '--version',
        action='version',
        version=version_string
    )
    
    return parser.parse_args()

def main():
    """Application entry point."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Create and run the application
        app = GameServerNotifier()
        asyncio.run(app.run())
    except KeyboardInterrupt:
        print("\nShutdown requested via keyboard interrupt")
    except Exception as e:
        print(f"Fatal error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 