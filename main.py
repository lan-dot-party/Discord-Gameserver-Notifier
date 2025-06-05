"""
Discord Gameserver Notifier - Main Entry Point

This module serves as the entry point for the Discord Gameserver Notifier application.
It handles the main event loop, graceful shutdown, and error recovery.
"""

import asyncio
import signal
import sys
import os
from typing import Optional
import logging
from src.config.config_manager import ConfigManager
from src.utils.logger import LoggerSetup
from src.discovery.network_scanner import DiscoveryEngine, ServerResponse
from src.discovery.server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo
from src.database.database_manager import DatabaseManager

class GameServerNotifier:
    """Main application class for the Discord Gameserver Notifier."""
    
    def __init__(self):
        """Initialize the GameServerNotifier application."""
        self.config_manager = ConfigManager()
        self.logger = LoggerSetup.setup_logger(self.config_manager.config)
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Initialize server info wrapper for standardized server data
        self.server_wrapper = ServerInfoWrapper()
        
        # Initialize database manager
        try:
            db_path = self.config_manager.config.get('database', {}).get('path', './gameservers.db')
            self.database_manager = DatabaseManager(db_path)
            self.logger.info("Database manager initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database manager: {e}", exc_info=True)
            self.database_manager = None
        
        # Initialize discovery engine
        try:
            self.discovery_engine = DiscoveryEngine(self.config_manager.config)
            self.discovery_engine.set_callbacks(
                on_discovered=self._on_server_discovered,
                on_lost=self._on_server_lost
            )
            self.logger.info("Discovery engine initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize discovery engine: {e}", exc_info=True)
            self.discovery_engine = None
        
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
        
        # Periodic cleanup interval (every 10 minutes)
        cleanup_interval = 600  # 10 minutes in seconds
        last_cleanup = 0
        
        while self.running:
            try:
                # Periodic database cleanup
                if self.database_manager:
                    import time
                    current_time = time.time()
                    if current_time - last_cleanup >= cleanup_interval:
                        try:
                            cleanup_config = self.config_manager.config.get('database', {})
                            max_failed_attempts = cleanup_config.get('cleanup_after_fails', 5)
                            inactive_hours = cleanup_config.get('inactive_hours', 24)
                            
                            cleanup_count = self.database_manager.cleanup_inactive_servers(
                                max_failed_attempts=max_failed_attempts,
                                inactive_hours=inactive_hours
                            )
                            
                            if cleanup_count > 0:
                                self.logger.info(f"Database cleanup completed: {cleanup_count} servers marked inactive")
                            
                            # Log database statistics
                            stats = self.database_manager.get_database_stats()
                            self.logger.info(f"Database stats: {stats['active_servers']}/{stats['total_servers']} active servers")
                            
                            last_cleanup = current_time
                        except Exception as e:
                            self.logger.error(f"Error during database cleanup: {e}", exc_info=True)
                
                # TODO: Discord webhook processing will be implemented in future tasks
                # await self.webhook_manager.process_notifications()
                
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
                    max_failed_attempts = cleanup_config.get('cleanup_after_fails', 5)
                    inactive_hours = cleanup_config.get('inactive_hours', 24)
                    
                    final_cleanup_count = self.database_manager.cleanup_inactive_servers(
                        max_failed_attempts=max_failed_attempts,
                        inactive_hours=inactive_hours
                    )
                    
                    if final_cleanup_count > 0:
                        self.logger.info(f"Final database cleanup: {final_cleanup_count} servers marked inactive")
                    
                    # Log final database statistics
                    final_stats = self.database_manager.get_database_stats()
                    self.logger.info(f"Final database stats: {final_stats}")
                    
                    self.logger.info("Database manager closed successfully")
                except Exception as e:
                    self.logger.error(f"Error closing database manager: {e}", exc_info=True)
            
            # TODO: Discord webhook manager will be implemented in future tasks
            # await self.webhook_manager.close()
            
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
            # Standardize the server information using the wrapper
            standardized_server = self.server_wrapper.standardize_server_response(server)
            
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
            if self.database_manager:
                try:
                    server_model = self.database_manager.add_or_update_server(standardized_server)
                    self.logger.info(f"Server stored in database with ID: {server_model.id}")
                    
                    # Log if this is a new discovery vs update
                    if server_model.first_seen == server_model.last_seen:
                        self.logger.info(f"New server discovery recorded: {server_model.get_server_key()}")
                    else:
                        self.logger.debug(f"Server updated in database: {server_model.get_server_key()}")
                        
                except Exception as db_error:
                    self.logger.error(f"Failed to store server in database: {db_error}", exc_info=True)
            
            # TODO: In future tasks, this will also:
            # - Send Discord notification with formatted summary
            
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
        
        Args:
            server: The lost server information
        """
        try:
            # Standardize the server information using the wrapper
            standardized_server = self.server_wrapper.standardize_server_response(server)
            
            self.logger.info(f"Lost {standardized_server.game} server: {standardized_server.name}")
            self.logger.info(f"Server was at: {standardized_server.ip_address}:{standardized_server.port}")
            
            # Log the formatted server summary for better readability
            if self.logger.isEnabledFor(logging.DEBUG):
                summary = self.server_wrapper.format_server_summary(standardized_server)
                self.logger.debug(f"Lost server summary:\n{summary}")
            
            # Mark server as failed in database
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
            
            # TODO: In future tasks, this will also:
            # - Send Discord notification about server going offline
            
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
            
            # TODO: In future tasks, this will also:
            # - Send Discord notification about server going offline

def main():
    """Application entry point."""
    try:
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