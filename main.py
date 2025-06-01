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

class GameServerNotifier:
    """Main application class for the Discord Gameserver Notifier."""
    
    def __init__(self):
        """Initialize the GameServerNotifier application."""
        self.config_manager = ConfigManager()
        self.logger = LoggerSetup.setup_logger(self.config_manager.config)
        self.running = False
        self.shutdown_event = asyncio.Event()
        
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
        
        while self.running:
            try:
                # TODO: These will be implemented in future tasks
                # await self.discovery_engine.scan()
                # await self.database_manager.cleanup()
                # await self.webhook_manager.process_notifications()
                
                # Temporary placeholder for future implementations
                self.logger.debug("Main loop iteration - waiting for implementation")
                
                # Check for shutdown signal
                try:
                    await asyncio.wait_for(self.shutdown_event.wait(), timeout=1.0)
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
            # TODO: These will be implemented in future tasks
            # await self.discovery_engine.stop()
            # await self.database_manager.close()
            # await self.webhook_manager.close()
            
            # Temporary placeholder for future implementations
            self.logger.debug("Shutdown sequence - waiting for implementation")
            
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