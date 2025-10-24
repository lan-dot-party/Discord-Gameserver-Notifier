"""
API Server for Discord Gameserver Notifier

Provides a read-only HTTP REST API for querying game server information.
Uses aiohttp for async HTTP server implementation.

Security:
- Read-only access (no write operations)
- SQLite connection in read-only mode
- No authentication required (designed for local network use)
"""

import logging
import sqlite3
import json
from typing import Dict, Any, List, Optional
from aiohttp import web
import asyncio
from contextlib import closing


class APIServer:
    """
    HTTP API Server for querying game server information.
    Provides read-only access to the gameservers database.
    """
    
    def __init__(self, db_path: str, host: str = '0.0.0.0', port: int = 8080):
        """
        Initialize API Server.
        
        Args:
            db_path: Path to SQLite database
            host: Host address to bind to (default: 0.0.0.0 for all interfaces)
            port: Port to listen on (default: 8080)
        """
        self.db_path = db_path
        self.host = host
        self.port = port
        self.logger = logging.getLogger("GameServerNotifier.APIServer")
        self.app = None
        self.runner = None
        self.site = None
        
        self.logger.info(f"API Server initialized - will listen on {host}:{port}")
    
    def _get_db_connection(self) -> sqlite3.Connection:
        """
        Get read-only database connection.
        
        Returns:
            sqlite3.Connection: Read-only database connection
        """
        # Open database in read-only mode for security
        conn = sqlite3.connect(f'file:{self.db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    
    async def handle_servers(self, request: web.Request) -> web.Response:
        """
        Handle GET /servers endpoint.
        Returns all active game servers.
        
        Args:
            request: aiohttp request object
            
        Returns:
            JSON response with active servers
        """
        try:
            # Run database query in thread pool to avoid blocking
            servers = await asyncio.get_event_loop().run_in_executor(
                None, 
                self._get_active_servers
            )
            
            self.logger.debug(f"API request: /servers - returned {len(servers)} active servers")
            
            return web.json_response({
                'success': True,
                'count': len(servers),
                'servers': servers
            })
            
        except Exception as e:
            self.logger.error(f"Error handling /servers request: {e}", exc_info=True)
            return web.json_response({
                'success': False,
                'error': 'Internal server error'
            }, status=500)
    
    def _get_active_servers(self) -> List[Dict[str, Any]]:
        """
        Query database for all active servers.
        
        Returns:
            List of server dictionaries
        """
        with closing(self._get_db_connection()) as conn:
            cursor = conn.execute("""
                SELECT 
                    ip_address,
                    port,
                    name,
                    game,
                    map_name,
                    players,
                    max_players
                FROM gameservers
                WHERE is_active = 1
                ORDER BY game, name
            """)
            
            servers = []
            for row in cursor.fetchall():
                servers.append({
                    'ip_address': row['ip_address'],
                    'port': row['port'],
                    'name': row['name'],
                    'game': row['game'],
                    'map_name': row['map_name'],
                    'players': row['players'],
                    'max_players': row['max_players']
                })
            
            return servers
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """
        Handle GET /health endpoint.
        Simple health check endpoint.
        
        Args:
            request: aiohttp request object
            
        Returns:
            JSON response with health status
        """
        try:
            # Test database connection
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._test_db_connection
            )
            
            return web.json_response({
                'status': 'healthy',
                'database': 'connected'
            })
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}", exc_info=True)
            return web.json_response({
                'status': 'unhealthy',
                'database': 'error',
                'error': str(e)
            }, status=503)
    
    def _test_db_connection(self) -> bool:
        """
        Test database connection.
        
        Returns:
            True if connection successful
        """
        with closing(self._get_db_connection()) as conn:
            cursor = conn.execute("SELECT 1")
            cursor.fetchone()
            return True
    
    async def handle_root(self, request: web.Request) -> web.Response:
        """
        Handle GET / endpoint.
        Returns API information.
        
        Args:
            request: aiohttp request object
            
        Returns:
            JSON response with API info
        """
        return web.json_response({
            'name': 'Discord Gameserver Notifier API',
            'version': '1.0.0',
            'endpoints': {
                '/': 'API information (this page)',
                '/health': 'Health check endpoint',
                '/servers': 'List all active game servers'
            }
        })
    
    def _setup_routes(self):
        """Setup API routes."""
        self.app.router.add_get('/', self.handle_root)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/servers', self.handle_servers)
    
    async def start(self):
        """Start the API server."""
        try:
            self.logger.info(f"Starting API server on {self.host}:{self.port}")
            
            # Create aiohttp application
            self.app = web.Application()
            self._setup_routes()
            
            # Setup and start runner
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            # Create TCP site
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            self.logger.info(f"✅ API server started successfully on http://{self.host}:{self.port}")
            self.logger.info(f"📡 Available endpoints:")
            self.logger.info(f"   - http://{self.host}:{self.port}/")
            self.logger.info(f"   - http://{self.host}:{self.port}/health")
            self.logger.info(f"   - http://{self.host}:{self.port}/servers")
            
        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}", exc_info=True)
            raise
    
    async def stop(self):
        """Stop the API server."""
        try:
            self.logger.info("Stopping API server...")
            
            if self.runner:
                await self.runner.cleanup()
            
            self.logger.info("✅ API server stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping API server: {e}", exc_info=True)
            raise

