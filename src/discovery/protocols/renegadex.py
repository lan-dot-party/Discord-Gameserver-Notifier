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


class RenegadeXBroadcastProtocol(asyncio.DatagramProtocol):
    """Protocol for collecting RenegadeX broadcast messages"""
    
    def __init__(self, broadcast_queue: asyncio.Queue):
        self.broadcast_queue = broadcast_queue
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        asyncio.create_task(self.broadcast_queue.put((data, addr)))
    
    def error_received(self, exc: Exception) -> None:
        logging.getLogger(__name__).debug(f"RenegadeX broadcast protocol error: {exc}")


class RenegadeXProtocol:
    """RenegadeX protocol handler for broadcast discovery"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 7777,  # Game server port
            'broadcast_port': 45542,  # Broadcast listening port
            'passive': True  # Uses passive listening instead of active queries
        }
    
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
                server_fragment_counts = {}
                
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
                            server_fragment_counts[server_key] = 0
                        
                        server_data_buffers[server_key].extend(data)
                        server_fragment_counts[server_key] += 1
                        
                        self.logger.debug(f"RenegadeX: Collected fragment {server_fragment_counts[server_key]} from {addr[0]} ({len(data)} bytes, total: {len(server_data_buffers[server_key])} bytes)")
                        
                        # Only try to parse if we have a potentially complete JSON message
                        # Check if the accumulated data looks like complete JSON (ends with '}')
                        complete_data = bytes(server_data_buffers[server_key])
                        if self._is_complete_renegadex_json(complete_data):
                            try:
                                server_info = await self._parse_renegadex_response(complete_data)
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
                                        self.logger.debug(f"Discovered RenegadeX server: {addr[0]}:{server_info.get('port', self.protocol_config['port'])} (assembled from {server_fragment_counts[server_key]} fragments)")
                                    
                                    # Clear the buffer for this server
                                    server_data_buffers[server_key] = bytearray()
                                    server_fragment_counts[server_key] = 0
                            except Exception as e:
                                # Only log parsing errors if we think we have complete data
                                self.logger.debug(f"RenegadeX: Failed to parse seemingly complete JSON from {addr[0]}: {e}")
                        
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
        This method tries to extract valid JSON even if there are duplicates or extra data.
        
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
            # Look for the first '{' and try to find its matching '}'
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
    
    async def _parse_renegadex_response(self, response_data: bytes) -> Optional[Dict[str, Any]]:
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
            server_info = json.loads(json_data)
            
            # Validate that this looks like a RenegadeX server response
            if not isinstance(server_info, dict):
                return None
            
            # Log the parsed server info for debugging
            self.logger.debug(f"RenegadeX: Parsed server info: {server_info}")
            
            return server_info
            
        except Exception as e:
            self.logger.debug(f"Failed to parse RenegadeX response: {e}")
            return None 