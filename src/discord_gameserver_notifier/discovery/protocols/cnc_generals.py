"""
Command & Conquer Generals Zero Hour protocol implementation for game server discovery.
Uses passive listening to detect server broadcasts on port 8086 UDP.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

from .common import ServerResponse
from ..protocol_base import ProtocolBase


class CnCGeneralsProtocol(ProtocolBase):
    """Command & Conquer Generals Zero Hour protocol handler for passive broadcast discovery"""
    
    def __init__(self, timeout: float = 11.0):
        super().__init__("", 0, timeout)
        self.timeout = timeout  # 11 seconds to catch two broadcasts (sent every 10 seconds)
        self.logger = logging.getLogger(__name__)
        self.protocol_config = {
            'port': 8086,  # CnC Generals broadcast port
            'passive': True,  # Uses passive listening
            'min_packet_size': 80,  # Minimum expected packet size
            'packets_required': 2  # Need to receive at least 2 packets to confirm it's a server
        }
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for CnC Generals servers.
        Since we don't parse detailed server information, this returns minimal info.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
        """
        fields = []
        
        # Add packet count for debugging
        if 'packets_received' in server_info:
            fields.append({
                'name': '📡 Pakete empfangen',
                'value': str(server_info['packets_received']),
                'inline': True
            })
        
        return fields
    
    async def scan_servers(self, scan_ranges: List[str]) -> List[ServerResponse]:
        """
        Scan for Command & Conquer Generals Zero Hour servers using passive broadcast listening.
        Listens for two consecutive UDP broadcasts on port 8086 to confirm server presence.
        
        Args:
            scan_ranges: List of network ranges to scan (not used for passive listening)
            
        Returns:
            List of ServerResponse objects for CnC Generals servers
        """
        servers = []
        broadcast_port = self.protocol_config['port']
        min_packets = self.protocol_config['packets_required']
        
        self.logger.debug(f"Starting passive listening for CnC Generals broadcasts on port {broadcast_port}")
        self.logger.info(f"Listening for {self.timeout} seconds to detect CnC Generals Zero Hour servers...")
        
        try:
            # Create a queue to collect broadcast messages
            broadcast_queue = asyncio.Queue()
            
            # Create UDP socket for listening to broadcasts
            loop = asyncio.get_running_loop()
            
            class CnCGeneralsBroadcastProtocol(asyncio.DatagramProtocol):
                """Protocol handler for receiving CnC Generals broadcasts"""
                
                def __init__(self, queue):
                    self.queue = queue
                
                def datagram_received(self, data, addr):
                    asyncio.create_task(self.queue.put((data, addr)))
                
                def error_received(self, exc):
                    logging.getLogger(__name__).debug(f"CnC Generals broadcast protocol error: {exc}")
            
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: CnCGeneralsBroadcastProtocol(broadcast_queue),
                local_addr=('0.0.0.0', broadcast_port),
                allow_broadcast=True
            )
            
            try:
                # Listen for broadcasts for the timeout period
                self.logger.debug(f"Listening for CnC Generals broadcasts for {self.timeout} seconds...")
                end_time = asyncio.get_event_loop().time() + self.timeout
                
                # Dictionary to track packets from each server
                server_packet_counts = {}  # IP -> count
                server_first_seen = {}  # IP -> timestamp
                
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
                        
                        # Validate the packet
                        if self._is_valid_cnc_generals_packet(data):
                            server_ip = addr[0]
                            
                            # Track packet count for this server
                            if server_ip not in server_packet_counts:
                                server_packet_counts[server_ip] = 0
                                server_first_seen[server_ip] = asyncio.get_event_loop().time()
                            
                            server_packet_counts[server_ip] += 1
                            
                            self.logger.debug(
                                f"CnC Generals: Received packet #{server_packet_counts[server_ip]} "
                                f"from {server_ip} ({len(data)} bytes)"
                            )
                            
                            # If we've received enough packets from this server, add it to the list
                            if (server_packet_counts[server_ip] >= min_packets and 
                                not any(s.ip_address == server_ip for s in servers)):
                                
                                server_info = {
                                    'name': 'Command & Conquer Generals Zero Hour Server',
                                    'game': 'Command & Conquer Generals Zero Hour',
                                    'map': 'Unknown',
                                    'players': 0,
                                    'max_players': 0,
                                    'packets_received': server_packet_counts[server_ip]
                                }
                                
                                server_response = ServerResponse(
                                    ip_address=server_ip,
                                    port=broadcast_port,
                                    game_type='cnc_generals',
                                    server_info=server_info,
                                    response_time=0.0
                                )
                                
                                servers.append(server_response)
                                self.logger.info(
                                    f"✓ CnC Generals Zero Hour Server erkannt: {server_ip}:{broadcast_port} "
                                    f"({server_packet_counts[server_ip]} Pakete empfangen)"
                                )
                        else:
                            self.logger.debug(
                                f"CnC Generals: Received invalid packet from {addr[0]} "
                                f"({len(data)} bytes, validation failed)"
                            )
                    
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing CnC Generals broadcast: {e}")
                
                # Log summary
                if server_packet_counts:
                    self.logger.debug(f"CnC Generals scan summary: {len(server_packet_counts)} unique IPs detected")
                    for ip, count in server_packet_counts.items():
                        status = "✓ Added" if count >= min_packets else "✗ Insufficient packets"
                        self.logger.debug(f"  {ip}: {count} packets - {status}")
                
            finally:
                transport.close()
        
        except OSError as e:
            if "Address already in use" in str(e):
                self.logger.warning(
                    f"Port {broadcast_port} bereits in Verwendung. "
                    "Möglicherweise läuft bereits eine CnC Generals Scan-Instanz."
                )
            else:
                self.logger.error(f"Fehler beim Lauschen auf CnC Generals Broadcasts: {e}")
        except Exception as e:
            self.logger.error(f"Fehler beim Lauschen auf CnC Generals Broadcasts: {e}")
        
        self.logger.info(f"CnC Generals scan abgeschlossen: {len(servers)} Server gefunden")
        return servers
    
    def _is_valid_cnc_generals_packet(self, data: bytes) -> bool:
        """
        Check if the received packet is a valid CnC Generals Zero Hour broadcast.
        
        Based on analysis of multiple servers:
        - Server type 1: ...000d0df200510120... or ...00010df200510120...
        - Server type 2: ...000d0df200670120... or ...00010df200670120...
        
        Common characteristics:
        - Minimum size: ~80 bytes (typical size is 477 bytes)
        - Contains the sequence 0df200 at position 6-9 (game identifier)
        - Fourth byte varies by server: 0x51 or 0x67 (possibly game mode/version)
        - Has variable headers in first 6 bytes
        
        Args:
            data: The received packet data
            
        Returns:
            True if the packet appears to be a valid CnC Generals broadcast
        """
        min_size = self.protocol_config['min_packet_size']
        
        # Check minimum size
        if len(data) < min_size:
            self.logger.debug(
                f"CnC Generals packet too small: {len(data)} bytes (minimum {min_size})"
            )
            return False
        
        # Check for the common sequence at position 6-9 (0df200)
        # This is the game identifier that appears in all CnC Generals broadcasts
        if len(data) >= 9:
            game_identifier = data[6:9]
            expected_identifier = b'\x0d\xf2\x00'
            
            if game_identifier == expected_identifier:
                # The fourth byte (position 9) can vary (0x51, 0x67, etc.)
                # This might indicate different game modes or versions
                variant_byte = data[9] if len(data) > 9 else 0x00
                
                self.logger.debug(
                    f"CnC Generals packet validation passed: {len(data)} bytes, "
                    f"signature: {data[6:10].hex() if len(data) >= 10 else data[6:9].hex()}, "
                    f"variant: 0x{variant_byte:02x}"
                )
                return True
            else:
                self.logger.debug(
                    f"CnC Generals packet signature mismatch: "
                    f"expected {expected_identifier.hex()}XX, got {game_identifier.hex()}"
                )
                return False
        
        return False

