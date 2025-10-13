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
        Check if the received packet is a valid CnC Generals Zero Hour server broadcast.
        
        Based on analysis of multiple servers and clients:
        - Server broadcasts: ...000d0df200XX0120... or ...00010df200XX0120...
        - Client disconnect: ...00070df200XX0120... (must be filtered out!)
        
        Packet structure:
        - Position 0-3: Variable session/packet ID
        - Position 4-5: Packet type (000d=broadcast part 1, 0001=broadcast part 2, 0007=client)
        - Position 6-8: Game identifier (0df200 for CnC Generals)
        - Position 9: Game variant (0x51 or 0x67 - possibly game mode/version)
        - Position 10-11: Always 0120
        
        Args:
            data: The received packet data
            
        Returns:
            True if the packet appears to be a valid CnC Generals server broadcast
        """
        min_size = self.protocol_config['min_packet_size']
        
        # Check minimum size
        if len(data) < min_size:
            self.logger.debug(
                f"CnC Generals packet too small: {len(data)} bytes (minimum {min_size})"
            )
            return False
        
        # Need at least 12 bytes to validate full structure
        if len(data) < 12:
            return False
        
        # Check packet type at position 4-5 (must be 000d or 0001 for servers)
        packet_type = data[4:6]
        valid_packet_types = [b'\x00\x0d', b'\x00\x01']  # Server broadcast types
        invalid_packet_types = [b'\x00\x07']  # Client disconnect packet
        
        if packet_type in invalid_packet_types:
            self.logger.debug(
                f"CnC Generals packet rejected: client packet type {packet_type.hex()}"
            )
            return False
        
        if packet_type not in valid_packet_types:
            self.logger.debug(
                f"CnC Generals packet rejected: unknown packet type {packet_type.hex()}"
            )
            return False
        
        # Check for the game identifier at position 6-9 (0df200)
        game_identifier = data[6:9]
        expected_identifier = b'\x0d\xf2\x00'
        
        if game_identifier != expected_identifier:
            self.logger.debug(
                f"CnC Generals packet signature mismatch: "
                f"expected {expected_identifier.hex()}XX, got {game_identifier.hex()}"
            )
            return False
        
        # Check for the constant sequence at position 10-11 (0120)
        constant_seq = data[10:12]
        expected_constant = b'\x01\x20'
        
        if constant_seq != expected_constant:
            self.logger.debug(
                f"CnC Generals packet rejected: invalid constant sequence "
                f"(expected {expected_constant.hex()}, got {constant_seq.hex()})"
            )
            return False
        
        # All checks passed - this is a valid server broadcast
        variant_byte = data[9]
        packet_type_str = "Part 1" if packet_type == b'\x00\x0d' else "Part 2"
        
        self.logger.debug(
            f"CnC Generals SERVER packet validated: {len(data)} bytes, "
            f"type: {packet_type.hex()} ({packet_type_str}), "
            f"variant: 0x{variant_byte:02x}"
        )
        return True

