from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
import socket
import struct
import asyncio
import logging
from discovery.protocol_base import ProtocolBase
from opengsq.binary_reader import BinaryReader

# Setup logger
logger = logging.getLogger(__name__)

@dataclass
class Warcraft3BroadcastInfo:
    """Information extracted from a Warcraft 3 broadcast packet"""
    protocol_signature: int
    packet_type: int
    packet_size: int
    game_version: int
    host_counter: int
    source_address: Tuple[str, int]
    
    def __str__(self) -> str:
        packet_type_str = {
            0x31: "CREATE_GAME",
            0x32: "REFRESH_GAME"
        }.get(self.packet_type, f"UNKNOWN(0x{self.packet_type:02x})")
        
        return (f"WC3 Broadcast [Type: {packet_type_str}] from {self.source_address[0]}:{self.source_address[1]}\n"
                f"  Protocol: 0x{self.protocol_signature:02x}\n"
                f"  Size: {self.packet_size} bytes\n"
                f"  Game Version: {self.game_version}\n"
                f"  Host Counter: {self.host_counter}")

class Warcraft3Protocol(ProtocolBase):
    """
    Protocol implementation for Warcraft 3 servers.
    Handles both passive broadcast listening and active querying.
    """
    
    PROTOCOL_SIG = 0xF7
    WARCRAFT3_PORT = 6112
    
    # Packet types
    PID_SEARCH_GAME = 0x2F
    PID_GAME_INFO = 0x30
    PID_CREATE_GAME = 0x31
    PID_REFRESH_GAME = 0x32
    
    def __init__(self, host: str = "255.255.255.255", port: int = WARCRAFT3_PORT, timeout: float = 5.0):
        """Initialize the Warcraft 3 protocol handler"""
        super().__init__(host, port, timeout)
        self._allow_broadcast = True
        logger.debug(f"Initialized Warcraft3Protocol (host={host}, port={port}, timeout={timeout})")
        
    @staticmethod
    def parse_broadcast_packet(data: bytes, addr: Tuple[str, int]) -> Optional[Warcraft3BroadcastInfo]:
        """
        Parse a Warcraft 3 broadcast packet.
        
        Args:
            data: Raw packet data
            addr: Source address tuple (ip, port)
            
        Returns:
            Parsed broadcast info or None if invalid
        """
        if len(data) < 16:  # Minimum packet size
            logger.debug(f"Packet too small from {addr[0]}:{addr[1]} (size: {len(data)})")
            return None
            
        try:
            br = BinaryReader(data)
            
            # Read and validate protocol signature
            protocol_sig = int.from_bytes(br.read_bytes(1), 'little')
            if protocol_sig != Warcraft3Protocol.PROTOCOL_SIG:
                logger.debug(f"Invalid protocol signature from {addr[0]}:{addr[1]}: 0x{protocol_sig:02x}")
                return None
                
            # Read packet type
            packet_type = int.from_bytes(br.read_bytes(1), 'little')
            
            # Only process Create/Refresh game packets
            if packet_type not in [Warcraft3Protocol.PID_CREATE_GAME, Warcraft3Protocol.PID_REFRESH_GAME]:
                logger.debug(f"Ignoring packet type 0x{packet_type:02x} from {addr[0]}:{addr[1]}")
                return None
            
            # Read packet size
            packet_size = int.from_bytes(br.read_bytes(2), 'little')
            
            # Read game version (4 bytes, little endian)
            game_version = int.from_bytes(br.read_bytes(4), 'little')
            
            # Read host counter (4 bytes, little endian)
            host_counter = int.from_bytes(br.read_bytes(4), 'little')
            
            info = Warcraft3BroadcastInfo(
                protocol_signature=protocol_sig,
                packet_type=packet_type,
                packet_size=packet_size,
                game_version=game_version,
                host_counter=host_counter,
                source_address=addr
            )
            
            logger.debug(f"Parsed broadcast packet:\n{info}")
            return info
            
        except Exception as e:
            logger.error(f"Error parsing broadcast from {addr[0]}:{addr[1]}: {e}")
            return None
    
    def create_search_game_packet(self, game_version: int) -> bytes:
        """
        Create a search game packet for the specific game version.
        
        Args:
            game_version: The game version to use in the packet
            
        Returns:
            Bytes containing the search game packet
        """
        packet = bytearray()
        packet.extend([
            self.PROTOCOL_SIG,          # Protocol signature
            self.PID_SEARCH_GAME,       # Packet type (Search Game)
            0x10, 0x00,                 # Packet size (16 bytes)
            0x50, 0x58, 0x33, 0x57      # Product "PX3W" (reversed "W3XP")
        ])
        
        # Add game version (little endian)
        packet.extend([
            game_version & 0xFF,
            (game_version >> 8) & 0xFF,
            (game_version >> 16) & 0xFF,
            (game_version >> 24) & 0xFF
        ])
        
        # Add host counter (zeros)
        packet.extend([0x00, 0x00, 0x00, 0x00])
        
        logger.debug(f"Created search game packet for version {game_version}")
        return bytes(packet)
    
    async def listen_for_broadcasts(self, callback) -> None:
        """
        Listen for Warcraft 3 broadcast packets.
        
        Args:
            callback: Async function to call with parsed broadcast info
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.WARCRAFT3_PORT))
        
        logger.info(f"Started listening for broadcasts on port {self.WARCRAFT3_PORT}")
        
        loop = asyncio.get_event_loop()
        
        while True:
            try:
                data, addr = await loop.sock_recvfrom(sock, 2048)
                logger.debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                
                broadcast_info = self.parse_broadcast_packet(data, addr)
                if broadcast_info:
                    await callback(broadcast_info)
            except Exception as e:
                logger.error(f"Error in broadcast listener: {e}")
                continue
    
    async def query_server(self, address: str, port: int, game_version: int) -> Optional[Dict[str, Any]]:
        """
        Query a specific Warcraft 3 server for details.
        
        Args:
            address: Server IP address
            port: Server port
            game_version: Game version to use in query
            
        Returns:
            Dictionary containing server details or None if failed
        """
        try:
            logger.debug(f"Querying server {address}:{port} (version {game_version})")
            
            # Create UDP socket for querying
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send search game packet
            search_packet = self.create_search_game_packet(game_version)
            sock.sendto(search_packet, (address, port))
            
            # Wait for response
            data, _ = sock.recvfrom(2048)
            
            if not data or len(data) < 4:
                logger.debug(f"Invalid response from {address}:{port} (size: {len(data) if data else 0})")
                return None
                
            br = BinaryReader(data)
            
            # Validate protocol signature
            protocol_sig = int.from_bytes(br.read_bytes(1), 'little')
            if protocol_sig != self.PROTOCOL_SIG:
                logger.debug(f"Invalid protocol signature in response: 0x{protocol_sig:02x}")
                return None
                
            # Validate packet type (should be GAME_INFO)
            packet_type = int.from_bytes(br.read_bytes(1), 'little')
            if packet_type != self.PID_GAME_INFO:
                logger.debug(f"Invalid response packet type: 0x{packet_type:02x}")
                return None
                
            # Read packet size
            packet_size = int.from_bytes(br.read_bytes(2), 'little')
            
            # Read game info
            product = br.read_bytes(4).decode('ascii')
            version = int.from_bytes(br.read_bytes(4), 'little')
            host_counter = int.from_bytes(br.read_bytes(4), 'little')
            entry_key = int.from_bytes(br.read_bytes(4), 'little')
            
            # Read game name (null-terminated)
            game_name = ""
            while True:
                char = int.from_bytes(br.read_bytes(1), 'little')
                if char == 0:
                    break
                game_name += chr(char)
            
            # Skip unknown byte
            br.read_bytes(1)
            
            # Read remaining fields
            slots_total = int.from_bytes(br.read_bytes(4), 'little')
            game_type = int.from_bytes(br.read_bytes(4), 'little')
            slots_used = int.from_bytes(br.read_bytes(4), 'little')
            slots_available = int.from_bytes(br.read_bytes(4), 'little')
            uptime = int.from_bytes(br.read_bytes(4), 'little')
            port = int.from_bytes(br.read_bytes(2), 'little')
            
            info = {
                'product': product,
                'version': version,
                'host_counter': host_counter,
                'entry_key': entry_key,
                'game_name': game_name,
                'slots_total': slots_total,
                'game_type': game_type,
                'slots_used': slots_used,
                'slots_available': slots_available,
                'uptime': uptime,
                'port': port
            }
            
            logger.debug(f"Server query response from {address}:{port}:\n" + 
                        "\n".join(f"  {k}: {v}" for k, v in info.items()))
            
            return info
            
        except Exception as e:
            logger.error(f"Error querying server {address}:{port}: {e}")
            return None
        finally:
            sock.close() 