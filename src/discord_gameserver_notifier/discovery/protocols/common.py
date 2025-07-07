"""
Common classes and utilities shared across all protocol implementations.
"""

import asyncio
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class ServerResponse:
    """Data class for server response information"""
    ip_address: str
    port: int
    game_type: str
    server_info: Dict[str, Any]
    response_time: float


class BroadcastResponseProtocol(asyncio.DatagramProtocol):
    """Protocol for collecting broadcast responses"""
    
    def __init__(self, responses_list: List[Tuple[bytes, Tuple[str, int]]]):
        self.responses = responses_list
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.responses.append((data, addr))
    
    def error_received(self, exc: Exception) -> None:
        logging.getLogger(__name__).debug(f"Broadcast response protocol error: {exc}") 