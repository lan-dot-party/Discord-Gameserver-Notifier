"""
Network filtering utility for ignoring specific network ranges.

This module provides functionality to filter out servers from specific network ranges
that should be ignored by the Discord Gameserver Notifier.
"""

import ipaddress
import logging
from typing import List, Union


class NetworkFilter:
    """
    Utility class for filtering IP addresses based on configured ignore ranges.
    
    This class allows the application to ignore servers from specific network ranges,
    preventing them from being stored in the database or triggering Discord notifications.
    """
    
    def __init__(self, ignore_ranges: List[str] = None):
        """
        Initialize the NetworkFilter with ignore ranges.
        
        Args:
            ignore_ranges: List of network ranges in CIDR notation to ignore
                          (e.g., ["192.168.1.0/24", "10.0.0.0/8"])
        """
        self.logger = logging.getLogger("GameServerNotifier.NetworkFilter")
        self.ignore_networks = []
        
        if ignore_ranges:
            self._parse_ignore_ranges(ignore_ranges)
        
        if self.ignore_networks:
            self.logger.info(f"🚫 NetworkFilter initialized with {len(self.ignore_networks)} ignore ranges:")
            for network in self.ignore_networks:
                self.logger.info(f"   🔒 Ignoring network range: {network}")
        else:
            self.logger.info("✅ NetworkFilter initialized with no ignore ranges - all servers will be processed")
    
    def _parse_ignore_ranges(self, ignore_ranges: List[str]) -> None:
        """
        Parse and validate the ignore ranges from configuration.
        
        Args:
            ignore_ranges: List of network ranges in CIDR notation
        """
        for range_str in ignore_ranges:
            try:
                # Parse the network range
                network = ipaddress.ip_network(range_str, strict=False)
                self.ignore_networks.append(network)
                self.logger.debug(f"✅ Successfully parsed ignore range: {network}")
            except ValueError as e:
                self.logger.error(f"❌ Invalid network range '{range_str}': {e}")
                continue
    
    def should_ignore_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address should be ignored based on configured ranges.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if the IP should be ignored, False otherwise
        """
        if not self.ignore_networks:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for network in self.ignore_networks:
                if ip in network:
                    self.logger.debug(f"🔍 IP {ip_address} matches ignore range {network}")
                    return True
            
            return False
            
        except ValueError as e:
            self.logger.error(f"Invalid IP address '{ip_address}': {e}")
            return False
    
    def should_ignore_server(self, ip_address: str, port: int = None) -> bool:
        """
        Check if a server should be ignored based on its IP address.
        
        Args:
            ip_address: Server IP address
            port: Server port (optional, for logging purposes)
            
        Returns:
            True if the server should be ignored, False otherwise
        """
        should_ignore = self.should_ignore_ip(ip_address)
        
        if should_ignore:
            # Find which specific range matched for better debugging
            matching_range = self._find_matching_range(ip_address)
            port_info = f":{port}" if port else ""
            self.logger.info(f"🚫 IGNORING SERVER {ip_address}{port_info} - matches ignore range: {matching_range}")
        
        return should_ignore
    
    def _find_matching_range(self, ip_address: str) -> str:
        """
        Find which specific ignore range matches the given IP address.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            String representation of the matching network range
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for network in self.ignore_networks:
                if ip in network:
                    return str(network)
            
            return "unknown"
            
        except ValueError:
            return "invalid_ip"
    
    def get_ignore_ranges(self) -> List[str]:
        """
        Get the list of configured ignore ranges as strings.
        
        Returns:
            List of network ranges in CIDR notation
        """
        return [str(network) for network in self.ignore_networks]
    
    def add_ignore_range(self, network_range: str) -> bool:
        """
        Add a new ignore range at runtime.
        
        Args:
            network_range: Network range in CIDR notation
            
        Returns:
            True if successfully added, False if invalid
        """
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            self.ignore_networks.append(network)
            self.logger.info(f"Added new ignore range: {network}")
            return True
        except ValueError as e:
            self.logger.error(f"Failed to add invalid network range '{network_range}': {e}")
            return False
    
    def remove_ignore_range(self, network_range: str) -> bool:
        """
        Remove an ignore range at runtime.
        
        Args:
            network_range: Network range in CIDR notation to remove
            
        Returns:
            True if successfully removed, False if not found
        """
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            if network in self.ignore_networks:
                self.ignore_networks.remove(network)
                self.logger.info(f"Removed ignore range: {network}")
                return True
            else:
                self.logger.warning(f"Ignore range not found: {network}")
                return False
        except ValueError as e:
            self.logger.error(f"Invalid network range '{network_range}': {e}")
            return False 