#!/usr/bin/env python3
"""
Example script demonstrating the ServerInfoWrapper usage
"""

import asyncio
import sys
import os
import json

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from discovery.network_scanner import NetworkScanner, DiscoveryEngine
from discovery.server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo


async def main():
    """Main example function"""
    
    # Example configuration
    config = {
        'network': {
            'timeout': 5.0,
            'scan_interval': 30,
            'scan_ranges': ['10.10.100.0/23']
        },
        'games': {
            'enabled': ['source', 'renegadex', 'warcraft3', 'flatout2']
        }
    }
    
    print("🔍 Starting Game Server Discovery Example")
    print("=" * 50)
    
    # Create scanner and wrapper
    scanner = NetworkScanner(config)
    wrapper = ServerInfoWrapper()
    
    print("📡 Scanning for game servers...")
    
    # Method 1: Get raw server responses and manually standardize
    print("\n--- Method 1: Manual Standardization ---")
    raw_servers = await scanner.scan_for_servers()
    
    if raw_servers:
        print(f"Found {len(raw_servers)} servers (raw format)")
        
        for server in raw_servers:
            print(f"\nRaw Server: {server.ip_address}:{server.port} ({server.game_type})")
            print(f"Raw Info: {json.dumps(server.server_info, indent=2)}")
            
            # Standardize manually
            standardized = wrapper.standardize_server_response(server)
            print(f"\nStandardized Summary:")
            print(wrapper.format_server_summary(standardized))
            print("-" * 30)
    else:
        print("No servers found with raw scan")
    
    # Method 2: Get directly standardized results
    print("\n--- Method 2: Direct Standardization ---")
    standardized_servers = await scanner.scan_for_standardized_servers()
    
    if standardized_servers:
        print(f"Found {len(standardized_servers)} servers (standardized format)")
        
        for server in standardized_servers:
            print(f"\n{wrapper.format_server_summary(server)}")
            
            # Show additional protocol-specific info
            if server.additional_info:
                print(f"\nAdditional Info:")
                for key, value in server.additional_info.items():
                    print(f"  {key}: {value}")
            print("-" * 50)
    else:
        print("No servers found with standardized scan")
    
    # Method 3: Using DiscoveryEngine
    print("\n--- Method 3: Using DiscoveryEngine ---")
    discovery_engine = DiscoveryEngine(config)
    
    standardized_servers = await discovery_engine.scan_once_standardized()
    
    if standardized_servers:
        print(f"Discovery Engine found {len(standardized_servers)} servers")
        
        # Group servers by game type
        servers_by_game = {}
        for server in standardized_servers:
            game = server.game
            if game not in servers_by_game:
                servers_by_game[game] = []
            servers_by_game[game].append(server)
        
        for game, servers in servers_by_game.items():
            print(f"\n🎮 {game} Servers ({len(servers)}):")
            for server in servers:
                print(f"  • {server.name} - {server.players}/{server.max_players} players")
                print(f"    {server.ip_address}:{server.port} - Map: {server.map}")
    else:
        print("Discovery Engine found no servers")
    
    # Method 4: Demonstrate serialization
    print("\n--- Method 4: Serialization Example ---")
    if standardized_servers:
        server = standardized_servers[0]
        
        # Convert to dictionary
        server_dict = wrapper.to_dict(server)
        print("Server as dictionary:")
        print(json.dumps(server_dict, indent=2))
        
        # Convert back from dictionary
        restored_server = wrapper.from_dict(server_dict)
        print(f"\nRestored server name: {restored_server.name}")
        print(f"Restored server game: {restored_server.game}")
    
    print("\n✅ Example completed!")


if __name__ == "__main__":
    asyncio.run(main()) 