import asyncio
from discovery.protocols.warcraft3 import Warcraft3Protocol, Warcraft3BroadcastInfo

async def handle_broadcast(info: Warcraft3BroadcastInfo):
    """
    Handle incoming Warcraft 3 broadcast packets
    """
    print(f"Received broadcast from {info.source_address}:")
    print(f"  Game Version: {info.game_version}")
    print(f"  Host Counter: {info.host_counter}")
    
    # Create protocol instance for querying
    protocol = Warcraft3Protocol()
    
    # Query the server for full details
    server_info = await protocol.query_server(
        address=info.source_address[0],
        port=info.source_address[1],
        game_version=info.game_version
    )
    
    if server_info:
        print("\nServer details:")
        print(f"  Game Name: {server_info['game_name']}")
        print(f"  Players: {server_info['slots_used']}/{server_info['slots_total']}")
        print(f"  Game Type: {server_info['game_type']}")
        print(f"  Uptime: {server_info['uptime']} seconds")
    else:
        print("\nFailed to query server details")

async def main():
    # Create protocol instance
    protocol = Warcraft3Protocol()
    
    print("Listening for Warcraft 3 broadcasts...")
    
    # Start listening for broadcasts
    await protocol.listen_for_broadcasts(handle_broadcast)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping...") 