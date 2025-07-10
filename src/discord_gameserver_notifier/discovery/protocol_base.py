class ProtocolBase:
    """Base class for all game server protocols"""
    
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        """
        Initialize the protocol base.
        
        Args:
            host: Target host address
            port: Target port
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self._allow_broadcast = False  # Can be enabled by child classes
        
    @property
    def allow_broadcast(self) -> bool:
        """Whether this protocol allows broadcast packets"""
        return self._allow_broadcast 
    
    def get_discord_fields(self, server_info: dict) -> list:
        """
        Get additional Discord embed fields for this protocol.
        
        Override this method in protocol implementations to provide
        game-specific fields that should appear in Discord notifications.
        
        Args:
            server_info: Server information dictionary from the protocol
            
        Returns:
            List of dictionaries with 'name', 'value', and 'inline' keys
            for Discord embed fields
        """
        return [] 