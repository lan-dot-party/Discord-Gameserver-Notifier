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