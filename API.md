# API Documentation - Discord Gameserver Notifier

## Overview

The Discord Gameserver Notifier provides an HTTP REST API for read-only access to detected game servers. The API is fully asynchronous, implemented with `aiohttp`, and runs in the same process as the main scanner.

## Security

- **Read-Only Access**: The API opens the SQLite database in read-only mode (`mode=ro`)
- **No Write Operations**: Data cannot be modified or deleted
- **No Authentication**: Designed for use in local networks
- **Thread-Safe**: SQLite queries are executed in a thread pool

## Configuration

The API is configured in `config.yaml`:

```yaml
api:
  enabled: true            # Enable/disable API
  host: "0.0.0.0"         # Bind address (0.0.0.0 = all interfaces, 127.0.0.1 = localhost only)
  port: 8080              # API port
```

### Host Configuration Notes

- `0.0.0.0` - API is accessible from all network interfaces (recommended for LAN access)
- `127.0.0.1` - API is only accessible from the local machine (more secure, but not from network)
- `172.29.100.28` - API is only accessible via a specific interface

## API Endpoints

### GET `/`

**Description**: API information and available endpoints

**Response**:
```json
{
  "name": "Discord Gameserver Notifier API",
  "version": "1.0.0",
  "endpoints": {
    "/": "API information (this page)",
    "/health": "Health check endpoint",
    "/servers": "List all active game servers"
  }
}
```

### GET `/health`

**Description**: Health check endpoint for monitoring

**Response (Healthy)**:
```json
{
  "status": "healthy",
  "database": "connected"
}
```

**Response (Unhealthy)** (HTTP 503):
```json
{
  "status": "unhealthy",
  "database": "error",
  "error": "Error message..."
}
```

### GET `/servers`

**Description**: List of all active game servers

**Filter**: Only servers with `is_active = 1` are returned

**Response**:
```json
{
  "success": true,
  "count": 2,
  "servers": [
    {
      "ip_address": "172.29.100.28",
      "port": 27015,
      "name": "My CS:GO Server",
      "game": "Counter-Strike: Global Offensive",
      "map_name": "de_dust2",
      "players": 12,
      "max_players": 16
    },
    {
      "ip_address": "172.29.100.29",
      "port": 7777,
      "name": "UT3 Deathmatch",
      "game": "Unreal Tournament 3",
      "map_name": "DM-Deck",
      "players": 4,
      "max_players": 16
    }
  ]
}
```

**Fields per Server**:
- `ip_address` - Server IP address
- `port` - Server port
- `name` - Server name
- `game` - Game name
- `map_name` - Current map
- `players` - Number of online players
- `max_players` - Maximum players

**Sorting**: By `game` and then by `name`

## Usage Examples

### cURL

```bash
# Get all active servers
curl http://172.29.100.28:8080/servers

# Health check
curl http://172.29.100.28:8080/health

# API info
curl http://172.29.100.28:8080/
```

### Python

```python
import requests

# Get all active servers
response = requests.get('http://172.29.100.28:8080/servers')
data = response.json()

for server in data['servers']:
    print(f"{server['game']}: {server['name']} - {server['players']}/{server['max_players']} players")
```

### JavaScript/Browser

```javascript
// Get all active servers
fetch('http://172.29.100.28:8080/servers')
  .then(response => response.json())
  .then(data => {
    console.log(`Found: ${data.count} servers`);
    data.servers.forEach(server => {
      console.log(`${server.name} - ${server.players}/${server.max_players} players`);
    });
  });
```

## SQLite and Multi-User Access

SQLite supports **multiple concurrent read operations** without issues. The API uses:

1. **Read-Only Mode**: `PRAGMA query_only = ON` (implicit through `mode=ro`)
2. **Separate Connections**: Each request opens its own connection
3. **Thread Pool**: Database queries don't block the event loop
4. **Auto-Close**: Connections are automatically closed

The scanner can continue writing to the database while the API reads simultaneously. SQLite uses file locking to guarantee data consistency.

## Integration into Existing Systems

The API can easily be integrated into existing systems:

- **Website**: Display active servers on your LAN party website
- **Discord Bot**: Create a bot that shows server status
- **Monitoring**: Monitor server utilization with Grafana/Prometheus
- **Mobile App**: Create an app for your LAN party

## Troubleshooting

### API doesn't start

1. **Port already in use**: Change the port in config.yaml
2. **Permission denied**: Ports < 1024 require root privileges
3. **Firewall**: Ensure the port is allowed in the firewall

```bash
# Check if port is in use
netstat -tuln | grep 8080

# Allow port in firewall (Linux)
sudo ufw allow 8080/tcp
```

### API not reachable

1. **Host configuration**: Ensure that `host: "0.0.0.0"` is set
2. **Firewall**: Check firewall rules
3. **Network**: Test with `curl http://localhost:8080/health` from the server

### Empty server list

1. **Scanner running**: Ensure the scanner is active
2. **Servers found**: Check the logs to see if servers were detected
3. **is_active = 1**: Only active servers are displayed

```bash
# Check database directly
sqlite3 gameservers.db "SELECT name, is_active FROM gameservers;"
```

## Logs

The API logs all requests and errors:

```
2024-10-24 10:15:30 INFO API Server initialized - will listen on 0.0.0.0:8080
2024-10-24 10:15:30 INFO ✅ API server started successfully on http://0.0.0.0:8080
2024-10-24 10:15:31 DEBUG API request: /servers - returned 5 active servers
```

Log level can be adjusted in `config.yaml`:

```yaml
debugging:
  log_level: "DEBUG"  # For detailed API logs
```

## Performance

The API is optimized for LAN deployment:

- **Async**: Non-blocking I/O with asyncio
- **Thread Pool**: Database queries don't block the event loop
- **Lightweight**: Minimal dependencies (only aiohttp)
- **Fast**: Typical response time < 10ms

For large LAN parties (100+ servers), performance should not be an issue.

