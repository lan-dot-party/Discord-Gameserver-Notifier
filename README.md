# Discord Gameserver Notifier

A Python-based tool for automatic detection of game servers in local networks with Discord notifications via webhooks. Uses opengsq-python for game server communication and provides real-time monitoring of gaming communities.

## Features

- 🔍 **Automatic Network Discovery**: Finds game servers in local networks using broadcast queries and passive listening
- 🎮 **Multi-Protocol Support**: Supports multiple game protocols with specialized discovery methods
- 📊 **Discord Integration**: Automatic notifications for new servers and server status changes via webhooks
- 🏷️ **Game-Specific Mentions**: Configure different Discord mentions for each game type (global + game-specific)
- 💾 **Database Tracking**: Persistent storage and monitoring of discovered servers with SQLite
- ⚡ **Real-time Updates**: Continuous monitoring of server status with configurable scan intervals
- 🔧 **Configurable**: Flexible settings for network ranges, scan intervals, and cleanup thresholds
- 🚫 **Network Filtering**: Ignore specific network ranges (test/development environments)
- 🎯 **Intelligent Cleanup**: Automatic removal of inactive servers with configurable failure thresholds
- 📈 **Performance Tracking**: Response time monitoring and server statistics
- 🔒 **Security Features**: Network range filtering and secure webhook management
- 🌐 **Asynchronous Architecture**: Non-blocking network operations for optimal performance
- 📝 **Comprehensive Logging**: Detailed logging with configurable levels and file output
- 🔄 **Graceful Shutdown**: Proper cleanup and database maintenance on application exit
- 🎨 **Rich Discord Embeds**: Game-specific colors, emojis, and formatted server information
- 📊 **Database Statistics**: Real-time monitoring of active/inactive servers and cleanup operations

## Supported Games

| Game | Config Code |
|------|-------------|
| Source Engine Games | `source` |
| Renegade X | `renegadex` |
| Warcraft III | `warcraft3` |
| Flatout 2 | `flatout2` |
| Unreal Tournament 3 | `ut3` |
| ElDewrito | `eldewrito` |

## Installation

### Prerequisites

- Python 3.8 or higher
- Network access for UDP broadcast queries
- Discord webhook URL

### Installation Methods

#### Option 1: Package Installation (Recommended)

**From PyPI:**
```bash
# Install from PyPI
pip install Discord-Gameserver-Notifier

# Run directly
discord-gameserver-notifier --help
```

**From GitHub Releases:**

Choose the appropriate package for your system from the [releases page](https://github.com/lan-dot-party/Discord-Gameserver-Notifier/releases):

**Debian/Ubuntu (.deb):**
```bash
# Download and install .deb package
wget https://github.com/lan-dot-party/Discord-Gameserver-Notifier/releases/latest/download/discord-gameserver-notifier_*.deb
sudo dpkg -i discord-gameserver-notifier_*.deb
sudo apt-get install -f  # Fix dependencies if needed
```

**RHEL/Fedora/openSUSE (.rpm):**
```bash
# Download and install .rpm package
wget https://github.com/lan-dot-party/Discord-Gameserver-Notifier/releases/latest/download/discord-gameserver-notifier-*.rpm
sudo rpm -i discord-gameserver-notifier-*.rpm
```

**Arch Linux (.pkg.tar.zst):**
```bash
# Download and install Arch package
wget https://github.com/lan-dot-party/Discord-Gameserver-Notifier/releases/latest/download/discord-gameserver-notifier-*.pkg.tar.zst
sudo pacman -U discord-gameserver-notifier-*.pkg.tar.zst
```

All package installations place the executable in `/usr/bin/discord-gameserver-notifier` and are ready to use system-wide.

#### Option 2: Manual Installation (Development)

For development or manual installation:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/lan-dot-party/Discord-Gameserver-Notifier.git
   cd Discord-Gameserver-Notifier
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the application:**
   ```bash
   cp config/config.yaml.example config/config.yaml
   # Edit config/config.yaml with your settings
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

### Systemd Service (Linux)

For automatic startup and service management on Linux systems, the systemd service is automatically created when installing via package managers (.deb, .rpm, .pkg.tar.zst or PyPI):

1. **Install the package** (any of the package installation methods above will automatically create the systemd service)

2. **Configure the service**:
   ```bash
   # Edit configuration (service file is already created)
   sudo nano /etc/dgn/config.yaml
   ```

3. **Enable and start the service**:
   ```bash
   # Enable automatic startup
   sudo systemctl enable discord-gameserver-notifier
   
   # Start the service
   sudo systemctl start discord-gameserver-notifier
   
   # Check status
   sudo systemctl status discord-gameserver-notifier
   
   # View logs
   sudo journalctl -u discord-gameserver-notifier -f
   ```

**Service Features:**
- Runs as dedicated `dgn` system user
- Automatic restart on failure
- Proper logging to systemd journal
- Security hardening (restricted filesystem access)
- Configuration in `/etc/dgn/config.yaml`
- Data stored in `/var/lib/dgn/`
- Logs in `/var/log/dgn/`
- Executable located in `/usr/bin/discord-gameserver-notifier`

## Configuration

### Basic Configuration

Copy `config/config.yaml.example` to `config/config.yaml` and adjust the settings:

```yaml
network:
  scan_ranges:
    - "192.168.1.0/24"    # Your local network
    - "10.0.0.0/24"       # Additional networks
  scan_interval: 300      # Scan every 5 minutes
  timeout: 5              # Server response timeout
  
  # Ignore specific network ranges
  ignore_ranges:
    - "192.168.100.0/24"  # Test network
    - "10.10.10.0/24"     # Development environment

games:
  enabled:
    - "source"            # Source Engine games
    - "renegadex"         # Renegade X
    - "warcraft3"         # Warcraft III
    - "flatout2"          # Flatout 2
    - "ut3"               # Unreal Tournament 3
    - "eldewrito"         # ElDewrito

discord:
  webhook_url: "https://discord.com/api/webhooks/..."
  mentions:
    - "@everyone"         # Optional mentions
  
  # Optional: Game-specific mentions (added to global mentions)
  game_mentions:
    source:               # Source Engine games
      - "<@&SOURCE_ROLE_ID>"
    renegadex:            # Renegade X
      - "<@&RENEGADEX_ROLE_ID>"
    warcraft3:            # Warcraft III
      - "<@&WC3_ROLE_ID>"
    ut3:                  # Unreal Tournament 3
      - "<@&UT3_ROLE_ID>"
    flatout2:             # Flatout 2
      - "<@&FLATOUT2_ROLE_ID>"
    eldewrito:            # ElDewrito
      - "<@&ELDEWRITO_ROLE_ID>"

database:
  path: "./gameservers.db"
  cleanup_after_fails: 3  # Mark inactive after 3 failed attempts
  inactive_minutes: 3     # Minutes before cleanup
  cleanup_interval: 60    # Cleanup every minute

debugging:
  log_level: "INFO"       # DEBUG, INFO, WARNING, ERROR
  log_to_file: true
  log_file: "./notifier.log"
```

### Game-Specific Mentions

This feature allows you to mention different Discord roles or users for different game types:

**How it works:**
- **Global Mentions** (`mentions`): Used for all discovered servers, regardless of game type
- **Game-Specific Mentions** (`game_mentions`): Used in addition to global mentions, but only for the corresponding game type
- **Combined Mentions**: Both mention types are automatically combined

**Example Scenario:**
```yaml
discord:
  mentions:
    - "@everyone"                    # Global for all games
  game_mentions:
    source:
      - "<@&SOURCE_GAMERS_ROLE>"     # Additionally for Source Engine games
    renegadex:
      - "<@&RENEGADEX_FANS_ROLE>"    # Additionally for Renegade X
```

**Result:**
- **Counter-Strike Server discovered**: `@everyone <@&SOURCE_GAMERS_ROLE> 🎉 New gameserver discovered in network!`
- **Renegade X Server discovered**: `@everyone <@&RENEGADEX_FANS_ROLE> 🎉 New gameserver discovered in network!`
- **Warcraft III Server discovered**: `@everyone 🎉 New gameserver discovered in network!` (only global mentions)

**Supported Game Types:**
- `source` - Source Engine games (Counter-Strike, Half-Life, etc.)
- `renegadex` - Renegade X
- `warcraft3` - Warcraft III
- `ut3` - Unreal Tournament 3
- `flatout2` - Flatout 2
- `eldewrito` - ElDewrito

### Discord Setup

1. Create a webhook in your Discord server:
   - Server Settings → Integrations → Webhooks → Create Webhook
2. Copy the webhook URL to your configuration
3. Configure optional mentions and channel settings

See `docs/DISCORD_INTEGRATION.md` for detailed setup instructions.

### Network Filtering

Configure network ranges to ignore (useful for test environments):

```yaml
network:
  ignore_ranges:
    - "192.168.100.0/24"  # Test lab
    - "10.10.10.0/24"     # Development workstations
    - "172.16.0.0/16"     # Internal services
    - "192.168.1.100/32"  # Specific server
```

See `docs/NETWORK_FILTERING.md` for more information.

## Usage

### Running the Application

**After Package Installation:**
```bash
# Standard execution
discord-gameserver-notifier

# With debug logging
discord-gameserver-notifier --log-level DEBUG

# Background execution
nohup discord-gameserver-notifier &

# View help
discord-gameserver-notifier --help
```

**Manual Installation:**
```bash
# Standard execution
python main.py

# With debug logging
python main.py --log-level DEBUG

# Background execution
nohup python main.py &
```

### Monitoring

The application provides comprehensive logging:

```
INFO - Starting main application loop...
INFO - Discovery engine started successfully
INFO - NetworkScanner initialized with 2 scan ranges
INFO - Enabled games: source, renegadex, warcraft3, flatout2, ut3
INFO - Found 3 source servers
INFO - Discovered source server: Counter-Strike 1.6 Server
INFO - Server details: 192.168.1.100:27015
INFO - Players: 12/32, Map: de_dust2
```

### Database Management

The application automatically manages a SQLite database:
- Stores discovered servers with full details
- Tracks server status and response times
- Performs automatic cleanup of inactive servers
- Maintains server history and statistics

## Advanced Features

### Network Discovery Methods

- **Active Broadcast**: Sends queries to broadcast addresses
- **Passive Listening**: Listens for server announcements
- **Two-Step Discovery**: Combines broadcast discovery with direct queries
- **Multi-Protocol Support**: Handles different game protocols simultaneously

### Discord Integration

- **Rich Embeds**: Game-specific colors and emojis
- **Server Details**: Name, map, players, IP, version, response time
- **Status Updates**: New server notifications and offline alerts
- **Message Management**: Automatic cleanup of outdated notifications
- **Flexible Mentions**: Global and game-specific mention support

### Performance Features

- **Asynchronous Operations**: Non-blocking network operations
- **Connection Pooling**: Efficient database connections
- **Response Caching**: Optimized server queries
- **Graceful Error Handling**: Robust error recovery

### Debug Mode

Enable debug logging for detailed information:

```yaml
debugging:
  log_level: "DEBUG"
  log_to_file: true
```

### Network Connectivity

Ensure UDP broadcast packets are allowed:
- Check firewall rules for outbound UDP traffic
- Verify network broadcast is enabled
- Test with specific IP ranges first

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [opengsq-python](https://github.com/opengsq/opengsq-python) for game server protocol implementations
- Discord community for webhook API documentation
- Game server communities for protocol specifications