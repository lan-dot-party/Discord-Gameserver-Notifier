# Discord Gameserver Notifier

A Python-based tool that automatically discovers and monitors game servers in your local network and sends notifications about their status via Discord webhooks.

## Features

- Automatic discovery of game servers in specified network ranges
- Support for multiple game protocols:
  - Unreal Tournament (99, 2004, 3)
  - Source Engine games (CS2, CS 1.6, Garry's Mod)
  - Renegade X
  - Trackmania
  - Warcraft 3
  - Wreckfest
  - Flatout 2
  - Minecraft
  - Toxikk
- Discord webhook integration for server status notifications
- SQLite database for persistent server tracking
- Configurable network scanning and monitoring
- Support for multiple Discord channels with game-specific notifications

## Requirements

- Python 3.8 or higher
- Dependencies (installed automatically):
  - opengsq>=3.3.0
  - discord-webhook>=1.3.0
  - SQLAlchemy>=2.0.27
  - python-dotenv>=1.0.1
  - pyyaml>=6.0.1
  - schedule>=1.2.1
  - colorlog>=6.8.2
  - netifaces>=0.11.0

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Discord-Gameserver-Notifier.git
   cd Discord-Gameserver-Notifier
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix or MacOS:
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create configuration file:
   ```bash
   cp config/config.yaml.example config/config.yaml
   ```

5. Edit `config/config.yaml` with your settings:
   - Add your Discord webhook URLs
   - Configure network ranges to scan
   - Adjust game-specific settings
   - Set up logging preferences

## Configuration

The configuration file (`config/config.yaml`) contains several sections:

### Discord Webhooks
Configure multiple webhooks for different Discord channels with game-specific notifications:
```yaml
discord:
  webhooks:
    - name: "main"
      url: "your-webhook-url"
      games: ["ut99", "ut2004", "cs2"]
```

### Network Settings
Define which networks to scan and exclude:
```yaml
network:
  scan_ranges:
    - "192.168.1.0/24"
  exclude_ranges:
    - "192.168.1.1/32"
```

### Game-specific Settings
Configure settings for each supported game:
```yaml
games:
  ut99:
    query_port_offset: 1
    broadcast_port: 8777
```

See the example configuration file for more details.

## Usage

1. Start the notifier:
   ```bash
   python main.py
   ```

2. Command-line options:
   ```bash
   python main.py --config     # Show current configuration
   python main.py --list      # List discovered servers
   python main.py --debug     # Enable debug logging
   ```

## Project Structure

```
.
├── game_wrappers/          # Game-specific protocol wrappers
├── database/              # Database operations and models
├── discord/              # Discord webhook integration
├── utils/                # Helper functions
├── config/               # Configuration files
├── data/                 # Database and other data files
└── logs/                 # Log files
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [opengsq](https://github.com/opengsq/opengsq-python) for game server query protocols
- All contributors and users of this project
