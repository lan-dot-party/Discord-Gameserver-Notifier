# Discord Gameserver Notifier

A Python-based tool for automatic detection of game servers in the local network with Discord notifications via webhooks. Uses opengsq-python for game server communication.

## Project Structure

```
discord-gameserver-notifier/
├── src/
│   ├── __init__.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── config_manager.py
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── network_scanner.py
│   │   └── game_wrappers.py
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   └── database_manager.py
│   ├── discord/
│   │   ├── __init__.py
│   │   └── webhook_manager.py
│   └── utils/
│       ├── __init__.py
│       └── logger.py
├── config/
│   └── config.yaml.example
├── requirements.txt
├── main.py
└── README.md
```

## Installation

Detailed installation instructions will be added soon.

## Configuration

See `config/config.yaml.example` for configuration options.

## License

See the LICENSE file for details. 