# Discord Gameserver Notifier

A Python-based tool for automatic detection of game servers in the local network with Discord notifications via webhooks. Uses opengsq-python for game server communication.

## Features

- 🔍 **Automatische Netzwerk-Discovery**: Findet Spieleserver im lokalen Netzwerk
- 🎮 **Multi-Protokoll-Unterstützung**: Source Engine, RenegadeX, Warcraft 3, Flatout 2, Unreal Tournament 3
- 📊 **Discord-Integration**: Automatische Benachrichtigungen über neue Server
- 💾 **Datenbank-Tracking**: Persistente Speicherung und Überwachung von Servern
- ⚡ **Echtzeit-Updates**: Kontinuierliche Überwachung des Server-Status
- 🔧 **Konfigurierbar**: Flexible Einstellungen für Netzwerkbereiche und Scan-Intervalle
- 🚫 **Netzwerk-Filterung**: Ignoriere bestimmte Netzwerkbereiche (Test-/Entwicklungsumgebungen)

## Unterstützte Spiele

| Spiel | Protokoll | Port | Discovery-Methode | Status |
|-------|-----------|------|-------------------|--------|
| Source Engine Games | Source Query | 27015 | Active Broadcast | ✅ |
| Renegade X | JSON Broadcast | 45542 | Passive Listening | ✅ |
| Warcraft III | W3GS | 6112 | Active Broadcast | ✅ |
| Flatout 2 | Binary Protocol | 23757 | Two-Step Discovery | ✅ |
| Unreal Tournament 3 | UDK LAN Beacon | 14001 | Active Broadcast | ✅ |

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
│       ├── logger.py
│       └── network_filter.py
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