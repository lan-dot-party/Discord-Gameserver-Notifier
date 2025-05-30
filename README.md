# Discord Gameserver Notifier

Ein Python-Projekt zur Erkennung und Benachrichtigung über neue Spieleserver im lokalen Netzwerk via Discord Webhooks.

## Features

- Automatische Erkennung neuer Spieleserver im Netzwerk
- Unterstützung für verschiedene Spiele:
  - Unreal Tournament (99, 2004, 3)
  - Source Engine Spiele (CS2, CS 1.6, Garry's Mod)
  - Renegade X
  - Trackmania
  - Warcraft 3
  - Wreckfest
  - Flatout 2
  - Minecraft
  - Toxikk
- Discord Webhook Integration für Benachrichtigungen
- Lokale SQLite Datenbank zur Verwaltung bekannter Server
- Konfigurierbare Beacon-Nachrichten zum Triggern neuer Server

## Installation

1. Repository klonen:
```bash
git clone https://github.com/yourusername/Discord-Gameserver-Notifier.git
cd Discord-Gameserver-Notifier
```

2. Python-Umgebung erstellen und aktivieren:
```bash
python -m venv venv
source venv/bin/activate  # Unter Windows: venv\Scripts\activate
```

3. Abhängigkeiten installieren:
```bash
pip install -r requirements.txt
```

4. Konfigurationsdatei anpassen:
```bash
cp config/config.yaml.example config/config.yaml
# Bearbeiten Sie config.yaml mit Ihren Einstellungen
```

## Konfiguration

Die Konfiguration erfolgt über die `config.yaml` Datei:

- Discord Webhook URLs
- Zeitintervalle für Beacon-Nachrichten
- Zu überwachende Spiele
- Datenbankeinstellungen
- Logging-Konfiguration

## Verwendung

1. Programm starten:
```bash
python main.py
```

2. Verfügbare Kommandozeilen-Befehle:
- `--config`: Zeigt aktuelle Konfiguration
- `--list`: Zeigt aktuelle Server-Liste
- `--logs`: Zeigt aktuelle Logs

## Projektstruktur

```
.
├── discovery/          # Netzwerk-Discovery Module
├── game_wrappers/     # Spielespezifische Wrapper
├── database/          # Datenbankoperationen
├── discord/           # Discord Integration
├── utils/             # Hilfsfunktionen
├── config/            # Konfigurationsdateien
└── tests/             # Testfälle
```

## Entwicklung

- Python 3.8+
- SQLite3
- Verwendung von opengsq-python für Spieleserver-Abfragen

## Lizenz

MIT License
