# Network Discovery Implementation

## Übersicht

Die Network Discovery Funktionalität wurde erfolgreich implementiert und ermöglicht das automatische Erkennen von **Source Engine** und **Renegade X** Spieleservern im lokalen Netzwerk.

## Implementierte Komponenten

### 1. NetworkScanner (`src/discovery/network_scanner.py`)

**Hauptfunktionen:**
- Broadcast-Queries für Source Engine Server (Port 27015)
- Passive Broadcast-Listening für Renegade X Server (Port 45542)
- Verwendung von opengsq-python für Protokoll-Handling
- Asynchrone Netzwerk-Kommunikation
- Parsing von Server-Antworten

**Konfiguration:**
```yaml
network:
  scan_ranges:
    - "192.168.1.0/24"
    - "10.0.0.0/24"
  timeout: 5
games:
  enabled:
    - "source"        # Source Engine games
    - "renegadex"     # Renegade X
```

### 2. DiscoveryEngine (`src/discovery/network_scanner.py`)

**Hauptfunktionen:**
- Koordination der periodischen Netzwerk-Scans
- Integration in die Hauptanwendung
- Callback-System für entdeckte/verlorene Server
- Graceful Start/Stop-Funktionalität

### 3. Integration in main.py

Die Discovery Engine wurde vollständig in das Hauptprogramm integriert:
- Automatischer Start beim Anwendungsstart
- Callback-Funktionen für Server-Events
- Graceful Shutdown beim Beenden

## Unterstützte Protokolle

### Source Engine Broadcast Query

**Implementierung:**
- Payload: `\xFF\xFF\xFF\xFF\x54Source Engine Query\x00`
- Broadcast an: `255.255.255.255:27015` (für jedes konfigurierte Netzwerk)
- Timeout: Konfigurierbar (Standard: 5 Sekunden)
- Response-Parsing: Verwendet opengsq-python's Source-Protokoll

**Erkannte Server-Informationen:**
- Server-Name
- Aktuelle Map
- Spieleranzahl (aktuell/maximal)
- Spiel-Typ
- Server-Typ und Umgebung

### Renegade X Passive Listening

**Implementierung:**
- Passive Listening auf Port 45542
- JSON-Broadcast-Nachrichten von Renegade X Servern
- Multi-Packet JSON-Assembly für große Nachrichten
- Timeout: Konfigurierbar (Standard: 5 Sekunden)

**Erkannte Server-Informationen:**
- Server-Name
- Aktuelle Map
- Spieleranzahl (aktuell/maximal)
- Game Version
- Passwort-Status
- Steam-Requirement
- Team-Modus
- Ranked-Status

## Verwendung

### Konfiguration

1. Kopiere `config/config.yaml.example` zu `config/config.yaml`
2. Passe die Netzwerkbereiche an:
   ```yaml
   network:
     scan_ranges:
       - "192.168.1.0/24"  # Dein lokales Netzwerk
       - "10.0.0.0/24"     # Weitere Netzwerke
   games:
     enabled:
       - "source"          # Source Engine Spiele
       - "renegadex"       # Renegade X
   ```

### Ausführung

```bash
python main.py
```

Die Anwendung wird:
1. Die Konfiguration laden
2. Die Discovery Engine starten
3. Periodische Netzwerk-Scans durchführen
4. Entdeckte Server loggen

### Logs

```
INFO - Starting DiscoveryEngine
INFO - NetworkScanner initialized with 2 scan ranges
INFO - Enabled games: source, renegadex
DEBUG - Broadcasting Source query to 192.168.1.255:27015
DEBUG - Starting passive listening for RenegadeX broadcasts on port 45542
INFO - Found 1 source servers
INFO - Found 1 renegadex servers
INFO - Discovered source server: 192.168.1.100:27015
INFO - Discovered renegadex server: 10.10.101.3:7777
DEBUG - RenegadeX server details: Name='Renegade X Server', Map='CNC-Field', Players=0/64, Version='5.89.877', Passworded=False
```

## Technische Details

### Broadcast-Mechanismus (Source Engine)

1. **Netzwerk-Berechnung:** Für jeden konfigurierten Bereich wird die Broadcast-Adresse berechnet
2. **UDP-Socket:** Erstellt mit `allow_broadcast=True`
3. **Query-Versendung:** Source Engine Query wird an Broadcast-Adresse gesendet
4. **Response-Sammlung:** Alle Antworten werden innerhalb des Timeouts gesammelt
5. **Parsing:** opengsq-python parst die Server-Antworten

### Passive Listening (Renegade X)

1. **UDP-Socket:** Lauscht auf Port 45542 für Broadcasts
2. **Multi-Packet Assembly:** Sammelt und kombiniert JSON-Pakete von derselben IP
3. **JSON-Parsing:** Verwendet opengsq-python's RenegadeX-Protokoll
4. **Duplikat-Vermeidung:** Verhindert mehrfache Erkennung desselben Servers

### Asynchrone Architektur

- **NetworkScanner:** Führt einzelne Scans durch
- **DiscoveryEngine:** Koordiniert periodische Scans
- **BroadcastResponseProtocol:** Sammelt UDP-Antworten (Source)
- **RenegadeXBroadcastProtocol:** Sammelt RenegadeX-Broadcasts
- **Callbacks:** Benachrichtigen über entdeckte Server

### Erweiterbarkeit

Das System ist für weitere Spieleprotokolle vorbereitet:
```python
self.protocol_configs = {
    'source': {
        'port': 27015,
        'query_data': b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
    },
    'renegadex': {
        'port': 7777,
        'broadcast_port': 45542,
        'passive': True
    },
    # Weitere Protokolle können hier hinzugefügt werden
}
```

## Nächste Schritte

1. **Datenbank-Integration:** Server in SQLite speichern
2. **Discord-Benachrichtigungen:** Webhooks für neue Server
3. **Weitere Protokolle:** UT3, Warcraft3
4. **Server-Tracking:** Überwachung von Online/Offline-Status

## Troubleshooting

### Keine Server gefunden
- Überprüfe Netzwerk-Konfiguration in `config.yaml`
- Stelle sicher, dass entsprechende Server im Netzwerk laufen
- Erhöhe das Timeout bei langsamen Netzwerken

### RenegadeX-spezifische Probleme
- Stelle sicher, dass Port 45542 nicht blockiert ist
- RenegadeX Server senden kontinuierlich Broadcasts - warte mindestens 5 Sekunden
- Überprüfe mit `netstat -u` ob Broadcasts ankommen

### Import-Fehler
- Stelle sicher, dass opengsq-python als Submodul verfügbar ist
- Überprüfe Python-Pfade und Abhängigkeiten

### Broadcast-Probleme
- Überprüfe Firewall-Einstellungen
- Teste mit `tcpdump` oder Wireshark die UDP-Pakete 