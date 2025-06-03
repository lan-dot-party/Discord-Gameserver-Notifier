# Network Discovery Implementation

## Übersicht

Die Network Discovery Funktionalität wurde erfolgreich implementiert und ermöglicht das automatische Erkennen von Source Engine Spieleservern im lokalen Netzwerk mittels Broadcast-Queries.

## Implementierte Komponenten

### 1. NetworkScanner (`src/discovery/network_scanner.py`)

**Hauptfunktionen:**
- Broadcast-Queries für Source Engine Server (Port 27015)
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
    - "source"
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

## Source Engine Broadcast Query

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

## Verwendung

### Konfiguration

1. Kopiere `config/config.yaml.example` zu `config/config.yaml`
2. Passe die Netzwerkbereiche an:
   ```yaml
   network:
     scan_ranges:
       - "192.168.1.0/24"  # Dein lokales Netzwerk
       - "10.0.0.0/24"     # Weitere Netzwerke
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
INFO - Enabled games: source
DEBUG - Broadcasting Source query to 192.168.1.255:27015
INFO - Found 1 source servers
INFO - Discovered source server: 192.168.1.100:27015
```

## Technische Details

### Broadcast-Mechanismus

1. **Netzwerk-Berechnung:** Für jeden konfigurierten Bereich wird die Broadcast-Adresse berechnet
2. **UDP-Socket:** Erstellt mit `allow_broadcast=True`
3. **Query-Versendung:** Source Engine Query wird an Broadcast-Adresse gesendet
4. **Response-Sammlung:** Alle Antworten werden innerhalb des Timeouts gesammelt
5. **Parsing:** opengsq-python parst die Server-Antworten

### Asynchrone Architektur

- **NetworkScanner:** Führt einzelne Scans durch
- **DiscoveryEngine:** Koordiniert periodische Scans
- **BroadcastResponseProtocol:** Sammelt UDP-Antworten
- **Callbacks:** Benachrichtigen über entdeckte Server

### Erweiterbarkeit

Das System ist für weitere Spieleprotokolle vorbereitet:
```python
self.protocol_configs = {
    'source': {
        'port': 27015,
        'query_data': b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
    },
    # Weitere Protokolle können hier hinzugefügt werden
}
```

## Nächste Schritte

1. **Datenbank-Integration:** Server in SQLite speichern
2. **Discord-Benachrichtigungen:** Webhooks für neue Server
3. **Weitere Protokolle:** UT3, RenegadeX, Warcraft3
4. **Server-Tracking:** Überwachung von Online/Offline-Status

## Troubleshooting

### Keine Server gefunden
- Überprüfe Netzwerk-Konfiguration in `config.yaml`
- Stelle sicher, dass Source Engine Server im Netzwerk laufen
- Erhöhe das Timeout bei langsamen Netzwerken

### Import-Fehler
- Stelle sicher, dass opengsq-python als Submodul verfügbar ist
- Überprüfe Python-Pfade und Abhängigkeiten

### Broadcast-Probleme
- Überprüfe Firewall-Einstellungen
- Teste mit `tcpdump` oder Wireshark die UDP-Pakete 