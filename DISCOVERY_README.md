# Network Discovery Implementation

## Übersicht

Die Network Discovery Funktionalität wurde erfolgreich implementiert und ermöglicht das automatische Erkennen von **Source Engine**, **Renegade X**, **Flatout 2** und **Unreal Tournament 3** Spieleservern im lokalen Netzwerk.

## Implementierte Komponenten

### 1. NetworkScanner (`src/discovery/network_scanner.py`)

**Hauptfunktionen:**
- Broadcast-Queries für Source Engine Server (Port 27015)
- Passive Broadcast-Listening für Renegade X Server (Port 45542)
- Zweistufige Broadcast-Discovery für Flatout 2 Server (Port 23757)
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
    - "flatout2"      # Flatout 2
    - "ut3"           # Unreal Tournament 3
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

### Flatout 2 Two-Step Discovery

**Implementierung:**
- **Schritt 1:** Broadcast an `255.255.255.255:23757` zur IP-Erkennung
- **Schritt 2:** Direkte Queries an entdeckte IPs für detaillierte Informationen
- Spezifisches Flatout 2 Protokoll mit Session-ID und Game-Identifier
- Verzögerung zwischen Queries um Port-Konflikte zu vermeiden

**Erkannte Server-Informationen:**
- Server-Name (Hostname)
- Server-Timestamp
- Server-Flags und Status
- Konfigurationsdaten
- Game-Identifier Validierung

**Technische Details:**
```python
# Flatout 2 Request Payload
request_data = (
    b"\x22\x00" +                    # Protocol header
    b"\x99\x72\xcc\x8f" +          # Session ID
    b"\x00" * 4 +                   # Padding pre-identifier
    b"FO14" +                       # Game identifier
    b"\x00" * 8 +                   # Padding post-identifier
    b"\x18\x0c" +                   # Query command
    b"\x00\x00\x22\x00" +          # Command data
    b"\x2e\x55\x19\xb4\xe1\x4f\x81\x4a"  # Packet end
)
```

**Warum zweistufig?**
- Flatout 2 Server antworten nur auf Port 23757
- Sowohl Quell- als auch Zielport müssen 23757 sein für korrekte Kommunikation
- Mehrere gleichzeitige Queries auf denselben Port führen zu "Address already in use" Fehlern
- Erste Stufe sammelt alle verfügbaren Server-IPs
- Zweite Stufe fragt jeden Server einzeln mit kleiner Verzögerung ab

### Unreal Tournament 3

**Implementierung:**
- **Protocol**: UDK (Unreal Development Kit) LAN Beacon
- **Port**: 14001
- **Discovery Method**: Active broadcast queries
- **Games**: Unreal Tournament 3
- **Features**: 
  - Game mode detection (Deathmatch, CTF, Warfare, etc.)
  - Mutator information (Instagib, Low Gravity, etc.)
  - Bot configuration and skill levels
  - Server settings (frag/time limits, pure server, etc.)

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
   games:
     enabled:
       - "source"          # Source Engine Spiele
       - "renegadex"       # Renegade X
       - "flatout2"        # Flatout 2
       - "ut3"             # Unreal Tournament 3
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
INFO - Enabled games: source, renegadex, flatout2, ut3
DEBUG - Broadcasting Source query to 192.168.1.255:27015
DEBUG - Starting passive listening for RenegadeX broadcasts on port 45542
DEBUG - Starting Flatout 2 two-step discovery process
DEBUG - Step 1: Broadcasting Flatout2 discovery to 255.255.255.255:23757
DEBUG - Discovered Flatout2 server IP: 10.10.101.3
INFO - Step 1 complete: Found 1 Flatout2 server IPs
DEBUG - Step 2: Querying 1 discovered IPs individually
DEBUG - Querying Flatout2 server at 10.10.101.3:23757
DEBUG - Successfully queried Flatout2 server: 10.10.101.3:23757
DEBUG - Flatout2 server details: Name='Gombi', Flags=1353097456, Status=0
INFO - Found 1 source servers
INFO - Found 1 renegadex servers
INFO - Found 1 flatout2 servers
INFO - Found 1 ut3 servers
INFO - Discovered source server: 192.168.1.100:27015
INFO - Discovered renegadex server: 10.10.101.3:7777
INFO - Discovered flatout2 server: 10.10.101.3:23757
INFO - Discovered ut3 server: 192.168.1.101:14001
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

### Flatout 2 Two-Step Discovery

1. **Broadcast-Discovery:** Query wird an `255.255.255.255:23757` gesendet
2. **IP-Sammlung:** Alle antwortenden Server-IPs werden gesammelt
3. **Individuelle Queries:** Jede IP wird einzeln mit 0.1s Verzögerung abgefragt
4. **Response-Validierung:** Prüfung auf Game-ID "FO14" (robuste Erkennung aller Versionen)
5. **Parsing:** opengsq-python's Flatout2-Protokoll parst die Server-Details
6. **Port-Spezifikation:** Sowohl Quell- als auch Zielport müssen 23757 sein
7. **Versions-Unterstützung:** Erkennt alle Flatout 2 Protokoll-Versionen über Game-ID

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
    'flatout2': {
        'port': 23757,
        'query_data': (
            b"\x22\x00" +        # Protocol header
            b"\x99\x72\xcc\x8f" +            # Session ID
            b"\x00" * 4 +               # Padding pre-identifier
            b"FO14" +       # Game identifier
            b"\x00" * 8 +               # Padding post-identifier
            b"\x18\x0c" +         # Query command
            b"\x00\x00\x22\x00" +       # Command data
            b"\x2e\x55\x19\xb4\xe1\x4f\x81\x4a"              # Standard packet end
        )
    },
    'ut3': {
        'port': 14001,
        'query_data': b'\xFF\xFF\xFF\xFF\x54Unreal Tournament 3 Query\x00'
    },
    # Weitere Protokolle können hier hinzugefügt werden
}
```