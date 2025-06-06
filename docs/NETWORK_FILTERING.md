# Network Filtering Feature

## Übersicht

Die Network Filtering Funktion ermöglicht es, bestimmte Netzwerkbereiche zu definieren, die vom Discord Gameserver Notifier ignoriert werden sollen. Server in diesen Bereichen werden nicht in die Datenbank eingetragen und lösen keine Discord-Benachrichtigungen aus.

## Konfiguration

### Grundkonfiguration

Die Netzwerkfilterung wird in der `config/config.yaml` Datei unter dem `network` Abschnitt konfiguriert:

```yaml
network:
  scan_ranges:
    - "192.168.1.0/24"
    - "10.0.0.0/24"
  scan_interval: 300
  timeout: 5
  
  # Netzwerkbereiche die ignoriert werden sollen
  ignore_ranges:
    - "192.168.100.0/24"  # Test-Netzwerk
    - "10.10.10.0/24"     # Entwicklungsumgebung
    - "172.16.0.0/16"     # Internes Netzwerk
```

### Unterstützte Formate

Die `ignore_ranges` unterstützen CIDR-Notation:

- **Einzelne IP**: `192.168.1.100/32` (nur diese eine IP)
- **Subnetz**: `192.168.1.0/24` (alle IPs von 192.168.1.1 bis 192.168.1.254)
- **Größere Bereiche**: `10.0.0.0/8` (alle IPs von 10.0.0.1 bis 10.255.255.254)
- **Private Netzwerke**: `172.16.0.0/12` (alle IPs von 172.16.0.1 bis 172.31.255.254)

## Funktionsweise

### Globale Filterung

Die Netzwerkfilterung erfolgt **zentral** in der `main.py` Datei, bevor Server-Informationen verarbeitet werden:

1. **Server Discovery**: Wenn ein Server entdeckt wird, wird zuerst geprüft, ob seine IP-Adresse in einem der konfigurierten `ignore_ranges` liegt
2. **Frühzeitige Filterung**: Falls ja, wird die Verarbeitung sofort beendet - kein Datenbankeintrag, keine Discord-Nachricht
3. **Protokoll-unabhängig**: Die Filterung funktioniert für alle unterstützten Protokolle (Source, RenegadeX, Warcraft3, Flatout2, UT3)

### Implementierungsdetails

```python
# In main.py - _on_server_discovered()
if self.network_filter.should_ignore_server(server.ip_address, server.port):
    self.logger.debug(f"Server {server.ip_address}:{server.port} ignored due to network filter")
    return
```

Die Filterung erfolgt **vor** der Standardisierung und Datenbankverarbeitung, was maximale Effizienz gewährleistet.

## Anwendungsfälle

### Test- und Entwicklungsumgebungen

```yaml
ignore_ranges:
  - "192.168.100.0/24"  # Dediziertes Test-Netzwerk
  - "10.10.10.0/24"     # Entwickler-Workstations
```

### Interne Server

```yaml
ignore_ranges:
  - "172.16.0.0/16"     # Interne Unternehmensserver
  - "10.0.0.0/8"        # Komplettes internes Netzwerk
```

### Spezifische Server

```yaml
ignore_ranges:
  - "192.168.1.100/32"  # Einzelner Server
  - "192.168.1.200/32"  # Weiterer spezifischer Server
```

## Logging

### Info-Level

Beim Start wird die Anzahl der konfigurierten Ignore-Ranges angezeigt:

```
INFO - 🚫 NetworkFilter initialized with 3 ignore ranges:
INFO -    🔒 Ignoring network range: 192.168.100.0/24
INFO -    🔒 Ignoring network range: 10.10.10.0/24
INFO -    🔒 Ignoring network range: 172.16.0.0/16
```

Wenn Server ignoriert werden:

```
INFO - 🚫 IGNORING SERVER 192.168.100.5:27015 - matches ignore range: 192.168.100.0/24
INFO - 🚫 Server 192.168.100.5:27015 (source) IGNORED by network filter - skipping database and Discord processing
```

### Debug-Level

Bei aktiviertem Debug-Logging werden zusätzliche Details angezeigt:

```
DEBUG - ✅ Successfully parsed ignore range: 192.168.100.0/24
DEBUG - 🔍 IP 192.168.100.5 matches ignore range 192.168.100.0/24
```

## Vorteile

### Performance

- **Frühzeitige Filterung**: Server werden bereits vor der Datenbankverarbeitung gefiltert
- **Keine unnötigen Operationen**: Keine Discord-API-Aufrufe für ignorierte Server
- **Reduzierte Datenbankgröße**: Weniger Einträge in der Datenbank

### Flexibilität

- **Laufzeit-Konfiguration**: Änderungen in der config.yaml werden beim nächsten Neustart aktiv
- **CIDR-Unterstützung**: Flexible Netzwerkbereich-Definition
- **Protokoll-unabhängig**: Funktioniert mit allen Game-Protokollen

### Wartbarkeit

- **Zentrale Konfiguration**: Alle Ignore-Rules an einem Ort
- **Keine Protokoll-spezifische Implementierung**: Entwickler müssen bei neuen Protokollen nicht an die Filterung denken
- **Klare Trennung**: NetworkFilter-Klasse ist unabhängig und testbar

## Fehlerbehebung

### Ungültige Netzwerkbereiche

Bei ungültigen CIDR-Notationen wird ein Fehler geloggt:

```
ERROR - Invalid network range '192.168.1.0/33': netmask is not valid for host
```

### Keine Filterung aktiv

Wenn keine `ignore_ranges` konfiguriert sind:

```
DEBUG - NetworkFilter initialized with no ignore ranges
```

### Server werden trotzdem verarbeitet

1. Prüfe die CIDR-Notation in der Konfiguration
2. Stelle sicher, dass die IP-Adresse wirklich im konfigurierten Bereich liegt
3. Aktiviere Debug-Logging für detaillierte Informationen

## Beispielkonfiguration

```yaml
network:
  scan_ranges:
    - "192.168.1.0/24"
    - "10.0.0.0/24"
  scan_interval: 300
  timeout: 5
  
  # Umfassende Ignore-Konfiguration
  ignore_ranges:
    # Test-Umgebungen
    - "192.168.100.0/24"    # Test-Labor
    - "192.168.200.0/24"    # QA-Umgebung
    
    # Entwicklung
    - "10.10.10.0/24"       # Dev-Workstations
    - "10.10.20.0/24"       # Dev-Server
    
    # Interne Infrastruktur
    - "172.16.0.0/16"       # Interne Services
    - "10.0.100.0/24"       # Management-Netzwerk
    
    # Spezifische Server
    - "192.168.1.100/32"    # Alter Test-Server
    - "192.168.1.200/32"    # Backup-Server
```

Diese Konfiguration würde alle Server in den angegebenen Bereichen ignorieren, während Server in anderen Bereichen normal verarbeitet werden. 