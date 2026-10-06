# Discord Integration - Setup Guide

## Übersicht

Der Discord Gameserver Notifier kann automatisch Benachrichtigungen an Discord-Kanäle senden, wenn neue Spieleserver im Netzwerk entdeckt oder wenn Server offline gehen.

## Features

- 🎉 **Neue Server Benachrichtigungen**: Automatische Meldungen wenn neue Gameserver entdeckt werden
- 🔴 **Offline Benachrichtigungen**: Meldungen wenn Server nicht mehr erreichbar sind
- 🎮 **Spiel-spezifische Formatierung**: Verschiedene Farben und Emojis je nach Spieltyp
- 📊 **Detaillierte Server-Informationen**: Servername, Spiel, Map, Spieleranzahl, IP-Adresse, Version
- 🔒 **Passwort-Status**: Anzeige ob Server passwortgeschützt ist
- ⚡ **Antwortzeit**: Ping-Zeit zum Server
- 🏷️ **Mentions**: Konfigurierbare @everyone, @here oder Rollen-Mentions

## Discord Webhook Setup

### 1. Discord Webhook erstellen

1. Gehe zu deinem Discord Server
2. Klicke auf **Server Settings** (Zahnrad-Symbol)
3. Navigiere zu **Integrations** → **Webhooks**
4. Klicke auf **Create Webhook**
5. Wähle den gewünschten Kanal aus
6. Gib dem Webhook einen Namen (z.B. "Gameserver Notifier")
7. Kopiere die **Webhook URL**

### 2. Konfiguration

Bearbeite die `config/config.yaml` Datei:

```yaml
discord:
  # Deine Discord Webhook URL
  webhook_url: "https://discord.com/api/webhooks/1234567890123456789/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz"
  
  # Optional: Channel ID für Referenz
  channel_id: "1234567890"
  
  # Optional: Mentions für neue Server
  mentions:
    - "@everyone"     # Alle Benutzer erwähnen
    # - "@here"       # Nur online Benutzer erwähnen
    # - "<@&ROLE_ID>" # Spezifische Rolle erwähnen
```

### 3. Test der Integration

Führe das Test-Script aus um die Discord-Integration zu testen:

```bash
python test_discord.py
```

Das Script sendet Test-Nachrichten für verschiedene Spieletypen an deinen Discord-Kanal.

## Nachrichtenformat

### Neue Server Entdeckung

```
🎉 @everyone Neuer Gameserver im Netzwerk entdeckt!

🟢 Neuer Server: Test Source Server
🎮 Counter-Strike: Source Server wurde entdeckt!

🎮 Spiel: Counter-Strike: Source
🗺️ Aktuelle Map: de_dust2
👥 Spieler: 12/16
📍 IP-Adresse: 192.168.1.100:27015
🔧 Version: 1.0.0.70
🔒 Passwort: 🔓 Nein
⚡ Antwortzeit: 0.05s

Protokoll: SOURCE • Entdeckt um 14:30:25
```

### Server Offline

```
🔴 Server Offline: Test Source Server
🎮 Counter-Strike: Source Server ist nicht mehr erreichbar

🎮 Spiel: Counter-Strike: Source
🗺️ Aktuelle Map: de_dust2
👥 Spieler: 12/16
📍 IP-Adresse: 192.168.1.100:27015
🔧 Version: 1.0.0.70
🔒 Passwort: 🔓 Nein

Protokoll: SOURCE
```

## Spiel-spezifische Farben und Emojis

| Spieltyp | Farbe | Emoji | Beschreibung |
|----------|-------|-------|--------------|
| Source Engine | 🟠 Orange | 🎮 | Counter-Strike, Half-Life, etc. |
| RenegadeX | 🟢 Grün | ⚔️ | Command & Conquer RenegadeX |
| Warcraft 3 | 🔵 Blau | 🏰 | Warcraft III und Custom Games |
| Flatout 2 | 🔴 Rot | 🏎️ | Flatout 2 Racing |
| Unreal Tournament 3 | 🟣 Lila | 🔫 | Unreal Tournament 3 |
| Unbekannt | 🟦 Blau | 🎯 | Andere/Unbekannte Protokolle |

## Gameserver-Übersicht (optional)

Zusätzlich zu den Benachrichtigungen kann DGN eine **dauerhaft stehende Übersicht** aller aktiven
Gameserver in einem eigenen Channel pflegen. Die Übersicht ist eine einzelne Nachricht, die bei
Änderungen (neue/verschwundene Server, Spielerzahl, Map) **bearbeitet** statt neu gepostet wird.
Die bisherigen Benachrichtigungen über `discord.webhook_url` laufen unverändert weiter.

### Einrichtung

1. Eigenen Textchannel anlegen, z. B. `#gameserver-übersicht`, und für `@everyone` das Recht
   „Nachrichten senden" entziehen. Der Channel sollte nur die Übersicht enthalten.
2. In diesem Channel einen **eigenen Webhook** erstellen (nicht den der Benachrichtigungen).
3. Konfiguration:

```yaml
discord:
  overview:
    enabled: true
    webhook_url: ""              # besser: DGN_DISCORD_OVERVIEW_WEBHOOK_URL in der .env
    title: "🎮 Gameserver-Übersicht"
    show_stale: true             # Server, die im letzten Scan fehlten, mit 🟡 markieren (false = ausblenden)
    refresh_interval: 300        # spätestens alle X Sekunden „Stand" aktualisieren (0 = nur bei Änderungen)
    pause_on_shutdown: true      # beim Beenden „Übersicht pausiert" anzeigen
```

### Darstellung

- Eine Box (Discord Components V2), gruppiert nach Spiel, pro Server Name, Spieler, Map und
  `IP:Port` als kopierbarer Text.
- 🟢 = im letzten Scan gefunden, 🟡 = zuletzt nicht erreichbar (wird nach `inactive_minutes` /
  `cleanup_after_fails` entfernt), 🔒 = Passwort.
- Fußzeile mit Zeitstempel (in der Zeitzone des jeweiligen Betrachters), Server- und Spielerzahl.
- Bei sehr vielen Servern wird auf mehrere Nachrichten verteilt (max. 5).

### Hinweise

- Die Message-IDs werden in der Datenbank (Tabelle `app_state`) gespeichert. Nach einem Neustart
  wird dieselbe Nachricht weiter bearbeitet. Wird die Nachricht manuell gelöscht, postet DGN sie neu.
- Geht die Datenbank verloren oder wird der Webhook gewechselt, bleiben alte Übersichtsnachrichten
  stehen und müssen manuell gelöscht werden (ein Webhook kann seine Nachrichten nicht auflisten).
- Ein „Beitreten"-Button ist nicht möglich: Discord erlaubt in Links und Buttons nur `http`, `https`
  und `discord://`, `steam://connect/...` wird abgelehnt bzw. nicht klickbar dargestellt.
- Ist der Webhook ungültig oder gelöscht, deaktiviert sich die Übersicht bis zum nächsten Neustart
  (Fehler im Log), damit Discord den Server nicht wegen Dauerfehlern sperrt.

## Troubleshooting

### Webhook URL nicht konfiguriert
```
Discord webhook URL not configured - Discord notifications disabled
```
**Lösung**: Konfiguriere eine gültige Webhook URL in `config/config.yaml`

### Webhook Test fehlgeschlagen
```
Discord webhook test failed - notifications may not work
```
**Mögliche Ursachen**:
- Ungültige Webhook URL
- Webhook wurde gelöscht
- Netzwerkprobleme
- Discord API Rate Limiting

### Benachrichtigung fehlgeschlagen
```
Failed to send Discord notification. Status: 404
```
**Mögliche Ursachen**:
- Webhook wurde gelöscht oder deaktiviert
- Kanal wurde gelöscht
- Keine Berechtigung für den Kanal

### Rate Limiting
Discord hat Rate Limits für Webhooks:
- 30 Nachrichten pro Minute pro Webhook
- 5 Nachrichten pro 5 Sekunden

Der Notifier implementiert automatische Verzögerungen zwischen Nachrichten.

## Erweiterte Konfiguration

### Mentions konfigurieren

```yaml
discord:
  mentions:
    - "@everyone"           # Alle Benutzer
    - "@here"              # Nur online Benutzer
    - "<@&123456789>"      # Spezifische Rolle (Rollen-ID erforderlich)
    - "<@987654321>"       # Spezifischer Benutzer (Benutzer-ID erforderlich)
```

### Rollen-ID finden
1. Aktiviere Developer Mode in Discord (User Settings → Advanced → Developer Mode)
2. Rechtsklick auf die Rolle → "Copy ID"

### Benutzer-ID finden
1. Aktiviere Developer Mode in Discord
2. Rechtsklick auf den Benutzer → "Copy ID"

## Sicherheit

- **Webhook URLs geheim halten**: Teile deine Webhook URL niemals öffentlich
- **Berechtigung beschränken**: Gib dem Webhook nur die minimal notwendigen Berechtigungen
- **Regelmäßige Überprüfung**: Überprüfe regelmäßig aktive Webhooks in deinen Server-Einstellungen

## Beispiel-Ausgabe

Wenn der Notifier läuft und neue Server entdeckt, siehst du Logs wie:

```
2024-01-15 14:30:25 INFO: Discovered Counter-Strike: Source server: Test Source Server
2024-01-15 14:30:25 INFO: Discord notification sent for new server: Test Source Server
2024-01-15 14:30:25 DEBUG: Discord message ID stored in database: 1234567890123456789
```

Und entsprechende Nachrichten in deinem Discord-Kanal mit allen Server-Details in einem schön formatierten Embed. 