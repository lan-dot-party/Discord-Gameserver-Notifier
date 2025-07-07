# Deployment-Taskliste – Discord Gameserver Notifier

Die Liste ist nach logischer Reihenfolge aufgebaut.  
Fülle die Checkboxen bei Erledigung – so behalten wir den Überblick.

## 1️⃣ Code-Anpassungen

### 1.1 ConfigManager
- [x] Standard-Pfad auf **`/etc/dgn/config.yaml`** setzen  
- [x] Fallback-Suchreihenfolge implementieren  
  1. CLI-Argument / Umgebungsvariable  
  2. `/etc/dgn/config.yaml`  
  3. `$XDG_CONFIG_HOME/dgn/config.yaml` (optional)  
  4. Repository-Pfad `config/config.yaml`
- [x] (Optional) neues CLI-Argument `--config <pfad>` bzw. Env `DGN_CONFIG` hinzufügen  
- [x] Unit-Tests für die Pfadlogik schreiben/aktualisieren

### 1.2 pyproject.toml
- [x] Beispiel-Konfig **`config/config.yaml.example`** in `[tool.hatch.build.targets.wheel] include` aufnehmen

## 2️⃣ Packaging-Files

### 2.1 Post-Install-Skript
- [x] Verzeichnis **`packaging/`** anlegen  
- [x] **`postinstall.sh`** erstellen  
  - legt `/etc/dgn` an (falls fehlt)  
  - kopiert Beispiel-Konfig nach `/etc/dgn/config.yaml`, wenn dort noch keine Datei existiert  
- [x] Skript ausführbar machen (`chmod +x`)

### 2.2 Systemd-Service (❗ optional, aber empfohlen)
- [x] Datei `discord-gameserver-notifier.service` erstellen  
- [x] Service im FPM-Aufruf einbinden (`--deb-systemd` / `--rpm-service`)  
- [x] Dokumentation im README ergänzen

## 3️⃣ GitHub-Actions

### 3.1 Neuer Job **`package-linux`**
- [x] Nach dem bestehenden *build*-Job ausführen (`needs: build`)  
- [x] FPM installieren  
- [x] Version automatisch aus `pyproject.toml` lesen  
- [x] Wheel in **.deb** & **.rpm** umwandeln  
  - `--before-install packaging/preinstall.sh`
  - `--after-install packaging/postinstall.sh`
  - `--before-remove packaging/preremove.sh`
  - `--deb-systemd / --rpm-service packaging/discord-gameserver-notifier.service`
- [x] Artefakte `*.deb`, `*.rpm` hochladen

## 4️⃣ Tests & Verifikation

- [ ] Lokalen Wheel-Build durchführen (`python -m build`)  
- [ ] Mit FPM .deb erzeugen und via `sudo dpkg -i` installieren  
- [ ] Prüfen, dass  
  - Konsolen-Skript `discord-gameserver-notifier` funktioniert  
  - Config aus `/etc/dgn` geladen wird  
- [ ] RPM analog (z. B. Fedora in Docker/Podman) testen  
- [ ] Unit-/Integration-Tests grün

## 5️⃣ Release-Prozess

- [ ] Versions-Bump in `pyproject.toml`  
- [ ] Git-Tag `vX.Y.Z` pushen (löst Workflow aus)  
- [ ] Prüfen, dass CI Wheel + .deb + .rpm erstellt  
- [ ] Release-Assets auf GitHub kontrollieren 