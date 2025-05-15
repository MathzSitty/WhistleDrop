# WhistleDrop - Secure & Anonymous Whistleblower Platform

WhistleDrop ist eine Prototyp-Implementierung einer sicheren und anonymen Whistleblower-Plattform. Sie ist darauf ausgelegt, als Tor Hidden Service betrieben zu werden und ermöglicht es Whistleblowern, Dateien (z.B. Dokumente, Bilder) einzureichen, die dann Ende-zu-Ende für einen designierten Journalisten verschlüsselt werden.

## Inhaltsverzeichnis

1.  [Grundprinzipien](#grundprinzipien)
2.  [Entitäten](#entitäten)
3.  [Systemarchitektur](#systemarchitektur)
4.  [Sicherheitsdesign](#sicherheitsdesign)
5.  [Projektstruktur](#projektstruktur)
6.  [Setup und Installation](#setup-und-installation)
    *   [Voraussetzungen](#voraussetzungen)
    *   [Umgebungsvariablen konfigurieren](#umgebungsvariablen-konfigurieren)
    *   [Installation der Abhängigkeiten](#installation-der-abhängigkeiten)
    *   [Verzeichnisse und Zertifikate erstellen](#verzeichnisse-und-zertifikate-erstellen)
    *   [Journalist: RSA-Schlüsselpaare generieren](#journalist-rsa-schlüsselpaare-generieren)
    *   [Server-Admin: Journalisten-Account erstellen](#server-admin-journalisten-account-erstellen)
    *   [Server-Admin: Öffentliche Schlüssel zum Server hochladen (via GUI)](#server-admin-öffentliche-schlüssel-zum-server-hochladen-via-gui)
7.  [WhistleDrop Server starten](#whistledrop-server-starten)
    *   [Mit `tor_manager.py` (Empfohlen für Testen mit automatisiertem Standalone Tor & ephemerem Service)](#mit-tor_managerpy-empfohlen-für-testen-mit-automatisiertem-standalone-tor--ephemerem-service)
    *   [Mit manuellem Tor Hidden Service & Gunicorn (Produktion)](#mit-manuellem-tor-hidden-service--gunicorn-produktion)
8.  [Benutzung](#benutzung)
    *   [Whistleblower: Datei hochladen](#whistleblower-datei-hochladen)
    *   [Journalist: Journalist GUI Tool verwenden](#journalist-journalist-gui-tool-verwenden)
9.  [Wichtige Sicherheitshinweise & Limitierungen](#wichtige-sicherheitshinweise--limitierungen)
10. [Mögliche zukünftige Verbesserungen](#mögliche-zukünftige-verbesserungen)

## Grundprinzipien

*   **Anonymität:** Whistleblower interagieren über Tor mit der Plattform, um ihre IP-Adresse zu verschleiern.
*   **Vertraulichkeit:** Eingereichte Dateien werden sofort auf dem Server mit starker symmetrischer Verschlüsselung (AES-GCM) verschlüsselt. Der symmetrische Schlüssel selbst wird dann mit asymmetrischer Verschlüsselung (RSA-OAEP) unter Verwendung eines vorab hochgeladenen öffentlichen Schlüssels des Journalisten verschlüsselt. Der ursprüngliche Dateiname wird ebenfalls verschlüsselt.
*   **Integrität:** AES-GCM bietet authentifizierte Verschlüsselung und stellt sicher, dass Daten nicht manipuliert werden.
*   **Keine unverschlüsselten Daten auf der Festplatte:** Weder die Originaldatei noch der AES-Schlüssel werden jemals unverschlüsselt auf die Festplatte des Servers geschrieben.
*   **Einmalige Verwendung öffentlicher Schlüssel:** Jeder auf dem Server gespeicherte öffentliche RSA-Schlüssel des Journalisten wird nur einmal zum Verschlüsseln eines AES-Schlüssels verwendet und dann als "benutzt" markiert.
*   **Dateigrößenbeschränkung:** Der Server erzwingt eine maximale Uploadgröße (konfigurierbar), um Ressourcenmissbrauch zu verhindern.

## Entitäten

1.  **Whistleblower:** Eine anonyme Person, die eine Datei über den Tor Hidden Service hochlädt.
2.  **WhistleDrop Server:** Ein Server, auf dem die WhistleDrop Python/Flask-Anwendung läuft und der als Tor Hidden Service erreichbar ist. Er handhabt die Dateiaufnahme, Verschlüsselung und Speicherung. Der Server verwendet HTTPS mit einem selbstsignierten Zertifikat für die lokale Kommunikation, auf die der Tor Hidden Service weiterleitet.
3.  **Journalist:** Der Empfänger der Information. Der Journalist besitzt die RSA-Privatschlüssel, die notwendig sind, um die AES-Schlüssel und anschließend die eingereichten Dateien zu entschlüsseln. Er verwendet das Journalist GUI Tool und authentifiziert sich per Username/Passwort am Server.

## Systemarchitektur

1.  **Aktion des Whistleblowers:**
    *   Verbindet sich über den Tor Browser mit der `https://<onion-adresse>.onion`-Adresse von WhistleDrop. (Muss ggf. eine Zertifikatswarnung für das selbstsignierte Zertifikat des Hidden Service akzeptieren).
    *   Lädt eine Datei über ein einfaches Webformular hoch.
2.  **Aktion des WhistleDrop Servers (beim Upload):**
    *   Empfängt die Datei im Speicher. Prüft auf Dateigrößenlimit.
    *   Generiert einen einzigartigen, zufälligen AES-256-Schlüssel.
    *   Verschlüsselt die Dateidaten und den Originaldateinamen im Speicher mit AES-256-GCM.
    *   Ruft einen verfügbaren öffentlichen RSA-Schlüssel (inkl. eines "Key Hints" zur Identifizierung) aus seiner lokalen Datenbank ab.
    *   Verschlüsselt den AES-Schlüssel mit diesem öffentlichen RSA-Schlüssel.
    *   Speichert die verschlüsselte Datei, den verschlüsselten AES-Schlüssel, den verschlüsselten Dateinamen, die ID des verwendeten öffentlichen RSA-Schlüssels und den Key Hint in einem eindeutigen Einreichungsverzeichnis.
    *   Markiert den öffentlichen RSA-Schlüssel in seiner Datenbank als "benutzt".
    *   Gibt eine Erfolgsmeldung an den Whistleblower zurück.
3.  **Aktion des Journalisten (Abruf & Entschlüsselung mit GUI):**
    *   Verwendet das `journalist_tool/journalist_gui.py` Skript.
    *   Konfiguriert die Server URL (die `https://<onion-adresse>.onion`-Adresse oder `http://<onion-adresse>.onion` je nach HS-Konfiguration, oder lokal `https://127.0.0.1:<https_port>`).
    *   Loggt sich mit seinem Benutzernamen und Passwort am Server ein.
    *   Kann neue RSA-Schlüsselpaare (optional passwortgeschützt) generieren und öffentliche Schlüssel zum Server hochladen.
    *   Ruft die Liste der Einreichungen ab. Die Liste zeigt die Submission ID und einen "Key Hint".
    *   Wählt eine Einreichung und den zugehörigen privaten Schlüssel (anhand des Hints).
    *   Gibt ggf. das Passwort für den privaten Schlüssel ein.
    *   Das Tool lädt die verschlüsselten Komponenten herunter, entschlüsselt den AES-Schlüssel mit dem privaten RSA-Schlüssel, entschlüsselt dann den Originaldateinamen und den Dateiinhalt mit dem AES-Schlüssel.
    *   Speichert die entschlüsselte Datei lokal.

## Sicherheitsdesign

*   **Verschlüsselung:**
    *   Dateiinhalt & Dateiname: AES-256-GCM.
    *   AES-Schlüssel: RSA-4096 mit OAEP-Padding.
*   **Schlüsselverwaltung:**
    *   AES-Schlüssel sind dateispezifisch, einmalig verwendet und verschlüsselt gespeichert.
    *   Journalisten-RSA-Schlüsselpaare werden vom Journalisten offline generiert (optional passwortgeschützt). Nur öffentliche Schlüssel (mit einem Hint) werden dem Server über das Journalist GUI hinzugefügt.
    *   Server führt eine Datenbank mit verfügbaren öffentlichen RSA-Schlüsseln und deren Hints. Jeder öffentliche Schlüssel wird nur einmal verwendet.
    *   Private RSA-Schlüssel verlassen *niemals* den Journalisten.
*   **In-Memory-Verarbeitung:** Hochgeladene Dateien und AES-Schlüssel werden im Speicher verschlüsselt, bevor (verschlüsselte) Derivate auf die Festplatte geschrieben werden.
*   **Tor Hidden Service:** Bietet Anonymität auf Transportebene für den Whistleblower und verschleiert den Serverstandort. Der Service kann so konfiguriert werden, dass er HTTPS mit einem selbstsignierten Zertifikat anbietet.
*   **Authentifizierung:** Journalisten-Endpunkte sind durch einen Login (Username/Passwort) geschützt. Passwörter werden serverseitig gehasht gespeichert. Die Kommunikation erfolgt über HTTPS.

## Projektstruktur
whistledrop/
├── whistledrop_server/         # Flask server application
│   ├── app.py                  # Main Flask app, routes, login logic
│   ├── crypto_utils.py         # Cryptographic functions
│   ├── key_manager.py          # Manages RSA public keys & journalist accounts (SQLite DB)
│   ├── models.py               # User model for Flask-Login (Journalist)
│   ├── storage_manager.py      # Handles file storage for submissions
│   ├── config.py               # Configuration (ports, paths, etc.)
│   ├── templates/              # HTML templates
│   │   ├── upload.html         # Whistleblower upload form
│   │   └── login.html          # Journalist login form
│   ├── data/                   # Data directory (submissions/, db/) - NICHT versionieren!
│   │   └── db/key_store.db     # SQLite Datenbank
│   ├── certs/                  # SSL certificates (cert.pem, key.pem) - NICHT versionieren!
│   └── wsgi.py                 # WSGI entry for Gunicorn
├── journalist_tool/            # Scripts and GUI for the journalist
│   ├── journalist_gui.py       # Tkinter GUI application
│   ├── crypto_utils.py         # Crypto functions (shared logic with server)
│   ├── gui_config.json         # GUI configuration (server URL, SOCKS proxy)
│   ├── private_keys/           # Journalist stores private keys here - NICHT versionieren!
│   ├── public_keys_for_server/ # Generated public keys for server upload
│   └── decrypted_submissions/  # Default location for decrypted files - NICHT versionieren!
├── utils/                      # Utility scripts
│   ├── generate_rsa_keys.py    # To create RSA key pairs
│   ├── add_public_key_to_db.py # To add public keys to server DB (CLI)
│   ├── create_journalist_account.py # To create journalist accounts (CLI)
│   ├── generate_ssl_certs.py   # To create self-signed SSL certs for Flask
│   └── tor_manager.py          # Script to start/manage Standalone Tor & WhistleDrop server
├── .gitignore
├── requirements.txt
└── README.md (Diese Datei)

## Setup und Installation

### Voraussetzungen

*   Python 3.9+
*   `pip` (Python Paket-Installer)
*   **Standalone Tor (Expert Bundle):** Empfohlen für den Serverbetrieb mit `tor_manager.py`. Download von [torproject.org](https://www.torproject.org/download/tor/).
*   **Tor Browser:** Für den Whistleblower und optional für den Journalisten, um auf `.onion`-Adressen zuzugreifen.
*   (Optional) Git zum Klonen des Repositories.
*   (Optional) Ein SQLite Browser zum Inspizieren der `key_store.db`.

### Umgebungsvariablen konfigurieren

*   **Für den WhistleDrop Server (wo `tor_manager.py` läuft):**
    *   `WHISTLEDROP_SECRET_KEY` (Optional, für Flask Sessions): Ein langer, zufälliger String. Wenn nicht gesetzt, wird ein Standardwert verwendet (nicht für Produktion empfohlen).
    *   `TOR_CONTROL_PASSWORD` (Optional, **nicht empfohlen bei CookieAuthentication**): Nur wenn der ControlPort des Standalone Tor mit `HashedControlPassword` gesichert ist. `tor_manager.py` ist für `CookieAuthentication` mit dem Standalone Tor optimiert.

*   **Für die Maschine des Journalisten (wo `journalist_gui.py` läuft, für `.onion`-Zugriff):**
    *   `HTTP_PROXY="socks5h://127.0.0.1:9050"` (oder der Port deines Tor SOCKS Proxys, z.B. `9150` für Tor Browser)
    *   `HTTPS_PROXY="socks5h://127.0.0.1:9050"`
    *   `NO_PROXY="localhost,127.0.0.1"` (Wichtig, damit lokale Serveradressen nicht über den Proxy geleitet werden)

### Installation der Abhängigkeiten

1.  Klone das Repository oder lade die Projektdateien herunter.
2.  Navigiere in das Hauptverzeichnis `whistledrop/`.
3.  Erstelle eine virtuelle Python-Umgebung und aktiviere sie:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # .\venv\Scripts\activate    # Windows
    ```
4.  Installiere die benötigten Pakete:
    ```bash
    pip install -r requirements.txt
    ```

### Verzeichnisse und Zertifikate erstellen

1.  **Verzeichnisse:** Obwohl einige Skripte versuchen, Verzeichnisse zu erstellen, stelle sicher, dass folgende existieren:
    ```bash
    mkdir -p whistledrop_server/data/submissions
    mkdir -p whistledrop_server/data/db
    mkdir -p whistledrop_server/certs
    mkdir -p journalist_tool/private_keys
    mkdir -p journalist_tool/public_keys_for_server
    mkdir -p journalist_tool/decrypted_submissions
    ```
2.  **SSL-Zertifikate für Flask Server (HTTPS):**
    Führe das Skript aus, um selbstsignierte Zertifikate zu generieren, die der Flask-Server für HTTPS verwendet (wichtig, wenn der Hidden Service auf ein HTTPS-Ziel zeigt).
    ```bash
    python utils/generate_ssl_certs.py
    ```
    Dies erstellt `cert.pem` und `key.pem` in `whistledrop_server/certs/`.

### Journalist: RSA-Schlüsselpaare generieren

Der Journalist generiert seine RSA-Schlüsselpaare mit dem Journalist GUI:
1.  Starte das Journalist GUI (`python journalist_tool/journalist_gui.py`).
2.  Gehe zum Tab "Key Generation".
3.  Konfiguriere Anzahl, Präfix und optional ein Passwort.
4.  Klicke "Generate Key Pairs".
    *   Private Schlüssel werden in `journalist_tool/private_keys/` gespeichert.
    *   Öffentliche Schlüssel (für den Server) in `journalist_tool/public_keys_for_server/`.

### Server-Admin: Journalisten-Account erstellen

Bevor ein Journalist sich einloggen kann, muss ein Account für ihn auf dem Server erstellt werden:
1.  Führe auf der Maschine, auf der der WhistleDrop-Server laufen wird, folgendes Skript aus:
    ```bash
    python utils/create_journalist_account.py
    ```
2.  Folge den Anweisungen, um einen Benutzernamen und ein Passwort für den Journalisten festzulegen. Diese Zugangsdaten werden gehasht in der `key_store.db` gespeichert.

### Server-Admin: Öffentliche Schlüssel zum Server hochladen (via GUI)

Nachdem der Journalist seine Schlüssel generiert und der Admin den Journalisten-Account erstellt hat:
1.  Der Journalist startet das GUI, konfiguriert die Server-URL (z.B. die `.onion`-Adresse oder `https://127.0.0.1:<https_port>`) und den SOCKS-Proxy (z.B. `127.0.0.1:9050` für den vom `tor_manager.py` gestarteten Standalone Tor).
2.  Der Journalist loggt sich mit seinem Benutzernamen und Passwort ein.
3.  Im Tab "Connection & Admin" klickt der Journalist auf "Select & Upload Public Keys" und wählt die zuvor generierten öffentlichen Schlüssel aus `journalist_tool/public_keys_for_server/` aus.

## WhistleDrop Server starten

### Mit `tor_manager.py` (Empfohlen für Testen mit automatisiertem Standalone Tor & ephemerem Service)

Dieses Skript automatisiert den Start eines lokalen Standalone Tor-Prozesses (Expert Bundle), die Erstellung eines ephemeren Hidden Service und den Start des Flask-Webservers.

1.  **Standalone Tor (Expert Bundle) vorbereiten:**
    *   Lade das Tor Expert Bundle von torproject.org herunter und entpacke es (z.B. nach `C:\Tor` oder `/opt/tor_expert_bundle`).
    *   Erstelle eine `torrc`-Datei für diesen Standalone Tor (z.B. in `C:\Tor\data\torrc` oder `/opt/tor_expert_bundle/Data/Tor/torrc`) mit mindestens folgendem Inhalt (Pfade anpassen!):
        ```torrc
        DataDirectory /pfad/zu/deinem/tor_data_verzeichnis # z.B. C:\Tor\data
        GeoIPFile /pfad/zu/deinem/tor_data_verzeichnis/geoip
        GeoIPv6File /pfad/zu/deinem/tor_data_verzeichnis/geoip6
        ControlPort 9051
        CookieAuthentication 1
        Log notice file /pfad/zu/deinem/tor_data_verzeichnis/notice.log
        SocksPort 9050
        SocksPolicy accept 127.0.0.1/32
        SocksPolicy reject *
        ```
        Kopiere `geoip` und `geoip6` Dateien aus einer Tor Browser Installation in dein `DataDirectory`.
    *   Passe die Pfade `TOR_EXE_PATH` und `TOR_RC_PATH` am Anfang von `utils/tor_manager.py` an deine Installation an.

2.  **`tor_manager.py` starten:**
    ```bash
    python utils/tor_manager.py
    ```
    *   Das Skript startet den Standalone Tor, dann den Flask-Server und gibt die `.onion`-Adresse aus.
    *   Standardmäßig wird ein HTTPS Hidden Service erstellt, der auf den lokalen HTTPS Flask-Server zeigt. Du kannst `USE_LOCAL_HTTPS_TARGET = False` in `tor_manager.py` setzen, um testweise einen HTTP Hidden Service zu erstellen, der auf einen lokalen HTTP Flask-Server zeigt.

### Mit manuellem Tor Hidden Service & Gunicorn (Produktion)

Für einen produktiven, persistenten Hidden Service:

1.  **Flask-Anwendung mit Gunicorn bereitstellen:**
    ```bash
    gunicorn --bind 127.0.0.1:5001 'whistledrop_server.app:app' --certfile whistledrop_server/certs/cert.pem --keyfile whistledrop_server/certs/key.pem
    # Port 5001 ist der HTTPS-Port, auf dem Flask lauscht.
    # Für HTTP (nicht empfohlen für das Backend eines HTTPS .onion):
    # gunicorn --bind 127.0.0.1:5000 'whistledrop_server.app:app'
    ```
2.  **Tor Hidden Service manuell konfigurieren:**
    *   Bearbeite die `torrc`-Datei deines System-Tor-Dienstes.
    *   Füge Zeilen für deinen Hidden Service hinzu (Beispiel für HTTPS .onion):
        ```torrc
        HiddenServiceDir /var/lib/tor/whistledrop_service/ # Pfad zum Speichern der HS-Schlüssel
        HiddenServicePort 443 127.0.0.1:5001             # Leitet Port 443 des .onion auf lokalen HTTPS-Flask-Server
        # Für HTTP .onion (wenn Flask auf HTTP Port 5000 lauscht):
        # HiddenServicePort 80 127.0.0.1:5000
        ```
    *   Starte den Tor-Dienst neu. Die `.onion`-Adresse findest du in der Datei `hostname` im `HiddenServiceDir`.

## Benutzung

### Whistleblower: Datei hochladen
1.  Öffne die `.onion`-Adresse (z.B. `https://<zufälligezeichen>.onion`) im Tor Browser.
2.  Akzeptiere ggf. die Zertifikatswarnung (da das Zertifikat selbstsigniert ist).
3.  Wähle eine Datei aus und klicke "Upload Securely".
4.  Eine Erfolgsmeldung mit einer Submission ID wird angezeigt.

### Journalist: Journalist GUI Tool verwenden
1.  **Vorbereitung:** Stelle sicher, dass die Umgebungsvariablen `HTTP_PROXY`, `HTTPS_PROXY` und `NO_PROXY` korrekt gesetzt sind, wenn du das GUI startest (siehe [Umgebungsvariablen konfigurieren](#umgebungsvariablen-konfigurieren)).
2.  Starte das GUI: `python journalist_tool/journalist_gui.py`.
3.  **Konfiguration im Tab "Connection & Admin":**
    *   **Server URL:** Gib die `.onion`-Adresse des WhistleDrop-Servers ein (z.B. `https://<onion-adresse>.onion` oder `http://...` je nach HS-Konfiguration) oder die lokale Adresse (z.B. `https://127.0.0.1:5001` für Tests).
    *   **Tor SOCKS Proxy:** Host `127.0.0.1`, Port `9050` (für den vom `tor_manager.py` gestarteten Standalone Tor) oder `9150` (wenn du den SOCKS-Proxy des Tor Browsers verwenden möchtest und dieser läuft).
    *   Klicke "Save Connection & Proxy Settings".
4.  **Login:** Klicke auf "Login" und gib deinen Benutzernamen und dein Passwort ein.
5.  **Schlüssel hochladen:** Lade deine zuvor generierten öffentlichen RSA-Schlüssel über "Select & Upload Public Keys" hoch.
6.  **Submissions abrufen (Tab "Submissions"):**
    *   Klicke "Refresh Submissions List".
    *   Wähle eine Submission aus.
    *   Wähle den passenden privaten Schlüssel über "Select Private Key...".
    *   Gib ggf. das Passwort für den privaten Schlüssel ein.
    *   Klicke "Decrypt Submission" und speichere die entschlüsselte Datei.

## Wichtige Sicherheitshinweise & Limitierungen

*   **Prototyp-Status:** Dies ist eine Prototyp-Implementierung. Sie wurde nicht umfassend auf Sicherheit geprüft und sollte **nicht für den produktiven Umgang mit echten, hochsensiblen Whistleblower-Daten verwendet werden.**
*   **Selbstsignierte Zertifikate:** Die Verwendung von HTTPS mit selbstsignierten Zertifikaten (sowohl für den lokalen Flask-Server als auch potenziell für den `.onion`-Dienst) führt zu Browser-Warnungen.
*   **Server-Sicherheit:** Die Sicherheit des zugrundeliegenden Serversystems ist entscheidend.
*   **Metadaten:** Obwohl die Plattform versucht, Metadaten zu minimieren, können Dateiformate selbst Metadaten enthalten. Whistleblower sollten entsprechend geschult werden (z.B. Verwendung von Tails, Metadaten-Bereinigungstools).
*   **Kein Virenscan:** Hochgeladene Dateien werden nicht auf Malware gescannt. Journalisten müssen äußerste Vorsicht walten lassen und Dateien in isolierten Umgebungen prüfen.
*   **Rate Limiting:** Aktuell kein robustes Rate Limiting implementiert, was den Server anfällig für DoS-Angriffe oder das schnelle "Verbrauchen" von Public Keys machen könnte.

## Mögliche zukünftige Verbesserungen

*   Implementierung eines robusten Rate-Limitings.
*   Verbesserte Fehlerbehandlung und Logging.
*   Option für Journalisten, Public Keys direkt im GUI zu verwalten (z.B. als "verbraucht" markierte Keys wieder freizugeben, falls ein Upload fehlschlug).
*   Integration eines Virenscanners (serverseitig, in einer Sandbox).
*   Zwei-Faktor-Authentifizierung für Journalisten-Logins.
*   Detailliertere Anleitung zur Absicherung des Serverbetriebs.
*   Unterstützung für persistente Hidden Services direkt im `tor_manager.py`.
*   Verbesserung der Robustheit des automatischen Tor-Starts im `tor_manager.py` (z.B. besseres Warten auf "Bootstrapped 100%").