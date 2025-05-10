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
    *   [Verzeichnisse erstellen](#verzeichnisse-erstellen)
    *   [Journalist: RSA-Schlüsselpaare generieren](#journalist-rsa-schlüsselpaare-generieren)
    *   [Server-Admin: Öffentliche Schlüssel zur Server-Datenbank hinzufügen](#server-admin-öffentliche-schlüssel-zur-server-datenbank-hinzufügen)
7.  [WhistleDrop Server starten](#whistledrop-server-starten)
    *   [Mit `tor_manager.py` (Empfohlen für einfaches Testen mit ephemerem Service)](#mit-tor_managerpy-empfohlen-für-einfaches-testen-mit-ephemerem-service)
    *   [Mit manuellem Tor Hidden Service & Gunicorn (Produktion)](#mit-manuellem-tor-hidden-service--gunicorn-produktion)
8.  [Benutzung](#benutzung)
    *   [Whistleblower: Datei hochladen](#whistleblower-datei-hochladen)
    *   [Journalist: Journalist GUI Tool verwenden](#journalist-journalist-gui-tool-verwenden)
9.  [Wichtige Sicherheitshinweise & Limitierungen](#wichtige-sicherheitshinweise--limitierungen)
10. [Mögliche zukünftige Verbesserungen](#mögliche-zukünftige-verbesserungen)

## Grundprinzipien

*   **Anonymität:** Whistleblower interagieren über Tor mit der Plattform, um ihre IP-Adresse zu verschleiern.
*   **Vertraulichkeit:** Eingereichte Dateien werden sofort auf dem Server mit starker symmetrischer Verschlüsselung (AES-GCM) verschlüsselt. Der symmetrische Schlüssel selbst wird dann mit asymmetrischer Verschlüsselung (RSA-OAEP) unter Verwendung eines vorab geladenen öffentlichen Schlüssels des Journalisten verschlüsselt. Der ursprüngliche Dateiname wird ebenfalls verschlüsselt.
*   **Integrität:** AES-GCM bietet authentifizierte Verschlüsselung und stellt sicher, dass Daten nicht manipuliert werden.
*   **Keine unverschlüsselten Daten auf der Festplatte:** Weder die Originaldatei noch der AES-Schlüssel werden jemals unverschlüsselt auf die Festplatte des Servers geschrieben.
*   **Einmalige Verwendung öffentlicher Schlüssel:** Jeder auf dem Server gespeicherte öffentliche RSA-Schlüssel des Journalisten wird nur einmal zum Verschlüsseln eines AES-Schlüssels verwendet und dann als "benutzt" markiert.
*   **Dateigrößenbeschränkung:** Der Server erzwingt eine maximale Uploadgröße (konfigurierbar), um Ressourcenmissbrauch zu verhindern.

## Entitäten

1.  **Whistleblower:** Eine anonyme Person, die eine Datei über den Tor Hidden Service hochlädt.
2.  **WhistleDrop Server:** Ein Server, auf dem die WhistleDrop Python/Flask-Anwendung läuft und der als Tor Hidden Service erreichbar ist. Er handhabt die Dateiaufnahme, Verschlüsselung und Speicherung.
3.  **Journalist:** Der Empfänger der Information. Der Journalist besitzt die RSA-Privatschlüssel, die notwendig sind, um die AES-Schlüssel und anschließend die eingereichten Dateien zu entschlüsseln. Er verwendet das Journalist GUI Tool.

## Systemarchitektur

1.  **Aktion des Whistleblowers:**
    *   Verbindet sich über den Tor Browser mit der `.onion`-Adresse von WhistleDrop.
    *   Lädt eine Datei über ein einfaches Webformular hoch. Die Webseite hat ein modernes Design mit Herbst-Thema und einer Ladeanzeige.
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
    *   Konfiguriert die Server URL (die `.onion`-Adresse) und seinen API-Key.
    *   Kann neue RSA-Schlüsselpaare (optional passwortgeschützt) generieren und öffentliche Schlüssel zum Server hochladen.
    *   Ruft die Liste der Einreichungen ab. Die Liste zeigt die Submission ID und einen "Key Hint" (Name des serverseitig verwendeten öffentlichen Schlüssels).
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
    *   Journalisten-RSA-Schlüsselpaare werden vom Journalisten offline generiert (optional passwortgeschützt). Nur öffentliche Schlüssel (mit einem Hint) werden dem Server-Admin übergeben.
    *   Server führt eine Datenbank mit verfügbaren öffentlichen RSA-Schlüsseln und deren Hints. Jeder öffentliche Schlüssel wird nur einmal verwendet.
    *   Private RSA-Schlüssel verlassen *niemals* den Journalisten.
*   **In-Memory-Verarbeitung:** Hochgeladene Dateien und AES-Schlüssel werden im Speicher verschlüsselt, bevor (verschlüsselte) Derivate auf die Festplatte geschrieben werden.
*   **Tor Hidden Service:** Bietet Anonymität auf Transportebene für den Whistleblower und verschleiert den Serverstandort.
*   **Authentifizierung:** Journalisten-API-Endpunkte sind durch einen API-Key geschützt.

## Projektstruktur
whistledrop/
├── whistledrop_server/ # Flask server application
│ ├── app.py # Main Flask app, routes
│ ├── crypto_utils.py # Cryptographic functions
│ ├── key_manager.py # Manages RSA public keys (SQLite DB)
│ ├── storage_manager.py # Handles file storage for submissions
│ ├── config.py # Configuration
│ ├── templates/upload.html # HTML upload form (autumn theme)
│ ├── data/ # Data directory (submissions/, db/) - NICHT versionieren!
│ └── wsgi.py # WSGI entry for Gunicorn
├── journalist_tool/ # Scripts and GUI for the journalist
│ ├── journalist_gui.py # Tkinter GUI application (autumn theme)
│ ├── crypto_utils.py # Crypto functions (shared logic with server)
│ ├── private_keys/ # Journalist stores private keys here - NICHT versionieren!
│ ├── public_keys_for_server/ # Generated public keys for server upload
│ └── decrypted_submissions/ # Default location for decrypted files - NICHT versionieren!
├── utils/ # Utility scripts
│ ├── generate_rsa_keys.py # To create RSA key pairs
│ ├── add_public_key_to_db.py # To add public keys to server DB (CLI)
│ └── tor_manager.py # Script to help manage Tor hidden service (ephemeral)
├── .gitignore
├── requirements.txt
└── README.md (Diese Datei)


## Setup und Installation

### Voraussetzungen

*   Python 3.9+
*   `pip` (Python Paket-Installer)
*   Tor (installiert und lauffähig, insbesondere für `tor_manager.py` und den Journalisten für `.onion`-Zugriff)
*   (Optional) Git zum Klonen des Repositories.
*   (Optional) Ein SQLite Browser (z.B. "DB Browser for SQLite") zum Inspizieren der `key_store.db`.

### Umgebungsvariablen konfigurieren

Die folgenden Umgebungsvariablen sind wichtig für den Betrieb:

*   **Für den WhistleDrop Server (wo `app.py` / `tor_manager.py` laufen):**
    1.  `WHISTLEDROP_JOURNALIST_API_KEY`
        *   **Zweck:** Geheimer Schlüssel für den Journalisten zur Authentifizierung an den API-Endpunkten des Servers. Dieser Schlüssel muss dem Journalisten sicher mitgeteilt werden.
        *   **Beispielwert:** `IhrStarkerZufaelligerAPIKeyHierBestehendAus64Zeichen` (Generieren Sie einen langen, zufälligen String, z.B. mit `python -c "import secrets; print(secrets.token_hex(32))"`).
        *   **Setzen:** Via `export VARNAME="wert"` (Linux/macOS) oder `set VARNAME=wert` (Windows CMD) oder über die Systemeinstellungen für Umgebungsvariablen. Der Server gibt eine Warnung aus und generiert einen temporären Key für die aktuelle Sitzung, falls diese Variable nicht gesetzt ist. Für den produktiven Betrieb **muss** diese Variable gesetzt werden.

    2.  `TOR_CONTROL_PASSWORD` (Optional)
        *   **Zweck:** Das Klartext-Passwort für den Tor ControlPort, falls dieser passwortgeschützt ist (z.B. wenn Sie `HashedControlPassword` in `torrc` verwenden). `tor_manager.py` benötigt dies zur Authentifizierung via `stem`.
        *   **Beispielwert:** `IhrOriginalTorControlPasswort`
        *   **Empfehlung:** Bevorzugen Sie `CookieAuthentication 1` in Ihrer `torrc`-Datei für lokale Skripte wie `tor_manager.py`. Wenn Sie `CookieAuthentication` verwenden, setzen Sie `TOR_CONTROL_PASSWORD` **nicht** (oder lassen Sie es leer).

    3.  `WHISTLEDROP_SECRET_KEY` (Optional, für Flask)
        *   **Zweck:** Ein geheimer Schlüssel für Flask-spezifische Funktionen (z.B. Signierung von Session-Cookies). Weniger kritisch für diese API-fokussierte Anwendung, aber gute Praxis.
        *   **Beispielwert:** `EinAndererSehrStarkerFlaskGeheimschluessel`

*   **Für die Maschine des Journalisten (wo `journalist_gui.py` läuft, um auf `.onion`-Adressen zuzugreifen):**
    1.  `HTTP_PROXY`
        *   **Zweck:** Leitet HTTP-Anfragen des Journalist GUI über den lokalen Tor SOCKS Proxy.
        *   **Beispielwert:** `socks5h://127.0.0.1:9050` (Standard-Tor-Port) oder `socks5h://127.0.0.1:9150` (üblicher Port, wenn Tor Browser läuft).
    2.  `HTTPS_PROXY`
        *   **Zweck:** Leitet HTTPS-Anfragen des Journalist GUI über den lokalen Tor SOCKS Proxy.
        *   **Beispielwert:** `socks5h://127.0.0.1:9050` (oder `9150`)

    **Hinweis:** Das `h` in `socks5h` ist wichtig für die DNS-Auflösung von `.onion`-Adressen über den Proxy. Starten Sie Ihr Terminal/Ihre IDE neu, nachdem Sie Umgebungsvariablen gesetzt haben, damit diese wirksam werden.

### Installation der Abhängigkeiten

1.  Klonen Sie das Repository (optional) oder laden Sie die Projektdateien herunter.
2.  Navigieren Sie in das Hauptverzeichnis `whistledrop/`.
3.  Erstellen Sie eine virtuelle Python-Umgebung und aktivieren Sie sie:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # .\venv\Scripts\activate    # Windows
    ```
4.  Installieren Sie die benötigten Pakete:
    ```bash
    pip install -r requirements.txt
    ```

### Verzeichnisse erstellen

Obwohl einige Skripte versuchen, Verzeichnisse zu erstellen, stellen Sie sicher, dass folgende existieren (besonders `data` und die Unterverzeichnisse für den Journalisten):
```bash
mkdir -p whistledrop_server/data/submissions
mkdir -p whistledrop_server/data/db
mkdir -p journalist_tool/private_keys
mkdir -p journalist_tool/public_keys_for_server
mkdir -p journalist_tool/decrypted_submissions