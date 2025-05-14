# WhistleDrop - Secure & Anonymous Whistleblower Platform (SecureDrop-Inspired Workflow)

WhistleDrop ist eine Prototyp-Implementierung einer sicheren und anonymen Whistleblower-Plattform, deren Workflow stark von SecureDrop inspiriert ist. Sie ist darauf ausgelegt, als Tor Hidden Service betrieben zu werden. Whistleblower laden Dateien über einen HTTPS-Onion-Service hoch. Journalisten erhalten Benachrichtigungen über neue Einreichungen über eine separate, gesicherte Web-Schnittstelle (ebenfalls über Tor). Die eigentlichen verschlüsselten Daten werden durch einen Administrator exportiert und offline (z.B. per USB-Stick) an den Journalisten übergeben, der sie dann auf einer isolierten "Secure Viewing Station" (SVS) entschlüsselt.

## Inhaltsverzeichnis

1.  [Grundprinzipien](#grundprinzipien)
2.  [Entitäten](#entitäten)
3.  [Systemarchitektur & Workflow](#systemarchitektur--workflow)
4.  [Sicherheitsdesign](#sicherheitsdesign)
5.  [Projektstruktur](#projektstruktur)
6.  [Setup und Installation (Server-Administrator)](#setup-und-installation-server-administrator)
    *   [Voraussetzungen (Server)](#voraussetzungen-server)
    *   [Umgebungsvariablen konfigurieren (Server)](#umgebungsvariablen-konfigurieren-server)
    *   [SSL-Zertifikat generieren (Server)](#ssl-zertifikat-generieren-server)
    *   [Installation der Abhängigkeiten (Server)](#installation-der-abhängigkeiten-server)
    *   [Verzeichnisse erstellen (Server)](#verzeichnisse-erstellen-server)
7.  [Setup und Installation (Journalist)](#setup-und-installation-journalist)
    *   [Voraussetzungen (Journalist Workstation / SVS)](#voraussetzungen-journalist-workstation--svs)
    *   [RSA-Schlüsselpaare für Inhaltsverschlüsselung generieren (Journalist)](#rsa-schlüsselpaare-für-inhaltsverschlüsselung-generieren-journalist)
    *   [Installation der Abhängigkeiten (Journalist)](#installation-der-abhängigkeiten-journalist)
8.  [Administrative Aufgaben (Server-Administrator)](#administrative-aufgaben-server-administrator)
    *   [Öffentliche RSA-Schlüssel (für Verschlüsselung) zur Server-Datenbank hinzufügen](#öffentliche-rsa-schlüssel-für-verschlüsselung-zur-server-datenbank-hinzufügen)
    *   [API-Key für Journalist Interface sicher generieren und mitteilen](#api-key-für-journalist-interface-sicher-generieren-und-mitteilen)
9.  [WhistleDrop Server starten (Server-Administrator)](#whistledrop-server-starten-server-administrator)
    *   [Mit `tor_manager.py` (Empfohlen für Testen mit ephemerem Service)](#mit-tor_managerpy-empfohlen-für-testen-mit-ephemerem-service)
    *   [Mit manuellem Tor Hidden Service & Gunicorn (Produktion)](#mit-manuellem-tor-hidden-service--gunicorn-produktion)
10. [Benutzung](#benutzung)
    *   [Whistleblower: Datei über HTTPS-Onion-Service hochladen](#whistleblower-datei-über-https-onion-service-hochladen)
    *   [Journalist: Metadaten über Journalist Interface abrufen](#journalist-metadaten-über-journalist-interface-abrufen)
    *   [Server-Administrator: Einreichungen exportieren](#server-administrator-einreichungen-exportieren)
    *   [Journalist: Exportierte Einreichungen importieren und entschlüsseln (GUI/CLI)](#journalist-exportierte-einreichungen-importieren-und-entschlüsseln-guicli)
11. [Wichtige Sicherheitshinweise & Limitierungen](#wichtige-sicherheitshinweise--limitierungen)
12. [Mögliche zukünftige Verbesserungen](#mögliche-zukünftige-verbesserungen)

## Grundprinzipien

*   **Anonymität (Whistleblower):** Interaktion über HTTPS Tor Hidden Service.
*   **Vertraulichkeit (Ende-zu-Ende):** Dateien werden auf dem Server mit AES-GCM verschlüsselt (dateispezifischer Schlüssel). Dieser AES-Schlüssel wird mit dem öffentlichen RSA-Schlüssel des Journalisten verschlüsselt.
*   **Integrität:** AES-GCM bietet authentifizierte Verschlüsselung.
*   **Keine unverschlüsselten Daten auf dem Server-Festplatte:** Originaldateien und AES-Schlüssel werden nie unverschlüsselt gespeichert.
*   **Einmalige Verwendung öffentlicher RSA-Schlüssel:** Jeder RSA-Schlüssel wird nur einmal verwendet und dann als "benutzt" markiert.
*   **Isolation der Entschlüsselung:** Journalisten entschlüsseln Daten auf einer separaten, idealerweise isolierten Secure Viewing Station (SVS), nicht durch direkten Online-Zugriff auf den Submission-Server.
*   **Kontrollierter Datenfluss zum Journalisten:** Verschlüsselte Daten werden vom Admin exportiert und offline (z.B. USB) an den Journalisten übergeben.

## Entitäten

1.  **Whistleblower:** Anonyme Person, die Dateien über den HTTPS Tor Hidden Service hochlädt.
2.  **WhistleDrop Server (Application Server):** Server mit Flask-Anwendung für Uploads und das Journalist Interface (Metadaten). Läuft als Tor Hidden Service.
3.  **Server-Administrator:** Wartet den Server, fügt Journalisten-RSA-Schlüssel hinzu, exportiert Einreichungen.
4.  **Journalist:** Empfänger der Information.
    *   Greift über Tor auf das **Journalist Interface** zu, um Metadaten neuer Einreichungen zu sehen.
    *   Erhält exportierte, verschlüsselte Einreichungen vom Administrator.
    *   Verwendet eine **Secure Viewing Station (SVS)** (lokaler, isolierter Rechner) und das Journalist Tool (GUI/CLI), um die Einreichungen mit seinen privaten RSA-Schlüsseln zu entschlüsseln.

## Systemarchitektur & Workflow

1.  **Aktion des Whistleblowers:**
    *   Verbindet sich über Tor Browser mit `https://<onion-address-uploads>` von WhistleDrop.
    *   Lädt eine Datei hoch.
2.  **Aktion des WhistleDrop Servers (beim Upload):**
    *   Empfängt Datei (HTTPS), prüft Größe.
    *   Generiert AES-Schlüssel, verschlüsselt Datei und Dateinamen.
    *   Holt verfügbaren öffentlichen RSA-Schlüssel (mit Hint) aus DB.
    *   Verschlüsselt AES-Schlüssel mit diesem RSA-Schlüssel.
    *   Speichert alle verschlüsselten Komponenten und Metadaten (inkl. RSA Key Hint).
    *   Markiert RSA-Schlüssel als benutzt.
    *   Gibt Erfolgsmeldung an Whistleblower.
3.  **Aktion des Journalisten (Metadaten-Abruf):**
    *   Verbindet sich über Tor Browser (oder GUI-integrierten Tor-Zugriff) mit `https://<onion-address-journalist-interface>`.
    *   Authentifiziert sich mit einem API-Key.
    *   Sieht eine Liste neuer Einreichungen (Submission ID, Zeitstempel, Key Hint). **Kein Download der Dateien hier!**
4.  **Aktion des Server-Administrators (Datenexport):**
    *   Verwendet das Skript `utils/export_submissions.py` auf dem Server, um ausgewählte (oder alle neuen) Einreichungen zu exportieren.
    *   Das Skript packt die verschlüsselten Dateien jeder Einreichung (z.B. in ein ZIP-Archiv pro Submission oder ein Gesamtarchiv).
    *   Überträgt diese exportierten Daten sicher auf ein Wechselmedium (z.B. verschlüsselter USB-Stick).
5.  **Datenübergabe (Offline):**
    *   Der Administrator übergibt das Wechselmedium physisch ("Sneakernet") an den Journalisten.
6.  **Aktion des Journalisten (Import & Entschlüsselung auf SVS):**
    *   Überträgt die exportierten Daten vom Wechselmedium auf seine Secure Viewing Station (SVS).
    *   Verwendet das `journalist_tool/journalist_gui.py` (oder `decrypt_tool.py`):
        *   Wählt das Verzeichnis mit den importierten, verschlüsselten Einreichungen.
        *   Das Tool listet die verfügbaren (lokalen) Submission IDs und deren Key Hints.
        *   Wählt eine Submission und den passenden privaten RSA-Schlüssel (anhand des Hints).
        *   Gibt ggf. das Passwort für den privaten RSA-Schlüssel ein.
        *   Das Tool entschlüsselt die lokalen Dateien.
        *   Speichert die entschlüsselte Datei auf der SVS.

## Sicherheitsdesign

*   **Verschlüsselung (Inhalt):** AES-256-GCM (Dateiinhalt & Dateiname), RSA-4096 mit OAEP (AES-Schlüssel).
*   **Schlüsselverwaltung (Inhalt):** Wie zuvor, private RSA-Schlüssel verlassen nie den Journalisten/SVS.
*   **Transportverschlüsselung:**
    *   Whistleblower zu Server: HTTPS über Tor.
    *   Journalist zu Journalist Interface (Metadaten): HTTPS über Tor.
*   **Authentifizierung (Journalist Interface):** API-Key.
*   **Datenintegrität beim Export/Import:** ZIP-Archive können Checksummen verwenden. Der Prozess selbst minimiert Online-Risiken.
*   **Isolation:** Die Entschlüsselung findet auf einer (ideal) Air-Gapped SVS statt.
*   **Tor Hidden Service:** Verschleiert Serverstandort, bietet anonymen Zugriff.

## Projektstruktur
whistledrop/
├── whistledrop_server/
│ ├── app.py # Flask app (HTTPS Uploads & Journalist Interface)
│ ├── crypto_utils.py # Server-seitige Kryptofunktionen
│ ├── key_manager.py # Verwaltung RSA-Schlüssel für Verschlüsselung (DB)
│ ├── storage_manager.py # Speicherung der Einreichungen
│ ├── config.py # Konfiguration
│ ├── templates/ # HTML-Vorlagen
│ │ ├── upload.html
│ │ └── journalist_interface.html # NEU
│ ├── data/ # Datenverzeichnis - NICHT versionieren!
│ ├── certs/ # SSL Zertifikate - NICHT versionieren!
│ └── wsgi.py # WSGI-Einstiegspunkt
├── journalist_tool/
│ ├── journalist_gui.py # Tkinter GUI (arbeitet mit lokalen, exportierten Daten)
│ ├── decrypt_tool.py # CLI Tool (arbeitet mit lokalen, exportierten Daten)
│ ├── crypto_utils.py # Client-seitige Kryptofunktionen
│ ├── gui_config.json # GUI Konfig (URL Journalist Interface, lokale Pfade) - NICHT versionieren
│ ├── private_keys/ # Private RSA-Schlüssel des Journalisten - NICHT versionieren!
│ ├── public_keys_for_server/ # Öffentliche RSA-Schlüssel für Server-Admin
│ ├── decrypted_submissions/ # Standard-Ausgabeort für entschlüsselte Dateien
│ └── local_encrypted_submissions_import/ # Standard-Eingabeort für vom Admin exportierte Daten
├── utils/
│ ├── generate_rsa_keys.py # Erstellt RSA-Schlüsselpaare für Inhaltsverschlüsselung
│ ├── add_public_key_to_db.py # Admin-Skript: Fügt RSA Public Keys zur Server-DB hinzu
│ ├── export_submissions.py # NEU: Admin-Skript zum Exportieren von Einreichungen
│ └── tor_manager.py # Verwaltet Tor Hidden Service (nur HTTPS)
├── .gitignore
├── requirements.txt
└── README.md (Diese Datei)


## Setup und Installation (Server-Administrator)

### Voraussetzungen (Server)
*   Python 3.9+
*   `pip`
*   Tor (laufender Dienst, ControlPort konfiguriert)
*   OpenSSL (Kommandozeile)

### Umgebungsvariablen konfigurieren (Server)
*   `WHISTLEDROP_JOURNALIST_API_KEY`: Starker, geheimer API-Key für das Journalist Interface.
    *   Generieren: `python -c "import secrets; print(secrets.token_hex(32))"`
    *   Sicher an den/die Journalisten übermitteln.
*   `TOR_CONTROL_PASSWORD` (Optional): Passwort für Tor ControlPort.
*   `WHISTLEDROP_SECRET_KEY` (Optional): Für Flask Sessions.

### SSL-Zertifikat generieren (Server)
Einmalig für den HTTPS-Dienst (siehe vorherige Anleitung, Phase 1, Schritt 5).
```bash
mkdir -p whistledrop_server/certs
openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout whistledrop_server/certs/key.pem \
        -out whistledrop_server/certs/cert.pem \
        -days 3650 -subj "/CN=yourwhistledrop.onion"

Installation der Abhängigkeiten (Server)
Wie zuvor: Projekt klonen/herunterladen, venv erstellen, pip install -r requirements.txt.
Verzeichnisse erstellen (Server)
config.py versucht dies, aber zur Sicherheit:
mkdir -p whistledrop_server/data/submissions whistledrop_server/data/db whistledrop_server/certs

Setup und Installation (Journalist)
Voraussetzungen (Journalist Workstation / SVS)
Python 3.9+
pip
(Für GUI) Tkinter (meist bei Python dabei)
(Für Zugriff auf Journalist Interface) Tor Browser oder systemweiter Tor-Dienst mit SOCKS-Proxy.
RSA-Schlüsselpaare für Inhaltsverschlüsselung generieren (Journalist)
Auf der (sicheren) Maschine des Journalisten:
# Im geklonten/heruntergeladenen Projektverzeichnis
python utils/generate_rsa_keys.py

Private RSA-Schlüssel (journalist_tool/private_keys/) geheim halten!
Öffentliche RSA-Schlüssel (journalist_tool/public_keys_for_server/) dem Server-Admin geben.
Installation der Abhängigkeiten (Journalist)
Wenn das Projekt (oder nur journalist_tool und utils) auf die Journalisten-Maschine/SVS kopiert wird:
# Im Projektverzeichnis auf der Journalisten-Maschine/SVS
python -m venv venv
source venv/bin/activate # oder .\venv\Scripts\activate
pip install -r requirements.txt # Enthält nun weniger Abhängigkeiten

Administrative Aufgaben (Server-Administrator)
Öffentliche RSA-Schlüssel (für Verschlüsselung) zur Server-Datenbank hinzufügen
Die vom Journalisten erhaltenen öffentlichen RSA-Schlüssel (*_public_encryption.pem) auf den Server übertragen und hinzufügen:
# Auf dem Server, im WhistleDrop-Projektverzeichnis
source venv/bin/activate
python utils/add_public_key_to_db.py /pfad/zu/den/uebertragenen/public_keys/

API-Key für Journalist Interface sicher generieren und mitteilen
Siehe "Umgebungsvariablen konfigurieren (Server)". Dieser Key wird vom Journalisten in der GUI oder für curl/Skripte benötigt, um auf das Journalist Interface zuzugreifen.
WhistleDrop Server starten (Server-Administrator)
Mit tor_manager.py (Empfohlen für Testen mit ephemerem Service)
Startet Gunicorn (Flask App) und konfiguriert Tor Hidden Service für HTTPS:
# Im WhistleDrop-Projektverzeichnis
source venv/bin/activate
python utils/tor_manager.py

Die .onion-Adresse für Whistleblower-Uploads UND das Journalist Interface wird ausgegeben.
Mit manuellem Tor Hidden Service & Gunicorn (Produktion)
Gunicorn Webserver (Flask App mit HTTPS) starten:
source venv/bin/activate
gunicorn --bind YOUR_SERVER_HOST:YOUR_FLASK_HTTPS_PORT \
         --workers 4 \
         --certfile whistledrop_server/certs/cert.pem \
         --keyfile whistledrop_server/certs/key.pem \
         whistledrop_server.wsgi:app

Tor torrc konfigurieren:
HiddenServiceDir /var/lib/tor/whistledrop_service/
HiddenServiceVersion 3
HiddenServicePort 443 127.0.0.1:YOUR_FLASK_HTTPS_PORT # Für Uploads & Journalist Interface

Server neu starten/laden. .onion-Adresse aus /var/lib/tor/whistledrop_service/hostname entnehmen.

Benutzung
Whistleblower: Datei über HTTPS-Onion-Service hochladen
Öffne https://<onion-address> (vom Admin erhalten) im Tor Browser.
Datei auswählen und hochladen.
Journalist: Metadaten über Journalist Interface abrufen
Öffne https://<onion-address>/journalist (oder der konfigurierte Pfad) im Tor Browser.
Authentifiziere dich (z.B. Basic Auth, wenn implementiert, oder API-Key im Header für Skripte).
Oder: Nutze die Funktion im journalist_gui.py (Tab "Submissions"), die sich mit dem API-Key und Tor SOCKS Proxy mit dem Interface verbindet, um die Metadatenliste (Submission IDs, Key Hints) abzurufen.
Notiere dir Submission IDs und die zugehörigen Key Hints für interessante Einreichungen.
Server-Administrator: Einreichungen exportieren
Auf dem WhistleDrop-Server (im Projektverzeichnis):
source venv/bin/activate
python utils/export_submissions.py --output_dir /pfad/zum/sicheren/exportverzeichnis/ [--all | --id SUBMISSION_ID1 --id SUBMISSION_ID2]****

--output_dir: Verzeichnis, in das die verschlüsselten Submission-Archive (z.B. ZIPs) gespeichert werden. Dieses Verzeichnis sollte auf einem Wechselmedium oder einem sicheren Transferpfad liegen.
--all: Exportiert alle noch nicht als "exportiert" markierten Submissions.
--id ID: Exportiert spezifische Submission IDs.
Optional: Das Skript könnte eine lokale Datei pflegen, um bereits exportierte Submissions zu verfolgen, um Doppel-Exporte zu vermeiden, wenn --all verwendet wird.
Übertrage die exportierten Archive (z.B. von /pfad/zum/sicheren/exportverzeichnis/) sicher auf ein USB-Laufwerk.
Übergebe das USB-Laufwerk physisch an den Journalisten.
Journalist: Exportierte Einreichungen importieren und entschlüsseln (GUI/CLI)
Auf der Secure Viewing Station (SVS): Kopiere die Archive vom USB-Laufwerk in ein lokales Verzeichnis (z.B. journalist_tool/local_encrypted_submissions_import/). Entpacke sie, falls sie als Archive exportiert wurden (jede Submission in einem eigenen Unterordner).
Mit der GUI (journalist_gui.py):
Setup Tab:
Konfiguriere die URL des "Journalist Interface" und deinen API-Key.
Konfiguriere den "Local Encrypted Submissions Import Dir" (wo du die Daten von USB hinkopiert hast).
Konfiguriere das "Default RSA Private Keys Dir" (wo deine privaten Entschlüsselungsschlüssel liegen).
Submissions Tab:
Klicke "Refresh Local Submissions": Listet Submissions aus dem lokalen Importverzeichnis.
Optional: Klicke "Fetch New Submission Info from Server": Ruft Metadaten vom Journalist Interface ab, um sie mit lokalen Daten zu vergleichen oder neue, noch nicht exportierte Submissions zu sehen.
Wähle eine (lokal vorhandene) Submission.
Wähle den passenden privaten RSA-Schlüssel (anhand des Key Hints).
Gib ggf. das Passwort für den RSA-Schlüssel ein.
Klicke "Decrypt Submission".
Mit dem CLI-Tool (decrypt_tool.py):
python journalist_tool/decrypt_tool.py \
    --submission_path /pfad/zur/lokalen/submission_id_verzeichnis/ \
    --private_rsa_key /pfad/zum/privaten_rsa_schluessel.pem \
    --output_dir /pfad/fuer/entschluesselte_datei/