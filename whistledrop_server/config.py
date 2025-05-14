# whistledrop/whistledrop_server/config.py
import os
import secrets # For generating default API key if not set via ENV
import string

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # --- Security ---
    SECRET_KEY = os.environ.get('WHISTLEDROP_SECRET_KEY') or 'a-very-secret-dev-key-CHANGE-ME-IN-PROD'

    # API Key for Journalist Interface (Metadaten-Zugriff)
    # In Produktion IMMER eine Umgebungsvariable verwenden!
    WHISTLEDROP_JOURNALIST_API_KEY = os.environ.get('WHISTLEDROP_JOURNALIST_API_KEY')
    if not WHISTLEDROP_JOURNALIST_API_KEY:
        # Generiere einen NUR für Entwicklungszwecke, wenn keine Umgebungsvariable gesetzt ist.
        # Dieser wird bei jedem Serverstart neu generiert, wenn keine Variable gesetzt ist.
        print("WARNING: WHISTLEDROP_JOURNALIST_API_KEY is not set as an environment variable.")
        print("         A temporary API key will be generated for this session FOR THE JOURNALIST INTERFACE.")
        print("         For production or persistent use, please set this environment variable securely.")
        temp_api_key = ''.join(
            secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(64))
        WHISTLEDROP_JOURNALIST_API_KEY = temp_api_key
        print(f"         Temporary Journalist API Key: {WHISTLEDROP_JOURNALIST_API_KEY}")
        print("         This key is ONLY valid for the current server session.")


    # --- Storage ---
    DATA_DIR = os.path.join(BASE_DIR, "data")
    SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions") # Stores encrypted submissions
    KEY_DB_DIR = os.path.join(DATA_DIR, "db")
    KEY_DB_PATH = os.path.join(KEY_DB_DIR, "key_store.db") # SQLite DB for RSA public keys

    # Directory for admin to export submissions to (used by export_submissions.py)
    # This path is a suggestion; admin might choose a different secure location.
    DEFAULT_EXPORT_DIR = os.path.join(DATA_DIR, "exported_for_journalist")


    # --- Cryptography ---
    AES_KEY_SIZE = 32  # bytes, for AES-256
    AES_NONCE_SIZE = 12  # bytes, for GCM

    # --- Server (Flask App for Whistleblower Uploads & Journalist Interface) ---
    MAX_UPLOAD_SIZE_MB = 50
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    SERVER_HOST = "127.0.0.1"  # Host for Flask app (via Gunicorn) to bind to locally
    FLASK_HTTPS_PORT = 8443    # Local port for Flask (via Gunicorn) to run HTTPS on.
                               # Tor will map hidden service port 443 to this local port.

    # --- HTTPS Configuration (for Flask/Gunicorn) ---
    CERT_DIR = os.path.join(BASE_DIR, "certs")
    SSL_CERT_PATH = os.path.join(CERT_DIR, "cert.pem")
    SSL_KEY_PATH = os.path.join(CERT_DIR, "key.pem")

    # --- Tor Control & Hidden Service Configuration ---
    TOR_CONTROL_PORT = 9051 # Default Tor control port
    TOR_CONTROL_PASSWORD = os.environ.get('TOR_CONTROL_PASSWORD') # Optional

    # SFTP settings are removed as SFTP server is no longer used.

    @staticmethod
    def ensure_dirs_exist():
        os.makedirs(Config.SUBMISSIONS_DIR, exist_ok=True)
        os.makedirs(Config.KEY_DB_DIR, exist_ok=True)
        os.makedirs(Config.CERT_DIR, exist_ok=True)
        os.makedirs(Config.DEFAULT_EXPORT_DIR, exist_ok=True) # Ensure default export dir exists

        # Check for SSL cert and key, provide instructions if missing
        if not (os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH)):
            print("WARNING: SSL certificate (cert.pem) or key (key.pem) not found in whistledrop_server/certs/")
            print("WARNING: HTTPS for whistleblower uploads and Journalist Interface will not work without them.")
            print("         Please generate them using OpenSSL, for example:")
            print("         mkdir -p whistledrop_server/certs")
            print("         openssl req -x509 -newkey rsa:4096 -nodes \\")
            print("                 -keyout whistledrop_server/certs/key.pem \\")
            print("                 -out whistledrop_server/certs/cert.pem \\")
            print("                 -days 3650 -subj \"/CN=yourwhistledropservice.onion\"")
            print("         (Replace 'yourwhistledropservice.onion' with your actual .onion address or a placeholder CN).")

# Call ensure_dirs_exist when this module is imported so paths are ready.
Config.ensure_dirs_exist()