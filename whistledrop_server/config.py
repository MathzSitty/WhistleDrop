# whistledrop/whistledrop_server/config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # --- Security ---
    SECRET_KEY = os.environ.get('WHISTLEDROP_SECRET_KEY') or 'a-very-secret-dev-key-CHANGE-ME'  # Für Flask Session etc.

    # Journalist API Key for accessing protected journalist endpoints
    # In Produktion IMMER eine Umgebungsvariable verwenden!
    # Fallback hier nur für einfache Entwicklung ohne gesetzte Variable.
    JOURNALIST_API_KEY = os.environ.get('WHISTLEDROP_JOURNALIST_API_KEY')
    if not JOURNALIST_API_KEY:
        # Generiere einen NUR für Entwicklungszwecke, wenn keine Umgebungsvariable gesetzt ist.
        # Dieser wird bei jedem Serverstart neu generiert, wenn keine Variable gesetzt ist.
        # In Produktion MUSS die Umgebungsvariable gesetzt sein.
        import secrets
        import string
        print("WARNUNG: WHISTLEDROP_JOURNALIST_API_KEY ist nicht als Umgebungsvariable gesetzt.")
        print("         Ein temporärer API-Key wird für diese Sitzung generiert.")
        print("         Für Produktion oder persistente Nutzung bitte die Umgebungsvariable setzen.")
        temp_api_key = ''.join(
            secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(64))
        JOURNALIST_API_KEY = temp_api_key
        print(f"         Temporärer API Key: {JOURNALIST_API_KEY}")
        print("         Dieser Key ist NUR für die aktuelle Server-Session gültig.")

    # --- Storage ---
    # ... (Rest der Config bleibt gleich) ...
    DATA_DIR = os.path.join(BASE_DIR, "data")
    SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions")
    KEY_DB_DIR = os.path.join(DATA_DIR, "db")
    KEY_DB_PATH = os.path.join(KEY_DB_DIR, "key_store.db")

    # --- Cryptography ---
    AES_KEY_SIZE = 32
    AES_NONCE_SIZE = 12

    # --- Server ---
    MAX_UPLOAD_SIZE_MB = 50
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 5000

    # --- Tor Control ---
    TOR_CONTROL_PORT = 9051
    TOR_CONTROL_PASSWORD = os.environ.get('TOR_CONTROL_PASSWORD')

    @staticmethod
    def ensure_dirs_exist():
        os.makedirs(Config.SUBMISSIONS_DIR, exist_ok=True)
        os.makedirs(Config.KEY_DB_DIR, exist_ok=True)


Config.ensure_dirs_exist()