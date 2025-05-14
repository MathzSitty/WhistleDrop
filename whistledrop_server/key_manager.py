# whistledrop/whistledrop_server/key_manager.py
import logging
import sqlite3
import os
from .config import Config  # For KEY_DB_PATH

logger = logging.getLogger(__name__)


def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    os.makedirs(os.path.dirname(Config.KEY_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.KEY_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.Error as e:
        logger.warning(f"Could not set WAL mode for key_store.db: {e}. Using default.")
    return conn


def initialize_key_database():
    """Initializes the RSA public key database and table if they don't exist."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rsa_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_pem TEXT NOT NULL UNIQUE,
                key_identifier_hint TEXT,
                is_used BOOLEAN NOT NULL DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP NULL
            )
        """)

        cursor.execute("PRAGMA table_info(rsa_public_keys)")
        columns = [column['name'] for column in cursor.fetchall()]
        if 'key_identifier_hint' not in columns:
            try:
                cursor.execute("ALTER TABLE rsa_public_keys ADD COLUMN key_identifier_hint TEXT")
                conn.commit()
                logger.info("Added 'key_identifier_hint' column to rsa_public_keys table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e).lower():
                    logger.info("'key_identifier_hint' column already exists.")
                else:
                    logger.error(f"Failed to add 'key_identifier_hint' column: {e}", exc_info=True)
                    raise

        conn.commit()
        logger.info("RSA public key database initialized/verified successfully.")
    except sqlite3.Error as e:
        logger.error(f"SQLite DB error during initialization of rsa_public_keys: {e}", exc_info=True)
    finally:
        if conn:
            conn.close()


def add_public_key(key_pem_str: str, identifier_hint: str | None = None) -> bool:
    """Adds a new RSA public key PEM string and its identifier hint to the database."""
    if not key_pem_str.strip().startswith("-----BEGIN PUBLIC KEY-----"):
        logger.error("Invalid public key format: PEM missing header.")
        return False

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if identifier_hint and len(identifier_hint) > 255:
            identifier_hint = identifier_hint[:255]
            logger.warning(f"Identifier hint truncated to 255 chars.")

        logger.info(f"Attempting to add public key. Hint: '{identifier_hint}', PEM starts: {key_pem_str[:40]}...")
        cursor.execute(
            "INSERT INTO rsa_public_keys (key_pem, key_identifier_hint, is_used) VALUES (?, ?, 0)",
            (key_pem_str, identifier_hint)
        )
        conn.commit()
        logger.info(f"Public key added. DB Row ID: {cursor.lastrowid}, Hint: '{identifier_hint}'")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Failed to add public key (Hint: '{identifier_hint}'): Key PEM already exists.")
        return False
    except sqlite3.Error as e:
        logger.error(f"SQLite DB error adding public key (Hint: '{identifier_hint}'): {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


def get_available_public_key() -> tuple[str, int, str | None] | None:
    """Retrieves an available (unused) RSA public key PEM, its ID, and its hint."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, key_pem, key_identifier_hint 
            FROM rsa_public_keys 
            WHERE is_used = 0 
            ORDER BY RANDOM() 
            LIMIT 1
        """)
        row = cursor.fetchone()
        if row:
            logger.info(f"Retrieved available public key. ID: {row['id']}, Hint: '{row['key_identifier_hint']}'")
            return row['key_pem'], row['id'], row['key_identifier_hint']
        else:
            logger.warning("No available (unused) RSA public keys found.")
            return None
    except sqlite3.Error as e:
        logger.error(f"SQLite DB error retrieving available public key: {e}", exc_info=True)
        return None
    finally:
        if conn:
            conn.close()


def mark_key_as_used(key_id: int) -> bool:
    """Marks a specific RSA public key as used in the database."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE rsa_public_keys 
            SET is_used = 1, used_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND is_used = 0
        """, (key_id,))
        conn.commit()
        if cursor.rowcount > 0:
            logger.info(f"Public key ID {key_id} marked as used.")
            return True
        else:
            cursor.execute("SELECT is_used FROM rsa_public_keys WHERE id = ?", (key_id,))
            row = cursor.fetchone()
            if row and row['is_used'] == 1:
                logger.warning(f"Key ID {key_id} already marked as used.")
            elif not row:
                logger.warning(f"Key ID {key_id} not found to mark as used.")
            else:
                logger.warning(f"Failed to mark key ID {key_id} as used (unexpected state).")
            return False
    except sqlite3.Error as e:
        logger.error(f"SQLite DB error marking key ID {key_id} as used: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


def count_available_public_keys() -> int:
    """Counts the number of available (unused) RSA public keys."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM rsa_public_keys WHERE is_used = 0")
        count = cursor.fetchone()[0]
        logger.debug(f"Counted {count} available public keys.")
        return count
    except sqlite3.Error as e:
        logger.error(f"SQLite DB error counting available public keys: {e}", exc_info=True)
        return -1  # Indicate error
    finally:
        if conn:
            conn.close()


initialize_key_database()