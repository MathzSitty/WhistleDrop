import logging
import sqlite3
import os

from .config import Config

logger = logging.getLogger(__name__)


def get_db_connection():
    conn = sqlite3.connect(Config.KEY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_key_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Add new column key_identifier_hint
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rsa_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_pem TEXT NOT NULL UNIQUE,
                key_identifier_hint TEXT, -- New column for user-friendly hint
                is_used BOOLEAN NOT NULL DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP NULL
            )
        """)
        # Add the column if it doesn't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE rsa_public_keys ADD COLUMN key_identifier_hint TEXT")
            logger.info("Added 'key_identifier_hint' column to rsa_public_keys table.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                pass # Column already exists, fine
            else:
                raise # Other operational error
        conn.commit()
        logger.info("Key database initialized/updated successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database error during initialization: {e}")
    finally:
        if conn: conn.close()


def add_public_key(key_pem_str: str, identifier_hint: str | None = None) -> bool:
    if not key_pem_str.strip().startswith("-----BEGIN PUBLIC KEY-----"):
        logger.error("Invalid public key format (missing PEM header).")
        return False

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # CRITICAL LOGGING: What is the value of identifier_hint here?
        logger.info(
            f"KEY_MANAGER.ADD_PUBLIC_KEY: Attempting to INSERT key. Hint received: '{identifier_hint}'. PEM starts: {key_pem_str[:40]}...")

        cursor.execute(
            "INSERT INTO rsa_public_keys (key_pem, key_identifier_hint) VALUES (?, ?)",
            (key_pem_str, identifier_hint)  # This 'identifier_hint' is directly from the function argument
        )
        conn.commit()
        logger.info(
            f"Public key added (DB Hint was: {identifier_hint}). DB Row ID: {cursor.lastrowid}")  # Log what was attempted to be inserted
        return True
    except sqlite3.IntegrityError as ie:
        logger.warning(f"IntegrityError (likely duplicate) adding public key (Hint: {identifier_hint}). Error: {ie}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Database error adding public key (Hint: {identifier_hint}). Error Type: {type(e)}, Error: {e}")
        return False
    except Exception as ex:
        logger.error(f"Unexpected Python error in add_public_key (Hint: {identifier_hint}). Error: {ex}")
        return False
    finally:
        if conn: conn.close()


def get_available_public_key() -> tuple[str, int, str | None] | None:  # Returns hint as well
    """Returns (key_pem, key_id, key_identifier_hint) or None."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, key_pem, key_identifier_hint FROM rsa_public_keys WHERE is_used = 0 ORDER BY RANDOM() LIMIT 1")  # Random selection
        row = cursor.fetchone()
        if row:
            logger.info(f"Retrieved available public key ID: {row['id']}, Hint: {row['key_identifier_hint']}")
            return row['key_pem'], row['id'], row['key_identifier_hint']
        else:
            logger.warning("No available RSA public keys in the database.")
            return None
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving public key: {e}")
        return None
    finally:
        if conn: conn.close()


# mark_key_as_used remains the same
def mark_key_as_used(key_id: int) -> bool:
    conn = get_db_connection()
    try:
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
            logger.warning(f"Failed to mark key ID {key_id} as used (already used or not found).")
            return False
    except sqlite3.Error as e:
        logger.error(f"Database error marking key as used: {e}")
        return False
    finally:
        if conn: conn.close()


initialize_key_database()  # Run on import