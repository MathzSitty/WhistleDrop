# whistledrop/whistledrop_server/key_manager.py
import logging
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from .config import Config

logger = logging.getLogger(__name__)


def get_db_connection():
    conn = sqlite3.connect(Config.KEY_DB_PATH)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def initialize_key_database():
    """
    Initializes or updates the database schema for both RSA public keys
    and journalist accounts.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # --- RSA Public Keys Table ---
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
        # Add 'key_identifier_hint' column if it doesn't exist (for backward compatibility)
        try:
            cursor.execute("ALTER TABLE rsa_public_keys ADD COLUMN key_identifier_hint TEXT")
            logger.info("Added 'key_identifier_hint' column to rsa_public_keys table.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                pass  # Column already exists
            else:
                logger.error(f"SQLite error checking/adding hint column: {e}")
                # raise # Re-raise if it's a critical schema issue not related to duplicate column

        # --- Journalists Table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS journalists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        logger.info("Key and Journalist database initialized/updated successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database error during initialization: {e}")
    finally:
        if conn: conn.close()

# --- Journalist Account Management ---

def add_journalist(username: str, password: str) -> bool:
    """Adds a new journalist to the database with a hashed password."""
    if not username or not password:
        logger.error("Username and password cannot be empty.")
        return False

    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO journalists (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        logger.info(f"Journalist account '{username}' created successfully. DB Row ID: {cursor.lastrowid}")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Failed to add journalist '{username}': Username likely already exists.")
        return False
    except sqlite3.Error as e:
        logger.error(f"Database error adding journalist '{username}': {e}")
        return False
    finally:
        if conn: conn.close()

def get_journalist_by_username(username: str) -> dict | None:
    """Retrieves a journalist by username. Returns a dict or None."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM journalists WHERE username = ?", (username,))
        journalist_row = cursor.fetchone()
        if journalist_row:
            return dict(journalist_row)
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving journalist '{username}': {e}")
        return None
    finally:
        if conn: conn.close()

def get_journalist_by_id(user_id: int) -> dict | None:
    """Retrieves a journalist by ID. Returns a dict or None. (Used by Flask-Login)"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM journalists WHERE id = ?", (user_id,))
        journalist_row = cursor.fetchone()
        if journalist_row:
            return dict(journalist_row)
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving journalist by ID '{user_id}': {e}")
        return None
    finally:
        if conn: conn.close()

def verify_journalist_password(username: str, password_to_check: str) -> bool:
    """Verifies a journalist's password against the stored hash."""
    journalist_data = get_journalist_by_username(username)
    if journalist_data and check_password_hash(journalist_data['password_hash'], password_to_check):
        return True
    return False

# --- RSA Public Key Management (existing functions, largely unchanged but reviewed) ---

def add_public_key(key_pem_str: str, identifier_hint: str | None = None) -> bool:
    if not key_pem_str.strip().startswith("-----BEGIN PUBLIC KEY-----"):
        logger.error("Invalid public key format (missing PEM header).")
        return False

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        logger.info(
            f"KEY_MANAGER.ADD_PUBLIC_KEY: Attempting to INSERT key. Hint: '{identifier_hint}'. PEM: {key_pem_str[:40]}...")
        cursor.execute(
            "INSERT INTO rsa_public_keys (key_pem, key_identifier_hint) VALUES (?, ?)",
            (key_pem_str, identifier_hint)
        )
        conn.commit()
        logger.info(
            f"Public key added (DB Hint: {identifier_hint}). DB Row ID: {cursor.lastrowid}")
        return True
    except sqlite3.IntegrityError as ie:
        logger.warning(f"IntegrityError (likely duplicate) adding public key (Hint: {identifier_hint}). Error: {ie}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Database error adding public key (Hint: {identifier_hint}). Error: {e}")
        return False
    finally:
        if conn: conn.close()

def get_available_public_key() -> tuple[str, int, str | None] | None:
    """Returns (key_pem, key_id, key_identifier_hint) or None."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, key_pem, key_identifier_hint FROM rsa_public_keys WHERE is_used = 0 ORDER BY RANDOM() LIMIT 1")
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

# Initialize database schema on import
initialize_key_database()