# whistledrop/utils/create_journalist_account.py
import sys
import os
# import getpass # getpass wird nicht mehr verwendet
import logging

# --- Path Adjustment ---
current_script_path = os.path.abspath(__file__)
utils_dir = os.path.dirname(current_script_path)
project_root_dir = os.path.dirname(utils_dir)

if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)
# --- End Path Adjustment ---

from whistledrop_server import key_manager # Imports key_manager which initializes DB
from whistledrop_server.config import Config # To show DB path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("create_journalist_util")

def main():
    print("--- WhistleDrop: Create Journalist Account ---")
    print(f"Target Database: {Config.KEY_DB_PATH}\n")

    username = input("Enter username for the new journalist: ").strip()
    if not username:
        logger.error("Username cannot be empty.")
        return

    print("\nWARNING: You will now be asked to enter a password.")
    print("For security reasons, passwords are usually hidden during input.")
    print("Due to potential compatibility issues with 'getpass' in some terminals,")
    print("this script will use standard input, meaning YOUR PASSWORD WILL BE VISIBLE ON SCREEN.")
    print("Ensure no one is looking over your shoulder.\n")

    while True:
        # password = getpass.getpass("Enter password: ") # Ersetzt durch input()
        password = input("Enter password (WILL BE VISIBLE): ")
        if not password:
            logger.warning("Password cannot be empty.")
            continue
        # password_confirm = getpass.getpass("Confirm password: ") # Ersetzt durch input()
        password_confirm = input("Confirm password (WILL BE VISIBLE): ")
        if password == password_confirm:
            break
        else:
            logger.error("Passwords do not match. Please try again.")

    if key_manager.add_journalist(username, password):
        logger.info(f"Journalist account '{username}' created successfully.")
        print(f"\nJournalist account '{username}' created successfully.")
    else:
        logger.error(f"Failed to create journalist account '{username}'. Check logs for details (e.g., username might already exist).")
        print(f"\nFailed to create journalist account '{username}'.")

if __name__ == "__main__":
    # Ensure the database and tables are created if they don't exist.
    # key_manager.initialize_key_database() is called on import of key_manager.
    try:
        # Attempt a benign DB operation to ensure it's connectable,
        # or rely on the implicit initialization.
        pass
    except Exception as db_init_e:
        print(f"CRITICAL: Could not ensure database is initialized: {db_init_e}")
        sys.exit(1)
    main()