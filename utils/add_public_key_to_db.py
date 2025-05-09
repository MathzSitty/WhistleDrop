# whistledrop/utils/add_public_key_to_db.py
import sys
import os
import glob
import logging
import argparse

# Ensure the script can find whistledrop_server modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from whistledrop_server import key_manager
from whistledrop_server.config import Config

logger = logging.getLogger("add_public_key_util")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def process_single_key_file(key_file_path: str) -> bool:
    logger.info(f"Processing key file: {key_file_path}")
    try:
        with open(key_file_path, 'r') as f:
            public_key_pem = f.read()

        if not public_key_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"):
            logger.warning(f"Skipping {key_file_path}: Not a valid PEM public key (missing header).")
            return False

        filename_base = os.path.basename(key_file_path)
        hint = filename_base
        possible_suffixes = ["_public.pem", ".pem", "_public.pub", ".pub"]
        for suffix in possible_suffixes:
            if hint.lower().endswith(suffix.lower()):
                hint = hint[:-len(suffix)]
                break

        # CRITICAL LOGGING: What hint is the CLI utility extracting?
        logger.info(f"ADD_PUB_KEY_CLI: Extracted HINT: '{hint}' for file '{filename_base}'")

        if key_manager.add_public_key(public_key_pem, identifier_hint=hint):  # Pass hint
            logger.info(f"Successfully added public key: {filename_base} (Hint stored: '{hint}')")
            return True
        else:
            logger.warning(
                f"Failed to add public key: {filename_base} (Hint attempted: '{hint}') - likely duplicate or invalid.")
            return False
    except FileNotFoundError:
        logger.error(f"Error: File not found at {key_file_path}")
        return False
    except Exception as e:
        logger.error(f"Error processing file {key_file_path}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="WhistleDrop Server - Add Public Key(s) Utility. "
                    "Adds public keys from specified file(s) or a directory to the server's database. "
                    "A hint (usually derived from the filename) is stored with each key."
    )
    parser.add_argument(
        "path",
        help="Path to a single public key PEM/PUB file or a directory containing such files."
    )
    parser.add_argument(
        "-p", "--pattern",
        default="*_public.pem",
        help="File pattern to search for public keys in directory mode (e.g., '*.pub', 'key_*.pem'). "
             "Default: '*_public.pem'. Also tries '*.pem' and '*.pub' if default doesn't match."
    )

    args = parser.parse_args()

    print("WhistleDrop Server - Add Public Key(s) Utility")
    print("---------------------------------------------")
    print(f"Target Key Database: {Config.KEY_DB_PATH}\n")

    files_to_process = []
    if os.path.isfile(args.path):
        files_to_process.append(args.path)
    elif os.path.isdir(args.path):
        logger.info(f"Searching for keys in directory: {args.path} with primary pattern: {args.pattern}")
        files_to_process.extend(glob.glob(os.path.join(args.path, args.pattern)))

        if not files_to_process:
            logger.info(f"No files found with '{args.pattern}'. Trying common patterns '*.pem' and '*.pub'...")
            common_patterns = ["*.pem", "*.pub"]
            for pat in common_patterns:
                files_to_process.extend(glob.glob(os.path.join(args.path, pat)))
            files_to_process = sorted(list(set(files_to_process)))  # Remove duplicates
    else:
        logger.error(f"Error: Path not found or is not a file/directory: {args.path}")
        parser.print_help()
        return

    if not files_to_process:
        logger.warning(f"No public key files found at path '{args.path}' with specified/fallback patterns.")
        return

    logger.info(f"Found {len(files_to_process)} potential public key file(s) to process.")

    success_count = 0
    failure_count = 0
    for key_file_path in files_to_process:
        if not (key_file_path.lower().endswith(".pem") or key_file_path.lower().endswith(".pub")):
            logger.info(f"Skipping {key_file_path}: does not have a .pem or .pub extension.")
            continue
        if process_single_key_file(key_file_path):
            success_count += 1
        else:
            failure_count += 1

    print("\n--- Summary ---")
    print(f"Successfully added keys: {success_count}")
    print(f"Failed to add keys:    {failure_count}")
    if failure_count > 0:
        print("Check logs above for details on failures.")


if __name__ == "__main__":
    try:
        # This will create the DB and table with the hint column if it doesn't exist
        key_manager.initialize_key_database()
    except Exception as db_init_e:
        print(f"CRITICAL: Could not initialize/update key database: {db_init_e}")
        print("Please ensure the server's data directory is writable, the database can be accessed,")
        print("and the key_manager.py file contains the latest schema with 'key_identifier_hint'.")
        sys.exit(1)
    main()