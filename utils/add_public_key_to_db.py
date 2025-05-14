# whistledrop/utils/add_public_key_to_db.py
import sys
import os
# import glob # pathlib is generally preferred now
import logging
import argparse
from pathlib import Path

# Ensure the script can find whistledrop_server modules when run from utils/
current_utils_dir = Path(__file__).parent.resolve()
project_root = current_utils_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from whistledrop_server import key_manager
from whistledrop_server.config import Config  # For displaying KEY_DB_PATH

logger = logging.getLogger("add_public_key_util")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])


def process_single_key_file(key_file_path: Path) -> bool:
    """
    Processes a single public key file, reads its content, extracts a hint,
    and attempts to add it to the key_store.db via key_manager.
    Returns True if successful, False otherwise.
    """
    logger.info(f"Processing key file: {key_file_path.name}")
    try:
        with open(key_file_path, 'r', encoding='utf-8') as f:
            public_key_pem = f.read()

        if not public_key_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"):
            logger.warning(f"Skipping '{key_file_path.name}': Not a valid PEM public key (missing expected header).")
            return False

        filename_base = key_file_path.stem
        hint = filename_base

        possible_suffixes_in_stem = ["_public_encryption", "_public", "_encryption"]
        for suffix in possible_suffixes_in_stem:
            if hint.lower().endswith(suffix.lower()):
                hint = hint[:-len(suffix)]
                break

        logger.info(f"Extracted Hint: '{hint}' for file '{key_file_path.name}'")

        if key_manager.add_public_key(public_key_pem, identifier_hint=hint):
            return True
        else:
            return False

    except FileNotFoundError:
        logger.error(f"Error: File not found at {key_file_path}")
        return False
    except IOError as e_io:
        logger.error(f"IOError reading file {key_file_path.name}: {e_io}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error processing file {key_file_path.name}: {e}", exc_info=True)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="WhistleDrop Server - Add Public RSA Encryption Key(s) Utility. "
                    "Adds public RSA keys (for encrypting submissions) from specified file(s) "
                    "or a directory to the server's key database. "
                    "A 'hint' (derived from filename) is stored with each key."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a single public key PEM/PUB file or a directory containing such files."
    )
    parser.add_argument(
        "-p", "--pattern",
        default="*_public*.pem",
        help="File pattern for public keys in directory mode (default: '*_public*.pem'). "
             "Fallbacks: '*.pem', '*.pub'."
    )

    args = parser.parse_args()

    print("\nWhistleDrop Server - Add Public RSA Encryption Key(s) Utility")
    print("-------------------------------------------------------------")
    print(f"Target Key Database: {Path(Config.KEY_DB_PATH).resolve()}\n")

    try:
        key_manager.initialize_key_database()  # Ensure DB is ready
    except Exception as db_init_e:
        logger.critical(f"CRITICAL: Could not initialize/verify key database: {db_init_e}", exc_info=True)
        sys.exit(1)

    files_to_process = []
    input_path: Path = args.path.resolve()

    if input_path.is_file():
        files_to_process.append(input_path)
    elif input_path.is_dir():
        logger.info(f"Searching for keys in directory: {input_path} with primary pattern: '{args.pattern}'")
        files_to_process.extend(sorted(list(input_path.glob(args.pattern))))

        if not files_to_process:
            logger.info(f"No files found with '{args.pattern}'. Trying fallbacks '*.pem', '*.pub'...")
            fallback_patterns = ["*.pem", "*.pub"]
            temp_files = set()
            for pat in fallback_patterns:
                temp_files.update(input_path.glob(pat))
            files_to_process = sorted(list(temp_files))
    else:
        logger.error(f"Error: Path not found or is not a file/directory: {args.path}")
        parser.print_help()
        return

    if not files_to_process:
        logger.warning(f"No public key files found at path '{args.path}' with specified/fallback patterns.")
        return

    logger.info(f"Found {len(files_to_process)} potential public key file(s) to process:")
    for f_path in files_to_process: logger.info(f"  - {f_path.name}")
    print("---")

    success_count = 0
    failure_count = 0

    for key_file_path_obj in files_to_process:
        if not (key_file_path_obj.name.lower().endswith(".pem") or key_file_path_obj.name.lower().endswith(".pub")):
            logger.info(f"Skipping '{key_file_path_obj.name}': does not have .pem or .pub extension.")
            continue

        if process_single_key_file(key_file_path_obj):
            success_count += 1
        else:
            failure_count += 1
        print("---")

    print("\n--- Summary ---")
    print(f"Successfully added keys: {success_count}")
    print(f"Failed to add keys:    {failure_count}")
    if failure_count > 0:
        print("Check logs above for details on failures (e.g., duplicate keys, invalid format).")
    print("---")


if __name__ == "__main__":
    main()