# whistledrop/journalist_tool/decrypt_tool.py
import argparse
import os
import logging
import getpass
import sys
from pathlib import Path

# Adjust path to allow imports from parent directory (whistledrop/)
current_script_dir = Path(__file__).parent.resolve()
project_root_dir = current_script_dir.parent
if str(project_root_dir) not in sys.path:
    sys.path.insert(0, str(project_root_dir))

from journalist_tool import crypto_utils  # Import from within the journalist_tool package

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("decrypt_tool_cli_local")

# Default local directories
DEFAULT_DECRYPTED_OUTPUT_DIR = Path("decrypted_submissions/")
DEFAULT_RSA_PRIVATE_KEYS_DIR = Path("private_keys/")  # For journalist's RSA keys (content decryption)
DEFAULT_LOCAL_SUBMISSIONS_IMPORT_DIR = Path(
    "local_encrypted_submissions_import/")  # Where exported submissions are placed

# Standard filenames expected within each (locally imported) submission directory
# These should match what storage_manager.py and export_submissions.py use.
LOCAL_ENCRYPTED_FILE_NAME = "encrypted_file.dat"
LOCAL_ENCRYPTED_AES_KEY_NAME = "encrypted_aes_key.dat"
LOCAL_ENCRYPTED_ORIGINAL_FILENAME_NAME = "encrypted_filename.dat"


# LOCAL_RSA_PUBLIC_KEY_HINT_NAME = "rsa_public_key_hint.txt" # Hint is read by GUI, not directly by CLI for decryption logic

def load_encrypted_component(submission_dir_path: Path, component_filename: str) -> bytes | None:
    """Loads an encrypted component file from a local submission directory."""
    file_path = submission_dir_path / component_filename
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        logger.info(f"Successfully loaded '{component_filename}' from '{submission_dir_path}'.")
        return content
    except FileNotFoundError:
        logger.error(f"Encrypted component '{component_filename}' not found in '{submission_dir_path}'.")
        return None
    except IOError as e:
        logger.error(f"IOError reading '{component_filename}' from '{submission_dir_path}': {e}")
        return None


def load_private_rsa_key_pem(private_key_path: Path) -> str | None:
    """Loads the PEM content of the RSA private key used for decrypting submission content."""
    try:
        with open(private_key_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"RSA private key file (for content decryption) not found at: {private_key_path}")
        return None
    except Exception as e:
        logger.error(f"Error reading RSA private key file {private_key_path}: {e}", exc_info=True)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="WhistleDrop Journalist Decryption Tool (CLI - Local/Offline Edition). "
                    "Decrypts a locally available, previously exported submission package."
    )
    parser.add_argument(
        "--submission_path",
        type=Path,
        required=True,
        help="Path to the local directory containing the encrypted submission files "
             "(e.g., .../local_encrypted_submissions_import/submission_id_xyz/)."
    )
    parser.add_argument(
        "--private_rsa_key",
        type=Path,
        required=True,
        help=f"Path to the journalist's private RSA key PEM file (for decrypting submission content). "
             f"If not absolute, assumed relative to current dir or '{DEFAULT_RSA_PRIVATE_KEYS_DIR}'."
    )
    parser.add_argument(
        "--output_dir",
        type=Path,
        default=DEFAULT_DECRYPTED_OUTPUT_DIR,
        help=f"Directory to save the decrypted file (default: ./{DEFAULT_DECRYPTED_OUTPUT_DIR})."
    )

    args = parser.parse_args()

    # Resolve and validate submission path
    submission_dir_path = args.submission_path.resolve()
    if not submission_dir_path.is_dir():
        logger.error(f"Submission path '{submission_dir_path}' is not a valid directory or does not exist.")
        return

    # Resolve and validate RSA private key path
    rsa_private_key_path = args.private_rsa_key.resolve()
    if not rsa_private_key_path.is_file():
        # Try in default directory if path was relative and not found
        alt_rsa_path = (Path.cwd() / DEFAULT_RSA_PRIVATE_KEYS_DIR / args.private_rsa_key.name).resolve()
        if alt_rsa_path.is_file():
            rsa_private_key_path = alt_rsa_path
        else:
            logger.error(f"RSA private key file not found at '{rsa_private_key_path}' or in default dir.")
            return

    # Ensure output directory exists
    output_dir_path = args.output_dir.resolve()
    try:
        output_dir_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f"Could not create output directory '{output_dir_path}': {e}")
        return

    # Load RSA private key PEM content
    private_key_pem_for_decryption = load_private_rsa_key_pem(rsa_private_key_path)
    if not private_key_pem_for_decryption:
        return

    # Get password for the RSA private key (for content decryption)
    decryption_rsa_key_password = getpass.getpass(
        f"Enter password for RSA private key '{rsa_private_key_path.name}' (for submission content decryption, leave blank if none): "
    )
    if not decryption_rsa_key_password:
        decryption_rsa_key_password = None

    logger.info(f"Attempting to decrypt submission from local path: '{submission_dir_path}'")
    logger.info(f"Using RSA decryption key: '{rsa_private_key_path.name}'")

    try:
        # 1. Load encrypted components from the local submission directory
        logger.info("Loading encrypted components from local submission directory...")
        encrypted_aes_key_data = load_encrypted_component(submission_dir_path, LOCAL_ENCRYPTED_AES_KEY_NAME)
        encrypted_original_filename_data = load_encrypted_component(submission_dir_path,
                                                                    LOCAL_ENCRYPTED_ORIGINAL_FILENAME_NAME)
        encrypted_file_data = load_encrypted_component(submission_dir_path, LOCAL_ENCRYPTED_FILE_NAME)

        if not all([encrypted_aes_key_data, encrypted_original_filename_data, encrypted_file_data]):
            logger.error("One or more encrypted components could not be loaded. Aborting decryption.")
            return
        logger.info("All encrypted components loaded successfully from local directory.")

        # 2. Decrypt AES key
        logger.info("Decrypting AES key...")
        decrypted_aes_key = crypto_utils.decrypt_rsa(
            encrypted_aes_key_data,
            private_key_pem_for_decryption,
            decryption_rsa_key_password
        )
        if not decrypted_aes_key:
            logger.error("Failed to decrypt AES key. Incorrect password for RSA key or key mismatch.")
            return
        logger.info("AES key decrypted successfully.")

        # 3. Decrypt original filename
        logger.info("Decrypting original filename...")
        decrypted_original_filename_bytes = crypto_utils.decrypt_aes_gcm(
            encrypted_original_filename_data,
            decrypted_aes_key
        )

        submission_id_for_filename = submission_dir_path.name  # Use submission dir name as fallback ID
        original_filename_str = f"{submission_id_for_filename}_decrypted_file.dat"  # Default
        if decrypted_original_filename_bytes:
            try:
                original_filename_str = decrypted_original_filename_bytes.decode('utf-8', errors='replace')
                logger.info(f"Decrypted original filename: {original_filename_str}")
            except Exception as e_fname_decode:
                logger.warning(
                    f"Could not decode original filename: {e_fname_decode}. Using default: {original_filename_str}")
        else:
            logger.warning(f"Failed to decrypt original filename. Using generic name: {original_filename_str}")

        # 4. Decrypt file data
        logger.info(f"Decrypting file content (for '{original_filename_str}')...")
        decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
        if not decrypted_file_data:
            logger.error("Failed to decrypt file data. AES-GCM decryption failed.")
            return
        logger.info("File content decrypted successfully.")

        # 5. Save decrypted file
        safe_original_filename = "".join(
            c for c in original_filename_str if c.isalnum() or c in ['.', '_', '-']).strip()
        if not safe_original_filename:
            safe_original_filename = f"{submission_id_for_filename}_decrypted_file.dat"

        output_file_path = output_dir_path / safe_original_filename
        try:
            with open(output_file_path, 'wb') as f_out:
                f_out.write(decrypted_file_data)
            logger.info(f"Success! Decrypted file saved to: {output_file_path.resolve()}")
            print(f"\nSuccess! Decrypted file saved to: {output_file_path.resolve()}")
        except IOError as e_save:
            logger.error(f"Failed to save decrypted file to '{output_file_path}': {e_save}", exc_info=True)
            print(f"\nError: Could not save decrypted file to '{output_file_path}'. Check permissions.")

    except Exception as e_unexpected:
        logger.error(f"An unexpected error occurred during the local decryption process: {e_unexpected}", exc_info=True)
        print(f"An unexpected error occurred: {e_unexpected}")


if __name__ == "__main__":
    # Ensure default directories exist if running script directly
    DEFAULT_DECRYPTED_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_RSA_PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_LOCAL_SUBMISSIONS_IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    main()