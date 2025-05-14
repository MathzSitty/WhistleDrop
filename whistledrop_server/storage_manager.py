# whistledrop/whistledrop_server/storage_manager.py
import os
import uuid
import logging
from .config import Config  # For SUBMISSIONS_DIR
from pathlib import Path  # For more robust path operations

logger = logging.getLogger(__name__)

# Define standard filenames used within each submission's directory
ENCRYPTED_FILE_NAME = "encrypted_file.dat"
ENCRYPTED_AES_KEY_NAME = "encrypted_aes_key.dat"
ENCRYPTED_ORIGINAL_FILENAME_NAME = "encrypted_filename.dat"
RSA_PUBLIC_KEY_ID_NAME = "rsa_public_key_id.txt"  # Stores the DB ID of the RSA key used
RSA_PUBLIC_KEY_HINT_NAME = "rsa_public_key_hint.txt"  # Stores the hint for that RSA key


def save_submission(encrypted_file_data: bytes,
                    encrypted_aes_key_data: bytes,
                    rsa_public_key_id: int,
                    encrypted_original_filename: bytes,
                    rsa_public_key_hint: str | None) -> str | None:
    """
    Saves the encrypted components of a submission to a unique directory.
    Each component is saved as a separate file within this directory.
    The rsa_public_key_hint is crucial for the journalist to identify which
    of their private keys to use for decryption.

    Returns the submission_id (directory name) if successful, None otherwise.
    """
    submission_id = str(uuid.uuid4())
    submission_path = Path(Config.SUBMISSIONS_DIR) / submission_id

    try:
        submission_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created submission directory: {submission_path}")

        # Define paths for each component using pathlib
        file_path = submission_path / ENCRYPTED_FILE_NAME
        aes_key_path = submission_path / ENCRYPTED_AES_KEY_NAME
        rsa_key_id_path = submission_path / RSA_PUBLIC_KEY_ID_NAME
        filename_path = submission_path / ENCRYPTED_ORIGINAL_FILENAME_NAME
        rsa_key_hint_path = submission_path / RSA_PUBLIC_KEY_HINT_NAME

        with open(file_path, 'wb') as f:
            f.write(encrypted_file_data)
        logger.debug(f"Saved {ENCRYPTED_FILE_NAME} for submission {submission_id}")

        with open(aes_key_path, 'wb') as f:
            f.write(encrypted_aes_key_data)
        logger.debug(f"Saved {ENCRYPTED_AES_KEY_NAME} for submission {submission_id}")

        with open(rsa_key_id_path, 'w', encoding='utf-8') as f:
            f.write(str(rsa_public_key_id))
        logger.debug(f"Saved {RSA_PUBLIC_KEY_ID_NAME} ({rsa_public_key_id}) for submission {submission_id}")

        with open(filename_path, 'wb') as f:
            f.write(encrypted_original_filename)
        logger.debug(f"Saved {ENCRYPTED_ORIGINAL_FILENAME_NAME} for submission {submission_id}")

        if rsa_public_key_hint:
            with open(rsa_key_hint_path, 'w', encoding='utf-8') as f:
                f.write(rsa_public_key_hint)
            logger.debug(f"Saved {RSA_PUBLIC_KEY_HINT_NAME} ('{rsa_public_key_hint}') for submission {submission_id}")
        else:
            # Create an empty hint file if no hint was provided.
            # This ensures the file exists, which might be expected by export/import scripts.
            with open(rsa_key_hint_path, 'w', encoding='utf-8') as f:
                f.write("")  # Empty string
            logger.warning(f"No RSA public key hint provided for submission {submission_id}. Saved empty hint file.")

        logger.info(
            f"Submission {submission_id} saved successfully. RSA Key ID: {rsa_public_key_id}, Hint: '{rsa_public_key_hint}'")
        return submission_id

    except IOError as e_io:
        logger.error(f"IOError saving submission {submission_id} to {submission_path}: {e_io}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error saving submission {submission_id} to {submission_path}: {e}", exc_info=True)

    logger.warning(f"Attempting to clean up failed submission directory: {submission_path}")
    if submission_path.exists():
        try:
            for item in submission_path.iterdir():  # Iterate over items in the directory
                item.unlink()  # Remove file or symlink
            submission_path.rmdir()  # Remove the directory itself
            logger.info(f"Successfully cleaned up failed submission directory: {submission_path}")
        except Exception as e_cleanup:
            logger.error(f"Error during cleanup of failed submission directory {submission_path}: {e_cleanup}",
                         exc_info=True)
    return None


def get_submission_package_path(submission_id: str) -> Path | None:
    """
    Returns the absolute Path object to a submission directory if it exists.
    Used by the export utility.
    """
    submission_path = Path(Config.SUBMISSIONS_DIR) / submission_id
    if submission_path.is_dir():
        return submission_path.resolve()
    else:
        logger.warning(f"Submission directory for ID '{submission_id}' not found at {submission_path}")
        return None


def list_submissions() -> list[str]:
    """
    Lists all valid submission IDs (directory names) in the submissions directory.
    This is used internally by the Journalist Interface API.
    """
    submissions_dir_path = Path(Config.SUBMISSIONS_DIR)
    if not submissions_dir_path.is_dir():
        logger.info(f"Submissions directory '{submissions_dir_path}' does not exist. Returning empty list.")
        return []

    submission_ids = []
    try:
        for item in submissions_dir_path.iterdir():
            if item.is_dir():
                # Basic validation: check if essential files exist to consider it a valid submission dir
                # This is a light check. A more robust check might verify all expected files.
                # if (item / ENCRYPTED_FILE_NAME).exists() and \
                #    (item / ENCRYPTED_AES_KEY_NAME).exists() and \
                #    (item / RSA_PUBLIC_KEY_HINT_NAME).exists(): # Hint file is important
                submission_ids.append(item.name)
                # else:
                #    logger.warning(f"Directory '{item.name}' in submissions folder is missing essential files. Skipping.")
        logger.info(f"Found {len(submission_ids)} submission directories in '{submissions_dir_path}'.")
        return submission_ids
    except OSError as e:
        logger.error(f"OSError listing submissions in {submissions_dir_path}: {e}", exc_info=True)
        return []


# Ensure the main submissions directory exists when this module is imported.
# Config.ensure_dirs_exist() should have already done this.
if not Path(Config.SUBMISSIONS_DIR).exists():
    try:
        Path(Config.SUBMISSIONS_DIR).mkdir(parents=True, exist_ok=True)
        logger.info(f"Ensured submissions directory exists: {Config.SUBMISSIONS_DIR}")
    except OSError as e:
        logger.critical(f"Could not create submissions directory {Config.SUBMISSIONS_DIR}: {e}", exc_info=True)
        # This is a critical failure for the application.