# whistledrop/whistledrop_server/storage_manager.py
import os
import uuid
import logging
from .config import Config

logger = logging.getLogger(__name__)


def save_submission(encrypted_file_data: bytes,
                    encrypted_aes_key_data: bytes,
                    rsa_public_key_id: int,
                    encrypted_original_filename: bytes,
                    rsa_public_key_hint: str | None) -> str | None: # Added hint
    submission_id = str(uuid.uuid4())
    submission_path = os.path.join(Config.SUBMISSIONS_DIR, submission_id)

    try:
        os.makedirs(submission_path, exist_ok=True)

        file_path = os.path.join(submission_path, "encrypted_file.dat")
        aes_key_path = os.path.join(submission_path, "encrypted_aes_key.dat")
        rsa_key_id_path = os.path.join(submission_path, "rsa_public_key_id.txt")
        filename_path = os.path.join(submission_path, "encrypted_filename.dat")  # New
        rsa_key_hint_path = os.path.join(submission_path, "rsa_public_key_hint.txt")  # New file for hint

        with open(file_path, 'wb') as f:
            f.write(encrypted_file_data)
        with open(aes_key_path, 'wb') as f:
            f.write(encrypted_aes_key_data)
        with open(rsa_key_id_path, 'w') as f:
            f.write(str(rsa_public_key_id))
        with open(filename_path, 'wb') as f:
            f.write(encrypted_original_filename)
        if rsa_public_key_hint:  # Only write if hint is available
            with open(rsa_key_hint_path, 'w') as f: f.write(rsa_public_key_hint)

        logger.info(f"Submission {submission_id} saved. RSA Key ID: {rsa_public_key_id}, Hint: {rsa_public_key_hint}")
        return submission_id
    except Exception as e:
        logger.error(f"Error saving submission {submission_id}: {e}", exc_info=True)
        # Basic cleanup attempt
        if os.path.exists(submission_path):
            for item in os.listdir(submission_path):
                try:
                    os.remove(os.path.join(submission_path, item))
                except:
                    pass
            try:
                os.rmdir(submission_path)
            except:
                pass
        return None


def get_submission_data(submission_id: str) -> tuple[bytes, bytes, int, bytes, str | None] | None:
    """
    Returns (enc_file_data, enc_aes_key_data, rsa_pub_key_id, enc_orig_filename) or None
    """
    submission_path = os.path.join(Config.SUBMISSIONS_DIR, submission_id)
    file_path = os.path.join(submission_path, "encrypted_file.dat")
    aes_key_path = os.path.join(submission_path, "encrypted_aes_key.dat")
    rsa_key_id_path = os.path.join(submission_path, "rsa_public_key_id.txt")
    filename_path = os.path.join(submission_path, "encrypted_filename.dat")  # New
    rsa_key_hint_path = os.path.join(submission_path, "rsa_public_key_hint.txt")

    if not all(os.path.exists(p) for p in [file_path, aes_key_path, rsa_key_id_path, filename_path]):
        logger.warning(f"Submission {submission_id} or essential components not found.")
        return None

    try:
        with open(file_path, 'rb') as f:
            encrypted_file_data = f.read()
        with open(aes_key_path, 'rb') as f:
            encrypted_aes_key_data = f.read()
        with open(rsa_key_id_path, 'r') as f:
            rsa_public_key_id = int(f.read().strip())
        with open(filename_path, 'rb') as f:
            encrypted_original_filename = f.read()  # New

        rsa_public_key_hint = None
        if os.path.exists(rsa_key_hint_path):  # Hint file is optional for backward compatibility
            with open(rsa_key_hint_path, 'r') as f:
                rsa_public_key_hint = f.read().strip()

        logger.info(f"Retrieved data for submission {submission_id} (Hint: {rsa_public_key_hint}).")
        return encrypted_file_data, encrypted_aes_key_data, rsa_public_key_id, encrypted_original_filename, rsa_public_key_hint
    except (IOError, ValueError) as e:
        logger.error(f"Error retrieving submission {submission_id}: {e}", exc_info=True)
        return None


def list_submissions() -> list[str]:
    try:
        if not os.path.exists(Config.SUBMISSIONS_DIR): return []
        return [d for d in os.listdir(Config.SUBMISSIONS_DIR)
                if os.path.isdir(os.path.join(Config.SUBMISSIONS_DIR, d))]
    except OSError as e:
        logger.error(f"Error listing submissions: {e}")
        return []