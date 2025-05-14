# whistledrop/journalist_tool/crypto_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag  # For AES-GCM tag mismatch
import logging

logger = logging.getLogger(__name__)

# Constants for AES-GCM, should match server-side (whistledrop_server/config.py)
AES_NONCE_SIZE = 12  # bytes
AES_GCM_TAG_LENGTH = 16  # bytes


def decrypt_aes_gcm(encrypted_data_with_nonce_tag: bytes, key: bytes) -> bytes | None:
    """
    Decrypts data using AES-256-GCM.
    Assumes the input format: nonce (12 bytes) + GCM tag (16 bytes) + ciphertext.
    Returns the decrypted plaintext as bytes, or None if decryption fails.
    """
    expected_min_length = AES_NONCE_SIZE + AES_GCM_TAG_LENGTH
    if len(encrypted_data_with_nonce_tag) < expected_min_length:
        logger.error(
            f"AES-GCM decryption error: Encrypted data is too short ({len(encrypted_data_with_nonce_tag)} bytes) to contain nonce and tag (min {expected_min_length} bytes).")
        return None

    if len(key) * 8 not in [128, 192, 256]:  # Check key size in bits
        logger.error(f"AES-GCM decryption error: Invalid key size. Expected 16, 24, or 32 bytes, got {len(key)} bytes.")
        return None

    nonce = encrypted_data_with_nonce_tag[:AES_NONCE_SIZE]
    tag = encrypted_data_with_nonce_tag[AES_NONCE_SIZE: AES_NONCE_SIZE + AES_GCM_TAG_LENGTH]
    ciphertext = encrypted_data_with_nonce_tag[AES_NONCE_SIZE + AES_GCM_TAG_LENGTH:]

    if not ciphertext:
        logger.warning("AES-GCM decryption warning: Ciphertext part is empty after extracting nonce and tag.")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        logger.debug("AES-GCM decryption successful.")
        return decrypted_data
    except InvalidTag:
        logger.error("AES-GCM decryption failed: Invalid GCM tag. Data may be tampered, or the key/nonce is incorrect.")
        return None
    except Exception as e:
        logger.error(f"AES-GCM decryption encountered an unexpected error: {e}", exc_info=True)
        return None


def decrypt_rsa(ciphertext: bytes, private_key_pem_str: str, password: str | None = None) -> bytes | None:
    """
    Decrypts data (typically an AES key) using an RSA private key with OAEP padding.
    Returns the decrypted plaintext as bytes, or None if decryption fails.
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem_str.encode('utf-8'),
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )

        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug("RSA decryption successful.")
        return plaintext
    except (ValueError, TypeError) as e:
        logger.error(f"RSA decryption failed. Incorrect password, corrupted/invalid key, or malformed PEM. Error: {e}",
                     exc_info=False)
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during RSA decryption: {e}", exc_info=True)
        return None