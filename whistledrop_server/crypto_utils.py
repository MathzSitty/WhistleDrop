# whistledrop/whistledrop_server/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .config import Config  # For AES_KEY_SIZE, AES_NONCE_SIZE
import logging

logger = logging.getLogger(__name__)


def generate_aes_key() -> bytes:
    """Generates a cryptographically secure random key for AES."""
    return os.urandom(Config.AES_KEY_SIZE)


def generate_nonce() -> bytes:
    """Generates a cryptographically secure random nonce for AES-GCM."""
    return os.urandom(Config.AES_NONCE_SIZE)


def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-256-GCM.
    Prepends nonce and appends the GCM tag to the ciphertext.
    Format: nonce (12 bytes) + GCM tag (16 bytes) + ciphertext
    """
    if len(key) != Config.AES_KEY_SIZE:
        logger.error(f"AES encryption error: Invalid key size. Expected {Config.AES_KEY_SIZE}, got {len(key)}.")
        raise ValueError(f"Invalid AES key size. Expected {Config.AES_KEY_SIZE} bytes.")

    nonce = generate_nonce()
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        ciphertext = encryptor.update(data) + encryptor.finalize()
        # The tag is available via encryptor.tag after finalize()
        # Prepend nonce, then tag, then ciphertext for storage/transmission
        return nonce + encryptor.tag + ciphertext
    except Exception as e:
        logger.error(f"AES-GCM encryption failed: {e}", exc_info=True)
        raise  # Re-raise the exception to be handled by the caller


def encrypt_rsa(data: bytes, public_key_pem_str: str) -> bytes:
    """
    Encrypts data (typically an AES key) using an RSA public key with OAEP padding.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem_str.encode('utf-8'),  # Ensure PEM string is bytes
            backend=default_backend()
        )

        ciphertext = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),  # Hash algorithm for OAEP
                label=None  # Optional label, usually None
            )
        )
        return ciphertext
    except ValueError as ve:  # Often indicates an issue with the key format or content
        logger.error(f"RSA encryption error: PEM public key could not be loaded or is invalid. {ve}", exc_info=True)
        raise ValueError(f"Invalid RSA public key PEM: {ve}")
    except Exception as e:
        logger.error(f"RSA encryption failed: {e}", exc_info=True)
        raise  # Re-raise to be handled by the caller