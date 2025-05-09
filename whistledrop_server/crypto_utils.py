# whistledrop/whistledrop_server/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag  # For GCM decryption errors
from .config import Config


def generate_aes_key():
    return os.urandom(Config.AES_KEY_SIZE)


def generate_nonce():
    return os.urandom(Config.AES_NONCE_SIZE)


def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    nonce = generate_nonce()
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext


def decrypt_aes_gcm(encrypted_data_with_nonce_tag: bytes, key: bytes) -> bytes | None:
    """
    Decrypts data using AES-GCM. Returns None on decryption failure (e.g., bad key, tampered data).
    """
    if len(encrypted_data_with_nonce_tag) < Config.AES_NONCE_SIZE + 16:  # Nonce + Tag
        # logger.error("Encrypted data is too short to contain nonce and tag.") # Add logging if used on server
        return None

    nonce = encrypted_data_with_nonce_tag[:Config.AES_NONCE_SIZE]
    tag_length = 16
    tag = encrypted_data_with_nonce_tag[Config.AES_NONCE_SIZE: Config.AES_NONCE_SIZE + tag_length]
    ciphertext = encrypted_data_with_nonce_tag[Config.AES_NONCE_SIZE + tag_length:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        # logger.error("AES-GCM decryption failed: Invalid tag. Data may be tampered or key is incorrect.") # Add logging
        return None
    except Exception as e:
        # logger.error(f"AES-GCM decryption failed: {e}") # Add logging
        return None


def encrypt_rsa(data: bytes, public_key_pem: str) -> bytes:
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_rsa(ciphertext: bytes, private_key_pem: str, password: str | None = None) -> bytes | None:
    """
    Decrypts data using an RSA private key (PEM format).
    Handles password-protected keys. Returns None on failure.
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=password.encode() if password else None,
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
        return plaintext
    except (ValueError, TypeError) as e:  # Catches issues like incorrect password
        # logger.error(f"RSA decryption failed (ValueError/TypeError, possibly wrong password or corrupt key): {e}") # Add logging
        return None
    except Exception as e:
        # logger.error(f"RSA decryption failed (general exception): {e}") # Add logging
        return None