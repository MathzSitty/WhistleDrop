# whistledrop/journalist_tool/crypto_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import logging

logger = logging.getLogger(__name__)

AES_KEY_SIZE = 32 # Should match server config
AES_NONCE_SIZE = 12 # Should match server config


def decrypt_aes_gcm(encrypted_data_with_nonce_tag: bytes, key: bytes) -> bytes | None:
    if len(encrypted_data_with_nonce_tag) < AES_NONCE_SIZE + 16:  # Nonce (12) + Tag (16)
        logger.error("Encrypted data is too short to contain nonce and GCM tag.")
        return None

    nonce = encrypted_data_with_nonce_tag[:AES_NONCE_SIZE]
    # AES-GCM tag is typically 16 bytes (128 bits)
    tag_length = 16
    tag = encrypted_data_with_nonce_tag[AES_NONCE_SIZE : AES_NONCE_SIZE + tag_length]
    ciphertext = encrypted_data_with_nonce_tag[AES_NONCE_SIZE + tag_length:]

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except InvalidTag:
        logger.error("AES-GCM decryption failed: Invalid tag. Data may be tampered or key is incorrect.")
        return None
    except Exception as e:
        logger.error(f"An unexpected AES-GCM decryption error occurred: {e}", exc_info=True)
        return None


def decrypt_rsa(ciphertext: bytes, private_key_pem_str: str, password: str | None = None) -> bytes | None:
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem_str.encode(),
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
    except (ValueError, TypeError) as e:
        # ValueError can be raised for incorrect password or malformed key
        logger.error(
            f"RSA decryption failed. This could be due to an incorrect password, a corrupted key, or key type mismatch. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during RSA decryption: {e}", exc_info=True)
        return None