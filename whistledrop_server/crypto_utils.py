# whistledrop/whistledrop_server/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
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