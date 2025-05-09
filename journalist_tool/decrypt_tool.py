# whistledrop/journalist_tool/decrypt_tool.py
import argparse
import os
import requests
import logging
import getpass
from . import crypto_utils

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SERVER_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_PRIVATE_KEYS_DIR = "private_keys/"
DEFAULT_DOWNLOAD_DIR = "decrypted_submissions/"


def fetch_from_server(url: str, api_key: str | None) -> bytes | None:
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        # proxies = {"http": "socks5h://localhost:9050", "https": "socks5h://localhost:9050"}
        # response = requests.get(url, headers=headers, proxies=proxies, timeout=60)
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None


def load_private_key_pem(private_key_filename: str) -> str | None:
    try:
        with open(private_key_filename, 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading private key file {private_key_filename}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="WhistleDrop Journalist Decryption Tool (CLI)")
    parser.add_argument("submission_id", help="The ID of the submission to decrypt.")
    parser.add_argument("private_key_file", help=f"Filename of RSA private key PEM in '{DEFAULT_PRIVATE_KEYS_DIR}'")
    parser.add_argument("--server_url", default=DEFAULT_SERVER_BASE_URL)
    parser.add_argument("--api_key", help="API key for authenticating to the server's journalist endpoints.")
    parser.add_argument("--output_dir", default=DEFAULT_DOWNLOAD_DIR)
    # --original_filename is removed as we fetch it from server
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    full_private_key_path = os.path.join(DEFAULT_PRIVATE_KEYS_DIR, args.private_key_file)
    private_key_pem = load_private_key_pem(full_private_key_path)
    if not private_key_pem: return

    # Ask for private key password
    private_key_password = getpass.getpass(
        f"Enter password for private key '{args.private_key_file}' (leave blank if none): ")
    if not private_key_password: private_key_password = None  # Ensure it's None if empty

    logger.info(f"Attempting to decrypt {args.submission_id} using {args.private_key_file}")

    try:
        # 1. Get package details (URLs for components)
        package_info_url = f"{args.server_url}/journalist/submission/{args.submission_id}/package"
        logger.info(f"Fetching package info from: {package_info_url}")
        package_info_json = fetch_from_server(package_info_url, args.api_key)
        if not package_info_json: logger.error("Failed to fetch package info."); return
        package_data = requests.utils.json.loads(package_info_json)  # Using requests' json for safety

        # 2. Download encrypted components
        enc_aes_key_url = package_data['encrypted_aes_key_url']
        enc_file_url = package_data['encrypted_file_url']
        enc_filename_url = package_data['encrypted_filename_url']

        logger.info("Downloading encrypted AES key...")
        encrypted_aes_key_data = fetch_from_server(enc_aes_key_url, args.api_key)
        if not encrypted_aes_key_data: logger.error("Failed to download encrypted AES key."); return

        logger.info("Downloading encrypted original filename...")
        encrypted_original_filename_data = fetch_from_server(enc_filename_url, args.api_key)
        if not encrypted_original_filename_data: logger.error("Failed to download encrypted original filename."); return

        logger.info("Downloading encrypted file...")
        encrypted_file_data = fetch_from_server(enc_file_url, args.api_key)
        if not encrypted_file_data: logger.error("Failed to download encrypted file."); return

        # 3. Decrypt AES key
        logger.info("Decrypting AES key...")
        decrypted_aes_key = crypto_utils.decrypt_rsa(encrypted_aes_key_data, private_key_pem, private_key_password)
        if not decrypted_aes_key:
            logger.error("Failed to decrypt AES key. Incorrect password or key mismatch.");
            return

        # 4. Decrypt original filename
        logger.info("Decrypting original filename...")
        decrypted_original_filename_bytes = crypto_utils.decrypt_aes_gcm(encrypted_original_filename_data,
                                                                         decrypted_aes_key)
        if not decrypted_original_filename_bytes:
            logger.warning("Failed to decrypt original filename. Using generic name.")
            original_filename = f"{args.submission_id}_decrypted.dat"
        else:
            original_filename = decrypted_original_filename_bytes.decode('utf-8', errors='replace')
            logger.info(f"Decrypted original filename: {original_filename}")

        # 5. Decrypt file data
        logger.info(f"Decrypting file content (for '{original_filename}')...")
        decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
        if not decrypted_file_data:
            logger.error("Failed to decrypt file data.");
            return

        # 6. Save decrypted file
        # Sanitize filename (basic)
        safe_original_filename = "".join(c for c in original_filename if c.isalnum() or c in ['.', '_', '- ']).rstrip()
        if not safe_original_filename: safe_original_filename = f"{args.submission_id}_decrypted.dat"

        output_file_path = os.path.join(args.output_dir, safe_original_filename)
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_file_data)
        logger.info(f"Success! Decrypted file saved to: {output_file_path}")
        print(f"\nSuccess! Decrypted file saved to: {output_file_path}")

    except requests.exceptions.RequestException as e:
        logger.error(f"A network error occurred: {e}")
    except Exception as e:
        logger.error(f"An unexpected error during decryption: {e}", exc_info=True)


if __name__ == "__main__":
    main()