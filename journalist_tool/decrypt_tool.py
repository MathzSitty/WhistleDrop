# whistledrop/journalist_tool/decrypt_tool.py
import argparse
import os
import requests # Standard requests, no session management here for simplicity
import logging
import getpass
from . import crypto_utils # Relative import

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SERVER_BASE_URL = "https://127.0.0.1:5001" # Default to HTTPS
DEFAULT_PRIVATE_KEYS_DIR = "private_keys/"
DEFAULT_DOWNLOAD_DIR = "decrypted_submissions/"


def fetch_from_server(url: str, session: requests.Session | None = None, verify_ssl: bool = False) -> bytes | None:
    """
    Fetches data from the server.
    NOTE: This CLI tool currently does NOT support the new username/password login.
          It would require session management or token-based auth.
          This function is left as a placeholder if direct, unauthenticated (or differently authenticated)
          endpoints were ever needed, or if the tool were to be expanded.
    """
    headers = {}
    # API Key logic removed.
    # If this tool were to be used, it would need to handle login and session cookies.
    # For now, it will likely fail on authenticated endpoints.

    active_session = session if session else requests
    try:
        # Proxies might be needed for .onion, configure via environment or args if re-enabled
        # proxies = {"http": "socks5h://localhost:9050", "https": "socks5h://localhost:9050"}
        # response = active_session.get(url, headers=headers, proxies=proxies, verify=verify_ssl, timeout=60)
        response = active_session.get(url, headers=headers, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Server response: {e.response.status_code} - {e.response.text[:200]}")
        return None


def load_private_key_pem(private_key_filename: str) -> str | None:
    try:
        with open(private_key_filename, 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading private key file {private_key_filename}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="WhistleDrop Journalist Decryption Tool (CLI). "
                    "IMPORTANT: This tool is NOT fully compatible with the new username/password login system "
                    "and will likely fail to access server resources. Use the Journalist GUI."
    )
    parser.add_argument("submission_id", help="The ID of the submission to decrypt.")
    parser.add_argument("private_key_file", help=f"Filename of RSA private key PEM in '{DEFAULT_PRIVATE_KEYS_DIR}'")
    parser.add_argument("--server_url", default=DEFAULT_SERVER_BASE_URL, help="Server base URL (e.g., https://host:port)")
    parser.add_argument("--output_dir", default=DEFAULT_DOWNLOAD_DIR)
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl", help="Disable SSL certificate verification (for self-signed certs).")
    parser.set_defaults(verify_ssl=True) # Verify SSL by default

    args = parser.parse_args()

    logger.warning("IMPORTANT: This CLI tool is not fully functional with the current server authentication model.")
    logger.warning("Please use the Journalist GUI for full functionality.")
    # Prompt to continue or exit
    # proceed = input("Do you want to attempt to proceed anyway? (yes/no) [no]: ").lower()
    # if proceed not in ['yes', 'y']:
    #     print("Exiting.")
    #     return
    print("Exiting due to incompatibility. Please use the Journalist GUI.")
    return


    # --- The following logic is largely unreachable or will fail due to auth ---
    os.makedirs(args.output_dir, exist_ok=True)

    full_private_key_path = os.path.join(DEFAULT_PRIVATE_KEYS_DIR, args.private_key_file)
    private_key_pem = load_private_key_pem(full_private_key_path)
    if not private_key_pem: return

    private_key_password = getpass.getpass(f"Enter password for private key '{args.private_key_file}' (leave blank if none): ")
    if not private_key_password: private_key_password = None

    logger.info(f"Attempting to decrypt {args.submission_id} using {args.private_key_file}")

    # This CLI tool would need a requests.Session object that has successfully logged in.
    # For simplicity, we'll use a new session, which won't be authenticated.
    cli_session = requests.Session()

    try:
        package_info_url = f"{args.server_url.rstrip('/')}/journalist/submission/{args.submission_id}/package"
        logger.info(f"Fetching package info from: {package_info_url} (SSL Verify: {args.verify_ssl})")
        package_info_json = fetch_from_server(package_info_url, session=cli_session, verify_ssl=args.verify_ssl)
        if not package_info_json: logger.error("Failed to fetch package info."); return
        package_data = json.loads(package_info_json) # Using standard json

        enc_aes_key_url = package_data['encrypted_aes_key_url']
        enc_file_url = package_data['encrypted_file_url']
        enc_filename_url = package_data['encrypted_filename_url']

        logger.info("Downloading encrypted AES key...")
        encrypted_aes_key_data = fetch_from_server(enc_aes_key_url, session=cli_session, verify_ssl=args.verify_ssl)
        if not encrypted_aes_key_data: logger.error("Failed to download encrypted AES key."); return

        # ... (rest of the download and decryption logic would follow, but likely fail at fetch_from_server) ...
        # This part is largely unchanged from your original file, assuming data could be fetched.

        logger.info("Downloading encrypted original filename...")
        encrypted_original_filename_data = fetch_from_server(enc_filename_url, session=cli_session, verify_ssl=args.verify_ssl)
        if not encrypted_original_filename_data: logger.error("Failed to download encrypted original filename."); return

        logger.info("Downloading encrypted file...")
        encrypted_file_data = fetch_from_server(enc_file_url, session=cli_session, verify_ssl=args.verify_ssl)
        if not encrypted_file_data: logger.error("Failed to download encrypted file."); return

        logger.info("Decrypting AES key...")
        decrypted_aes_key = crypto_utils.decrypt_rsa(encrypted_aes_key_data, private_key_pem, private_key_password)
        if not decrypted_aes_key: logger.error("Failed to decrypt AES key. Incorrect password or key mismatch."); return

        logger.info("Decrypting original filename...")
        decrypted_original_filename_bytes = crypto_utils.decrypt_aes_gcm(encrypted_original_filename_data, decrypted_aes_key)
        original_filename = f"{args.submission_id}_decrypted.dat"
        if decrypted_original_filename_bytes:
            original_filename = decrypted_original_filename_bytes.decode('utf-8', errors='replace')
            logger.info(f"Decrypted original filename: {original_filename}")
        else: logger.warning("Failed to decrypt original filename. Using generic name.")

        logger.info(f"Decrypting file content (for '{original_filename}')...")
        decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
        if not decrypted_file_data: logger.error("Failed to decrypt file data."); return

        safe_original_filename = "".join(c for c in original_filename if c.isalnum() or c in ['.', '_', '-']).rstrip()
        if not safe_original_filename: safe_original_filename = f"{args.submission_id}_decrypted.dat"
        output_file_path = os.path.join(args.output_dir, safe_original_filename)
        with open(output_file_path, 'wb') as f: f.write(decrypted_file_data)
        logger.info(f"Success! Decrypted file saved to: {output_file_path}")
        print(f"\nSuccess! Decrypted file saved to: {output_file_path}")

    except requests.exceptions.RequestException as e:
        logger.error(f"A network error occurred: {e}")
    except Exception as e:
        logger.error(f"An unexpected error during decryption: {e}", exc_info=True)


if __name__ == "__main__":
    main()